#!/usr/bin/env python3
"""Find a form of the Zeek-summary JOIN that ClickHouse actually accepts.

THE LIVE FAILURE, recurring every retrain cycle on the deployed worker:

    Worker loop error: Received ClickHouse exception, code: 48
    DB::Exception: Correlated subqueries are not supported in JOINs yet,
    but found in expression: keys AS k. (NOT_IMPLEMENTED)

Stack: worker.py train_if_due -> detectors.py:442 AdaptiveBaseline.train. So the Adaptive
Baseline NEVER TRAINS, and its training history is empty while the other three detectors train
fine -- the same "one model permanently absent, status page looks healthy" shape the file's own
comment describes for a previous defect.

CAUSE. `zeek_window_summary_sql()` is a complete `WITH ... SELECT` statement (it defines
conn_agg, dns_agg, ... then a `keys` CTE). `ZEEK_JOIN_CTE` wraps that whole statement as
`zeek_w AS ({summary})`, and the training queries then do:

    WITH zeek_w AS (WITH keys AS (...) SELECT ... FROM keys k ...)
    SELECT ... FROM flows_aggregated a LEFT JOIN zeek_w z ON ...

A WITH nested inside a JOINed CTE is what ClickHouse rejects here.

This script runs each candidate form against the live database and reports which one works, so
the fix is chosen by MEASUREMENT rather than by reading the error message and guessing.
"""
from __future__ import annotations

import shlex
import subprocess
import sys

sys.path.insert(0, ".")
from weirvern.zeek_features import zeek_window_summary_sql  # noqa: E402

S, E = "2026-09-18 00:00:00", "2026-09-20 00:00:00"
summary = zeek_window_summary_sql(S, E)

# The summary is "WITH a AS (...), b AS (...) SELECT ... FROM keys k ...". Split it so the CTE
# block can be hoisted, which is the difference between candidates 1 and 3.
head, sep, body = summary.partition("SELECT\n")
if not sep:
    head, sep, body = summary.partition("SELECT ")
hoisted_with = head.rstrip().rstrip(",")          # "WITH conn_agg AS (...), ... keys AS (...)"
tail = sep + body                                  # "SELECT ... FROM keys k ..."

candidates = {
    # 0. What ships today -- expected to fail with code 48.
    "as-shipped (CTE wrapping the whole WITH)": (
        f"WITH zeek_w AS ({summary}) "
        f"SELECT count() FROM weirvern.flows_aggregated a "
        f"LEFT JOIN zeek_w z ON z.window_start = a.window_start AND z.src_addr = a.src_addr"
    ),
    # 1. Inline derived table instead of a CTE.
    "inline derived table": (
        f"SELECT count() FROM weirvern.flows_aggregated a "
        f"LEFT JOIN ({summary}) z "
        f"ON z.window_start = a.window_start AND z.src_addr = a.src_addr"
    ),
    # 2. Hoist the summary's own WITH into the outer query, then join a plain CTE reference.
    #    This is the form most likely to work: nothing WITH-shaped sits inside the JOIN.
    "hoisted WITH + join plain CTE": (
        f"{hoisted_with}, "
        f"zeek_w AS ({tail}) "
        f"SELECT count() FROM weirvern.flows_aggregated a "
        f"LEFT JOIN zeek_w z ON z.window_start = a.window_start AND z.src_addr = a.src_addr"
    ),
    # 3. Hoist, and join the tail inline.
    "hoisted WITH + inline tail": (
        f"{hoisted_with} "
        f"SELECT count() FROM weirvern.flows_aggregated a "
        f"LEFT JOIN ({tail}) z "
        f"ON z.window_start = a.window_start AND z.src_addr = a.src_addr"
    ),
}


def run(sql: str) -> tuple[int, str]:
    remote = (
        "CH=$(kubectl -n weirvern get secret weirvern-secrets "
        "-o jsonpath='{.data.CLICKHOUSE_PASSWORD}' | base64 -d); "
        f"kubectl -n weirvern exec clickhouse-0 -c clickhouse -- "
        f"clickhouse-client --password \"$CH\" -q {shlex.quote(sql)}"
    )
    out = subprocess.run(
        ["bash", "-lc", f"ssh -o BatchMode=yes root@192.168.2.159 {shlex.quote(remote)}"],
        capture_output=True, text=True, timeout=200,
    )
    msg = ""
    for line in ((out.stderr or "") + (out.stdout or "")).splitlines():
        if "Code:" in line:
            msg = line.strip()[:150]
            break
    return out.returncode, (msg or (out.stdout or "").strip()[:60] or "no output")


print("  candidate                                   exit  detail")
for name, sql in candidates.items():
    code, detail = run(sql)
    mark = "OK " if code == 0 else "FAIL"
    print(f"  {mark} {name:40s} {code:5d}  {detail}")
