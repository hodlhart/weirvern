#!/usr/bin/env python3
"""Narrow the structural cause: which part of the summary makes ClickHouse reject the JOIN?

ESTABLISHED: naming the CTE `keys` is NOT the cause (renaming it fails identically), and neither
is the surrounding WITH (`WITH zeek_w AS (...) SELECT ... LEFT JOIN zeek_w` fails while a bare
`SELECT count() FROM (same summary)` succeeds). So something INSIDE the summary is what
ClickHouse treats as a correlated subquery when the summary is joined.

The summary's shape is: several `<x>_agg` CTEs, then `keys` = a UNION DISTINCT over those CTEs,
then a SELECT that LEFT JOINs twelve of the `_agg` CTEs onto `keys`.

Two candidates, and they need different fixes:

  A. `UNION DISTINCT` inside a CTE. ClickHouse rewrites UNION DISTINCT using a subquery, and a
     subquery inside a joined CTE is exactly what the error names.
  B. The twelve-way LEFT JOIN chain itself, which may trip the same restriction.

This probe isolates each by building progressively simpler summaries and running them joined.
Whichever minimal form FIRST succeeds tells us what to change. Everything is measured against
the live server; nothing here is inferred from the error text.
"""
from __future__ import annotations

import shlex
import subprocess
import sys

sys.path.insert(0, ".")
from weirvern.zeek_features import zeek_window_summary_sql  # noqa: E402

S, E = "2026-09-18 00:00:00", "2026-09-20 00:00:00"
summary = zeek_window_summary_sql(S, E)

# Replace UNION DISTINCT with UNION ALL and see whether that alone changes the outcome. UNION ALL
# does not need the dedup rewrite, so if this succeeds the rewrite is the cause. It changes
# SEMANTICS (duplicate keys), so it is a diagnostic, not the fix.
no_distinct = summary.replace("UNION DISTINCT", "UNION ALL")
renamed_keys = no_distinct.replace("keys AS (", "hw AS (").replace("FROM keys k", "FROM hw k")

cases = {
    "0. summary alone (no join)": f"SELECT count() FROM ({summary})",
    "1. summary JOINed (as shipped)": (
        f"WITH zeek_w AS ({summary}) SELECT count() FROM weirvern.flows_aggregated a "
        f"LEFT JOIN zeek_w z ON z.window_start = a.window_start AND z.src_addr = a.src_addr"
    ),
    "2. summary JOINed, UNION ALL instead of DISTINCT": (
        f"WITH zeek_w AS ({renamed_keys}) SELECT count() FROM weirvern.flows_aggregated a "
        f"LEFT JOIN zeek_w z ON z.window_start = a.window_start AND z.src_addr = a.src_addr"
    ),
    "3. summary JOINed, no keys CTE (conn_agg only)": (
        "WITH zeek_w AS (SELECT toStartOfFiveMinute(ts) AS window_start, src_addr, "
        "count() AS zeek_conn_count FROM weirvern.zeek_conn "
        f"WHERE ts BETWEEN '{S}' AND '{E}' GROUP BY window_start, src_addr) "
        "SELECT count() FROM weirvern.flows_aggregated a "
        "LEFT JOIN zeek_w z ON z.window_start = a.window_start AND z.src_addr = a.src_addr"
    ),
    "4. summary JOINed via IN (no LEFT JOIN)": (
        f"SELECT count() FROM weirvern.flows_aggregated a WHERE (a.window_start, a.src_addr) IN "
        f"(SELECT window_start, src_addr FROM ({summary}))"
    ),
}

for name, sql in cases.items():
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
    detail = "no output"
    for line in ((out.stderr or "") + (out.stdout or "")).splitlines():
        if "Code:" in line:
            detail = line.strip().split("DB::Exception:")[-1].strip()[:95]
            break
        if line.strip().isdigit():
            detail = f"count={line.strip()}"
    mark = "OK  " if out.returncode == 0 else "FAIL"
    print(f"  {mark} {name:48s} exit {out.returncode:4d}  {detail}")
