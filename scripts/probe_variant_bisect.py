#!/usr/bin/env python3
"""Bisect the Zeek summary's UNION to find which branch introduces the Variant type.

ESTABLISHED BY MEASUREMENT:
  * `dhcp_agg` selected `src_addr`; weirvern.zeek_dhcp has no such column -> Code 47. FIXED.
  * The summary still fails standalone with Code 44, "Data types Variant/Dynamic are not allowed
    in ORDER BY keys".
  * UNION ALL fails identically to UNION DISTINCT -> the dedup rewrite is NOT the cause.
  * The FIRST TWO branches unioned together succeed (1496 rows).
  * All 12 `_agg` CTEs run fine on their own.

So one specific branch, added to the union, introduces a mismatched column type. Adding branches
one at a time and stopping at the first failure names it exactly. This is a bisect with a
mechanical answer, so it is done with a loop rather than by reading the SQL and guessing.
"""
from __future__ import annotations

import shlex
import subprocess
import sys

sys.path.insert(0, ".")

from weirvern.zeek_features import zeek_window_summary_sql  # noqa: E402

S, E = "2026-09-18 00:00:00", "2026-09-20 00:00:00"
summary = zeek_window_summary_sql(S, E)


def run(query: str) -> tuple[int, str]:
    remote = (
        "CH=$(kubectl -n weirvern get secret weirvern-secrets "
        "-o jsonpath='{.data.CLICKHOUSE_PASSWORD}' | base64 -d); "
        f"kubectl -n weirvern exec clickhouse-0 -c clickhouse -- "
        f"clickhouse-client --password \"$CH\" -q {shlex.quote(query)}"
    )
    out = subprocess.run(
        ["bash", "-lc", f"ssh -o BatchMode=yes root@192.168.2.159 {shlex.quote(remote)}"],
        capture_output=True, text=True, timeout=180,
    )
    text = (out.stderr or "") + (out.stdout or "")
    for line in text.splitlines():
        if "Code:" in line:
            return out.returncode, line.strip().split("DB::Exception:")[-1].strip()[:95]
    return out.returncode, text.strip()[:60] or "empty"


# Extract the `keys` CTE body by brace matching -- a regex keyed to indentation would silently
# fail to match and this probe would report nothing wrong.
i = summary.find("keys AS (")
assert i > 0, "keys CTE not found; the probe would test nothing"
depth, j = 0, i
for k in range(i + len("keys AS ("), len(summary)):
    if summary[k] == "(":
        depth += 1
    elif summary[k] == ")":
        depth -= 1
        if depth == 0:
            j = k
            break
keys_sel = summary[i + len("keys AS (") : j]
assert "UNION" in keys_sel, "the extracted body has no UNION -- extraction is wrong"

# The WITH block that DEFINES the _agg CTEs, which each mini-query must carry to resolve them.
head = summary[:i]
head = head.rstrip().rstrip(",")
assert head.lstrip().upper().startswith("WITH"), f"head does not start with WITH: {head[:40]!r}"

import re  # noqa: E402

branches = [
    b.strip()
    for b in re.split(r"\bUNION\s+(?:DISTINCT|ALL)\b", keys_sel, flags=re.I)
    if b.strip().upper().startswith("SELECT")
]
print(f"  {len(branches)} branches in the keys union\n")

# Add branches cumulatively; the first count that fails names the branch that broke it.
prev_ok = None
for n in range(1, len(branches) + 1):
    union = "\nUNION DISTINCT ".join(branches[:n])
    code, detail = run(f"{head} SELECT count() FROM ({union})")
    label = branches[n - 1]
    if code == 0:
        prev_ok = label
        print(f"  OK   {n:2d} branches  (+ {label[:46]:48s}) {detail}")
    else:
        print(f"  FAIL {n:2d} branches  (+ {label[:46]:48s}) {detail}")
        print(f"\n  ── the branch that introduces the failure: {label!r} ──")
        # Ask the SERVER for the column types of that branch vs a known-good one, so the fix
        # follows the actual types rather than a guess.
        for name, q in (("breaking", label), ("good", branches[0])):
            _, types = run(
                f"SELECT arrayStringConcat(groupArray(concat(name,'=',type)),', ') "
                f"FROM (DESCRIBE ({q}))"
            )
            print(f"     {name:8s} {types[:130]}")
        break
else:
    print("\n  all branches union cleanly in isolation -- the failure must be in the outer SELECT")
    print(f"  (last good cumulative union used {len(branches)} branches; prev ok = {prev_ok!r})")
