#!/usr/bin/env python3
"""Locate the Variant type that breaks the Zeek summary, by ASKING THE SERVER for types.

ESTABLISHED BY MEASUREMENT:
  * `dhcp_agg` selected `src_addr`; weirvern.zeek_dhcp has no such column -> Code 47. FIXED.
  * The summary still fails standalone: Code 44, "Data types Variant/Dynamic are not allowed in
    ORDER BY keys". ClickHouse implements UNION DISTINCT by ORDER BY-ing every output column,
    which is the only place the summary orders by anything.
  * All 12 `_agg` CTEs run fine ON THEIR OWN.
  * system.columns shows NO Variant/Dynamic column in the weirvern database.

So a UNION branch's `src_addr` is not the plain String the others are -- most likely because one
table stores src_addr differently (IPv4 vs String), and ClickHouse promotes the mismatched pair to
a Variant. That is checkable directly: DESCRIBE each branch's projection and compare the types.
The fix should follow the observed types, not a guess about them.
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
            return out.returncode, line.strip().split("DB::Exception:")[-1].strip()[:100]
    return out.returncode, text.strip()


# Split the summary into its parts using brace matching rather than a pattern that assumes
# indentation -- a regex that silently fails to match would report "nothing wrong" here.
i = summary.find("keys AS (")
assert i > 0, "keys CTE not found; the probe would test nothing"
head = summary[:i]
j, depth = i + len("keys AS "), 0
for k in range(i + len("keys AS ("), len(summary)):
    if summary[k] == "(":
        depth += 1
    elif summary[k] == ")":
        depth -= 1
        if depth == 0:
            j = k + 1
            break
keys_sel = summary[i + len("keys AS (") : j - 1]

# 1. The types each UNION branch contributes. A mismatch here is the whole story.
print("  ── types of `src_addr` per UNION branch (a mismatch promotes to Variant) ──")
for br in keys_sel.replace("UNION DISTINCT", "\n").replace("UNION ALL", "\n").splitlines():
    br = br.strip().rstrip(";")
    if not br.upper().startswith("SELECT"):
        continue
    code, types = run(
        f"SELECT arrayStringConcat(groupArray(concat(name,'=',type)),' ') FROM "
        f"(DESCRIBE TABLE (SELECT * FROM ({br}) LIMIT 0))"
    )
    print(f"     {'OK  ' if code == 0 else 'FAIL'} {br[:52]:54s} {types[:80] if code == 0 else types}")

# 2. Does the whole summary work if the dedup is dropped? UNION ALL needs no ORDER BY, so if this
#    succeeds the failure is specifically in the UNION DISTINCT rewrite.
print("\n  ── the summary with UNION ALL instead of UNION DISTINCT ──")
code, detail = run(f"SELECT count() FROM ({summary.replace('UNION DISTINCT', 'UNION ALL')})")
print(f"     {'OK  ' if code == 0 else 'FAIL'} exit {code}  {detail[:90]}")

# 3. And the shipping form, for contrast.
print("\n  ── the summary exactly as shipped ──")
code, detail = run(f"SELECT count() FROM ({summary})")
print(f"     {'OK  ' if code == 0 else 'FAIL'} exit {code}  {detail[:90]}")

# 4. The union over just two branches, to see the error reproduce in miniature.
first_two = "\nUNION DISTINCT ".join(
    b.strip() for b in keys_sel.split("UNION DISTINCT")[:2]
)
code, detail = run(f"{head.rstrip().rstrip(',')} SELECT count() FROM ({first_two})")
print("\n  ── only the first two branches unioned ──")
print(f"     {'OK  ' if code == 0 else 'FAIL'} exit {code}  {detail[:90]}")
