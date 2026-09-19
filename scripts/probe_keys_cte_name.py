#!/usr/bin/env python3
"""Is the CTE name `keys` the cause of the live Code:48 failure?

THE ERROR:  Code: 48. "Correlated subqueries are not supported in JOINs yet, but found in
expression: keys AS k."

That message is confusing, and the phrase it complains about is `keys AS k` -- a plain CTE
alias. `keys` is ALSO a built-in ClickHouse function (it returns the keys of a Map). A CTE named
after a built-in function is a name-resolution hazard, and a name-resolution problem wearing a
"correlated subquery" error message is exactly the kind of thing that gets mis-diagnosed.

This probe tests the hypothesis directly by renaming ONLY the CTE and its references, and
running the identical query both ways against the live database:

  A. as-shipped   WITH ... keys AS (...) ... FROM keys k
  B. renamed      WITH ... host_windows AS (...) ... FROM host_windows k

If B works and A fails, the name is the cause and the fix is a rename rather than a rewrite.
If both fail, the name is a red herring and the problem is structural -- which is worth knowing
before touching the query.

Everything else is identical between the two, so the comparison isolates one variable.
"""
from __future__ import annotations

import shlex
import subprocess
import sys

sys.path.insert(0, ".")
from weirvern.zeek_features import zeek_window_summary_sql  # noqa: E402

S, E = "2026-09-18 00:00:00", "2026-09-20 00:00:00"
summary = zeek_window_summary_sql(S, E)

# Rename the CTE and every reference to it. Both the definition (`keys AS (`) and the FROM
# (`FROM keys k`) are rewritten; a partial rename would produce a "table not found" error that
# looks like a different problem.
renamed = summary.replace("keys AS (", "host_windows AS (").replace("FROM keys k", "FROM host_windows k")


def wrap(inner: str) -> str:
    return (
        f"WITH zeek_w AS ({inner}) "
        f"SELECT count() FROM weirvern.flows_aggregated a "
        f"LEFT JOIN zeek_w z ON z.window_start = a.window_start AND z.src_addr = a.src_addr"
    )


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
    for line in ((out.stderr or "") + (out.stdout or "")).splitlines():
        if "Code:" in line:
            return out.returncode, line.strip()[:160]
    return out.returncode, (out.stdout or "").strip()[:80] or "no output"


# Sanity: the rename must actually have changed the text, or the comparison proves nothing.
assert renamed != summary, "the rename did not apply -- the comparison would be meaningless"
assert "keys AS (" not in renamed, "the CTE definition was not renamed"
assert "FROM keys k" not in renamed, "the CTE reference was not renamed"

print("  A. as-shipped (CTE named `keys`)")
code, detail = run(wrap(summary))
print(f"     exit {code}  {detail}")

print("  B. renamed (CTE `host_windows`)")
code_b, detail_b = run(wrap(renamed))
print(f"     exit {code_b}  {detail_b}")

print()
if code != 0 and code_b == 0:
    print("  VERDICT: the NAME is the cause. Renaming the CTE fixes it.")
elif code == 0 and code_b == 0:
    print("  VERDICT: both work -- the failure must be elsewhere in the real query.")
else:
    print("  VERDICT: not the name. Both fail, so the problem is structural.")
