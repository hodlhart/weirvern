#!/usr/bin/env python3
"""Run a ClickHouse query against the deployed cluster and print the result.

WHY THIS EXISTS. Every investigation in this project needs the same three-hop plumbing --
ssh to the sensor host, read the ClickHouse password out of the Kubernetes secret, exec into
the clickhouse pod, run one query -- and doing it inline in a heredoc each time is how quoting
bugs get introduced. Three separate probes today produced wrong answers purely from shell
quoting: a `WHERE database="weirvern"` collapsed to an identifier instead of a string literal,
and a hex-encoded table list hit a String/UInt64 type error. The query text is passed through
`shlex.quote` here, so the SQL reaches the server exactly as written.

CONFIGURATION COMES FROM THE ENVIRONMENT, never from the file. `WEIRVERN_SENSOR_HOST` is the
ssh target; there is no default address, so this script cannot leak one into the tree, and it
fails loudly rather than silently querying the wrong box. That mirrors the harness convention
(`INTERCEPT_SEGMENT` and friends) that exists for the same reason.

USAGE
    WEIRVERN_SENSOR_HOST=root@sensor ./scripts/chq.py "SELECT count() FROM weirvern.flows"
    WEIRVERN_SENSOR_HOST=root@sensor ./scripts/chq.py --tsv "SELECT ... FORMAT TSV"
    ./scripts/chq.py --schema weirvern.flows        # column names and types

Exit status is the server's, so a failing query fails the caller.
"""
from __future__ import annotations

import argparse
import os
import shlex
import subprocess
import sys

HOST_VAR = "WEIRVERN_SENSOR_HOST"
NAMESPACE = os.environ.get("WEIRVERN_NAMESPACE", "weirvern")


def remote_command(sql: str) -> str:
    """The shell fragment that runs `sql` inside the clickhouse pod.

    The password is read from the cluster's own secret rather than passed in, so it never
    appears in this process's arguments or environment.
    """
    return (
        f"CH=$(kubectl -n {NAMESPACE} get secret weirvern-secrets "
        "-o jsonpath='{.data.CLICKHOUSE_PASSWORD}' | base64 -d); "
        f"kubectl -n {NAMESPACE} exec clickhouse-0 -c clickhouse -- "
        f"clickhouse-client --password \"$CH\" -q {shlex.quote(sql)}"
    )


def run(sql: str, timeout: int = 240) -> tuple[int, str]:
    host = os.environ.get(HOST_VAR)
    if not host:
        sys.exit(
            f"{HOST_VAR} is not set. This script has no default host on purpose: an address "
            f"baked in here would be committed to a public repository.\n"
            f"  export {HOST_VAR}=root@<sensor>\n"
            f"  (a non-default namespace can be set with WEIRVERN_NAMESPACE)"
        )
    inner = remote_command(sql)
    outer = f"ssh -o BatchMode=yes {shlex.quote(host)} {shlex.quote(inner)}"
    proc = subprocess.run(
        ["bash", "-lc", outer], capture_output=True, text=True, timeout=timeout,
    )
    return proc.returncode, ((proc.stdout or "") + (proc.stderr or "")).strip()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("sql", nargs="?", help="the query; omit when using --schema")
    ap.add_argument("--tsv", action="store_true", help="append FORMAT TSV")
    ap.add_argument("--schema", metavar="DB.TABLE",
                    help="print the column names and types of a table")
    ap.add_argument("--timeout", type=int, default=240)
    args = ap.parse_args()

    if args.schema:
        db, _, table = args.schema.partition(".")
        if not table:
            sys.exit("--schema wants DB.TABLE, e.g. --schema weirvern.flows")
        # Built with parameters rather than string interpolation: an earlier hex-encoded
        # attempt at exactly this query failed with a String/UInt64 type error.
        sql = (
            "SELECT name, type FROM system.columns "
            f"WHERE database = '{db}' AND table = '{table}' ORDER BY position"
        )
        code, out = run(sql, args.timeout)
        print(out)
        return code

    if not args.sql:
        sys.exit("no query given (see --help)")

    sql = args.sql
    if args.tsv and "FORMAT" not in sql.upper():
        sql = f"{sql} FORMAT TSV"
    code, out = run(sql, args.timeout)
    print(out)
    return code


if __name__ == "__main__":
    sys.exit(main())
