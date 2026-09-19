#!/usr/bin/env python3
"""Apply the two Zeek-summary fixes, idempotently and without depending on spacing.

Both defects are in `zeek_window_summary_sql()`, the sole source of all 49 Zeek ML features, and
either one makes the whole statement fail -- so every zeek_* feature imputed to zero:

  1. CODE 47 -- `dhcp_agg` selects a bare `src_addr`, but `weirvern.zeek_dhcp` has no such column;
     it keys its peers as `client_addr`/`server_addr`:
         Unknown expression identifier `src_addr` in scope dhcp_agg

  2. CODE 44 -- the four Tier-3 tables (`zeek_dhcp`, `zeek_tunnel`, `zeek_quic`, `zeek_ldap_search`)
     store `src_addr IPv4` while every Tier-1/2 table stores `src_addr String`. The 12-way
     `UNION DISTINCT` mixes the two types, ClickHouse promotes the column to `Variant`, and the
     dedup's ORDER BY rejects it:
         Data types Variant/Dynamic are not allowed in ORDER BY keys

  The fix for both is the same shape: name the right column, and cast it to String at the read
  layer. `toString(IPv4)` yields the identical dotted form the String tables already hold
  (verified against live rows), so the join to `flows_aggregated.src_addr` is unaffected.

EDITING BY CTE BODY, NOT BY LINE PATTERN. Each fix locates the CTE by name and rewrites the
address line inside it. An earlier version matched exact line text including the FOLLOWING line's
indentation, which differs between CTEs (dhcp_agg uses 16 spaces, the other three use 18) -- so it
silently failed to apply. Locating the CTE and working inside it removes that whole class of bug.

Idempotent, and it reports what it found rather than assuming a starting state.
"""
from __future__ import annotations

import pathlib
import re
import sys

SRC = pathlib.Path(__file__).resolve().parent.parent / "weirvern" / "zeek_features.py"

# CTE name -> (table it must read, the expression that must replace a bare `src_addr,`).
#   dhcp_agg ALSO renames the column: weirvern.zeek_dhcp has no src_addr at all, so reading the
#   right column is part of the fix, not just casting it.
REPLACEMENT = {
    "dhcp_agg": ("zeek_dhcp", "toString(client_addr) AS src_addr"),
    "tunnel_agg": ("zeek_tunnel", "toString(src_addr) AS src_addr"),
    "quic_agg": ("zeek_quic", "toString(src_addr) AS src_addr"),
    "ldap_agg": ("zeek_ldap_search", "toString(src_addr) AS src_addr"),
}


def cte_body(text: str, name: str) -> tuple[int, int, str]:
    """Return (start, end, body) for `NAME AS ( ... ),` using brace matching.

    Brace matching rather than a non-greedy regex: several of these bodies contain `)` inside
    expressions and long comments, and a regex that stops early or spans into the NEXT CTE would
    make the checks below silently pass against the wrong text.
    """
    marker = f"{name} AS ("
    i = text.find(marker)
    if i < 0:
        raise SystemExit(f"ERROR: {name} not found -- update this script")
    depth = 0
    for k in range(i + len(marker) - 1, len(text)):
        if text[k] == "(":
            depth += 1
        elif text[k] == ")":
            depth -= 1
            if depth == 0:
                return i, k + 1, text[i : k + 1]
    raise SystemExit(f"ERROR: unbalanced parentheses in {name}")


def main() -> int:
    text = SRC.read_text()
    changes: list[tuple[str, str, str]] = []   # (name, old_body, new_body)

    for name, (table, replacement) in REPLACEMENT.items():
        start, end, body = cte_body(text, name)

        # Guard the assumption: this CTE must read the table the fix names. If a future edit
        # swaps the table, applying the wrong column would be worse than doing nothing.
        if f"weirvern.{table}" not in body:
            print(f"  ERROR: {name} no longer reads weirvern.{table} -- update this script")
            return 1

        if replacement in body:
            print(f"  already  {name} ({replacement} already present)")
            continue

        # Replace the bare address line wherever it appears in this CTE, preserving indentation.
        # `repl` binds the loop variable by value: a lambda closing over `replacement` directly
        # would read whatever the loop last set, so the wrong expression could be substituted.
        repl = replacement
        new_body, n = re.subn(
            r"(?m)^(\s*)src_addr,\s*$",
            lambda m, r=repl: f"{m.group(1)}{r},",
            body,
        )
        if n != 1:
            print(f"  ERROR: {name} has {n} bare `src_addr,` lines; expected exactly 1")
            print("         (the SELECT shape changed -- update this script)")
            return 1

        text = text[:start] + new_body + text[end:]
        changes.append((name, body, new_body))
        print(f"  fixed    {name}: src_addr -> {replacement}")

    if not changes:
        print("  nothing to do")
        return 0

    SRC.write_text(text)

    # Re-verify from disk, so a botched write cannot be reported as success.
    written = SRC.read_text()
    for name, (_table, replacement) in REPLACEMENT.items():
        _s, _e, body = cte_body(written, name)
        if replacement not in body:
            print(f"  ERROR: {name} does not contain {replacement!r} after writing -- aborting")
            SRC.write_text(text)  # best effort; the operator will see the failure
            return 1
    print(f"  verified {len(changes)} change(s) on disk")
    return 0


if __name__ == "__main__":
    sys.exit(main())
