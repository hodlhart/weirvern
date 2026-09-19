"""The Zeek summary must be RUNNABLE, and its union must have one column type.

WHY THIS FILE EXISTS. `zeek_window_summary_sql()` is the sole source of all 49 Zeek ML features.
It was returning nothing at all, for two independent reasons, and neither was visible from the
outside:

  1. `dhcp_agg` selected a bare `src_addr`, but `weirvern.zeek_dhcp` has no such column -- it
     keys its peers as `client_addr`/`server_addr`. The whole statement raised
         Code: 47. Unknown expression identifier `src_addr` in scope dhcp_agg
     The caller caught the exception and logged "Zeek summary is empty for this sweep", which
     reads exactly like a quiet sensor.

  2. The four Tier-3 tables (`zeek_dhcp`, `zeek_tunnel`, `zeek_quic`, `zeek_ldap_search`) were
     created with `src_addr IPv4` while every Tier-1/2 table uses `src_addr String`. The 12-way
     `UNION DISTINCT` therefore mixed the two types, ClickHouse promoted the column to `Variant`,
     and the dedup's ORDER BY rejected it:
         Code: 44. Data types Variant/Dynamic are not allowed in ORDER BY keys
     A mixed-type union is invisible in the SQL text -- it depends on the schema -- so reading
     the query cannot catch it.

Consequence of both: every `zeek_*` feature imputed to zero, and the Adaptive Baseline could not
train (the worker raised Code 48 on every retrain cycle). The status page showed a healthy
cluster throughout.

These tests pin the properties that were violated. They are deliberately STATIC -- they read the
generated SQL -- because that is what runs in CI, and because both defects were properties of the
generated text rather than of a single execution.
"""
from __future__ import annotations

import re

import pytest

from weirvern.zeek_features import zeek_window_summary_sql

S, E = "2026-01-01 00:00:00", "2026-01-02 00:00:00"


@pytest.fixture(scope="module")
def sql() -> str:
    return zeek_window_summary_sql(S, E)


def _cte_body(sql: str, name: str) -> str:
    """The body of `NAME AS ( ... )` inside the summary, brace-matched.

    WHY NOT A REGEX. The first version of this helper used a non-greedy pattern anchored to
    `\\n\\s*),`. It matched `conn_agg` for EVERY table queried -- because the pattern could run
    past the intended CTE's closing paren into a later one -- so the cast test compared the wrong
    text and passed while three Tier-3 CTEs were uncast. That bug was caught only by
    `scripts/prove_zeek_summary_guards.py`, which reintroduces the defect and requires the test to
    fail. Brace matching cannot span a CTE boundary, so it fails safe here.
    """
    marker = f"{name} AS ("
    i = sql.find(marker)
    assert i > 0, f"{name} is gone from the summary -- update this test"
    depth = 0
    for k in range(i + len(marker) - 1, len(sql)):
        if sql[k] == "(":
            depth += 1
        elif sql[k] == ")":
            depth -= 1
            if depth == 0:
                return sql[i : k + 1]
    raise AssertionError(f"unbalanced parentheses in {name}")


def _union_branches(sql: str) -> list[str]:
    """The SELECTs that feed the `keys` CTE, split on its UNIONs.

    Brace-matched rather than regexed: the CTE body contains comments long enough that an
    indentation-anchored pattern silently fails to match, and a matcher that finds nothing would
    make the type test below pass while checking nothing at all.
    """
    i = sql.find("keys AS (")
    assert i > 0, "the `keys` CTE is gone -- this test can no longer see the union"
    depth = 0
    end = i
    for k in range(i + len("keys AS ("), len(sql)):
        if sql[k] == "(":
            depth += 1
        elif sql[k] == ")":
            depth -= 1
            if depth == 0:
                end = k
                break
    body = sql[i + len("keys AS (") : end]
    branches = [
        b.strip() for b in re.split(r"\bUNION\s+(?:DISTINCT|ALL)\b", body, flags=re.I)
        if b.strip().upper().startswith("SELECT")
    ]
    assert branches, "the keys CTE yielded no branches -- the extraction is wrong"
    return branches


def test_the_summary_is_valid_sql_not_just_a_string(sql: str):
    """It must at least look like one statement, so a broken f-string fails loudly here."""
    assert sql.lstrip().upper().startswith("WITH"), "the summary no longer starts with WITH"
    assert "SELECT" in sql
    # An unrendered placeholder would reach ClickHouse verbatim and fail there.
    assert "{" not in sql and "}" not in sql, "an f-string placeholder was not substituted"


def test_no_branch_names_a_column_its_table_does_not_have(sql: str):
    """`dhcp_agg` read `src_addr` from a table that keys its peers as `client_addr`."""
    body = _cte_body(sql, "dhcp_agg")
    assert "client_addr" in body, (
        "dhcp_agg must read client_addr, not src_addr: weirvern.zeek_dhcp has no src_addr column, "
        "and this exact mistake made the entire summary raise Code 47"
    )
    # A bare src_addr anywhere in this CTE means the wrong column is back.
    assert not re.search(r"^\s*src_addr,\s*$", body, re.M), (
        "dhcp_agg selects a bare src_addr, which weirvern.zeek_dhcp does not have"
    )


def test_every_branch_that_yields_src_addr_casts_it_to_string(sql: str):
    """THE DEFECT THAT COST THE MOST: a union of IPv4 and String promotes to Variant.

    The four Tier-3 tables store `src_addr IPv4`; everything else stores `String`. ClickHouse
    resolves the mixed union to `Variant`, and UNION DISTINCT cannot ORDER BY that -- so the
    query fails as a whole with Code 44, not with anything that mentions a type mismatch.

    The fix is to cast at the read layer. This test asserts that every union branch which
    produces `src_addr` does so through a cast, so a newly added IPv4 table cannot silently
    reintroduce the mixed type. A branch that selects a bare `src_addr` is allowed ONLY if its
    table is a String one -- so the tables are listed explicitly rather than inferred.
    """
    string_tables = {
        "zeek_conn", "zeek_dns", "zeek_ssl", "zeek_ssh",
        "zeek_http", "zeek_files", "zeek_notice", "zeek_weird",
    }
    ipv4_tables = {"zeek_dhcp", "zeek_tunnel", "zeek_quic", "zeek_ldap_search"}
    # Nothing may be in both, or the classification is meaningless.
    assert not (string_tables & ipv4_tables)

    # The branches select `w, src_addr FROM <cte>`; the CTEs read the tables above.
    branches = _union_branches(sql)
    assert len(branches) >= 10, f"expected the full union, found {len(branches)} branches"

    for table in ipv4_tables:
        # Find the CTE that reads this table and confirm its src_addr comes from a cast.
        cte_name = _cte_reading(sql, table)
        assert cte_name, f"no CTE reads {table} -- update this test"
        body = _cte_body(sql, cte_name)
        assert re.search(r"toString\(\s*(src_addr|client_addr)\s*\)", body), (
            f"{cte_name} reads {table}, whose src_addr is IPv4. It must cast with toString(...) or "
            f"the 12-way UNION DISTINCT becomes Variant and the whole summary fails with Code 44."
        )


def _cte_reading(sql: str, table: str) -> str | None:
    """The name of the `_agg` CTE whose body reads `weirvern.<table>`."""
    for name in ("conn_agg", "dns_agg", "ssl_agg", "notice_agg", "weird_agg", "dhcp_agg",
                 "tunnel_agg", "quic_agg", "ldap_agg", "ssh_agg", "http_agg", "files_agg"):
        try:
            if f"weirvern.{table}" in _cte_body(sql, name):
                return name
        except AssertionError:
            continue
    return None


def test_the_summary_has_exactly_one_shape_of_src_addr(sql: str):
    """Every branch must alias its address to `src_addr` so the union lines up."""
    for table in ("zeek_dhcp", "zeek_tunnel", "zeek_quic", "zeek_ldap_search",
                  "zeek_conn", "zeek_dns", "zeek_ssl", "zeek_ssh",
                  "zeek_http", "zeek_files", "zeek_notice", "zeek_weird"):
        name = _cte_reading(sql, table)
        if not name:
            continue
        assert "src_addr" in _cte_body(sql, name), (
            f"{name} does not alias its address to src_addr"
        )
