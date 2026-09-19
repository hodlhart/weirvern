"""Every table/column a UI query names must exist in the shipped schema.

WHY THIS EXISTS. Twice now a panel has been permanently empty because a query named a
column that does not exist:

  1. `top_talkers` read `sum(total_bytes), sum(flow_count)` from `weirvern.flows`, but those
     columns live on `weirvern.flows_aggregated`. ClickHouse raised "Code: 47. Unknown
     expression or identifier", every helper catches exceptions by design (a UI must not
     crash on a query error), and the panel rendered empty in every deployment. An empty
     table is a plausible state, so nothing looked wrong.

  2. The SOC helpers added for the Netflow/Zeek/Health views queried
     `flows_aggregated.proto`, `flows_aggregated.dst_port` and `flows.ts` -- none of which
     exist. `proto`/`dst_port` are per-FLOW facts on `flows`, and `flows` keys its time on
     `timestamp`, not `ts`. Caught by this test's manual predecessor before shipping.

Both are the same failure: a name in one place that no other place produces. The schema is
parsed out of the shipped .sql, so a query referring to a column that is not there fails
HERE rather than rendering an empty panel forever.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SOC = ROOT / "weirvern" / "admin" / "soc.py"


def _schema_sql() -> str:
    text = "\n".join(p.read_text() for p in sorted((ROOT / "weirvern" / "schema").glob("*.sql")))
    # Strip comments: prose containing "CREATE TABLE in ..." has already produced junk table
    # names in an audit in this repo, and the same trap applies to column parsing.
    text = re.sub(r"--[^\n]*", "", text)
    return re.sub(r"/\*.*?\*/", "", text, flags=re.S)


def _columns_of(table: str) -> set[str]:
    m = re.search(
        r"CREATE TABLE (?:IF NOT EXISTS )?(?:weirvern\.)?" + re.escape(table) + r"\s*\((.*?)\n\)",
        _schema_sql(),
        re.S,
    )
    if not m:
        return set()
    out: set[str] = set()
    for line in m.group(1).splitlines():
        line = line.strip().rstrip(",")
        if not line or line.startswith(("#", "--")):
            continue
        first = line.split()[0]
        if first.upper() in {"PRIMARY", "INDEX", "ENGINE", "ORDER", "PARTITION", "SETTINGS",
                             "SAMPLE", "TTL", "COMMENT"}:
            continue
        if re.fullmatch(r"[a-z_][a-z0-9_]*", first):
            out.add(first)
    return out


# Every (table, column) pair the SOC module needs, stated explicitly rather than inferred:
# inferring from the SQL text is how a wrong name gets parsed into a passing test.
REQUIRED = {
    "flows": ["timestamp", "src_addr", "dst_addr", "proto", "dst_port", "bytes", "packets"],
    "flows_aggregated": ["window_start", "src_addr", "flow_count", "total_bytes", "unique_dst_ips"],
    "zeek_conn": ["ts", "service", "src_addr"],
    "zeek_dns": ["ts", "query", "src_addr"],
    "netflow_anomalies": ["detected_at"],
    "ml_models": ["trained_at"],
}


@pytest.mark.parametrize("table,columns", sorted(REQUIRED.items()))
def test_schema_has_the_columns_the_soc_queries_need(table, columns):
    have = _columns_of(table)
    assert have, f"table {table!r} is not in the shipped schema"
    missing = [c for c in columns if c not in have]
    assert not missing, (
        f"weirvern/admin/soc.py needs {table}.{missing}, which do not exist. The query would "
        f"raise 'Unknown expression or identifier' at runtime and the panel would render "
        f"EMPTY FOREVER -- indistinguishable from a quiet network. Available: {sorted(have)}"
    )


def test_every_zeek_table_named_by_the_soc_module_exists():
    """The Zeek panel lists logs by table name; a typo would show a permanently empty chart."""
    import importlib.util

    spec = importlib.util.spec_from_file_location("soc", SOC)
    assert spec is not None and spec.loader is not None, "cannot load weirvern/admin/soc.py"
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    for label, table in mod.ZEEK_LOGS:
        assert _columns_of(table), (
            f"ZEEK_LOGS names {label!r} -> {table!r}, but no such table is declared. "
            "The GUI would show an empty chart for a log that has nowhere to land."
        )


def test_the_aggregate_table_really_lacks_proto_and_dst_port():
    """Pin the FACT the two queries depend on, so a future schema change is not silent.

    `protocol_mix` and `top_ports` read raw `flows` specifically because the aggregate has
    no `proto`/`dst_port`. If someone adds those columns to the aggregate, that reasoning
    becomes stale and these queries should be reconsidered -- this test makes that a
    decision rather than an accident.
    """
    agg = _columns_of("flows_aggregated")
    assert "proto" not in agg and "dst_port" not in agg, (
        "flows_aggregated now carries per-flow columns; the SOC queries were written around "
        "their absence. Reconsider whether protocol_mix/top_ports should use the aggregate."
    )
    raw = _columns_of("flows")
    assert "proto" in raw and "dst_port" in raw, (
        "flows must carry proto and dst_port -- protocol_mix and top_ports read them from here."
    )
