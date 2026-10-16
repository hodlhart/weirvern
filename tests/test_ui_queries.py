"""The UI query helpers must reference columns that actually exist.

THE BUG THIS GUARDS: `top_talkers` read `sum(total_bytes), sum(flow_count)` from
`weirvern.flows`, but those columns exist only on `weirvern.flows_aggregated`.
ClickHouse raised

    Code: 47. Unknown expression or identifier `total_bytes`

and the helper catches every exception and returns [] by design — a UI must not
crash on a query error. The result was a permanently EMPTY Top Talkers panel in
the web GUI, in every deployment, with the failure logged only at
debug level. It looked exactly like a network with no traffic.

Nothing caught it because no test asserted the panel had CONTENT, and an empty
table is a plausible state. These tests assert against the real schema instead: the
column list is parsed out of the shipped .sql, so a query naming a column that does
not exist fails here rather than silently rendering an empty panel.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

SCHEMA = Path(__file__).resolve().parent.parent / "weirvern" / "schema" / "001_weirvern.sql"


def _columns_of(table: str) -> set[str]:
    """Column names of a table, parsed from the shipped schema.

    Parsed rather than hardcoded so this keeps working when the schema changes --
    the point is to catch a query referencing a column that does not exist, and a
    hardcoded list would drift exactly like the query did.

    `table` may be given qualified (`weirvern.zeek_conn`) or bare (`zeek_conn`);
    the DDL uses the bare name inside a `CREATE DATABASE weirvern` context, so the
    prefix is stripped. An earlier version of this helper matched only the
    qualified form and failed on every table.
    """
    bare = table.split(".")[-1]
    text = SCHEMA.read_text()
    m = re.search(
        rf"CREATE TABLE IF NOT EXISTS\s+`?(?:weirvern\.)?{re.escape(bare)}`?\s*\((.*?)\)\s*ENGINE",
        text, re.S | re.I,
    )
    if not m:
        pytest.fail(f"table {bare} not found in the shipped schema")
    cols = set()
    for line in m.group(1).splitlines():
        line = line.strip()
        if not line or line.startswith("--") or line.upper().startswith("INDEX"):
            continue
        name = line.split()[0].strip(",").strip("`")
        if name and not name.startswith((")", "PRIMARY", "ORDER", "PARTITION")):
            cols.add(name)
    return cols


@pytest.fixture(scope="module")
def flows_cols():
    return _columns_of("weirvern.flows")


@pytest.fixture(scope="module")
def agg_cols():
    return _columns_of("weirvern.flows_aggregated")


# --- the specific regression --------------------------------------------------
def test_top_talkers_queries_columns_that_exist(agg_cols):
    """Extract the identifiers top_talkers uses and check them against the schema.

    A regex over the SQL is enough here because the query is a literal, and being
    slightly over-inclusive is fine: a false positive means a test failure to
    investigate, whereas under-checking is what let this ship.
    """
    from weirvern.admin import status

    sql = _sql_literals(status.top_talkers)
    assert "flows_aggregated" in sql, (
        "top_talkers must read the aggregated table: total_bytes and flow_count "
        "do not exist on weirvern.flows"
    )

    for column in ("total_bytes", "flow_count", "unique_dst_ips", "window_start"):
        assert column in sql, f"expected {column} in the query"
        assert column in agg_cols, f"{column} is not a flows_aggregated column"

    # THE RAW PATH EXISTS BY DESIGN (2026-10-16, the dashboard-wide filter): a protocol or port
    # filter cannot be answered by the aggregate at all, so the panel switches to `flows` --
    # with ITS columns, which the schema check above does not cover.
    assert "FROM weirvern.flows " in sql, (
        "the filtered branch must read raw flows; without it a proto/port filter would be "
        "silently ignored here while the other panels applied it")
    for column in ("timestamp", "bytes", "dst_addr"):
        assert column in sql, f"the raw branch must query {column}"


def test_the_columns_top_talkers_needs_are_not_on_raw_flows(flows_cols):
    """Documents WHY the table choice matters: if these ever appear on the raw
    table the query could move, but until then it cannot."""
    for column in ("total_bytes", "flow_count", "unique_dst_ips"):
        assert column not in flows_cols, (
            f"{column} is now on weirvern.flows; the top_talkers query comment "
            f"explaining the table choice is stale"
        )


def test_top_talkers_failure_is_logged_above_debug(caplog):
    """An empty panel and a broken query look identical, so a failure must be
    visible in the logs rather than swallowed at debug level."""
    import logging

    from weirvern.admin import status

    class Boom:
        def query(self, *a, **k):
            raise RuntimeError("Code: 47. Unknown identifier `total_bytes`")

    with caplog.at_level(logging.WARNING):
        out = status.top_talkers(Boom())
    # STRENGTHENED (issue #13): a failed read is now a STATE the panel renders ("Cannot draw
    # this: ..."), not an empty list that reads as a quiet network. The log stays as the second
    # layer.
    assert out["available"] is False and out["points"] == [], (
        "a failed read must be renderable as a failure, not an empty list")
    assert "talkers" in out["reason"]
    assert any("top_talkers failed" in r.message for r in caplog.records), (
        "the failure was swallowed silently; an empty talkers table is "
        "indistinguishable from a quiet network"
    )


# --- the same class of check for the other UI queries -------------------------
def test_recent_anomalies_queries_real_columns():
    from weirvern.admin import status

    sql = _sql_literals(status.recent_anomalies)
    cols = _columns_of("weirvern.netflow_anomalies")
    for column in ("detected_at", "src_addr", "anomaly_score", "severity",
                   "detected_by_models"):
        assert column in sql
        assert column in cols, f"{column} is not a netflow_anomalies column"


def test_anomalies_detailed_queries_real_columns():
    """The GUI's explainability query -- the one the whole drill-down depends on."""
    from weirvern.admin import status

    sql = _sql_literals(status.anomalies_detailed)
    cols = _columns_of("weirvern.netflow_anomalies")
    for column in ("primary_deviation_feature", "primary_deviation_zscore",
                   "deviation_magnitude", "feature_contributions",
                   "baseline_comparison", "model_agreement", "confidence",
                   "isolation_forest_score", "gradient_boosting_score",
                   "dbscan_score", "baseline_score"):
        assert column in sql, f"{column} missing from anomalies_detailed"
        assert column in cols, f"{column} is not a netflow_anomalies column"


def _sql_literals(func) -> str:
    """Concatenated SQL string literals from a function, COMMENTS EXCLUDED.

    Reading the whole source (as an earlier version of this helper did) picks up
    comments, so documenting a bug -- "the query must not use id_orig_h" -- made the
    guard fire on its own explanation. Parsing the AST keeps the check aimed at what
    the code actually executes.
    """
    import ast
    import inspect
    import textwrap

    tree = ast.parse(textwrap.dedent(inspect.getsource(func)))
    parts = [
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    ]
    return " ".join(parts)


def test_host_detail_queries_real_columns():
    """Every table the drill-down references must exist, and it must read the raw
    `flows` table for per-flow detail (the aggregate has no dst_addr or ports)."""
    from weirvern.admin import status

    sql = _sql_literals(status.host_detail)
    known = {
        "weirvern.flows": _columns_of("weirvern.flows"),
        "weirvern.netflow_anomalies": _columns_of("weirvern.netflow_anomalies"),
        "weirvern.zeek_conn": _columns_of("weirvern.zeek_conn"),
    }
    for table in known:
        assert table in sql, f"host_detail no longer queries {table}"

    # Every `weirvern.<table>` reference must name a real table.
    for referenced in set(re.findall(r"weirvern\.(\w+)", sql)):
        assert f"weirvern.{referenced}" in known, (
            f"host_detail references an unknown table: weirvern.{referenced}"
        )


def test_zeek_columns_used_by_host_detail_exist():
    """The Zeek enrichment reads src_addr/service/ts from zeek_conn.

    NOT `id_orig_h`: the schema deliberately normalizes Zeek's field name to
    `src_addr` at ingest so the Zeek and NetFlow tables can be joined on a common
    column. Asserting the raw Zeek name here was the test's own mistake -- it is
    the NORMALIZED name that must exist.
    """
    sql_cols = _columns_of("weirvern.zeek_conn")
    for column in ("src_addr", "service", "ts", "orig_bytes", "resp_bytes"):
        assert column in sql_cols, f"{column} is not a zeek_conn column"


def test_host_detail_does_not_use_raw_zeek_field_names():
    """Guards the normalization decision from the other side. The check targets SQL
    literals only, so the comment documenting the bug does not trip it."""
    from weirvern.admin import status

    sql = _sql_literals(status.host_detail)
    assert "id_orig_h" not in sql, (
        "host_detail uses Zeek's raw field name in its SQL; the schema normalizes "
        "it to src_addr at ingest, so this join returns no rows"
    )
