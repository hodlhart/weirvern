"""The per-endpoint flows window: grain, view, reader and retention.

WHY THIS FILE EXISTS. `flows_window` is keyed on the SOURCE of a flow, so the half of the network
that only receives traffic has no flow evidence at all. Schema 061 adds a PARALLEL table keyed on
(window_start, host_addr, direction) and a UNION ALL view feeding it from both endpoints. These
tests pin the properties that make that safe:

  * the grain includes `direction`, so the outbound and inbound rows of one host-window are two
    rows and the engine cannot merge them into one;
  * each flow reaches the aggregate exactly once per direction -- the view has two branches over
    the same table and no join, and each branch emits one row per input row;
  * the outbound branch is the SAME population as `flows_window`'s view (same window expression,
    same endpoints, same casts), which is what makes the live parity check exact;
  * the reader splices the merge with the time predicate and validates the direction, so no
    reader can scan beyond retention or interpolate a free-form direction;
  * the table is on the retention control, so its TTL converges with every other managed table;
  * the ripple flow channels declare both directions and the outbound names keep their meaning.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from pathlib import Path

import pytest

from weirvern import flow_windows, retention
from weirvern.models import ripple_evidence
from weirvern.models.ripple import CHANNEL_FAMILIES

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "weirvern" / "schema"
ENDPOINT_SQL = (SCHEMA / "061_flows_window_endpoint.sql").read_text()
OLD_SQL = (SCHEMA / "050_flows_window.sql").read_text()

TABLE = "weirvern.flows_window_endpoint"
VIEW = "weirvern.flows_window_endpoint_mv"


def _without_comments(sql: str) -> str:
    """The schema as apply_schema sees it: comments stripped BEFORE the statement split."""
    return "\n".join(line.split("--", 1)[0] for line in sql.splitlines())


def _view_body() -> str:
    body = _without_comments(ENDPOINT_SQL).split(
        f"CREATE MATERIALIZED VIEW IF NOT EXISTS {VIEW}", 1)[1]
    return body.split(";", 1)[0]


def test_the_table_grain_is_window_host_direction():
    assert f"CREATE TABLE IF NOT EXISTS {TABLE}" in ENDPOINT_SQL
    assert "ENGINE = AggregatingMergeTree()" in ENDPOINT_SQL
    assert "PARTITION BY toYYYYMM(window_start)" in ENDPOINT_SQL
    # DIRECTION IS PART OF THE SORTING KEY. Without it the engine would merge a host's outbound
    # and inbound states into one row and the direction label would be whichever arrived first.
    assert "ORDER BY (window_start, host_addr, direction)" in ENDPOINT_SQL
    for column, kind in (("window_start", r"DateTime"),
                         ("host_addr", r"String"),
                         ("direction", r"LowCardinality\(String\)"),
                         ("flow_count", r"AggregateFunction\(count, UInt8\)"),
                         ("total_bytes", r"AggregateFunction\(sum, UInt64\)"),
                         ("total_packets", r"AggregateFunction\(sum, UInt64\)"),
                         ("unique_peer_ips", r"AggregateFunction\(uniq, String\)"),
                         ("updated_at", r"SimpleAggregateFunction\(max, DateTime\)")):
        assert re.search(rf"^\s*{column}\s+{kind}", ENDPOINT_SQL, re.M), (
            f"missing column declaration: {column} {kind}"
        )


def test_the_bootstrap_ttl_is_the_seven_day_floor():
    assert "TTL window_start + INTERVAL 7 DAY" in ENDPOINT_SQL
    # The retention control owns the real value; the schema only bootstraps the floor.
    assert "flows_window_endpoint" in retention.table_names()
    entry = next(t for t in retention.RETENTION_TABLES if t.name == "flows_window_endpoint")
    assert entry.column == "window_start"


def test_the_view_is_dropped_and_recreated():
    """`CREATE ... IF NOT EXISTS` does not rebuild a view; 050 documents the same defect."""
    assert f"DROP VIEW IF EXISTS {VIEW}" in ENDPOINT_SQL
    assert ENDPOINT_SQL.index(f"DROP VIEW IF EXISTS {VIEW}") < ENDPOINT_SQL.index(
        f"CREATE MATERIALIZED VIEW IF NOT EXISTS {VIEW}")


def test_the_view_has_two_endpoint_branches_over_one_source_and_no_join():
    body = _view_body()
    assert body.count("FROM weirvern.flows") == 2, (
        "the view must read the source exactly twice: once per endpoint"
    )
    assert not re.search(r"\bJOIN\b", body), (
        "a join could duplicate a flow; the UNION ALL of two plain reads cannot"
    )
    assert "GROUP BY window_start, host_addr, direction" in body


def test_the_outbound_branch_is_the_same_population_as_flows_window():
    """This is what the live parity check compares, so the SQL must agree on all three facts.

    `flows_window`'s view groups `src_addr` by `toStartOfFiveMinute(time_flow_start)` and sums
    `toUInt64(bytes)` / `toUInt64(packets)` with `countState()`. The endpoint view's 'out' branch
    must use the same window expression and the same casts, or its totals would differ for a
    reason that has nothing to do with inbound traffic.
    """
    body = _view_body()
    assert body.count("toStartOfFiveMinute(time_flow_start) AS window_start") == 2
    assert "sumState(toUInt64(bytes))" in body and "sumState(toUInt64(packets))" in body
    # The old view's shape, verbatim, minus the target table.
    assert "toStartOfFiveMinute(time_flow_start) AS window_start" in OLD_SQL
    assert "sumState(toUInt64(bytes))" in OLD_SQL
    assert "countState()" in OLD_SQL
    out_branch = body.split("UNION ALL", 1)[0]
    assert re.search(r"src_addr\s+AS host_addr", out_branch)
    assert re.search(r"dst_addr\s+AS peer_addr", out_branch)


def test_the_two_branches_attribute_opposite_endpoints():
    body = _view_body()
    out_branch, in_branch = body.split("UNION ALL", 1)
    assert "src_addr" in out_branch and "AS host_addr" in out_branch
    assert "'out'" in out_branch and "dst_addr" in out_branch and "AS peer_addr" in out_branch
    assert "dst_addr" in in_branch and "AS host_addr" in in_branch
    assert "'in'" in in_branch and "src_addr" in in_branch and "AS peer_addr" in in_branch
    # The peer is the OTHER endpoint in both branches, and the diversity state counts it.
    assert "uniqState(peer_addr)" in body


def test_the_backfill_uses_the_views_shape_not_a_second_one():
    """A backfill that drifted from the view would write different numbers for one window."""
    import importlib.util

    path = ROOT / "scripts" / "backfill_flows_window_endpoint.py"
    spec = importlib.util.spec_from_file_location("backfill_endpoint", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    aggregate_sql = module.AGGREGATE_SQL

    required = ("toStartOfFiveMinute(time_flow_start) AS window_start",
                "uniqState(peer_addr)",
                "GROUP BY window_start, host_addr, direction")
    for fragment in required:
        assert fragment in aggregate_sql, fragment
        assert fragment in ENDPOINT_SQL, fragment
    # Each endpoint, as a host and as a peer, in both the shipped view and the backfill.
    for fragment in ("AS host_addr", "AS peer_addr", "'out'", "'in'"):
        assert fragment in aggregate_sql
        assert fragment in ENDPOINT_SQL


def test_folded_endpoint_keeps_the_predicate_beside_the_merge_and_groups_by_direction():
    sql = flow_windows.folded_endpoint(
        flow_windows.endpoint_between("2026-11-12 10:00:00", "2026-11-12 11:00:00"), "in")
    assert "{" not in sql, "an unsubstituted placeholder reached the fragment"
    for combinator in ("countMerge(", "sumMerge(", "uniqMerge("):
        assert combinator in sql
    assert f"FROM {TABLE}" in sql
    assert "WHERE window_start BETWEEN '2026-11-12 10:00:00'" in sql, (
        "the predicate is not inside the merged select, so part pruning cannot apply"
    )
    assert "direction = 'in'" in sql
    assert "GROUP BY window_start, host_addr, direction" in sql


def test_folded_endpoint_refuses_a_direction_it_does_not_know():
    with pytest.raises(ValueError, match="unknown direction"):
        flow_windows.folded_endpoint(
            flow_windows.endpoint_between("2026-11-12 10:00:00", "2026-11-12 11:00:00"),
            "sideways")


class _Rows:
    def __init__(self, rows, sql, parameters):
        self.result_rows = rows
        self.sql = sql
        self.parameters = parameters


class _Client:
    def __init__(self, rows):
        self.rows = rows
        self.calls = []

    def query(self, sql, parameters=None):
        self.calls.append((sql, parameters))
        return _Rows(self.rows, sql, parameters)


def test_host_windows_reads_one_host_one_direction_through_the_folded_fragment():
    row = (datetime(2026, 11, 19, 13, 55, tzinfo=UTC),
           datetime(2026, 11, 19, 14, 0, tzinfo=UTC), "198.51.100.10", "in", 12, 900, 14, 3)
    client = _Client([row])
    out = flow_windows.host_windows(client, "198.51.100.10", direction="in",
                                    since=datetime(2026, 11, 19, 13, 0, tzinfo=UTC),
                                    until=datetime(2026, 11, 19, 14, 0, tzinfo=UTC))
    assert out == [{"window_start": row[0], "window_end": row[1], "host_addr": row[2],
                    "direction": "in", "flow_count": 12, "total_bytes": 900,
                    "total_packets": 14, "unique_peer_ips": 3}]
    sql, parameters = client.calls[0]
    assert "FROM weirvern.flows_window_endpoint" in sql
    assert "direction = 'in'" in sql and "countMerge(" in sql
    assert parameters["host"] == "198.51.100.10", (
        "the host must be a bound parameter, not interpolated into the SQL"
    )
    assert "198.51.100.10" not in sql


def test_the_flow_channels_declare_both_directions_and_the_old_names_survive():
    by_name = {spec.channel: spec for spec in ripple_evidence.FLOW_SPECS}
    assert set(by_name) == {"flow_volume", "flow_bytes", "flow_dst_diversity",
                            "flow_in_volume", "flow_in_bytes", "flow_in_peer_diversity"}
    for name in ("flow_volume", "flow_bytes", "flow_dst_diversity"):
        assert by_name[name].direction == "out"
        assert by_name[name].host_column == "host_addr"
        assert by_name[name].table == TABLE
    for name in ("flow_in_volume", "flow_in_bytes", "flow_in_peer_diversity"):
        assert by_name[name].direction == "in"
        assert by_name[name].table == TABLE
    # One family: an inbound and an outbound view of the same flow records cannot corroborate.
    assert {CHANNEL_FAMILIES[name] for name in by_name} == {"flow"}


def test_a_channel_refuses_a_direction_that_is_not_in_or_out():
    from weirvern.models.generic_channels import ChannelSpec

    spec = ChannelSpec("bad", "flow", TABLE, "host_addr", direction="sideways",
                       count_state="flow_count")
    with pytest.raises(ValueError, match="direction must be"):
        spec.sql_anchored(bucket_s=3600, anchor=datetime(2026, 11, 19, 14, 0, tzinfo=UTC),
                          since=datetime(2026, 11, 19, 13, 0, tzinfo=UTC),
                          until=datetime(2026, 11, 19, 14, 0, tzinfo=UTC),
                          scope_cidrs=("198.51.100.0/24",))


def test_every_flow_source_is_on_the_retention_control():
    for spec in ripple_evidence.SPECS:
        if spec.family == "flow":
            assert spec.table.split(".")[-1] in retention.table_names(), (
                f"{spec.channel} reads {spec.table}, which no retention pass manages"
            )


def test_the_network_payload_carries_a_ripple_on_a_destination_endpoint(monkeypatch):
    """The Network tab reads ripples from the same overview; an inbound subject must survive it.

    The graph's edges come from raw `flows`, so both endpoints are already nodes. What was missing
    was a ripple ROW for the receiving endpoint: `_attach_ripples` could only ever see hosts that
    appeared as flow sources. This pins the server half of that seam (the jsdom harness pins the
    client half: an edge whose only rippling end is its target still draws the chip).
    """
    from weirvern.admin import payloads

    inbound_host = "198.51.100.44"
    monkeypatch.setattr(ripple_evidence, "overview", lambda client, hours: {
        "available": True, "reason": "", "window_hours": int(hours),
        "ripples": [{"host": inbound_host, "severity": "medium", "families": ["flow"]}],
        "severity_bands": ripple_evidence.severity_bands(),
    })
    payload = {"available": True, "hours": 24, "nodes": [{"id": inbound_host}],
               "edges": [{"source": "203.0.113.9", "target": inbound_host}]}
    out = payloads._attach_ripples(object(), payload, hours=24)
    assert out["ripple_available"] is True
    assert [row["host"] for row in out["ripples"]] == [inbound_host]
