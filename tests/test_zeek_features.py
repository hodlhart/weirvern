"""Zeek feature extraction: the arithmetic, and the absent-vs-zero distinction.

The wiring is covered in test_zeek_ml_wiring.py; this file covers what the numbers ARE.

THE DISTINCTION EVERYTHING HERE HINGES ON: Zeek and NetFlow are separate sensors observing
potentially different traffic. Measured on the test box -- 91 NetFlow hosts, 35 Zeek hosts,
**2 overlapping** -- so "Zeek never saw this host" is the common case there, not an edge
case. If that were indistinguishable from "Zeek saw the host and there was nothing", the
models would learn that most host-windows are defined by empty features, which is a fact
about the sensor deployment rather than about the network.

So `zeek_present` is a feature in its own right, and the tests below check it is set
correctly in both directions.
"""
from __future__ import annotations

import math

import pytest

from weirvern.features import IF_FEATURES, extract_features
from weirvern.zeek_features import (
    ZEEK_DBSCAN_FEATURES,
    ZEEK_FEATURES,
    ZEEK_PRESENCE_FEATURE,
    extract_zeek_features,
    zeek_join_coverage,
)

# A row shaped exactly as the summary query returns it: aliases are the FEATURE names, and
# the ratios are computed in SQL. Copied from real output measured on the live deployment
# (198.51.100.1, a window in which 88 of 89 connections were unanswered SYNs).
REAL_SCAN_ROW = {
    "window_start": "2026-09-17 23:25:00",
    "src_addr": "198.51.100.1",
    "zeek_conn_count": math.log1p(89),
    "zeek_unique_dst_ips": math.log1p(4),
    "zeek_service_count": math.log1p(2),
    "zeek_dns_count": math.log1p(79),
    "zeek_dns_mean_query_entropy": 2.9693712769499143,
    "zeek_dns_mean_query_len": 29.82278481012658,
    "zeek_ja4_count": 0,
    "zeek_notice_count": 0,
    "zeek_weird_count": 0,
    "zeek_rej_ratio": 0.0,
    "zeek_s0_ratio": 88 / 89,
    "zeek_completed_ratio": 1 / 89,
    "zeek_outbound_ratio": 1.0,          # 36861 orig bytes, 0 response
    "zeek_dns_rcode_error_ratio": 0.0,
    "zeek_dns_failed_ratio": 31 / 79,
    "zeek_ssl_modern_ratio": 0.0,
    "zeek_service_rarity": 0.0,
    "zeek_present": 1,
}


# ── absent vs zero ──────────────────────────────────────────────────────────────

def test_no_row_at_all_means_absent():
    feats = extract_zeek_features({})
    assert feats[ZEEK_PRESENCE_FEATURE] == 0.0
    for name in ZEEK_FEATURES:
        assert feats[name] == 0.0, f"{name} is non-zero with no row"


def test_a_row_of_zeroes_means_absent_too():
    """All-zero counts across every log is "Zeek did not see this host", not "this host did
    nothing" -- the summary only produces a row for hosts Zeek DID see, so an all-zero row
    can only come from a caller that fabricated one."""
    feats = extract_zeek_features({k: 0 for k in ZEEK_FEATURES})
    assert feats[ZEEK_PRESENCE_FEATURE] == 0.0


def test_a_host_with_one_connection_is_present_not_absent():
    """The boundary. One connection is real evidence and must not be read as absence."""
    feats = extract_zeek_features({"zeek_conn_count": 1, "zeek_present": 1,
                                   "zeek_s0_ratio": 1.0})
    assert feats[ZEEK_PRESENCE_FEATURE] == 1.0
    assert feats["zeek_conn_count"] > 0


def test_notices_alone_count_as_present():
    """A host that only raised a Zeek notice was still observed. Reading its absence would
    discard the single strongest signal in the row."""
    feats = extract_zeek_features({"zeek_notice_count": 3, "zeek_present": 1})
    assert feats[ZEEK_PRESENCE_FEATURE] == 1.0
    assert feats["zeek_notice_count"] > 0


# ── the derived values ──────────────────────────────────────────────────────────

def test_the_real_scan_row_extracts_sensibly():
    """A measured row: 88 unanswered SYNs out of 89 connections, zero response bytes."""
    feats = extract_zeek_features(REAL_SCAN_ROW)
    assert feats[ZEEK_PRESENCE_FEATURE] == 1.0
    # s0_ratio dominates: nearly every connection was a SYN with no reply.
    assert feats["zeek_s0_ratio"] == pytest.approx(88 / 89)
    assert feats["zeek_completed_ratio"] == pytest.approx(1 / 89)
    # All bytes outbound and none back -- the shape of a one-way transfer.
    assert feats["zeek_outbound_ratio"] == 1.0
    assert feats["zeek_dns_failed_ratio"] == pytest.approx(31 / 79)
    assert feats["zeek_dns_mean_query_entropy"] == pytest.approx(2.97, abs=0.01)


def test_ratios_are_read_from_the_row_not_recomputed():
    """One implementation per formula. The SQL computes them and aliases them with the
    FEATURE name; recomputing in Python would be a second implementation that could drift,
    and the drifted one would be invisible because the training queries never call this
    function."""
    row = {"zeek_conn_count": 10, "zeek_s0_ratio": 0.5, "zeek_rej_ratio": 0.25,
           "zeek_present": 1}
    feats = extract_zeek_features(row)
    assert feats["zeek_s0_ratio"] == 0.5
    assert feats["zeek_rej_ratio"] == 0.25


def test_a_ratio_never_divides_by_zero():
    """A host with DNS records but no connections has no meaningful connection ratio, and
    `nan` would be rejected by sklearn rather than treated as missing -- poisoning the whole
    vector rather than one column."""
    feats = extract_zeek_features({"zeek_conn_count": 0, "zeek_dns_count": 5,
                                   "zeek_present": 1})
    for name in ("zeek_s0_ratio", "zeek_rej_ratio", "zeek_completed_ratio",
                 "zeek_outbound_ratio"):
        assert feats[name] == 0.0
        # nan != nan, so this catches a nan that slipped past the zero check.
        assert feats[name] == feats[name], f"{name} is nan"


def test_service_rarity_is_clamped_and_needs_a_baseline():
    """Using FEWER services than the baseline is not novelty. And with no baseline supplied
    the feature is 0 rather than guessed."""
    # The window count comes from SQL and is already log1p'd; the baseline is raw.
    row = {"zeek_conn_count": math.log1p(5), "zeek_service_count": math.log1p(2),
           "zeek_present": 1}
    assert extract_zeek_features(row)["zeek_service_rarity"] == 0.0
    # A baseline of 5 services and a window with 2 is ordinary, not novel.
    assert extract_zeek_features(row, {"baseline_service_count": 5})[
        "zeek_service_rarity"] == 0.0
    # 2 in-window against a baseline of 1 is novelty of exactly (2 - 1) / 1.
    rarity = extract_zeek_features(row, {"baseline_service_count": 1})[
        "zeek_service_rarity"]
    assert rarity == pytest.approx(1.0)


def test_sql_count_features_are_not_log_scaled_a_second_time():
    """The query owns the log transform; scoring passes its value through (GitHub #58).

    A host with 10,000 connections must not dominate a distance metric, but that is the SQL's
    job. Applying log1p here as well made inference see log1p(log1p(n)) while every model was
    trained on log1p(n).
    """
    feats = extract_zeek_features({"zeek_conn_count": math.log1p(1000),
                                   "zeek_present": 1})
    assert feats["zeek_conn_count"] == pytest.approx(math.log1p(1000))
    small = extract_zeek_features({"zeek_conn_count": math.log1p(10),
                                   "zeek_present": 1})
    assert small["zeek_conn_count"] == pytest.approx(math.log1p(10))


def test_training_and_scoring_vectors_agree_for_every_scaled_count():
    """The seven count aliases are the training matrix's columns; scoring must return them
    unchanged for every magnitude (0, 1, 10, 100, 10000)."""
    names = ("zeek_conn_count", "zeek_unique_dst_ips", "zeek_service_count",
             "zeek_dns_count", "zeek_ja4_count", "zeek_notice_count", "zeek_weird_count")
    for raw in (0, 1, 10, 100, 10_000):
        sql_row = {name: math.log1p(raw) for name in names}
        sql_row["zeek_present"] = 1
        feats = extract_zeek_features(sql_row)
        for name in names:
            assert feats[name] == pytest.approx(sql_row[name]), (
                f"{name} at raw {raw}: scoring transformed a value the model trained on")


def test_a_none_value_never_raises():
    """ClickHouse returns NULLs for a LEFT JOIN that did not match, and a NULL must degrade
    to 0 rather than raise inside a training loop."""
    row = {k: None for k in ZEEK_FEATURES}
    row["zeek_conn_count"] = None
    feats = extract_zeek_features(row)
    assert all(isinstance(v, float) for v in feats.values())


def test_a_non_numeric_value_never_raises():
    """Defensive: a String column arriving where a number is expected must not take the
    worker down."""
    feats = extract_zeek_features({"zeek_conn_count": "not-a-number", "zeek_present": 1})
    assert feats["zeek_conn_count"] == 0.0


# ── integration with the NetFlow features ───────────────────────────────────────

def test_extract_features_merges_both_sources():
    flow = {"total_bytes": 5000, "total_packets": 40, "unique_dst_ips": 3, "flow_count": 9,
            "window_start": __import__("datetime").datetime(2026, 9, 17, 23, 25)}
    feats = extract_features(flow, zeek=REAL_SCAN_ROW)
    # Both sides present in one dict.
    assert feats["log_bytes"] > 0
    assert feats[ZEEK_PRESENCE_FEATURE] == 1.0
    assert feats["zeek_s0_ratio"] > 0
    # And every declared feature is populated, so the vector has no accidental holes.
    for name in IF_FEATURES:
        assert name in feats, f"{name} is declared in IF_FEATURES but never produced"


def test_the_presence_flag_reaches_both_vectors():
    assert ZEEK_PRESENCE_FEATURE in IF_FEATURES
    assert ZEEK_PRESENCE_FEATURE in ZEEK_DBSCAN_FEATURES


def test_zeek_features_are_the_tail_of_each_vector():
    """Order is load-bearing: a model rebuilds its input by POSITION against its recorded
    `feature_columns`, so an interleaved feature would silently reinterpret every column
    after it for any model trained earlier."""
    assert IF_FEATURES[-len(ZEEK_FEATURES):] == ZEEK_FEATURES
    assert ZEEK_DBSCAN_FEATURES[-len(ZEEK_DBSCAN_FEATURES):] == ZEEK_DBSCAN_FEATURES
    # The DBSCAN subset must actually be a subset of the full set, or the query helper and
    # the declared columns disagree.
    assert set(ZEEK_DBSCAN_FEATURES) <= set(ZEEK_FEATURES)


# ── the coverage check ──────────────────────────────────────────────────────────

def test_coverage_reports_the_measured_disjoint_case():
    """91 NetFlow hosts, 35 Zeek hosts, 2 overlapping -- the state of the test deployment,
    where Zeek features are imputed for nearly every row. This must say so rather than
    reporting a healthy system."""
    out = zeek_join_coverage(netflow_hosts=91, zeek_hosts=35, overlapping=2)
    assert out["coverage"] < 0.05
    assert "disjoint" in out["verdict"] or "poor" in out["verdict"]
    assert out["overlapping"] == 2


def test_coverage_handles_no_netflow_hosts():
    out = zeek_join_coverage(netflow_hosts=0, zeek_hosts=5, overlapping=0)
    assert out["coverage"] == 0.0
    assert "nothing to join" in out["verdict"]


def test_a_missing_service_history_is_not_a_baseline_of_one():
    """GitHub #62: a failed service-history query leaves the dict without the key.

    Manufacturing a baseline of one made a five-service host score 4.0 of pure novelty.
    """
    row = {"zeek_conn_count": math.log1p(5), "zeek_service_count": math.log1p(5),
           "zeek_present": 1}
    assert extract_zeek_features(row, {})["zeek_service_rarity"] == 0.0
    assert extract_zeek_features(row, {"baseline_ja4_set": ["ja4_a"]})[
        "zeek_service_rarity"] == 0.0


def test_rarity_uses_the_real_baseline_when_it_is_present():
    """The signal still works where the history IS present: 5 services against 5 is 0.0;
    the same window against a baseline of 1 is exactly 4.0."""
    row = {"zeek_conn_count": math.log1p(5), "zeek_service_count": math.log1p(5),
           "zeek_present": 1}
    assert extract_zeek_features(row, {"baseline_service_count": 5})[
        "zeek_service_rarity"] == pytest.approx(0.0)
    assert extract_zeek_features(row, {"baseline_service_count": 1})[
        "zeek_service_rarity"] == pytest.approx(4.0)
