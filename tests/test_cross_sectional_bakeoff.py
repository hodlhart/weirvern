"""Tests for the cross-sectional bake-off harness (scripts/cross_sectional_bakeoff.py).

The harness is an offline evaluation tool, not a detector: nothing here exercises ClickHouse.
What it pins is the part that would silently invalidate every number in the report -- the SQL
must select the production 19-feature vector in the production order, the fold parser must not
mangle timestamps, and the degeneracy/coverage measures must say what they claim.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import numpy as np
import pytest

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location(
    "cross_sectional_bakeoff", ROOT / "scripts" / "cross_sectional_bakeoff.py")
assert SPEC is not None and SPEC.loader is not None
bakeoff = importlib.util.module_from_spec(SPEC)
sys.modules["cross_sectional_bakeoff"] = bakeoff
SPEC.loader.exec_module(bakeoff)


def test_matrix_sql_selects_the_production_vector_in_order() -> None:
    sql = bakeoff.matrix_sql("2026-11-12 00:00:00", "2026-11-13 00:00:00", ["203.0.113.0/24"])
    select = sql.split("SELECT a.window_start", 1)[1].split("FROM (", 1)[0]
    positions = [select.index(f"z.{name}") for name in bakeoff.ZEEK_DBSCAN_FEATURES]
    assert positions == sorted(positions), "Zeek columns must appear in DBSCAN_FEATURES order"
    for name in bakeoff.DBSCAN_FEATURES[:8]:
        assert bakeoff._BASE_SQL[name] in select
    assert "flagged" in select and "prod_isolation" in select
    assert "LIMIT" not in sql.upper(), "the evaluation needs every window, not a sample"
    assert "isIPAddressInRange(a.src_addr, '203.0.113.0/24')" in sql


def test_matrix_sql_uses_the_flagged_predicate() -> None:
    sql = bakeoff.matrix_sql("2026-11-12 00:00:00", "2026-11-13 00:00:00", ["203.0.113.0/24"])
    assert "severity IN ('high','critical')" in sql
    assert "toStartOfFiveMinutes(window_start)" in sql


def test_parse_fold_spec_keeps_timestamps_intact() -> None:
    fold = bakeoff.parse_fold_spec(
        "F1,2026-11-13 00:00:00,2026-11-16 00:00:00,2026-11-16 00:00:00,2026-11-17 00:00:00")
    assert fold.name == "F1"
    assert fold.train_start == "2026-11-13 00:00:00"
    assert fold.test_end == "2026-11-17 00:00:00"


def test_parse_fold_spec_rejects_a_short_spec() -> None:
    with pytest.raises(SystemExit):
        bakeoff.parse_fold_spec("F1,2026-11-13 00:00:00,2026-11-16 00:00:00")


def test_stable_order_is_deterministic_and_complete() -> None:
    host = np.array(["a", "a", "b", "b"])
    t = np.array([np.datetime64("2026-11-13T00:00"), np.datetime64("2026-11-13T00:05"),
                  np.datetime64("2026-11-13T00:00"), np.datetime64("2026-11-13T00:05")])
    first = bakeoff.stable_order(host, t)
    second = bakeoff.stable_order(host, t)
    assert np.array_equal(first, second)
    assert sorted(first.tolist()) == [0, 1, 2, 3]


def test_split_fit_calibration_is_disjoint_and_covers_every_row() -> None:
    order = np.arange(30)
    fit, cal = bakeoff.split_fit_calibration(order)
    assert set(fit.tolist()) & set(cal.tolist()) == set()
    assert sorted(fit.tolist() + cal.tolist()) == list(range(30))
    assert len(cal) == 10


def test_distinct_stats_reports_a_constant_score_as_degenerate() -> None:
    scores = np.full(10, 0.99)
    host = np.array(["a"] * 5 + ["b"] * 5)
    stats = bakeoff.distinct_stats(scores, host)
    assert stats["distinct"] == 1
    assert stats["modal_share"] == 1.0
    assert stats["per_host_median"] == 1.0


def test_wilson_interval_brackets_the_estimate() -> None:
    lo, hi = bakeoff.wilson(10, 1000)
    assert lo < 0.01 < hi
    assert lo == pytest.approx(0.0054, abs=5e-4)


def test_alert_persistence_counts_a_consecutive_run() -> None:
    t = np.datetime64("2026-11-13T00:00") + np.arange(6) * np.timedelta64(5, "m")
    host = np.array(["a"] * 6)
    scores = np.array([0.0, 2.0, 2.0, 0.0, 2.0, 0.0])
    out = bakeoff.alert_persistence(scores, host, t, threshold=1.0)
    # three alerts; three of the five consecutive pairs start on an alert, and exactly one of
    # those three is followed by another alert.
    assert out["p_alert_next_given_alert"] == pytest.approx(1 / 3)
    assert out["chance"] == pytest.approx(3 / 6)


def test_coverage_stats_separates_full_from_partial_rows() -> None:
    X = np.array([[1.0, 2.0], [np.nan, 2.0], [3.0, 4.0]])
    scores = np.array([0.1, 0.9, 0.2])
    out = bakeoff.coverage_stats(scores, X)
    assert out["rows_full_coverage"] == 2
    assert out["score_p50_full"] == pytest.approx(0.15)
    assert out["score_p50_partial"] == pytest.approx(0.9)
