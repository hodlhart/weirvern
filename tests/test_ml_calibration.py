"""The calibration layer must be a budget, not a decorative statistic."""
from pathlib import Path

import numpy as np

from weirvern.models.calibration import (
    conformal_pvalue,
    conformal_threshold,
    fit,
)


def test_conformal_threshold_is_the_expected_order_statistic():
    ref = list(range(100))
    # alpha=0.10 -> ceil(101*0.90)=91 -> the 91st smallest (index 90).
    assert conformal_threshold(ref, 0.10) == 90.0


def test_conformal_pvalue_is_small_for_a_tail_score():
    ref = list(range(100))
    assert conformal_pvalue(99, ref) < 0.05
    assert conformal_pvalue(0, ref) > 0.95


def test_fit_reports_a_validation_false_alarm_rate_near_the_target():
    rng = np.random.default_rng(7)
    ref = rng.normal(size=1000)
    cal = fit(ref, 0.10)
    assert cal is not None
    assert cal.sample_count == 1000
    assert cal.validation_count == 500
    assert 0.02 <= cal.observed_far <= 0.20, cal
    assert cal.threshold < cal.p99  # a 10% budget sits inside the p95 tail


def test_fit_refuses_a_reference_set_too_small_to_say_anything():
    assert fit(list(range(19)), 0.01) is None


def test_the_calibration_tables_are_shipped_and_append_only():
    root = Path(__file__).resolve().parents[1]
    sql = (root / "weirvern" / "schema" / "030_ml_calibration.sql").read_text()
    for table in ("ml_calibration", "ml_calibration_history"):
        assert f"weirvern.{table}" in sql
    assert "ReplacingMergeTree" in sql
    assert "MergeTree" in sql
    assert "reference_source" in sql
