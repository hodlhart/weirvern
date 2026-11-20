from weirvern.models.scoring import (
    calibrate_isolation_forest,
    calibrate_probability,
    normalize_isolation_forest,
    normalize_probability,
    normalize_zscore,
    score_by_percentile,
)


def test_zscore_zero_below_shift():
    assert normalize_zscore(1.0) == 0.0
    assert normalize_zscore(2.5) == 0.0


def test_zscore_monotonic_and_capped():
    assert 0.0 < normalize_zscore(3.0) < 0.99
    assert normalize_zscore(3.5) > normalize_zscore(3.0)
    # Sigmoid saturates slowly through log-space; extreme z hits the 0.99 cap
    assert normalize_zscore(100.0) > 0.8
    assert normalize_zscore(1e9) == 0.99


def test_if_normalization():
    assert normalize_isolation_forest(0.5) == 0.0
    assert normalize_isolation_forest(-0.5) == min(0.99, 0.8)
    assert normalize_isolation_forest(-1.0) == 0.99


def test_probability_normalization():
    assert normalize_probability(0.4) == 0.0
    assert normalize_probability(0.5) == 0.0
    assert round(normalize_probability(0.9), 4) == round(0.792, 4)
    assert normalize_probability(1.0) == 0.99


def test_percentile_brackets():
    s = score_by_percentile
    assert s(50, 100, 200, 300) == 0.0
    assert 0.3 <= s(150, 100, 200, 300) <= 0.6
    assert 0.6 <= s(250, 100, 200, 300) <= 0.85
    assert 0.85 <= s(400, 100, 200, 300) <= 0.99
    assert s(1_000_000, 100, 200, 300) == 0.99


# --- percentile calibration of Isolation Forest scores -----------------------
CAL = {"p50": -0.05, "p05": -0.20, "p01": -0.25}


def test_calibration_zeroes_ordinary_traffic():
    """The bug this fixes: ordinary traffic saturated at ~0.8 with the fixed
    multiplier, making benign hosts score like a port scanner."""
    assert calibrate_isolation_forest(-0.04, CAL) == 0.0   # above median
    assert calibrate_isolation_forest(0.10, CAL) == 0.0    # clearly normal
    assert normalize_isolation_forest(-0.04) > 0.05        # old behaviour


def test_calibration_monotonic_and_bounded():
    prev = -1.0
    for s in (0.0, -0.05, -0.10, -0.20, -0.22, -0.25, -0.5, -1.0):
        v = calibrate_isolation_forest(s, CAL)
        assert v >= prev, f"not monotonic at {s}"
        assert 0.0 <= v <= 0.99
        prev = v


def test_calibration_tiers():
    assert calibrate_isolation_forest(-0.10, CAL) < 0.60   # between p50 and p05
    assert 0.60 <= calibrate_isolation_forest(-0.22, CAL) <= 0.85
    assert calibrate_isolation_forest(-1.0, CAL) >= 0.85   # beyond p01


def test_calibration_falls_back_without_data():
    assert calibrate_isolation_forest(-0.5, {}) == normalize_isolation_forest(-0.5)


# --- percentile calibration of classifier probabilities ----------------------
PCAL = {"p50": 0.02, "p90": 0.55, "p94": 0.80}


def test_probability_calibration_zeroes_ordinary_traffic():
    """The bug this fixes: 15x class-weighting pushed benign windows to ~0.97
    raw probability -> false-positive 'high' alerts on ordinary traffic."""
    assert calibrate_probability(0.01, PCAL) == 0.0    # below median
    assert calibrate_probability(0.02, PCAL) == 0.0    # at median
    assert normalize_probability(0.97) > 0.90          # old behaviour on that input


def test_probability_calibration_tiers_and_monotonic():
    prev = -1.0
    for p in (0.0, 0.02, 0.1, 0.4, 0.55, 0.7, 0.8, 0.9, 1.0):
        v = calibrate_probability(p, PCAL)
        assert v >= prev and 0.0 <= v <= 0.99, f"bad at {p}: {v} after {prev}"
        prev = v
    assert calibrate_probability(0.55, PCAL) <= 0.60
    assert 0.60 <= calibrate_probability(0.75, PCAL) <= 0.85
    assert calibrate_probability(0.99, PCAL) >= 0.85


def test_probability_calibration_fallback():
    assert calibrate_probability(0.9, {}) == normalize_probability(0.9)


def test_the_removed_distance_calibration_is_not_exported():
    """Its only caller was the removed density detector, so the helper went with it."""
    import weirvern.models.scoring as scoring

    assert not hasattr(scoring, "calibrate_distance")
