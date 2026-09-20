from weirvern.models.scoring import (
    calibrate_distance,
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


# --- percentile calibration of DBSCAN distances -------------------------------
# The bug this fixes: the score was `min(0.99, distance / 5.0)` -- a magic divisor unrelated
# to the data. Tight clusters (typical distances ~1.5) mapped everything to <=0.3 and the
# detector could never corroborate; loose ones saturated at 0.99. Graded against the training
# distribution now, like every other detector.

DCAL = {"p50": 2.0, "p95": 4.0, "p99": 6.0}


def test_distance_calibration_zeroes_the_normal_half():
    """Half the training data sits at/below p50; ordinary traffic must score zero."""
    assert calibrate_distance(1.0, DCAL) == 0.0
    assert calibrate_distance(2.0, DCAL) == 0.0


def test_distance_calibration_tiers_and_monotonic():
    prev = -1.0
    for d in (0.0, 1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 12.0):
        v = calibrate_distance(d, DCAL)
        assert v >= prev, f"not monotonic at {d}"
        assert 0.0 <= v <= 0.99
        prev = v
    assert calibrate_distance(3.0, DCAL) <= 0.60          # p50..p95
    assert 0.60 <= calibrate_distance(5.0, DCAL) <= 0.85  # p95..p99
    assert calibrate_distance(12.0, DCAL) >= 0.85         # beyond p99


def test_distance_calibration_scales_with_the_cluster_tightness():
    """The point of calibrating: a distance of 3 is unremarkable for one deployment and
    extreme for another, and the same absolute number must score differently."""
    tight = {"p50": 0.5, "p95": 1.0, "p99": 1.5}
    loose = {"p50": 5.0, "p95": 10.0, "p99": 15.0}
    assert calibrate_distance(3.0, tight) >= 0.85, "3 sigma from a tight cluster is extreme"
    assert calibrate_distance(3.0, loose) <= 0.60, "3 sigma toward a loose cluster is ordinary"


def test_distance_calibration_falls_back_to_the_old_shape():
    """An artifact trained before the calibration existed must keep its behaviour until the
    next retrain replaces it -- not crash, not silently rescale."""
    assert calibrate_distance(2.5, {}) == min(0.99, 2.5 / 5.0)
