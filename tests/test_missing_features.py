"""Null-preserving missing-data handling — the `ml_missing_features` contract.

THE OPERATOR'S REQUIREMENT: "we have to be able to use the ml even if we are missing the data.
can we just log it as null until it comes in?" These tests pin that sentence:

  * a source that was not measured is None (and NaN in a training matrix), never 0;
  * a MEASURED zero stays 0 — the two facts are not allowed to collapse;
  * with the flag OFF every path is the one that existed before (same preprocessor, same
    vector, same width), and with it ON the neutral is the TRAINING median and the missing
    indicator is set;
  * a window below the coverage floor is excluded from the calibration fit and the FAR
    measurement, and the detector row says "insufficient telemetry" instead of quoting a rate;
  * DBSCAN abstains below the floor and otherwise measures distance over observed dimensions.

The flag is OFF by default, and one of these tests exists only to keep it that way.
"""
from __future__ import annotations

import math
from datetime import datetime

import numpy as np
import pytest

from weirvern.config import ModelConfig, Settings
from weirvern.ensemble import detect_flows
from weirvern.features import (
    DBSCAN_FEATURES,
    IF_FEATURES,
    TELEMETRY_FEATURES,
    extract_features,
    feature_vector,
)
from weirvern.models.calibration import fit, run, usable_scores
from weirvern.models.detector_status import (
    DEFAULT_MIN_COVERAGE,
    INSUFFICIENT_TELEMETRY,
    detector_rows,
)
from weirvern.models.detectors import (
    DBSCANDetector,
    IsolationForestDetector,
    RobustPreprocessor,
)
from weirvern.models.missing import (
    MissingAwarePreprocessor,
    coverage,
    masked_distance,
    null_absent_zeek,
)
from weirvern.zeek_features import (
    ZEEK_DNS_FEATURES,
    ZEEK_GRAPH_FEATURES,
    extract_zeek_features,
)

WINDOW = datetime(2026, 11, 19, 8, 0, 0)


def _flow(**overrides):
    base = {"src_addr": "198.51.100.10", "window_start": WINDOW, "total_bytes": 1000,
            "total_packets": 10, "unique_dst_ips": 2, "flow_count": 4}
    base.update(overrides)
    return base


# ── assembly: null vs measured zero ──────────────────────────────────────────────────────────

def test_a_missing_source_is_none_and_a_measured_zero_stays_zero():
    absent = extract_features(_flow(), preserve_missing=True)
    # No diversity table, no temporal table, no Zeek row: these were never measured.
    assert absent["log_unique_dst_ports"] is None
    assert absent["port_entropy"] is None
    assert absent["bytes_stddev_norm"] is None
    assert absent["activity_regularity"] is None
    assert absent["burstiness"] is None
    assert absent["zeek_dns_count"] is None
    assert absent["zeek_present"] is None
    # ...while a measured zero is still a zero. The flow's own aggregates were read.
    assert absent["log_bytes"] == math.log1p(1000)
    assert absent["log_flow_count"] == math.log1p(4)
    assert absent["is_business_hours"] in (0.0, 1.0)

    # A flow with no window has no time of day to encode; the historical zeros would be a
    # fabricated midnight rather than a measurement.
    timeless = extract_features({"total_bytes": 10, "total_packets": 1},
                                preserve_missing=True)
    assert timeless["hour_sin"] is None and timeless["is_business_hours"] is None

    # A diversity row that exists and reports zero ports is a MEASUREMENT of zero.
    measured = extract_features(
        _flow(), diversity={"unique_dst_ports": 0, "port_entropy": 0.0,
                            "bytes_stddev": 0.0, "unique_connections": 0},
        preserve_missing=True,
    )
    assert measured["log_unique_dst_ports"] == 0.0
    assert measured["port_entropy"] == 0.0

    # A Zeek row with no SSH conversations is a measured zero for that family.
    zeek = {"zeek_present": 1, "zeek_conn_count": math.log1p(3), "zeek_ssh_count": 0}
    f = extract_features(_flow(), zeek=zeek, preserve_missing=True)
    assert f["zeek_ssh_count"] == 0.0
    assert f["zeek_conn_count"] == math.log1p(3)


def test_the_legacy_assembly_still_returns_the_constant_zeroes():
    """With the flag off, the dict is the one the deployed models were trained on."""
    f = extract_features(_flow())
    assert f["log_unique_dst_ports"] == 0.0
    assert f["activity_regularity"] == 1.0
    assert f["zeek_dns_count"] == 0.0
    assert all(value is not None for value in f.values())


def test_an_absent_zeek_row_is_none_but_an_absent_dns_family_is_also_none():
    blank = extract_zeek_features({}, None, preserve_missing=True)
    assert blank["zeek_present"] is None
    assert all(blank[name] is None for name in ZEEK_DNS_FEATURES)

    # Conn was observed, DNS was not: the 13 DNS features are missing, the SSH zero is real.
    row = {"zeek_present": 1, "zeek_conn_count": math.log1p(5), "zeek_dns_count": 0,
           "zeek_ssh_count": 0}
    out = extract_zeek_features(row, None, preserve_missing=True)
    assert all(out[name] is None for name in ZEEK_DNS_FEATURES)
    assert all(out[name] is None for name in ZEEK_GRAPH_FEATURES)
    assert out["zeek_ssh_count"] == 0.0
    assert out["zeek_present"] == 1.0

    # And the legacy reader is unchanged: the same row reads as zeroes.
    legacy = extract_zeek_features(row, None)
    assert legacy["zeek_dns_count"] == 0.0
    assert legacy["zeek_graph_fan_in"] == 0.0


def test_the_training_matrix_recovers_absence_as_nan():
    names = list(IF_FEATURES)
    X = np.zeros((2, len(names)), dtype=float)
    dns = names.index("zeek_dns_count")
    ssh = names.index("zeek_ssh_count")
    # Row 1 has a Zeek conn row but no DNS row.
    X[1, names.index("zeek_present")] = 1.0
    X[1, names.index("zeek_conn_count")] = 1.0
    out = null_absent_zeek(X, names)
    # Row 0: no Zeek row at all -- every Zeek column is unmeasured.
    for name in ("zeek_present", "zeek_conn_count", "zeek_dns_count", "zeek_ssh_count"):
        assert np.isnan(out[0, names.index(name)])
    # Row 1: DNS is unmeasured, SSH is a measured zero.
    assert np.isnan(out[1, dns])
    assert out[1, ssh] == 0.0
    # The caller's matrix is untouched (it is the Gradient Boosting student's input too).
    assert X[1, dns] == 0.0


# ── scoring: OFF is the old path, ON imputes the neutral + indicator ────────────────────────

def test_flag_off_scores_the_legacy_vector_byte_for_byte(tmp_path):
    feats = {"log_bytes": 1.5, "port_entropy": 2.0}
    vec = feature_vector(feats, IF_FEATURES)
    assert vec == [feats.get(name, 0.0) for name in IF_FEATURES]

    det = IsolationForestDetector(tmp_path, ModelConfig())
    assert isinstance(det.preprocessor, RobustPreprocessor)
    det.preprocessor.fit_transform(np.tile(np.linspace(0.0, 1.0, len(IF_FEATURES)), (3, 1)))

    captured = {}

    class Stub:
        def score_samples(self, matrix):
            captured["X"] = matrix
            return np.array([-0.7])

    det.model = Stub()
    det.calibration = {"p01": -1.0, "p05": -0.5, "p50": 0.0}
    det.predict({}, feats)

    expected = det.preprocessor.transform(np.asarray([vec], dtype=float))
    assert captured["X"].shape == (1, len(IF_FEATURES))  # no indicator columns
    assert np.array_equal(captured["X"], expected)


def test_the_missing_aware_preprocessor_imputes_the_training_median_and_flags_it():
    X = np.array([[1.0, 10.0], [2.0, 20.0], [3.0, 30.0], [4.0, 40.0], [5.0, 50.0]])
    pre = MissingAwarePreprocessor()
    pre.fit_transform(X)
    assert pre.neutral_[0] == 3.0 and pre.neutral_[1] == 30.0

    out = pre.transform(np.array([[np.nan, 35.0]]))
    assert out.shape == (1, 4)  # two values + two indicators
    # The imputed value is the neutral, so after standardisation it sits at the column mean.
    assert out[0, 0] == pytest.approx(0.0, abs=1e-12)
    assert out[0, 2] == 1.0   # column 0 was missing
    assert out[0, 3] == 0.0   # column 1 was observed

    partial, observed = pre.transform_with_mask(np.array([[np.nan, 35.0]]))
    assert observed.tolist() == [[False, True]]
    assert partial.shape == (1, 4)


def test_flag_on_sets_the_indicator_for_the_missing_feature(tmp_path):
    det = IsolationForestDetector(tmp_path, ModelConfig(missing_features=True))
    assert isinstance(det.preprocessor, MissingAwarePreprocessor)
    training = np.tile(np.linspace(0.0, 1.0, len(IF_FEATURES)), (5, 1))
    training[0, IF_FEATURES.index("zeek_dns_count")] = np.nan
    det.preprocessor.fit_transform(training)

    captured = {}

    class Stub:
        def score_samples(self, matrix):
            captured["X"] = matrix
            return np.array([-0.7])

    det.model = Stub()
    det.calibration = {"p01": -1.0, "p05": -0.5, "p50": 0.0}
    features = {name: 0.0 for name in IF_FEATURES}
    features["zeek_dns_count"] = None
    det.predict({}, features)

    matrix = captured["X"]
    assert matrix.shape == (1, 2 * len(IF_FEATURES))
    assert matrix[0, len(IF_FEATURES) + IF_FEATURES.index("zeek_dns_count")] == 1.0
    assert np.isfinite(matrix).all()


def test_the_flag_defaults_to_off_everywhere(tmp_path):
    assert ModelConfig().missing_features is False
    assert ModelConfig().min_feature_coverage == DEFAULT_MIN_COVERAGE
    assert Settings().ml_missing_features is False
    # Every vector-based detector is on the legacy preprocessor unless the flag says otherwise.
    assert isinstance(IsolationForestDetector(tmp_path, ModelConfig()).preprocessor,
                      RobustPreprocessor)
    assert isinstance(DBSCANDetector(tmp_path, ModelConfig()).preprocessor, RobustPreprocessor)
    with pytest.raises(ValueError):
        Settings(ml_min_feature_coverage=1.5).validate()


def test_the_worker_folds_the_operator_flag_into_the_model_config():
    """The env/ConfigMap key is only real if it reaches the object the detectors read."""
    from weirvern.worker import model_config  # noqa: PLC0415

    enabled = model_config(Settings(ml_missing_features=True, ml_min_feature_coverage=0.4))
    assert enabled.missing_features is True
    assert enabled.min_feature_coverage == 0.4

    default = model_config(Settings())
    assert default.missing_features is False
    assert default.min_feature_coverage == DEFAULT_MIN_COVERAGE


def test_the_indicator_names_are_explicit_and_recorded():
    from weirvern.models.missing import model_input_columns  # noqa: PLC0415

    assert model_input_columns(["a", "b"]) == ["a", "b", "a__missing", "b__missing"]
    assert model_input_columns(["a"], indicators=False) == ["a"]


def test_an_artifact_from_the_other_mode_is_refused(tmp_path):
    """Flipping the flag holds every existing artifact out until it retrains."""
    trained = IsolationForestDetector(tmp_path, ModelConfig(missing_features=True))
    trained.metadata.feature_columns = list(IF_FEATURES)
    trained.metadata.params = {"missing_features": True}
    trained.save()

    old_mode = IsolationForestDetector(tmp_path, ModelConfig(missing_features=False))
    assert old_mode.load() is False, "an ON-trained artifact must not serve an OFF runtime"
    same_mode = IsolationForestDetector(tmp_path, ModelConfig(missing_features=True))
    assert same_mode.load() is True


# ── DBSCAN: abstain, or mask the unobserved dimensions ──────────────────────────────────────

def test_dbscan_abstains_below_the_floor_and_scores_above_it(tmp_path):
    det = DBSCANDetector(tmp_path, ModelConfig(missing_features=True))
    det.preprocessor.fit_transform(np.tile(np.linspace(0.0, 1.0, len(DBSCAN_FEATURES)), (4, 1)))
    det.cluster_centers = [np.zeros(len(DBSCAN_FEATURES))]
    det.calibration = {"p50": 0.5, "p95": 1.0, "p99": 2.0}

    all_missing = {name: None for name in DBSCAN_FEATURES}
    assert det.predict({}, all_missing) == 0.0, "DBSCAN must abstain, not cluster a guess"

    measured = {name: 0.0 for name in DBSCAN_FEATURES}
    assert math.isfinite(det.predict({}, measured))


def test_masked_distance_uses_only_observed_dimensions_and_rescales():
    centre = np.zeros(2)
    # Both observed: the ordinary Euclidean distance.
    assert masked_distance(np.array([3.0, 4.0]), centre, np.array([True, True])) == 5.0
    # One observed: the observed leg, rescaled to the full vector's width.
    assert masked_distance(np.array([3.0, 4.0]), centre,
                           np.array([True, False])) == pytest.approx(3.0 * math.sqrt(2))
    assert masked_distance(np.array([3.0, 4.0]), centre,
                           np.array([False, False])) == float("inf")


# ── calibration: insufficient windows are not evidence ─────────────────────────────────────

def test_a_window_below_the_coverage_floor_is_excluded_from_fit_and_far():
    rows = [(0.90, 0.02)] * 20 + [(0.99, 1.00)] * 20
    kept, excluded = usable_scores(rows, DEFAULT_MIN_COVERAGE)
    assert len(kept) == 20 and excluded == 20
    cal = fit(kept, 0.01)
    assert cal is not None
    assert cal.sample_count == 20, "the reference fit must not see the excluded windows"
    assert cal.observed_far <= 1.0

    # A NULL coverage is NOT an exclusion: the flag was off when those rows were written.
    kept_unknown, excluded_unknown = usable_scores([(0.5, None)] * 25, DEFAULT_MIN_COVERAGE)
    assert len(kept_unknown) == 25 and excluded_unknown == 0


def test_calibration_records_the_exclusion_on_the_row():
    class Result:
        def __init__(self, rows):
            self.result_rows = rows

    class FakeClient:
        def __init__(self):
            self.inserts = []

        def query(self, sql, parameters=None):
            if "FROM weirvern.ml_window_scores" in sql:
                names = ("Isolation Forest", "Gradient Boosting", "KNN distance", "LOF",
                         "Adaptive Baseline")
                rows = []
                for name in names:
                    rows.extend([name, 0.9, 0.02] for _ in range(20))
                    rows.extend([name, 0.99, 0.90] for _ in range(20))
                return Result(rows)
            raise AssertionError(sql)

        def insert(self, table, rows, column_names=None):
            self.inserts.append((table, rows, column_names))

    client = FakeClient()
    rows = run(client, Settings(ml_min_feature_coverage=0.15))
    pooled = [row for row in rows if row["scope"] == "global"]
    assert len(pooled) == 5  # one per live detector; the fused score has no population here
    for row in pooled:
        assert row["sample_count"] == 20
        assert row["excluded_windows"] == 20
        assert "excluded 20 window(s)" in row["reference_source"]
    # Every model also gets a coverage-stratum row. 20 windows cannot resolve a 1% budget, so
    # the stratum explicitly borrows the pooled threshold and says so.
    strata = [row for row in rows if row["scope"] == "coverage"]
    assert strata and all("FELL BACK to the pooled threshold" in r["reference_source"]
                          for r in strata)


# ── the detector table's fifth state ────────────────────────────────────────────────────────

def _detector_row(*, coverage_value, observed=0.0, target=0.01):
    return detector_rows(
        {"KNN distance": {"trained_at": "2026-11-19 08:21:17", "samples": 5000}},
        {"KNN distance": {"version": "v5", "written_at": "2026-11-19T08:22:00+00:00"}},
        {"KNN distance": {"observed_far": observed, "target_far": target,
                          "coverage": coverage_value}},
        {"KNN distance": "production"},
        min_coverage=DEFAULT_MIN_COVERAGE,
    )[0]


def test_the_detector_row_says_insufficient_telemetry_rather_than_a_score():
    row = _detector_row(coverage_value=0.02)
    assert row["status"] == INSUFFICIENT_TELEMETRY
    assert row["insufficient_telemetry"] is True
    assert row["contributing"] is False
    assert row["eligible"] is False
    # NO NUMBER: there was no measurement this rate could have come from.
    assert "0.00" not in row["status"]


def test_a_detector_with_measured_coverage_still_reports_its_budget():
    row = _detector_row(coverage_value=0.80)
    assert row["status"] == "contributing"
    assert row["insufficient_telemetry"] is False


# ── the ensemble records what it measured ───────────────────────────────────────────────────

class _Detector:
    """The smallest thing `detect_flows` will accept in its detector list."""

    name = "Isolation Forest"

    def predict(self, flow, features):
        return 0.0


def test_the_population_row_carries_coverage_and_the_exclusion_decision():
    settings = Settings()
    enabled = ModelConfig(missing_features=True, min_feature_coverage=0.5)
    population: list[dict] = []
    detect_flows([_flow()], [_Detector()], settings, enabled, score_population=population)
    assert len(population) == 1
    sample = population[0]
    # The flow features were measured; the 63 Zeek and the diversity/temporal columns were not.
    expected = coverage(extract_features(_flow(), preserve_missing=True), TELEMETRY_FEATURES)
    assert sample["coverage"] == pytest.approx(expected)
    assert expected < 0.5
    assert sample["excluded"] is True
    # A detector that declares no vector contract is measured over the whole telemetry union.
    assert sample["model_coverage"] == {"Isolation Forest": pytest.approx(expected)}

    disabled_population: list[dict] = []
    detect_flows([_flow()], [_Detector()], settings, ModelConfig(),
                 score_population=disabled_population)
    assert disabled_population[0]["coverage"] is None
    assert disabled_population[0]["excluded"] is False


def test_the_baseline_skips_the_behavioural_term_when_zeek_was_not_measured(tmp_path):
    """A missing feature is not a zero: the behavioural term is skipped, not priced as idle."""
    from weirvern.models.detectors import AdaptiveBaselineDetector  # noqa: PLC0415

    detector = AdaptiveBaselineDetector(tmp_path, ModelConfig(missing_features=True))
    detector.baselines["198.51.100.10"] = {
        "avg_bytes": 1000.0, "stddev_bytes": 10.0,
        "avg_packets": 10.0, "stddev_packets": 1.0,
        "avg_unique_dsts": 2.0, "stddev_unique_dsts": 1.0,
        "p95_bytes": 1500.0, "p99_bytes": 2000.0, "p999_bytes": 3000.0,
        "p95_packets": 15.0, "p99_packets": 20.0, "p999_packets": 30.0,
        "zeek_seen": True, "avg_conn": 5.0, "stddev_conn": 2.0,
        "avg_s0": 0.1, "stddev_s0": 0.2, "avg_s0_count": -5.0, "stddev_s0_count": 1.0,
        "avg_notices": 0.0, "stddev_notices": 1.0, "avg_services": 2.0,
        # A deliberately impossible negative mean: a window of zeroes would read as a 5-sigma
        # event against it, so a HIGH zero-score proves the zero reached the arithmetic.
    }
    flow = {"src_addr": "198.51.100.10", "total_bytes": 1000.0, "total_packets": 10.0,
            "unique_dst_ips": 2.0}
    zeroes = detector.predict(flow, {name: 0.0 for name in IF_FEATURES})
    missing = detector.predict(flow, {name: None for name in IF_FEATURES})
    assert missing < zeroes, "a missing Zeek window was priced as a real, extreme observation"
    assert missing == detector.predict(flow, {})
