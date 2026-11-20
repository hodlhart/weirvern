"""The cross-sectional detectors and the coverage-stratified calibration they need.

WHY THIS FILE EXISTS. Replacing DBSCAN is not "add a model". Three separate claims have to hold,
and each one is a test here:

  1. the new scores are CONTINUOUS and a reference that cannot produce one is REFUSED, not
     shipped (DBSCAN's failure was a score constant on 98% of windows);
  2. a threshold is chosen PER COVERAGE STRATUM, because a partially observed window scores
     systematically lower and a single pooled bar silenced 35% of the population (0.00% alert rate
     on partial rows against 2.3-2.5% on full ones -- the measurement this change exists to fix);
  3. the new detectors are actually IN the fused score when eligible, are EXCLUDED when not, and
     DBSCAN is out of the ensemble with a payload that says why.
"""
from __future__ import annotations

from datetime import datetime
from types import SimpleNamespace

import numpy as np
import pytest

from weirvern.config import FUSED_MODEL, ModelConfig, Settings
from weirvern.ensemble import (
    MODEL_FAMILIES,
    contributing_scores,
    detect_flows,
    strong_model_families,
)
from weirvern.features import DBSCAN_FEATURES
from weirvern.models.calibration import (
    MIN_STRATUM_SAMPLES,
    coverage_stratum,
    fit_stratified,
)
from weirvern.models.detector_status import REFUSED, detector_rows
from weirvern.models.detectors import (
    KNNDistanceDetector,
    LOFDetector,
    cross_sectional_training_sql,
)
from weirvern.worker import build_detectors

DIM = len(DBSCAN_FEATURES)


# ── fixtures: a synthetic 19-feature population, and a client that serves it ──────────────────

def _matrix(rows: int = 400, *, seed: int = 7) -> list[tuple[float, ...]]:
    """Four separated blobs with real spread -- a population a distance can be measured in."""
    rng = np.random.default_rng(seed)
    centres = rng.normal(0.0, 4.0, size=(4, DIM))
    return [tuple(centres[i % 4] + rng.normal(0.0, 0.35, DIM)) for i in range(rows)]


class _Rows:
    def __init__(self, rows):
        self.result_rows = rows


class _MatrixClient:
    """The two queries a detector's train makes: the feature matrix and the scope table."""

    def __init__(self, rows):
        self.rows = rows
        self.queries: list[str] = []

    def query(self, sql, settings=None, parameters=None):  # noqa: ARG002 - signature parity
        self.queries.append(sql)
        if "network_scopes" in sql:
            return _Rows([])
        return _Rows(self.rows)

    def feature_query(self) -> str:
        return next(q for q in self.queries if "flows_window" in q)


def _train(detector, rows):
    client = _MatrixClient(rows)
    ok = detector.train(datetime(2026, 11, 16), datetime(2026, 11, 19), client)
    return ok, client


# ── 1. the score is continuous, and a degenerate reference is refused ────────────────────────

def test_knn_produces_a_continuous_score(tmp_path):
    rows = _matrix()
    det = KNNDistanceDetector(tmp_path, ModelConfig())
    ok, _ = _train(det, rows)
    assert ok, "a well-spread population must train"
    assert det.is_ready()

    scores = det.score(np.asarray(rows, dtype=float))
    assert np.isfinite(scores).all()
    assert float(scores.std()) > 0.0
    assert np.unique(np.round(scores, 9)).size > 100, (
        "the score is a step function, not a distance: "
        f"{np.unique(np.round(scores, 9)).size} distinct values over {scores.size} rows")


def test_a_constant_reference_is_refused_rather_than_shipped(tmp_path):
    """Every window identical => every distance 0 => no threshold can separate anything."""
    det = KNNDistanceDetector(tmp_path, ModelConfig())
    ok, _ = _train(det, [(1.0,) * DIM] * 200)

    assert ok is False, "a constant reference must not produce a detector"
    assert det.train_outcome == "degenerate-reference"
    assert det.is_ready() is False
    assert not det.artifact_path().exists(), "a refused fit must not leave an artifact on disk"
    # ... and it says "no opinion" rather than a number that would read as normal.
    assert det.predict({}, dict.fromkeys(DBSCAN_FEATURES, 1.0)) == 0.0


def test_the_reference_travels_with_the_artifact(tmp_path):
    """A distance is meaningless without the population it was measured against."""
    rows = _matrix()
    det = KNNDistanceDetector(tmp_path, ModelConfig())
    ok, _ = _train(det, rows)
    assert ok and det.artifact_path().exists()

    restored = KNNDistanceDetector(tmp_path, ModelConfig())
    assert restored.load() is True
    assert restored.is_ready()
    assert restored.reference_ is not None
    np.testing.assert_allclose(restored.score(np.asarray(rows, dtype=float)),
                               det.score(np.asarray(rows, dtype=float)))


def test_lof_has_its_own_artifact_and_bounded_statistic(tmp_path):
    rows = _matrix()
    knn = KNNDistanceDetector(tmp_path, ModelConfig())
    lof = LOFDetector(tmp_path, ModelConfig())
    assert _train(knn, rows)[0] and _train(lof, rows)[0]

    assert knn.artifact_path() != lof.artifact_path()
    assert knn.artifact_path().name == "KNN distance_v5.pkl"
    assert lof.artifact_path().name == "LOF_v5.pkl"

    statistic = lof.score(np.asarray(rows, dtype=float))
    assert np.isfinite(statistic).all()
    # log1p keeps the bake-off's 8.5e8 pathology at ~20.6, not at 850 million.
    assert float(np.max(statistic)) < 50.0


def test_lof_never_ships_a_threshold_in_the_hundreds_of_millions(tmp_path):
    """The bake-off's F4 fold produced a threshold of 8.5e8 -- a detector silently off.

    Either the fit is refused (the reference cannot produce a bounded score) or the bound holds.
    What must never happen is a persisted model whose score scale is astronomical.
    """
    rng = np.random.default_rng(11)
    rows = [(2.0,) * DIM] * 380 + [tuple(rng.normal(9.0, 1.0, DIM)) for _ in range(20)]
    det = LOFDetector(tmp_path, ModelConfig())
    ok, _ = _train(det, rows)
    if ok:
        p99 = float(np.percentile(det.score(np.asarray(rows, dtype=float)), 99))
        assert p99 < 50.0, f"LOF shipped a score on the 8.5e8 scale: p99={p99}"
    else:
        assert det.train_outcome == "degenerate-reference"
        assert not det.artifact_path().exists()


# ── 2. stratified conformal calibration ─────────────────────────────────────────────────────

def _stratified_population() -> list[tuple[float, str]]:
    """Two clean strata: partial windows score far lower than fully observed ones.

    This is the measured shape of the deployment, not an invented one: the 8/19 stratum sits at
    the imputed median on eleven columns and lands near the bottom of a pooled distance
    distribution (bake-off §5.1).
    """
    rng = np.random.default_rng(3)
    rows = [(float(rng.uniform(2.0, 6.0)), "19/19") for _ in range(1000)]
    rows += [(float(rng.uniform(0.0, 0.4)), "8/19") for _ in range(1000)]
    rows += [(float(rng.uniform(1.0, 3.0)), "16/19") for _ in range(30)]
    return rows


def test_each_stratum_gets_its_own_threshold():
    strat = fit_stratified(_stratified_population(), 0.01)
    assert strat is not None
    assert strat.threshold_for("8/19") < 0.45
    assert strat.threshold_for("19/19") > 5.0
    assert strat.threshold_for("8/19") != pytest.approx(strat.threshold_for("19/19"))


def test_a_sparse_stratum_falls_back_to_the_pooled_threshold_explicitly():
    strat = fit_stratified(_stratified_population(), 0.01)
    assert strat is not None
    assert "16/19" in strat.fallbacks
    assert strat.fallbacks["16/19"] == 30
    assert strat.threshold_for("16/19") == pytest.approx(strat.pooled.threshold)
    assert strat.min_samples == MIN_STRATUM_SAMPLES


def test_a_partially_observed_window_is_not_silently_normal():
    """THE REGRESSION, in one assertion pair: pooled silent, own stratum alerting."""
    rows = _stratified_population()
    strat = fit_stratified(rows, 0.01)
    assert strat is not None
    pooled = strat.threshold_for("")
    own = strat.threshold_for("8/19")
    highest_partial = max(score for score, key in rows if key == "8/19")
    assert highest_partial < pooled, (
        "the pooled bar sits above EVERY partial window -- that is the 0.00% alert rate the "
        f"bake-off measured (partial max {highest_partial:.3f}, pooled bar {pooled:.3f})")
    assert highest_partial >= own, "the stratum bar must make its own top 1% alertable"


def test_coverage_stratum_prefers_counts_and_buckets_a_bare_ratio():
    assert coverage_stratum(0.4211, 8, 19) == "8/19"
    assert coverage_stratum(0.4211) == "0.42"
    assert coverage_stratum(1.0) == "1.00"
    assert coverage_stratum(None) == "", "an unmeasured coverage is not a stratum"


def test_an_unknown_stratum_uses_the_pooled_threshold():
    strat = fit_stratified(_stratified_population(), 0.01)
    assert strat is not None
    assert strat.threshold_for("") == pytest.approx(strat.pooled.threshold)
    assert strat.for_stratum("19/19").threshold == pytest.approx(strat.threshold_for("19/19"))


# ── 3. DBSCAN is out; the new detectors are in ───────────────────────────────────────────────

def test_build_detectors_returns_the_five_live_models_and_no_dbscan(tmp_path):
    settings = SimpleNamespace(model_dir=str(tmp_path))
    names = [d.name for d in build_detectors(settings, ModelConfig())]
    assert names == ["Isolation Forest", "Gradient Boosting", "KNN distance", "LOF",
                     "Adaptive Baseline"]
    assert "DBSCAN" not in names


def test_dbscan_is_not_a_family_in_the_ensemble():
    assert "DBSCAN" not in MODEL_FAMILIES
    assert MODEL_FAMILIES["KNN distance"] != MODEL_FAMILIES["LOF"], (
        "two independent detectors must not collapse into one corroborating family")
    assert strong_model_families({"KNN distance": 0.9, "LOF": 0.9}, 0.85) == 2


def test_the_detectors_payload_says_dbscan_is_retired():
    """A retired detector has training rows and an artifact in history -- absence cannot say it."""
    rows = detector_rows(
        {"DBSCAN": {"trained_at": "2026-11-19 08:21:17", "samples": 5000}},
        {"DBSCAN": {"version": "v5", "written_at": "2026-11-19T08:22:00+00:00"}},
        {"DBSCAN": {"observed_far": 1.0, "target_far": 0.01}}, {},
    )
    dbscan = next(r for r in rows if r["name"] == "DBSCAN")
    assert dbscan["status"].startswith("retired -- removed from the ensemble on 2026-11-20")
    assert "scores were degenerate" in dbscan["status"]
    assert dbscan["contributing"] is False
    assert dbscan["eligible"] is False


def test_a_refused_fit_is_reported_as_a_degenerate_reference():
    rows = detector_rows(
        {"LOF": {"trained_at": "2026-11-20 10:00:00", "samples": 0}},
        {}, {"LOF": {"observed_far": 0.0, "target_far": 0.01}}, {"LOF": "production"},
        outcomes={"LOF": "degenerate-reference"},
    )
    lof = next(r for r in rows if r["name"] == "LOF")
    assert lof["status"] == REFUSED
    assert lof["trained"] is False
    assert lof["contributing"] is False


def test_the_training_query_no_longer_samples_one_host_in_five():
    sql = cross_sectional_training_sql("2026-11-13 00:00:00", "2026-11-16 00:00:00", ModelConfig())
    assert "% 5" not in sql
    assert "sipHash64(a.src_addr) %" not in sql, "the 1-in-5 HOST cut is still in the query"
    assert "ORDER BY sipHash64(a.src_addr, a.window_start)" in sql
    assert "LIMIT 5000" in sql


def test_the_detector_actually_runs_the_query_without_host_sampling(tmp_path):
    det = KNNDistanceDetector(tmp_path, ModelConfig())
    ok, client = _train(det, _matrix())
    assert ok
    sql = client.feature_query()
    assert "% 5" not in sql and "sipHash64(a.src_addr) %" not in sql


# ── 4. the fused score includes them -- proven, not assumed ──────────────────────────────────

class _FakeDetector:
    def __init__(self, name: str, score: float):
        self.name = name
        self._score = score

    def predict(self, flow, features=None):  # noqa: ARG002 - ensemble contract
        return self._score


def _fused(scores: dict[str, float], eligible: dict[str, bool] | None = None) -> float:
    """Run the real ensemble over fake detectors and read the fused score it produced."""
    from typing import Any

    detectors: list[Any] = [_FakeDetector(name, value) for name, value in scores.items()]
    population: list[dict] = []
    flow = {
        "src_addr": "198.51.100.10", "window_start": datetime(2026, 11, 19, 8, 0, 0),
        "total_bytes": 1000, "total_packets": 10, "unique_dst_ips": 2, "flow_count": 20,
    }
    detect_flows([flow], detectors, Settings(), ModelConfig(), eligible=eligible,
                 score_population=population)
    assert population, "detect_flows recorded no population row"
    return float(population[0]["scores"][FUSED_MODEL])


BASE = {"Isolation Forest": 0.50, "Gradient Boosting": 0.20, "Adaptive Baseline": 0.10}


def test_the_fused_score_changes_when_the_new_detectors_are_present_and_eligible():
    eligible = {name: True for name in (*BASE, "KNN distance", "LOF")}
    assert _fused(BASE, eligible) == pytest.approx(0.50)
    assert _fused({**BASE, "KNN distance": 0.91}, eligible) == pytest.approx(0.91)
    assert _fused({**BASE, "KNN distance": 0.91, "LOF": 0.94}, eligible) == pytest.approx(0.94)
    # Removing one changes the fused score back -- "in the ensemble" is an assertion, not a hope.
    assert _fused({**BASE, "LOF": 0.94}, eligible) == pytest.approx(0.94)
    assert _fused({**BASE, "KNN distance": 0.91}, eligible) == pytest.approx(0.91)


def test_an_uncalibrated_detector_is_excluded_from_the_fused_score_not_counted_as_zero():
    """The expected first state: trained, not yet calibrated. It must not set the fused score."""
    scores = {**BASE, "KNN distance": 0.97, "LOF": 0.40}
    # KNN is ABSENT from the mapping: no calibration row yet -> no met budget -> not eligible.
    eligible = {name: True for name in (*BASE, "LOF")}
    assert _fused(scores, eligible) == pytest.approx(0.50)
    # ... and an explicit False does the same.
    assert _fused(scores, {**eligible, "KNN distance": False, "LOF": False}) == pytest.approx(0.50)


def test_contributing_scores_drops_ineligible_models_instead_of_zeroing_them():
    kept = contributing_scores({"a": 0.5, "b": 0.9}, {"a": True, "b": False})
    assert kept == {"a": 0.5}, "a zeroed model still drags a mean fusion; it must be removed"
