"""The detectors, rebuilt from the v19 model code with the lessons applied:

1. IsolationForestDetector — v19's 14-feature multi-granularity version with
   extremes sampling retained (trains on normal traffic AND extreme outliers).
2. GradientBoostingDetector — semi-supervised student of the Isolation Forest,
   class-imbalance weighted, F1-evaluated on a held-out split.
3. KNNDistanceDetector — cross-sectional distance to the k-th nearest reference window (k=10)
   on the 19-feature CROSS_SECTIONAL_FEATURES vector.
4. LOFDetector — local outlier factor (k=20, novelty=True) on the SAME 19-feature vector, as an
   INDEPENDENT detector: its own reference set, artifact, calibration and eligibility row.
5. AdaptiveBaselineDetector — per-host percentile/σ baselines from ClickHouse.

`DETECTOR_NAMES` is the engine's roster, and it is what the Detectors table renders: a name outside
it has no row, because a detector that is no longer built no longer exists (it is not "retired" --
there is nothing to retire).

Changes vs legacy: SQL is parameterized and lives close to the models; all
magic numbers come from weirvern.config.ModelConfig; training always
persists artifacts; predict() is pure (no DB calls).
"""
from __future__ import annotations

import logging
import math
import time
from datetime import datetime
from typing import Any

import numpy as np
from clickhouse_connect.driver.client import Client
from sklearn.ensemble import GradientBoostingClassifier, IsolationForest
from sklearn.impute import SimpleImputer
from sklearn.metrics import f1_score
from sklearn.model_selection import train_test_split
from sklearn.neighbors import LocalOutlierFactor, NearestNeighbors
from sklearn.preprocessing import StandardScaler

from weirvern import flow_windows, networks
from weirvern.config import ModelConfig
from weirvern.features import CROSS_SECTIONAL_FEATURES, IF_FEATURES, feature_vector
from weirvern.models.base import BaseDetector, ModelMetadata
from weirvern.models.calibration import COVERAGE_CONTRACT, register_model_contract
from weirvern.models.missing import (
    DEFAULT_MIN_COVERAGE,
    MissingAwarePreprocessor,
    below_floor,
    model_input_columns,
    null_absent_zeek,
)
from weirvern.models.scoring import (
    calibrate_isolation_forest,
    calibrate_probability,
    normalize_zscore,
    score_by_percentile,
)
from weirvern.zeek_features import (
    ZEEK_CROSS_SECTIONAL_FEATURES,
    ZEEK_FEATURES,
    ZEEK_JOIN_ON,
    zeek_baseline_ja4_sql,
    zeek_baseline_sql,
    zeek_join_cte,
)

logger = logging.getLogger(__name__)

QUERY_SETTINGS = {"max_memory_usage": 4_000_000_000, "max_execution_time": 120}



def _zeek_clause(start: str, end: str, columns: list[str] | None = None) -> tuple[str, str, str]:
    """(with-clause, select-list, join-clause) for the Zeek side of a training query.

    One helper for every detector. Duplicating the join per detector is how the models
    drift apart: three training on one window and the fourth on a slightly different key,
    which no metric would show and which would appear only as one detector disagreeing with
    the others for no stated reason.

    `columns` selects which Zeek features to include. The DEFAULT is all of them, matching
    IF_FEATURES; the cross-sectional pair passes its smaller set, because a distance in a
    high-dimensional space stops separating anything when samples are few.
    """
    if columns is None:
        columns = ZEEK_FEATURES
    select = ",\n".join(f"                z.{c}" for c in columns)
    return zeek_join_cte(start, end), select, ZEEK_JOIN_ON


def _flagged_exclusion_clause(start: str, end: str, cfg: ModelConfig) -> str:
    """WHERE-fragment excluding host-windows the system already flagged, or "" to disable.

    WHY THIS EXISTS: a training window is the last RETRAIN_WINDOW_H of traffic, which
    includes any ongoing incident. Isolation Forest's contamination~6% EXPECTS outliers in
    training, so a sustained attack lasting days quietly becomes part of the learned
    "normal" -- and no metric can show it, because the model looks healthiest exactly when
    it has stopped recognising the thing it was trained on.

    The exclusion uses the system's OWN prior detections: rows in netflow_anomalies at
    high/critical severity for the same (host, window). It is the minimum defence rather
    than the full one -- a slow attack that never reaches those tiers still trains in, and
    the stronger design (a frozen benign baseline with champion/challenger disagreement as
    its own signal) remains on the audit backlog. But between "trust every row" and "use
    the rows we already decided were anomalous", this is strictly the better half.

    Returns a fragment that begins with "AND", or "" when disabled -- callers splice it
    after their own WHERE conditions, so a disabled clause changes nothing.
    """
    if not getattr(cfg, "exclude_flagged_from_training", True):
        return ""
    # The severity tiers are the ones severity_of can emit; 'medium' and below are NOT
    # excluded, deliberately -- ordinary noise and tuning misses must remain trainable,
    # or the exclusion list grows to swallow the whole segment.
    #
    # TUPLE NOT IN rather than NOT EXISTS with a correlated subquery: ClickHouse's
    # correlated-subquery support is deliberately limited, while tuple membership
    # against a derived table is a first-class form. VERIFIED against a live
    # clickhouse-server:26.8 (the deployed image), including that the filter actually
    # drops flagged rows and leaves everything else -- see test_ml_hygiene_exclusion.py.
    return f"""
              AND (a.src_addr, toStartOfFiveMinutes(a.window_start)) NOT IN (
                  SELECT src_addr, toStartOfFiveMinutes(window_start)
                  FROM weirvern.netflow_anomalies
                  WHERE window_start BETWEEN '{start}' AND '{end}'
                    AND severity IN ('high', 'critical')
              )"""


class RobustPreprocessor:
    """Median impute + standardize, fitted once (legacy RobustDataPreprocessor)."""

    def __init__(self) -> None:
        self.imputer = SimpleImputer(strategy="median")
        self.scaler = StandardScaler()
        self.fitted = False

    def fit_transform(self, X: np.ndarray) -> np.ndarray:
        X = np.nan_to_num(X)
        X = self.imputer.fit_transform(X)
        X = self.scaler.fit_transform(X)
        self.fitted = True
        return X

    def transform(self, X: np.ndarray) -> np.ndarray:
        if not self.fitted:
            raise ValueError("Preprocessor not fitted")
        return self.scaler.transform(self.imputer.transform(np.nan_to_num(X)))


Preprocessor = RobustPreprocessor | MissingAwarePreprocessor


def _preprocessor_for(cfg: ModelConfig, *, indicators: bool = True) -> Preprocessor:
    """The preprocessor this configuration calls for.

    OFF (the default) is the historical median-impute-over-`nan_to_num` object, byte for
    byte. ON is the missing-aware one, which keeps NaN through the fit so the median is the
    training-time neutral rather than the median of a matrix that already turned every
    absence into 0.
    """
    if getattr(cfg, "missing_features", False):
        return MissingAwarePreprocessor(indicators=indicators)
    return RobustPreprocessor()


def _floor(cfg: ModelConfig) -> float:
    """The coverage floor, with an explicit None check (0.0 is a valid, disabling value)."""
    value = getattr(cfg, "min_feature_coverage", DEFAULT_MIN_COVERAGE)
    return DEFAULT_MIN_COVERAGE if value is None else float(value)


# ============================================================================
class IsolationForestDetector(BaseDetector):
    name = "Isolation Forest"

    def __init__(self, model_dir, cfg: ModelConfig | None = None):
        super().__init__(model_dir)
        self.cfg = cfg or ModelConfig()
        self.model: IsolationForest | None = None
        self.preprocessor: Preprocessor = _preprocessor_for(self.cfg)
        self.X_train_unscaled: np.ndarray | None = None
        # Percentile calibration of score_samples (set at train time)
        self.calibration: dict[str, float] = {}

    def is_ready(self) -> bool:
        return self.model is not None and self.preprocessor.fitted

    def expected_feature_columns(self) -> list[str]:
        return list(IF_FEATURES)


    def train(self, start_dt: datetime, end_dt: datetime, client: Client) -> bool:
        st = time.time()
        s, e = start_dt.strftime("%Y-%m-%d %H:%M:%S"), end_dt.strftime("%Y-%m-%d %H:%M:%S")
        zeek_cte, zeek_cols, zeek_join = _zeek_clause(s, e)
        # Training hygiene: do not learn from windows the system already flagged (see
        # _flagged_exclusion_clause). Empty string when disabled.
        excl = _flagged_exclusion_clause(s, e, self.cfg)
        # A model trained on hosts the operator did not declare is a model fitted to a
        # different population than the one it will alert on. Empty when no scopes exist.
        scope_filter = networks.training_filter(client)
        q = f"""  # nosec B608 - interpolates formatted datetimes + int config only, never flow data
            WITH {zeek_cte}
            SELECT
                log(a.total_bytes + 1),
                log(a.total_packets + 1),
                a.total_bytes / NULLIF(a.total_packets, 0),
                sin(2*pi()*toHour(a.window_start)/24),
                cos(2*pi()*toHour(a.window_start)/24),
                sin(2*pi()*toDayOfWeek(a.window_start)/7),
                cos(2*pi()*toDayOfWeek(a.window_start)/7),
                if(toHour(a.window_start) BETWEEN 8 AND 18 AND toDayOfWeek(a.window_start) < 6, 1, 0),
                log(a.unique_dst_ips + 1),
                log(a.flow_count + 1),
                log(coalesce(d.unique_dst_ports, 0) + 1),
                coalesce(d.port_entropy, 0),
                coalesce(d.bytes_stddev, 0) / NULLIF(a.total_bytes, 0),
                coalesce(d.unique_connections, a.flow_count) / NULLIF(a.flow_count, 1),
{zeek_cols}
            FROM {flow_windows.folded(flow_windows.between(s, e))}
            LEFT JOIN weirvern.flows_aggregated_diversity d
                ON a.window_start = d.window_start AND a.src_addr = d.src_addr
            {zeek_join}
            WHERE a.window_start BETWEEN '{s}' AND '{e}'
              AND a.total_bytes > 0
              AND (
                  sipHash64(a.src_addr, a.window_start) % 10 < 7
                  OR a.total_bytes IN (
                      SELECT total_bytes FROM (
                          SELECT window_start, src_addr, sumMerge(total_bytes) AS total_bytes
                          FROM weirvern.flows_window
                          WHERE window_start BETWEEN '{s}' AND '{e}'
                          GROUP BY window_start, src_addr)
                      ORDER BY total_bytes DESC LIMIT {int(self.cfg.if_extremes)})
                  OR coalesce(d.unique_dst_ports, 0) IN (
                      SELECT unique_dst_ports FROM weirvern.flows_aggregated_diversity
                      WHERE window_start BETWEEN '{s}' AND '{e}'
                      ORDER BY unique_dst_ports DESC LIMIT {int(self.cfg.if_extremes)})
              ){excl}{scope_filter}
            -- A LIMIT WITHOUT AN ORDER IS A DIFFERENT SAMPLE ON EVERY RUN (GitHub #61).
            -- The hash that already selects the sample also orders the cut, so the same
            -- window trains from the same rows regardless of part layout.
            ORDER BY sipHash64(a.src_addr, a.window_start)
            LIMIT {int(self.cfg.if_n_samples)}
        """
        data = client.query(q, settings=QUERY_SETTINGS).result_rows
        if len(data) < 100:
            logger.warning("Not enough data for %s (%d rows)", self.name, len(data))
            return False

        X = np.asarray(data, dtype=float)
        if self.cfg.missing_features:
            # The SQL coalesced every absent source to 0; recover "absent" as NaN so the
            # median is taken over measured values only and the indicators are real.
            X = null_absent_zeek(X, IF_FEATURES)
        Xs = self.preprocessor.fit_transform(X)
        self.X_train_unscaled = X  # gradient-boosting student (legacy coupling, kept)
        self.model = IsolationForest(contamination=self.cfg.contamination, random_state=self.cfg.random_state).fit(Xs)
        ar = float((self.model.predict(Xs) == -1).sum() / len(Xs))

        # Calibrate the score→anomaly mapping against the training distribution.
        train_scores = self.model.score_samples(Xs)
        self.calibration = {
            "p01": float(np.percentile(train_scores, 1)),
            "p05": float(np.percentile(train_scores, 5)),
            "p50": float(np.percentile(train_scores, 50)),
        }

        self.metadata = ModelMetadata(
            model_type=self.name, duration_seconds=time.time() - st,
            feature_columns=IF_FEATURES,
            params={
                "contamination": self.cfg.contamination,
                "n_samples": len(Xs),
                "extremes": self.cfg.if_extremes,
                # WHICH VECTOR THIS ARTIFACT LEARNS. Flipping the flag changes the model's
                # input width (77 values vs 77 values + 77 indicators), so an artifact from
                # the other mode cannot be scored against this vector. load() refuses a
                # mismatch and the detector retrains instead of quietly answering nothing.
                "missing_features": bool(self.cfg.missing_features),
                "min_feature_coverage": _floor(self.cfg),
                "model_input_columns": model_input_columns(
                    IF_FEATURES, indicators=bool(self.cfg.missing_features)),
                "calibration": {k: round(v, 6) for k, v in self.calibration.items()},
            },
            metrics={"anomaly_rate": round(ar, 4)},
            window_start=start_dt, window_end=end_dt, sample_count=len(Xs),
        )
        logger.info(
            "✅ %s trained on %d samples (anomaly rate %.3f%%, calibration p50=%.3f p05=%.3f p01=%.3f)",
            self.name, len(Xs), ar * 100,
            self.calibration["p50"], self.calibration["p05"], self.calibration["p01"],
        )
        self.save()
        return True

    def predict(self, flow: dict[str, Any],
                features: dict[str, float | None] | None = None) -> float:
        model = self.model
        if model is None:
            return 0.0
        try:
            if self.cfg.missing_features:
                # Below the floor there is no score to give: imputing most of a vector and
                # calling the result a detector's opinion is how "no telemetry" became 0.33.
                if below_floor(features, IF_FEATURES, _floor(self.cfg)):
                    return 0.0
                vec = feature_vector(features or {}, IF_FEATURES, preserve_missing=True)
            else:
                vec = feature_vector(features or {}, IF_FEATURES)
            X = self.preprocessor.transform(np.asarray([vec], dtype=float))
            s = model.score_samples(X)[0]
            return calibrate_isolation_forest(float(s), self.calibration)
        except Exception as exc:  # noqa: BLE001
            return self.note_predict_error(exc)


# ============================================================================
class GradientBoostingDetector(BaseDetector):
    name = "Gradient Boosting"

    def __init__(self, model_dir, cfg: ModelConfig | None = None):
        super().__init__(model_dir)
        self.cfg = cfg or ModelConfig()
        self.model: GradientBoostingClassifier | None = None
        self.preprocessor: Preprocessor = _preprocessor_for(self.cfg)
        # Percentile calibration of predict_proba (set at train time)
        self.calibration: dict[str, float] = {}

    def is_ready(self) -> bool:
        return self.model is not None and self.preprocessor.fitted

    def expected_feature_columns(self) -> list[str]:
        return list(IF_FEATURES)

    def train(self, teacher: IsolationForestDetector, X_unscaled: np.ndarray | None,
              start_dt: datetime, end_dt: datetime, client: Client) -> bool:
        if X_unscaled is None or not teacher.is_ready():
            logger.warning("No teacher model/data — skipping %s", self.name)
            return False
        st = time.time()
        if len(X_unscaled) > self.cfg.gb_max_samples:
            rng = np.random.default_rng(self.cfg.random_state)
            idx = rng.choice(len(X_unscaled), self.cfg.gb_max_samples, replace=False)
            X_unscaled = X_unscaled[idx]

        Xs = teacher.preprocessor.transform(np.asarray(X_unscaled, dtype=float))
        t_model = teacher.model
        if t_model is None:
            logger.warning("Teacher model vanished — skipping %s", self.name)
            return False
        y = np.asarray([1 if p == -1 else 0 for p in t_model.predict(Xs)])
        pos, neg = int((y == 1).sum()), int((y == 0).sum())
        if pos == 0:
            logger.info("Teacher found no anomalies — network healthy, skipping %s", self.name)
            return False
        weight = neg / pos

        self.preprocessor = teacher.preprocessor
        Xtr, Xte, ytr, yte = train_test_split(Xs, y, test_size=self.cfg.test_size,
                                              random_state=self.cfg.random_state, stratify=y)
        sample_weights = [weight if i == 1 else 1 for i in ytr]
        self.model = GradientBoostingClassifier(random_state=self.cfg.random_state).fit(
            Xtr, ytr, sample_weight=sample_weights)
        f1 = float(f1_score(yte, self.model.predict(Xte)))

        # Calibrate probabilities against the TRAINING distribution. Necessary
        # because class-imbalance sample_weight distorts predict_proba: without
        # this, ordinary windows scored ~0.97 anomaly probability (false
        # positives). Training data is ~94% benign, so it defines "ordinary".
        train_probs = self.model.predict_proba(Xtr)[:, 1]
        self.calibration = {
            "p50": float(np.percentile(train_probs, 50)),
            "p90": float(np.percentile(train_probs, 90)),
            "p94": float(np.percentile(train_probs, 94)),
        }

        self.metadata = ModelMetadata(
            model_type=self.name, duration_seconds=time.time() - st,
            feature_columns=IF_FEATURES,
            params={
                "scale_pos_weight": round(weight, 2),
                "n_samples": len(Xtr),
                # The student shares the teacher's preprocessor, so it shares the mode too;
                # recorded so load() can refuse a student from the other vector shape.
                "missing_features": bool(self.cfg.missing_features),
                "min_feature_coverage": _floor(self.cfg),
                "model_input_columns": model_input_columns(
                    IF_FEATURES, indicators=bool(self.cfg.missing_features)),
                "calibration": {k: round(v, 6) for k, v in self.calibration.items()},
            },
            metrics={"f1_score": round(f1, 4)},
            window_start=start_dt, window_end=end_dt, sample_count=len(Xtr),
        )
        logger.info(
            "✅ %s trained. F1: %.3f (class weight %.1f, calibration p50=%.3f p90=%.3f p94=%.3f)",
            self.name, f1, weight,
            self.calibration["p50"], self.calibration["p90"], self.calibration["p94"],
        )
        self.save()
        return True

    def predict(self, flow: dict[str, Any],
                features: dict[str, float | None] | None = None) -> float:
        model = self.model
        if model is None:
            return 0.0
        try:
            if self.cfg.missing_features:
                if below_floor(features, IF_FEATURES, _floor(self.cfg)):
                    return 0.0
                vec = feature_vector(features or {}, IF_FEATURES, preserve_missing=True)
            else:
                vec = feature_vector(features or {}, IF_FEATURES)
            X = self.preprocessor.transform(np.asarray([vec], dtype=float))
            p = model.predict_proba(X)[0]
            return calibrate_probability(float(p[1]), self.calibration)
        except Exception as exc:  # noqa: BLE001
            return self.note_predict_error(exc)


# ============================================================================
# ── CROSS-SECTIONAL DETECTORS: THE SAME VECTOR, TWO INDEPENDENT SCORES ─────────────────────────
#
# WHY THIS EXISTS. The density detector this slot replaced asked "is this window inside a dense
# cluster?" and answered with a step function: 97.89% of 27,454 stored scores sat at 0.99 or above
# (p50 = p99 = max = 0.99), so no threshold could separate anything from anything. The question the
# slot should ask is CROSS-SECTIONAL -- "does this host-window look unlike the population of
# host-windows?" -- and `scripts/cross_sectional_bakeoff.py` measured six answers to it on this
# deployment (`docs/research/cross-sectional-detector-2026-11-20.md`).
#
# Two of them ship here, as SEPARATE detectors with separate artifacts, reference sets,
# calibrations and eligibility rows:
#
#   * KNN distance (k=10) -- the bake-off winner: 1.18% held-out FAR at a 0.01 target with
#     per-coverage-stratum calibration, 2,590 distinct scores, 0.01 s fit / 4.8 us per window.
#   * LOF (k=20, novelty=True) -- the only genuinely independent score in the study (rho = -0.08
#     with Isolation Forest against kNN's +0.46). Its raw score is unbounded and, on a reference
#     full of exact duplicate quiet windows, produced a threshold of 8.5e8 (a detector silently
#     off). It ships BOUNDED: the statistic is log1p(LOF) and a fit whose reference distances are
#     degenerate is REFUSED rather than persisted.
#
# NEITHER of them shares a line of model code with the other: `_fit_reference` and `_grade` are
# plumbing (median impute + standardise, and a monotone map into the ensemble's band), not a
# combined density model.
#
# THE SCORE IS THE STATISTIC, MAPPED MONOTONICALLY. `score(X)` returns the raw statistic the
# bake-off measured -- the k-th neighbour distance in scaled units, or log1p(LOF). `predict()`
# maps that number into [0, 0.99] with a STRICTLY INCREASING piecewise map over the reference
# quantiles, because the ensemble's fusion, agreement and severity gates are defined on that
# band. Strict monotonicity matters: a conformal threshold chosen on the raw statistic selects
# exactly the same windows as one chosen on the mapped score, so the measured false-alarm rates
# carry over unchanged.

# A reference smaller than this is not a population. It is also below the 100-row floor every
# detector here uses, so the message stays consistent.
MIN_REFERENCE_ROWS = 100
# How many distinct k-th-neighbour distances a usable reference must produce. A constant (or
# near-constant) reference -- every window identical, or a handful of blobs -- yields a degenerate
# score: every threshold lands on the same value and the detector is either always on or always
# off. Both detectors refuse that fit.
MIN_DISTINCT_DISTANCES = 50
# How many reference windows a COVERAGE STRATUM needs before its own quantiles are trusted for
# scoring. Below it, grading falls back to the pooled quantiles (the same explicit fallback the
# calibration layer makes for its thresholds).
MIN_GRADE_SAMPLES = 50


def cross_sectional_training_sql(start: str, end: str, cfg: ModelConfig,
                                 *, scope_filter: str = "", limit: int | None = None) -> str:
    """The 19-feature training matrix for BOTH cross-sectional detectors.

    One builder for both, assembled from the repository's own constants (`_zeek_clause`,
    `flow_windows.folded`, `_flagged_exclusion_clause`) so the two reference sets cannot drift
    into different feature definitions.

    NO HOST SAMPLING. This query used to carry `sipHash64(a.src_addr) % 5 == 1` -- a 1-in-5 cut
    of the HOST population. Measured on the deployment: 24 monitored hosts, 5 surviving the cut.
    A cross-sectional model needs a population to compare against; five hosts is not one. The
    sample is bounded by ROWS instead (`ORDER BY sipHash64(src_addr, window_start) LIMIT n`), the
    same deterministic cut the bake-off used, so every monitored host can contribute rows.

    `scope_filter` is `networks.training_filter(client)` at the call site -- a predicate that
    keeps training on the monitored scopes. Passed in so this function stays testable without a
    ClickHouse client.
    """
    s, e = start, end
    zeek_cte, zeek_cols, zeek_join = _zeek_clause(s, e, ZEEK_CROSS_SECTIONAL_FEATURES)
    excl = _flagged_exclusion_clause(s, e, cfg)
    n_rows = int(limit if limit is not None else cfg.knn_n_samples)
    return f"""  # nosec B608 - interpolates formatted datetimes + int config only, never flow data
        WITH {zeek_cte}
        SELECT
            log(a.total_bytes + 1),
            log(a.total_packets + 1),
            log(a.unique_dst_ips + 1),
            log(a.flow_count + 1),
            log(coalesce(d.unique_dst_ports, 0) + 1),
            coalesce(d.port_entropy, 0),
            coalesce(t.activity_regularity, 1.0),
            coalesce(t.burstiness, 1.0),
{zeek_cols}
        FROM {flow_windows.folded(flow_windows.between(s, e))}
        LEFT JOIN weirvern.flows_aggregated_diversity d
            ON a.window_start = d.window_start AND a.src_addr = d.src_addr
        LEFT JOIN weirvern.flows_aggregated_temporal t
            ON a.window_start = t.window_start AND a.src_addr = t.src_addr
        {zeek_join}
        WHERE a.window_start BETWEEN '{s}' AND '{e}'
          AND a.total_bytes > 0{excl}{scope_filter}
        -- Deterministic row sample, NOT a host sample: every monitored host contributes, and
        -- the cut is stable across retrains so the reference does not churn between cycles.
        ORDER BY sipHash64(a.src_addr, a.window_start)
        LIMIT {n_rows}
    """


def kth_neighbour_distances(X: np.ndarray, k: int) -> np.ndarray:
    """Distance from every row of `X` to its k-th nearest neighbour IN `X`.

    Self is the first neighbour of a row scored against its own reference (distance 0), so this
    is the k-th of the remaining k-1 others -- exactly what the bake-off measured for its fit
    half. A row NOT in the reference has k reference neighbours, which the conformal threshold
    absorbs: the calibration slice is always out-of-sample.
    """
    matrix = np.asarray(X, dtype=float)
    neighbours = int(max(1, min(int(k), len(matrix) - 1)))
    model = NearestNeighbors(n_neighbors=neighbours + 1).fit(matrix)
    dist, _ = model.kneighbors(matrix, n_neighbors=neighbours + 1)
    # Column 0 is the row itself (distance 0); the k-th neighbour is at column k.
    return np.asarray(dist[:, -1], dtype=float)


def reference_degeneracy(distances: np.ndarray) -> str:
    """Why a reference cannot produce a usable score, or "" when it can.

    THE CHECK IS THE POINT. A detector shipped for months with a score that was constant on 98% of
    windows because nothing refused a reference that could not be separated. Here a fit whose
    k-th-neighbour distances do not vary is REFUSED -- no artifact is written, `is_ready()` stays
    False, and the Detectors row says `not trained: degenerate reference` rather than showing a
    detector that is merely quiet.
    """
    values = np.asarray(distances, dtype=float)
    if values.size == 0:
        return "the reference is empty"
    if not bool(np.isfinite(values).all()):
        return "a k-th neighbour distance is not finite"
    distinct = int(np.unique(np.round(values, 12)).size)
    if distinct < MIN_DISTINCT_DISTANCES:
        return (f"the reference produces only {distinct} distinct k-th neighbour distance(s) "
                f"(need {MIN_DISTINCT_DISTANCES})")
    p50, p99 = (float(v) for v in np.percentile(values, [50, 99]))
    if not p99 > p50:
        return "the k-th neighbour distance does not vary across the reference (p99 == p50)"
    return ""


def distance_quantiles(distances: np.ndarray) -> dict[str, float]:
    """The quantiles the score map is anchored on."""
    values = np.asarray(distances, dtype=float)
    p10, p50, p95, p99 = (float(v) for v in np.percentile(values, [10, 50, 95, 99]))
    return {"p10": p10, "p50": p50, "p95": p95, "p99": p99}


def grade_distance(distance: float, quantiles: dict[str, float]) -> float:
    """Map a raw cross-sectional statistic into the ensemble's [0, 0.99) band.

    STRICTLY INCREASING, so selecting the top 1% by this score is selecting the top 1% by the raw
    distance -- the conformal rate the bake-off measured is preserved exactly.

    The shape follows the other detectors' percentile grading (normal traffic low, only the tail
    high) for a reason: a rank-uniform score would put HALF the population above 0.20, and
    `DETECTED_BY_SCORE`/the agreement gate would then read kNN as agreeing on almost every
    window. Anchors: p50 -> 0.15, p95 -> 0.60, p99 -> 0.85, asymptotic to 0.99.
    """
    q = quantiles or {}
    p50 = float(q.get("p50", 0.0) or 0.0)
    p95 = float(q.get("p95", p50) or p50)
    p99 = float(q.get("p99", p95) or p95)
    d = max(float(distance), 0.0)
    if p50 <= 0.0 or p95 <= p50 or p99 <= p95:
        # A reference this degenerate should never have been persisted; refuse to pretend a
        # score is calibrated rather than emitting a number nobody can read.
        return 0.0
    if d <= p50:
        return 0.15 * (d / p50)
    if d <= p95:
        return 0.15 + 0.45 * ((d - p50) / (p95 - p50))
    if d <= p99:
        return 0.60 + 0.25 * ((d - p95) / (p99 - p95))
    # The last band approaches 0.99 without ever reaching it, so equal distances cannot tie at a
    # ceiling and a 1% threshold keeps its resolution in the tail.
    scale = max(p99 - p95, 1e-9)
    return 0.85 + 0.14 * (1.0 - math.exp(-(d - p99) / scale))


def coverage_stratum_of_row(row: np.ndarray, expected: int) -> str:
    """`observed/expected` for one RAW feature row (NaN = absent, never 0)."""
    observed = int(np.isfinite(np.asarray(row, dtype=float)).sum())
    return f"{observed}/{int(expected)}"


def _fit_reference(Xraw: np.ndarray, cfg: ModelConfig) -> tuple[Any, np.ndarray]:
    """Fit the shared preprocessor and return (preprocessor, scaled matrix).

    Median impute with the training-time neutral, then StandardScaler.
    With `missing_features` ON the neutrals come from `column_neutrals` over observed values and
    the absent Zeek families are NaN (see `null_absent_zeek`); with it OFF the historical
    `RobustPreprocessor` is used unchanged.
    """
    prep = _preprocessor_for(cfg, indicators=False)
    scaled = np.asarray(prep.fit_transform(np.asarray(Xraw, dtype=float)), dtype=float)
    return prep, scaled


def _grade_by_stratum(distances: np.ndarray, strata: list[str]) -> dict[str, dict[str, float]]:
    """Reference quantiles per coverage stratum, plus the pooled entry under "".

    A stratum with fewer than MIN_GRADE_SAMPLES reference windows keeps the pooled entry: its own
    quantiles would be estimated from a handful of points, and the score would swing between
    retrains. That is the same explicit fallback the calibration layer makes for thresholds.
    """
    pooled = distance_quantiles(distances)
    groups: dict[str, list[float]] = {}
    for value, key in zip(distances, strata, strict=False):
        groups.setdefault(str(key), []).append(float(value))
    out: dict[str, dict[str, float]] = {"": pooled}
    for key, values in groups.items():
        if key and len(values) >= MIN_GRADE_SAMPLES:
            out[key] = distance_quantiles(np.asarray(values, dtype=float))
    return out


# ============================================================================
class KNNDistanceDetector(BaseDetector):
    """Distance to the k-th nearest neighbour in a persisted reference population.

    THE SCORE. `score(X)` is the k-th neighbour distance in the standardised 19-feature space --
    the statistic the bake-off measured at 1.18% held-out FAR. `predict()` maps it monotonically
    into [0, 0.99] for the ensemble (see `grade_distance`).

    THE REFERENCE IS PERSISTED. The artifact carries the scaled reference matrix (at most
    `cfg.knn_n_samples` rows x 19 columns, 8 bytes each -- 760 KB at the 5,000-row cap) plus the
    per-stratum quantiles. It has to travel with the model: a distance is meaningless without the
    population it was measured against.
    """

    name = "KNN distance"

    def __init__(self, model_dir, cfg: ModelConfig | None = None):
        super().__init__(model_dir)
        self.cfg = cfg or ModelConfig()
        self.k = int(getattr(self.cfg, "knn_k", 10) or 10)
        self.preprocessor: Any = _preprocessor_for(self.cfg, indicators=False)
        self.reference_: np.ndarray | None = None
        self.strata_: list[str] = []
        self.grades_: dict[str, dict[str, float]] = {}
        self.neighbours: NearestNeighbors | None = None
        # "" = never trained, "ok", "insufficient-rows", "degenerate-reference".
        self.train_outcome = ""

    def is_ready(self) -> bool:
        return self.neighbours is not None and self.reference_ is not None

    def expected_feature_columns(self) -> list[str]:
        return list(CROSS_SECTIONAL_FEATURES)

    def score(self, X: np.ndarray) -> np.ndarray:
        """The raw statistic: distance to the k-th nearest reference window."""
        if self.neighbours is None or self.reference_ is None:
            raise RuntimeError("KNN distance is not fitted")
        matrix = np.asarray(self.preprocessor.transform(np.asarray(X, dtype=float)), dtype=float)
        k = int(max(1, min(self.k, len(self.reference_))))
        dist, _ = self.neighbours.kneighbors(matrix, n_neighbors=k)
        return np.asarray(dist[:, -1], dtype=float)

    def train(self, start_dt: datetime, end_dt: datetime, client: Client) -> bool:
        st = time.time()
        s, e = start_dt.strftime("%Y-%m-%d %H:%M:%S"), end_dt.strftime("%Y-%m-%d %H:%M:%S")
        query = cross_sectional_training_sql(
            s, e, self.cfg, scope_filter=networks.training_filter(client),
            limit=self.cfg.knn_n_samples)
        data = client.query(query, settings=QUERY_SETTINGS).result_rows
        if len(data) < MIN_REFERENCE_ROWS:
            self.train_outcome = "insufficient-rows"
            logger.warning(
                "Not enough data for %s: %d rows (floor %d). Every monitored host is sampled; "
                "a longer seed window is what adds rows.", self.name, len(data), MIN_REFERENCE_ROWS)
            return False
        Xraw = np.asarray(data, dtype=float)
        if self.cfg.missing_features:
            Xraw = null_absent_zeek(Xraw, CROSS_SECTIONAL_FEATURES)
        prep, scaled = _fit_reference(Xraw, self.cfg)
        distances = kth_neighbour_distances(scaled, self.k)
        reason = reference_degeneracy(distances)
        if reason:
            # REFUSE THE FIT. Clearing the in-memory model matters: a half-fitted detector that
            # kept scoring would be exactly the silent failure this check exists to prevent.
            self.train_outcome = "degenerate-reference"
            self.reference_ = None
            self.neighbours = None
            self.grades_ = {}
            logger.error(
                "%s REFUSED its reference: %s. No artifact was written; the detector reports "
                "'not trained: degenerate reference' and contributes nothing.", self.name, reason)
            return False
        self.preprocessor = prep
        self.reference_ = scaled
        strata = [coverage_stratum_of_row(row, len(CROSS_SECTIONAL_FEATURES)) for row in Xraw]
        self.strata_ = strata
        self.grades_ = _grade_by_stratum(distances, strata)
        self.neighbours = NearestNeighbors(
            n_neighbors=int(max(1, min(self.k, len(scaled))))).fit(scaled)
        self.metadata = ModelMetadata(
            model_type=self.name, duration_seconds=time.time() - st,
            feature_columns=CROSS_SECTIONAL_FEATURES,
            params={"model": "knn-distance", "k": self.k, "n_samples": len(scaled),
                    "reference_rows": len(scaled),
                    "reference_bytes": int(scaled.nbytes),
                    "missing_features": bool(self.cfg.missing_features),
                    "min_feature_coverage": _floor(self.cfg),
                    "grades": {key: {k2: round(v2, 6) for k2, v2 in q.items()}
                               for key, q in self.grades_.items()}},
            metrics={"reference_rows": int(len(scaled)),
                     "distinct_reference_distances": int(np.unique(np.round(distances, 12)).size),
                     "reference_p50": round(float(np.median(distances)), 6),
                     "reference_p99": round(float(np.percentile(distances, 99)), 6),
                     "strata": {key: strata.count(key) for key in sorted(set(strata))}},
            window_start=start_dt, window_end=end_dt, sample_count=len(scaled),
        )
        self.train_outcome = "ok"
        logger.info("✅ %s trained: %d reference windows, %d distinct distances, k=%d",
                    self.name, len(scaled), int(np.unique(np.round(distances, 12)).size), self.k)
        self.save()
        return True

    def predict(self, flow: dict[str, Any],
                features: dict[str, float | None] | None = None) -> float:
        if not self.is_ready():
            return 0.0
        try:
            if self.cfg.missing_features:
                if below_floor(features, CROSS_SECTIONAL_FEATURES, _floor(self.cfg)):
                    return 0.0
                vec = feature_vector(features or {}, CROSS_SECTIONAL_FEATURES, preserve_missing=True)
            else:
                vec = feature_vector(features or {}, CROSS_SECTIONAL_FEATURES)
            row = np.asarray([vec], dtype=float)
            distance = float(self.score(row)[0])
            stratum = coverage_stratum_of_row(row[0], len(CROSS_SECTIONAL_FEATURES))
            quantiles = self.grades_.get(stratum, self.grades_.get("", {}))
            return float(grade_distance(distance, quantiles))
        except Exception as exc:  # noqa: BLE001
            return self.note_predict_error(exc)


# ============================================================================
class LOFDetector(BaseDetector):
    """Local Outlier Factor (k=20, novelty=True) over the same 19-feature vector.

    INDEPENDENT OF KNN ON PURPOSE. Separate class, separate training query result, separate
    reference set, separate artifact (`LOF_v5.pkl`), separate calibration and eligibility row.
    The bake-off measured it as the only score not redundant with Isolation Forest (rho = -0.08
    against kNN's +0.46), which is the reason to carry a second cross-sectional view at all.

    THE SCORE IS BOUNDED. Raw LOF divides by a local reachability density, and a reference full
    of exact duplicate quiet windows makes that density infinite -- the bake-off's F4 fold produced
    a 99th-percentile score of 8.5e8, i.e. a threshold above every score the detector could emit
    (a detector silently off, reading as a 0.39% false-alarm rate). Two defences here:

      1. the statistic is `log1p(LOF)`, so a threshold lives on a scale a reader can judge
         (log1p(8.5e8) ~= 20.6 instead of 850,000,000); and
      2. a fit whose reference k-th-neighbour distances are degenerate is REFUSED, exactly as for
         kNN, so the pathology cannot be persisted and reported as a quiet detector.
    """

    name = "LOF"

    def __init__(self, model_dir, cfg: ModelConfig | None = None):
        super().__init__(model_dir)
        self.cfg = cfg or ModelConfig()
        self.k = int(getattr(self.cfg, "lof_neighbors", 20) or 20)
        self.preprocessor: Any = _preprocessor_for(self.cfg, indicators=False)
        self.reference_: np.ndarray | None = None
        self.strata_: list[str] = []
        self.grades_: dict[str, dict[str, float]] = {}
        self.model: LocalOutlierFactor | None = None
        self.train_outcome = ""

    def is_ready(self) -> bool:
        return self.model is not None and self.reference_ is not None

    def expected_feature_columns(self) -> list[str]:
        return list(CROSS_SECTIONAL_FEATURES)

    def score(self, X: np.ndarray) -> np.ndarray:
        """The raw statistic: log1p(LOF). Higher = less like its local neighbourhood."""
        if self.model is None or self.reference_ is None:
            raise RuntimeError("LOF is not fitted")
        matrix = np.asarray(self.preprocessor.transform(np.asarray(X, dtype=float)), dtype=float)
        # sklearn's score_samples is the NEGATIVE LOF (higher = more normal); negate first, then
        # log1p. Both are monotone, so ordering -- and any conformal threshold -- is preserved.
        raw = np.maximum(-np.asarray(self.model.score_samples(matrix), dtype=float), 0.0)
        return np.log1p(raw)

    def train(self, start_dt: datetime, end_dt: datetime, client: Client) -> bool:
        st = time.time()
        s, e = start_dt.strftime("%Y-%m-%d %H:%M:%S"), end_dt.strftime("%Y-%m-%d %H:%M:%S")
        query = cross_sectional_training_sql(
            s, e, self.cfg, scope_filter=networks.training_filter(client),
            limit=self.cfg.lof_n_samples)
        data = client.query(query, settings=QUERY_SETTINGS).result_rows
        if len(data) < max(MIN_REFERENCE_ROWS, self.k + 1):
            self.train_outcome = "insufficient-rows"
            logger.warning(
                "Not enough data for %s: %d rows (floor %d, k=%d). Every monitored host is "
                "sampled; a longer seed window is what adds rows.",
                self.name, len(data), max(MIN_REFERENCE_ROWS, self.k + 1), self.k)
            return False
        Xraw = np.asarray(data, dtype=float)
        if self.cfg.missing_features:
            Xraw = null_absent_zeek(Xraw, CROSS_SECTIONAL_FEATURES)
        prep, scaled = _fit_reference(Xraw, self.cfg)
        distances = kth_neighbour_distances(scaled, self.k)
        reason = reference_degeneracy(distances)
        if reason:
            self.train_outcome = "degenerate-reference"
            self.reference_ = None
            self.model = None
            self.grades_ = {}
            logger.error(
                "%s REFUSED its reference: %s. No artifact was written; the detector reports "
                "'not trained: degenerate reference' and contributes nothing.", self.name, reason)
            return False
        model = LocalOutlierFactor(n_neighbors=int(min(self.k, len(scaled) - 1)),
                                   novelty=True).fit(scaled)
        raw = np.maximum(-np.asarray(model.score_samples(scaled), dtype=float), 0.0)
        statistic = np.log1p(raw)
        if not bool(np.isfinite(statistic).all()):
            self.train_outcome = "degenerate-reference"
            self.reference_ = None
            self.model = None
            self.grades_ = {}
            logger.error("%s REFUSED: log1p(LOF) is not finite on the reference.", self.name)
            return False
        finite_quantiles = distance_quantiles(statistic)
        if not finite_quantiles["p99"] > finite_quantiles["p50"]:
            self.train_outcome = "degenerate-reference"
            self.reference_ = None
            self.model = None
            self.grades_ = {}
            logger.error("%s REFUSED: log1p(LOF) does not vary across the reference.", self.name)
            return False
        self.preprocessor = prep
        self.reference_ = scaled
        strata = [coverage_stratum_of_row(row, len(CROSS_SECTIONAL_FEATURES)) for row in Xraw]
        self.strata_ = strata
        self.grades_ = _grade_by_stratum(statistic, strata)
        self.model = model
        self.metadata = ModelMetadata(
            model_type=self.name, duration_seconds=time.time() - st,
            feature_columns=CROSS_SECTIONAL_FEATURES,
            params={"model": "lof", "k": self.k, "novelty": True, "n_samples": len(scaled),
                    "reference_rows": len(scaled),
                    "reference_bytes": int(scaled.nbytes),
                    "statistic": "log1p(lof)",
                    "missing_features": bool(self.cfg.missing_features),
                    "min_feature_coverage": _floor(self.cfg),
                    "grades": {key: {k2: round(v2, 6) for k2, v2 in q.items()}
                               for key, q in self.grades_.items()}},
            metrics={"reference_rows": int(len(scaled)),
                     "distinct_reference_distances": int(np.unique(np.round(distances, 12)).size),
                     "statistic_p50": round(float(np.median(statistic)), 6),
                     "statistic_p99": round(float(np.percentile(statistic, 99)), 6),
                     "statistic_max": round(float(np.max(statistic)), 6),
                     "strata": {key: strata.count(key) for key in sorted(set(strata))}},
            window_start=start_dt, window_end=end_dt, sample_count=len(scaled),
        )
        self.train_outcome = "ok"
        logger.info("✅ %s trained: %d reference windows, log1p(LOF) p50=%.3f p99=%.3f, k=%d",
                    self.name, len(scaled), float(np.median(statistic)),
                    float(np.percentile(statistic, 99)), self.k)
        self.save()
        return True

    def predict(self, flow: dict[str, Any],
                features: dict[str, float | None] | None = None) -> float:
        if not self.is_ready():
            return 0.0
        try:
            if self.cfg.missing_features:
                if below_floor(features, CROSS_SECTIONAL_FEATURES, _floor(self.cfg)):
                    return 0.0
                vec = feature_vector(features or {}, CROSS_SECTIONAL_FEATURES, preserve_missing=True)
            else:
                vec = feature_vector(features or {}, CROSS_SECTIONAL_FEATURES)
            row = np.asarray([vec], dtype=float)
            statistic = float(self.score(row)[0])
            stratum = coverage_stratum_of_row(row[0], len(CROSS_SECTIONAL_FEATURES))
            return float(grade_distance(statistic,
                                        self.grades_.get(stratum, self.grades_.get("", {}))))
        except Exception as exc:  # noqa: BLE001
            return self.note_predict_error(exc)


# Both models register the GENERIC coverage contract with the calibration layer. They do not need
# a custom one -- `ml_window_scores` stores (score, coverage, observed, expected) and that is
# enough -- but the registration is the declared seam: the calibration layer never branches on a
# model name, it asks the registry how to read a row.
register_model_contract(KNNDistanceDetector.name, COVERAGE_CONTRACT)
register_model_contract(LOFDetector.name, COVERAGE_CONTRACT)


# ============================================================================
class AdaptiveBaselineDetector(BaseDetector):
    """Per-host statistical baselines from ClickHouse (avg/stddev/percentiles).

    Score = max of percentile-graded bytes, percentile-graded packets, and
    sigmoid z-score of unique-destination count. Baselines persist to the DB
    (baseline_history) AND to disk, so a restart is warm.
    """

    name = "Adaptive Baseline"

    def __init__(self, model_dir, cfg: ModelConfig | None = None):
        super().__init__(model_dir)
        self.cfg = cfg or ModelConfig()
        # `Any` rather than `float`: the per-host dict carries the volumetric and behavioural
        # statistics AND, since the JA4 history was wired in, the fingerprint history SET
        # (`baseline_ja4_set`, a list of strings) the novelty ratio is computed against.
        self.baselines: dict[str, dict[str, Any]] = {}

    def is_ready(self) -> bool:
        return len(self.baselines) > 0

    @staticmethod
    def _zeek_baseline_fields(r: tuple) -> dict[str, float | bool]:
        """Read the Zeek columns of a baseline row by NAME rather than by position.

        The training query selects these from ZEEK_FEATURES in list order, so the only safe way
        to read them is from the same list. The positional literals this replaces assumed seven
        Zeek columns where the query emits fifty, so every value landed on a different
        measurement without raising.

        The four dispersion columns AFTER the feature block are the measured sigmas (see the
        training query's comment); their read is guarded so a row-shaped-otherwise (a test
        fixture, or a future query edit) degrades to the sqrt-mean fallback rather than
        raising -- the same honesty rule the rest of this module follows.
        """
        base = 9  # src_addr, 6 volume stats, 2 quantile arrays
        idx = {name: base + i for i, name in enumerate(ZEEK_FEATURES)}
        sd_base = base + len(ZEEK_FEATURES) + 1  # +1: the zeek_seen flag

        def _col(i: int, default: float) -> float:
            try:
                return float(r[i]) if r[i] is not None else default
            except (IndexError, TypeError, ValueError):
                return default

        avg_conn = _col(idx["zeek_conn_count"], 0.0)
        avg_s0 = _col(idx["zeek_s0_ratio"], 0.0)
        avg_notices = _col(idx["zeek_notice_count"], 0.0)
        conn_sd = _col(sd_base, 0.0)
        s0_count_avg = _col(sd_base + 1, 0.0)
        s0_count_sd = _col(sd_base + 2, 0.0)
        notice_sd = _col(sd_base + 3, 0.0)

        def _sigma(measured: float, mean: float, *, count_like: bool) -> float:
            """The divisor for a z-score: the measured sigma, else sqrt(mean), else 1.0.

            Three cases, in order, because each is a different kind of "we do not know
            the spread":

              * the measured sigma is positive -> use it. This is the honest number.
              * sigma is 0 BUT the mean is positive -> every training bucket was
                identical, which is itself unusual; sqrt(mean) is the Poisson floor for
                count-like data (sigma ~ sqrt(mu)) and is deliberately LESS than the mean,
                so a new event is priced as rare rather than impossible. A ratio keeps
                sqrt(mean) too: a ratio with mean m has variance <= m(1-m) <= m.
              * nothing to go on (mean 0) -> 1.0. A variance floor, so a division by
                ~zero cannot invent an infinite z-score out of an idle host.
            """
            if measured > 0:
                return measured
            if mean > 0:
                return max(1.0, math.sqrt(mean)) if count_like else math.sqrt(mean)
            return 1.0

        return {
            "zeek_seen": bool(r[base + len(ZEEK_FEATURES)]),
            "avg_conn": avg_conn,
            "stddev_conn": _sigma(conn_sd, avg_conn, count_like=True),
            "avg_s0": avg_s0,
            "stddev_s0": _sigma(s0_count_sd, avg_s0, count_like=True),
            # Count-scale S0 statistics for the z-score in predict(). `avg_s0_count`/
            # `stddev_s0_count` are absent from pre-change artifacts; the .get() in
            # predict() falls back to the ratio-scale pair, which reproduces the old
            # behaviour until the next retrain replaces the artifact.
            "avg_s0_count": s0_count_avg,
            "stddev_s0_count": _sigma(s0_count_sd, s0_count_avg, count_like=True),
            "avg_services": _col(idx["zeek_service_count"], 0.0),
            "avg_notices": avg_notices,
            "stddev_notices": _sigma(notice_sd, avg_notices, count_like=True),
        }

    def train(self, start_dt: datetime, end_dt: datetime, client: Client) -> bool:
        st = time.time()
        s, e = start_dt.strftime("%Y-%m-%d %H:%M:%S"), end_dt.strftime("%Y-%m-%d %H:%M:%S")
        # The Zeek join gives this detector a BEHAVIOURAL baseline alongside the volumetric
        # one. The existing three statistics (bytes, packets, unique destinations) all
        # measure how MUCH a host did; none measures WHAT it did. A host whose volume is
        # perfectly normal while it starts making refused connections, or suddenly speaking
        # services it never has, is invisible to a volume-only baseline -- and that is the
        # shape of an intrusion rather than of a busy day.
        #
        # The Zeek aggregates here are per-host ACROSS the window, not per 5-minute bucket,
        # because the question is "what is normal for this host" rather than "what happened
        # in this bucket". Averages and percentiles are the right shape for that.
        zeek_cte, zeek_select, zeek_join = _zeek_clause(s, e)
        # Training hygiene: do not learn from windows the system already flagged (see
        # _flagged_exclusion_clause). Empty string when disabled.
        excl = _flagged_exclusion_clause(s, e, self.cfg)
        scope_filter = networks.training_filter(client)
        # The shared helper returns `z.<feature>` per column, correct for a per-row SELECT. This
        # query GROUPS BY src_addr, so each column has to sit under an aggregate. Built here
        # from the same ZEEK_FEATURES list the helper uses, so the names still cannot drift --
        # only the wrapping differs.
        zeek_select = ",\n".join(
            f"                max(coalesce(z.{c}, 0))" if c == "zeek_present"
            else f"                avg(coalesce(z.{c}, 0))"
            for c in ZEEK_FEATURES
        )
        q = f"""  # nosec B608 - interpolates formatted datetimes + int config only, never flow data
            WITH {zeek_cte}
            SELECT
                a.src_addr,
                avg(a.total_bytes), sqrt(varPop(a.total_bytes)),
                avg(a.total_packets), sqrt(varPop(a.total_packets)),
                avg(a.unique_dst_ips), sqrt(varPop(a.unique_dst_ips)),
                quantiles(0.95, 0.99, 0.999)(a.total_bytes),
                quantiles(0.95, 0.99, 0.999)(a.total_packets),
                -- THE ZEEK COLUMNS COME FROM THE SHARED HELPER, aliased as the FEATURE names.
                --
                -- This block used to hand-write `z.conn_count`, `z.s0_count`,
                -- `z.service_count` and `z.notice_count`. The shared CTE exposes those
                -- concepts under their FEATURE names -- `zeek_conn_count`, `zeek_s0_ratio`,
                -- `zeek_service_count`, `zeek_notice_count` -- so the query failed outright:
                --
                --   Code: 47. DB::Exception: Identifier 'z.conn_count' cannot be resolved
                --   from subquery with name z.
                --
                -- Which means the Adaptive Baseline could NOT TRAIN AT ALL against the Zeek
                -- join, while the other three detectors could. Nothing raised at import time,
                -- the other three trained fine, and the failure appeared only when this
                -- detector ran -- so a deployment would have had three working models and one
                -- permanently absent, with a healthy-looking status page.
                -- Every Zeek column must be AGGREGATED here, because this query groups by
                -- src_addr: `Column 'z.zeek_present' is not under aggregate function and not
                -- in GROUP BY keys`. `avg` for the measurements, `max` for the presence flag
                -- (mean presence is meaningless; "seen at any point" is the question).
                {zeek_select},
                max(coalesce(z.zeek_conn_count, 0) > 0)  AS zeek_seen,
                -- THE BEHAVIOURAL DISPERSIONS, MEASURED RATHER THAN COPIED FROM THE MEAN.
                --
                -- These were previously faked in Python: `stddev_conn` was a copy of
                -- `avg_conn` and the notices z-score divided by `max(avg_notices, 1.0)`.
                -- A mean-copy prices one new event on a quiet host as if it were a
                -- mu-sigma event -- for a host averaging 5 conns, one extra refused
                -- connection read as a 1-sigma-ish signal and 50 read as 9-sigma,
                -- saturating. Poisson-ish counts have sigma ~ sqrt(mu); the honest
                -- number comes from the SAME sqrt(varPop(...)) estimator the volume
                -- stats above use, applied per host across the training window.
                --
                -- The S0 columns are COUNT-scale on purpose: predict() compares a
                -- window's S0 COUNT (ratio x conns) against the baseline, so the
                -- baseline must live in the same units. Comparing a count observation
                -- to a ratio baseline was a units mismatch the old 1.0 floor masked.
                sqrt(varPop(coalesce(z.zeek_conn_count, 0)))            AS zeek_conn_sd,
                avg(coalesce(z.zeek_s0_ratio, 0)
                    * coalesce(z.zeek_conn_count, 0))                   AS zeek_s0_count_avg,
                sqrt(varPop(coalesce(z.zeek_s0_ratio, 0)
                    * coalesce(z.zeek_conn_count, 0)))                  AS zeek_s0_count_sd,
                sqrt(varPop(coalesce(z.zeek_notice_count, 0)))          AS zeek_notice_sd
            FROM {flow_windows.folded(flow_windows.between(s, e))}
            {zeek_join}
            WHERE a.window_start BETWEEN '{s}' AND '{e}'{excl}{scope_filter}
            GROUP BY a.src_addr
            HAVING count() >= {int(self.cfg.baseline_min_obs)}
            LIMIT 100000
        """
        rows = client.query(q, settings=QUERY_SETTINGS).result_rows
        if len(rows) < 10:
            logger.warning("Not enough baseline data (%d hosts)", len(rows))
            return False
        self.baselines = {}
        zeek_seen_hosts = 0
        for r in rows:
            bq, pq = r[7], r[8]
            self.baselines[r[0]] = {
                "avg_bytes": float(r[1] or 0), "stddev_bytes": float(r[2] or 1),
                "avg_packets": float(r[3] or 0), "stddev_packets": float(r[4] or 1),
                "avg_unique_dsts": float(r[5] or 0), "stddev_unique_dsts": float(r[6] or 1),
                "p95_bytes": float(bq[0]), "p99_bytes": float(bq[1]), "p999_bytes": float(bq[2]),
                "p95_packets": float(pq[0]), "p99_packets": float(pq[1]), "p999_packets": float(pq[2]),
                # Behavioural norms from Zeek. `zeek_seen` is carried through so predict()
                # can tell "this host has no Zeek baseline" from "its baseline is zero",
                # exactly as the feature vector's presence flag does.
                # READ BY NAME, NOT BY POSITION.
                #
                # These were literals (r[9]..r[15]) and they were WRONG: the Zeek columns are
                # generated from ZEEK_FEATURES and there are 50 of them, not 7, so r[9] is
                # `max(zeek_present)` -- a 0/1 flag -- rather than a connection count. Every read
                # landed on a different quantity: zeek_seen became the host's DNS count,
                # avg_conn its presence flag, avg_s0 its rejection ratio. The result was not an
                # exception but a baseline computed from whatever sat at that index, and because
                # `zeek_seen` gates the whole behavioural term in predict(), a host with no DNS
                # silently scored volume-only. Deriving the offset from the shared list means a
                # reorder or a new Zeek feature cannot shift these reads again.
                **self._zeek_baseline_fields(r),
            }
            if self.baselines[r[0]]["zeek_seen"]:
                zeek_seen_hosts += 1
        # ── THE SHAPE / BEHAVIOUR BASELINES (ML-17) ────────────────────────────────────────────
        #
        # The volume baseline answers HOW MUCH; the Phase-2 diversity and temporal rows answer
        # HOW: fan-out, port spread, entropy, regularity and burstiness. They are already model
        # inputs, so a host can be flagged by one of them while the three volume bars stay flat.
        # The explainer should be able to say that instead of calling the window normal.
        #
        # A SEPARATE QUERY, deliberately: the main training query's column offsets are consumed
        # by `_zeek_baseline_fields` and its 50-column list. Adding fields there would move every
        # positional read and is the exact class of bug that once made `zeek_seen` the DNS count.
        # A missing diversity/temporal row omits that family's keys rather than inventing a zero
        # baseline; `div_n`/`temp_n` make the presence test explicit.
        try:
            stats_rows = client.query(
                f"""  # nosec B608 - formatted datetimes + config only, never flow data
                SELECT
                    a.src_addr,
                    avg(a.flow_count), sqrt(varPop(a.flow_count)),
                    avg(coalesce(d.unique_dst_ports, 0)), sqrt(varPop(coalesce(d.unique_dst_ports, 0))),
                    avg(coalesce(d.port_entropy, 0)), sqrt(varPop(coalesce(d.port_entropy, 0))),
                    avg(coalesce(t.activity_regularity, 1)), sqrt(varPop(coalesce(t.activity_regularity, 1))),
                    avg(coalesce(t.burstiness, 1)), sqrt(varPop(coalesce(t.burstiness, 1))),
                    count(d.window_start) AS div_n, count(t.window_start) AS temp_n
                FROM {flow_windows.folded(flow_windows.between(s, e))}
                LEFT JOIN weirvern.flows_aggregated_diversity d
                    ON d.window_start = a.window_start AND d.src_addr = a.src_addr
                LEFT JOIN weirvern.flows_aggregated_temporal t
                    ON t.window_start = a.window_start AND t.src_addr = a.src_addr
                WHERE a.window_start BETWEEN '{s}' AND '{e}'{excl}{scope_filter}
                GROUP BY a.src_addr
                HAVING count() >= {int(self.cfg.baseline_min_obs)}
                LIMIT 100000
                """,
                settings=QUERY_SETTINGS,
            ).result_rows
            for row in stats_rows:
                b = self.baselines.get(str(row[0]))
                if b is None:
                    continue
                b.update({
                    "avg_flow_count": float(row[1] or 0),
                    "stddev_flow_count": float(row[2] or 0),
                })
                if int(row[11] or 0) > 0:
                    b.update({
                        "avg_unique_ports": float(row[3] or 0),
                        "stddev_unique_ports": float(row[4] or 0),
                        "avg_port_entropy": float(row[5] or 0),
                        "stddev_port_entropy": float(row[6] or 0),
                    })
                if int(row[12] or 0) > 0:
                    b.update({
                        "avg_activity_regularity": float(row[7] or 0),
                        "stddev_activity_regularity": float(row[8] or 0),
                        "avg_burstiness": float(row[9] or 0),
                        "stddev_burstiness": float(row[10] or 0),
                    })
        except Exception as exc:  # noqa: BLE001
            # The volume/Zeek baseline still works; the new bars will be absent, not fabricated.
            logger.warning("Could not load the shape/behaviour baselines (ML-17): %s", exc)
        # ── THE HISTORIES THE TWO DERIVED FEATURES READ ─────────────────────────────────────────
        #
        # `zeek_ja4_novelty` and `zeek_service_rarity` are computed AT SCORING TIME from the
        # host's longer-window history: "is this TLS fingerprint one this host has used before?"
        # and "how much of its service variety is new?". That history arrives on the baseline
        # dict as `baseline_ja4_set`, `baseline_ja4_count` and `baseline_service_count` -- and
        # NOTHING WAS PUTTING IT THERE. Both queries were written, tested, and never called
        # from production; the extractor found no history, took its conservative floor, and
        # reported "entirely novel" (1.0) for every host-window that used TLS at all. The
        # feature exists to notice a NEW TLS stack on an internal host, which is how malware is
        # introduced and how a rogue device announces itself. In this state it noticed nothing
        # and said so everywhere.
        #
        # Same window as the baseline itself, so "the host's history" means one thing across the
        # whole pipeline. Wrapped on purpose: a missing history must degrade the two derived
        # features to their honest "nothing to compare against" values, never fail the baseline
        # that every volume decision depends on.
        hist_hosts = 0
        try:
            for row in client.query(zeek_baseline_ja4_sql(s, e),
                                    settings=QUERY_SETTINGS).result_rows:
                b = self.baselines.get(str(row[0]))
                if b is None:
                    continue
                b["baseline_ja4_count"] = float(row[1] or 0)
                raw_set = row[2]
                b["baseline_ja4_set"] = list(raw_set) if isinstance(raw_set, (list, tuple)) else []
                if b["baseline_ja4_set"]:
                    hist_hosts += 1
            for row in client.query(zeek_baseline_sql(s, e),
                                    settings=QUERY_SETTINGS).result_rows:
                b = self.baselines.get(str(row[0]))
                if b is None:
                    continue
                b["baseline_service_count"] = float(row[1] or 0)
                b["baseline_conn_count"] = float(row[2] or 0)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "Could not load the JA4/service histories, so zeek_ja4_novelty and "
                "zeek_service_rarity will read 0.0 (there is nothing to compare against): %s",
                exc,
            )
        seeded = self._apply_normal_seeds(client)
        if seeded["applied"]:
            logger.info(
                "📚 %d normalized pattern(s) pooled into %d host baseline(s): the operator's "
                "judgement is part of what this baseline calls normal",
                seeded["applied"], seeded["hosts"],
            )
        self.metadata = ModelMetadata(
            model_type=self.name, duration_seconds=time.time() - st,
            params={"min_obs": self.cfg.baseline_min_obs},
            metrics={"baseline_count": len(self.baselines),
                     "zeek_baselined_hosts": zeek_seen_hosts,
                     "hosts_with_fp_history": hist_hosts,
                     "seeded_entries": seeded["applied"]},
            window_start=start_dt, window_end=end_dt, sample_count=len(self.baselines),
        )
        logger.info(
            "✅ Baselines computed for %d hosts (%d with Zeek behavioural baselines)",
            len(self.baselines), zeek_seen_hosts,
        )
        if zeek_seen_hosts == 0 and self.baselines:
            # Worth saying out loud rather than leaving as a silently missing dimension: the
            # volumetric baseline works, the behavioural one contributes nothing, and nothing
            # in the metrics would otherwise show the difference. Seen on the test box, where
            # the Zeek and NetFlow host sets barely overlap.
            logger.warning(
                "No host has a Zeek behavioural baseline, so this detector is volume-only. "
                "Check that both sensors observe the same segment (zeek_join_coverage)."
            )
        self.save()
        return True

    def _apply_normal_seeds(self, client: Client) -> dict[str, int]:
        """Pool the operator's normalized patterns into each host's statistics.

        A normalization is a statement of fact about the host, so it is ADDED to what the host
        has observed -- never substituted for it -- and it can only widen a band. The alternative
        (replacing the statistics) would let one click erase a host's real history, and the
        alternative of doing nothing would make the Normalize tab a decoration.

        Never raises: a failed read leaves the baselines exactly as measured and says so, because
        a normalization that could not be applied is a fact the operator needs, not a silent no-op.
        """
        from .. import normalize, normalize_store

        try:
            seeds = normalize_store.seeds(client)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Normalized traffic could not be read; baselines stay as measured: %s",
                           exc)
            return {"applied": 0, "hosts": 0}
        applied = hosts = 0
        for src, entries in seeds.items():
            b = self.baselines.get(src)
            if not b:
                continue
            touched = False
            for e in entries:
                n = int(e.get("samples") or 0)
                if n <= 0:
                    continue
                pooled_bytes = normalize.pool(
                    {"samples": float(b.get("sample_count", 1) or 1),
                     "avg": b["avg_bytes"], "var": b["stddev_bytes"] ** 2},
                    {"samples": n, "avg": float(e["avg_bytes"]), "var": float(e["var_bytes"])})
                pooled_packets = normalize.pool(
                    {"samples": float(b.get("sample_count", 1) or 1),
                     "avg": b["avg_packets"], "var": b["stddev_packets"] ** 2},
                    {"samples": n, "avg": float(e["avg_packets"]),
                     "var": float(e["var_packets"])})
                b["avg_bytes"], b["stddev_bytes"] = (
                    pooled_bytes["avg"], normalize.sigma(pooled_bytes["avg"],
                                                         pooled_bytes["var"]))
                b["avg_packets"], b["stddev_packets"] = (
                    pooled_packets["avg"], normalize.sigma(pooled_packets["avg"],
                                                           pooled_packets["var"]))
                # Percentiles move only when the seed is big enough to mean something, and only
                # upward: the seed's normal-approximation tail is what a wider band looks like.
                sb = normalize.sigma(pooled_bytes["avg"], pooled_bytes["var"])
                sp = normalize.sigma(pooled_packets["avg"], pooled_packets["var"])
                b["p95_bytes"] = normalize.widen(b["p95_bytes"],
                                                 pooled_bytes["avg"] + 1.645 * sb, n)
                b["p99_bytes"] = normalize.widen(b["p99_bytes"],
                                                 pooled_bytes["avg"] + 2.326 * sb, n)
                b["p999_bytes"] = normalize.widen(b["p999_bytes"],
                                                  pooled_bytes["avg"] + 3.090 * sb, n)
                b["p95_packets"] = normalize.widen(b["p95_packets"],
                                                   pooled_packets["avg"] + 1.645 * sp, n)
                b["p99_packets"] = normalize.widen(b["p99_packets"],
                                                   pooled_packets["avg"] + 2.326 * sp, n)
                b["p999_packets"] = normalize.widen(b["p999_packets"],
                                                    pooled_packets["avg"] + 3.090 * sp, n)
                b["seeded_entries"] = int(b.get("seeded_entries", 0)) + 1
                applied += 1
                touched = True
            if touched:
                hosts += 1
        return {"applied": applied, "hosts": hosts}

    def predict(self, flow: dict[str, Any],
                features: dict[str, float | None] | None = None) -> float:
        src = flow.get("src_addr") or ""
        b = self.baselines.get(src)
        if not b:
            return 0.0
        try:
            tb = float(flow.get("total_bytes", 0) or 0)
            tp = float(flow.get("total_packets", 0) or 0)
            s_b = score_by_percentile(tb, b["p95_bytes"], b["p99_bytes"], b["p999_bytes"])
            s_p = score_by_percentile(tp, b["p95_packets"], b["p99_packets"], b["p999_packets"])
            z = (float(flow.get("unique_dst_ips", 0)) - b["avg_unique_dsts"]) / max(b["stddev_unique_dsts"], 1.0)
            s_u = normalize_zscore(z)

            # BEHAVIOURAL dimension, from Zeek. Trained in train() and consumed here -- a
            # baseline that is computed but never consulted changes nothing, which is the
            # easiest way to wire something up and have it silently do no work.
            #
            # Gated on `zeek_seen`: a host with no Zeek baseline gets NO behavioural score
            # rather than a score of 0 against a zero baseline, which would either never fire
            # or fire constantly depending on how the divisor fell. Absence is not evidence.
            #
            # AND WITH MISSING-DATA HANDLING ON, a feature that is None means "not measured"
            # rather than 0: the same rule applies to the window. Scoring a missing conn
            # count as zero would price it as an infinitely quiet window, which is the
            # defect the flag exists to remove, so the behavioural term is skipped instead.
            s_z = 0.0
            conn = None if features is None else features.get("zeek_conn_count")
            s0 = None if features is None else features.get("zeek_s0_ratio")
            notices = None if features is None else features.get("zeek_notice_count")
            if b.get("zeek_seen") and conn is not None and s0 is not None and notices is not None:
                # Refused-and-unanswered connections relative to what is normal for THIS host.
                # A host whose established S0 rate is ~0 and which suddenly shows 88 of them is
                # the case this exists for; the same 88 on a host that always scans is not.
                conn = float(conn)
                s0 = float(s0)
                conn_z = (conn - b["avg_conn"]) / max(b["stddev_conn"], 1.0)
                # The observation is an S0 COUNT (ratio x conns) and is compared against the
                # host's own typical S0 COUNT, in the same units. The old ratio-vs-count
                # comparison was a units mismatch papered over by a 1.0 floor; the
                # count-scale baseline arrived with the measured dispersions, and the
                # .get() pair keeps pre-change artifacts working until the next retrain.
                s0_count = s0 * max(conn, 1.0)
                avg_s0_count = float(b.get("avg_s0_count", b.get("avg_s0", 0.0)) or 0.0)
                sd_s0_count = float(
                    b.get("stddev_s0_count", b.get("stddev_s0", 1.0)) or 1.0
                )
                s0_z = (s0_count - avg_s0_count) / max(sd_s0_count, 1.0)
                # Notices are Zeek's own opinion; a host that normally raises none raising
                # several is worth weighing even when its volume is unremarkable. The
                # divisor is the measured sigma when available (was: the mean itself).
                notice_z = (float(notices) - b["avg_notices"]) / max(
                    float(b.get("stddev_notices", b["avg_notices"]) or 0.0), 1.0
                )
                s_z = max(normalize_zscore(conn_z), normalize_zscore(s0_z),
                          normalize_zscore(notice_z))

            return max(s_b, s_p, s_u, s_z)
        except Exception as exc:  # noqa: BLE001
            return self.note_predict_error(exc)

    def persist_history(self, client: Client, window_hours: int) -> None:
        """Mirror baselines to ClickHouse for audit/rebuild (legacy behavior)."""
        from ..clock import utcnow

        rows = [[
            utcnow(), src, b["avg_bytes"], b["stddev_bytes"], b["avg_packets"], b["stddev_packets"],
            b["avg_unique_dsts"], b["stddev_unique_dsts"], 1, window_hours,
            b["p95_bytes"], b["p99_bytes"], b["p999_bytes"],
            b["p95_packets"], b["p99_packets"], b["p999_packets"],
        ] for src, b in self.baselines.items()]
        if not rows:
            return
        client.insert("weirvern.baseline_history", rows, column_names=[
            "computed_at", "src_addr", "avg_bytes", "stddev_bytes", "avg_packets",
            "stddev_packets", "avg_unique_dsts", "stddev_unique_dsts", "sample_count",
            "window_hours", "p95_bytes", "p99_bytes", "p999_bytes",
            "p95_packets", "p99_packets", "p999_packets",
        ])
        logger.info("💾 Persisted %d baselines to baseline_history", len(rows))


# ============================================================================
# THE ENGINE'S ROSTER
#
# THE ONE LIST OF DETECTORS THAT EXIST. `build_detectors` constructs exactly these, the Detectors
# table renders exactly these, and a name outside it has no row -- because a detector that is no
# longer built no longer exists. That is different from the training log: `ml_models` keeps history
# for every name that ever trained, and reading the table off that log is how a removed detector
# stayed on screen as a row about a model nobody could retrain.
DETECTOR_CLASSES: tuple[type[Any], ...] = (
    IsolationForestDetector,
    GradientBoostingDetector,
    KNNDistanceDetector,
    LOFDetector,
    AdaptiveBaselineDetector,
)
DETECTOR_NAMES: tuple[str, ...] = tuple(cls.name for cls in DETECTOR_CLASSES)
