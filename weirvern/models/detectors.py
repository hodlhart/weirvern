"""The four detectors, rebuilt from the v19 model code with the lessons applied:

1. IsolationForestDetector — v19's 14-feature multi-granularity version with
   extremes sampling retained (trains on normal traffic AND extreme outliers).
2. GradientBoostingDetector — semi-supervised student of the Isolation Forest,
   class-imbalance weighted, F1-evaluated on a held-out split.
3. DBSCANDetector — 8-feature clustering; score = distance to nearest centroid.
4. AdaptiveBaselineDetector — per-host percentile/σ baselines from ClickHouse.

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
from sklearn.cluster import DBSCAN
from sklearn.ensemble import GradientBoostingClassifier, IsolationForest
from sklearn.impute import SimpleImputer
from sklearn.metrics import f1_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

from weirvern.config import ModelConfig
from weirvern.features import DBSCAN_FEATURES, IF_FEATURES, feature_vector
from weirvern.models.base import BaseDetector, ModelMetadata
from weirvern.models.scoring import (
    calibrate_distance,
    calibrate_isolation_forest,
    calibrate_probability,
    normalize_zscore,
    score_by_percentile,
)
from weirvern.zeek_features import (
    ZEEK_DBSCAN_FEATURES,
    ZEEK_FEATURES,
    ZEEK_JOIN_ON,
    zeek_join_cte,
)

logger = logging.getLogger(__name__)

QUERY_SETTINGS = {"max_memory_usage": 4_000_000_000, "max_execution_time": 120}



def _zeek_clause(start: str, end: str, columns: list[str] | None = None) -> tuple[str, str, str]:
    """(with-clause, select-list, join-clause) for the Zeek side of a training query.

    One helper for all four detectors. Duplicating the join per detector is how the models
    drift apart: three training on one window and the fourth on a slightly different key,
    which no metric would show and which would appear only as one detector disagreeing with
    the others for no stated reason.

    `columns` selects which Zeek features to include. The DEFAULT is all of them, matching
    IF_FEATURES; DBSCAN passes its smaller set, because clustering degrades with
    dimensionality when samples are few.
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


# ============================================================================
class IsolationForestDetector(BaseDetector):
    name = "Isolation Forest"

    def __init__(self, model_dir, cfg: ModelConfig | None = None):
        super().__init__(model_dir)
        self.cfg = cfg or ModelConfig()
        self.model: IsolationForest | None = None
        self.preprocessor = RobustPreprocessor()
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
            FROM weirvern.flows_aggregated a
            LEFT JOIN weirvern.flows_aggregated_diversity d
                ON a.window_start = d.window_start AND a.src_addr = d.src_addr
            {zeek_join}
            WHERE a.window_start BETWEEN '{s}' AND '{e}'
              AND a.total_bytes > 0
              AND (
                  sipHash64(a.src_addr, a.window_start) % 10 < 7
                  OR a.total_bytes IN (
                      SELECT total_bytes FROM weirvern.flows_aggregated
                      WHERE window_start BETWEEN '{s}' AND '{e}'
                      ORDER BY total_bytes DESC LIMIT {int(self.cfg.if_extremes)})
                  OR coalesce(d.unique_dst_ports, 0) IN (
                      SELECT unique_dst_ports FROM weirvern.flows_aggregated_diversity
                      WHERE window_start BETWEEN '{s}' AND '{e}'
                      ORDER BY unique_dst_ports DESC LIMIT {int(self.cfg.if_extremes)})
              ){excl}
            LIMIT {int(self.cfg.if_n_samples)}
        """
        data = client.query(q, settings=QUERY_SETTINGS).result_rows
        if len(data) < 100:
            logger.warning("Not enough data for %s (%d rows)", self.name, len(data))
            return False

        X = np.asarray(data, dtype=float)
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

    def predict(self, flow: dict[str, Any], features: dict[str, float] | None = None) -> float:
        model = self.model
        if model is None:
            return 0.0
        try:
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
        self.preprocessor = RobustPreprocessor()
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

    def predict(self, flow: dict[str, Any], features: dict[str, float] | None = None) -> float:
        model = self.model
        if model is None:
            return 0.0
        try:
            vec = feature_vector(features or {}, IF_FEATURES)
            X = self.preprocessor.transform(np.asarray([vec], dtype=float))
            p = model.predict_proba(X)[0]
            return calibrate_probability(float(p[1]), self.calibration)
        except Exception as exc:  # noqa: BLE001
            return self.note_predict_error(exc)


# ============================================================================
class DBSCANDetector(BaseDetector):
    name = "DBSCAN"

    def __init__(self, model_dir, cfg: ModelConfig | None = None):
        super().__init__(model_dir)
        self.cfg = cfg or ModelConfig()
        self.cluster_centers: list[np.ndarray] = []
        self.preprocessor = RobustPreprocessor()
        # Percentile calibration of training distances to the nearest centre (set at
        # train time). See calibrate_distance for why the old fixed /5.0 had to go.
        self.calibration: dict[str, float] = {}

    def is_ready(self) -> bool:
        return len(self.cluster_centers) > 0

    def expected_feature_columns(self) -> list[str]:
        return list(DBSCAN_FEATURES)

    def train(self, start_dt: datetime, end_dt: datetime, client: Client) -> bool:
        st = time.time()
        s, e = start_dt.strftime("%Y-%m-%d %H:%M:%S"), end_dt.strftime("%Y-%m-%d %H:%M:%S")
        zeek_cte, zeek_cols, zeek_join = _zeek_clause(s, e, ZEEK_DBSCAN_FEATURES)
        # Training hygiene: do not learn from windows the system already flagged (see
        # _flagged_exclusion_clause). Empty string when disabled.
        excl = _flagged_exclusion_clause(s, e, self.cfg)
        q = f"""  # nosec B608 - interpolates formatted datetimes + int config only, never flow data
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
            FROM weirvern.flows_aggregated a
            LEFT JOIN weirvern.flows_aggregated_diversity d
                ON a.window_start = d.window_start AND a.src_addr = d.src_addr
            LEFT JOIN weirvern.flows_aggregated_temporal t
                ON a.window_start = t.window_start AND a.src_addr = t.src_addr
            {zeek_join}
            WHERE a.window_start BETWEEN '{s}' AND '{e}'
              AND a.total_bytes > 0
              AND sipHash64(a.src_addr) % 5 == 1{excl}
            LIMIT {int(self.cfg.dbscan_n_samples)}
        """
        data = client.query(q, settings=QUERY_SETTINGS).result_rows
        if len(data) < 100:
            logger.warning("Not enough data for %s (%d rows)", self.name, len(data))
            return False
        Xs = self.preprocessor.fit_transform(np.asarray(data, dtype=float))
        labels = DBSCAN(eps=self.cfg.dbscan_eps, min_samples=self.cfg.dbscan_min_samples).fit_predict(Xs)
        self.cluster_centers = [np.mean(Xs[labels == cid], axis=0) for cid in set(labels) if cid != -1]
        n_clusters, n_outliers = len(self.cluster_centers), int((labels == -1).sum())

        # CALIBRATE THE DISTANCE MAPPING against the training distribution.
        #
        # The predict() score was `distance / 5.0` -- a fixed divisor unrelated to the
        # data's scale, which made the detector un-corroborable on tight clusters and
        # saturated on loose ones. Every training sample's distance to its NEAREST
        # cluster centre is recorded here by percentile, so predict() can grade a new
        # distance against what normal looked like for THIS deployment.
        if self.cluster_centers:
            dists = np.array([
                min(float(np.linalg.norm(x - c)) for c in self.cluster_centers)
                for x in Xs
            ])
            self.calibration = {
                "p50": float(np.percentile(dists, 50)),
                "p95": float(np.percentile(dists, 95)),
                "p99": float(np.percentile(dists, 99)),
            }

        self.metadata = ModelMetadata(
            model_type=self.name, duration_seconds=time.time() - st,
            feature_columns=DBSCAN_FEATURES,
            params={"eps": self.cfg.dbscan_eps, "min_samples": self.cfg.dbscan_min_samples,
                    "n_samples": len(Xs),
                    "calibration": {k: round(v, 6) for k, v in self.calibration.items()}},
            metrics={"clusters": n_clusters, "outliers": n_outliers},
            window_start=start_dt, window_end=end_dt, sample_count=len(Xs),
        )
        logger.info("✅ %s trained: %d clusters, %d outliers", self.name, n_clusters, n_outliers)
        self.save()
        return True

    def predict(self, flow: dict[str, Any], features: dict[str, float] | None = None) -> float:
        if not self.cluster_centers:
            return 0.0
        try:
            vec = np.asarray(feature_vector(features or {}, DBSCAN_FEATURES), dtype=float)
            Xp = self.preprocessor.transform(np.asarray([vec], dtype=float))[0]
            dist = min(float(np.linalg.norm(Xp - c)) for c in self.cluster_centers)
            # Graded against the training distribution (see calibrate_distance), not a
            # fixed divisor; falls back to the old shape for artifacts trained before
            # the calibration existed, so a stale artifact keeps its behaviour until
            # the next retrain replaces it.
            return calibrate_distance(dist, self.calibration)
        except Exception as exc:  # noqa: BLE001
            return self.note_predict_error(exc)


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
        self.baselines: dict[str, dict[str, float]] = {}

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
            FROM weirvern.flows_aggregated a
            {zeek_join}
            WHERE a.window_start BETWEEN '{s}' AND '{e}'{excl}
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
        self.metadata = ModelMetadata(
            model_type=self.name, duration_seconds=time.time() - st,
            params={"min_obs": self.cfg.baseline_min_obs},
            metrics={"baseline_count": len(self.baselines),
                     "zeek_baselined_hosts": zeek_seen_hosts},
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

    def predict(self, flow: dict[str, Any], features: dict[str, float] | None = None) -> float:
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
            s_z = 0.0
            if b.get("zeek_seen") and features:
                # Refused-and-unanswered connections relative to what is normal for THIS host.
                # A host whose established S0 rate is ~0 and which suddenly shows 88 of them is
                # the case this exists for; the same 88 on a host that always scans is not.
                conn = float(features.get("zeek_conn_count", 0.0) or 0.0)
                s0 = float(features.get("zeek_s0_ratio", 0.0) or 0.0)
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
                notices = float(features.get("zeek_notice_count", 0.0) or 0.0)
                notice_z = (notices - b["avg_notices"]) / max(
                    float(b.get("stddev_notices", b["avg_notices"]) or 0.0), 1.0
                )
                s_z = max(normalize_zscore(conn_z), normalize_zscore(s0_z),
                          normalize_zscore(notice_z))

            return max(s_b, s_p, s_u, s_z)
        except Exception as exc:  # noqa: BLE001
            return self.note_predict_error(exc)

    def persist_history(self, client: Client, window_hours: int) -> None:
        """Mirror baselines to ClickHouse for audit/rebuild (legacy behavior)."""
        from datetime import datetime as _dt

        rows = [[
            _dt.now(), src, b["avg_bytes"], b["stddev_bytes"], b["avg_packets"], b["stddev_packets"],
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
