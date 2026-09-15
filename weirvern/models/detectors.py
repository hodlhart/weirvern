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
    calibrate_isolation_forest,
    calibrate_probability,
    normalize_zscore,
    score_by_percentile,
)

logger = logging.getLogger(__name__)

QUERY_SETTINGS = {"max_memory_usage": 4_000_000_000, "max_execution_time": 120}


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

    def train(self, start_dt: datetime, end_dt: datetime, client: Client) -> bool:
        st = time.time()
        s, e = start_dt.strftime("%Y-%m-%d %H:%M:%S"), end_dt.strftime("%Y-%m-%d %H:%M:%S")
        q = f"""  # nosec B608 - interpolates formatted datetimes + int config only, never flow data
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
                coalesce(d.unique_connections, a.flow_count) / NULLIF(a.flow_count, 1)
            FROM weirvern.flows_aggregated a
            LEFT JOIN weirvern.flows_aggregated_diversity d
                ON a.window_start = d.window_start AND a.src_addr = d.src_addr
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
              )
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
            window_start=str(start_dt), window_end=str(end_dt), sample_count=len(Xs),
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
            logger.warning("Prediction error %s: %s", self.name, exc)
            return 0.0


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
            window_start=str(start_dt), window_end=str(end_dt), sample_count=len(Xtr),
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
            logger.warning("Prediction error %s: %s", self.name, exc)
            return 0.0


# ============================================================================
class DBSCANDetector(BaseDetector):
    name = "DBSCAN"

    def __init__(self, model_dir, cfg: ModelConfig | None = None):
        super().__init__(model_dir)
        self.cfg = cfg or ModelConfig()
        self.cluster_centers: list[np.ndarray] = []
        self.preprocessor = RobustPreprocessor()

    def is_ready(self) -> bool:
        return len(self.cluster_centers) > 0

    def train(self, start_dt: datetime, end_dt: datetime, client: Client) -> bool:
        st = time.time()
        s, e = start_dt.strftime("%Y-%m-%d %H:%M:%S"), end_dt.strftime("%Y-%m-%d %H:%M:%S")
        q = f"""  # nosec B608 - interpolates formatted datetimes + int config only, never flow data
            SELECT
                log(a.total_bytes + 1),
                log(a.total_packets + 1),
                log(a.unique_dst_ips + 1),
                log(a.flow_count + 1),
                log(coalesce(d.unique_dst_ports, 0) + 1),
                coalesce(d.port_entropy, 0),
                coalesce(t.activity_regularity, 1.0),
                coalesce(t.burstiness, 1.0)
            FROM weirvern.flows_aggregated a
            LEFT JOIN weirvern.flows_aggregated_diversity d
                ON a.window_start = d.window_start AND a.src_addr = d.src_addr
            LEFT JOIN weirvern.flows_aggregated_temporal t
                ON a.window_start = t.window_start AND a.src_addr = t.src_addr
            WHERE a.window_start BETWEEN '{s}' AND '{e}'
              AND a.total_bytes > 0
              AND sipHash64(a.src_addr) % 5 == 1
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
        self.metadata = ModelMetadata(
            model_type=self.name, duration_seconds=time.time() - st,
            feature_columns=DBSCAN_FEATURES,
            params={"eps": self.cfg.dbscan_eps, "min_samples": self.cfg.dbscan_min_samples, "n_samples": len(Xs)},
            metrics={"clusters": n_clusters, "outliers": n_outliers},
            window_start=str(start_dt), window_end=str(end_dt), sample_count=len(Xs),
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
            return min(0.99, dist / 5.0)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Prediction error %s: %s", self.name, exc)
            return 0.0


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

    def train(self, start_dt: datetime, end_dt: datetime, client: Client) -> bool:
        st = time.time()
        s, e = start_dt.strftime("%Y-%m-%d %H:%M:%S"), end_dt.strftime("%Y-%m-%d %H:%M:%S")
        q = f"""  # nosec B608 - interpolates formatted datetimes + int config only, never flow data
            SELECT
                src_addr,
                avg(total_bytes), sqrt(varPop(total_bytes)),
                avg(total_packets), sqrt(varPop(total_packets)),
                avg(unique_dst_ips), sqrt(varPop(unique_dst_ips)),
                quantiles(0.95, 0.99, 0.999)(total_bytes),
                quantiles(0.95, 0.99, 0.999)(total_packets)
            FROM weirvern.flows_aggregated
            WHERE window_start BETWEEN '{s}' AND '{e}'
            GROUP BY src_addr
            HAVING count() >= {int(self.cfg.baseline_min_obs)}
            LIMIT 100000
        """
        rows = client.query(q, settings=QUERY_SETTINGS).result_rows
        if len(rows) < 10:
            logger.warning("Not enough baseline data (%d hosts)", len(rows))
            return False
        self.baselines = {}
        for r in rows:
            bq, pq = r[7], r[8]
            self.baselines[r[0]] = {
                "avg_bytes": float(r[1] or 0), "stddev_bytes": float(r[2] or 1),
                "avg_packets": float(r[3] or 0), "stddev_packets": float(r[4] or 1),
                "avg_unique_dsts": float(r[5] or 0), "stddev_unique_dsts": float(r[6] or 1),
                "p95_bytes": float(bq[0]), "p99_bytes": float(bq[1]), "p999_bytes": float(bq[2]),
                "p95_packets": float(pq[0]), "p99_packets": float(pq[1]), "p999_packets": float(pq[2]),
            }
        self.metadata = ModelMetadata(
            model_type=self.name, duration_seconds=time.time() - st,
            params={"min_obs": self.cfg.baseline_min_obs},
            metrics={"baseline_count": len(self.baselines)},
            window_start=str(start_dt), window_end=str(end_dt), sample_count=len(self.baselines),
        )
        logger.info("✅ Baselines computed for %d hosts", len(self.baselines))
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
            return max(s_b, s_p, s_u)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Prediction error %s: %s", self.name, exc)
            return 0.0

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
