"""Detector tests: training metadata, artifact persistence roundtrip (the
warm-start guarantee) — no ClickHouse needed (train paths are mocked)."""
import numpy as np
import pytest

from weirvern.config import ModelConfig
from weirvern.models.base import ModelMetadata
from weirvern.models.detectors import AdaptiveBaselineDetector, IsolationForestDetector


def test_metadata_row_shape():
    m = ModelMetadata(model_type="X", feature_columns=["a", "b"])
    row = m.to_row()
    assert row["model_type"] == "X"
    assert isinstance(row["model_id"], str) and row["model_id"]
    assert row["feature_columns"] == ["a", "b"]
    assert len(row) == 11


@pytest.fixture()
def trained_if(tmp_path):
    det = IsolationForestDetector(tmp_path, ModelConfig())
    rng = np.random.default_rng(1)
    # 400 samples: 360 normal-ish, 40 anomalies (extreme bytes)
    X = rng.normal(10.0, 1.0, (400, 14)).astype(float)
    X[:40, 0] = rng.uniform(15, 20, 40)  # extreme log_bytes
    det.preprocessor.fit_transform(X)
    Xs = det.preprocessor.transform(X)
    from sklearn.ensemble import IsolationForest

    det.model = IsolationForest(contamination=0.06, random_state=42).fit(Xs)  # type: ignore[arg-type]
    det.X_train_unscaled = X
    det.metadata = ModelMetadata(
        model_type="Isolation Forest", feature_columns=["x"] * 14,
        params={"contamination": 0.06}, metrics={"anomaly_rate": 0.10},
        sample_count=400,
    )
    return det


def test_isolation_forest_scores_outlier(tmp_path):
    det = IsolationForestDetector(tmp_path, ModelConfig())
    assert not det.is_ready()
    rng = np.random.default_rng(2)
    X = rng.normal(10.0, 1.0, (300, 14)).astype(float)
    det.preprocessor.fit_transform(X)
    from sklearn.ensemble import IsolationForest

    det.model = IsolationForest(contamination=0.1, random_state=0).fit(det.preprocessor.transform(X))  # type: ignore[arg-type]
    assert det.is_ready()

    normal = dict.fromkeys([f"f{i}" for i in range(14)], 0.0)
    normal["log_bytes"] = 10.0
    s_n = det.predict({}, {"log_bytes": 10.0, **{f"f{i}": 0.0 for i in range(1, 14)}})
    s_e = det.predict({}, {"log_bytes": 19.0, **{f"f{i}": 0.0 for i in range(1, 14)}})
    assert s_e >= s_n >= 0.0


def test_save_load_roundtrip(trained_if, tmp_path):
    """Warm start: a fresh detector must recover model+preprocessor from disk."""
    trained_if.save()
    fresh = IsolationForestDetector(tmp_path, ModelConfig())
    assert not fresh.is_ready()
    assert fresh.load()
    assert fresh.is_ready()
    assert fresh.X_train_unscaled is not None
    # Scores must match pre-restart (the warm-start contract)
    feats = {"log_bytes": 17.0, **{f"f{i}": 0.0 for i in range(1, 14)}}
    s_before = trained_if.predict({}, feats)
    s_after = fresh.predict({}, feats)
    assert abs(s_before - s_after) < 1e-6


def test_adaptive_baseline_predict():
    det = AdaptiveBaselineDetector("/tmp/ff-none", ModelConfig())
    det.baselines["10.0.0.5"] = {
        "avg_bytes": 1000.0, "stddev_bytes": 200.0,
        "avg_packets": 100.0, "stddev_packets": 20.0,
        "avg_unique_dsts": 5.0, "stddev_unique_dsts": 2.0,
        "p95_bytes": 1400.0, "p99_bytes": 1800.0, "p999_bytes": 2200.0,
        "p95_packets": 140.0, "p99_packets": 180.0, "p999_packets": 220.0,
    }
    normal = det.predict({"src_addr": "10.0.0.5", "total_bytes": 1000, "total_packets": 100, "unique_dst_ips": 5})
    assert normal == 0.0
    spike = det.predict({"src_addr": "10.0.0.5", "total_bytes": 5_000_000, "total_packets": 100, "unique_dst_ips": 5})
    assert spike > 0.8
    unknown = det.predict({"src_addr": "10.9.9.9", "total_bytes": 5_000_000, "total_packets": 100, "unique_dst_ips": 5})
    assert unknown == 0.0
