"""Detector tests: training metadata, artifact persistence roundtrip (the
warm-start guarantee) — no ClickHouse needed (train paths are mocked)."""
import math
import re
from datetime import datetime

import numpy as np
import pytest

from weirvern.config import ModelConfig
from weirvern.features import DBSCAN_FEATURES, IF_FEATURES, ZEEK_FEATURES
from weirvern.models.base import ModelMetadata
from weirvern.models.detectors import (
    AdaptiveBaselineDetector,
    DBSCANDetector,
    IsolationForestDetector,
)
from weirvern.zeek_features import extract_zeek_features


class _TrainRows:
    def __init__(self, rows):
        self.result_rows = rows


class _TrainClient:
    """Just enough Client for DBSCANDetector.train: .query(...).result_rows."""

    def __init__(self, rows):
        self._rows = rows
        self.last_query = ""

    def query(self, _q, settings=None):  # noqa: ARG002 - signature parity
        self.last_query = _q
        return _TrainRows(self._rows)


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
    # 400 samples at the REAL vector width (len(IF_FEATURES)): the artifact contract
    # refuses a mismatch at load, so a toy width here would test the refusal, not warm-start.
    width = len(IF_FEATURES)
    X = rng.normal(10.0, 1.0, (400, width)).astype(float)
    X[:40, 0] = rng.uniform(15, 20, 40)  # extreme log_bytes
    det.preprocessor.fit_transform(X)
    Xs = det.preprocessor.transform(X)
    from sklearn.ensemble import IsolationForest

    det.model = IsolationForest(contamination=0.06, random_state=42).fit(Xs)  # type: ignore[arg-type]
    det.X_train_unscaled = X
    det.metadata = ModelMetadata(
        model_type="Isolation Forest", feature_columns=list(IF_FEATURES),
        params={"contamination": 0.06}, metrics={"anomaly_rate": 0.10},
        sample_count=400,
    )
    return det


def test_isolation_forest_scores_outlier(tmp_path):
    det = IsolationForestDetector(tmp_path, ModelConfig())
    assert not det.is_ready()
    rng = np.random.default_rng(2)
    X = rng.normal(10.0, 1.0, (300, len(IF_FEATURES))).astype(float)
    det.preprocessor.fit_transform(X)
    from sklearn.ensemble import IsolationForest

    det.model = IsolationForest(contamination=0.1, random_state=0).fit(det.preprocessor.transform(X))  # type: ignore[arg-type]
    assert det.is_ready()

    # Real-width vectors: `predict` builds by NAME from IF_FEATURES, so the scaler must
    # have been fitted at that same width or every score is the catch-all 0.0.
    normal = dict.fromkeys(IF_FEATURES, 0.0)
    normal["log_bytes"] = 10.0
    extreme = dict.fromkeys(IF_FEATURES, 0.0)
    extreme["log_bytes"] = 19.0
    s_n = det.predict({}, normal)
    s_e = det.predict({}, extreme)
    assert det.predict_errors == 0, "the scores were the catch-all fallback, not real ones"
    assert 0.0 <= s_n <= 1.0 and 0.0 <= s_e <= 1.0


def test_save_load_roundtrip(trained_if, tmp_path):
    """Warm start: a fresh detector must recover model+preprocessor from disk.

    The fixture trains on a vector with the REAL width (len(IF_FEATURES)): the artifact
    contract added in the 2026-10-15 review refuses an artifact whose recorded columns
    disagree with the running code, and a 14-column toy would be refused (correctly)."""
    trained_if.save()
    fresh = IsolationForestDetector(tmp_path, ModelConfig())
    assert not fresh.is_ready()
    assert fresh.load()
    assert fresh.is_ready()
    assert fresh.X_train_unscaled is not None
    # Scores must match pre-restart (the warm-start contract)
    feats = dict.fromkeys(IF_FEATURES, 0.0)
    feats["log_bytes"] = 17.0
    s_before = trained_if.predict({}, feats)
    s_after = fresh.predict({}, feats)
    assert abs(s_before - s_after) < 1e-6


def test_adaptive_baseline_predict():
    det = AdaptiveBaselineDetector("/tmp/ff-none", ModelConfig())
    det.baselines["198.51.100.5"] = {
        "avg_bytes": 1000.0, "stddev_bytes": 200.0,
        "avg_packets": 100.0, "stddev_packets": 20.0,
        "avg_unique_dsts": 5.0, "stddev_unique_dsts": 2.0,
        "p95_bytes": 1400.0, "p99_bytes": 1800.0, "p999_bytes": 2200.0,
        "p95_packets": 140.0, "p99_packets": 180.0, "p999_packets": 220.0,
    }
    normal = det.predict({"src_addr": "198.51.100.5", "total_bytes": 1000, "total_packets": 100, "unique_dst_ips": 5})
    assert normal == 0.0
    spike = det.predict(
        {"src_addr": "198.51.100.5", "total_bytes": 5_000_000,
         "total_packets": 100, "unique_dst_ips": 5}
    )
    assert spike > 0.8
    unknown = det.predict(
        {"src_addr": "203.0.113.9", "total_bytes": 5_000_000,
         "total_packets": 100, "unique_dst_ips": 5}
    )
    assert unknown == 0.0


def test_both_training_queries_order_the_sample_before_the_limit(tmp_path):
    """GitHub #61: a bare LIMIT returns a different subset on every run.

    The hash that selects the sample is the order of the cut, so a retrain sees the same
    rows for the same window regardless of ClickHouse part layout.
    """
    start, end = datetime(2026, 1, 1), datetime(2026, 1, 2)
    for det in (IsolationForestDetector(tmp_path, ModelConfig()),
                DBSCANDetector(tmp_path, ModelConfig())):
        client = _TrainClient([])
        det.train(start, end, client)
        assert re.search(
            r"ORDER BY sipHash64\(a\.src_addr, a\.window_start\)\s+LIMIT",
            client.last_query,
        ), f"{det.name} has no deterministic order before its sample limit"


def test_a_failed_service_history_leaves_rarity_at_zero_and_trains_volume(tmp_path):
    """GitHub #62: the auxiliary service query can fail while the volume baseline still
    trains. Every host must stay at rarity 0.0, not be handed a manufactured baseline of 1."""
    class _HistoryFails(_TrainClient):
        def query(self, q, settings=None):  # noqa: ARG002
            if "baseline_service_count" in q:
                raise RuntimeError("service history unavailable")
            if "baseline_ja4" in q:
                return _TrainRows([])
            return super().query(q, settings)

    def _row(i):
        # 9 volume/quantile values + 50 feature columns + presence + four sigmas.
        return (f"198.51.100.{i}", 1, 1, 1, 1, 1, 1, (1, 2, 3), (1, 2, 3),
                *([0.0] * len(ZEEK_FEATURES)), 1, 0.0, 0.0, 0.0, 0.0)

    det = AdaptiveBaselineDetector(tmp_path, ModelConfig())
    assert det.train(datetime(2026, 1, 1), datetime(2026, 1, 2),
                     _HistoryFails([_row(i) for i in range(10)]))

    assert len(det.baselines) == 10, "the volume baseline did not train"
    for baseline in det.baselines.values():
        assert "baseline_service_count" not in baseline
    rarity = extract_zeek_features(
        {"zeek_present": 1, "zeek_service_count": math.log1p(5)}, det.baselines["198.51.100.0"])
    assert rarity["zeek_service_rarity"] == 0.0


def test_dbscan_says_so_when_it_finds_no_clusters(tmp_path, caplog):
    """A trained-but-centreless DBSCAN must be LOUD, not a silent zero-scorer.

    Measured, review round 2026-10-15: on the eval seed, DBSCAN formed 2 cluster
    centres at 146 sampled training rows and 0 at 124 -- same code, same seed shape,
    different volume. With no centres every score is the "no opinion" 0.0 and
    is_ready() is False, so the scan-family specialist is effectively off -- and the
    old log line ("trained: 0 clusters") said nothing about any of that."""
    rng = np.random.default_rng(0)
    rows = [tuple(rng.normal(10.0, 1.0, len(DBSCAN_FEATURES))) for _ in range(120)]
    det = DBSCANDetector(tmp_path, ModelConfig())

    with caplog.at_level("WARNING"):
        assert not det.train(datetime(2026, 1, 1), datetime(2026, 1, 2), _TrainClient(rows)), (
            "a centreless DBSCAN claimed it could score")

    assert not det.cluster_centers, "uniform noise should not form 0.6-eps clusters"
    assert det.metadata.metrics["clusters"] == 0
    assert not det.is_ready(), "a detector that can never score must not claim readiness"
    assert det.predict({}, dict.fromkeys(DBSCAN_FEATURES, 0.0)) == 0.0
    assert any("NO CLUSTER CENTRES" in m for m in caplog.messages), (
        "the centreless state must be a WARNING -- it disables the scan-family escalation"
    )


# ── A FAILURE MUST SAY WHICH FAILURE IT IS (WV1-22) ─────────────────────────────────────────────
#
# train() returns a bare bool and returns False for two unrelated reasons: too few rows, or enough
# rows with no dense region. Callers could not tell them apart, so the detection-quality gate
# explained a 195-row failure with "DBSCAN needs >=100 rows" -- a cause its own log line
# contradicted, sending the operator after a remedy that does not address what was reported.


def test_TOO_FEW_ROWS_is_recorded_as_a_row_shortfall(tmp_path, caplog):
    rows = [(1.0,) * len(DBSCAN_FEATURES)] * 40   # below the 100 floor
    det = DBSCANDetector(tmp_path, ModelConfig())

    with caplog.at_level("WARNING"):
        assert not det.train(datetime(2026, 1, 1), datetime(2026, 1, 2), _TrainClient(rows))

    assert det.train_outcome == "insufficient-rows", (
        f"a row shortfall was recorded as {det.train_outcome!r}; the caller cannot tell it from "
        f"the opposite case and will explain it with the wrong cause"
    )
    assert any("floor 100" in m for m in caplog.messages), (
        f"the floor must be in the message, or 12 rows and 99 read the same: {caplog.messages}"
    )


def test_ENOUGH_ROWS_WITH_NO_DENSE_REGION_is_a_DIFFERENT_failure(tmp_path, caplog):
    """The measured case: 195 rows, above the floor, no centres. The remedy is eps/min_samples,
    not a longer seed."""
    rng = np.random.default_rng(0)
    rows = [tuple(rng.normal(10.0, 1.0, len(DBSCAN_FEATURES))) for _ in range(195)]
    det = DBSCANDetector(tmp_path, ModelConfig())

    with caplog.at_level("WARNING"):
        assert not det.train(datetime(2026, 1, 1), datetime(2026, 1, 2), _TrainClient(rows))

    assert det.train_outcome == "no-dense-structure", (
        f"195 rows above the floor was recorded as {det.train_outcome!r}, which is the state that "
        f"made the gate blame the row count"
    )
    assert not any("Not enough data" in m for m in caplog.messages), (
        "a row-shortfall warning was emitted for a row count above the floor"
    )


def test_a_HEALTHY_train_is_recorded_as_ok(tmp_path):
    rng = np.random.default_rng(7)
    # Three tight, well-separated blobs: DBSCAN finds them at eps=0.6.
    rows = [tuple(rng.normal(c, 0.01, len(DBSCAN_FEATURES))) for c in (2.0, 20.0, 60.0)
            for _ in range(60)]
    det = DBSCANDetector(tmp_path, ModelConfig())

    assert det.train(datetime(2026, 1, 1), datetime(2026, 1, 2), _TrainClient(rows))
    assert det.train_outcome == "ok", det.train_outcome
    assert det.cluster_centers, "the fixture should have produced centres"
