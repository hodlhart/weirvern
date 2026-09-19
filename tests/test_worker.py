"""Worker tests — retrain cadence, sweep verdict handling, and row dedup.

No ClickHouse required: detectors are stubs and the client is a fake. The
baseline fake subclasses the real AdaptiveBaselineDetector so the worker's
isinstance-based lookup (which deliberately avoids positional indexing) is
exercised faithfully.
"""
from datetime import datetime, timedelta
from typing import Any

from weirvern.config import ModelConfig, Settings
from weirvern.models.detectors import AdaptiveBaselineDetector
from weirvern.worker import detection_sweep, train_if_due


class _FakeMeta:
    def to_row(self):
        return {
            "model_id": "m", "model_type": "t", "trained_at": 1,
            "training_duration_seconds": 1, "feature_columns": [], "model_params": "{}",
            "metrics": "{}", "training_window_start": "", "training_window_end": "",
            "training_sample_count": 0, "current_weight": 1.0,
        }


class FakeModel:
    """Counting detector stub (duck-typed; not an isinstance target)."""

    def __init__(self, name, train_ok=True):
        self.name = name
        self.trains = 0
        self.train_ok = train_ok
        self.X_train_unscaled = object() if name == "Isolation Forest" else None
        self.metadata = _FakeMeta()

    def train(self, *a, **k):
        self.trains += 1
        return self.train_ok

    def load(self):
        return False

    def is_ready(self):
        return False

    def persist_history(self, client, window_hours):
        pass


class FakeBaseline(AdaptiveBaselineDetector):
    """Real detector type (so isinstance finds it) with a counted, DB-free train."""

    def __init__(self, model_dir="/tmp/ff-fake-baseline", cfg=None):  # noqa: ANN001
        super().__init__(model_dir, cfg or ModelConfig())
        self.trains = 0
        self.train_ok = True
        self.history_calls = 0

    def train(self, *a, **k):  # noqa: ANN002, ANN003
        self.trains += 1
        return self.train_ok

    def persist_history(self, client, window_hours):  # noqa: ANN001
        self.history_calls += 1

    def load(self):
        return False


class FakeClient:
    def insert(self, *a, **k):
        pass


fake_client: Any = FakeClient()


def fake_detectors():
    """(detectors, named-tuple) with a real-typed baseline, in build_detectors order."""
    if_model = FakeModel("Isolation Forest")
    gb_model = FakeModel("Gradient Boosting")
    db_model = FakeModel("DBSCAN")
    bl_model = FakeBaseline()
    return [if_model, gb_model, db_model, bl_model], (if_model, gb_model, db_model, bl_model)


class FakeSettings:
    retrain_every_h = 6
    retrain_window_h = 72


# --- cadence -----------------------------------------------------------------
def test_first_call_always_full_trains():
    detectors, (if_m, gb_m, db_m, bl_m) = fake_detectors()
    result = train_if_due(fake_client, detectors, FakeSettings(), ModelConfig(), last_full_train=None)
    assert result is not None
    assert if_m.trains == 1
    assert db_m.trains == 1
    assert bl_m.trains == 1
    assert gb_m.trains == 1  # student trains when the teacher did


def test_not_due_refreshes_baseline_only():
    detectors, (if_m, gb_m, db_m, bl_m) = fake_detectors()
    last = datetime.now()
    result = train_if_due(fake_client, detectors, FakeSettings(), ModelConfig(), last_full_train=last)
    assert result == last  # full-train timestamp unchanged
    assert if_m.trains == 0
    assert gb_m.trains == 0
    assert db_m.trains == 0
    assert bl_m.trains == 1  # fast baseline refresh
    assert bl_m.history_calls == 1  # DB mirror kept in step with the artifact


def test_cadence_does_not_advance_when_nothing_trained():
    """Reviewer finding: the timestamp advanced even when every train() failed,
    deferring the next full retrain a whole cadence with stale models."""
    detectors, (if_m, gb_m, db_m, bl_m) = fake_detectors()
    for m in (if_m, gb_m, db_m, bl_m):
        m.train_ok = False
    stale = datetime.now() - timedelta(hours=7)
    result = train_if_due(fake_client, detectors, FakeSettings(), ModelConfig(), last_full_train=stale)
    assert result == stale, "cadence advanced despite nothing training"


def test_fast_path_finds_baseline_without_positional_coupling():
    """Reviewer finding: the fast path used detectors[3] positionally."""
    if_m = FakeModel("Isolation Forest")
    bl_m = FakeBaseline()
    others = [FakeModel("Gradient Boosting"), FakeModel("DBSCAN")]
    detectors = [if_m, bl_m, *others]  # baseline deliberately NOT last
    last = datetime.now()
    train_if_due(fake_client, detectors, FakeSettings(), ModelConfig(), last_full_train=last)
    assert bl_m.trains == 1, "baseline refresh did not run (positional coupling?)"
    assert if_m.trains == 0


def test_due_triggers_full_retrain():
    detectors, (if_m, gb_m, db_m, bl_m) = fake_detectors()
    stale = datetime.now() - timedelta(hours=7)
    result = train_if_due(fake_client, detectors, FakeSettings(), ModelConfig(), last_full_train=stale)
    assert result is not None and result > stale
    assert if_m.trains == 1
    assert bl_m.trains >= 1


# --- sweep -------------------------------------------------------------------
class StubDetector:
    def __init__(self, score):
        self.score = score
        self.name = f"Stub{score}"

    def predict(self, flow, features=None):  # noqa: ANN001
        return self.score

    def is_ready(self):
        return True


AGG_COLS = ["window_start", "window_end", "src_addr", "flow_count", "total_bytes",
            "total_packets", "avg_bytes", "avg_packets", "unique_dst_ips"]
AGG_ROWS = [(datetime(2026, 9, 14, 10, 30), datetime(2026, 9, 14, 10, 35),
             "198.51.100.10", 60, 500_000, 500, 9000.0, 9.0, 8)]


def _install_db_stubs(monkeypatch, existing_anomalies):
    """Stub db access: aggregates present, optional pre-existing anomaly rows."""
    import weirvern.db as db

    def fake_named(client, query, **params):  # noqa: ANN001
        if "flows_aggregated_diversity" in query or "flows_aggregated_temporal" in query:
            return ["window_start", "src_addr"], []
        return AGG_COLS, AGG_ROWS

    def fake_rows(client, query, **params):  # noqa: ANN001
        if "netflow_anomalies" in query:
            return existing_anomalies
        return []

    monkeypatch.setattr(db, "fetch_rows_named", fake_named)
    monkeypatch.setattr(db, "fetch_rows", fake_rows)


def _capturing_client():
    inserted: list = []

    class FakeCH:
        def insert(self, table, rows, column_names=None):  # noqa: ANN001
            inserted.extend(rows)

    fake: Any = FakeCH()
    return fake, inserted


def test_detection_sweep_returns_exact_verdicts(monkeypatch):
    """v20 regression: alerts must come from THIS sweep's verdicts (once),
    not a re-query that re-alerted old rows every cycle."""
    _install_db_stubs(monkeypatch, existing_anomalies=[])
    fake_ch, inserted_rows = _capturing_client()
    detectors = [StubDetector(0.9), StubDetector(0.88)]  # both fire → verdict

    verdicts = detection_sweep(fake_ch, detectors, Settings(), ModelConfig())

    assert len(verdicts) == 1
    assert len(inserted_rows) == 1
    assert verdicts[0]["src_addr"] == "198.51.100.10"
    assert verdicts[0]["anomaly_score"] > 0.8


def test_sweep_skips_already_recorded_windows(monkeypatch):
    """Reviewer finding (verified live before the fix): overlapping sweeps
    re-inserted the same (window_start, src_addr) anomaly row."""
    _install_db_stubs(
        monkeypatch,
        existing_anomalies=[(datetime(2026, 9, 14, 10, 30), "198.51.100.10")],
    )
    fake_ch, inserted_rows = _capturing_client()
    detectors = [StubDetector(0.9), StubDetector(0.88)]

    verdicts = detection_sweep(fake_ch, detectors, Settings(), ModelConfig())

    assert inserted_rows == [], "duplicate anomaly row was re-inserted"
    assert verdicts == [], "already-recorded window must not be re-returned for alerting"


def test_min_agreement_setting_actually_gates_detections(monkeypatch):
    """MIN_AGREEMENT was documented, validated, and surfaced in `weirvern tune`,
    but NOTHING read it: ensemble.py hardcoded `0.33 if score < 0.6 else 0.25`.
    An operator raising MIN_AGREEMENT to demand broader detector agreement saw no
    change at all, with no way to tell the setting was inert.

    This test fails if the gate ever stops consulting settings.min_agreement.

    Configuration, measured rather than assumed: 4 detectors, 1 firing at 0.5, so
    agreement = 1/4 = 0.25 and the score (0.5) is below 0.6, i.e. this exercises
    the LOW-score tier. Both sides have real margin: 0.25 vs the 0.33 default
    (suppressed by 0.08), and 0.25 vs a relaxed 0.18 (passes by 0.07). An earlier
    version of this test used a case that landed exactly ON a tier boundary --
    agreement 0.25 against a high-score tier of 0.25 -- which asserted nothing
    useful because the comparison is strict.
    """
    detectors = [StubDetector(0.5), StubDetector(0.01), StubDetector(0.01),
                 StubDetector(0.01)]

    # Default MIN_AGREEMENT (0.33): a lone-detector 0.25 agreement is suppressed.
    _install_db_stubs(monkeypatch, existing_anomalies=[])
    fake_ch, rows = _capturing_client()
    assert detection_sweep(fake_ch, detectors, Settings(), ModelConfig()) == [], \
        "a 0.25 agreement must not pass the default 0.33 gate"
    assert rows == []

    # Relax MIN_AGREEMENT below 0.25: the same window must now pass. If the
    # setting is inert, this assertion is what fails.
    _install_db_stubs(monkeypatch, existing_anomalies=[])
    fake_ch2, rows2 = _capturing_client()
    verdicts = detection_sweep(fake_ch2, detectors, Settings(min_agreement=0.18),
                              ModelConfig())
    assert len(verdicts) == 1, (
        "MIN_AGREEMENT=0.18 did not let a 0.25-agreement detection through, "
        "which means the setting is not being read"
    )
    assert len(rows2) == 1
    assert verdicts[0]["model_agreement"] == 0.25


def test_min_agreement_also_gates_the_high_score_tier(monkeypatch):
    """The high-score tier (score >= 0.6) is MIN_AGREEMENT minus the margin. It
    must respond to MIN_AGREEMENT too, not stay pinned at its default.

    Measured: 5 detectors, 1 firing at 0.92 -> agreement = 0.2. The default high
    tier is 0.25, so 0.2 is suppressed; relaxing MIN_AGREEMENT to 0.18 moves the
    tier to the floor (0.20) and lets it through.
    """
    detectors = [StubDetector(0.92)] + [StubDetector(0.01)] * 4

    _install_db_stubs(monkeypatch, existing_anomalies=[])
    fake_ch, _ = _capturing_client()
    assert detection_sweep(fake_ch, detectors, Settings(), ModelConfig()) == [], \
        "a 0.2 agreement must not pass the default 0.25 high-score tier"

    _install_db_stubs(monkeypatch, existing_anomalies=[])
    fake_ch2, _ = _capturing_client()
    relaxed = detection_sweep(fake_ch2, detectors, Settings(min_agreement=0.18),
                              ModelConfig())
    assert len(relaxed) == 1, "the high-score tier ignored MIN_AGREEMENT"


def test_default_agreement_gate_reproduces_the_original_hardcoded_pair():
    """The gate replaced `0.33 if score < 0.6 else 0.25` with values derived from
    MIN_AGREEMENT. Those derivations must reproduce the original pair EXACTLY at
    the default, or every detection's agreement bar shifts on the default path.

    This is why the relaxation is a subtractive margin (0.08) and not a
    multiplier: 0.33 * 0.75 = 0.2475, which would have moved the high-score bar
    by 0.0025 without anyone noticing.
    """
    mc = ModelConfig()
    settings = Settings()
    low_tier = settings.min_agreement
    high_tier = max(mc.min_agreement_floor, settings.min_agreement - mc.min_agreement_margin)
    assert low_tier == 0.33, f"low-score tier drifted to {low_tier}"
    assert abs(high_tier - 0.25) < 1e-12, f"high-score tier drifted to {high_tier}"

    # Both tiers must rise together when the operator raises the setting.
    raised = Settings(min_agreement=0.60)
    assert raised.min_agreement > low_tier
    high_raised = max(mc.min_agreement_floor, raised.min_agreement - mc.min_agreement_margin)
    assert high_raised > high_tier
    # ...and the floor must hold against an absurdly low value.
    silly = Settings(min_agreement=0.05)
    assert max(mc.min_agreement_floor, silly.min_agreement - mc.min_agreement_margin) \
        == mc.min_agreement_floor


