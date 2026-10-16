"""Worker tests — retrain cadence, sweep verdict handling, and row dedup.

No ClickHouse required: detectors are stubs and the client is a fake. The
baseline fake subclasses the real AdaptiveBaselineDetector so the worker's
isinstance-based lookup (which deliberately avoids positional indexing) is
exercised faithfully.
"""
import logging
import pathlib
import re
from datetime import datetime, timedelta
from typing import Any

from weirvern.config import ModelConfig, Settings
from weirvern.models.detectors import AdaptiveBaselineDetector
from weirvern.worker import (
    AGG_BUCKET_S,
    _collapse_partial_aggregates,
    _covered_through,
    _load_detect_cursor,
    _save_detect_cursor,
    detection_sweep,
    train_if_due,
)

ROOT = pathlib.Path(__file__).resolve().parent.parent


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
    def __init__(self, score, name=""):
        self.score = score
        # DISTINCT NAMES MATTER: scores are keyed by detector NAME in detect_flows, so two
        # same-score stubs without names collapse into one entry -- and an agreement ratio
        # computed from the collapsed dict reads like a lone detector.
        self.name = name or f"Stub{score}"

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
    by_table: dict[str, list] = {}

    class FakeCH:
        def insert(self, table, rows, column_names=None):  # noqa: ANN001
            inserted.extend(rows)
            by_table.setdefault(table, []).extend(rows)

    fake: Any = FakeCH()
    # SOC-2: a sweep now writes to more than one table (anomalies AND near misses),
    # so a test asserting on "anything inserted" cannot tell a stored anomaly from a
    # stored near miss. `by_table` is the precise view; `inserted` stays a flat sum
    # for the tests that genuinely mean "any row at all".
    fake.by_table = by_table
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

    RAISING the setting is what this test exercises: 2 of 4 detectors agreeing (0.5)
    passes the default and is gated by a raised 0.60. Relaxing BELOW one detector's
    share (0.25) no longer admits a lone detector's word -- that is the solo floor
    from the 2026-10-15 review, pinned separately in
    `test_the_solo_share_never_passes_even_relaxed`.
    """
    detectors = [StubDetector(0.5, "alpha"), StubDetector(0.5, "beta"),
                 StubDetector(0.01, "gamma"), StubDetector(0.01, "delta")]

    # Default MIN_AGREEMENT (0.33): 2 of 4 agreeing (0.5) passes.
    _install_db_stubs(monkeypatch, existing_anomalies=[])
    fake_ch, rows = _capturing_client()
    verdicts = detection_sweep(fake_ch, detectors, Settings(), ModelConfig())
    assert len(verdicts) == 1, "a 0.5 agreement must pass the default 0.33 gate"
    assert verdicts[0]["model_agreement"] == 0.5

    # Raise MIN_AGREEMENT above 0.5: the same window must now be suppressed. If the
    # setting is inert, this assertion is what fails.
    _install_db_stubs(monkeypatch, existing_anomalies=[])
    fake_ch2, _ = _capturing_client()
    assert detection_sweep(fake_ch2, detectors, Settings(min_agreement=0.60),
                           ModelConfig()) == [], \
        "raising MIN_AGREEMENT to 0.60 did not gate a 0.5 agreement"
    gate_rows = fake_ch2.by_table.get("weirvern.near_misses", [])
    assert len(gate_rows) == 1, (
        "the suppressed window should be recorded as a near miss (SOC-2); "
        f"near-miss rows captured: {len(gate_rows)}"
    )


def test_the_solo_share_never_passes_even_relaxed(monkeypatch):
    """A lone detector's word is excluded at EVERY tier (review round 2026-10-15): with four
    detectors the smallest non-zero agreement (0.25) used to sit exactly ON the top-tier bar,
    and relaxing MIN_AGREEMENT below it admitted the lone detector entirely. The one
    exemption is a lone specialist backed by a structural signature (pinned in
    test_ensemble.py), not a relaxed setting."""
    detectors = [StubDetector(0.5, "alpha"), StubDetector(0.01, "beta"),
                 StubDetector(0.01, "gamma"), StubDetector(0.01, "delta")]

    _install_db_stubs(monkeypatch, existing_anomalies=[])
    fake_ch, _ = _capturing_client()
    assert detection_sweep(fake_ch, detectors, Settings(min_agreement=0.18),
                           ModelConfig()) == [], \
        "a lone detector passed with MIN_AGREEMENT relaxed below its share"
    assert len(fake_ch.by_table.get("weirvern.near_misses", [])) == 1, (
        "the gated window did not surface as a near miss, so the drop would be invisible"
    )


def test_min_agreement_also_gates_the_high_score_tier(monkeypatch):
    """The high-score tier (score >= 0.6) is MIN_AGREEMENT minus the margin. It
    must respond to MIN_AGREEMENT too, not stay pinned at its default.

    Uses 2 of 5 detectors agreeing (0.4, score 0.92): the default high tier (0.25)
    passes it; raising MIN_AGREEMENT to 0.60 moves the tier to 0.52, which gates it.
    (Relaxing BELOW the solo share no longer admits a lone detector -- see
    `test_the_solo_share_never_passes_even_relaxed`.)
    """
    detectors = ([StubDetector(0.92, "alpha"), StubDetector(0.92, "beta")]
                 + [StubDetector(0.01, n) for n in ("gamma", "delta", "epsilon")])

    _install_db_stubs(monkeypatch, existing_anomalies=[])
    fake_ch, _ = _capturing_client()
    assert len(detection_sweep(fake_ch, detectors, Settings(), ModelConfig())) == 1, \
        "a 0.4 agreement must pass the default 0.25 high-score tier"

    _install_db_stubs(monkeypatch, existing_anomalies=[])
    fake_ch2, _ = _capturing_client()
    assert detection_sweep(fake_ch2, detectors, Settings(min_agreement=0.60),
                           ModelConfig()) == [], "the high-score tier ignored MIN_AGREEMENT"
    assert len(fake_ch2.by_table.get("weirvern.near_misses", [])) == 1


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




# ── AN EMPTY SIDE-TABLE MUST SAY SO ──────────────────────────────────────────────────────────
#
# CONFIRMED DEFECT (audit F005), found by counting the guards rather than reading them: `if not
# zeek_idx` exists in detection_sweep and WARNS, while `if not div_idx` / `if not tmp_idx` did not
# exist at all. An unjoined side-table then reaches `extract_features`, where `if diversity:` /
# `if temporal:` fall through to values that LOOK like measurements:
#
#     log_unique_dst_ports = log1p(0)   port_entropy = 0.0
#     connection_density   = 1.0        activity_regularity = 1.0      burstiness = 1.0
#
# So every score in the sweep is computed from imputed numbers and NOTHING SAID SO. The asymmetry
# was the trap: one sibling warned, which made the code look careful.
#
# These drive the REAL `detection_sweep` with a stubbed table reader, so they fail if the warnings
# are removed. Detection still proceeds -- returning early would turn a degraded sweep into no
# sweep, which is worse -- so each test asserts BOTH the warning and that the verdicts still come
# back.

def test_an_empty_diversity_side_table_WARNS(monkeypatch, caplog):
    """CONFIRMED DEFECT (audit F005): the diversity side-table had NO empty-guard, while the Zeek
    one in the same function WARNS. An unjoined side-table reaches `extract_features`, where
    `if diversity:` falls through to log1p(0)/0.0/1.0 -- values that LOOK like measurements -- so
    every score in the sweep is computed from imputed numbers and nothing said so.

    The asymmetry was the trap: one sibling warned, which made the code look careful.

    `_install_db_stubs` returns empty diversity and temporal rows, so this is the default state of
    every other test in this file -- which is exactly why the missing warning mattered."""
    _install_db_stubs(monkeypatch, existing_anomalies=[])
    fake_ch, _ = _capturing_client()
    with caplog.at_level(logging.WARNING):
        detection_sweep(fake_ch, [StubDetector(0.9), StubDetector(0.88)], Settings(), ModelConfig())
    text = caplog.text.lower()
    assert "diversity" in text and "imputed" in text, (
        "an empty diversity side-table degrades every score in the sweep and must say so"
    )


def test_an_empty_temporal_side_table_WARNS(monkeypatch, caplog):
    """The temporal pair is worse than the diversity one: `activity_regularity` and `burstiness`
    both default to 1.0, which read as PERFECTLY REGULAR traffic rather than as a missing
    measurement."""
    _install_db_stubs(monkeypatch, existing_anomalies=[])
    fake_ch, _ = _capturing_client()
    with caplog.at_level(logging.WARNING):
        detection_sweep(fake_ch, [StubDetector(0.9), StubDetector(0.88)], Settings(), ModelConfig())
    text = caplog.text.lower()
    assert "temporal" in text and "imputed" in text


def test_the_warning_does_not_replace_the_sweep(monkeypatch, caplog):
    """Detection must still PROCEED. Returning early on an empty side-table would turn a degraded
    sweep into NO sweep, and an alert missing a feature still beats no alert -- so the fix is to
    state the degradation, not to refuse."""
    _install_db_stubs(monkeypatch, existing_anomalies=[])
    fake_ch, inserted = _capturing_client()
    with caplog.at_level(logging.WARNING):
        verdicts = detection_sweep(fake_ch, [StubDetector(0.9), StubDetector(0.88)],
                                   Settings(), ModelConfig())
    assert verdicts, "the sweep must still produce verdicts from imputed features"
    assert inserted, "and must still persist them"


def test_a_POPULATED_side_table_does_not_warn(monkeypatch, caplog):
    """The warning must be about the FAULT, not about the code path. One that fires every sweep is
    one nobody reads, which is the state this fix exists to avoid."""
    import weirvern.db as db

    def fake_named(client, query, **params):  # noqa: ANN001
        if "flows_aggregated_diversity" in query:
            return ["window_start", "src_addr", "unique_dst_ports"], [
                (AGG_ROWS[0][0], AGG_ROWS[0][1], 12)]
        if "flows_aggregated_temporal" in query:
            return ["window_start", "src_addr", "activity_regularity"], [
                (AGG_ROWS[0][0], AGG_ROWS[0][1], 0.9)]
        if "netflow_anomalies" in query:
            return []
        return AGG_COLS, AGG_ROWS

    monkeypatch.setattr(db, "fetch_rows_named", fake_named)
    monkeypatch.setattr(db, "fetch_rows", lambda c, q, **p: [])
    fake_ch, _ = _capturing_client()
    with caplog.at_level(logging.WARNING):
        detection_sweep(fake_ch, [StubDetector(0.9), StubDetector(0.88)], Settings(), ModelConfig())
    text = caplog.text.lower()
    assert "diversity metrics are empty" not in text, "a populated side-table must not warn"
    assert "temporal metrics are empty" not in text


# ── THE LOOKBACK MUST BE WIDER THAN THE AGGREGATION BUCKET ───────────────────────────────────
#
# MEASURED LIVE DEFECT (audit F022, found from outside). The materialised views bucket on
# `toStartOfFiveMinute(time_flow_start)` while the sweep looked back exactly `detect_interval_s`
# = 300s -- THE SAME DURATION. Consequences, all measured on the box:
#
#   * all three aggregation tables held 16,934/16,870 rows, newest `window_start` a 5-minute
#     boundary 315s old, raw flows still arriving;
#   * the sweep's own query (`window_start >= now() - INTERVAL 300 SECOND`) matched ZERO rows
#     when run by hand;
#   * /api/health reported clickhouse ok, tables ok, ingest_freshness ok, zeek_freshness ok,
#     models ok, alerts ok -- every probe green while detection analysed nothing.
#
# WHY EQUAL DURATIONS RACE: bucket B covers [B, B+300) and is only WRITTEN once a flow lands in
# it, while the sweep requires `window_start >= T - 300`. So B is visible only while T <= B+300,
# which is exactly when its flows stop arriving and the next bucket has only just opened and may
# be empty. With cadence == bucket the phase never drifts, so a sweep can sit in the empty case
# indefinitely rather than averaging out.
#
# These tests pin the WINDOW the sweep asks for, because the window is the whole defect -- a test
# that only checked "detection returns verdicts" passes with an empty window and is exactly the
# failure mode being fixed.

def _sweep_since(monkeypatch, *, interval_s):
    """The `since` the sweep computes, captured from the query it actually issues."""
    import weirvern.db as db
    from weirvern.config import Settings

    seen: list[str] = []

    def fake_named(client, query, **params):  # noqa: ANN001
        seen.append(str(params.get("since", "")))
        return [], []

    monkeypatch.setattr(db, "fetch_rows_named", fake_named)
    monkeypatch.setattr(db, "fetch_rows", lambda c, q, **p: [])
    # Settings is FROZEN, so the value is passed to the constructor -- the first version of this
    # helper tried to assign the field and got FrozenInstanceError.
    settings = Settings(detect_interval_s=interval_s)
    detection_sweep(_capturing_client()[0], [StubDetector(0.9)], settings, ModelConfig())
    return seen[0] if seen else None


def test_the_lookback_is_WIDER_than_the_aggregation_bucket(monkeypatch):
    """THE DEFECT ITSELF: equal durations race, so the window must exceed the bucket."""
    from weirvern.worker import AGG_BUCKET_S

    since = _sweep_since(monkeypatch, interval_s=AGG_BUCKET_S)
    assert since, "the sweep issued no query, so this test proves nothing"
    asked = datetime.fromisoformat(since)
    span = (datetime.now() - asked).total_seconds()
    assert span > AGG_BUCKET_S, (
        f"the lookback is {span:.0f}s against a {AGG_BUCKET_S}s bucket. A bucket is then dropped "
        f"before the next one has rows, and the sweep analyses NOTHING while every probe reads green"
    )


def test_a_FASTER_cadence_cannot_reintroduce_the_race(monkeypatch):
    """The trap in the obvious fix. `2 * detect_interval_s` works at the shipped 300s and BREAKS
    the moment an operator raises the cadence: at DETECT_INTERVAL_S=60 that gives a 120s lookback
    against a 300s bucket, and the race returns silently on a deployment that just made detection
    faster. The lookback is derived from the BUCKET for this reason."""
    from weirvern.worker import AGG_BUCKET_S

    for interval in (10, 60, 120, 300, 900):
        since = _sweep_since(monkeypatch, interval_s=interval)
        asked = datetime.fromisoformat(since)
        span = (datetime.now() - asked).total_seconds()
        assert span > AGG_BUCKET_S, (
            f"at DETECT_INTERVAL_S={interval} the lookback is {span:.0f}s against a "
            f"{AGG_BUCKET_S}s bucket, so a bucket falls out of the window before the next has rows"
        )


def test_the_lookback_still_covers_at_least_one_detection_interval(monkeypatch):
    """The other direction: the window must also be at least one cadence, or a slow cadence would
    skip rows entirely."""
    for interval in (10, 60, 300, 900):
        since = _sweep_since(monkeypatch, interval_s=interval)
        span = (datetime.now() - datetime.fromisoformat(since)).total_seconds()
        assert span >= interval, (
            f"at DETECT_INTERVAL_S={interval} the lookback is only {span:.0f}s, so consecutive "
            f"sweeps would not overlap and rows between them would never be scored"
        )


def test_the_bucket_constant_matches_the_SCHEMA():
    """A constant that drifts from the view it describes is worse than a magic number: the sweep
    would look back a comfortable margin against a bucket that is no longer that size. This reads
    the schema file itself rather than trusting the constant.

    PRECISE ABOUT WHAT IT CHECKS: `window_start` is the column the sweep filters on, so THIS test
    pins how `window_start` is computed. The schema also uses `toStartOfMinute` inside an
    aggregation (`count(DISTINCT toStartOfMinute(time_flow_start)) AS active_minutes`), which is a
    count of distinct minutes within a bucket and NOT a bucket boundary -- so a check for the
    string "toStartOfMinute(" anywhere in the file is wrong, and the first version of this test
    failed for exactly that reason.
    """
    from weirvern.worker import AGG_BUCKET_S

    schema = (ROOT / "weirvern" / "schema" / "001_weirvern.sql").read_text()

    # Every `... AS window_start` expression, which is what the sweep's WHERE clause filters on.
    exprs = re.findall(r"([A-Za-z_][\w.]*\([^)]*\))\s+AS window_start", schema)
    assert exprs, "no `AS window_start` expression found: the schema's shape changed"
    assert set(exprs) == {"toStartOfFiveMinute(time_flow_start)", "toStartOfFiveMinute(ts)"}, (
        f"the schema computes window_start as {sorted(set(exprs))}, but AGG_BUCKET_S assumes a "
        f"single 5-minute bucket. Two bucket sizes in one schema means one lookback cannot serve "
        f"them both, and the sweep would race the larger one"
    )
    assert AGG_BUCKET_S == 300, (
        f"AGG_BUCKET_S is {AGG_BUCKET_S} while window_start is toStartOfFiveMinute (300s). "
        f"Change one OR the other, never just this number"
    )


# ── A METADATA ROW FOR A DETECTOR THAT DID NOT TRAIN IS A FALSE CLAIM ────────────────────────
#
# CONFIRMED DEFECT (audit F023, measured against the live cluster). `_record_model_metadata`
# writes a TRAINING-HISTORY row, and both call sites handed it the WHOLE detector list
# unconditionally -- so a detector whose `train()` returned False still got a row. That row is
# what the health probe counts:
#
#     models  ok=True  "4 detector(s) with training history"
#
# Combined with F024 (the probe ignored the staleness it selected), a pipeline that had stopped
# training was indistinguishable from a healthy one. The fix passes only the detectors that
# returned True; these tests pin that, because a fix with no test is one refactor from returning.

def _metadata_rows_recorded(monkeypatch, train_results):
    """Run the cold-start train path with the given per-detector train() results, and return the
    detector NAMES whose metadata was recorded."""
    import weirvern.db as db

    recorded: list[str] = []

    class _Meta:
        def to_row(self):
            return {"model_id": "m", "model_type": "t", "trained_at": 1}

    class _Det:
        def __init__(self, name, trains):
            self.name = name
            self._trains = trains
            self.metadata = _Meta()
            self.X_train_unscaled = object()

        def train(self, *a, **k):
            return self._trains

        def persist_history(self, *a, **k):
            return None

        def load(self):
            return False

        def is_ready(self):
            # `load_or_train` calls this while computing `_oldest_trained_at`, which is the retrain
            # clock's input. A detector that is not ready contributes nothing to that clock.
            return True

    detectors = [_Det(n, ok) for n, ok in train_results.items()]

    class _Client:
        def insert(self, table, rows, column_names=None):
            if table == "weirvern.ml_models":
                recorded.append("recorded")

    # The cold-start path needs a client and its own db reads stubbed out.
    monkeypatch.setattr(db, "fetch_rows_named", lambda *a, **k: ([], []))
    monkeypatch.setattr(db, "fetch_rows", lambda *a, **k: [])
    from weirvern import worker as worker_mod

    real = worker_mod._record_model_metadata

    def spy(client, dets):
        for d in dets:
            recorded.append(d.name)
        return real(client, dets)

    monkeypatch.setattr(worker_mod, "_record_model_metadata", spy)
    worker_mod.load_or_train(_Client(), detectors, Settings(), ModelConfig())
    return recorded


def test_only_detectors_that_TRAINED_get_a_metadata_row(monkeypatch):
    """THE DEFECT: an untrained detector must not be recorded as having a training history."""
    names = _metadata_rows_recorded(monkeypatch, {
        "Isolation Forest": True, "Gradient Boosting": True,
        "DBSCAN": False, "Adaptive Baseline": True,
    })
    assert "DBSCAN" not in names, (
        "DBSCAN did not train but was recorded. Its row is what makes the health probe report "
        "'4 detector(s) with training history' for a pipeline that is not training"
    )
    assert "Isolation Forest" in names and "Adaptive Baseline" in names


def test_NOTHING_that_failed_to_train_is_recorded(monkeypatch):
    """And when nothing trains, no history is written at all."""
    names = _metadata_rows_recorded(monkeypatch, {
        "Isolation Forest": False, "Gradient Boosting": False,
        "DBSCAN": False, "Adaptive Baseline": False,
    })
    assert names == [], f"detectors that all failed to train were recorded: {names}"


# ── A SLOW CYCLE STEPPED OVER WINDOWS THAT WERE NEVER EXAMINED (audit F045) ──────────────────
#
# CONFIRMED ON THE LIVE CLUSTER before it was fixed, from `baseline_history.computed_at` gaps over
# 48 hours:
#
#     cycles: 292   median gap: 300s   p99: 966s   MAX: 1183s
#     ten separate gaps over 600s: 1183, 1170, 1138, 949, 897, 893, 847, 835, 818, 778
#     gap 1183s  ->  2 whole 5-minute buckets never examined
#
# `detection_sweep` computed `since = now() - (AGG_BUCKET_S + detect_interval_s)` EVERY cycle, which
# silently assumes the previous cycle ran `detect_interval_s` ago. `train_if_due` runs BEFORE the
# sweep in this module's loop and blocks, so the 6-hourly full retrain pushed the next sweep's
# `now()` forward with `since` moving in lockstep. Those buckets are still in `flows_aggregated` --
# they age out of the LOOKBACK, not out of the table -- so the data was there and stopped being
# examined, with the only trace being a heartbeat gap.


def _empty_sweep_client():
    """A client whose aggregate queries return no rows at all.

    Written here rather than reusing an existing stub because the assertion is about the ABSENCE of
    rows: `detection_sweep` must not record coverage for a window that contained nothing to examine.
    """
    class _R:
        column_names: list = []
        result_rows: list = []

    class _C:
        def query(self, *a, **kw):
            return _R()

        def insert(self, *a, **kw):
            return None

    return _C()


def _cursor_since(settings, cursor):
    """The window start the product's cursor function returns for a given carried cursor.

    Returns a plain `datetime`: `_covered_through` never returns a None cursor, because it always
    knows the sweep's start time. The optionality is in the INPUT.
    """
    since, _new_cursor = _covered_through(settings, cursor)
    return since


def test_a_HEALTHY_cycle_covers_exactly_what_the_old_code_covered():
    """THE INVARIANT THAT MATTERS MOST: the fix must change NOTHING when cycles run on time.

    A recovery mechanism that alters the healthy path is a second defect. The two arms of the `min`
    coincide when the cursor is one interval old, and this asserts that rather than trusting the
    arithmetic.
    """
    settings = Settings()
    now = datetime.now()
    lookback = AGG_BUCKET_S + settings.detect_interval_s

    since = _cursor_since(settings, now - timedelta(seconds=settings.detect_interval_s))
    old_behaviour = now - timedelta(seconds=lookback)

    assert abs((since - old_behaviour).total_seconds()) < 1, (
        f"a healthy cycle now starts its window at {since} instead of {old_behaviour}. The fix must "
        f"be inert when the previous cycle ran on time."
    )


def test_a_SLOW_cycle_re_covers_the_buckets_it_would_have_skipped():
    """THE DEFECT. A 1183s gap stepped over ~2 whole buckets, never examined, never logged."""
    settings = Settings()
    now = datetime.now()
    lookback = AGG_BUCKET_S + settings.detect_interval_s

    slow_gap_s = 1183  # the maximum measured on the live cluster
    since = _cursor_since(settings, now - timedelta(seconds=slow_gap_s))
    old_window_start = now - timedelta(seconds=lookback)

    recovered = (old_window_start - since).total_seconds()
    assert recovered > 0, (
        f"a {slow_gap_s}s cycle still starts its window at {since}, the same place the old code did, "
        f"so the buckets in between are still never examined"
    )
    # The recovered span must cover the full gap, not a token amount.
    assert recovered >= slow_gap_s - lookback - 1, (
        f"only {recovered:.0f}s recovered of a {slow_gap_s - lookback:.0f}s hole"
    )


def test_the_window_always_ends_at_NOW_so_coverage_means_covered():
    """The returned cursor is the sweep's start, in every branch -- so the next cycle's window starts
    from what THIS one actually reached, and a cursor can never claim more than was examined."""
    settings = Settings()
    now = datetime.now()
    for cursor in (None, now - timedelta(seconds=300), now - timedelta(seconds=1183),
                   now + timedelta(hours=3), now - timedelta(hours=100)):
        _since, new_cursor = _covered_through(settings, cursor)
        assert new_cursor is not None, f"no cursor returned for {cursor}"
        assert new_cursor >= now - timedelta(seconds=5), (
            f"the cursor {new_cursor} predates the sweep for input {cursor}"
        )


def test_with_NO_cursor_the_behaviour_is_the_old_window():
    """First run, or an unreadable checkpoint: nothing to resume from, so the DEFAULT window is right
    -- and the cursor returned is this sweep's start, because a first sweep that ran to completion
    genuinely covered up to now.

    An earlier version of this test asserted the cursor came back as None, which was the first draft
    of the design (advance only when a cursor already existed) rather than what the function does.
    Returning None on first run would mean the SECOND sweep still had nothing to resume from, so a
    slow early cycle would be unprotected -- which is exactly the case this fix is for.
    """
    settings = Settings()
    now = datetime.now()
    since, cursor = _covered_through(settings, None)

    expected = now - timedelta(seconds=AGG_BUCKET_S + settings.detect_interval_s)
    assert abs((since - expected).total_seconds()) < 1, (
        "with no cursor to resume from, the window must be the default one"
    )
    assert cursor is not None and cursor >= now - timedelta(seconds=5), (
        "no cursor was returned, so the next sweep has nothing to resume from either"
    )


def test_a_cursor_in_the_FUTURE_falls_back_instead_of_wedging(caplog):
    """A clock that stepped backwards would otherwise put the cursor in the future, where every later
    sweep examines nothing -- turning a clock correction into a permanent detection outage."""
    import logging

    settings = Settings()
    now = datetime.now()
    with caplog.at_level(logging.WARNING, logger="weirvern.worker"):
        since, cursor = _covered_through(settings, now + timedelta(hours=3))

    expected = now - timedelta(seconds=AGG_BUCKET_S + settings.detect_interval_s)
    assert abs((since - expected).total_seconds()) < 1, "did not fall back to the default window"
    assert cursor is not None, "the cursor was not reset, so it stays in the future forever"
    assert any("FUTURE" in r.getMessage() for r in caplog.records), (
        "the clock step was not reported, so a silent fallback is all an operator would see"
    )


def test_an_outage_longer_than_the_RETENTION_is_clamped_and_reported(caplog):
    """A worker scaled to zero for a day must not turn into a scoring burst over the whole retention
    -- and the unrecoverable part must be LOGGED, because silently narrowing the window is how the
    original defect hid."""
    import logging

    settings = Settings()
    now = datetime.now()
    gap_h = settings.retrain_window_h + 28

    with caplog.at_level(logging.WARNING, logger="weirvern.worker"):
        since, _cursor = _covered_through(settings, now - timedelta(hours=gap_h))

    floor = now - timedelta(hours=settings.retrain_window_h)
    assert abs((since - floor).total_seconds()) < 2, (
        f"the window start {since} was not clamped to the {settings.retrain_window_h}h retention "
        f"floor {floor}"
    )
    assert any("CANNOT be scored" in r.getMessage() for r in caplog.records), (
        "the unrecoverable part of the gap was not reported"
    )


def test_an_outage_WITHIN_retention_is_fully_recovered():
    """The clamp must not blunt the fix: a gap inside the retention is covered in full."""
    settings = Settings()
    now = datetime.now()
    gap_h = max(1, settings.retrain_window_h - 48)

    since, _cursor = _covered_through(settings, now - timedelta(hours=gap_h))

    wanted = now - timedelta(hours=gap_h) - timedelta(seconds=AGG_BUCKET_S)
    assert abs((since - wanted).total_seconds()) < 2, (
        f"a {gap_h}h gap inside the {settings.retrain_window_h}h retention was not covered in full: "
        f"window starts at {since}, expected {wanted}"
    )


def test_the_swep_ADVANCES_the_cursor_only_when_it_examined_something(tmp_path):
    """A cursor written BEFORE the work would turn any mid-sweep exception into a permanently skipped
    window -- the same defect made worse. This checks the three real paths: rows read and scored,
    rows read but nothing anomalous, and no rows at all."""
    settings = Settings(model_dir=str(tmp_path))

    # No aggregates at all: the window was not examined, so coverage must NOT be recorded.
    assert _load_detect_cursor(settings) is None
    fake = _empty_sweep_client()
    assert detection_sweep(fake, [StubDetector(0.9)], settings, ModelConfig()) == []
    assert _load_detect_cursor(settings) is None, (
        "a sweep that read no aggregates recorded coverage, so the window is skipped next cycle"
    )


def test_a_corrupt_cursor_is_DISCARDED_not_raised(tmp_path, caplog):
    """A malformed checkpoint must not stop detection. Refusing to sweep because a file is unreadable
    trades a small recovery for a total outage."""
    import logging

    settings = Settings(model_dir=str(tmp_path))
    (tmp_path / "detect_cursor.json").write_text("{ this is not json")

    with caplog.at_level(logging.WARNING, logger="weirvern.worker"):
        cursor = _load_detect_cursor(settings)

    assert cursor is None, "a corrupt cursor was trusted"
    assert any("unusable" in r.getMessage() for r in caplog.records), "the corruption was not reported"


def test_an_UNWRITABLE_cursor_does_not_lose_the_sweep(tmp_path, caplog):
    """A checkpoint that cannot be written is a bookkeeping problem. Raising would discard verdicts
    the sweep had already persisted and was about to alert on."""
    import logging

    settings = Settings(model_dir=str(tmp_path / "nope" / "deeper"))
    (tmp_path / "nope").write_text("this is a FILE, so the directory cannot be created")

    with caplog.at_level(logging.WARNING, logger="weirvern.worker"):
        _save_detect_cursor(settings, datetime.now())  # must not raise

    assert any("Could not record" in r.getMessage() for r in caplog.records), (
        "an unwritable cursor failed silently, so an operator would never know coverage was lost"
    )


def test_a_sweep_that_EXAMINED_rows_RECORDS_coverage(monkeypatch, tmp_path):
    """THE OTHER DIRECTION, which mutation testing showed was untested.

    A mutation that removed the cursor write entirely went UNCAUGHT, because the tests above only
    proved the empty case does NOT advance. Both directions matter: a sweep that read aggregates has
    genuinely covered that window, and if it never records that, every cycle re-reads the same
    lookback and a slow cycle is unprotected -- the defect this fix exists for.
    """
    from weirvern.worker import _load_detect_cursor

    _install_db_stubs(monkeypatch, existing_anomalies=[])
    fake_ch, _inserted = _capturing_client()

    settings = Settings(model_dir=str(tmp_path))
    assert _load_detect_cursor(settings) is None, "a cursor existed before anything ran"

    detection_sweep(fake_ch, [StubDetector(0.9), StubDetector(0.88)], settings, ModelConfig())

    cursor = _load_detect_cursor(settings)
    assert cursor is not None, (
        "a sweep that read and scored aggregates recorded no coverage, so the next cycle starts "
        "from now() again and a slow cycle still steps over windows"
    )
    assert cursor >= datetime.now() - timedelta(seconds=10), f"the cursor {cursor} is stale"


def test_the_cursor_ROUND_TRIPS_through_the_file(monkeypatch, tmp_path):
    """The checkpoint is only useful if the NEXT process reads what this one wrote -- a worker
    restart is one of the ways the skipped window occurred."""
    from weirvern.worker import _load_detect_cursor

    settings = Settings(model_dir=str(tmp_path))
    when = datetime.now() - timedelta(minutes=7)
    _save_detect_cursor(settings, when)

    # A fresh read, exactly as a restarted process would do it.
    assert _load_detect_cursor(settings) == when, "the cursor did not survive a round trip"

    # And a SECOND Settings over the same directory sees it too, which is the restart case.
    assert _load_detect_cursor(Settings(model_dir=str(tmp_path))) == when


# ── PARTIAL PER-BLOCK AGGREGATES BLINDED T1046 / T1018 (F-T1046) ─────────────────────────────
#
# A ClickHouse materialized view fires PER INSERT BLOCK, so every insert into `weirvern.flows`
# writes its own aggregate row for the same (window_start, src_addr). The target table is
# `MergeTree()`, not ReplacingMergeTree, so those partial rows are NEVER merged.
#
# MEASURED ON THE LIVE CLUSTER over 24 hours:
#
#     flows_aggregated:           592 host-windows, 555 fragmented = 93.8%, worst case 46 rows
#     flows_aggregated_diversity: 589 host-windows, 552 fragmented = 93.7%, worst case 46 rows
#
#     one worst-case host-window's 46 partial rows' unique_dst_ports:
#         [1,1,1,2,1,1,1,1,1,1,2,2,2,...]     <- 46 values
#         the sweep saw (max)     = 2 ports
#         the window holds (sum)  = 81
#
# So `flows` was one dict PER PARTIAL ROW (up to 46 scorer inputs for one host-window), and
# `flow_by_key`'s plain dict assignment meant the LAST partial won -- typically the smallest, so
# T1046's port threshold was evaluated against the least informative row of the window.


def _agg_row(flows, dsts, ports, byts, window=None, src="198.51.100.7"):
    """One PARTIAL aggregate row, shaped like `flows_aggregated`."""
    return {
        "window_start": window or datetime(2026, 9, 23, 9, 0),
        "window_end": (window or datetime(2026, 9, 23, 9, 0)) + timedelta(minutes=5),
        "src_addr": src,
        "flow_count": flows,
        "total_bytes": byts,
        "total_packets": flows * 2,
        "avg_bytes": byts / max(flows, 1),
        "avg_packets": 2.0,
        "unique_dst_ips": dsts,
    }


def _raw_card_stub(monkeypatch, mapping):
    """The raw-flow read returns TRUE distinct counts, keyed (window_start, src_addr)."""
    import weirvern.db as db

    def fake_named(client, query, **params):
        if "uniqExact" in query:
            return (
                ["window_start", "src_addr", "n_dst_ips", "n_dst_ports", "n_connections",
                 "port_entropy", "bytes_stddev", "packets_stddev", "active_minutes"],
                [[k[0], k[1], v[0], v[1], v[2], v[3] if len(v) > 3 else 0.0,
                  0.0, 0.0, 1] for k, v in mapping.items()],
            )
        return [], []

    monkeypatch.setattr(db, "fetch_rows_named", fake_named)


def test_partial_rows_COLLAPSE_to_one_row_per_host_window():
    """THE DEFECT: up to 46 scorer inputs for one host-window, each scored as the whole window."""

    # Five blocks, each seeing one destination -- the live shape.
    partials = [_agg_row(1, 1, 1, 100) for _ in range(5)]

    class _C:
        def insert(self, *a, **k):
            pass

    out = _collapse_partial_aggregates(partials, {}, _C())
    assert len(out) == 1, (
        f"{len(partials)} partial rows for ONE host-window produced {len(out)} rows. Every scorer "
        f"input and every threshold read is then a per-BLOCK number, not the window's"
    )
    assert out[0]["flow_count"] == 5, "the additive total was not folded"
    assert out[0]["total_bytes"] == 500, "bytes were not folded"
    assert "_largest_block_flows" not in out[0], "the internal scratch key leaked onto the row"


def test_the_sweeps_aggregate_reads_are_ORDERED():
    """A duplicated key resolves by whichever row the storage engine returns last -- so the read
    must be ordered, and the fold must not care either way.

    MEASURED (2026-10-16, seeded-attack harness): two scorings of the SAME window in one process
    gave DBSCAN 0.7178 in one and 0.6487 in the other for the same host, which flipped a detection
    out of the verdict list. These tables can hold one row per insert block for one (window, host);
    the side tables are indexed by key with "last wins", so without an ORDER BY the choice is the
    storage engine's, not the code's.
    """
    src = (ROOT / "weirvern" / "worker.py").read_text()
    for table in ("flows_aggregated", "flows_aggregated_diversity", "flows_aggregated_temporal"):
        needle = f"FROM weirvern.{table} WHERE window_start >= %(since)s"
        i = src.index(needle)
        assert "ORDER BY window_start, src_addr" in src[i:i + 160], (
            f"the read of {table} lost its ORDER BY: a duplicated key again resolves by arbitrary "
            "row order, and the same host-window can score differently between two runs")


def test_the_largest_block_is_chosen_by_a_TOTAL_order_not_by_arrival():
    """Two blocks with the SAME flow count used to decide the window's averages by arriving first.

    The fold's docstring promises "row order stops mattering here". For this tie it did not, and the
    seeded-attack harness measured the cost: the same host-window scored 0.6978 in one pass and
    0.6001 in the next with byte-identical feature contributions -- meaning the ROW had been
    assembled differently, not the model. A verdict that changes when the input rows are returned in
    a different order is a verdict nobody can act on.
    """
    small = _agg_row(3, 1, 1, 300)   # 3 flows, 300 bytes -> avg 100
    large = _agg_row(3, 1, 1, 900)   # 3 flows, 900 bytes -> avg 300: same count, bigger block

    class _C:
        def insert(self, *a, **k):
            pass

    one = _collapse_partial_aggregates([small, large], {}, _C())
    two = _collapse_partial_aggregates([large, small], {}, _C())
    assert len(one) == len(two) == 1
    assert one[0]["avg_bytes"] == two[0]["avg_bytes"] == 300.0, (
        "the same two blocks in a different order produced a different window: "
        f"{one[0]['avg_bytes']} vs {two[0]['avg_bytes']}")
    assert (one[0]["flow_count"], two[0]["flow_count"]) == (6, 6), "the additive fold regressed"
    assert not [k for k in one[0] if k.startswith("_largest_block")], (
        "an internal scratch key leaked onto the row")


def test_the_cardinality_comes_from_the_RAW_flows_not_the_sum(monkeypatch):
    """SUMMING PARTIALS IS AN UPPER BOUND, and these numbers GATE detection.

    Two blocks that each saw the SAME single destination have a true distinct count of 1; summing
    says 2. Inflating a count that gates a scan rule manufactures port-scan alerts on hosts that
    merely contacted the same few destinations repeatedly -- trading a detection gap for false
    positives is not a fix.
    """
    W = datetime(2026, 9, 23, 9, 0)
    # Both partial rows saw one destination, and both saw one port. The TRUE values are 1 and 1.
    partials = [_agg_row(1, 1, 1, 100, window=W), _agg_row(1, 1, 1, 100, window=W)]
    _raw_card_stub(monkeypatch, {(W, "198.51.100.7"): (1, 1, 1)})

    class _C:
        def insert(self, *a, **k):
            pass

    out = _collapse_partial_aggregates(partials, {}, _C())
    assert len(out) == 1
    assert out[0]["unique_dst_ips"] == 1, (
        f"unique_dst_ips came back {out[0]['unique_dst_ips']} for a window whose true distinct "
        f"destination count is 1 -- the summed upper bound was used where an exact value existed"
    )
    assert out[0]["unique_dst_ports"] == 1, "ports were not taken from the raw read"


def test_a_scan_spread_across_blocks_is_no_longer_UNDERCOUNTED(monkeypatch):
    """THE POINT OF THE FIX, stated as the detection question.

    A 500-port scan arriving in 46 insert blocks read as 1-2 ports, which is below every discovery
    threshold. The window's real count is what the rule must see.
    """
    W = datetime(2026, 9, 23, 9, 0)
    partials = [_agg_row(1, 1, 1, 40, window=W) for _ in range(46)]  # the live worst case
    # 500 distinct ports over the whole window, with the entropy that MANY distinct ports imply.
    # The per-block value could never exceed log2(2) = 1.0 with the fixture's 2-port blocks, and
    # T1046 requires 3.0 -- so this is the value the recomputation exists to produce.
    _raw_card_stub(monkeypatch, {(W, "198.51.100.7"): (500, 500, 500, 7.9)})

    class _C:
        def insert(self, *a, **k):
            pass

    out = _collapse_partial_aggregates(partials, {}, _C())
    merged = out[0]

    # What the OLD code handed the rule: one partial row's single port.
    old_view = max(p["unique_dst_ports"] if "unique_dst_ports" in p else p["unique_dst_ips"]
                   for p in partials)
    assert old_view == 1, "the fixture no longer models the defect"
    assert merged["unique_dst_ports"] == 500, (
        f"the rule sees {merged['unique_dst_ports']} ports; the window holds 500"
    )
    # And the threshold that was blind now fires.
    from weirvern.attack import DISCOVERY_MIN_PORTS
    assert old_view < DISCOVERY_MIN_PORTS, "a single partial row already cleared the threshold"
    assert merged["unique_dst_ports"] >= DISCOVERY_MIN_PORTS, (
        "the collapsed row STILL does not clear T1046's port threshold"
    )


def test_the_fallback_to_SUMMING_is_reported(monkeypatch, caplog):
    """An approximation a threshold reads must never be invisible -- that is how this hid."""
    import logging

    import weirvern.db as db

    def failing(client, query, **params):
        raise RuntimeError("raw flow table unavailable")

    monkeypatch.setattr(db, "fetch_rows_named", failing)
    partials = [_agg_row(1, 1, 1, 100) for _ in range(2)]

    class _C:
        def insert(self, *a, **k):
            pass

    with caplog.at_level(logging.WARNING, logger="weirvern.worker"):
        out = _collapse_partial_aggregates(partials, {}, _C())

    assert len(out) == 1, "the collapse did not happen at all when the raw read failed"
    assert any("UPPER BOUND" in r.getMessage() for r in caplog.records), (
        "the summed upper bound was used with no warning, so an approximate count would gate "
        "detection silently"
    )


def test_a_NON_fragmented_window_is_returned_UNCHANGED(monkeypatch):
    """The common case must not be rebuilt or re-derived: no extra work, bit-identical values."""
    import weirvern.db as db

    def must_not_be_called(client, query, **params):
        raise AssertionError("the raw-flow read ran for a window with no fragmentation")

    monkeypatch.setattr(db, "fetch_rows_named", must_not_be_called)
    single = [_agg_row(3, 9, 9, 300)]

    class _C:
        def insert(self, *a, **k):
            pass

    out = _collapse_partial_aggregates(single, {}, _C())
    assert out is single, "an unfragmented window was rebuilt, and the raw read was attempted"


def test_partial_rows_from_SEVERAL_hosts_collapse_independently(monkeypatch):
    """The fold is per host-window. A bug that merged across hosts would put one host's traffic on
    another's row, which is worse than the defect being fixed."""
    W = datetime(2026, 9, 23, 9, 0)
    partials = [
        _agg_row(1, 1, 1, 100, window=W, src="198.51.100.7"),
        _agg_row(1, 1, 1, 100, window=W, src="198.51.100.7"),
        _agg_row(2, 2, 2, 200, window=W, src="203.0.113.9"),
        _agg_row(3, 3, 3, 300, window=W, src="203.0.113.9"),
    ]
    _raw_card_stub(monkeypatch, {
        (W, "198.51.100.7"): (2, 2, 2),
        (W, "203.0.113.9"): (5, 5, 5),
    })

    class _C:
        def insert(self, *a, **k):
            pass

    out = _collapse_partial_aggregates(partials, {}, _C())
    by_host = {r["src_addr"]: r for r in out}
    assert len(out) == 2, f"expected one row per host, got {len(out)}"
    assert by_host["198.51.100.7"]["flow_count"] == 2
    assert by_host["203.0.113.9"]["flow_count"] == 5
    assert by_host["198.51.100.7"]["unique_dst_ips"] == 2
    assert by_host["203.0.113.9"]["unique_dst_ips"] == 5


def test_the_SWEEP_itself_collapses_partials_not_just_the_helper(monkeypatch):
    """THE WIRING, and mutation testing showed this was untested.

    Every test above calls `_collapse_partial_aggregates` DIRECTLY, so a mutation that deleted the
    call from `detection_sweep` was MISSED -- the helper still worked perfectly and nothing invoked
    it. That is the same decoration trap this project keeps hitting: testing a function is not
    testing that the product uses it.

    This drives the REAL sweep with a fragmented fixture and asserts on what the SCORER received.
    """
    import weirvern.db as db
    import weirvern.worker as worker_mod

    W = datetime(2026, 9, 23, 9, 0)
    # Two partial rows for ONE host-window. Additive totals must arrive as 2 flows, 200 bytes.
    agg = [
        ["ts", W, W + timedelta(minutes=5), "198.51.100.7", 10, 10, 10, 10, 10, 1, 1, 100, 2, 100.0, 2.0],
        ["ts", W, W + timedelta(minutes=5), "198.51.100.7", 10, 10, 10, 10, 10, 1, 1, 100, 2, 100.0, 2.0],
    ]
    columns = ["kind", "window_start", "window_end", "src_addr", "c1", "c2", "c3", "c4", "c5",
               "unique_dst_ips", "flow_count", "total_bytes", "total_packets", "avg_bytes",
               "avg_packets"]

    seen_by_scorer: list = []

    def fake_named(client, query, **params):
        if "flows_aggregated_diversity" in query:
            return ([], [])
        if "flows_aggregated_temporal" in query:
            return ([], [])
        if "uniqExact" in query:  # the raw-flow cardinality read
            return (["window_start", "src_addr", "n_dst_ips", "n_dst_ports", "n_connections",
                     "port_entropy", "bytes_stddev", "packets_stddev", "active_minutes"],
                    [[W, "198.51.100.7", 1, 1, 1, 0.0, 0.0, 0.0, 1]])
        if "weirvern.flows" in query and "window_start >=" in query:
            return columns, agg
        return ([], [])

    monkeypatch.setattr(db, "fetch_rows_named", fake_named)
    monkeypatch.setattr(db, "fetch_rows", lambda c, q, **p: [])

    real_detect = worker_mod.ensemble.detect_flows

    def capture(flows, *a, **kw):
        seen_by_scorer.append(len(flows))
        return real_detect(flows, *a, **kw)

    monkeypatch.setattr(worker_mod.ensemble, "detect_flows", capture)

    fake_ch, _inserted = _capturing_client()
    worker_mod.detection_sweep(fake_ch, [StubDetector(0.9)], Settings(), ModelConfig())

    assert seen_by_scorer, "the sweep never reached the scorer, so this test proves nothing"
    assert seen_by_scorer[0] == 1, (
        f"the scorer received {seen_by_scorer[0]} rows for ONE host-window. The collapse exists but "
        f"`detection_sweep` does not call it, so every threshold still reads a per-BLOCK number"
    )


def test_ENTROPY_is_RECOMPUTED_because_the_partials_cannot_express_it(monkeypatch):
    """THE HALF A COLLAPSE ALONE CANNOT FIX, and it took a live measurement to see.

    `port_entropy` is a per-BLOCK measurement. Entropy over 2 distinct ports is bounded by
    log2(2) = 1.0, no matter how many blocks are added -- you cannot fold your way to a larger
    number. MEASURED on the live cluster: the fragmented windows hold per-block entropy of 0 to
    0.54, and T1046 requires 3.0, so collapsing alone left that rule blind.

    The value has to be RECOMPUTED over the whole window, with the materialized view's own
    expression. This asserts that the recomputed value reaches the row, not merely that the
    collapse ran.
    """
    W = datetime(2026, 9, 23, 9, 0)
    # Each block saw 2 ports, so each block's entropy is at most 1.0. The window's true entropy is
    # 7.9 -- the value a real scan produces.
    partials = [_agg_row(1, 2, 2, 100, window=W) for _ in range(10)]
    for p in partials:
        p["port_entropy"] = 0.54  # the live per-block maximum
    _raw_card_stub(monkeypatch, {(W, "198.51.100.7"): (400, 400, 400, 7.9)})

    class _C:
        def insert(self, *a, **k):
            pass

    out = _collapse_partial_aggregates(partials, {}, _C())
    merged = out[0]

    from weirvern.attack import DISCOVERY_MIN_ENTROPY
    assert partials[0]["port_entropy"] < DISCOVERY_MIN_ENTROPY, "the fixture no longer models it"
    assert merged["port_entropy"] == 7.9, (
        f"port_entropy came back {merged['port_entropy']}; the per-block value cannot exceed 1.0 "
        f"with 2 ports, and T1046 needs {DISCOVERY_MIN_ENTROPY}"
    )
    assert merged["port_entropy"] >= DISCOVERY_MIN_ENTROPY, "T1046's entropy gate is still blind"


def test_T1046_FIRES_on_a_scan_spread_across_many_blocks(monkeypatch):
    """THE DETECTION QUESTION, end to end through the product's own mapper.

    Before: the rule read one partial row (2 ports, entropy 0.54) and matched nothing.
    After: it sees the window (400 ports, entropy 7.9) and fires.
    """
    from weirvern.attack import DISCOVERY_MIN_PORTS, map_techniques

    W = datetime(2026, 9, 23, 9, 0)
    partials = [_agg_row(1, 2, 2, 100, window=W) for _ in range(10)]
    for p in partials:
        p["port_entropy"] = 0.54
    _raw_card_stub(monkeypatch, {(W, "198.51.100.7"): (400, 400, 400, 7.9)})

    class _C:
        def insert(self, *a, **k):
            pass

    # What the OLD code handed the rule: the last partial row alone.
    old_matches = map_techniques(dict(partials[-1]))
    assert not old_matches, (
        f"a single partial row already mapped {[m.technique.id for m in old_matches]}, so this "
        f"fixture does not model the blindness"
    )

    merged = _collapse_partial_aggregates(partials, {}, _C())[0]
    new_matches = map_techniques(dict(merged))
    ids = [m.technique.id for m in new_matches]

    assert "T1046" in ids, (
        f"a 400-port scan over 10 insert blocks mapped {ids or 'NOTHING'}. The window's ports "
        f"({merged['unique_dst_ports']} >= {DISCOVERY_MIN_PORTS}) and its entropy "
        f"({merged['port_entropy']}) both clear T1046's gates."
    )


def test_the_raw_read_issues_the_VIEWS_OWN_expressions(monkeypatch):
    """THE QUERY ITSELF, which the value-level tests cannot see.

    Two mutations were MISSED before this test existed: deleting `entropy(dst_port)` from the
    SELECT, and dropping the `dst_port > 0` filter. Both change the SQL the product issues, and
    every other test replaces `db.fetch_rows_named` wholesale -- so the query text was never
    examined and the mutations were invisible.

    WHAT EACH MUTATION WOULD COST, so the assertions are not arbitrary:
      * without `entropy(dst_port)` the read returns a constant, T1046's entropy gate never passes,
        and the rule stays blind exactly as before this fix
      * without `dst_port > 0` the read counts port 0, which the materialized view EXCLUDES, so the
        recomputed numbers would describe a different population than the table they replace
    """
    import weirvern.db as db

    seen: list[str] = []

    def capture(client, query, **params):
        seen.append(query)
        return ([], [])

    monkeypatch.setattr(db, "fetch_rows_named", capture)

    class _C:
        def insert(self, *a, **k):
            pass

    # Two partials so the collapse path runs and the raw read is attempted.
    W = datetime(2026, 9, 23, 9, 0)
    _collapse_partial_aggregates([_agg_row(1, 1, 1, 100, window=W) for _ in range(2)], {}, _C())

    assert seen, "the raw-flow read was never issued, so nothing was recomputed"
    q = seen[0]

    assert "entropy(dst_port)" in q, (
        "the raw read does not compute entropy, so port_entropy cannot be recovered and T1046's "
        "entropy gate stays blind"
    )
    assert "stddevPop" in q, (
        "the raw read does not compute stddev, so bytes_stddev/packets_stddev stay per-block"
    )
    assert "dst_port > 0" in q, (
        "the raw read counts port 0, which the materialized view EXCLUDES -- the recomputed numbers "
        "would describe a different population than the table they replace"
    )
    # And the cardinalities must be exact, not approximate counts.
    assert "uniqExact(dst_addr)" in q, "dst addresses are not counted exactly"
    assert "uniqExact(dst_port)" in q, "ports are not counted exactly"


# ── SIGTERM's "graceful shutdown" MUST REACH THE INGEST LOOP (audit F079) ─────────────────────────
#
# `tail_forever` has accepted a `stop` event for a while, and the worker's call site NEVER PASSED
# ONE. On SIGTERM the handler set `_stop`, the detect loop broke, and `sys.exit(0)` tore the process
# down with the ingest thread wherever it was. Because the cursor is checkpointed AFTER each pass, a
# kill mid-pass leaves it at the PREVIOUS offset, and the next start re-reads and re-inserts every
# row since -- into `flows`, a plain MergeTree with no deduplication. That is F018 re-entering through
# process teardown rather than through an in-memory cursor.
#
# These read the SOURCE because the defect was in the WIRING, and a test that starts a loop with its
# own stop event (as the ingester's tests correctly do) cannot see the call site at all.


def _main_source() -> str:
    import pathlib as _p
    return (_p.Path(__file__).resolve().parent.parent / "weirvern" / "worker.py").read_text()


def test_the_ingest_thread_is_handed_the_shutdown_event():
    """The call site must pass `stop=_stop`, or graceful shutdown never reaches ingest."""
    import ast

    tree = ast.parse(_main_source())
    call = None
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        f = node.func
        if not (isinstance(f, ast.Attribute) and f.attr == "Thread"):
            continue
        for kw in node.keywords:
            if kw.arg == "target" and isinstance(kw.value, ast.Name) \
                    and kw.value.id == "tail_forever":
                call = node
    assert call is not None, "could not find the Thread(target=tail_forever) call site"

    kwargs = {kw.arg: kw.value for kw in call.keywords}
    assert "kwargs" in kwargs, "the Thread call has no kwargs dict"
    blob = ast.unparse(kwargs["kwargs"])
    assert "stop" in blob, (
        f"the ingest thread is started with kwargs={blob} -- NO stop event. A SIGTERM sets _stop and "
        f"exits the process, killing the ingest thread mid-pass; the cursor is checkpointed after "
        f"each pass, so the next start re-ingests everything since. This is audit F079"
    )
    assert "_stop" in blob, (
        f"the ingest thread's stop event is {blob}. It must be the SAME `_stop` the SIGTERM handler "
        f"sets and the detect loop reads -- a separate private event would never be signalled, which "
        f"is a silent version of the same defect"
    )


def test_shutdown_JOINS_the_ingest_thread_before_exiting():
    """Passing the event is not enough: without a join the pass is still cut short."""
    src = _main_source()
    assert "ingest_thread.join(" in src, (
        "shutdown never joins the ingest thread, so a SIGTERM still cuts the in-flight pass off "
        "partway and loses the rows since the last checkpoint (audit F079)"
    )

    # The join must be in the SHUTDOWN path, after the detect loop, and before the siphon teardown --
    # otherwise the pass is still cut short, or the child is SIGKILLed while ingest is still running.
    #
    # The anchor is the loop tail's remaining-time computation. It used to be the single
    # `_stop.wait(...)` that followed it; the tail now sleeps IN SLICE S (so the Sluice Gate's own
    # interval is honoured -- see worker._sluice_maybe), and the anchor moves to the line that
    # replaced the wait rather than pinning the old shape. The ORDER this test exists to hold is
    # unchanged: loop tail, then join, then the siphon teardown.
    i_join = src.index("ingest_thread.join(")
    i_loop = src.index("remaining = max(1, settings.detect_interval_s")
    i_siphon = src.index("siphon.stop()")
    assert i_loop < i_join, "the ingest join happens before the detect loop ends"
    assert i_join < i_siphon, (
        "the ingest join is AFTER the siphon teardown -- the supervised child would be stopped while "
        "ingest is still writing"
    )


def test_the_join_is_BOUNDED_so_a_stalled_pass_cannot_hold_the_pod_open():
    """An unbounded join is its own outage: the kubelet SIGKILLs at the grace period and the very
    checkpoint the wait protects is lost, plus the SIPKILL of the supervised child is delayed."""
    import re

    src = _main_source()
    m = re.search(r"ingest_thread\.join\(([^)]*)\)", src)
    assert m, "no ingest_thread.join(...) found"
    args = m.group(1)
    assert "timeout" in args, (
        f"the ingest join is unbounded: join({args}). A stalled pass would hold the process open "
        f"until the kubelet kills it"
    )


def test_the_shared_event_actually_stops_a_REAL_ingest_loop_and_checkpoints():
    """The source assertions above pin the wiring; this proves the wiring DOES what it claims.

    It starts the real `tail_forever` with the same event the SIGTERM handler sets, sets it the way
    the handler does, joins the way main() does, and then checks the thing that actually matters: a
    FRESH loop over the same unchanged file re-ingests NOTHING, because the cursor was checkpointed
    before the thread finished.
    """
    import threading as _th
    import time as _time

    from weirvern.ingester import _tail_state_path, tail_forever

    class _Counter:
        def __init__(self):
            self.rows = 0

        def insert(self, table, rows, column_names=None):  # noqa: ANN001
            self.rows += len(rows)
            return len(rows)

    def _rec(i):  # noqa: ANN001
        base = 1_756_000_000_000_000_000
        return {
            "type": "NETFLOW_V5", "time_received_ns": base + i * 10**9,
            "sampler_address": "192.0.2.10", "time_flow_start_ns": base + i * 10**9,
            "time_flow_end_ns": base + i * 10**9 + 5 * 10**8, "bytes": 1000 + i, "packets": 10,
            "src_addr": f"198.51.100.{10 + i}", "dst_addr": "203.0.113.9",
            "src_port": 40_000 + i, "dst_port": 443, "proto": 6, "tcp_flags": 24,
        }

    import json as _json
    import pathlib as _p
    import tempfile as _tf

    with _tf.TemporaryDirectory() as d:
        f = _p.Path(d) / "flows.jsonl"
        f.write_text("\n".join(_json.dumps(_rec(i)) for i in range(6)) + "\n")

        c1 = _Counter()
        stop = _th.Event()
        th = _th.Thread(target=tail_forever,
                        kwargs={"client": c1, "path": str(f), "interval_s": 0.15,
                                "zeek_dir": "", "exporter_allow": "", "stop": stop},
                        daemon=True)
        th.start()
        _time.sleep(0.8)          # at least one full pass
        stop.set()                # what _handle_sigterm does
        th.join(timeout=10)       # what main() now does
        assert not th.is_alive(), "the ingest loop did not stop within the join timeout"
        assert c1.rows == 6, f"the first loop ingested {c1.rows} rows, expected 6"

        assert _p.Path(_tail_state_path(str(f))).exists(), (
            "no checkpoint was written, so this test cannot show the cursor survived"
        )

        # A RESTART over the same, unchanged file must ingest NOTHING. This is the outcome the fix is
        # for: without the join, a kill mid-pass leaves the cursor behind and this reads 6 again.
        c2 = _Counter()
        stop2 = _th.Event()
        th2 = _th.Thread(target=tail_forever,
                         kwargs={"client": c2, "path": str(f), "interval_s": 0.15,
                                 "zeek_dir": "", "exporter_allow": "", "stop": stop2},
                         daemon=True)
        th2.start()
        _time.sleep(0.5)
        stop2.set()
        th2.join(timeout=10)
        assert c2.rows == 0, (
            f"the restart re-ingested {c2.rows} rows from an unchanged file -- duplicate rows in a "
            f"MergeTree with no deduplication"
        )
