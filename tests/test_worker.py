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
from weirvern.worker import detection_sweep, train_if_due

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
    # SOC-2: "suppressed" no longer means "gone" -- the window is recorded as a near
    # miss instead. The anomaly-side assertion goes through by_table so it keeps
    # meaning exactly what it always meant, and the near-miss side is pinned below.
    _install_db_stubs(monkeypatch, existing_anomalies=[])
    fake_ch, rows = _capturing_client()
    assert detection_sweep(fake_ch, detectors, Settings(), ModelConfig()) == [], \
        "a 0.25 agreement must not pass the default 0.33 gate"
    assert fake_ch.by_table.get("weirvern.netflow_anomalies", []) == [], \
        "a suppressed window must not be recorded as an anomaly"
    gate_rows = fake_ch.by_table.get("weirvern.near_misses", [])
    assert len(gate_rows) == 1, (
        "the suppressed window should be recorded as a near miss (SOC-2); "
        f"near-miss rows captured: {len(gate_rows)}"
    )

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
    assert len(fake_ch2.by_table.get("weirvern.netflow_anomalies", [])) == 1
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
