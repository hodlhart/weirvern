"""ML-1: detection quality is MEASURED, and the measurement is wired in.

THE FINDING THIS FILE EXISTS FOR. Nothing measured whether the pipeline detected the
attacks it exists for. `f1_score` appeared once in the codebase -- fidelity of Gradient
Boosting to its teacher, not accuracy on real attacks -- and the demo seed tool plus a
README smoke test are not a measurement. Meanwhile an arity bug that stopped ALL
detection passed 1089 tests, because every test checked components and none checked
outcomes: "insert writes N values", "the scorer adds up", "the fixture parses". The
question nobody asked was the operator's: "if a port scan happens, does an alert come
out the end?"

THE ANSWER IS A HARNESS, AND THE HARNESS IS GATED. `scripts/eval_detection.py` seeds
attacks through the real generator, the real materialized views, the real training and
the real sweep, then asserts the final verdicts. The CI job `detection-quality` runs it
against a service ClickHouse on every push and PR. These tests pin the parts that would
silently rot:

  * the harness exists and its assertions are the OUTCOME level ones (verdicts), not
    component level (a helper returning a number);
  * CI runs it -- a harness nobody runs is the same class of failure as `f1_score`
    appearing once: a measurement capability that measures nothing;
  * the negative direction is real: the harness distinguishes attacks from benign
    traffic, or its "detected!" would mean nothing. Verified live: with every attack
    switch off, the scanner host's worst severity was medium, not high/critical;
  * it drives the REAL pipeline. An earlier draft re-implemented the worker's
    enrichment, which would have tested a copy of the pipeline instead of the pipeline.
"""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HARNESS = ROOT / "scripts" / "eval_detection.py"
GENERATOR = ROOT / "weirvern" / "tools" / "demo_flows.py"
CI = ROOT / ".github" / "workflows" / "ci.yml"


def test_the_harness_exists_and_runs_the_real_pipeline():
    assert HARNESS.exists(), (
        "scripts/eval_detection.py is gone. Nothing then measures whether the pipeline "
        "detects seeded attacks, which is the gap ML-1 exists to close."
    )
    src = HARNESS.read_text()
    # The real pieces, by name: the generator, the sweep, the trainers.
    assert "demo_flows" in src, "the harness no longer seeds via the real generator"
    assert "detection_sweep" in src, (
        "the harness no longer calls the worker's real detection sweep, so it is testing "
        "a copy of the pipeline rather than the pipeline"
    )
    assert "build_detectors" in src, "the harness no longer builds the real detectors"
    assert "db.connect" in src or "from weirvern import db" in src, (
        "the harness does not touch a real database"
    )


def test_the_assertions_are_on_final_verdicts_not_components():
    """The whole point: verdicts, not helper return values."""
    src = HARNESS.read_text()
    assert "worst_severity" in src, (
        "the harness no longer reduces verdicts to severities, so it cannot assert the "
        "outcome an operator cares about"
    )
    for level in ('"high"', '"critical"'):
        assert level in src, f"the harness no longer checks for {level} severity"
    # And it must FAIL when the attacks are not detected -- every check must feed a
    # failure counter that decides the exit code.
    assert "failures += 1" in src, "a failed assertion no longer counts toward the exit code"
    assert "return 1" in src, "the harness cannot exit non-zero, so CI cannot fail on it"


def test_ci_gates_on_the_harness():
    src = CI.read_text()
    assert "eval_detection.py" in src, (
        "CI no longer runs the detection eval. A harness nobody runs measures nothing -- "
        "exactly the 'f1_score appears once' state ML-1 flagged."
    )
    job = src[src.index("detection-quality"):]
    assert "clickhouse" in job, (
        "the detection-quality job lost its ClickHouse service; the harness needs a real "
        "database or it cannot run the materialized views"
    )
    assert "MODEL_DIR" in job, (
        "the job does not set MODEL_DIR; the default /models is not writable on a runner"
    )


def test_the_seeded_attacks_and_benign_hosts_are_named_constants():
    """One definition, so the assertions and the seed cannot disagree about who is who."""
    src = HARNESS.read_text()
    assert "SCANNER" in src and "BEACON" in src and "EXFIL" in src, (
        "the harness no longer names its seeded attackers"
    )
    assert "benign_hosts" in src, (
        "the harness lost its benign-host derivation, so it cannot check the other "
        "direction -- that ordinary traffic is NOT all alerted on"
    )
    # The derivation comes from the seed's device count, not a literal that can silently
    # shrink under it (the review found one benign host the old literal .13-.20 missed).
    assert "range(3, devices)" in src, (
        "the benign set is no longer derived from the device count the seed actually used"
    )


def test_the_harness_holds_the_attack_period_out_of_training():
    """Review round 2026-10-15: training and scoring covered the SAME span, attacks
    included, so overfitting/drift -- the failure modes that matter most for an anomaly
    detector -- were invisible to the only quality gate in CI."""
    src = HARNESS.read_text()
    assert "attack_start_minute" in src, "the harness no longer delays the seeded attacks"
    assert "train_end_dt" in src, (
        "the harness no longer separates the training window from the scoring span, so a "
        "detector is again scored on attacks it trained on"
    )


def test_the_harness_waits_for_the_aggregates_to_SETTLE_not_just_appear():
    """Issue #2, measured: the old wait broke on the FIRST non-zero count -- the seed inserts
    in chunks and the MVs fire per insert, so training and the sweep then ran against a table
    that was still filling, and WHICH windows existed differed run to run. That is the coin
    toss behind detection-quality flipping PASS/FAIL on identical eval code."""
    src = HARNESS.read_text()
    assert "wait_for_aggregates" in src, "the settle-wait is gone; the race is back"
    assert "if rows and rows[0][0] > 0:" not in src, (
        "the first-nonzero wait is back: the run trains and scores against a half-filled table"
    )
    assert "eval inputs:" in src, (
        "the run no longer records its seed and inputs; a red CI run cannot be reproduced"
    )


def test_the_settle_wait_returns_only_when_the_count_stops_growing():
    import importlib.util
    from types import SimpleNamespace

    spec = importlib.util.spec_from_file_location("eval_detection_under_test", HARNESS)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    class _C:
        def __init__(self, counts):
            self.counts, self.i = counts, 0

        def query(self, sql, parameters=None, **_kw):
            n = self.counts[min(self.i, len(self.counts) - 1)]
            self.i += 1
            return SimpleNamespace(result_rows=[(n, None)])

    count, err = mod.wait_for_aggregates(_C([5, 9, 12, 12, 12, 12]), timeout_s=5)
    assert err == "" and count == 12

    count, err = mod.wait_for_aggregates(_C(list(range(1, 50))), timeout_s=1)
    assert err and "did not settle" in err, (
        "a table that never stops growing must be a stated failure, not a shrug")


def test_the_harness_asserts_a_storm_ceiling_and_determinism():
    """The two checks that bound what a green run MEANS: a host flagged in most windows is
    a storm no matter which other assertions pass, and two identical sweeps must agree."""
    src = HARNESS.read_text()
    assert "storm" in src, "the harness no longer bounds verdict volume per host"
    assert "deterministic" in src.lower(), (
        "the harness no longer re-runs the sweep and compares -- ordering/clock leaks "
        "would pass again"
    )


def test_the_seed_start_is_anchored_to_the_aggregation_grid():
    """Issue #49, measured: the seed's start was wall-clock, so two eval runs two minutes
    apart landed the same flows at different phases of the five-minute bucket grid -- 728 vs
    732 settled rows, 158 vs 118 verdicts, the benign high+ set changing, DBSCAN's cluster
    centres appearing in one run and vanishing in the other. One fixture, two datasets.

    The start is now a multiple of the bucket width, and every fixture value -- durations
    included -- comes from the seeded rng: same seed, frozen clock, same bytes."""
    import importlib.util
    import json
    import os
    import tempfile
    from types import SimpleNamespace

    spec = importlib.util.spec_from_file_location("demo_flows_under_test", GENERATOR)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    # 1. THE ANCHOR: a multiple of the 300s grid, never after the clock it was read from,
    #    and STABLE within a bucket -- everything inside one five-minute window seeds
    #    byte-identical data, which is what makes two eval runs comparable.
    for now in (1_800_000_123.7, 1_800_000_299.9, 1_800_000_300.0, 12345.0):
        assert mod._anchored_start(now) % 300 == 0, f"start for {now} is off the bucket grid"
        assert mod._anchored_start(now) <= int(now)
    assert mod._anchored_start(1_800_000_001.0) == mod._anchored_start(1_800_000_299.9)

    # 2. FROZEN CLOCK, SAME SEED -> IDENTICAL FIXTURE, timestamps included. The duration
    #    draw used the module-global `random` before this; it differed run to run.
    def run(seed: int, start: int):
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "demo.jsonl")
            mod.generate(SimpleNamespace(minutes=10, devices=4, output=out, seed=seed,
                                         scanner=True, scan_ports=20, beacon=True,
                                         exfil=True, attack_start_minute=3, start=start))
            return [json.loads(line) for line in open(out) if line.strip()]

    a = run(7, 1_800_000_000)
    b = run(7, 1_800_000_000)
    assert a == b, "the same seed and clock produced two different fixtures"
    assert [r["time_flow_end_ns"] for r in a] == [r["time_flow_end_ns"] for r in b]
    # Not degenerate: the end stamp is a per-flow draw, not one constant.
    assert len({r["time_flow_end_ns"] for r in a}) > 1

    # 3. THE EVAL STATES ITS PHASE: the log names the first bucket it calibrated on, and the
    #    generator's anchor is what puts it on a bucket boundary.
    harness = HARNESS.read_text()
    assert "seed phase:" in harness, (
        "the eval no longer states the phase it seeded on; a green run cannot be reproduced "
        "from its log alone"
    )
    assert "_anchored_start" in GENERATOR.read_text(), (
        "the generator's start is unanchored again -- the phase is wall-clock dependent"
    )

def test_a_detector_that_cannot_train_on_the_seed_is_reported_and_does_not_decide(monkeypatch, capsys):
    """A GATE THAT DIES AT TRAINING MEASURES NOTHING (measured 2026-11-16).

    The job went red on `detector(s) failed to train on the holdout window: DBSCAN` with the
    detector's own log line saying it had 195 rows and found no dense region above eps=0.6. The
    failure is a property of the SEED -- after 1-in-5 host sampling its fifth-nearest-neighbour
    distance is wider than the configured radius -- and the gate died before scoring a single
    attack. Whether the pipeline detects the seeded attacks went unmeasured for weeks.

    So DBSCAN's inability to train is a SKIP: named on stdout, with the outcome and the radius it
    tried, while the detectors that DO carry the verdict stay hard failures. A green job must never
    read as "all four detectors were exercised".
    """
    import importlib.util
    from datetime import datetime
    from types import SimpleNamespace

    spec = importlib.util.spec_from_file_location("eval_detection_skip_under_test", HARNESS)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    class _Model:
        def __init__(self, trains=True, outcome="ok"):
            self.trains, self.outcome = trains, outcome
            self.train_outcome = outcome
            self.X_train_unscaled = [[0.0]]
            self.cfg = SimpleNamespace(dbscan_eps=0.6, dbscan_min_samples=5)

        def train(self, *a, **k):
            return self.trains

    def _settings_pair(db_trains=True, baseline_trains=True):
        models = [_Model(), _Model(),
                  _Model(trains=db_trains, outcome="no-dense-structure"),
                  _Model(trains=baseline_trains)]
        monkeypatch.setattr("weirvern.db.fetch_rows",
                            lambda *a, **k: [(datetime(2026, 1, 1), datetime(2026, 1, 2))])
        monkeypatch.setattr("weirvern.worker.build_detectors", lambda *a, **k: tuple(models))
        return models

    _settings_pair(db_trains=False)
    detectors, err = mod.train_detectors(object(), (object(), object()), attack_start_minute=200)
    out = capsys.readouterr().out
    assert err is None, f"a sparse seed for DBSCAN failed the whole gate: {err}"
    assert detectors is not None
    assert "SKIP" in out and "DBSCAN" in out, f"the skip was not reported: {out!r}"
    assert "NOT measured" in out, "the skip must say what went unmeasured, not just that it skipped"
    assert "eps=0.6" in out, "the skip must carry the radius it could not cluster at"

    _settings_pair(baseline_trains=False)
    detectors, err = mod.train_detectors(object(), (object(), object()), attack_start_minute=200)
    assert detectors is None and err, "a detector that DOES carry the verdict may still fail the gate"
    assert "Adaptive Baseline" in err and "DBSCAN" not in err, (
        f"the error blames the skipped detector: {err}"
    )

def test_the_drain_compares_naive_and_aware_datetimes_without_dying():
    """MEASURED IN CI 2026-11-16, after the detectors had trained and the sweep had run:

        if covered is not None and covered >= hi:
        TypeError: can't compare offset-naive and offset-aware datetimes

    The cursor is written from a ClickHouse value (naive) and `hi` comes from the seed clock, which
    is pinned to UTC and therefore aware. The whole eval was thrown away at its last step, on a
    comparison the run could not fail more cheaply. ClickHouse stores UTC, so a naive value IS UTC
    and saying so is the fix; treating "naive" as "unknown timezone" would silently shift the
    comparison by the runner's offset.
    """
    import importlib.util
    from datetime import UTC, datetime, timedelta

    spec = importlib.util.spec_from_file_location("eval_detection_tz_under_test", HARNESS)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    aware = datetime(2026, 11, 16, 5, 0, tzinfo=UTC)
    naive_same = datetime(2026, 11, 16, 5, 0)
    naive_earlier = datetime(2026, 11, 16, 4, 0)
    naive_later = datetime(2026, 11, 16, 6, 0)

    assert mod._cursor_reached(naive_same, aware), "equal instants must compare equal across kinds"
    assert mod._cursor_reached(aware, naive_same)
    assert not mod._cursor_reached(naive_earlier, aware)
    assert mod._cursor_reached(naive_later, aware)
    assert not mod._cursor_reached(None, aware), "no cursor is not coverage"
    # A naive value is read as UTC, never as local time: one hour's difference must stay one hour.
    assert mod._as_utc(naive_same) == aware
    assert mod._as_utc(naive_same) - timedelta(hours=1) == mod._as_utc(naive_earlier)

def test_the_drain_budget_covers_the_distance_the_cursor_travels():
    """MEASURED IN CI 2026-11-16: "the sweep did not cover the seed after 8 calls (4.9 chunks needed
    for a 4.9h span)" -- in the same run whose own log said Detection is 19.4h behind.

    The seed is anchored to the most recent UTC midnight, so an evening CI run starts five hours of
    seeded traffic nineteen hours in the past. The cursor has to travel ~19h at one 1h chunk per
    call; the budget was computed from the seed's own 4.9h length. Sixteen verdicts were scored, all
    over windows ending fourteen hours before the attacks, and the gate failed looking like a
    coverage defect in the sweep.

    These are the run's own numbers: 19.4h behind, 4.9h span, 1h chunks.
    """
    import importlib.util
    from datetime import UTC, datetime, timedelta

    spec = importlib.util.spec_from_file_location("eval_detection_budget_under_test", HARNESS)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    hi = datetime(2026, 11, 16, 19, 24, tzinfo=UTC)
    lo = hi - timedelta(hours=4.9)
    cursor = hi - timedelta(hours=19.4)

    calls, behind = mod.drain_call_budget(covered=cursor, hi=hi, lo=lo, chunk_s=3600.0)
    assert abs(behind - 19.4 * 3600) < 60, f"the backlog was read as {behind / 3600:.1f}h"
    assert calls >= 24, (
        f"the budget is {calls} calls for a {behind / 3600:.1f}h backlog in 1h chunks -- the sweep "
        f"cannot reach the seeded attacks, which is the failure this replaces"
    )

    # The old arithmetic, kept as the negative: span-only budgeting under-budgets by design.
    old_calls = int(4.9) + 4
    assert calls > old_calls, "budgeting from the span alone is what produced 8 calls for 19.4h"

    # No cursor yet: fall back to the span plus slack rather than refusing to start.
    calls_absent, behind_absent = mod.drain_call_budget(covered=None, hi=hi, lo=lo, chunk_s=3600.0)
    assert behind_absent == 0 and calls_absent >= 8, (calls_absent, behind_absent)

    # A cursor already at `hi` needs no backlog allowance, only the slack.
    calls_ahead, _ = mod.drain_call_budget(covered=hi, hi=hi, lo=lo, chunk_s=3600.0)
    assert calls_ahead < calls, "a cursor at the last seeded window must not be budgeted as behind"
