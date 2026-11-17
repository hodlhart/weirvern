"""The deep health report: what each probe claims, and whether the claim is earned.

WHY THIS FILE EXISTS. `collect_health` had NO test coverage before this, and audit F024 was a
defect living in that gap: the `models` probe selected `max(trained_at)` per detector and then
never compared it to anything, so `ok=True` was driven purely by rows existing.

MEASURED on the live cluster while confirming it: every detector's last training was 27.2 HOURS
old against `RETRAIN_EVERY_H=6` -- 4.5x the cadence -- and `/api/health` reported:

    models  ok=True  "4 detector(s) with training history"

Combined with F023 (a metadata row was written for a detector that never trained), a pipeline that
had stopped training was indistinguishable from a healthy one. THAT is the shape of this project's
worst failure class: a green reading over work that did not happen.

So these tests are about whether a probe's verdict FOLLOWS its own evidence, which is checkable
with a stub client and no cluster.
"""

from __future__ import annotations

import datetime
from types import SimpleNamespace

from weirvern.admin import status


class _Result:
    def __init__(self, rows):
        self.result_rows = rows


class _StubClient:
    """A ClickHouse client that answers per-SQL-fragment from a dict.

    HONOURS ITS QUERY, in the sense that one fragment's rows cannot leak into another's answer --
    the first version of this pattern in this project returned every row for a table whatever the
    WHERE clause said, which made working filters look broken.

    IT MUST ANSWER `SELECT version()`. The connectivity probe runs FIRST and `collect_health`
    stops there when it fails, so a stub that only knew about `ml_models` produced a report with
    two probes and no `models` probe at all -- and the tests then failed claiming the probe did
    not exist, which is a fact about the stub rather than about the code. `version()` is answered
    here for the same reason the real client answers it.
    """

    def __init__(self, by_fragment=None):
        self.by_fragment = by_fragment or {}

    def query(self, sql, *a, **kw):
        if "version()" in sql:
            # A SYNTHETIC version, deliberately. This used to be the ACTUAL server version read
            # off the live cluster, which is deployment information in a tracked file and tripped
            # the sanitation guard -- and then the COMMENT explaining the removal repeated the
            # same literal, which tripped it again. The value is irrelevant to every assertion
            # here: the probe only needs a non-empty version to consider ClickHouse reachable, so
            # a made-up one serves exactly as well and leaks nothing.
            #
            # If you are tempted to make this realistic, do not: the guard is right, and the
            # probe does not care what the version IS.
            return _Result([("0.0.0-test",)])
        for frag, rows in self.by_fragment.items():
            if frag in sql:
                return _Result(rows)
        return _Result([])


def _settings(**kw):
    base = {"retrain_every_h": 6, "retrain_window_h": 24, "detect_interval_s": 300}
    base.update(kw)
    return SimpleNamespace(**base)


def _probe(name, **kw):
    """One probe from the report, by name."""
    report = status.collect_health(_StubClient(kw.pop("by_fragment", {})), _settings(**kw))
    return next((p for p in report.probes if p.name == name), None)


# ── the models probe: ROW EXISTENCE IS NOT FRESHNESS ─────────────────────────────────────────

def test_a_STALE_pipeline_is_reported_as_not_ok():
    """THE DEFECT ITSELF (F024). Four detectors last trained 27h ago against a 6h cadence is a
    pipeline that has stopped training, and the probe must say so rather than counting rows."""
    now = datetime.datetime.now()
    old = now - datetime.timedelta(hours=27)
    rows = [(n, old, "{}", 20) for n in ("Isolation Forest", "Gradient Boosting", "DBSCAN")]
    rows.append(("Adaptive Baseline", now - datetime.timedelta(hours=1), "{}", 216))
    p = _probe("models", by_fragment={"FROM weirvern.ml_models": rows})
    assert p is not None, "the models probe did not run"
    assert p.ok is False, (
        f"a detector 27h stale against a 6h cadence must not report ok. Got ok={p.ok}, "
        f"detail={p.detail!r} -- which is the live state this was found in"
    )
    assert "STALE" in str(p.detail).upper(), f"the detail must name the problem: {p.detail!r}"


def test_a_FRESH_pipeline_is_ok():
    """The other direction: a real pipeline must not be reported broken, or the probe becomes
    noise nobody reads."""
    now = datetime.datetime.now()
    rows = [(n, now - datetime.timedelta(hours=1), "{}", 20)
            for n in ("Isolation Forest", "Gradient Boosting", "DBSCAN", "Adaptive Baseline")]
    p = _probe("models", by_fragment={"FROM weirvern.ml_models": rows})
    assert p is not None and p.ok is True, f"a 1h-old pipeline must be ok: {p.detail!r}"
    assert "cadence" in str(p.detail), "a green verdict should state the interval it judged against"


def test_NO_rows_at_all_is_not_ok_and_says_so():
    p = _probe("models", by_fragment={"FROM weirvern.ml_models": []})
    assert p is not None and p.ok is False
    assert "no training runs" in str(p.detail)


def test_a_FRESH_deployment_is_not_reported_as_stale():
    """THE TRAP IN THE OBVIOUS FIX, measured while writing it. `_staleness` iterates a FIXED list
    of four known detectors and treats any model ABSENT from its map as never-trained -- correct
    for `model_overview`, which reads a full history, and wrong for this probe, whose query returns
    one row per detector that HAS history. An unfiltered hand-off made an empty result report ALL
    FOUR detectors stale, turning "no models yet" into a hard failure on every fresh install."""
    assert status._model_staleness([], _settings()) == []


def test_a_single_detector_does_not_make_the_others_look_stale():
    """The same trap in a less obvious form: one detector present and fresh must not cause the
    three absent ones to be reported."""
    now = datetime.datetime.now()
    fresh = [("Isolation Forest", now - datetime.timedelta(hours=1), "{}", 1)]
    assert status._model_staleness(fresh, _settings()) == []


def test_a_detector_with_NO_timestamp_is_stale():
    """A detector that never trained has no timestamp, and a MISSING MEASUREMENT MUST NOT READ AS
    A HEALTHY ONE -- the rule `_staleness` already documents, which this adapter must not undo."""
    assert status._model_staleness([("DBSCAN", None, "{}", 0)], _settings()) == ["DBSCAN"]


def test_the_cadence_comes_from_settings_not_a_literal():
    """A hardcoded 6 would ignore an operator who set RETRAIN_EVERY_H, and the probe would then
    disagree with the retrain clock it is judging."""
    now = datetime.datetime.now()
    rows = [("Isolation Forest", now - datetime.timedelta(hours=2), "{}", 1)]
    assert status._model_staleness(rows, _settings(retrain_every_h=1)) == ["Isolation Forest"]
    assert status._model_staleness(rows, _settings(retrain_every_h=24)) == []


def test_a_datetime_from_clickhouse_is_accepted():
    """ClickHouse returns a naive datetime, and `_model_staleness` must convert rather than raise.
    A TypeError here would be swallowed by the probe's own try/except and read as "not stale"."""
    now = datetime.datetime.now()
    assert status._model_staleness([("DBSCAN", now - datetime.timedelta(hours=30), "{}", 1)],
                                   _settings()) == ["DBSCAN"]


# ── the report as a whole ────────────────────────────────────────────────────────────────────

def test_the_report_never_raises_on_a_broken_client():
    """`collect_health` documents "Never raises", and a health check that throws on a database
    problem takes down the page that would have explained it."""

    class _Exploding:
        def query(self, *a, **kw):
            raise RuntimeError("clickhouse is unreachable")

    report = status.collect_health(_Exploding(), _settings())
    assert report is not None
    assert report.probes, "a broken client must still produce probes that report the failure"


def test_every_probe_carries_a_detail_string():
    """A probe with `ok=False` and no detail sends an operator to the logs with no idea what to
    look for, and a probe with `ok=True` and no detail cannot be audited later."""
    report = status.collect_health(_StubClient(), _settings())
    for p in report.probes:
        assert isinstance(p.detail, str), f"probe {p.name!r} has no detail"


# ── the detect_loop probe: NOTHING ELSE MEASURES DETECTION ───────────────────────────────────
#
# WHY. Measured on the live cluster while the sweep was analysing ZERO rows, every OTHER probe
# reported ok -- clickhouse, tables, ingest_freshness, zeek_freshness, models, alerts. The
# container was healthy, data was flowing, models were loaded, and detection was doing nothing.
# The worker's liveness probe cannot catch it either: it imports `weirvern.config` and proves only
# that the interpreter works, while the loop swallows every exception and sleeps 30s.
#
# The evidence is written per cycle by two independent paths: `baseline_history.computed_at` (the
# baseline detector's train) and `near_misses.replaced_at` (the sweep scoring a host-window).

def _loop_probe(scoring, training, **settings_kw):
    """The `detect_loop` probe for a given pair of (count, age) readings.

    `scoring` comes from `ml_window_scores` -- every scored host-window, before the threshold.
    `training` comes from `baseline_history` -- the baseline detector's train().

    THEY ARE DIFFERENT FACTS, and the probe used to pass if EITHER was fresh. Training keeps its
    own schedule, so it stayed fresh through a sixteen-hour scoring outage and the green verdict
    was wrong. The scoring age is the verdict; the training age is evidence.
    """
    by_fragment = {
        "FROM weirvern.ml_window_scores": [scoring] if scoring is not None else [],
        "FROM weirvern.baseline_history": [training] if training is not None else [],
    }
    return _probe("detect_loop", by_fragment=by_fragment, **settings_kw)


def test_a_FRESH_cycle_is_ok():
    p = _loop_probe((216, 40), (329, 44))
    assert p is not None, "the detect_loop probe did not run"
    assert p.ok is True, f"a 40s-old cycle must be ok: {p.detail!r}"


def test_a_STOPPED_loop_is_not_ok():
    """THE DEFECT THIS PROBE EXISTS FOR: the loop stopped and nothing noticed."""
    p = _loop_probe((216, 7200), (329, 7200))
    assert p is not None and p.ok is False, f"a 2h-stale loop must not be ok: {p.detail!r}"
    assert "NOTHING SCORED" in str(p.detail), f"the detail must name the fault: {p.detail!r}"


def test_TRAINING_being_fresh_does_NOT_excuse_scoring_being_stale():
    """THE LIVE OUTAGE, inverted (2026-11-12).

    This test used to be called `test_EITHER_signal_being_fresh_is_enough` and asserted the
    opposite. Its stated reason was that a single signal can go quiet for a benign cause: nothing
    scores in a window, or the baseline lacks samples. That was true of `near_misses`, which only
    moves when something scores ABNORMALLY -- but the fix widened the check until the healthiest
    signal decided the verdict, and that is what hid sixteen hours of dark detection: training ran
    the whole time, so the freshest age was minutes old while nothing was scored at all.
    """
    p = _loop_probe((216, 99999), (329, 30))
    assert p is not None and p.ok is False, (
        "training being fresh must not excuse scoring being stale -- that is exactly the state "
        f"the live box sat in for 16 hours. Got ok={p.ok}, detail={p.detail!r}"
    )


def test_scoring_fresh_with_lagging_training_is_ok():
    """The converse, and it is not symmetry for its own sake: scoring is the product. A baseline
    that is due for retraining while windows are still being scored is a maintenance note, not an
    outage, and calling it one would train the operator to ignore the probe."""
    p = _loop_probe((216, 30), (329, 99999))
    assert p is not None and p.ok is True, f"{p.detail!r}"


def test_BOTH_signals_stale_is_not_ok():
    """The converse, so the either/or above cannot be satisfied by weakening this."""
    assert _loop_probe((216, 99999), (329, 99999)).ok is False


def test_training_running_but_NEVER_scored_is_named_as_its_own_fault():
    """A loop that trains and never scores is not "never ran" -- something IS running, and saying
    "the loop has never run" would send the next person to the wrong place."""
    p = _loop_probe(None, (329, 40))
    assert p is not None and p.ok is False
    assert "NOTHING HAS EVER BEEN SCORED" in str(p.detail), f"{p.detail!r}"
    assert "monitored network scope" in str(p.detail), (
        "the one benign cause must be named, or this reads as a code fault every time"
    )


def test_an_EMPTY_table_reads_as_NEVER_RAN_not_as_stale():
    """The distinction the SQL has to preserve. A zero COUNT is the only trustworthy "never ran"
    signal -- and the detail must say "never" rather than quoting an age, because the age from an
    empty aggregate is meaningless."""
    p = _loop_probe((0, 1790165466), (0, 1790165466))
    assert p is not None and p.ok is False
    assert "NEVER run" in str(p.detail), f"an empty table must say 'never run': {p.detail!r}"


def test_a_56_YEAR_age_is_not_quoted_to_the_operator():
    """A regression guard on a mistake I made. `dateDiff` against an empty subquery returns the
    difference from ClickHouse's default datetime -- 1790165466s, about 56 years -- so a probe
    that trusted the age would tell an operator their brand-new install last ran in 1970."""
    p = _loop_probe((0, 1790165466), (0, 1790165466))
    assert "56 year" not in str(p.detail) and "1970" not in str(p.detail)


def test_the_threshold_follows_the_CONFIGURED_cadence():
    """A hardcoded 900 would call a 1800s-cadence deployment dead every cycle, and a hardcoded 60
    would call a 300s cadence dead on every cycle. Both are the "probe that lies" failure."""
    assert _loop_probe((1, 500), (1, 500)).ok is True           # default 300s cadence
    assert _loop_probe((1, 500), (1, 500), detect_interval_s=60).ok is False
    assert _loop_probe((1, 500), (1, 500), detect_interval_s=1800).ok is True


def test_the_probe_NAMES_its_evidence():
    """An operator reading ok=False needs to know which signal it judged, and a green verdict
    should be auditable after the fact."""
    p = _loop_probe((216, 120), (329, 200))
    assert "scored" in str(p.detail) and "trained" in str(p.detail), f"{p.detail!r}"


def test_a_broken_query_does_not_produce_a_false_verdict():
    """If the query itself fails the probe must not GUESS -- but it must not vanish either.

    The original contract was silence: "the `if err is None` guard prevents a database problem being
    reported as a stopped detection loop". That intent survives; the mechanism changed under F047,
    because silence turned out to be indistinguishable from a pass.

    THE FAILURE IS SCOPED TO THIS PROBE'S OWN TABLES, and that detail is the whole test. An
    earlier version made EVERY query raise -- which aborts `collect_health` at the `clickhouse`
    connectivity probe, so execution never reached `detect_loop` and the test passed vacuously
    whether the guard was there or not. A mutation that removed the guard was NOT caught. Making
    only `baseline_history`/`near_misses` fail lets the report get far enough to try.
    """
    class _SelectivelyExploding(_StubClient):
        def query(self, sql, *a, **kw):
            if "ml_window_scores" in sql or "baseline_history" in sql:
                raise RuntimeError("clickhouse is unreachable")
            return super().query(sql, *a, **kw)

    report = status.collect_health(_SelectivelyExploding(), _settings())
    names = [p.name for p in report.probes]
    assert "clickhouse" in names, (
        "the report must reach past connectivity for this test to mean anything -- if it did not, "
        "the assertion below proves nothing"
    )
    assert "models" in names or "detect_loop" in names, (
        f"execution did not reach the later probes, so this test is vacuous: {names}"
    )
    # ── THIS ASSERTION WAS INVERTED BY AUDIT F047, DELIBERATELY ────────────────────────────────
    #
    # It used to read `assert "detect_loop" not in names` -- "a failed query must not emit a
    # detect_loop verdict". The INTENT was right (a database problem must not be reported as a
    # stopped detection loop) but the MECHANISM was wrong: omitting the row entirely means a
    # consumer cannot tell "this check passed" from "this check never ran", and the cause is
    # attributed nowhere because every remaining row reads normally.
    #
    # MEASURED by driving the real collect_health: a single failing query removed up to three
    # probes from the report, and the health view looked healthy minus lines nobody counts.
    #
    # So the row IS emitted, and it says the check could not run -- which satisfies the original
    # intent (the database problem is not reported as a stopped loop) without the silence.
    assert "detect_loop" in names, (
        f"a failed query removed the probe's row entirely, so the report cannot distinguish a "
        f"passing check from one that never ran: {names}"
    )
    probe = next(p for p in report.probes if p.name == "detect_loop")
    assert probe.ok is False, (
        f"a check that could not run reported ok={probe.ok}. It must not claim either health or "
        f"not-applicability: it did not measure anything"
    )
    assert "could not run" in str(probe.detail), (
        f"the row must SAY it could not run rather than reading as a verdict: {probe.detail!r}"
    )
    assert "unreachable" in str(probe.detail), (
        f"the underlying cause should be carried through, not swallowed: {probe.detail!r}"
    )


# ── an ABSENT probe is not a passing one (audit F081) ────────────────────────────────────────

def test_an_EMPTY_zeek_table_reports_the_probe_rather_than_omitting_it():
    """THE DEFECT. The probe was added only when a freshness age came back, so an empty
    `zeek_conn` left NO zeek_freshness row in the report at all. Measured before the fix:

        probes: ['clickhouse', 'tables', 'ingest_freshness', 'models', 'detect_loop', ...]
        zeek_freshness present? False

    A consumer reading `overall ok` could not tell "the sensor is healthy" from "the sensor has
    never produced a single record". `ingest_freshness`, two probes above, already reports its own
    empty case as a FAILURE with a remedy -- so the two siblings disagreed about emptiness.
    """
    class _C(_StubClient):
        def __init__(self, heartbeats):
            super().__init__()
            self.heartbeats = heartbeats

        def query(self, sql, *a, **kw):
            if "sensor_status" in sql:
                return _Result([(self.heartbeats,)])
            if "zeek_conn" in sql:
                return _Result([(0, None)])          # empty table
            return super().query(sql, *a, **kw)

    report = status.collect_health(_C(0), _settings())
    names = [p.name for p in report.probes]
    assert "zeek_freshness" in names, (
        f"an empty zeek_conn produced NO zeek_freshness row at all, so a missing row reads as "
        f"healthy. Probes present: {names}"
    )
    p = report.by_name("zeek_freshness")
    assert p.ok is None, (
        f"with no sensor deployed there is nothing to measure, so the verdict must be "
        f"not-applicable rather than a claim either way: ok={p.ok!r}, detail={p.detail!r}"
    )


def test_a_DEPLOYED_sensor_with_no_records_is_a_FAILURE():
    """THE FAULT F081 HID. A sensor that IS deployed and has captured nothing is broken, and the
    probe must say so rather than reporting "not applicable"."""
    class _C(_StubClient):
        def query(self, sql, *a, **kw):
            if "sensor_status" in sql:
                return _Result([(5,)])               # a sensor IS reporting heartbeats
            if "zeek_conn" in sql:
                return _Result([(0, None)])          # and it has captured nothing
            return super().query(sql, *a, **kw)

    report = status.collect_health(_C(), _settings())
    p = report.by_name("zeek_freshness")
    assert p is not None and p.ok is False, (
        f"a deployed sensor with an empty zeek_conn must be a failure, not silence: "
        f"ok={p.ok if p else None!r}"
    )
    assert "NET_RAW" in str(p.detail) or "ZEEK_IFACE" in str(p.detail), (
        f"the detail does not name anything actionable: {p.detail!r}"
    )


def test_a_NOT_APPLICABLE_probe_does_not_make_the_whole_report_fail():
    """The complementary mistake: if `ok=None` were treated as falsy, every NetFlow-only deployment
    would report an overall fault for a check that has nothing to measure -- and a report that is
    always failing is one an operator stops reading."""
    report = status.HealthReport(probes=[
        status.Probe("clickhouse", ok=True),
        status.Probe("zeek_freshness", ok=None),
    ])
    assert report.ok is True, (
        "a not-applicable probe made the whole report fail, so a cluster with no capture sensor "
        "would always report unhealthy"
    )


def test_a_NOT_APPLICABLE_probe_cannot_MASK_a_real_failure():
    """The paired case, so the fix cannot pass by ignoring Nones in a way that also ignores
    failures."""
    report = status.HealthReport(probes=[
        status.Probe("clickhouse", ok=False),
        status.Probe("zeek_freshness", ok=None),
    ])
    assert report.ok is False, "a not-applicable probe masked a failing one"


def test_a_report_of_ONLY_not_applicable_probes_is_not_healthy():
    """If every check is not applicable, nothing was measured, and claiming health would be a
    measurement nothing made."""
    report = status.HealthReport(probes=[status.Probe("zeek_freshness", ok=None)])
    assert report.ok is False


def test_a_FRESH_zeek_table_still_reports_ok():
    """The working case, so the new branches did not break the ordinary path."""
    class _C(_StubClient):
        def query(self, sql, *a, **kw):
            if "sensor_status" in sql:
                return _Result([(5,)])
            if "zeek_conn" in sql:
                return _Result([(1000, 7)])
            return super().query(sql, *a, **kw)

    report = status.collect_health(_C(), _settings())
    p = report.by_name("zeek_freshness")
    assert p is not None and p.ok is True, f"{p.detail if p else 'probe missing'!r}"
    # THE VALUE IS THE AGE, and the count appears only in the prose. An earlier version of this
    # assertion used age 42 and count 1000 and then asserted "42" was absent -- which failed on the
    # probe being correct, because 42.0 IS the age. The numbers must be distinguishable:
    # age 7, count 1000, so the value can only be one of them.
    assert float(p.value) == 7.0, f"the probe value is not the freshness age: {p.value!r}"
    assert "1000" in str(p.detail), (
        f"the record count is not reported anywhere, so a probe on a large but stalled table gives "
        f"no way to tell: {p.detail!r}"
    )


# ── THE IDENTITY FEED HAD NO PROBE AT ALL, AND WENT QUIET FOR 20 HOURS (F094) ────────────────
#
# `host_fingerprints` is the input to host identification. MEASURED on the live sensor while looking
# for something else: the newest observation was 72,837 seconds old -- 20.2 hours -- while every
# probe on the health page read green. The `identity` probe reports COVERAGE from the VERDICT table,
# which shrinks slowly as hosts age out of a 7-day window, so a dead feed looks like a stable
# deployment for most of a week. Nothing in the admin surface read `host_fingerprints` at all.
#
# WHY A PROBE AND NOT A WRITE-PATH WARNING: `_record_observations` logs dropped rows at DEBUG on
# purpose -- identification is enrichment, and losing flow data to report a fingerprint problem would
# be trading the important thing for the useful one. That design is right, and the missing
# measurement is the defect: if failures are deliberately quiet, something must measure the RESULT,
# or a total outage and a quiet segment are indistinguishable.


def test_a_STALLED_identity_feed_is_reported_as_not_ok():
    """THE DEFECT. The live stall was 20.2 hours with every other probe green."""
    p = _probe("fingerprint_feed", by_fragment={
        "FROM weirvern.host_fingerprints": [(72_837, 5872)],
    })
    assert p is not None, "the fingerprint_feed probe does not exist"
    assert p.ok is False, (
        f"a feed with no observations for 20.2 hours reported ok={p.ok}. That is the live state "
        f"this probe exists for, and nothing was watching it"
    )
    assert "dhcp" in str(p.detail), (
        f"the detail must name what to check (the sensor's logs): {p.detail!r}"
    )


def test_a_HEALTHY_identity_feed_is_ok():
    """The other direction. The measured healthy gaps are median 73s, p90 212s, p99 2,277s, so a
    feed observed minutes ago is normal and must not be flagged -- a probe that cries wolf gets
    ignored, and an ignored probe is how the stall went unseen."""
    for age in (10, 73, 212, 2_277, 3_599):
        p = _probe("fingerprint_feed", by_fragment={
            "FROM weirvern.host_fingerprints": [(age, 5_000)],
        })
        assert p is not None and p.ok is True, (
            f"an observation {age}s old was flagged; healthy gaps reach {2_277}s at p99: {p.detail!r}"
        )


def test_the_threshold_sits_ABOVE_the_measured_healthy_gaps():
    """The bound is derived from the feed's own gap distribution, not picked.

    My first version used 24 hours, on the reasoning that a quiet segment produces nothing for hours.
    The measurement contradicted that -- p99 is 2,277s, under 40 minutes -- and the consequence was
    concrete: at 20h17m of real staleness the probe still reported `ok`. This asserts the bound is
    above p99 (no false positives on a healthy feed) AND below the measured stall (it actually
    fires), so neither mistake can come back.
    """
    healthy_p99_s = 2_277
    measured_stall_s = 72_837
    just_under = _probe("fingerprint_feed", by_fragment={
        "FROM weirvern.host_fingerprints": [(healthy_p99_s + 60, 100)],
    })
    assert just_under is not None and just_under.ok is True, (
        "a gap just above the measured healthy p99 was flagged as a fault"
    )
    stalled = _probe("fingerprint_feed", by_fragment={
        "FROM weirvern.host_fingerprints": [(measured_stall_s, 100)],
    })
    assert stalled is not None and stalled.ok is False, (
        "the measured 20.2-hour stall does not trip the probe, so it cannot detect what it exists for"
    )
    four_hours = _probe("fingerprint_feed", by_fragment={
        "FROM weirvern.host_fingerprints": [(4 * 3600 + 1, 100)],
    })
    assert four_hours is not None and four_hours.ok is False, (
        "a gap beyond four hours -- an order of magnitude above p99 -- went unflagged"
    )


def test_no_observations_at_all_is_TRI_STATE_not_a_failure():
    """A NetFlow-only deployment has no Zeek sensor and correctly writes nothing.

    Reporting that as a failure would make the probe wrong on every such deployment -- which is
    exactly the mistake `zeek_freshness` made before F081. `ok=None` means "not measurable here":
    neither a pass nor a fault, and the detail says which case it might be.
    """
    p = _probe("fingerprint_feed", by_fragment={
        "FROM weirvern.host_fingerprints": [(0, 0)],
    })
    assert p is not None, "the probe did not run for an empty table"
    assert p.ok is None, (
        f"an empty observation table reported ok={p.ok}. On a NetFlow-only deployment this is "
        f"CORRECT and must not be a failure; the absence is not evidence either way"
    )
    assert "NetFlow-only" in str(p.detail), (
        f"the detail must name the benign case as well as the fault: {p.detail!r}"
    )


# ── A FAILED OR MALFORMED SUB-QUERY MUST NOT TAKE OUT THE REPORT (F047) ──────────────────────
#
# Six probes were wrapped in `if err is None:` with NO else branch, so a sub-query that raised
# removed that probe's row entirely. MEASURED by driving the real `collect_health`:
#
#     tables raising      -> 5 probes, missing ['ingest_freshness', 'alerts_24h', 'fingerprint_feed']
#     detect_loop raising -> 6 probes, missing ['detect_loop']
#
# A consumer cannot tell "this check passed" from "this check never ran", and the cause is attributed
# nowhere because every remaining row reads normally. Two more shapes were found in the same probe:
# a row that is well-formed enough to be returned but too short to unpack, which crashed
# `collect_health` outright, and a probe that fell through EVERY branch and added no row.

_ALL_PROBES = ("clickhouse", "tables", "ingest_freshness", "zeek_freshness", "models",
               "detect_loop", "alerts_24h", "fingerprint_feed")


def _report_with(monkeypatch_fragment=None, by_fragment=None):
    """The full report from a stub, with an optional per-fragment override or injected failure."""
    client = _StubClient(by_fragment or {})
    if monkeypatch_fragment:
        original = client.query

        def exploding(sql, *a, **kw):
            if monkeypatch_fragment in sql:
                raise RuntimeError("simulated sub-query failure")
            return original(sql, *a, **kw)

        client.query = exploding
    return status.collect_health(client, _settings())


def test_a_single_failing_sub_query_does_not_REMOVE_a_probe_row():
    """THE DEFECT. An absent row is indistinguishable from a passing one."""
    report = _report_with(monkeypatch_fragment="FROM weirvern.baseline_history")
    names = [p.name for p in report.probes]

    assert "clickhouse" in names, "the report did not get past connectivity; the test is vacuous"
    assert "detect_loop" in names, (
        f"a failing query removed the detect_loop row entirely: {names}. A consumer cannot tell "
        f"that from a passing check"
    )
    probe = next(p for p in report.probes if p.name == "detect_loop")
    assert probe.ok is False, (
        f"a check that could not run reported ok={probe.ok}. It measured nothing, so it must not "
        f"claim health -- and it is not the tri-state 'not applicable' either"
    )
    assert "could not run" in str(probe.detail), f"the row must say so: {probe.detail!r}"


def test_a_failing_sub_query_still_leaves_EVERY_probe_reported():
    """The whole-report version: no probe may disappear, whichever one breaks."""
    for fragment in ("count() FROM weirvern.flows", "FROM weirvern.baseline_history",
                     "FROM weirvern.ml_models", "FROM weirvern.alert_events"):
        report = _report_with(monkeypatch_fragment=fragment)
        names = [p.name for p in report.probes]
        missing = [n for n in _ALL_PROBES if n not in names]
        assert not missing, (
            f"breaking {fragment!r} removed {missing} from the report. Every probe must report "
            f"something, or the absence is unreadable"
        )


def test_a_too_short_row_is_REPORTED_not_a_crash():
    """A row that is returned but too narrow to unpack crashed `collect_health` outright.

    MEASURED before the fix: `IndexError: list index out of range` from the `alerts_24h` probe's
    `r[0]: r[1]` join, which takes out the ENTIRE health view and blames this probe for a shape
    problem that originated in the query result.
    """
    report = _report_with(by_fragment={"FROM weirvern.alert_events": [["log-only"]]})
    names = [p.name for p in report.probes]
    assert "alerts_24h" in names, f"the short row removed the probe: {names}"
    probe = next(p for p in report.probes if p.name == "alerts_24h")
    assert probe.ok is False, f"a malformed row reported ok={probe.ok}"
    assert "without the (reason, count) pair" in str(probe.detail), (
        f"the row must say what was wrong with the shape: {probe.detail!r}"
    )


def test_records_with_a_NULL_age_still_report_the_probe():
    """The branch that fell through entirely.

    `zeek_conn` returning count>0 with a NULL age matched neither the empty case nor the
    age-present case, so NO row was added. MEASURED before the fix: `zeek_freshness` simply missing.
    """
    report = _report_with(by_fragment={"FROM weirvern.zeek_conn": [[7, None]]})
    names = [p.name for p in report.probes]
    assert "zeek_freshness" in names, (
        f"records with a NULL age removed the probe instead of reporting a check failure: {names}"
    )
    probe = next(p for p in report.probes if p.name == "zeek_freshness")
    assert probe.ok is False, f"an unmeasurable freshness reported ok={probe.ok}"
    assert "cannot be measured" in str(probe.detail), f"say why: {probe.detail!r}"


def test_the_report_is_COMPLETE_when_everything_works():
    """The other direction, so the fix cannot be "always emit a failure row"."""
    report = _report_with()
    names = [p.name for p in report.probes]
    missing = [n for n in _ALL_PROBES if n not in names]
    assert not missing, f"a healthy cluster is missing {missing}"
    for p in report.probes:
        assert "could not run" not in str(p.detail), (
            f"{p.name} reported a check failure on a healthy cluster: {p.detail!r}"
        )


# ── THE HEALTH VIEW WAS BLIND TO THE LOGIN GATE (audit F090) ────────────────────────────────────
#
# Nothing in status.py read `user_store`, `has_users` or `USERS_CONFIGMAP`, so a store that could not
# be read produced NO probe, NO failure, and an overall report that read green -- while every API read
# was served WITHOUT an account. The only signal anywhere was `accounts_note` on /api/session.
#
# The open-read POSTURE is deliberate (`_accounts_on` documents it: a broken store must not lock
# everyone out of the dashboard). What was missing is that the condition is VISIBLE.


class _Store:
    """A user store whose observable state is scripted."""

    def __init__(self, records, exists):
        self._records = records
        self.exists = exists

    def snapshot(self):
        return list(self._records)

    def has_users(self):
        return bool(self._records)


def _account_probe(store):
    """The account_store probe from a real collect_health, with the given store."""
    report = status.collect_health(_StubClient({}), _settings(), user_store=store)
    return next((p for p in report.probes if p.name == "account_store"), None)


def _one_admin():
    from weirvern.admin import users as users_mod

    return users_mod.UserRecord(
        username="admin", role=users_mod.ROLE_ADMIN,
        hash="scrypt$n=16384$r=8$p=1$" + "aa" * 16 + "$" + "bb" * 32,
    )


def test_the_health_report_REPORTS_an_unreadable_account_store():
    """THE DEFECT. An unreadable store leaves the gate OFF; the report must say so."""
    probe = _account_probe(_Store([], exists=None))
    assert probe is not None, (
        "collect_health produced no account_store probe, so the health view cannot tell an operator "
        "that the dashboard is serving reads without an account"
    )
    assert probe.ok is None, (
        f"an unreadable store reported ok={probe.ok!r}. None is right: it is neither a pipeline "
        f"failure nor a pass -- 'measured, and not applicable here'"
    )
    assert "login gate is OFF" in probe.detail, probe.detail


def test_the_health_report_is_RED_when_the_store_exists_but_holds_no_accounts():
    """A different fact from unreadable: the store ANSWERED and it is empty, which should not persist
    after a successful bootstrap."""
    probe = _account_probe(_Store([], exists=True))
    assert probe.ok is False, f"an empty account store reported ok={probe.ok!r}"
    assert "NO accounts" in probe.detail, probe.detail


def test_the_health_report_is_GREEN_when_accounts_exist():
    """The other direction, so the probe cannot be 'always complain'."""
    probe = _account_probe(_Store([_one_admin()], exists=True))
    assert probe.ok is True, f"a store with an account reported ok={probe.ok!r}: {probe.detail}"
    assert "1 account" in probe.detail, probe.detail


def test_the_probe_row_is_PRESENT_even_with_no_store():
    """THE F047 RULE: an absent probe is indistinguishable from a passing one.

    The CLI's status path has no store to hand. It must still produce the row, explaining why it
    cannot answer, rather than dropping it.
    """
    report = status.collect_health(_StubClient({}), _settings())  # no user_store
    names = [p.name for p in report.probes]
    assert "account_store" in names, (
        f"no account_store row when no store was supplied, so its absence is unreadable. "
        f"Probes: {names}"
    )
    probe = next(p for p in report.probes if p.name == "account_store")
    assert probe.ok is None and "not probed" in probe.detail, probe.detail


def test_the_GUI_health_routes_pass_the_store():
    """A probe nothing feeds is the same silence in a new shape.

    THE CALL MOVED into `payloads.health_deep` when the route crossed to Flask, so the scan covers
    BOTH modules: the fetcher must pass `user_store` to `collect_health`, and each surface must pass
    it to the fetcher. Without either half the probe reports "not probed" in the very process that
    HAS a store.

    Checked with `ast` rather than by searching lines: my first version looked for `user_store` on the
    SAME LINE as the call, and a later reformat (for a line-length rule) moved the argument onto its
    own line -- so the test failed on a change that was correct. A source-text assertion that depends
    on formatting is testing the formatter.
    """
    import ast
    import pathlib as _p

    admin = _p.Path(__file__).resolve().parent.parent / "weirvern" / "admin"

    # 1. The fetcher must thread the store into the health collector.
    collector_calls = []
    for name in ("web.py", "payloads.py"):
        tree = ast.parse((admin / name).read_text())
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            fn = node.func
            fname = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", "")
            if fname == "collect_health":
                collector_calls.append((name, node))
    assert collector_calls, "no collect_health call sites found"
    for name, node in collector_calls:
        kws = {k.arg for k in node.keywords}
        assert "user_store" in kws, (
            f"{name} does not pass the account store, so the probe reports 'not probed' in the "
            f"very process that HAS one: {ast.unparse(node)}"
        )

    # 2. The surface must hand it to the shared fetcher. The console's handler was retired with its
    #    HTTP server, so flask_app.py is the only surface left; `_soft_route` takes the fetcher as
    #    its first argument, so both the callee and the first argument are matched.
    for name in ("flask_app.py",):
        tree = ast.parse((admin / name).read_text())
        fetches = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            for target in [node.func, *node.args[:1]]:
                tname = (target.attr if isinstance(target, ast.Attribute)
                         else getattr(target, "id", ""))
                if tname == "health_deep":
                    fetches.append(node)
                    break
        assert fetches, f"{name} does not route /api/health through payloads.health_deep"
        for node in fetches:
            kws = {k.arg for k in node.keywords}
            assert "user_store" in kws, (
                f"{name}'s health route does not pass the account store: {ast.unparse(node)}"
            )

# ── issue #29: the volume evidence is READ, and a failed read is on the record ───────────────


def test_the_volume_evidence_uses_the_REAL_flows_column():
    """Issue #29, measured: the probe queried `weirvern.flows WHERE ts >= ...`, and `flows`
    keys its time on `timestamp` -- so the query threw on every call and the input-volume
    evidence this branch exists to show was never once produced. The stub honours fragments,
    so this test answers only the query that names the real column, and records it."""
    seen = {}

    class _Rec(_StubClient):
        def query(self, sql, *a, **kw):
            # THE FIRST TIME-FILTERED READER WINS. The bare `SELECT count() FROM weirvern.flows`
            # that the key-table probe makes has no WHERE clause (and asks nothing about time), so
            # it cannot stand in for the volume evidence; the feed probe that now also reads this
            # table asks about time_flow_start and runs LAST, so `setdefault` keeps the volume
            # query. Keeping the last would let that later reader satisfy this assertion while
            # testing nothing it exists to pin.
            if "FROM weirvern.flows WHERE" in sql:
                seen.setdefault("sql", sql)
            return super().query(sql, *a, **kw)

    report = status.collect_health(_Rec({"FROM weirvern.flows": [(18430, 12)]}), _settings())
    p = next((x for x in report.probes if x.name == "models"), None)
    assert p is not None
    assert "timestamp >=" in seen.get("sql", ""), f"the query does not use the real column: {seen.get('sql')}"
    assert "18430 flow row(s)" in str(p.detail), p.detail
    assert "12 host(s)" in str(p.detail), p.detail


def test_a_FAILED_volume_read_is_carried_into_the_detail():
    """The swallow, made honest: when the volume query fails, its reason must ride in the
    detail the operator reads -- a probe that cannot read its evidence must not read as one
    with nothing to say."""

    class _BrokenVolume(_StubClient):
        def query(self, sql, *a, **kw):
            if "FROM weirvern.flows" in sql:
                raise RuntimeError("Code: 47. Unknown identifier ts")
            return super().query(sql, *a, **kw)

    report = status.collect_health(_BrokenVolume({}), _settings())
    p = next((x for x in report.probes if x.name == "models"), None)
    assert p is not None
    assert "could not be read" in str(p.detail), p.detail
    assert "Unknown identifier" in str(p.detail), p.detail


# ── the capture probe: is the TAP alive, or merely configured? ───────────────────────────────────
#
# Every other probe infers capture from the rows that arrive, and "no rows" cannot tell a quiet
# network from a dead tap. Measured 2026-11-17: flows stopped at 13:12 and nothing on the box said
# why; the health panel was green because ClickHouse was fine and the tables were fine. The tap
# now publishes its own state to a hostPath, and this probe reads it.


def _tap_state(tmp_path, monkeypatch, **overrides):
    import json
    import time as _time

    path = tmp_path / "tap" / "state.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "ts": _time.time(), "running": True,
        "targets": [{"iface": "eth1", "source": "loch"}],
        "segments_swept": 7, "ring_files": 2, "ring_bytes": 20480, "last_error": "",
    }
    payload.update(overrides)
    path.write_text(json.dumps(payload))
    monkeypatch.setenv("WEIRVERN_TAP_STATE", str(path))
    return path


def test_capture_probe_reports_a_LIVE_tap_with_its_interface_and_counters(tmp_path, monkeypatch):
    _tap_state(tmp_path, monkeypatch)
    p = status._capture_probe(SimpleNamespace(netflow_mode="active"))
    assert p.ok is True, p.detail
    assert "eth1" in p.detail and "7 segment(s)" in p.detail, p.detail


def test_capture_probe_FAILS_when_the_tap_stopped_publishing(tmp_path, monkeypatch):
    """The dead-tap case: the file exists but is older than three publish ticks."""
    import time as _time

    _tap_state(tmp_path, monkeypatch, ts=_time.time() - 600, last_error="")
    p = status._capture_probe(SimpleNamespace(netflow_mode="active"))
    assert p.ok is False, "a tap that has not published for ten minutes was reported healthy"
    assert "dead or wedged" in p.detail, p.detail


def test_capture_probe_FAILS_when_the_tap_is_alive_but_not_capturing(tmp_path, monkeypatch):
    _tap_state(tmp_path, monkeypatch, running=False, last_error="socket: Operation not permitted")
    p = status._capture_probe(SimpleNamespace(netflow_mode="active"))
    assert p.ok is False
    assert "NOT capturing" in p.detail and "Operation not permitted" in p.detail, p.detail


def test_capture_probe_FAILS_when_active_but_no_state_was_EVER_published(tmp_path, monkeypatch):
    monkeypatch.setenv("WEIRVERN_TAP_STATE", str(tmp_path / "never" / "state.json"))
    p = status._capture_probe(SimpleNamespace(netflow_mode="active"))
    assert p.ok is False
    assert "NEVER published" in p.detail, p.detail


def test_capture_probe_is_NOT_APPLICABLE_on_a_box_with_no_tap(tmp_path, monkeypatch):
    """A deployment fed by an external exporter has no tap to be alive; that is not a fault."""
    monkeypatch.setenv("WEIRVERN_TAP_STATE", str(tmp_path / "none" / "state.json"))
    p = status._capture_probe(SimpleNamespace(netflow_mode="passive"))
    assert p.ok is None, "a box with no tap was reported as failing"
    assert "nothing to be alive" in p.detail, p.detail


def test_capture_probe_FAILS_on_a_corrupt_state_file(tmp_path, monkeypatch):
    path = tmp_path / "tap" / "state.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{ not json")
    monkeypatch.setenv("WEIRVERN_TAP_STATE", str(path))
    p = status._capture_probe(SimpleNamespace(netflow_mode="active"))
    assert p.ok is False
    assert "could not be read" in p.detail, p.detail


# ── the feed probe: A LIVE TAP ON A DEAD MIRROR ────────────────────────────────────────────────
#
# MEASURED 2026-11-17, on the live box. The tap had been publishing state every tick for hours,
# `running: true`, 286 segments summarised, ring healthy -- and its capture port was receiving
# 163 packets in 45 seconds of which 0.0% were unicast: mDNS from the gateway and router beacons to
# a multicast group, and nothing else. Flows had fallen from 12.4M an hour to about 300. Every probe
# in this report read green, because "alive" was the question and the tap was very much alive.
#
# The first version of this check asked whether ANY flow had a unicast destination, and the box
# refuted it within the hour: the starving feed still carried 47 unicast flows of 322 (14.6%),
# because a handful of hosts renew DHCP and answer ARP. The verdict therefore comes from the feed's
# own history -- today's aggregate for the hours elapsed against the same hours on prior days -- and
# the unicast share rides along as the explanation.

def _feed(rows=322, unicast=47, host_pairs=0, age=5, *, today_rows=None, today_hosts=11,
          history=None, history_hosts=3717):
    """The two rows the feed probe reads: the last hour of raw flows, and the daily aggregate."""
    import datetime as _d

    today = _d.date.today()
    series = []
    items = list(history or [])
    for i, n in enumerate(items):
        series.append((today - _d.timedelta(days=len(items) - i), n, history_hosts))
    if today_rows is not None:
        series.append((today, today_rows, today_hosts))
    return {"INTERVAL 60 MINUTE": [(rows, unicast, host_pairs, age)],
            "flows_aggregated": series}


def _feed_with_history(today_rows, median_rows, **kw):
    """A seven-day history whose median is `median_rows`, with `today_rows` so far today."""
    return _feed(today_rows=today_rows, history=[median_rows] * 7, **kw)


def test_feed_probe_FAILS_when_the_feed_COLLAPSED_against_its_own_history():
    """The measured outage: 1,389 aggregate rows today against a same-hours median of 10,392,847,
    and 11 hosts against 3,717, while the tap reported running and the rows were fresh."""
    p = _probe("feed", by_fragment=_feed_with_history(1389, 10_392_847,
                                                      today_hosts=11, history_hosts=3717))
    assert p is not None, "the feed probe did not run, so a dead mirror would read healthy again"
    assert p.ok is False, f"a collapsed feed was reported healthy: {p.detail!r}"
    assert p.value["state"] == "collapsed", p.value
    assert "1,389" in p.detail and "10,392,847" in p.detail, p.detail
    assert "mirror" in p.detail.lower(), f"the detail must name what to check: {p.detail!r}"


def test_feed_probe_does_NOT_fail_on_a_LOW_UNICAST_SHARE_alone():
    """The live refutation, pinned: 47 of 322 flows were unicast on the starving feed. A share
    threshold low enough to catch the outage would also fire on a genuinely idle segment, so the
    share must NOT be what decides."""
    p = _probe("feed", by_fragment=_feed_with_history(10_400_000, 10_392_847))
    assert p is not None
    assert p.ok is True, f"a healthy feed was failed on its unicast share: {p.detail!r}"
    assert p.value["state"] == "flowing", p.value
    assert p.value["unicast"] == 47, p.value


def test_feed_probe_PASSES_when_the_feed_matches_its_history():
    p = _probe("feed", by_fragment=_feed_with_history(9_800_000, 10_392_847))
    assert p is not None
    assert p.ok is True, p.detail
    assert p.value["state"] == "flowing", p.value


def test_feed_probe_is_NOT_APPLICABLE_when_thin_and_there_is_NO_history():
    """Five flows in an hour on a young deployment is not evidence about the mirror. Saying
    `False` here would make every small deployment report a fault it does not have."""
    p = _probe("feed", by_fragment=_feed(5, 1, today_rows=None, history=None))
    assert p is not None
    assert p.ok is None, f"a five-row window was judged: ok={p.ok}, {p.detail!r}"
    assert p.value["state"] == "thin", p.value


def test_feed_probe_FAILS_when_NOTHING_arrives():
    p = _probe("feed", by_fragment=_feed(0, 0, today_rows=None, history=None))
    assert p is not None
    assert p.ok is False
    assert p.value["state"] == "no_data", p.value


def test_feed_probe_FAILS_when_the_rows_are_STALE_even_though_they_exist():
    """Rows present, newest an hour old: the ingester stopped. This is the F024 shape (row
    existence read as freshness) in the flow store."""
    p = _probe("feed", by_fragment=_feed_with_history(10_000_000, 10_392_847, age=3600))
    assert p is not None
    assert p.ok is False, f"an hour-old flow was reported as a live feed: {p.detail!r}"
    assert p.value["state"] == "stale", p.value


def test_the_feed_probe_is_present_EVEN_when_it_cannot_read_the_store():
    """A missing row is indistinguishable from a passing one (F047). A store that cannot be read
    must still produce the row, with `ok=None` and the error named."""
    class _Unreadable(_StubClient):
        def query(self, sql, *a, **kw):
            if "INTERVAL 60 MINUTE" in sql:
                raise RuntimeError("Code: 47. Unknown identifier time_flow_start")
            return super().query(sql, *a, **kw)

    report = status.collect_health(_Unreadable({}), _settings())
    p = next((x for x in report.probes if x.name == "feed"), None)
    assert p is not None, "the feed probe vanished when it could not measure, which reads as a pass"
    assert p.ok is None, p.ok
    assert "Unknown identifier" in p.detail, p.detail


def test_the_feed_probe_survives_a_missing_aggregate_table():
    """`flows_aggregated` may not exist on a young deployment. Losing the baseline must not lose
    the probe: it must still report what the raw feed carries."""
    class _NoAggregate(_StubClient):
        def query(self, sql, *a, **kw):
            if "flows_aggregated" in sql:
                raise RuntimeError("Code: 60. Table weirvern.flows_aggregated doesn't exist")
            return super().query(sql, *a, **kw)

    report = status.collect_health(
        _NoAggregate({"INTERVAL 60 MINUTE": [(30_000, 29_500, 1_200, 3)]}), _settings())
    p = next((x for x in report.probes if x.name == "feed"), None)
    assert p is not None
    assert p.ok is True, f"a live feed was failed because its baseline table was missing: {p.detail!r}"
    assert p.value["baseline_rows"] is None, p.value


