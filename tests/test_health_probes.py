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

def _loop_probe(base, near, **settings_kw):
    """The `detect_loop` probe for a given pair of (count, age) readings.

    `base`/`near` are tuples shaped like the probe's SQL result: (count, age_seconds), or None for
    "the query returned nothing at all".
    """
    by_fragment = {
        "FROM weirvern.baseline_history": [base] if base is not None else [],
        "FROM weirvern.near_misses": [near] if near is not None else [],
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
    assert "stopped" in str(p.detail).lower()


def test_EITHER_signal_being_fresh_is_enough():
    """A single signal going quiet for a BENIGN reason must not read as a stopped loop --
    nothing may score in a window, or the baseline may lack samples. The loop ran if either ran."""
    assert _loop_probe((216, 99999), (1, 30)).ok is True
    assert _loop_probe((1, 30), (329, 99999)).ok is True


def test_BOTH_signals_stale_is_not_ok():
    """The converse, so the either/or above cannot be satisfied by weakening this."""
    assert _loop_probe((216, 99999), (329, 99999)).ok is False


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
    assert "baseline" in str(p.detail) and "scores" in str(p.detail), f"{p.detail!r}"


def test_a_broken_query_does_not_produce_a_false_verdict():
    """If the query itself fails the probe must stay silent, not guess. `_timed` returns the
    error, and the `if err is None` guard is what prevents a database problem being reported as a
    stopped detection loop.

    THE FAILURE IS SCOPED TO THIS PROBE'S OWN TABLES, and that detail is the whole test. An
    earlier version made EVERY query raise -- which aborts `collect_health` at the `clickhouse`
    connectivity probe, so execution never reached `detect_loop` and the test passed vacuously
    whether the guard was there or not. A mutation that removed the guard was NOT caught. Making
    only `baseline_history`/`near_misses` fail lets the report get far enough to try.
    """
    class _SelectivelyExploding(_StubClient):
        def query(self, sql, *a, **kw):
            if "baseline_history" in sql or "near_misses" in sql:
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
    assert "detect_loop" not in names, "a failed query must not emit a detect_loop verdict"
