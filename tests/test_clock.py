"""One clock: aware UTC everywhere, under any host timezone (HD-28).

WHENCE: GitHub #28. The worker mixed naive `datetime.now()` (local wall clock) with
ClickHouse's aware UTC values, so under TZ=America/Chicago the sweep window was five hours
off and ages could go negative -- and a negative age is never "stale", so a dead sensor read
as running. The convention is in weirvern/clock.py: computed/stored times are aware UTC;
only presentation converts, and a LEGACY naive value means local time (clock.as_aware).

These tests both drive the clock under a non-UTC zone and forbid the pattern from returning.
"""

import ast
import time
from datetime import timedelta
from pathlib import Path

import pytest

from weirvern.clock import age_seconds, from_epoch, utcnow
from weirvern.host_identity import stale_before

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "weirvern"


@pytest.fixture()
def chicago(monkeypatch):
    monkeypatch.setenv("TZ", "America/Chicago")
    time.tzset()
    try:
        yield
    finally:
        monkeypatch.delenv("TZ", raising=False)
        time.tzset()


def _naive_clock_calls() -> list[str]:
    """Every `now()` / `fromtimestamp(x)` call that produces a naive datetime."""
    hits: list[str] = []
    for path in sorted(PACKAGE.rglob("*.py")):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                continue
            attr = node.func.attr
            if attr not in ("now", "utcnow", "fromtimestamp"):
                continue
            if attr in ("now", "utcnow") and node.args:
                continue                      # now(tz) is aware and allowed
            if attr == "fromtimestamp" and (len(node.args) > 1
                                            or any(k.arg == "tz" for k in node.keywords)):
                continue
            hits.append(f"{path.relative_to(ROOT)}:{node.lineno}: {attr}")
    return hits


def test_no_naive_clock_call_survives_in_the_package():
    """MUTATION CHECK: revert any site to datetime.now() and this fails."""
    offenders = [h for h in _naive_clock_calls() if not h.startswith("weirvern/clock.py")]
    assert not offenders, (
        "naive clock calls (use weirvern.clock.utcnow / from_epoch): " + ", ".join(offenders))


def test_the_clock_is_utc_under_a_non_utc_host_zone(chicago):
    now = utcnow()
    assert now.utcoffset() == timedelta(0), f"utcnow() drifted to {now.utcoffset()}"
    assert now.tzinfo is not None


def test_an_epoch_is_utc_not_local(chicago):
    assert from_epoch(0).isoformat() == "1970-01-01T00:00:00+00:00"


def test_ages_never_go_negative_under_a_non_utc_zone(chicago):
    one_hour_ago = utcnow() - timedelta(hours=1)
    assert 3_500 < age_seconds(one_hour_ago) < 3_700
    # The live failure: a heartbeat 29 seconds old computed as -17998s.
    assert 25 < age_seconds(utcnow() - timedelta(seconds=29)) < 35


def test_a_legacy_naive_value_is_read_as_local_not_utc(chicago):
    # Exactly what the old code wrote: local wall clock, no zone.
    legacy = (utcnow() - timedelta(hours=1)).astimezone().replace(tzinfo=None)
    assert 3_500 < age_seconds(legacy) < 3_700, (
        "a legacy naive value was relabelled UTC, shifting every age by the offset")


def test_stale_before_is_utc_and_days_are_days(chicago):
    cutoff = stale_before(2)
    assert cutoff.utcoffset() == timedelta(0)
    assert (utcnow() - cutoff).days == 2


def test_the_worker_process_marker_is_aware(chicago):
    # _PROCESS_STARTED is written at import; importing here (after TZ) proves the value is
    # aware and in UTC rather than a local wall clock reading.
    import weirvern.worker as worker

    assert worker._PROCESS_STARTED.tzinfo is not None
    assert worker._PROCESS_STARTED.utcoffset() == timedelta(0)


def test_the_stored_flow_timestamp_is_utc(chicago):
    from weirvern.ingester import _ts, map_flow

    assert _ts(0).utcoffset() == timedelta(0)
    assert map_flow({})["timestamp"].utcoffset() == timedelta(0)
