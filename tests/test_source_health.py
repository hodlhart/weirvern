"""The source gate must fail closed.

These pin the distinction the card exists for: zero rows is not "no traffic", an unreadable
source is not zero, and a future timestamp is a clock fault rather than a fresh source.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("source_health", ROOT / "scripts" / "source_health.py")
assert SPEC and SPEC.loader
source_health = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = source_health
SPEC.loader.exec_module(source_health)


def test_fresh_source_is_ok():
    r = source_health.classify("flows", 10, "2026-01-01 00:00:00", 30, 900, 120, True)
    assert r.ok and r.status == "ok"


def test_empty_source_is_not_ok_and_says_empty():
    r = source_health.classify("flows", 0, None, None, 900, 120, True)
    assert not r.ok and r.status == "empty" and "no rows" in r.reason


def test_unreadable_source_is_unknown_not_zero():
    r = source_health.classify("flows", None, None, None, 900, 120, True)
    assert not r.ok and r.status == "unknown"
    assert r.rows is None


def test_stale_source_fails_and_names_the_bound():
    r = source_health.classify("flows", 10, "2026-01-01 00:00:00", 901, 900, 120, True)
    assert not r.ok and r.status == "stale" and "901" in r.reason


def test_future_timestamp_is_a_clock_fault_not_freshness():
    r = source_health.classify("flows", 10, "2026-01-01 00:00:00", -121, 900, 120, True)
    assert not r.ok and r.status == "clock_skew" and "future" in r.reason


def test_the_allowance_is_configurable():
    r = source_health.classify("flows", 10, "2026-01-01 00:00:00", 30, 10, 120, True)
    assert r.status == "stale"
    r2 = source_health.classify("flows", 10, "2026-01-01 00:00:00", 30, 60, 120, True)
    assert r2.status == "ok"


def test_a_failed_required_source_fails_the_payload():
    readings = [
        source_health.classify("flows", None, None, None, 900, 120, True),
        source_health.classify("zeek_conn", None, None, None, 900, 120, False),
    ]
    payload = source_health.as_payload(readings)
    assert payload["ok"] is False
    assert payload["required_failures"] == ["flows"]


def test_an_optional_source_does_not_fail_the_payload():
    readings = [
        source_health.classify("flows", 1, "2026-01-01 00:00:00", 10, 900, 120, True),
        source_health.classify("zeek_conn", 0, None, None, 900, 120, False),
    ]
    payload = source_health.as_payload(readings)
    assert payload["ok"] is True
