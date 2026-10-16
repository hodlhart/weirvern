"""The DNS-hit pass: alert-first recording must survive the clock types it actually meets.

MEASURED LIVE (2026-10-16): the pass scheduled every 60s and wrote NOTHING, because
ClickHouse hands back tz-AWARE datetimes for DateTime columns while the cursor is naive local
-- `ts > newest` raised "can't compare offset-naive and offset-aware datetimes", the outer
guard swallowed it as a warning, and a matching query that arrived during a live test was
missed by seconds. The pass now normalizes to the naive local wall clock (the DB's own
convention); these tests pin that, and that a hit becomes an event.
"""

from datetime import datetime, timedelta, timezone

import pytest

import weirvern.worker as worker
from weirvern import sluice_store
from weirvern.sluice import Rule


class _Settings:
    sluice_interval_s = 15


class _Result:
    def __init__(self, rows):
        self.result_rows = rows


class _Client:
    def __init__(self, rows):
        self.rows = rows
        self.sql = []

    def query(self, sql, parameters=None, **_kw):
        self.sql.append(sql)
        return _Result(self.rows)


@pytest.fixture
def wired(monkeypatch):
    captured: list[dict] = []
    rule = Rule("r1", domain="ads.example.com", mode="alert")
    monkeypatch.setattr(sluice_store, "load_live_rules", lambda client: [rule])
    monkeypatch.setattr(sluice_store, "write_events",
                        lambda client, events, now=None: captured.extend(events) or len(events))
    monkeypatch.setattr(worker, "_SLUICE_DNS",
                        {"cursor": datetime(2026, 10, 16, 8, 0, 0), "last": 0.0})
    return captured


def test_an_aware_timestamp_does_not_kill_the_pass(wired):
    aware = datetime(2026, 10, 16, 8, 55, 44, tzinfo=timezone(timedelta(hours=-5)))
    client = _Client([(aware, "203.0.113.20", "ads.example.com")])
    worker._sluice_dns_maybe(_Settings(), client)   # must not raise
    assert len(wired) == 1, "the hit was not recorded"
    assert wired[0]["kind"] == "dns" and wired[0]["domain"] == "ads.example.com"
    assert wired[0]["query"] == "ads.example.com"


def test_a_subdomain_hits_and_the_cursor_advances_in_wall_clock(wired):
    aware = datetime(2026, 10, 16, 8, 55, 44, tzinfo=timezone(timedelta(hours=-5)))
    client = _Client([(aware, "203.0.113.20", "tracker.ads.example.com")])
    worker._sluice_dns_maybe(_Settings(), client)
    assert len(wired) == 1, "a subdomain of a listed name must hit"
    assert worker._SLUICE_DNS["cursor"] == datetime(2026, 10, 16, 8, 55, 44), (
        "the cursor must advance as NAIVE wall clock, matching the stored values")


def test_a_name_that_does_not_match_writes_nothing(wired):
    aware = datetime(2026, 10, 16, 8, 55, 44, tzinfo=timezone(timedelta(hours=-5)))
    worker._sluice_dns_maybe(_Settings(), _Client([(aware, "203.0.113.20", "example.net")]))
    assert wired == []


def test_a_wildcard_marker_matches_like_its_base(monkeypatch):
    """`*.name` is stored as typed (the operator, 2026-10-16: "modify it like adding a *"); the
    matcher strips the marker because a name already covers its subdomains."""
    captured: list[dict] = []
    rule = Rule("r2", domain="*.ads.example.com", mode="alert")
    monkeypatch.setattr(sluice_store, "load_live_rules", lambda client: [rule])
    monkeypatch.setattr(sluice_store, "write_events",
                        lambda client, events, now=None: captured.extend(events) or len(events))
    monkeypatch.setattr(worker, "_SLUICE_DNS",
                        {"cursor": datetime(2026, 10, 16, 8, 0, 0), "last": 0.0})
    aware = datetime(2026, 10, 16, 8, 55, 44, tzinfo=timezone(timedelta(hours=-5)))
    worker._sluice_dns_maybe(_Settings(),
                             _Client([(aware, "203.0.113.20", "tracker.ads.example.com")]))
    assert len(captured) == 1 and captured[0]["rule_id"] == "r2"
