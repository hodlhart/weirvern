"""The evidence page's source states are words, not zeros.

`classify_source` is the single place a missing, stale, future-dated or fresh source becomes a
state. These pins keep an absent source from rendering as a clean one.
"""
from __future__ import annotations

from weirvern.admin import status


def test_no_rows_is_not_measured_not_fresh():
    got = status.classify_source(0, None)
    assert got["state"] == "not measured"
    assert "no records" in got["reason"]


def test_an_unreadable_source_is_unknown_not_zero():
    assert status.classify_source(None, None)["state"] == "unknown"


def test_a_future_timestamp_is_a_clock_failure_not_freshness():
    got = status.classify_source(10, -600)
    assert got["state"] == "failed"
    assert "future" in got["reason"]


def test_a_stale_source_names_its_age_and_state():
    got = status.classify_source(10, 1200)
    assert got["state"] == "stale" and got["age_s"] == 1200


def test_a_fresh_source_is_fresh():
    assert status.classify_source(10, 12)["state"] == "fresh"
