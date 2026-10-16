"""The global time window: relative hours, or an absolute range (the Kibana-style filter).

The operator's ask, verbatim: "a better time search like kibana uses throughout the project".
Kibana's time filter applies to EVERY panel; these tests pin the two properties that make that
possible here -- an absolute range is honoured EXACTLY (not rounded into "last N hours"), and a
window cannot leak from one request to the next on a reused thread.
"""

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from weirvern.admin import timewindow


def test_relative_means_the_last_n_hours():
    since, until = None, None
    params = timewindow.w(6)
    since, until = params["since"], params["until"]
    assert timedelta(hours=5, minutes=59) < (until - since) <= timedelta(hours=6)


def test_an_absolute_window_wins_over_hours_exactly():
    a = datetime(2026, 10, 5, 22, 13, tzinfo=UTC)
    b = a + timedelta(minutes=47, seconds=30)
    timewindow.set_window(a, b)
    try:
        params = timewindow.w(24)
        assert params["since"] == a and params["until"] == b, (
            "an absolute range must not be rounded to whole hours: the operator picked 22:13"
        )
    finally:
        timewindow.clear_window()


def test_the_window_must_be_cleared_or_the_next_request_inherits_it():
    """One thread serves many requests. A leftover window would answer the next request against
    the wrong stretch of time -- the exact bug class this module exists to end."""
    timewindow.set_window(datetime(2020, 1, 1, tzinfo=UTC), datetime(2020, 1, 2, tzinfo=UTC))
    timewindow.clear_window()
    params = timewindow.w(3)
    assert params["until"] - params["since"] <= timedelta(hours=3, seconds=1)


def test_parse_moment_accepts_what_the_console_and_a_url_produce():
    for text in ("2026-10-16", "2026-10-16 05:00", "2026-10-16T05:00:00", "2026-10-16T05:00:00Z"):
        got = timewindow.parse_moment(text)
        assert got.tzinfo is not None
    assert timewindow.parse_moment("2026-10-16 05:00").hour == 5


def test_a_bad_time_is_a_sentence_not_a_silent_fallback():
    with pytest.raises(ValueError, match="does not look like a time"):
        timewindow.parse_moment("yesterday-ish")


def test_the_range_must_run_forwards():
    with pytest.raises(ValueError, match="start must be before the end"):
        timewindow.parse_range("2026-10-16 06:00", "2026-10-16 05:00")


def test_the_span_is_capped_at_fourteen_days():
    with pytest.raises(ValueError, match="longer than"):
        timewindow.parse_range("2026-09-01 00:00", "2026-10-16 00:00")


def test_an_old_window_stays_exactly_that_window():
    """The clamp is on the SPAN, not on the endpoints: last week's incident is still reachable."""
    since, until = timewindow.parse_range("2026-10-05 22:00", "2026-10-05 23:00")
    assert until - since == timedelta(hours=1)
    assert since.day == 5


def test_the_console_can_ask_for_an_end_without_a_start_only_by_error():
    with pytest.raises(ValueError, match="needs a start"):
        timewindow.parse_range(None, "2026-10-16 05:00")


def test_the_windowed_queries_carry_BOTH_bounds_and_their_params():
    """Source-level, and honestly labelled as such: every windowed read must name an upper bound
    and a params dict that supplies `since`/`until`. Missing either would be a runtime failure
    the first time the query ran -- better a failing test now."""
    root = Path(timewindow.__file__).resolve().parents[2]
    for name in ("soc", "status", "assets"):
        src = (root / "weirvern" / "admin" / f"{name}.py").read_text()
        assert "%(since)s" in src or "top_ports" in name, name
        assert src.count("%(since)s") == src.count("%(until)s"), (
            f"{name}.py: {src.count('%(since)s')} since vs {src.count('%(until)s')} until -- "
            "one comparison lost its upper bound"
        )
        assert "INTERVAL %(h)s HOUR" not in src, f"{name}.py still asks for 'the last N hours'"
        assert "**timewindow.w(hours)" in src


def test_a_real_builder_carries_the_window_into_its_params():
    """Through the code path, not the source: a fake client records what the query was given."""
    captured = {}

    class _Client:
        def query(self, sql, parameters=None, **_kw):
            captured["sql"], captured["params"] = sql, parameters

            class R:
                result_rows = []

            return R()

    from weirvern.admin import status

    a = datetime(2026, 10, 6, 1, 2, tzinfo=UTC)
    b = a + timedelta(hours=2)
    timewindow.set_window(a, b)
    try:
        status.top_talkers(_Client(), hours=6)
    finally:
        timewindow.clear_window()
    assert captured["params"]["since"] == a and captured["params"]["until"] == b
