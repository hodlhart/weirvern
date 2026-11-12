"""Every collected source must be able to contribute evidence, and a broken one must not stop the rest."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

from weirvern.models import generic_channels as channels


def _windows(*, host: str, count: int, n: float, u: float, start: datetime):
    return [(host, start + timedelta(minutes=5 * i), n, u) for i in range(count)]


class FakeClient:
    """Answers by table name; a table in `broken` raises, as a real outage would."""

    def __init__(self, rows: dict[str, list[tuple]], broken: set[str] | None = None):
        self.rows = rows
        self.broken = broken or set()

    def query(self, sql: str, parameters=None):
        for table, rows in self.rows.items():
            if table in sql:
                if table in self.broken:
                    raise RuntimeError(f"{table} unavailable")
                return SimpleNamespace(result_rows=list(rows))
        if any(table in sql for table in self.broken):
            raise RuntimeError("brokén")
        return SimpleNamespace(result_rows=[])


START = datetime(2026, 11, 12, 0, 0, tzinfo=UTC)
NOW = START + timedelta(minutes=5 * 40)


def test_a_source_whose_window_is_far_above_normal_becomes_evidence():
    host = "198.51.100.10"
    rows = _windows(host=host, count=30, n=5, u=2, start=START)
    rows.append((host, NOW, 80, 2))                       # a jump at the current window
    client = FakeClient({"weirvern.zeek_http": rows})

    found = channels.evidence(client, [host], now=NOW)
    http = [e for e in found.get(host, []) if e.channel == "http"]
    assert http, "a 16x volume window must produce evidence"
    assert http[0].score >= 10
    assert http[0].pvalue <= 0.05
    assert http[0].family == "http" and http[0].scale == "5m"
    assert http[0].present is True


def test_a_normal_window_is_not_evidence_of_anything():
    host = "198.51.100.11"
    rows = _windows(host=host, count=30, n=5, u=2, start=START)
    rows.append((host, NOW, 5, 2))
    client = FakeClient({"weirvern.zeek_http": rows})

    found = [e for e in channels.evidence(client, [host], now=NOW).get(host, [])
             if e.channel == "http"]
    assert found and found[0].pvalue > 0.5


def test_a_host_without_enough_history_gets_no_evidence_rather_than_a_guess():
    host = "198.51.100.12"
    rows = _windows(host=host, count=3, n=5, u=2, start=START)
    rows.append((host, NOW, 80, 2))
    client = FakeClient({"weirvern.zeek_http": rows})

    assert channels.evidence(client, [host], now=NOW) == {}


def test_hosts_outside_the_monitored_set_are_ignored():
    inside, outside = "198.51.100.13", "198.51.100.99"
    rows = (_windows(host=inside, count=30, n=5, u=2, start=START)
            + [(inside, NOW, 80, 2)]
            + _windows(host=outside, count=30, n=5, u=2, start=START)
            + [(outside, NOW, 80, 2)])
    client = FakeClient({"weirvern.zeek_http": rows})

    found = channels.evidence(client, [inside], now=NOW)
    assert set(found) == {inside}
    assert {e.channel for e in found[inside]} == {"http"}


def test_one_broken_source_does_not_silence_the_others():
    host = "198.51.100.14"
    rows = _windows(host=host, count=30, n=5, u=2, start=START) + [(host, NOW, 80, 2)]
    client = FakeClient({"weirvern.zeek_http": rows, "weirvern.zeek_ssh": rows},
                        broken={"weirvern.zeek_ssh"})

    found = channels.evidence(client, [host], now=NOW)
    assert {e.channel for e in found[host]} == {"http"}


def test_the_score_is_a_ratio_not_an_arbitrary_number():
    assert channels.score_window(5, 2, median_n=5, median_u=2) == 1.0
    assert channels.score_window(50, 2, median_n=5, median_u=2) == 10.0
    # A quiet window with many distinct values is what a tunnel looks like: diversity must count.
    assert channels.score_window(1, 20, median_n=5, median_u=2) > 5
