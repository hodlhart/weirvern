"""Phase 1 ripples: measure a host against its own history, then group the evidence honestly.

No ClickHouse. The fake below ANSWERS THE SQL THE MODULE ACTUALLY BUILDS: it reads the anchor
and bucket size out of the query, buckets synthetic events the same way, and returns the
`(host, k, n, u, b)` shape. That means these tests fail if the SQL stops selecting the columns
the module reads, which a hand-written row fixture would not catch.
"""
from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

from weirvern.admin import payloads
from weirvern.models import ripple_evidence
from weirvern.models.ripple import empirical_pvalue_two_sided, group_evidence

NOW = datetime(2026, 11, 19, 14, 0, tzinfo=UTC)
HOST = "198.51.100.10"
HOURS = 168

_ANCHOR = re.compile(r"intDiv\((\d+) - toUnixTimestamp")
_BUCKET = re.compile(r", (\d+)\) AS k")


class FakeClient:
    """A tiny event store that executes the module's SQL shape, not a fixed row list."""

    def __init__(self, events: dict[str, list[tuple[str, datetime, str]]] | None = None,
                 *, fail: bool = False):
        self.events = events or {}
        self.fail = fail
        self.queries: list[str] = []

    def query(self, sql: str, parameters=None):
        self.queries.append(sql)
        if self.fail:
            raise ConnectionError("clickhouse is not reachable")
        table = next((name for name in self.events if name in sql), None)
        if table is None:
            return SimpleNamespace(result_rows=[])
        anchor_match = _ANCHOR.search(sql)
        bucket_match = _BUCKET.search(sql)
        if anchor_match is None or bucket_match is None:
            return SimpleNamespace(result_rows=[])
        anchor = int(anchor_match.group(1))
        bucket_s = int(bucket_match.group(1))
        distinct = "uniqExact" in sql
        buckets: dict[tuple[str, int], tuple[int, set[str]]] = {}
        for host, when, value in self.events[table]:
            index = (anchor - int(when.timestamp())) // bucket_s
            if index < 0:
                continue
            n, seen = buckets.get((host, index), (0, set()))
            buckets[(host, index)] = (n + 1, seen | {value} if distinct else seen)
        rows = []
        for (host, index), (n, seen) in sorted(buckets.items()):
            rows.append((host, index, n, len(seen) if distinct else 0, 0.0))
        return SimpleNamespace(result_rows=rows)


def _series(table: str, *, counts: dict[int, int] | None = None, host: str = HOST,
            values: int = 4, base: int = 6) -> list[tuple[str, datetime, str]]:
    """One event per unit of volume, half an hour inside each hourly bucket."""
    counts = counts or {}
    events = []
    for index in range(HOURS):
        when = NOW - timedelta(hours=index, minutes=30)
        for slot in range(counts.get(index, base)):
            events.append((host, when + timedelta(seconds=slot), f"{table}-{slot % values}"))
    return events


def _ripples(events: dict[str, list[tuple[str, datetime, str]]]) -> list:
    items = ripple_evidence.compute(FakeClient(events), now=NOW)
    return group_evidence(items)


def test_a_steady_channel_raises_no_significant_evidence_and_no_ripple():
    events = {"weirvern.zeek_dns": _series("dns", base=6)}
    items = ripple_evidence.compute(FakeClient(events), now=NOW)

    dns = [item for item in items if item.channel == "dns_volume"]
    assert dns, "a host with a week of history must be measured, not skipped"
    assert all(item.pvalue > 0.5 for item in dns), \
        [(item.scale, item.value, item.baseline_median, item.pvalue) for item in dns]
    assert [item for item in items if item.pvalue <= 0.05] == []
    assert group_evidence(items) == []


def test_a_step_change_in_one_channel_produces_evidence_with_a_small_p_value():
    events = {"weirvern.zeek_dns": _series("dns", counts={0: 60})}
    items = ripple_evidence.compute(FakeClient(events), now=NOW)

    hourly = [item for item in items if item.channel == "dns_volume" and item.scale == "1h"]
    assert len(hourly) == 1
    item = hourly[0]
    assert item.pvalue <= 0.01
    assert item.value == 60
    assert item.baseline_median == 6
    assert item.direction == "rose"
    assert item.sample_count >= 100
    assert item.coverage > 0.9


def test_a_channel_with_insufficient_history_produces_no_evidence_at_all():
    short = _series("dns")[: 3 * 6]          # three hours, then nothing
    events = {"weirvern.zeek_dns": short}
    assert ripple_evidence.compute(FakeClient(events), now=NOW) == []


def test_two_significant_channels_in_one_window_form_one_ripple_naming_both():
    events = {
        "weirvern.zeek_dns": _series("dns", counts={0: 60}),
        "weirvern.zeek_conn": _series("conn", counts={0: 60}),
    }
    ripples = _ripples(events)

    assert len(ripples) == 1, [(r.host, r.window_start, r.channels) for r in ripples]
    ripple = ripples[0]
    assert ripple.channels == ("conn_volume", "dns_volume")
    assert "conn_volume" in ripple.explanation and "dns_volume" in ripple.explanation
    assert {item.channel for item in ripple.evidence} == {"conn_volume", "dns_volume"}
    assert ripple.window_start == datetime(2026, 11, 19, 14, 0, tzinfo=UTC)


def test_significant_channels_in_different_windows_do_not_form_one_ripple():
    # Each channel moves in its own hour and only mildly: two baseline hours are at least as
    # high, so p is significant (> 0.01) but not extreme. One such channel cannot ripple, and
    # the two never share a window.
    dns_events = {"weirvern.zeek_dns": _series("dns", counts={0: 30, 10: 30, 11: 30})}
    conn_events = {"weirvern.zeek_conn": _series("conn", counts={0: 30, 10: 30, 11: 30})}
    later = ripple_evidence.compute(FakeClient(dns_events), now=NOW)
    earlier = ripple_evidence.compute(FakeClient(conn_events), now=NOW - timedelta(hours=2))

    significant = [item for item in later + earlier if item.pvalue <= 0.05]
    assert significant, "the fixture must actually produce significant evidence"
    assert all(item.pvalue > 0.01 for item in significant), \
        [(item.channel, item.scale, item.pvalue) for item in significant]
    assert group_evidence(later + earlier) == []


def test_a_single_extreme_channel_can_form_a_ripple_on_its_own():
    events = {"weirvern.zeek_dns": _series("dns", counts={0: 60})}
    ripples = _ripples(events)

    assert len(ripples) == 1
    assert ripples[0].channels == ("dns_volume",)
    assert ripples[0].score > 1.0
    assert ripples[0].combined_p <= 0.05


def test_one_channel_at_several_scales_is_still_one_channel():
    """A channel measured at 1h and 6h must not corroborate itself into a ripple."""
    # Four mildly elevated hours make the 1h view significant (4 of 168 baselines are at least
    # as high, so p = 0.030, above the extreme bar) and the 6h view significant (p = 0.036).
    events = {"weirvern.zeek_dns": _series("dns", counts={0: 10, 1: 10, 2: 10, 3: 10, 10: 10})}
    items = ripple_evidence.compute(FakeClient(events), now=NOW)

    scales = {item.scale for item in items
              if item.channel == "dns_volume" and item.pvalue <= 0.05}
    assert scales == {"1h", "6h"}, \
        [(item.scale, item.value, item.baseline_median, item.pvalue)
         for item in items if item.channel == "dns_volume"]
    assert group_evidence(items) == []


def test_the_explanation_names_the_channels_and_never_a_number_without_its_baseline():
    events = {
        "weirvern.zeek_dns": _series("dns", counts={0: 60}),
        "weirvern.zeek_conn": _series("conn", counts={0: 60}),
    }
    ripple = _ripples(events)[0]

    for channel in ripple.channels:
        assert re.search(rf"{channel} [\d.,]+ vs median [\d.,]+ \(p=", ripple.explanation), \
            ripple.explanation
    assert ripple.explanation.count("vs median") == len(ripple.channels)
    assert "198.51.100.10" in ripple.explanation


def test_the_api_returns_an_empty_list_and_a_reason_when_the_read_fails():
    out = payloads.ripples(FakeClient(fail=True), hours=24)

    assert out["available"] is False
    assert out["ripples"] == []
    assert out["count"] == 0
    assert out["reason"], "a failed read must name what happened"


def test_an_empty_window_is_available_not_a_failure():
    out = payloads.ripples(FakeClient({}), hours=24)

    assert out["available"] is True
    assert out["ripples"] == []
    assert out["count"] == 0
    assert out["reason"] == ""


def test_no_channel_claims_a_scale_the_lookback_cannot_support():
    for row in ripple_evidence.inventory():
        assert "7d" not in row["scales"], row
        assert row["scales"] == ["1h", "6h", "24h"], row


def test_a_two_sided_p_value_sees_a_fall_as_clearly_as_a_rise():
    assert 0.0 < empirical_pvalue_two_sided(0.0, [10.0] * 20) <= 0.05
    assert 0.0 < empirical_pvalue_two_sided(99.0, [10.0] * 20) <= 0.05
    assert empirical_pvalue_two_sided(10.0, [10.0] * 20) == 1.0


def test_the_read_path_returns_ripples_with_their_evidence():
    """The API is evidence -> grouping, not a stored verdict, so this proves the join."""
    window = datetime(2026, 11, 19, 14, 0)
    rows = [
        (window, window + timedelta(hours=1), HOST, "dns_volume", "dns", "1h", 60.0, 6.0,
         0.006, 167, 1.0, "rose", datetime(2026, 11, 19, 14, 37)),
        (window, window + timedelta(hours=1), HOST, "conn_volume", "conn", "1h", 41.0, 5.0,
         0.012, 167, 1.0, "rose", datetime(2026, 11, 19, 14, 37)),
    ]
    client = SimpleNamespace(
        query=lambda sql, parameters=None: SimpleNamespace(result_rows=rows))

    out = ripple_evidence.overview(client, hours=24, now=NOW)

    assert out["available"] is True
    assert out["count"] == 1
    ripple = out["ripples"][0]
    assert ripple["channels"] == ["conn_volume", "dns_volume"]
    assert len(ripple["evidence"]) == 2
    assert ripple["evidence"][0]["baseline_median"] in (6.0, 5.0)
    assert "vs median" in ripple["explanation"]


def test_evidence_for_a_steady_channel_is_still_storable():
    """Storing p~1 is the point: the operator sees what was measured, not only alarms."""
    items = ripple_evidence.compute(FakeClient({"weirvern.zeek_dns": _series("dns")}), now=NOW)
    row = next(item for item in items if item.channel == "dns_volume" and item.scale == "1h")
    assert row.host == HOST
    assert row.as_dict()["baseline_median"] == 6.0
    assert row.as_dict()["p_value"] == 1.0
    assert row.as_dict()["sample_count"] == 167
