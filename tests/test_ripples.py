"""Phase 1 ripples: attribute the subject, collapse families, and respect the p-value floor.

No ClickHouse. The fake below ANSWERS THE SQL THE MODULE ACTUALLY BUILDS: it reads the anchor,
bucket size and monitored CIDRs out of the query, attributes each event to its monitored
endpoint exactly as the SQL does, and returns the `(host, k, n, u, b)` shape. That means these
tests fail if the SQL stops selecting the columns or the predicate the module relies on, which
a hand-written row fixture would not catch.
"""
from __future__ import annotations

import ipaddress
import math
import re
import statistics
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

from weirvern.admin import payloads
from weirvern.models import ripple_evidence, ripple_tail
from weirvern.models.generic_channels import ChannelSpec
from weirvern.models.ripple import (
    CHANNEL_FAMILIES,
    ChannelEvidence,
    empirical_pvalue_two_sided,
    group_evidence,
    pvalue_floor,
    severity_band,
    severity_bands,
)

NOW = datetime(2026, 11, 19, 14, 0, tzinfo=UTC)
WINDOW = datetime(2026, 11, 19, 14, 0, tzinfo=UTC)
HOST = "198.51.100.10"
EXTERNAL = "203.0.113.9"
OTHER_EXTERNAL = "203.0.113.77"
NET = ipaddress.ip_network("198.51.100.0/24")
NETS = [NET]
HOURS = 168

_ANCHOR = re.compile(r"intDiv\((\d+) - toUnixTimestamp")
_BUCKET = re.compile(r", (\d+)\) AS k")
_SINCE = re.compile(r">= '([^']+)'")
_UNTIL = re.compile(r"< '([^']+)'")
_SCOPE = re.compile(r"isIPAddressInRange\([^,]+,\s*'([^']+)'\)")


def _parse(text: str) -> datetime:
    return datetime.strptime(text, "%Y-%m-%d %H:%M:%S").replace(tzinfo=UTC)


def _in_scope(addr: str, nets: list[ipaddress.IPv4Network | ipaddress.IPv6Network]) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return any(ip in net for net in nets if net.version == ip.version)


class FakeClient:
    """A tiny event store that executes the module's SQL shape, not a fixed row list.

    An event is `(src, dst, when, value, bytes)`. `value` feeds a diversity channel; `bytes`
    feeds a sum channel. The fake decides the SUBJECT the way the SQL does: source when the
    source is monitored, otherwise destination only when the query has a destination column.
    It also answers `system.columns` when `columns` is supplied, which is how the availability
    tests prove that a missing REQUIRED column is declared rather than silently empty.
    """

    def __init__(self, events: dict[str, list[tuple[str, str, datetime, str, float]]] | None = None,
                 *, scopes: tuple[str, ...] = ("198.51.100.0/24",), fail: bool = False,
                 columns: dict[str, set[str]] | None = None):
        self.events = events or {}
        self.scopes = list(scopes)
        self.fail = fail
        self.columns = columns
        self.queries: list[str] = []

    def query(self, sql: str, parameters=None):
        self.queries.append(sql)
        if self.fail:
            raise ConnectionError("clickhouse is not reachable")
        if "weirvern.network_scopes" in sql:
            return SimpleNamespace(result_rows=[(cidr,) for cidr in self.scopes])
        if "system.columns" in sql:
            requested = re.findall(r"'([^']+)'", sql.split("table IN (")[-1])
            rows = [(table, name) for table in requested
                    for name in sorted((self.columns or {}).get(table, set()))]
            return SimpleNamespace(result_rows=rows)
        table = next((name for name in self.events if name in sql), None)
        if table is None:
            return SimpleNamespace(result_rows=[])
        anchor_match = _ANCHOR.search(sql)
        bucket_match = _BUCKET.search(sql)
        since_match = _SINCE.search(sql)
        until_match = _UNTIL.search(sql)
        if not anchor_match or not bucket_match or not since_match or not until_match:
            return SimpleNamespace(result_rows=[])
        anchor = int(anchor_match.group(1))
        bucket_s = int(bucket_match.group(1))
        since = _parse(since_match.group(1))
        until = _parse(until_match.group(1))
        nets = [ipaddress.ip_network(cidr) for cidr in dict.fromkeys(_SCOPE.findall(sql))]
        has_peer = "isIPAddressInRange(dst_addr" in sql
        # THE ENDPOINT TABLE HAS A DIRECTION, and the fake must honour it or every test would read
        # both halves as one population. 'out' attributes to the source, 'in' to the destination,
        # exactly as the view's UNION ALL does.
        direction_match = re.search(r"direction = '(in|out)'", sql)
        direction = direction_match.group(1) if direction_match else None
        # `uniqMerge` is a distinct-count state just as `uniqExact` is a distinct count; the old
        # table and the endpoint table both express diversity through it.
        distinct = "uniqExact" in sql or "uniqMerge" in sql
        peer_diversity = "uniqExact(if(" in sql or "uniqMerge(unique_peer_ips)" in sql
        values_mode = " AS v " in sql
        buckets: dict[tuple[str, int], tuple[int, set[str], float]] = {}
        value_buckets: dict[tuple[str, int], set[str]] = {}
        for src, dst, when, value, nbytes in self.events[table]:
            if not (since <= when < until):
                continue
            if direction == "out":
                subject, peer = (src, dst) if _in_scope(src, nets) else ("", "")
            elif direction == "in":
                subject, peer = (dst, src) if _in_scope(dst, nets) else ("", "")
            elif has_peer:
                subject, peer = ((src, dst) if _in_scope(src, nets)
                                 else (dst, src) if _in_scope(dst, nets) else ("", ""))
            else:
                subject, peer = (src, dst) if _in_scope(src, nets) else ("", "")
            if not subject:
                continue
            index = (anchor - int(when.timestamp())) // bucket_s
            if index < 0:
                continue
            if values_mode:
                value_buckets.setdefault((subject, index), set()).add(value)
                continue
            n, seen, total = buckets.get((subject, index), (0, set(), 0.0))
            if distinct:
                seen = seen | {peer if peer_diversity else value}
            buckets[(subject, index)] = (n + 1, seen, total + float(nbytes))
        if values_mode:
            rows = [(host, index, value) for (host, index), values
                    in sorted(value_buckets.items()) for value in sorted(values)]
            return SimpleNamespace(result_rows=rows)
        rows = []
        for (host, index), (n, seen, total) in sorted(buckets.items()):
            rows.append((host, index, n, len(seen) if distinct else 0, total))
        return SimpleNamespace(result_rows=rows)


def _series(table: str, *, counts: dict[int, int] | None = None, host: str = HOST,
            peer: str = EXTERNAL, values: int = 4, base: int = 6, hours: int = HOURS,
            bytes_for: dict[int, float] | None = None, bytes_per: float = 100.0,
            reverse: bool = False,
            extra_for: dict[int, list[str]] | None = None
            ) -> list[tuple[str, str, datetime, str, float]]:
    """One event per unit of volume, half an hour inside each hourly bucket.

    `extra_for` appends values to one bucket: that is how a fingerprint/version CHANGE is
    modelled (the steady values are still there, one new one appears) without hand-building a
    fixture that would stop testing the SQL.
    """
    counts = counts or {}
    extra_for = extra_for or {}
    events = []
    for index in range(hours):
        when = NOW - timedelta(hours=index, minutes=30)
        amount = float((bytes_for or {}).get(index, bytes_per))
        for slot in range(counts.get(index, base)):
            src, dst = (peer, host) if reverse else (host, peer)
            events.append((src, dst, when + timedelta(seconds=slot),
                           f"{table}-{slot % values}", amount))
        for slot, value in enumerate(extra_for.get(index, [])):
            src, dst = (peer, host) if reverse else (host, peer)
            events.append((src, dst, when + timedelta(seconds=30 + slot), value, amount))
    return events


def _ripples(events: dict[str, list[tuple[str, str, datetime, str, float]]]) -> list:
    items = ripple_evidence.compute(FakeClient(events), now=NOW)
    return group_evidence(items, monitored=NETS)


def _evidence(channel: str, family: str, pvalue: float, *, scale: str = "1h",
              samples: int = 2000, host: str = HOST) -> ChannelEvidence:
    """One synthetic measurement for the grouping boundaries, with an explicit baseline size."""
    return ChannelEvidence(
        channel=channel, family=family, scale=scale, model_id=f"source:{channel}",
        model_version="test", score=10.0, pvalue=pvalue, freshness_s=0.0, present=True,
        host=host, observed_at=WINDOW, value=10.0, baseline_median=1.0,
        sample_count=samples, coverage=1.0, direction="rose",
        p_floor=pvalue_floor(samples),
    )


def test_a_steady_channel_raises_no_significant_evidence_and_no_ripple():
    events = {"weirvern.zeek_dns": _series("dns", base=6)}
    items = ripple_evidence.compute(FakeClient(events), now=NOW)

    dns = [item for item in items if item.channel == "dns_volume"]
    assert dns, "a host with a week of history must be measured, not skipped"
    assert all(item.pvalue > 0.5 for item in dns), \
        [(item.scale, item.value, item.baseline_median, item.pvalue) for item in dns]
    assert [item for item in items if item.pvalue <= 0.05] == []
    assert group_evidence(items, monitored=NETS) == []


def test_a_step_change_in_one_channel_produces_evidence_with_a_small_p_value():
    events = {"weirvern.zeek_dns": _series("dns", counts={0: 60})}
    items = ripple_evidence.compute(FakeClient(events), now=NOW)

    hourly = [item for item in items if item.channel == "dns_volume" and item.scale == "1h"]
    assert len(hourly) == 1
    item = hourly[0]
    assert item.pvalue <= 0.01
    assert item.pvalue == pvalue_floor(item.sample_count), \
        "a value beyond every baseline sample is at the floor, and says so"
    assert item.at_floor() is True
    assert item.floor() < ripple_evidence.DEFAULT_FAMILY_MAX_P
    assert item.value == 60
    assert item.baseline_median == 6
    assert item.direction == "rose"
    assert item.sample_count >= 100
    assert item.coverage > 0.9


def test_a_channel_with_insufficient_history_produces_no_evidence_at_all():
    short = _series("dns")[: 3 * 6]          # three hours, then nothing
    events = {"weirvern.zeek_dns": short}
    assert ripple_evidence.compute(FakeClient(events), now=NOW) == []


def test_two_significant_families_in_one_window_form_one_ripple_naming_both():
    events = {
        "weirvern.zeek_dns": _series("dns", counts={0: 60}),
        "weirvern.zeek_conn": _series("conn", counts={0: 60}),
    }
    ripples = _ripples(events)

    assert len(ripples) == 1, [(r.host, r.window_start, r.channels) for r in ripples]
    ripple = ripples[0]
    assert ripple.host == HOST
    assert ripple.families == ("conn", "dns")
    assert ripple.single_family is False
    assert ripple.channels == ("conn_volume", "dns_volume")
    assert "conn family" in ripple.explanation and "dns family" in ripple.explanation
    assert "independent families" in ripple.explanation
    assert {item.channel for item in ripple.evidence} == {"conn_volume", "dns_volume"}
    assert ripple.window_start == datetime(2026, 11, 19, 14, 0, tzinfo=UTC)


def test_significant_channels_in_different_windows_do_not_form_one_ripple():
    # Each channel moves in its own hour and only mildly: two baseline hours are at least as
    # high, so p is above the family bar. One such channel cannot ripple, and the two never
    # share a window.
    dns_events = {"weirvern.zeek_dns": _series("dns", counts={0: 30, 10: 30, 11: 30})}
    conn_events = {"weirvern.zeek_conn": _series("conn", counts={0: 30, 10: 30, 11: 30})}
    later = ripple_evidence.compute(FakeClient(dns_events), now=NOW)
    earlier = ripple_evidence.compute(FakeClient(conn_events), now=NOW - timedelta(hours=2))

    significant = [item for item in later + earlier if item.pvalue <= 0.05]
    assert significant, "the fixture must actually produce significant evidence"
    assert all(item.pvalue > 0.01 for item in significant), \
        [(item.channel, item.scale, item.pvalue) for item in significant]
    assert group_evidence(later + earlier, monitored=NETS) == []


def test_one_family_at_the_floor_is_not_a_ripple_when_it_cannot_reach_the_bar():
    """A single channel at the 1-hour floor is 0.006: above extreme, below two-family."""
    events = {"weirvern.zeek_dns": _series("dns", counts={0: 60})}
    ripples = _ripples(events)

    assert ripples == []


def test_flow_bytes_and_flow_volume_are_one_family_and_cannot_corroborate():
    """The exact 2026-11-19 defect: two units for the same flows counted as two channels."""
    events = {
        "weirvern.flows_window": _series("flow", counts={0: 6}, bytes_for={0: 5000.0}),
    }
    items = ripple_evidence.compute(FakeClient(events), now=NOW)
    significant = [item for item in items if item.pvalue <= 0.01]
    assert {item.channel for item in significant} == {"flow_bytes"}, \
        [(i.channel, i.pvalue) for i in significant]

    direct = [_evidence("flow_bytes", "flow", 0.005),
              _evidence("flow_volume", "flow", 0.005)]
    assert group_evidence(direct, monitored=NETS) == [], \
        "one family is one measurement, however many channels it is viewed through"


def test_an_inbound_only_host_now_has_flow_evidence():
    """THE GAP THIS WORK EXISTS FOR: a host that only receives traffic had NO flow evidence.

    The events are external -> HOST on every row, which is what a server, a NAS or a printer
    actually produces. Before schema 061 the flow channels read `src_addr`, every row belonged to
    an external address, and `compute()` dropped all of it.
    """
    events = {"weirvern.flows_window_endpoint": _series("flow", base=6, reverse=True)}
    items = ripple_evidence.compute(FakeClient(events), now=NOW)

    by_host = {(item.host, item.channel) for item in items}
    assert (HOST, "flow_in_volume") in by_host
    assert (HOST, "flow_in_bytes") in by_host
    assert (HOST, "flow_in_peer_diversity") in by_host
    assert not [item for item in items if item.host == HOST
                and item.channel in {"flow_volume", "flow_bytes", "flow_dst_diversity"}], (
        "an inbound-only host must not be reported as an outbound source"
    )
    assert not [item for item in items if item.host == EXTERNAL], (
        "the remote sender is a peer, never the subject of a ripple"
    )


def test_a_host_that_only_sends_is_not_double_counted():
    """One flow, one outbound row. The inbound channel must stay empty for a send-only host."""
    events = {
        "weirvern.flows_window": _series("flow", counts={0: 6}, base=6),
        "weirvern.flows_window_endpoint": _series("flow", counts={0: 6}, base=6),
    }
    items = ripple_evidence.compute(FakeClient(events), now=NOW)

    volume = [item for item in items if item.channel == "flow_volume" and item.scale == "1h"]
    assert len(volume) == 1
    # Six events in the current bucket. A view that emitted both endpoints into the same
    # direction, or a reader that summed the two directions, would read 12.
    assert volume[0].value == 6.0, volume[0].value
    assert not [item for item in items if item.host == HOST and item.channel.startswith("flow_in_")], (
        "a host that never received a flow must not acquire inbound evidence"
    )


def test_inbound_volume_cannot_corroborate_outbound_volume():
    """Both directions are one family, so a symmetric host cannot make a two-family ripple."""
    both = [_evidence("flow_volume", "flow", 0.005),
            _evidence("flow_in_volume", "flow", 0.005)]
    assert group_evidence(both, monitored=NETS) == []


def test_p_at_the_attainable_floor_with_a_short_baseline_is_not_evidence():
    short = _evidence("dns_volume", "dns", pvalue=1 / 21, samples=20)
    short = ChannelEvidence(**{**short.__dict__, "baseline_short": True})

    assert short.at_floor() is True
    assert short.floor() == pvalue_floor(20)
    assert short.as_dict()["baseline_short"] is True
    assert short.as_dict()["p_floor"] == round(pvalue_floor(20), 8)
    assert group_evidence([short], monitored=NETS) == []

    # The same fact at the API level: the scale says why it cannot be used.
    assert ripple_evidence.scale_report("6h")["usable"] is False
    assert "baseline too short" in ripple_evidence.scale_report("6h")["reason"]
    assert ripple_evidence.scale_report("1h")["usable"] is True
    assert ripple_evidence.scale_report("1h")["p_floor"] == round(pvalue_floor(167), 6)

    # And a lookback that cannot reach 30 windows emits no evidence at all.
    assert ripple_evidence.compute(FakeClient({"weirvern.zeek_dns": _series("dns")}),
                                   now=NOW, lookback_days=1) == []
    assert "baseline too short" in ripple_evidence.scale_report("1h", 1)["reason"]


def test_an_external_only_change_produces_no_ripple():
    events = {"weirvern.zeek_conn": _series("conn", counts={0: 60},
                                            host=EXTERNAL, peer=OTHER_EXTERNAL)}
    items = ripple_evidence.compute(FakeClient(events), now=NOW)

    assert items == []
    assert _ripples(events) == []


def test_an_inbound_change_is_attributed_to_the_monitored_destination():
    """A remote peer changing is the internal host's ripple, never the peer's."""
    events = {
        "weirvern.zeek_conn": _series("conn", counts={0: 60}, reverse=True),
        "weirvern.zeek_dns": _series("dns", counts={0: 60}, reverse=True),
    }
    items = ripple_evidence.compute(FakeClient(events), now=NOW)

    assert {item.host for item in items} == {HOST}, \
        sorted({item.host for item in items})
    assert EXTERNAL not in {item.host for item in items}

    ripples = _ripples(events)
    assert len(ripples) == 1
    assert ripples[0].host == HOST
    assert ripples[0].explanation.startswith(f"ripple on {HOST} ")
    assert EXTERNAL not in ripples[0].explanation


def test_a_ripple_needs_two_families_at_0_01_or_one_at_0_001():
    two = [_evidence("dns_volume", "dns", 0.01), _evidence("conn_volume", "conn", 0.01)]
    ripples = group_evidence(two, monitored=NETS)
    assert len(ripples) == 1
    assert ripples[0].score >= 3.0

    two_above = [_evidence("dns_volume", "dns", 0.011),
                 _evidence("conn_volume", "conn", 0.011)]
    assert group_evidence(two_above, monitored=NETS) == []

    one = [_evidence("dns_volume", "dns", 0.001)]
    ripples = group_evidence(one, monitored=NETS)
    assert len(ripples) == 1
    assert ripples[0].single_family is True
    assert ripples[0].score >= 3.0
    assert "single family dns" in ripples[0].explanation
    assert "not cross-family corroboration" in ripples[0].explanation

    one_above = [_evidence("dns_volume", "dns", 0.0011)]
    assert group_evidence(one_above, monitored=NETS) == []


def test_a_single_family_at_the_extreme_bar_is_stated_as_single_family():
    """One family can ripple alone only at 0.001, and then the sentence says so."""
    mixed = [_evidence("dns_volume", "dns", 0.001), _evidence("conn_volume", "conn", 0.02)]
    ripples = group_evidence(mixed, monitored=NETS)
    assert len(ripples) == 1
    assert ripples[0].families == ("dns",)
    assert ripples[0].single_family is True
    assert "single family dns" in ripples[0].explanation


def test_a_family_above_the_bar_does_not_corroborate():
    mixed = [_evidence("dns_volume", "dns", 0.05), _evidence("conn_volume", "conn", 0.02)]
    assert group_evidence(mixed, monitored=NETS) == []


def test_one_channel_at_several_scales_is_still_one_channel():
    """A channel measured at 1h and the same family elsewhere must not vote twice."""
    events = {"weirvern.zeek_dns": _series("dns", counts={0: 60})}
    items = ripple_evidence.compute(FakeClient(events), now=NOW)
    same_family = [item for item in items if item.family == "dns" and item.pvalue <= 0.01]
    assert {item.channel for item in same_family} == {"dns_volume"}
    assert group_evidence(same_family, monitored=NETS) == []


def test_the_explanation_names_the_family_and_subject_and_never_a_bare_p_value():
    events = {
        "weirvern.zeek_dns": _series("dns", counts={0: 60}),
        "weirvern.zeek_conn": _series("conn", counts={0: 60}),
    }
    ripple = _ripples(events)[0]

    assert HOST in ripple.explanation
    for channel, family in (("dns_volume", "dns"), ("conn_volume", "conn")):
        assert re.search(rf"{family} family: {channel} [\d.,]+ vs median [\d.,]+ "
                         rf"\((rose|fell|changed) at 1h; p[=<]=", ripple.explanation), \
            ripple.explanation
    assert ripple.explanation.count("vs median") == len(ripple.channels)
    # Every p-value is tied to a family, a channel, a median, a direction and a window count.
    for match in re.finditer(r"p[=<]=?[\d.e+-]+", ripple.explanation):
        assert "baseline windows" in ripple.explanation[match.end():match.end() + 80]
    assert "p=0.05" not in ripple.explanation


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
        assert "6h" not in row["scales"], row
        assert "24h" not in row["scales"], row
        assert row["scales"] == ["1h"], row
        assert row["scale_detail"]["6h"]["usable"] is False, row
        assert "baseline too short" in row["scale_detail"]["6h"]["reason"], row


def test_a_two_sided_p_value_sees_a_fall_as_clearly_as_a_rise():
    assert 0.0 < empirical_pvalue_two_sided(0.0, [10.0] * 20) <= 0.05
    assert 0.0 < empirical_pvalue_two_sided(99.0, [10.0] * 20) <= 0.05
    assert empirical_pvalue_two_sided(10.0, [10.0] * 20) == 1.0


def test_the_read_path_returns_ripples_with_their_evidence():
    """The API is evidence -> grouping, not a stored verdict, so this proves the join."""
    window = datetime(2026, 11, 19, 14, 0)
    rows = [
        (window, window + timedelta(hours=1), HOST, "dns_volume", "dns", "1h", 60.0, 6.0,
         0.004, 500, 1.0, "rose", datetime(2026, 11, 19, 14, 37)),
        (window, window + timedelta(hours=1), HOST, "conn_volume", "conn", "1h", 41.0, 5.0,
         0.005, 500, 1.0, "rose", datetime(2026, 11, 19, 14, 37)),
    ]

    def query(sql, parameters=None):
        if "weirvern.network_scopes" in sql:
            return SimpleNamespace(result_rows=[("198.51.100.0/24",)])
        return SimpleNamespace(result_rows=rows)

    out = ripple_evidence.overview(SimpleNamespace(query=query), hours=24, now=NOW)

    assert out["available"] is True
    assert out["count"] == 1
    assert out["monitored_networks"] == ["198.51.100.0/24"]
    assert out["baseline"]["1h"]["usable"] is True
    ripple = out["ripples"][0]
    assert ripple["host"] == HOST
    assert ripple["channels"] == ["dns_volume", "conn_volume"]
    assert ripple["families"] == ["conn", "dns"]
    assert ripple["single_family"] is False
    assert len(ripple["evidence"]) == 2
    assert ripple["evidence"][0]["baseline_median"] in (6.0, 5.0)
    assert "vs median" in ripple["explanation"]


def test_the_read_path_drops_stored_rows_for_external_subjects():
    """Old rows from before the fix must not resurrect a peer as a ripple subject."""
    window = datetime(2026, 11, 19, 14, 0)
    rows = [
        (window, window + timedelta(hours=1), EXTERNAL, "flow_bytes", "flow", "1h", 1.0, 1.0,
         0.004, 500, 1.0, "rose", datetime(2026, 11, 19, 14, 37)),
        (window, window + timedelta(hours=1), EXTERNAL, "flow_volume", "flow", "1h", 1.0, 1.0,
         0.004, 500, 1.0, "rose", datetime(2026, 11, 19, 14, 37)),
    ]

    def query(sql, parameters=None):
        if "weirvern.network_scopes" in sql:
            return SimpleNamespace(result_rows=[("198.51.100.0/24",)])
        return SimpleNamespace(result_rows=rows)

    out = ripple_evidence.overview(SimpleNamespace(query=query), hours=24, now=NOW)

    assert out["available"] is True
    assert out["count"] == 0
    assert out["evidence"]["monitored_rows"] == 0


def test_no_monitored_scope_means_no_evidence_rather_than_everything():
    events = {
        "weirvern.zeek_dns": _series("dns", counts={0: 60}),
        "weirvern.zeek_conn": _series("conn", counts={0: 60}),
    }
    assert ripple_evidence.compute(FakeClient(events, scopes=()), now=NOW) == []
    assert _ripples(events)  # the same fixture does ripple when a scope exists


# ── the four independent families (2026-11-19) ──────────────────────────────────────────────

OLD_FAMILIES = {"flow", "conn", "dns", "identity"}
NEW_FAMILIES = {"tls", "http", "ssh", "notice"}
NEW_CHANNELS = ("tls_fingerprint_diversity", "http_host_diversity", "http_ua_novelty",
                "ssh_version_change", "zeek_notice_volume", "zeek_weird_volume")


def _channels(items: list[ChannelEvidence], channel: str) -> list[ChannelEvidence]:
    return [item for item in items if item.channel == channel]


def test_the_four_new_families_are_independent_of_the_existing_four():
    """A family is one measurement, so a new one must add a view, not re-count an old one."""
    declared = {spec.channel: spec.family for spec in ripple_evidence.SPECS}
    assert declared == CHANNEL_FAMILIES, "the specs and the family map must not drift apart"
    assert not (NEW_FAMILIES & OLD_FAMILIES)
    assert {declared[name] for name in NEW_CHANNELS} == NEW_FAMILIES
    # The four channels the operator asked for are one per family, not four views of one.
    one_each = ["tls_fingerprint_diversity", "http_host_diversity", "ssh_version_change",
                "zeek_notice_volume"]
    assert len({declared[name] for name in one_each}) == 4
    # Two fields of the same HTTP request, and two outputs of the same Zeek pipeline, are
    # deliberately one family each: they may not corroborate themselves.
    assert declared["http_ua_novelty"] == declared["http_host_diversity"] == "http"
    assert declared["zeek_weird_volume"] == declared["zeek_notice_volume"] == "notice"


def test_a_new_tls_fingerprint_pair_produces_evidence_and_a_steady_one_does_not():
    steady = {"weirvern.zeek_ssl": _series("ssl", values=4)}
    steady_items = _channels(ripple_evidence.compute(FakeClient(steady), now=NOW),
                             "tls_fingerprint_diversity")
    assert steady_items, "a host with a week of TLS history must be measured"
    assert all(item.value == 4 for item in steady_items), [i.value for i in steady_items]
    assert all(item.pvalue > 0.5 for item in steady_items)
    assert group_evidence(steady_items, monitored=NETS) == []

    changed = {"weirvern.zeek_ssl": _series("ssl", values=4, extra_for={0: ["ssl-new"]})}
    items = _channels(ripple_evidence.compute(FakeClient(changed), now=NOW),
                      "tls_fingerprint_diversity")
    assert len(items) == 1
    item = items[0]
    assert item.value == 5, "the new (SNI, JA4) pair is one more distinct value this hour"
    assert item.baseline_median == 4
    assert item.direction == "rose"
    assert item.pvalue <= 0.01
    assert item.at_floor(), "a value beyond every baseline window is at the floor and says so"


def test_a_new_user_agent_produces_novelty_and_a_returning_one_does_not():
    returning = {"weirvern.zeek_http": _series("http", values=4)}
    returning_items = _channels(ripple_evidence.compute(FakeClient(returning), now=NOW),
                                "http_ua_novelty")
    assert returning_items, "the UA channel must be measured for a host with history"
    assert all(item.value == 0 for item in returning_items)
    assert all(item.pvalue > 0.5 for item in returning_items)
    assert [item for item in returning_items if item.pvalue <= 0.01] == []

    new_ua = {"weirvern.zeek_http": _series("http", values=4, extra_for={0: ["http-new"]})}
    items = _channels(ripple_evidence.compute(FakeClient(new_ua), now=NOW), "http_ua_novelty")
    assert len(items) == 1
    assert items[0].value == 1, "one user-agent this host has never sent"
    assert items[0].baseline_median == 0
    assert items[0].pvalue <= 0.01
    assert items[0].at_floor()


def test_an_ssh_version_pair_change_produces_evidence_and_a_steady_pair_does_not():
    steady = {"weirvern.zeek_ssh": _series("ssh", values=1)}
    steady_items = _channels(ripple_evidence.compute(FakeClient(steady), now=NOW),
                             "ssh_version_change")
    assert steady_items, "a host with a week of SSH history must be measured"
    assert all(item.value == 0 for item in steady_items), [i.value for i in steady_items]
    assert all(item.pvalue > 0.5 for item in steady_items)

    changed = {"weirvern.zeek_ssh": _series("ssh", values=1,
                                            extra_for={0: ["ssh-upgraded"]})}
    items = _channels(ripple_evidence.compute(FakeClient(changed), now=NOW),
                      "ssh_version_change")
    assert len(items) == 1
    assert items[0].value == 1, "the banner pair changed, and the channel is a boolean"
    assert items[0].baseline_median == 0
    assert items[0].pvalue <= 0.01


def test_notice_volume_obeys_the_same_thirty_window_floor():
    """Zeek's own findings get no exemption from the baseline rule."""
    short = {"weirvern.zeek_notice": _series("notice", hours=20)}
    assert _channels(ripple_evidence.compute(FakeClient(short), now=NOW),
                     "zeek_notice_volume") == []

    full = {"weirvern.zeek_notice": _series("notice", counts={0: 60})}
    items = _channels(ripple_evidence.compute(FakeClient(full), now=NOW), "zeek_notice_volume")
    assert len(items) == 1
    assert items[0].value == 60
    assert items[0].sample_count >= 100
    assert items[0].pvalue <= 0.01

    # The same short-lookback rule as every other channel: no baseline, no evidence.
    assert _channels(ripple_evidence.compute(FakeClient(full), now=NOW, lookback_days=1),
                     "zeek_notice_volume") == []


def test_a_channel_missing_a_required_column_is_declared_unavailable():
    """A renamed column must read as 'unavailable', never as 'this host was quiet'."""
    columns = {"zeek_ssl": {"ts", "src_addr", "dst_addr", "server_name"}}   # no ja4
    client = FakeClient({}, columns=columns)
    rows = {row["channel"]: row for row in ripple_evidence.availability(client)}

    tls = rows["tls_fingerprint_diversity"]
    assert tls["available"] is False
    assert tls["missing_columns"] == ["ja4"]
    assert "ja4" in tls["reason"]
    # A table the probe said nothing about is NOT declared broken.
    assert rows["http_host_diversity"]["available"] is True

    events = {"weirvern.zeek_ssl": _series("ssl", values=4, extra_for={0: ["ssl-new"]})}
    assert _channels(ripple_evidence.compute(FakeClient(events, columns=columns), now=NOW),
                     "tls_fingerprint_diversity") == []

    inventory = {row["channel"]: row for row in ripple_evidence.inventory()}
    assert "ja4" in inventory["tls_fingerprint_diversity"]["required_columns"]
    assert "ja4_orig" not in inventory["tls_fingerprint_diversity"]["required_columns"], \
        "ja4_orig exists but is empty on every live row, so it cannot be required"


def test_http_host_diversity_counts_the_header_not_the_subject_alias():
    """ClickHouse substitutes the `host` alias: unqualified, this would always measure 1."""
    spec = next(item for item in ripple_evidence.HTTP_SPECS
                if item.channel == "http_host_diversity")
    sql = spec.sql_anchored(bucket_s=3600, anchor=NOW, since=NOW - timedelta(days=7),
                            until=NOW, scope_cidrs=("198.51.100.0/24",))
    assert "uniqExact(weirvern.zeek_http.host)" in sql
    assert "uniqExact(host)" not in sql


# ── the lookback is derived from the retention in force ──────────────────────────────────────
#
# The measured defect this fixes: `lookback_days` was the constant 7 for every scale while the
# 6h scale needs 26 days (100 windows) to resolve the 0.01 bar. The 7-day constant was not a
# policy, it was a number nothing updated when retention rose to 258 days.


class _TtlClient:
    """A read client whose useful answer is the source tables' own TTLs."""

    def __init__(self, days: int = 258, scope: str = "198.51.100.0/24"):
        self.days = days
        self.scope = scope

    def query(self, sql, parameters=None):
        if "system.tables" in sql:
            names = re.findall(r"'([^']+)'", sql.split("name IN (")[-1])
            ddl = ("CREATE TABLE weirvern.x (ts DateTime) ENGINE = MergeTree "
                   "PARTITION BY toYYYYMM(ts) "
                   f"TTL ts + toIntervalDay({self.days}) SETTINGS index_granularity = 8192")
            return SimpleNamespace(result_rows=[(name, ddl) for name in names])
        if "network_scopes" in sql:
            return SimpleNamespace(result_rows=[(self.scope,)])
        return SimpleNamespace(result_rows=[])


def _query_sinces(client: FakeClient) -> list[datetime]:
    out = []
    for sql in client.queries:
        match = _SINCE.search(sql)
        if match:
            out.append(_parse(match.group(1)))
    return out


def test_the_lookback_is_derived_from_retention_and_capped_per_scale():
    """What each scale reads, from the retention, never past it."""
    assert ripple_evidence.scale_lookback_days("1h", 258) == 7      # the historical floor
    assert ripple_evidence.scale_lookback_days("6h", 258) == 26     # 100 windows + 2 spare
    assert ripple_evidence.scale_lookback_days("24h", 258) == 103
    assert ripple_evidence.scale_lookback_days("7d", 258) == 258    # capped: the bar needs 721

    for retention in (3, 7, 8, 30, 103, 258, 365):
        for scale in ("1h", "6h", "24h", "7d"):
            assert ripple_evidence.scale_lookback_days(scale, retention) <= retention, \
                f"{scale} at retention {retention} would read past the tables"


def test_a_short_lookback_uses_the_validated_tail_instead_of_going_mute():
    """8 days is enough for the 30-window floor but NOT for the empirical 0.01 bar.

    Before the fitted tail this scale was measured and refused. Now it is usable FOR COUNT
    CHANNELS, with the method named in the report and the empirical floor retained as the number
    the rank test would have had. The bar is unchanged: the report does not claim the empirical
    test can resolve it.
    """
    report = ripple_evidence.scale_report("6h", retention_days=8, kind="count")

    assert report["usable"] is True
    assert report["method"] == "parametric"
    assert report["p_floor"] >= ripple_evidence.DEFAULT_FAMILY_MAX_P, \
        "the empirical floor is still above the bar; that is why the tail is needed"
    assert report["p_floor_kind"] == "empirical"
    assert report["tail_p_floor"] == 1e-6
    assert report["tail_supported"] is True
    assert report["lookback_days"] == 8
    assert report["retention_days"] == 8
    assert report["baseline_windows"] == 31
    assert report["minimum_windows"] == 30
    assert report["required_lookback_days"] == 8, "the 30-window floor's lookback is unchanged"
    assert report["windows_for_bar"] == 100
    assert report["required_lookback_days_for_bar"] == 26
    assert report["reason"] == ""

    # A byte SUM is not a count, so the same scale refuses the fitted tail and says why.
    summed = ripple_evidence.scale_report("6h", retention_days=8, kind="sum")
    assert summed["usable"] is False
    assert summed["method"] == "insufficient"
    assert "not defined for a sum statistic" in summed["reason"]
    assert summed["tail_supported"] is False


def test_retention_above_the_requirement_makes_the_scale_usable():
    """The 6h and 24h scales become readable once the lookback is allowed to grow."""
    six = ripple_evidence.scale_report("6h", retention_days=258)
    assert six["usable"] is True
    assert six["lookback_days"] == 26
    assert six["baseline_windows"] == 103
    assert six["p_floor"] < ripple_evidence.DEFAULT_FAMILY_MAX_P

    day = ripple_evidence.scale_report("24h", retention_days=258)
    assert day["usable"] is True
    assert day["lookback_days"] == 103
    assert day["baseline_windows"] == 102

    # 7d is declared and honestly not usable at this deployment: the tail is implemented but the
    # scale is not enabled until a 30-window fit exists, and the report names both numbers.
    week = ripple_evidence.scale_report("7d", retention_days=258)
    assert week["usable"] is False
    assert week["method"] == "insufficient"
    assert week["lookback_days"] == 258
    assert "721" in week["reason"] and "258" in week["reason"]
    assert "30 are required" in week["reason"], week["reason"]


def test_no_query_reads_further_back_than_retention():
    client = FakeClient({"weirvern.zeek_dns": _series("dns")})
    ripple_evidence.compute(client, now=NOW, retention_days=30)
    sinces = _query_sinces(client)
    assert sinces
    assert min(sinces) >= NOW - timedelta(days=30)

    long_client = FakeClient({"weirvern.zeek_dns": _series("dns")})
    ripple_evidence.compute(long_client, now=NOW, retention_days=258)
    long_sinces = _query_sinces(long_client)
    assert min(long_sinces) >= NOW - timedelta(days=258)
    assert min(long_sinces) < NOW - timedelta(days=20), \
        "the 6h/24h scales must read past the old 7-day constant"


def test_the_payload_reports_the_lookback_and_the_retention_it_came_from():
    out = ripple_evidence.overview(_TtlClient(258), hours=6, now=NOW)

    assert out["available"] is True
    assert out["retention"]["days"] == 258
    assert out["retention"]["source"] == "system.tables TTL"
    assert out["baseline"]["1h"]["lookback_days"] == 7
    assert out["baseline"]["6h"]["lookback_days"] == 26
    assert out["baseline"]["24h"]["lookback_days"] == 103
    assert out["baseline"]["7d"]["lookback_days"] == 258
    assert out["baseline"]["6h"]["retention_days"] == 258
    # NO ROWS IN THIS READING IS NOT AN UNUSABLE SCALE. The capability is stated by
    # `expected_windows`; the state is stated by `usable`, and it says why.
    assert out["baseline"]["6h"]["expected_windows"] == 103
    assert out["baseline"]["6h"]["usable"] is False
    assert "no measured rows" in out["baseline"]["6h"]["reason"]
    assert out["baseline"]["24h"]["expected_windows"] == 102
    assert out["baseline"]["24h"]["usable"] is False
    assert out["baseline"]["7d"]["usable"] is False


def test_an_unreadable_ttl_falls_back_to_the_seven_day_floor_and_says_so():
    info = ripple_evidence.retention_in_force(FakeClient({}))

    assert info["days"] == 7
    assert info["source"] == "default"
    assert info["reason"]


def test_the_thirty_window_floor_and_the_family_rule_are_untouched():
    """This change reads MORE history; it does not lower what counts as a ripple."""
    assert ripple_evidence.MIN_BASELINE_SAMPLES == 30
    assert ripple_evidence.min_baseline_samples("6h") == 30
    report = ripple_evidence.scale_report("6h", retention_days=258)
    assert report["minimum_windows"] == 30
    assert report["required_lookback_days"] == 8

    # The same family at the ordinary bar still cannot corroborate itself...
    one = _evidence("flow_volume", "flow", 0.005, samples=103)
    two = _evidence("flow_bytes", "flow", 0.005, samples=103)
    assert group_evidence([one, two], monitored=NETS) == []

    # ...and two independent families at the ordinary bar still form one ripple.
    dns = _evidence("dns_volume", "dns", 0.005, samples=103)
    conn = _evidence("conn_volume", "conn", 0.005, samples=103)
    assert len(group_evidence([dns, conn], monitored=NETS)) == 1


# ── CRITICALITY: the bar's own arithmetic, defined once ─────────────────────────────────────


def test_severity_bands_are_the_ripple_bars_own_arithmetic():
    """Every threshold is derived from the grouping constants, not invented for the UI."""
    bands = severity_bands()

    assert bands["low"] == {"min_score": 3.0, "min_families": 1}
    # two families at p=0.01 -> 2 * -log10(0.01) = 4.0
    assert bands["medium"]["min_score"] == 4.0
    assert bands["medium"]["min_families"] == 2
    # three families at p=0.01 -> 6.0, which is also two at the 0.001 extreme bar
    assert bands["high"]["min_score"] == 6.0
    assert bands["high"]["min_families"] == 3
    assert bands["bar"] == {
        "family_max_p": 0.01, "extreme_p": 0.001,
        "min_score": 3.0, "min_families": 2,
    }


def test_severity_band_uses_score_and_distinct_families():
    assert severity_band(3.0, ["dns"]) == "low"
    assert severity_band(3.99, ["dns"]) == "low"
    assert severity_band(4.0, ["dns"]) == "medium"
    assert severity_band(4.29, ["conn", "dns"]) == "medium"
    assert severity_band(5.99, ["conn", "dns"]) == "medium"
    assert severity_band(6.0, ["conn", "dns"]) == "high"
    assert severity_band(5.0, ["conn", "dns", "tls"]) == "high"
    assert severity_band(7.11, ["conn", "dns", "tls"]) == "high"
    # A row below the bar is never decorated up: the grouping contract should refuse it.
    assert severity_band(2.9, ["conn", "dns"]) == "low"
    # Duplicate names are one family, not two votes.
    assert severity_band(3.42, ["flow", "flow"]) == "low"


def test_a_grouped_ripple_ships_the_band_the_page_renders():
    ripples = group_evidence(
        [_evidence("dns_volume", "dns", 0.006, samples=103),
         _evidence("conn_volume", "conn", 0.005, samples=103)],
        monitored=NETS,
    )
    assert len(ripples) == 1
    row = ripples[0].as_dict()

    assert row["severity"] == "medium"
    assert row["severity"] == severity_band(row["score"], row["families"])


# ── THE FITTED TAIL (2026-11-20) ─────────────────────────────────────────────────────────────
#
# The empirical test's floor is 1/(n+1); the bar is 0.01. These tests pin the selection rule (the
# empirical p is never replaced where it can resolve; the fitted tail is used only below 100
# windows), the provenance on every row, and the two ways the fit must refuse rather than invent
# a number: an over-dispersed baseline (which a Poisson tail would call a ripple) and a
# degenerate one (all zeros / zero variance).

def _count_spec(*, kind: str = "count", channel: str = "conn_volume") -> ChannelSpec:
    return ChannelSpec(channel=channel, family="conn", table="weirvern.zeek_conn",
                       host_column="src_addr", peer_column="dst_addr", kind=kind)


def _count_measure(reference: list[float], current: float, *, kind: str = "count",
                   scale: str = "6h") -> ChannelEvidence:
    return ripple_evidence._measure(
        _count_spec(kind=kind), scale=scale, host=HOST, moment=WINDOW, value=current,
        reference=[float(value) for value in reference], coverage=1.0)


def _parametric_row(channel: str, family: str, pvalue: float) -> ChannelEvidence:
    return ChannelEvidence(
        channel=channel, family=family, scale="6h", model_id=f"source:{channel}",
        model_version="test", score=10.0, pvalue=pvalue, freshness_s=0.0, present=True,
        host=HOST, observed_at=WINDOW, value=10.0, baseline_median=1.0, sample_count=40,
        coverage=1.0, direction="rose", p_floor=pvalue_floor(40),
        p_method="negbin", p_detail="negbin n=40 mean=7 var=110.8 index=15.8 size=0.47")


def test_at_100_windows_the_empirical_p_is_unchanged():
    """The rank test wins the moment it can resolve the bar; the tail never shadows it."""
    reference = [float(index % 17) for index in range(100)]
    current = max(reference) + 3.0
    item = _count_measure(reference, current)

    assert item.p_method == "empirical"
    assert item.pvalue == empirical_pvalue_two_sided(current, reference)
    assert item.p_detail == "ranks n=100"
    assert item.floor() == pvalue_floor(100)
    assert item.at_floor() is True          # it is the maximum, and n=100 resolves 0.01
    assert item.resolves(ripple_evidence.DEFAULT_FAMILY_MAX_P) is True


def test_below_100_windows_the_fitted_tail_is_used_and_the_method_is_recorded():
    """94 windows cannot express p<0.01 empirically (floor 0.0105); the tail can, and says so."""
    reference = [1.0] * 30 + [25.0] * 10          # mean 7, variance ~110: bursty
    item = _count_measure(reference, 50.0)        # p ~ 0.0098 under the fitted NB

    assert item.p_method == "negbin"
    assert item.pvalue < pvalue_floor(len(reference)), \
        "the fitted p must be below what the empirical test could have expressed"
    assert item.at_floor() is False
    assert item.resolves(ripple_evidence.DEFAULT_FAMILY_MAX_P) is True
    assert item.as_dict()["p_method"] == "negbin"
    assert item.as_dict()["p_detail"].startswith("negbin n=40")
    # The empirical floor is still reported, so a reader can compare the two resolutions.
    assert item.as_dict()["p_floor"] == round(pvalue_floor(40), 8)


def test_an_overdispersed_baseline_does_not_produce_the_poisson_false_ripple():
    """The whole reason for the negative binomial: Poisson would call this a ripple."""
    reference = [1.0] * 30 + [25.0] * 10
    fit = ripple_tail.fit_counts(reference)
    assert fit.method == "negbin", fit.summary()
    poisson = ripple_tail.TailFit(ripple_tail.POISSON, len(reference),
                                  mean=statistics.mean(reference))

    assert ripple_tail.tail_pvalue(40.0, poisson) <= 0.01, "the Poisson tail would fire"
    assert ripple_tail.tail_pvalue(40.0, fit) > 0.01, "the fitted NB tail must not"

    item = _count_measure(reference, 40.0)
    assert item.p_method == "negbin"
    assert item.pvalue > 0.01
    assert group_evidence([item], monitored=NETS) == []


def test_a_degenerate_baseline_reports_insufficient_not_p_zero():
    """All-zero and zero-variance baselines are a named state, never a fabricated p."""
    for reference in ([0.0] * 40, [5.0] * 40):
        item = _count_measure(reference, 5.0)

        assert item.p_method == "insufficient"
        assert math.isnan(item.pvalue)
        assert item.as_dict()["p_value"] is None
        assert item.as_dict()["p_method"] == "insufficient"
        assert item.p_detail.startswith("insufficient")
        assert item.at_floor() is False
        assert item.resolves(0.01) is False
        assert group_evidence([item], monitored=NETS) == []


def test_a_non_count_statistic_reports_insufficient_instead_of_a_modelled_p():
    """A negative binomial over bytes would be a category error; the row says so."""
    item = _count_measure([1000.0 + index for index in range(40)], 99999.0, kind="sum")

    assert item.p_method == "insufficient"
    assert math.isnan(item.pvalue)
    assert "not defined for a sum statistic" in item.p_detail


def test_the_family_rule_and_the_score_bar_are_unchanged_for_parametric_rows():
    """The tail changes how a p is produced, never what a ripple requires."""
    # Two views of ONE measurement still cannot corroborate: each is below the family bar but
    # neither is at the extreme bar, so one family is one family and no ripple forms.
    assert group_evidence(
        [_parametric_row("flow_volume", "flow", 0.005),
         _parametric_row("flow_bytes", "flow", 0.005)], monitored=NETS) == []
    # Two independent families at the family bar score 2 * -log10(0.01) = 4.0.
    out = group_evidence([_parametric_row("conn_volume", "conn", 0.01),
                          _parametric_row("dns_volume", "dns", 0.01)], monitored=NETS)
    assert len(out) == 1
    assert abs(out[0].score - 4.0) < 1e-9
    # Two families at 0.02 are not significant, so there is no ripple and no score arithmetic.
    assert group_evidence([_parametric_row("conn_volume", "conn", 0.02),
                           _parametric_row("dns_volume", "dns", 0.02)], monitored=NETS) == []
    # One family at the extreme bar still forms the single-family ripple, and says so.
    out = group_evidence([_parametric_row("conn_volume", "conn", 0.0004)], monitored=NETS)
    assert len(out) == 1 and out[0].single_family is True


def test_the_stored_row_and_the_read_path_carry_the_method():
    """Provenance is not a comment: it survives the write and the read."""
    item = _count_measure([1.0] * 30 + [25.0] * 10, 50.0)
    row = ripple_evidence._row(item)

    assert "p_method" in ripple_evidence.COLUMNS
    assert "p_detail" in ripple_evidence.COLUMNS
    assert row[ripple_evidence.COLUMNS.index("p_method")] == "negbin"
    assert row[ripple_evidence.COLUMNS.index("p_detail")].startswith("negbin")

    window = WINDOW
    stored = (window, window + timedelta(hours=1), HOST, "conn_volume", "conn", "6h", 50.0,
              7.0, 0.0098, "negbin", "negbin n=40 mean=7", 40, 1.0, "rose", window)

    def query(sql, parameters=None):
        if "network_scopes" in sql:
            return SimpleNamespace(result_rows=[(str(NET),)])
        return SimpleNamespace(result_rows=[stored])

    items = ripple_evidence.read(SimpleNamespace(query=query), hours=24, now=NOW)
    assert len(items) == 1
    assert items[0].p_method == "negbin"
    assert items[0].p_detail == "negbin n=40 mean=7"


def test_the_7d_scale_reports_usable_or_not_with_a_reason():
    """The coarse scale may not silently disappear: it says which state it is in and why."""
    report = ripple_evidence.scale_report("7d", retention_days=234, kind="count")

    if report["usable"]:
        assert report["method"] in ("empirical", "parametric")
        assert report["reason"] == ""
    else:
        assert report["method"] == "insufficient"
        assert report["reason"]
        assert "7d" in ripple_evidence.EVIDENCE_SCALES
