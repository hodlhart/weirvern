"""The Normalize feed's Alert column: the server-side join, and its honesty.

Operator (2026-11-20): "normalize needs an Alert column that says ripple or anomaly." The column
is decided SERVER-SIDE against the same two sources the Alerts tab reads, so the feed cannot
claim an alert the Alerts tab does not show. The cases below are the whole truth table, plus the
failed-read case, which must never render as "no alert".
"""

from __future__ import annotations

import datetime as _dt

from weirvern import normalize_store


class _Result:
    def __init__(self, rows):
        self.result_rows = rows


class _Client:
    """Answers the two join reads by table name; every other query is an empty success."""

    def __init__(self, *, ripples=(), models=(), fail=()):
        self.ripples = list(ripples)
        self.models = list(models)
        self.fail = set(fail)

    def query(self, sql, parameters=None, **_kw):  # noqa: ARG002
        if "ml_ripple_evidence" in sql:
            if "ripples" in self.fail:
                raise RuntimeError("ripple evidence unavailable")
            return _Result(self.ripples)
        if "netflow_anomalies" in sql:
            if "models" in self.fail:
                raise RuntimeError("anomaly table unavailable")
            return _Result(self.models)
        return _Result([])


def _row(**over):
    base = {
        "source": "flow", "src_addr": "192.0.2.40",
        "first_seen": "2026-11-20T08:00:00", "last_seen": "2026-11-20T08:59:00",
        "dst_prefix": "203.0.113.0/24", "dst_port": 443, "proto": "tcp",
        "dns_name": "", "dns_qtype": 0, "bytes": 1000, "flows": 4,
    }
    base.update(over)
    return base


def test_a_ripple_evidence_row_makes_the_row_say_ripple():
    rows = [_row()]
    out = normalize_store._annotate_alerts(
        _Client(ripples=[("192.0.2.40", "conn_volume", "conn", _dt.datetime(2026, 11, 20, 8))]), rows, hours=24)
    assert out["available"] is True
    assert rows[0]["alert_kind"] == "Ripple"
    assert rows[0]["alert_ref"]["ripple_window"].startswith("2026-11-20 08:00")


def test_a_model_detection_makes_the_row_say_anomaly_with_its_band():
    rows = [_row()]
    out = normalize_store._annotate_alerts(
        _Client(models=[("192.0.2.40", _dt.datetime(2026, 11, 20, 8), "high")]), rows, hours=24)
    assert out["available"] is True
    assert rows[0]["alert_kind"] == "Anomaly"
    assert rows[0]["alert_band"] == "high"


def test_both_sources_make_the_row_say_both_ripple_first():
    rows = [_row()]
    normalize_store._annotate_alerts(
        _Client(ripples=[("192.0.2.40", "conn_volume", "conn", _dt.datetime(2026, 11, 20, 8))],
                models=[("192.0.2.40", _dt.datetime(2026, 11, 20, 8), "critical")]), rows, hours=24)
    assert rows[0]["alert_kind"] == "Ripple + Anomaly"
    assert rows[0]["alert_band"] == "critical"


def test_a_row_with_neither_says_a_measured_em_dash():
    rows = [_row()]
    out = normalize_store._annotate_alerts(_Client(), rows, hours=24)
    assert out["available"] is True
    assert rows[0]["alert_kind"] == "—"
    assert rows[0]["alert_band"] == ""


def test_a_dns_row_matches_the_dns_channel_only():
    rows = [_row(source="dns", dns_name="example.test", dst_port=0)]
    normalize_store._annotate_alerts(
        _Client(ripples=[("192.0.2.40", "conn_volume", "conn", _dt.datetime(2026, 11, 20, 8))]), rows, hours=24)
    assert rows[0]["alert_kind"] == "—", "a conn ripple is not evidence for a DNS row"
    rows2 = [_row(source="dns", dns_name="example.test", dst_port=0)]
    normalize_store._annotate_alerts(
        _Client(ripples=[("192.0.2.40", "dns_nxdomain_ratio", "dns", _dt.datetime(2026, 11, 20, 8))]), rows2, hours=24)
    assert rows2[0]["alert_kind"] == "Ripple"


def test_a_failed_join_is_unavailable_never_no_alert():
    rows = [_row()]
    out = normalize_store._annotate_alerts(_Client(fail=("ripples", "models")), rows, hours=24)
    assert out["available"] is False
    assert out["errors"], "a failed join must carry the reason"
    # The row is left without a claim; the UI renders 'unavailable' from the payload flag.
    assert rows[0]["alert_kind"] == "—"


def test_an_aware_datetime_and_its_iso_string_produce_the_same_hour_key():
    """ClickHouse returns tz-aware datetimes; the feed's rows carry their ISO strings.

    MEASURED LIVE 2026-11-20: the join matched nothing on the box and every row read the em
    dash, because the datetime branch kept the offset ("16:00:00-06:00") while the string branch
    dropped it ("16:00:00"). Every fixture here was naive, so the suite could not see it.
    """
    aware = _dt.datetime(2026, 11, 20, 16, 42, tzinfo=_dt.timezone(_dt.timedelta(hours=-6)))
    assert normalize_store._hour_key(aware) == normalize_store._hour_key(
        "2026-11-20T16:42:00-06:00") == "2026-11-20 16:00:00"

    rows = [_row(first_seen="2026-11-20T16:05:00-06:00",
                 last_seen="2026-11-20T16:55:00-06:00")]
    out = normalize_store._annotate_alerts(_Client(models=[("192.0.2.40", aware, "high")]),
                                           rows, hours=24)
    assert out["available"] is True
    assert rows[0]["alert_kind"] == "Anomaly", (
        "an aware timestamp from ClickHouse did not match the row's ISO string")
    assert rows[0]["alert_band"] == "high"


def test_a_real_evidence_channel_matches_through_its_family():
    """The evidence table stores `conn_volume` / `dns_nxdomain_ratio`, never the lane name.

    MEASURED LIVE 2026-11-20: 4,225 distinct evidence keys and 0 matches, because the join
    compared the stored channel with the feed's lane ("conn"/"dns") literally. The canonical
    family map is the one the Alerts ripple page uses.
    """
    rows = [_row()]
    out = normalize_store._annotate_alerts(
        _Client(ripples=[("192.0.2.40", "conn_volume", "conn",
                          _dt.datetime(2026, 11, 20, 8))]), rows, hours=24)
    assert out["available"] is True
    assert rows[0]["alert_kind"] == "Ripple"
    assert rows[0]["alert_ref"]["ripple_window"].startswith("2026-11-20 08:00")

    dns_rows = [_row(source="dns", dns_name="example.test", dst_port=0)]
    normalize_store._annotate_alerts(
        _Client(ripples=[("192.0.2.40", "dns_nxdomain_ratio", "dns",
                          _dt.datetime(2026, 11, 20, 8))]), dns_rows, hours=24)
    assert dns_rows[0]["alert_kind"] == "Ripple"

    other = [_row()]
    normalize_store._annotate_alerts(
        _Client(ripples=[("192.0.2.40", "dns_volume", "dns",
                          _dt.datetime(2026, 11, 20, 8))]), other, hours=24)
    assert other[0]["alert_kind"] == "—", "a DNS ripple is not evidence for a flow row"


# ── the Zeek lane: a session row can carry every family Zeek itself measures ──────────────────
#
# MEASURED LIVE 2026-11-21 before this: a zeek row matched only conn/flow, so 211 tls evidence
# rows (9 hosts), 134 http (4), 42 ssh (1) and 399 notice (10) were visible on the Ripples page
# and invisible on the row. The rule is now derived from each channel's own table and its live
# required_columns, not from a hard-coded family list.


def _zeek_row(**over):
    return _row(source="zeek", dns_name="ssl", dst_port=443, **over)


def test_a_zeek_row_carries_every_family_its_pipeline_measures():
    for channel, family in (
        ("tls_fingerprint_diversity", "tls"),
        ("http_host_diversity", "http"),
        ("ssh_version_change", "ssh"),
        ("kerberos_volume", "identity"),
        ("zeek_notice_volume", "notice"),
        ("conn_volume", "conn"),
        ("flow_volume", "flow"),
    ):
        rows = [_zeek_row()]
        normalize_store._annotate_alerts(
            _Client(ripples=[("192.0.2.40", channel, family, _dt.datetime(2026, 11, 20, 8))]),
            rows, hours=24)
        assert rows[0]["alert_kind"] == "Ripple", (
            f"{family} evidence must surface on a Zeek row observed in the same hour")


def test_a_zeek_row_can_carry_dns_evidence_but_a_flow_row_cannot():
    """Both the session and the lookup are Zeek observations; NetFlow never saw a name."""
    zeek_rows = [_zeek_row()]
    normalize_store._annotate_alerts(
        _Client(ripples=[("192.0.2.40", "dns_volume", "dns",
                          _dt.datetime(2026, 11, 20, 8))]), zeek_rows, hours=24)
    assert zeek_rows[0]["alert_kind"] == "Ripple"

    flow_rows = [_row()]
    normalize_store._annotate_alerts(
        _Client(ripples=[("192.0.2.40", "dns_volume", "dns",
                          _dt.datetime(2026, 11, 20, 8))]), flow_rows, hours=24)
    assert flow_rows[0]["alert_kind"] == "—", (
        "the DNS lane is still separate for a NetFlow row; a name-resolution ripple says "
        "nothing about a flow claim")


def test_the_scanner_pipeline_is_not_a_feed_lane():
    rows = [_zeek_row()]
    normalize_store._annotate_alerts(
        _Client(ripples=[("192.0.2.40", "service_set_change", "service",
                          _dt.datetime(2026, 11, 20, 8))]), rows, hours=24)
    assert rows[0]["alert_kind"] == "—"


def test_a_zeek_row_reports_one_window_per_host_family_hour_not_one_per_evidence_row():
    """Three channels of one family in one hour are ONE alert, not three."""
    rows = [_zeek_row()]
    normalize_store._annotate_alerts(
        _Client(ripples=[
            ("192.0.2.40", "conn_volume", "conn", _dt.datetime(2026, 11, 20, 8)),
            ("192.0.2.40", "conn_dst_diversity", "conn", _dt.datetime(2026, 11, 20, 8)),
            ("192.0.2.40", "conn_reset_ratio", "conn", _dt.datetime(2026, 11, 20, 8)),
        ]), rows, hours=24)
    assert rows[0]["alert_kind"] == "Ripple"
    assert rows[0]["alert_ref"]["ripple_window"].startswith("2026-11-20 08:00")
    assert rows[0]["alert_ref"]["ripple_window"].count(",") == 0


def test_the_lane_map_is_derived_from_the_specs_not_a_family_list():
    from weirvern.models import ripple_evidence as rev

    zeek = rev.feed_lane_channels("zeek")
    assert set(zeek.values()) == {"flow", "conn", "dns", "tls", "http", "ssh", "identity",
                                  "notice"}
    # Every channel whose OWN table is a Zeek table is offered; nothing on a non-Zeek table is.
    for spec in rev.SPECS:
        if spec.table.startswith("weirvern.zeek_"):
            assert spec.channel in zeek, spec.channel
        if spec.table == "weirvern.asset_service_history":
            assert spec.channel not in zeek
    assert rev.feed_lane_families("flow") == frozenset({"conn", "flow"})
    assert rev.feed_lane_families("dns") == frozenset({"dns"})
    assert rev.feed_lane_families("unknown") == frozenset(), (
        "an unknown lane must not widen into every family")


def test_a_channel_whose_table_lacks_a_required_column_is_not_offered():
    """availability() is the gate: a missing column means 'insufficient', never a zero."""
    from weirvern.models import ripple_evidence as rev

    offered = rev.feed_lane_channels("zeek", available={"tls_fingerprint_diversity": False})
    assert "tls_fingerprint_diversity" not in offered
    assert "http_host_diversity" in offered
    assert "tls" not in set(offered.values())
