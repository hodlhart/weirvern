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
        _Client(ripples=[("192.0.2.40", "conn", _dt.datetime(2026, 11, 20, 8))]), rows, hours=24)
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
        _Client(ripples=[("192.0.2.40", "conn", _dt.datetime(2026, 11, 20, 8))],
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
        _Client(ripples=[("192.0.2.40", "conn", _dt.datetime(2026, 11, 20, 8))]), rows, hours=24)
    assert rows[0]["alert_kind"] == "—", "a conn ripple is not evidence for a DNS row"
    rows2 = [_row(source="dns", dns_name="example.test", dst_port=0)]
    normalize_store._annotate_alerts(
        _Client(ripples=[("192.0.2.40", "dns", _dt.datetime(2026, 11, 20, 8))]), rows2, hours=24)
    assert rows2[0]["alert_kind"] == "Ripple"


def test_a_failed_join_is_unavailable_never_no_alert():
    rows = [_row()]
    out = normalize_store._annotate_alerts(_Client(fail=("ripples", "models")), rows, hours=24)
    assert out["available"] is False
    assert out["errors"], "a failed join must carry the reason"
    # The row is left without a claim; the UI renders 'unavailable' from the payload flag.
    assert rows[0]["alert_kind"] == "—"
