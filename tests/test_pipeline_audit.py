"""BF-13: the pipeline self-audit -- one fixture per audit class.

A class whose read fails must surface as an entry in `errors`, never as an absent finding:
"nothing found" and "the check did not run" must never look alike on this page.
"""
import datetime as dt
from types import SimpleNamespace

from weirvern.admin import status


class _Client:
    """Routes queries by substring; anything unexpected raises (so a new query without a
    fixture fails loudly instead of silently returning nothing)."""

    def __init__(self, *, expired=(), stuck=()):
        self.expired = list(expired)
        self.stuck = list(stuck)

    def query(self, sql, parameters=None):  # noqa: ARG002
        if "sluice_rules" in sql and "expires_at <=" in sql:
            return SimpleNamespace(result_rows=list(self.expired))
        if "sluice_events" in sql:
            return SimpleNamespace(result_rows=list(self.stuck))
        raise RuntimeError(f"unfixtured query: {sql[:60]}")


def _fleet(*sensors):
    return {"available": True, "reason": None, "heartbeats_available": True,
            "sensors": list(sensors)}


def _monkey_fleet(monkeypatch, payload):
    monkeypatch.setattr("weirvern.fleet_store.build_fleet", lambda client, now=None, **k: payload)


def _detectors_overview_empty(monkeypatch):
    monkeypatch.setattr(status, "detectors_overview",
                        lambda client: {"available": True, "reason": "", "detectors": []})


def test_a_silent_sensor_is_found_and_links_to_its_drill_down(monkeypatch):
    _monkey_fleet(monkeypatch, _fleet(
        {"sensor_id": "edge-stale", "registered": True, "enabled": True, "state": "stale",
         "age_s": 5400.0, "stale_after_s": 45, "note": "ran and stopped"},
        {"sensor_id": "edge-alive", "registered": True, "enabled": True, "state": "alive",
         "age_s": 3.0, "stale_after_s": 45, "note": ""},
    ))
    _detectors_overview_empty(monkeypatch)
    out = status.pipeline_audit(_Client())
    silent = [f for f in out["findings"] if f["class"] == "silent_sensor"]
    assert [f["subject"] for f in silent] == ["edge-stale"]
    assert silent[0]["fix"]["view"] == "weirlings"
    assert silent[0]["fix"]["sensor"] == "edge-stale"
    assert "1h" in silent[0]["detail"]          # 5400s humanized
    assert out["counts"]["silent_sensor"] == 1


def test_a_disabled_sensor_is_not_a_finding(monkeypatch):
    """Switched-off silence is EXPECTED silence -- the whole point of the fleet's disabled
    state is that it must not be raised."""
    _monkey_fleet(monkeypatch, _fleet(
        {"sensor_id": "edge-off", "registered": True, "enabled": False, "state": "stale",
         "age_s": 99999.0, "stale_after_s": 45, "note": ""},
    ))
    _detectors_overview_empty(monkeypatch)
    out = status.pipeline_audit(_Client())
    assert [f for f in out["findings"] if f["class"] == "silent_sensor"] == []


def test_an_expired_rule_carries_how_long_it_has_been_elapsed(monkeypatch):
    now = dt.datetime(2026, 10, 17, 12, 0, 0)
    expired = dt.datetime(2026, 10, 14, 12, 0, 0)   # 3 days before
    _monkey_fleet(monkeypatch, _fleet())
    _detectors_overview_empty(monkeypatch)
    out = status.pipeline_audit(
        _Client(expired=[("r-1", "ads.example", "", expired)]), now=now)
    exp = [f for f in out["findings"] if f["class"] == "expired_rule"]
    assert len(exp) == 1
    assert exp[0]["elapsed_s"] == 3 * 86400
    assert exp[0]["fix"]["view"] == "sluice"
    assert "domain rule" in exp[0]["detail"]


def test_a_stuck_rule_names_its_span(monkeypatch):
    now = dt.datetime(2026, 10, 17, 12, 0, 0)
    first = dt.datetime(2026, 9, 1, 0, 0, 0)
    _monkey_fleet(monkeypatch, _fleet())
    _detectors_overview_empty(monkeypatch)
    out = status.pipeline_audit(
        _Client(stuck=[("r-2", 400, first, now)]), now=now)
    stuck = [f for f in out["findings"] if f["class"] == "stuck_rule"]
    assert len(stuck) == 1 and stuck[0]["fix"]["view"] == "blocked"
    assert "still wanted" in stuck[0]["detail"]


def test_an_unregistered_detector_is_listed_until_somebody_decides(monkeypatch):
    _monkey_fleet(monkeypatch, _fleet())
    monkeypatch.setattr(status, "detectors_overview", lambda client: {
        "available": True, "reason": "", "detectors": [
            {"name": "Mystery Net", "owner": "", "runbook": "", "rule": "", "loud": False,
             "known": False, "fired": 3, "acted": 0},
            {"name": "Isolation Forest", "owner": "ops", "runbook": "r", "rule": "x",
             "loud": True, "known": True, "fired": 9, "acted": 1},
        ]})
    out = status.pipeline_audit(_Client())
    un = [f for f in out["findings"] if f["class"] == "unowned_detector"]
    assert [f["subject"] for f in un] == ["Mystery Net"]
    assert un[0]["fix"]["view"] == "anomalies"


def test_a_failed_class_is_an_error_entry_not_an_absent_finding(monkeypatch):
    def _boom(client, now=None, **k):
        raise RuntimeError("registry down")
    monkeypatch.setattr("weirvern.fleet_store.build_fleet", _boom)
    _detectors_overview_empty(monkeypatch)
    out = status.pipeline_audit(_Client())
    assert out["available"] is True
    assert out["errors"]["silent_sensors"] == "RuntimeError"
    assert all(f["class"] != "silent_sensor" for f in out["findings"])
