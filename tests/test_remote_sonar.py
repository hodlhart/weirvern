"""Remote Sonar: a hub request must run on the sensor, never as a hub node Job."""
from __future__ import annotations

import json
from pathlib import Path

from weirvern.admin import sensor_agent, sonar

ROOT = Path(__file__).resolve().parents[1]


class _Result:
    def __init__(self, rows):
        self._rows = rows

    def named_results(self):
        return iter(self._rows)


class FakeDB:
    def __init__(self, states):
        self.states = list(states)
        self.inserts = []

    def insert(self, table, rows, column_names=None):
        self.inserts.append((table, rows, column_names))

    def query(self, *args, **kwargs):
        return _Result([self.states.pop(0)] if self.states else [])


def test_remote_survey_queues_and_returns_the_sensor_result(monkeypatch):
    db = FakeDB([
        {"request_id": "r1", "status": "pending", "result": "", "error": ""},
        {"request_id": "r1", "status": "running", "result": "", "error": ""},
        {"request_id": "r1", "status": "done",
         "result": json.dumps({"ok": True, "interface": "eth1", "hosts_answered": 3}),
         "error": ""},
    ])
    monkeypatch.setattr(sonar.time, "sleep", lambda _s: None)
    result = sonar.run_remote_survey(db, "weirling-a", "eth1", timeout_s=10, poll_s=0)
    assert result["ok"] is True
    assert result["interface"] == "eth1"
    # One queued row, then the sensor's claimed/running row; the hub never inserts a Job.
    assert db.inserts[0][0] == "weirvern.weirling_sonar_requests"
    assert db.inserts[0][1][0][4] == "pending"


def test_remote_survey_reports_a_sensor_refusal_without_faking_a_result(monkeypatch):
    db = FakeDB([
        {"request_id": "r1", "status": "failed", "result": "", "error": "NET_RAW is required"},
    ])
    monkeypatch.setattr(sonar.time, "sleep", lambda _s: None)
    assert sonar.run_remote_survey(db, "weirling-a", "eth1", timeout_s=10) == {
        "ok": False, "error": "NET_RAW is required"}


def test_remote_survey_is_not_a_hub_job():
    """THE ORDER MOVED into payloads.settings_sonar with the port, and it is asserted where it lives.

    A named remote sensor must be handled BEFORE any ClusterConfig or Job creation, or a hub interface
    with the same name would be surveyed and returned under the remote sensor's id. The ROUTE is on
    the Flask surface now and delegates to the same fetcher, so its text is read there -- asserting
    the deleted console handler's text would demand the branch be resurrected on a third surface.
    """
    src = (ROOT / "weirvern" / "admin" / "flask_app.py").read_text()
    assert "payloads.settings_sonar(" in src, "the sonar route no longer uses the shared fetcher"
    body = (ROOT / "weirvern" / "admin" / "payloads.py").read_text()
    body = body.split("def settings_sonar(", 1)[1].split("\ndef ", 1)[0]
    remote = body.index("run_remote_survey")
    job = body.index("run_survey_job(")
    assert remote < job, "the remote branch runs after the hub job, so a hub NIC can be surveyed"
    assert "remote = bool(sensor_id) and sensor_id != hub_sensor" in body


def test_sensor_claims_a_pending_sonar_and_posts_the_result(monkeypatch):
    calls = {}

    class Gateway:
        is_gateway = True

        def sonar_next(self):
            return {"request_id": "r1", "iface": "eth1", "mgmt_iface": "eth0"}

        def sonar_result(self, request_id, result, error=""):
            calls["posted"] = (request_id, result, error)
            return True

    monkeypatch.setattr("weirvern.admin.sonar.survey",
                        lambda iface, **kwargs: {"ok": True, "interface": iface})
    sensor_agent._run_pending_sonar(Gateway(), "eth9")
    assert calls["posted"][0] == "r1"
    assert calls["posted"][1]["ok"] is True


def test_remote_sonar_schema_is_durable_and_scoped_to_a_request():
    sql = (ROOT / "weirvern" / "schema" / "022_weirling_sonar.sql").read_text()
    for word in ("request_id", "sensor_id", "status", "result", "error", "TTL"):
        assert word in sql
    assert "weirvern.weirling_sonar_requests" in sql
