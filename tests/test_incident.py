"""The incident object: one page an analyst can act on.

These tests pin the properties the queue view depends on: the actor/asset/window are real
columns, the evidence pivot is the same one the evidence page uses, and a failed optional read
is named rather than rendered as an empty success. They also pin the review provenance and the
read-only posture -- reviewing an incident must never train a model.
"""
from __future__ import annotations

import ast
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from weirvern.admin import status, web_api


class _Res:
    def __init__(self, columns, rows):
        self.column_names = columns
        self.result_rows = rows


class FakeClient:
    def __init__(self, fail_episode=False):
        self.fail_episode = fail_episode
        self.queries = []

    def query(self, sql, parameters=None):
        self.queries.append((sql, parameters or {}))
        if "FROM weirvern.alert_episodes" in sql:
            if self.fail_episode:
                raise RuntimeError("Code: 47. simulated episode read failure")
            start = datetime(2026, 10, 30, 22, 9, 27, tzinfo=UTC)
            return _Res(
                ["src_addr", "episode_start", "episode_end", "first_detected", "last_detected",
                 "occurrences", "window_count", "max_score", "severity", "severity_rank", "role",
                 "page_window", "pageable", "page_reason", "paged_at"],
                [("198.51.100.77", start, start + timedelta(minutes=30), start, start,
                  3, 3, 0.94, "high", 3, "workstation", start + timedelta(minutes=5),
                  True, "severity", None)],
            )
        if "FROM weirvern.host_roles" in sql:
            return _Res(["role", "scope"], [("workstation", "user")])
        if "FROM weirvern.ml_window_scores" in sql:
            return _Res(["model_version"], [("0.23.15",)])
        if "FROM weirvern.alert_reviews" in sql:
            reviewed = datetime(2026, 10, 30, 23, 0, tzinfo=UTC)
            return _Res(["state", "note", "reviewed_at", "reviewed_by"],
                        [("ack", "looked at it; benign update traffic", reviewed, "hermes")])
        return _Res([], [])


def _evidence():
    return {
        "anomaly": {
            "strong_families": "scan, exfil",
            "baseline_comparison": "ports 300 vs baseline 4",
            "severity": "high",
            "anomaly_score": 0.94,
        },
        "flows": [{"dst_addr": "203.0.113.9"}],
        "zeek_conn": [{"dst_addr": "203.0.113.9"}],
        "zeek_dns": [],
        "zeek_ssl": [{"ja4": "t13d1516h2"}],
        "notice": [],
    }


def test_incident_carries_actor_asset_window_families_coverage_and_version(monkeypatch):
    monkeypatch.setattr(status, "alert_evidence",
                        lambda client, addr, start: _evidence())
    out = status.incident_detail(FakeClient(), "198.51.100.77", "2026-10-30T22:15:00")

    assert out["available"] is True
    incident = out["incident"]
    assert incident["actor"] == "198.51.100.77"
    assert incident["asset"]["role"] == "workstation"
    assert incident["asset"]["scope"] == "user"
    assert incident["window"]["start"].year == 2026
    assert incident["families"] == ["scan", "exfil"]
    assert incident["source_coverage"] == {"flows": 1, "zeek_conn": 1, "zeek_dns": 0,
                                          "zeek_ssl": 1, "notice": 0}
    assert incident["model_versions"] == ["0.23.15"]
    assert incident["evidence"]["anomaly"]["anomaly_score"] == 0.94


def test_incident_includes_review_provenance_and_expiry(monkeypatch):
    monkeypatch.setattr(status, "alert_evidence",
                        lambda client, addr, start: _evidence())
    out = status.incident_detail(FakeClient(), "198.51.100.77", "2026-10-30T22:15:00")
    review = out["incident"]["review"]
    assert review["state"] == "ack"
    assert review["reviewed_by"] == "hermes"
    assert review["reviewed_at"] == datetime(2026, 10, 30, 23, 0, tzinfo=UTC)
    assert review["expires_at"] == datetime(2026, 11, 29, 22, 9, 27, tzinfo=UTC)


def test_a_failed_episode_read_is_named_not_an_empty_success():
    out = status.incident_detail(FakeClient(fail_episode=True), "198.51.100.77",
                                 "2026-10-30T22:15:00")
    assert out["available"] is False
    assert "episode read failed" in out["reason"]
    assert out["incident"] is None


def test_incident_payload_is_json_serialisable():
    monkeypatch_free = {
        "available": True, "reason": "", "evidence_error": None,
        "incident": {"actor": "198.51.100.77",
                     "window": {"start": datetime(2026, 10, 30, 22, 9, 27, tzinfo=UTC)}},
    }
    payload = web_api.incident_payload(monkeypatch_free)
    json.dumps(payload)  # must not raise
    assert payload["incident"]["window"]["start"].startswith("2026-10-30T22:09:27")


def test_incident_read_path_contains_no_write_statement():
    source = ast.get_source_segment(
        Path(status.__file__).read_text(),
        next(node for node in ast.walk(ast.parse(Path(status.__file__).read_text()))
             if isinstance(node, ast.FunctionDef) and node.name == "incident_detail"),
    ) or ""
    for verb in ("INSERT", "ALTER", "DELETE", "OPTIMIZE", "TRUNCATE", "CREATE"):
        assert verb not in source.upper(), f"incident_detail must be read-only; found {verb}"


def test_evidence_page_renders_the_incident_context():
    root = Path(__file__).resolve().parent.parent / "weirvern" / "admin" / "web"
    html = (root / "index.html").read_text()
    js = (root / "app.js").read_text()
    assert 'id="ev-incident"' in html
    assert "renderIncidentContext" in js
    assert "API.incident" in js
    assert "/api/incident" in js
