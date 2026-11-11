"""The Findings drill must not turn a read failure into a clean host."""
from __future__ import annotations

from pathlib import Path

from weirvern.admin import assets

ROOT = Path(__file__).resolve().parents[1]
INDEX = (ROOT / "weirvern/admin/web/index.html").read_text()
APP = (ROOT / "weirvern/admin/web/app.js").read_text()
ASSETS = (ROOT / "weirvern/admin/web/assets.js").read_text()


class _Result:
    def __init__(self, rows):
        self.result_rows = rows


class _Client:
    def __init__(self, findings, registry=None):
        self.findings = findings
        self.registry = registry or []

    def query(self, sql, parameters=None):
        if "asset_findings" in sql:
            if isinstance(self.findings, Exception):
                raise self.findings
            return _Result(self.findings)
        if "asset_registry" in sql:
            return _Result(self.registry)
        raise AssertionError(sql)


def test_findings_are_grouped_and_named_without_a_ptr_lookup():
    client = _Client(
        findings=[("198.51.100.10", "high", "exposed service", "test-template", "", "2026-11-10 12:00:00", "")],
        registry=[("198.51.100.10", "lab-host")],
    )
    payload = assets.asset_findings_list(client)
    assert payload["available"] is True
    assert payload["count"] == 1
    assert payload["findings"][0]["hostname"] == "lab-host"
    assert payload["counts"]["high"] == 1
    assert payload["counts"]["total"] == 1


def test_an_unreadable_findings_table_is_unavailable_not_empty():
    payload = assets.asset_findings_list(_Client(findings=RuntimeError("table missing")))
    assert payload["available"] is False
    assert "could not be read" in payload["reason"]
    assert payload["findings"] == []


def test_a_readable_empty_findings_table_is_an_empty_answer():
    payload = assets.asset_findings_list(_Client(findings=[]))
    assert payload["available"] is True
    assert payload["count"] == 0
    assert payload["counts"] == {"total": 0}


def test_the_findings_surface_is_wired_as_a_drill_not_a_tab():
    assert 'id="view-findings"' in INDEX
    assert 'id="fd-table"' in INDEX
    assert "openFindings" in ASSETS
    assert "openFindings" in APP
    assert 'findings: "assets"' in APP
    assert 'if (v === "findings")' in APP
