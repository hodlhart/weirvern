"""US-3 pins: the self-audit's fixes keep the ids they name.

The failure this guards: fix buttons landed at the top of a page while the finding named a
rule or detector the operator then had to search for -- the id existed in the finding's
subject and was dropped from the fix. These pins hold the server shape the UI relies on to
land ON the target. Stub pattern mirrors test_pipeline_audit.py (route by substring; an
unfixtured query fails loudly).
"""
from __future__ import annotations

import datetime as dt
from types import SimpleNamespace

from weirvern.admin import status


class _Client:
    def __init__(self, *, expired=(), stuck=()):
        self.expired = list(expired)
        self.stuck = list(stuck)

    def query(self, sql, parameters=None):  # noqa: ARG002
        if "sluice_rules" in sql and "expires_at <=" in sql:
            return SimpleNamespace(result_rows=list(self.expired))
        if "sluice_events" in sql:
            return SimpleNamespace(result_rows=list(self.stuck))
        raise RuntimeError(f"unfixtured query: {sql[:60]}")


def _fleet():
    return {"available": True, "reason": None, "heartbeats_available": True, "sensors": []}


def _monkey_fleet(monkeypatch):
    monkeypatch.setattr("weirvern.fleet_store.build_fleet",
                        lambda client, now=None, **k: _fleet())


def _detectors(monkeypatch, detectors):
    monkeypatch.setattr(status, "detectors_overview",
                        lambda client: {"available": True, "reason": "", "detectors": detectors})


def test_an_expired_rule_fix_carries_the_rule_id(monkeypatch):
    _monkey_fleet(monkeypatch)
    _detectors(monkeypatch, [])
    expired = dt.datetime(2026, 10, 14, 12, 0, 0)
    out = status.pipeline_audit(
        _Client(expired=[("r-expired-1", "ads.example", "", expired)]),
        now=dt.datetime(2026, 10, 17, 12, 0, 0))
    f = [x for x in out["findings"] if x["class"] == "expired_rule"]
    assert len(f) == 1
    assert f[0]["fix"]["rule_id"] == "r-expired-1", \
        "the fix must name the rule it is about, or the button lands on a page top"
    assert f[0]["fix"]["view"] == "sluice"


def test_a_stuck_rule_fix_carries_the_rule_id(monkeypatch):
    _monkey_fleet(monkeypatch)
    _detectors(monkeypatch, [])
    first = dt.datetime(2026, 9, 1, 0, 0, 0)
    now = dt.datetime(2026, 10, 17, 12, 0, 0)
    out = status.pipeline_audit(_Client(stuck=[("r-stuck-2", 400, first, now)]), now=now)
    f = [x for x in out["findings"] if x["class"] == "stuck_rule"]
    assert len(f) == 1
    assert f[0]["fix"]["rule_id"] == "r-stuck-2"
    assert f[0]["fix"]["view"] == "blocked"


def test_an_unowned_detector_fix_names_the_detector(monkeypatch):
    _monkey_fleet(monkeypatch)
    _detectors(monkeypatch, [{"name": "Mystery Net", "known": False, "loud": False, "owner": ""}])
    out = status.pipeline_audit(_Client(), now=dt.datetime(2026, 10, 17, 12, 0, 0))
    f = [x for x in out["findings"] if x["class"] == "unowned_detector"]
    assert len(f) == 1
    assert f[0]["fix"]["detector"] == "Mystery Net", \
        "a registry fix without the detector name cannot land on its row"


def test_the_client_lands_on_rule_and_detector_targets():
    """The UI seam, pinned by source shape: auditGo must route rule ids and detector names."""
    from pathlib import Path

    src = (Path(__file__).resolve().parents[1] / "weirvern" / "admin" / "web" / "app.js").read_text()
    seg = src.split("function auditGo(", 1)[1].split("\nfunction ", 1)[0]
    assert "fix.rule_id" in seg and "blOpenRuleById" in seg and "sluiceHighlightRule" in seg, \
        "auditGo no longer routes rule fixes to the blocked card / sluice row"
    assert "fix.detector" in seg and 'anSetFilter("model"' in seg, \
        "auditGo no longer routes a detector fix to that detector's alerts"
