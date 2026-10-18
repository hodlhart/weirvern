"""WL-2 pins: the weirling sheet is for CHANGES, and the facts live where they belong.

The operator, 2026-10-18: "The pop out should only be for settings changes... it is still too
much information. It's an ugly list." The fact list left the sheet; capture loss and a
contradicted segment became ISSUE findings (the Logs tab owns issues), the row carries state,
mode, networks, the trend and the taps, and the trend itself is the pivot to Discover.
"""
from __future__ import annotations

from pathlib import Path

from weirvern.admin.status import sensor_issues

WEB = Path(__file__).resolve().parents[1] / "weirvern" / "admin" / "web"
PY = Path(__file__).resolve().parents[1] / "weirvern"

ROW = {
    "sensor_id": "edge-moved", "state": "alive",
    "segment": "fifth floor", "reported_segment": "sixth floor",
    "capture_loss_pct": 62.5, "packets_recv": 400, "packets_dropped": 250,
}


def test_a_measured_high_loss_is_an_issue_with_its_number():
    issues = sensor_issues(ROW)
    loss = [i for i in issues if i["class"] == "capture_loss"]
    assert len(loss) == 1
    assert "62.5%" in loss[0]["detail"] and "blind" in loss[0]["detail"]
    assert loss[0]["fix"]["sensor"] == "edge-moved"


def test_an_unmeasured_or_zero_loss_is_not_an_issue():
    for loss_value in (None, 0.0, 1.0):
        issues = sensor_issues({**ROW, "capture_loss_pct": loss_value})
        assert not [i for i in issues if i["class"] == "capture_loss"], (
            f"capture_loss_pct={loss_value!r} must not raise an issue: unmeasured and "
            f"measured-nothing are different facts, and a quiet sensor is not a problem"
        )


def test_a_contradicted_segment_names_both():
    issues = sensor_issues(ROW)
    seg = [i for i in issues if i["class"] == "segment_mismatch"]
    assert len(seg) == 1 and "fifth floor" in seg[0]["detail"] and "sixth floor" in seg[0]["detail"]
    assert sensor_issues({**ROW, "reported_segment": ""}) == [] or \
        not [i for i in sensor_issues({**ROW, "reported_segment": ""})
             if i["class"] == "segment_mismatch"]


def test_the_audit_emits_them_and_names_the_in_path_case():
    src = (PY / "admin" / "status.py").read_text()
    seg = src.split("def pipeline_audit(", 1)[1]
    assert "findings.extend(sensor_issues(r))" in seg
    assert "in-path, so its segment may be waiting for it" in seg


def test_the_sheet_builds_no_fact_sheet():
    src = (WEB / "weirlings.js").read_text()
    seg = src.split("async function openWeirling(", 1)[1].split("// ── the sensor's own intercept plan", 1)[0]
    assert 'el("dl", { class: "kv" })' not in seg, "the facts table came back"
    assert 'class: "findings"' not in seg, "the findings list came back"
    assert "wlSituation(r)" in seg


def test_the_trend_is_the_pivot_and_nics_are_plan_candidates():
    src = (WEB / "weirlings.js").read_text()
    assert "wl-flow-cell" in src and "discoverDrill({ sensor: r.sensor_id })" in src, \
        "the flow trend must be the pivot now that the sheet carries no onward links"
    assert "wl-plan-iface-list" in src, "the NICs must reach the plan's iface field"
    app = (WEB / "app.js").read_text()
    assert "capture_loss:" in app and "segment_mismatch:" in app, \
        "the issues renderer has no label for WL-2's classes"
