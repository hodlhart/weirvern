"""Pins for the Sluice Gate review fixes (UXF-SL1…SL7, DSG-SL1).

These are source-contract checks: the jsdom walk proves wiring, the live browser walk proves
layout. They name the property that must not regress, not the shape of the implementation.
"""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / "weirvern" / "admin" / "web"


def test_a_stale_gate_is_named_on_the_surface_not_only_in_a_title():
    html = (WEB / "index.html").read_text(encoding="utf-8")
    js = (WEB / "sluice.js").read_text(encoding="utf-8")
    assert 'id="sl-gate-warning"' in html
    assert "sluiceStateChip(g.state, g.stale)" in js
    assert "warning.textContent" in js
    assert "stale" in js and "degraded" in js


def test_the_empty_rules_sentence_names_hidden_revoked_rules_and_the_separate_domain_gate():
    js = (WEB / "sluice.js").read_text(encoding="utf-8")
    assert "hiddenRevoked" in js
    assert "revoked rule" in js
    assert "Domain blocking is a separate gate" in js
    assert "No blocking rules exist" not in js


def test_hits_use_the_selected_window_on_both_surfaces():
    py = (ROOT / "weirvern" / "admin" / "web.py").read_text(encoding="utf-8")
    js = (WEB / "sluice.js").read_text(encoding="utf-8")
    assert "hits_hours" in py
    assert "INTERVAL {int(hours)} HOUR" in py
    assert "/api/sluice?hours=${slHours}" in js
    assert "hits in ${hitHours}h" in js


def test_the_rule_composer_names_the_gate_and_disarms_on_edit():
    html = (WEB / "index.html").read_text(encoding="utf-8")
    js = (WEB / "sluice.js").read_text(encoding="utf-8")
    assert 'id="sl-target-type"' in html
    assert 'id="sl-gate-hint"' in html
    assert "Domain Gate (DNS answer)" in js
    assert "Traffic Gate (packet drop)" in js
    assert "SL_CREATE_ARM_TIMER" in js
    assert "slCreateDisarm" in js
    assert 'field.addEventListener("input"' in js


def test_the_blocks_drill_has_a_fresh_load_route():
    js = (WEB / "app.js").read_text(encoding="utf-8")
    assert 'if (v === "blocked")' in js
    assert 'showView("blocked")' in js


def test_the_mobile_sluice_checkboxes_are_a_full_touch_target():
    css = (WEB / "style.css").read_text(encoding="utf-8")
    phone = css.split("@media (max-width: 720px)", 1)[1]
    assert '#view-sluice .controls input[type="checkbox"]' in phone
    assert "width: 44px; height: 44px" in phone
