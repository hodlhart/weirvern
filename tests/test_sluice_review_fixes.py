"""Pins for the Sluice Gate review fixes (UXF-SL1…SL7, DSG-SL1).

These are source-contract checks: the jsdom walk proves wiring, the live browser walk proves
layout. They name the property that must not regress, not the shape of the implementation.
"""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / "weirvern" / "admin" / "web"


def test_a_stale_gate_is_named_on_the_surface_not_only_in_a_title():
    """A gate that stopped reporting is its own state, and the reader must see it on the card.

    Re-authored with the 2026-11-20 rebuild: the per-sensor card now carries the word in its
    meta line and its own consequence sentence, and the reason sits in `sl-gate-warning` rather
    than being duplicated in the gate line.
    """
    html = (WEB / "index.html").read_text(encoding="utf-8")
    js = (WEB / "sluice.js").read_text(encoding="utf-8")
    assert 'id="sl-gate-warning"' in js or 'id="sl-gate-warning"' in html
    assert 'bits.push("stale")' in js
    assert "Stopped reporting" in js
    assert "stale" in js and "degraded" in js


def test_the_empty_rules_sentence_names_hidden_revoked_rules_and_what_to_do():
    """An empty list explains the measurement: no rule filed, nothing in this gate, or N
    revoked rows hidden behind the filter. Re-authored with the 2026-11-20 rebuild, when the
    empty state stopped pointing at a "separate domain gate" and started naming the cause."""
    js = (WEB / "sluice.js").read_text(encoding="utf-8")
    assert "hiddenRevoked" in js
    assert "revoked rule" in js
    assert "No rule has been filed" in js
    assert "No blocking rules exist" not in js


def test_hits_use_the_selected_window_on_both_surfaces():
    py = (ROOT / "weirvern" / "admin" / "payloads.py").read_text(encoding="utf-8")
    js = (WEB / "sluice.js").read_text(encoding="utf-8")
    # THE FETCH MOVED into payloads.sluice with the port; the window arithmetic moved with it.
    assert "hits_hours" in py
    assert "INTERVAL {int(hours)} HOUR" in py
    assert "/api/sluice?hours=${slHours}" in js
    # The window is stated in words by one helper, so a gate sentence, a rule row and the sheet
    # cannot disagree about the interval ("24h" vs "the last 1d" was that disagreement).
    assert "function sl2Window(" in js
    assert "d.hits_hours" in js


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


# ── The 2026-11-20 re-engineer: evidence before action ───────────────────────────────────────
# These pin the CONTRACT of the new surface, not its markup: a rule states what it has done, a
# gate's chip uses the Alerts severity vocabulary, the fleet is per-sensor, and every arming
# change records a reason and proves the write with a read-back.

def test_the_payload_carries_per_rule_firing_evidence_in_the_selected_window():
    """A rule's sentence must be backed by an event count, and an unreadable event table is its
    own state: the row then says the evidence is unavailable rather than rendering a confident 0.
    """
    py = (ROOT / "weirvern" / "admin" / "payloads.py").read_text(encoding="utf-8")
    assert 'payload["evidence"]' in py
    assert "GROUP BY rule_id" in py
    assert '"last_age_s"' in py
    assert '"evidence": evidence.get(r.rule_id)' in py
    assert '"evidence_available": False' in py
    assert 'payload["evidence_reason"]' in py


def test_a_rule_row_states_its_matches_and_never_fabricates_a_zero():
    js = (WEB / "sluice.js").read_text(encoding="utf-8")
    assert "function sl2RuleEvidence(" in js
    assert "no DNS matches in" in js
    assert "no packet matches in" in js
    assert "match evidence unavailable" in js
    assert "DNS match" in js and "} dropped" in js


def test_a_rule_links_into_the_blocks_or_flows_behind_it():
    """An entity name navigates to its home view; a rule row is not a dead end."""
    js = (WEB / "sluice.js").read_text(encoding="utf-8")
    assert "#v=blocked&bl.domain=" in js
    assert "#v=discover&dc.addr=" in js
    assert "stopPropagation" in js, "the link navigates and the row opens the sheet"


def test_the_gate_state_chips_reuse_the_alerts_severity_vocabulary():
    js = (WEB / "sluice.js").read_text(encoding="utf-8")
    html = (WEB / "index.html").read_text(encoding="utf-8")
    assert "rp-sev-chip sev-" in js
    assert "SL2_STATE_SEV" in js
    assert "enforcing: \"low\"" in js and "degraded: \"critical\"" in js
    # The markup starts from a real chip, so the first paint is not an unstyled word.
    assert 'class="rp-sev-chip sev-low" id="sl2-traf-chip"' in html


def test_the_fleet_is_per_sensor_cards_and_says_when_there_is_nothing():
    html = (WEB / "index.html").read_text(encoding="utf-8")
    js = (WEB / "sluice.js").read_text(encoding="utf-8")
    assert 'class="sl2-fleet"' in html
    assert "sl2-sensor" in js
    assert "<thead" not in html.split('id="sl2-fleet"')[1].split("</div>")[0]
    assert "No sensor has reported a packet gate yet" in js
    assert "no packets matched since it started" in js


def test_arming_a_gate_requires_a_reason_and_reads_the_write_back():
    js = (WEB / "sluice.js").read_text(encoding="utf-8")
    assert 'postJSON("/api/settings/apply"' in js
    assert "A reason is required" in js
    assert "readBack" in js and "read back as" in js
    assert "THE RE-READ DOES NOT MATCH" in js


def test_the_mobile_rules_are_stacked_cards_not_a_scroll_box():
    css = (WEB / "style.css").read_text(encoding="utf-8")
    # The Sluice phone block is the one that carries the rules: slice from its own marker so a
    # different @media block earlier in the file cannot satisfy or fail this.
    start = css.index("/* ── Sluice on a phone")
    phone = css[start:]
    assert ".sl2-rules, .sl2-rules tbody, .sl2-rules tr, .sl2-rules td { display: block" in phone
    assert ".sl2-rules thead { display: none; }" in phone
    assert ".sl2-rules-wrap { overflow-x: visible; }" in phone
    assert "min-height: 44px" in phone


# ── The visual layer (2026-11-20): hierarchy, fault text, state-vs-action shapes ──────────────

def test_a_fault_owns_the_top_of_its_card_and_the_first_screen():
    """Severity outranks every control: a degraded gate and a stale sensor are stated in a
    full-width band at the top of their card, and the first screen repeats every fault."""
    html = (WEB / "index.html").read_text(encoding="utf-8")
    js = (WEB / "sluice.js").read_text(encoding="utf-8")
    assert 'id="sl2-attn"' in html
    assert 'id="sl2-traf-band"' in html and "sl2-sev-band" in html
    assert "renderSluiceAttention" in js and "sl2-sev-band" in js
    assert 'stale: "high"' in js and 'degraded: "critical"' in js
    # "New rule" is visually secondary even though it remains the header's one primary verb.
    assert "#sl2-new.sl2-new" in (WEB / "style.css").read_text(encoding="utf-8")


def test_rules_that_match_nothing_are_grouped_not_deleted():
    """The no-predicate records stay findable under one explanation, outside the real table."""
    html = (WEB / "index.html").read_text(encoding="utf-8")
    js = (WEB / "sluice.js").read_text(encoding="utf-8")
    assert 'id="sl2-orphans"' in html
    assert "function sl2HasPredicate(" in js
    assert "function renderSluiceOrphans(" in js
    assert "Rules that match nothing" in js
    assert "never match traffic" in js


def test_state_is_a_capsule_pill_and_action_is_a_button():
    css = (WEB / "style.css").read_text(encoding="utf-8")
    js = (WEB / "sluice.js").read_text(encoding="utf-8")
    assert ".rp-sev-chip.sl2-pill" in css
    assert "border-radius: 999px" in css
    assert "sl2-pill" in js
    # A pill has no solid control border; the button system keeps its 6px corners.
    assert "border: 0; border-radius: 999px" in css.replace("\n", " ")


def test_the_disabled_arming_control_names_its_reason_beside_it():
    html = (WEB / "index.html").read_text(encoding="utf-8")
    js = (WEB / "sluice.js").read_text(encoding="utf-8")
    css = (WEB / "style.css").read_text(encoding="utf-8")
    assert 'class="sl2-blocked-note hidden" id="sl2-traf-note"' in html
    assert "Arming is unavailable: file a packet rule first." in js
    assert ".sl2-blocked-note" in css
    assert "button:disabled" in css


def test_the_revoked_filter_is_a_designed_control_not_a_native_box():
    html = (WEB / "index.html").read_text(encoding="utf-8")
    css = (WEB / "style.css").read_text(encoding="utf-8")
    assert 'class="sl2-check"' in html
    assert ".sl2-show input:checked + .sl2-check" in css
    assert "input:focus-visible + .sl2-check" in css
