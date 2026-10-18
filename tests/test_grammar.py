"""US-4 pins: the click grammar -- cues at rest, one vocabulary, no dead pointers.

Documented in docs/theme.md §10. These pins keep the three promises checkable:
(1) the entity-link cue is SINGLE-SOURCED and visible at rest; (2) every `cursor: pointer`
in the stylesheet belongs to something that actually acts (the sweep); (3) the specific
affordances this card fixed stay fixed (the always-expanding count cell, the inert
'Block unavailable' text, the palette's visible entry).
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / "weirvern" / "admin" / "web"


def _css() -> str:
    css = (WEB / "style.css").read_text()
    return re.sub(r"/\*.*?\*/", "", css, flags=re.S)  # comments carry braces; strip first


def _rules(css: str) -> list[tuple[str, str]]:
    out = []
    for sel, body in re.findall(r"([^{}]+)\{([^{}]*)\}", css):
        out.append((" ".join(sel.split()), body))
    return out


def test_the_grammar_is_written_down():
    doc = (ROOT / "docs" / "theme.md").read_text()
    assert "## 10. The click grammar" in doc, "the grammar lost its home in docs/theme.md"
    for token in (".dcell", ".link", "tr.clickable", ".dc-row", ".expander", ".chip.act",
                  "#palette-btn", "Hover only amplifies"):
        assert token in doc, f"the grammar section no longer names {token}"


def test_the_entity_cue_is_single_sourced_and_at_rest():
    rules = _rules(_css())
    cue = [(s, b) for s, b in rules
           if "cursor: pointer" in b and ("dcell" in s or re.search(r"(^|[ ,])\.link($|[ ,:])", s))]
    assert len(cue) == 1, (
        f"the entity-link cue must be ONE rule, found {len(cue)}: {[s for s, _ in cue]}")
    sel, body = cue[0]
    assert "td.dcell" not in sel and "div.dcell" not in sel, \
        "per-element copies are how this drifted the first time"
    assert "color: var(--accent)" in body, "the cue lost its accent colour"
    assert "border-bottom: 1px dotted" in body, \
        "the cue must be visible AT REST (dotted underline), not on hover only"
    assert "cursor: pointer" in body


def test_the_pointer_sweep_no_dead_pointers():
    """Every cursor:pointer in the stylesheet belongs to an interactive vocabulary token.

    The failure mode: a rule that sets a pointer with no handler anywhere -- the element
    reads clickable and does nothing (the audit's '(a) looks-clickable-but-is-not' list).
    """
    allowed = (
        "button", ".review-act", ".user-role", ".user-act", ".icon-btn", ".sl-rule-row",
        ".zk-bar", ".tile", ".sheet-close", ".crumb", ".palette-row", ".clickable",
        ".dc-row", ".dcell", ".link", ".expander", ".chip.act", ".pager-btn",
        ".stat.clickable", ".dc-chip-x", ".tr-panel button", "h2.acc", ".modal-x",
        ".info-btn", ".graph", ".gate-field", ".sev-tiles",
        ".gate-linkish", ".setting-help-btn", ".setting-toggle-label",
        # A native disclosure is interactive: its own summary opens it (US-A2).
        "summary",
    )
    offenders = []
    for sel, body in _rules(_css()):
        if "cursor: pointer" not in body:
            continue
        if not any(tok in sel for tok in allowed):
            offenders.append(sel)
    assert not offenders, (
        "cursor: pointer on selectors with no interactive vocabulary: " + "; ".join(offenders))


def test_detail_rows_carry_their_cue():
    """DNS Q/A rows and Discover's feeds open on click; they had NO css rule at all."""
    css = _css()
    assert ".dc-row { cursor: pointer; }" in " ".join(css.split()), \
        "the detail-row cue vanished (rows open with no signifier again)"
    assert ".dc-row:hover" in css, "hover must amplify the row cue"


def test_a_bare_chip_never_carries_the_pointer():
    for sel, body in _rules(_css()):
        if "cursor: pointer" in body and ".chip" in sel and ".act" not in sel:
            raise AssertionError(f"bare status chip with a pointer: {sel}")
    """(The positive half lives in tests/test_clicks.py: .chip.act carries the cues.)"""


def test_the_count_cell_expands_for_every_n():
    src = (WEB / "app.js").read_text()
    assert 'class: "num dcell expander"' in src, \
        "the count cell lost its at-rest disclosure cue"
    assert '"aria-expanded": "false"' in src
    seg = src.split("function anToggleOccurrences(", 1)[1].split("\nfunction ", 1)[0]
    assert 'setAttribute("aria-expanded", "true")' in seg
    assert 'setAttribute("aria-expanded", "false")' in seg, \
        "collapse must flip the cue back"


def test_the_gate_unavailable_text_is_inert():
    src = (WEB / "app.js").read_text()
    seg = src.split('class: "gate-off", title: reason,', 1)[1].split("}));", 1)[0]
    assert "stopPropagation" in seg, \
        "text that cannot act must not inherit the row's click (it opened Evidence)"


def test_the_palette_has_a_visible_entry():
    html = (WEB / "index.html").read_text()
    assert 'id="palette-btn"' in html, "the palette is keyboard-only again"
    pal = (WEB / "palette.js").read_text()
    assert 'getElementById("palette-btn")' in pal and "paletteOpen()" in pal, \
        "the palette button exists but nothing opens on click"
