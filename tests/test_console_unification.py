"""The console unifications (audit, 2026-11-20): three things the audit found.

These are pins, not taste tests. Each one states the rule and fails if the console drifts back
to the state the audit measured:

  1. ONE EMPTY STATE, THREE FACTS. Seven classes collapsed "nothing exists", "nothing matches
     the filters" and "the read failed" into one muted look. The component states the fact in
     words; a filtered empty names the filters; a failed read says it is a failure.
  2. SHEETS VS MODALS. The right-side sheet is the only detail surface. A centre modal is for
     a destructive/irreversible confirmation (target, blast radius, reason) and nothing else.
  3. ONE CARD ANATOMY. Six card classes shared no padding, radius or heading rhythm. One
     anatomy, one spacing scale; a variant may change layout or carry a status edge only.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / "weirvern" / "admin" / "web"


def _read(name: str) -> str:
    return (WEB / name).read_text(encoding="utf-8")


def _js() -> str:
    return "\n".join(p.read_text(encoding="utf-8") for p in sorted(WEB.glob("*.js")))


def _rule_block(css: str, selector: str) -> str:
    """The first `selector { ... }` block at the start of a line, brace-counted.

    The line-start anchor matters: `.card, .gate-card { ... }` contains the substring
    `.gate-card {`, and a loose find would measure the shared tier rule instead of the
    variant and report the anatomy's own padding as the variant's.
    """
    css = re.sub(r"/\*.*?\*/", "", css, flags=re.S)
    match = re.search(rf"(?m)^{re.escape(selector)} \{{", css)
    start = match.start() if match else -1
    if start < 0:
        return ""
    open_at = css.find("{", start)
    depth = 0
    for i in range(open_at, len(css)):
        if css[i] == "{":
            depth += 1
        elif css[i] == "}":
            depth -= 1
            if depth == 0:
                return css[open_at : i + 1]
    return ""


# ── 1. one empty state, three facts ─────────────────────────────────────────────────────────

def test_the_component_has_exactly_three_states_and_states_them_in_words():
    js = _read("app.js")
    assert "function emptyState(opts = {})" in js, "the one empty-state component is gone"
    assert "EMPTY_STATE_WORDS" in js
    for state, word in (("none", "Nothing here yet"), ("filtered", "Nothing matches"),
                        ("failed", "Could not read")):
        assert f'{state}: "{word}"' in js, f"the {state} state lost its word"
    assert '"data-state": state' in js, "the state is not on the DOM for the style/audit"
    assert "function emptyStateCell(cols, opts)" in js, "tables cannot use the component"
    assert "function emptyRow(tbody, cols, message, action, opts = {})" in js


def test_a_filtered_empty_names_the_filters_and_a_failure_says_so():
    js = _read("app.js")
    assert "function activeFilterLabels(view)" in js, "the filtered state cannot name its filters"
    assert "empty-state-filters" in js and "Active filter" in js
    # The two views whose filters are the usual cause of a false "nothing here".
    assert 'activeFilterLabels("anomalies")' in js
    assert 'activeFilterLabels("network")' in _read("assets.js")
    # A failed read carries the failed state, not the "none" state.
    assets = _read("assets.js")
    assert 'state: "failed"' in assets
    assert '"The graph read failed — no edges were read."' in assets
    # The palette's "nothing matches" is a FILTERED state with the query named.
    assert 'state: "filtered"' in _read("palette.js")
    assert "search = " in _read("palette.js")


def test_the_seven_old_empty_classes_are_gone():
    js, html, css = _js(), _read("index.html"), _read("style.css")
    # Class USAGE (not the explanatory comment in app.js).
    for pattern in (r'class:\s*"empty"', r'class="empty"', r'class:\s*"chart-empty"',
                    r'class:\s*"net-peers-empty"', r'class:\s*"palette-empty"',
                    r'class:\s*"review-none"', r'class:\s*"wl-spark-empty"',
                    r'class:\s*"empty-act"'):
        assert not re.search(pattern, js + html), f"old empty class still used: {pattern}"
    # CSS RULES for the seven (a state word in a comment is fine; a selector is not).
    for selector in (".empty", ".chart-empty", ".net-peers-empty", ".palette-empty",
                     ".review-none", ".wl-spark-empty", ".empty-act"):
        assert not re.search(rf"^{re.escape(selector)}\s*\{{", css, re.M), \
            f"{selector} still has its own rule"
    assert re.search(r"^\.empty-state\s*\{", css, re.M), "the one component has no style"
    assert re.search(r'^\.empty-state\[data-state="failed"\]', css, re.M), \
        "a failed read cannot look different from an absence"


def test_a_measured_value_is_not_dressed_as_an_empty_state():
    """The fleet sparkline cell states a flow count or a dash; it is a value, not a void."""
    assert "spark-value" in _read("weirlings.js")
    assert "spark-value" in _read("style.css")


# ── 2. sheets vs modals ─────────────────────────────────────────────────────────────────────

def test_a_detail_object_opens_a_sheet_not_a_centre_modal():
    html = _read("index.html")
    at = html.index('id="bl-detail-card"')
    tag = html[html.rindex("<div", 0, at): html.index(">", at)]
    assert "card sheet" in tag, "the blocked-hit detail is not the house sheet"
    assert 'role="dialog"' in tag and 'aria-modal="true"' in tag
    assert 'aria-hidden="true"' in tag
    blocked = _read("blocked.js")
    assert "openSheet(els.card)" in blocked
    assert "openModal(els.card)" not in blocked, "a detail object is still a centre modal"
    assert "closeModal(els.card)" not in blocked


def test_a_centre_modal_is_only_a_destructive_confirmation():
    """The remaining openModal call sites are confirmations with a reason, not detail surfaces."""
    js = _js()
    # A detail renderer that moved into the modal shell again would carry a "-detail-" id.
    assert not re.search(r"openModal\([^)]*detail", js), \
        "a detail surface was moved back into the centre modal"
    # The two confirmation paths: the shared destructive dialog and the gate-change form.
    assert "function confirmDestructive(opts)" in js
    confirm = _read("sluice.js")
    assert 'openModal(node)' in confirm and 'id="sl2-confirm-reason"' in _read("index.html")


def test_the_sheet_standard_is_the_only_overlay_implementation():
    sheets = _read("sheets.js")
    for fn in ("function openSheet(", "function closeSheet(", "function wireSheet("):
        assert fn in sheets
    for name in ("blocked.js", "weirlings.js", "sluice.js", "scan.js"):
        js = _read(name)
        assert "sheet-scrim hidden" not in js, f"{name} built a private scrim"
        assert 'e.key === "Escape"' not in js or name == "scan.js", \
            f"{name} still binds its own sheet Escape"


# ── 3. one card anatomy ────────────────────────────────────────────────────────────────────

CARD_CLASSES = (".card", ".ext-card", ".gate-card", ".net-card", ".nz-card", ".rp-card")


def test_every_card_surface_shares_one_anatomy_and_one_scale():
    css = _read("style.css")
    for token in ("--card-pad: 20px", "--card-pad-tight: 10px", "--card-gap: 16px",
                  "--card-tight: 8px", "--card-radius: 8px"):
        assert token in css, f"the card scale lost {token}"
    shared = re.search(
        r"\.card, \.ext-card, \.gate-card, \.net-card, \.nz-card, \.rp-card \{(.*?)\}",
        css, re.S)
    assert shared, "the six card classes no longer share one anatomy"
    for declaration in ("background: var(--surface)", "border-radius: var(--card-radius)",
                        "box-shadow: var(--shadow-low)"):
        assert declaration in shared.group(1), f"the anatomy lost `{declaration}`"
    # The header/body/footer/action rhythm exists once.
    assert re.search(r"^\.card-head\s*\{", css, re.M)
    assert re.search(r"^\.card-foot, \.card-actions\s*\{", css, re.M)


def test_a_variant_changes_layout_not_its_own_padding_or_radius():
    css = _read("style.css")
    for selector in (".ext-card", ".gate-card", ".net-card", ".nz-card", ".rp-card"):
        block = _rule_block(css, selector)
        assert block, f"{selector} disappeared"
        assert "padding:" not in block, f"{selector} invents its own padding"
        assert "border-radius:" not in block, f"{selector} invents its own radius"


def test_the_anatomy_is_documented():
    docs = ROOT / "docs" / "design"
    cards = (docs / "cards.md").read_text(encoding="utf-8")
    for phrase in ("header", "body", "footer", "action row", "--card-pad",
                   "layout", "variant"):
        assert phrase.lower() in cards.lower(), f"cards.md does not cover {phrase!r}"
    empties = (docs / "empty-states.md").read_text(encoding="utf-8")
    for phrase in ("nothing here yet", "nothing matches", "could not read", "filters"):
        assert phrase.lower() in empties.lower(), f"empty-states.md does not cover {phrase!r}"
    sheets = (docs / "sheets.md").read_text(encoding="utf-8")
    assert "the only detail surface" in sheets.lower(), \
        "sheets.md does not state the one-detail-surface rule"
