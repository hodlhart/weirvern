"""Pins for the design system: the canon ratchet, the ledger, and the responsive audit.

These do not judge taste — they keep the law honest. If one of them fails, the console and
`docs/design/` have disagreed, and the disagreement is the defect.
"""
from __future__ import annotations

import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs" / "design"
WEB = ROOT / "weirvern" / "admin" / "web"

TAB = re.compile(r'data-view="([a-z0-9-]+)"\s*>([^<]+)<')
SECTION = re.compile(r'id="view-([a-z0-9-]+)"')


def _lint_module():
    spec = importlib.util.spec_from_file_location("canon_lint", ROOT / "scripts" / "canon_lint.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load scripts/canon_lint.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_canon_lint_is_green():
    """The ratchet passes against the committed baseline."""
    proc = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "canon_lint.py")],
        capture_output=True, text=True, cwd=ROOT, timeout=120,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "no new debt" in proc.stdout


def test_ratchet_flags_new_debt():
    """A ratchet that cannot go red is decoration, not a gate."""
    mod = _lint_module()
    canon = json.loads((DOCS / "canon.json").read_text(encoding="utf-8"))
    current = mod.collect(canon)
    # Pretend the baseline was better than reality on one value, the way a new violation appears.
    baseline = {kind: dict(counts) for kind, counts in current.items()}
    first_kind = next(k for k, v in baseline.items() if v)
    first_value = next(iter(baseline[first_kind]))
    baseline[first_kind][first_value] = 0
    new, _paid = mod.compare(current, baseline)
    assert any(first_value in line for line in new), "the ratchet did not notice a new violation"


def test_ledger_covers_every_tab_and_section():
    """No surface without a ledger entry, and no silent label drift."""
    ledger = json.loads((DOCS / "ledger.json").read_text(encoding="utf-8"))
    known = {v["id"]: v for v in ledger["views"]}
    html = (WEB / "index.html").read_text(encoding="utf-8")

    for vid, label in TAB.findall(html):
        assert vid in known, f"tab {vid!r} is not in the ledger"
        assert known[vid]["label"] == label.strip(), (
            f"tab {vid!r} shows {label.strip()!r}, ledger says {known[vid]['label']!r}"
        )
        assert known[vid]["tab"] is True, f"tab {vid!r} is ledgered as tab:false"

    tab_ids = {vid for vid, _ in TAB.findall(html)}
    section_ids = set(SECTION.findall(html))
    for vid in section_ids:
        assert vid in known, f"section #view-{vid} is not in the ledger"
    for vid, entry in known.items():
        if entry["tab"]:
            assert vid in tab_ids, f"ledger says {vid!r} is a tab; the markup has none"
        else:
            assert vid in section_ids, f"ledger says {vid!r} exists; the markup has no section"


def test_every_concept_has_one_owner_and_one_renderer():
    """The one-implementation rule: a concept may not have two homes."""
    ledger = json.loads((DOCS / "ledger.json").read_text(encoding="utf-8"))
    view_ids = {v["id"] for v in ledger["views"]}
    seen: set[str] = set()
    for c in ledger["concepts"]:
        assert c["canonical_id"] not in seen, f"duplicate canonical id {c['canonical_id']!r}"
        seen.add(c["canonical_id"])
        assert c["owned_by"] in view_ids, f"{c['concept']!r} is owned by unknown view {c['owned_by']!r}"
        assert c["renderer"].strip(), f"{c['concept']!r} has no renderer"
        assert c["labels"], f"{c['concept']!r} has no visible label"


def test_canon_numbers_are_coherent():
    """The canon's own arithmetic: a ramp that ramps, touch that does not contradict itself."""
    canon = json.loads((DOCS / "canon.json").read_text(encoding="utf-8"))
    ramp = canon["type"]["ramp_px"]
    assert ramp == sorted(ramp) and len(set(ramp)) == len(ramp), "the type ramp must ascend uniquely"
    assert canon["touch"]["primary_px"] >= canon["touch"]["secondary_floor_px"] >= 36
    widths = {w for w, _h in canon["responsive"]["review_widths"]}
    assert {1440, 820, 390} <= widths, "the review set must include desktop, tablet and phone"
    assert len(canon["frame"]["component_cap"]) == 8
    assert canon["budgets"]["row_verbs_per_view_max"] == 0


def test_audit_script_is_safe_and_compiles():
    """The audit must never carry a credential in source, and must be valid Python."""
    src = (ROOT / "scripts" / "responsive_audit.py").read_text(encoding="utf-8")
    compile(src, "responsive_audit.py", "exec")
    assert "token-file" in src
    # A token literal would look like a long random assignment; the script may only read one.
    assert not re.search(r'(TOKEN|token)\s*=\s*"[A-Za-z0-9]{20,}"', src)


def _rule_block(css: str, selector: str) -> str:
    """The first `selector { ... }` block, brace-counted (comments stripped first)."""
    css = re.sub(r"/\*.*?\*/", "", css, flags=re.S)
    start = css.find(selector + " {")
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


def test_the_shell_wraps_instead_of_widening_the_page():
    """US-A1: a flex row that cannot wrap made every view 257px too wide at 820."""
    css = (WEB / "style.css").read_text(encoding="utf-8")
    for selector in ("header", ".status"):
        block = _rule_block(css, selector)
        assert block, f"the {selector} rule disappeared"
        assert "flex-wrap: wrap" in block, (
            f"{selector} must wrap: without it the shell sets a page width above the 720 "
            "breakpoint and every view scrolls sideways on a tablet"
        )


def test_touch_controls_are_forty_four():
    """C-9 on the breakpoint that a finger uses: one button size, and it clears 44px."""
    css = (WEB / "style.css").read_text(encoding="utf-8")
    block = css[css.find("@media (max-width: 720px)") :]
    assert block, "the phone breakpoint disappeared"
    m = re.search(r"--btn-h:\s*(\d+)px", block)
    assert m, "the phone breakpoint no longer sets the button height"
    assert int(m.group(1)) >= 44, (
        f"touch buttons are {m.group(1)}px; canon C-9 wants 44 on touch (density loses to the thumb)"
    )


def test_network_scope_cards_are_not_rendered_as_single_line_buttons():
    """Network coverage readings are a block, not a row.

    The cards are <button> elements, so the global button system (inline-flex, centered,
    nowrap, fixed height) applies to them too. Without an explicit column layout the four
    readings run across one line and overlap the next card. Pin the opt-out.
    """
    css = (WEB / "style.css").read_text(encoding="utf-8")
    block = _rule_block(css, ".net-card")
    assert block, "the .net-card rule disappeared"
    for declaration in (
        "display: flex",
        "flex-direction: column",
        "height: auto",
        "white-space: normal",
    ):
        assert declaration in block, f".net-card lost `{declaration}`"


def test_every_tab_id_agrees_with_its_view_and_its_ledger_entry():
    """QA-1-D4: one name per surface, in the URL, the DOM and the label.

    The defect this pins: the inventory's tab said "Assets" while its id said `host`, so a
    script, a doc or the palette looking for the label could not find the surface.
    """
    import json
    import pathlib as _p
    import re as _re

    repo = _p.Path(__file__).resolve().parents[1]
    html = (repo / "weirvern/admin/web/index.html").read_text(encoding="utf-8")
    ledger = json.loads((repo / "docs/design/ledger.json").read_text(encoding="utf-8"))

    tabs = _re.findall(r'<button class="tab[^"]*" data-view="([^"]+)">([^<]+)</button>', html)
    # 14 since Normalize joined the Operations group (operator, 2026-11-19); 13 since Blocks
    # became a Sluice drill (2026-10-21), when the old Blocked tab was a second rules surface.
    assert len(tabs) == 14, len(tabs)
    for view_id, label in tabs:
        assert f'id="view-{view_id}"' in html, f"{view_id}: tab points at a view that does not exist"
        entry = next((v for v in ledger["views"] if v.get("id") == view_id), None)
        assert entry is not None, f"{view_id}: no ledger entry -- the surface is unowned"
        assert entry.get("label") == label.strip(), (
            f"{view_id}: tab says {label!r}, ledger says {entry.get('label')!r}"
        )


def test_there_is_one_auto_refresh_control_and_it_names_its_live_state():
    html = (WEB / "index.html").read_text()
    assert 'id="auto-toggle"' in html
    assert 'id="autorefresh"' not in html, "the duplicate checkbox came back"
    assert "live · 15s" in html, "the pill does not state the cadence"


def test_sluice_rule_rows_are_keyboard_operable():
    js = (WEB / "sluice.js").read_text()
    # The rule sentence is a real button, not a clickable row: one native control owns the
    # doorway, so Enter and Space work without a hand-rolled keydown handler.
    assert 'class: "sl2-rule-btn"' in js
    assert 'el("button"' in js
    assert 'addEventListener("click", () => openRuleSheet(rule))' in js


def test_the_gate_state_and_rule_counts_are_stated_once_with_their_owner():
    html = (WEB / "index.html").read_text()
    assert 'id="sl-state"' not in html, "the old duplicate gate state came back"
    assert html.count('id="sl2-traf-chip"') == 1
    assert html.count('id="sl2-fleet"') == 1
    js = (WEB / "sluice.js").read_text()
    # The heading lives in the markup now (0.23.74): the JS renders rows into it, so the phrase
    # appears exactly once on the page and not at all in the renderer.
    assert html.count("Fleet packet gates") == 1
    assert "Fleet packet gates" not in js
    # The stat tiles were deleted with the 2026-11-20 rebuild; the same fact is stated in the
    # evidence sentence ("N of M stored packet rules installed") instead of a tile beside it.
    assert "stored packet rule" in js, "the Traffic Gate lost its installed/stored rule count"


def test_chart_colours_are_tokens_not_hex_in_javascript():
    js = "\n".join(p.read_text() for p in sorted(WEB.glob("*.js")))
    assert not re.search(r"#[0-9a-fA-F]{3,8}\b", js), "a chart colour bypassed the series token"
    css = (WEB / "style.css").read_text()
    assert "--series-1:" in css and "--series-10:" in css


def test_the_type_ramp_is_used_not_declared():
    css = (WEB / "style.css").read_text()
    assert not re.search(r"font-size:\s*[0-9.]+px", css), "a raw font-size came back"
    for token in ("--fs-1", "--fs-2", "--fs-3", "--fs-4", "--fs-6"):
        assert token in css, f"{token} is declared but never used"
