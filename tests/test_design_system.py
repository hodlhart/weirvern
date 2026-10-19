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
    # 14 since Identity was folded into Assets (operator, 2026-10-19).
    assert len(tabs) == 14, len(tabs)
    for view_id, label in tabs:
        assert f'id="view-{view_id}"' in html, f"{view_id}: tab points at a view that does not exist"
        entry = next((v for v in ledger["views"] if v.get("id") == view_id), None)
        assert entry is not None, f"{view_id}: no ledger entry -- the surface is unowned"
        assert entry.get("label") == label.strip(), (
            f"{view_id}: tab says {label!r}, ledger says {entry.get('label')!r}"
        )
