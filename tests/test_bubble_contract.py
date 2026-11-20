"""THE BUBBLE RATCHET: one pill geometry, and no legacy pill class anywhere.

The operator pass (2026-11-20) unified four ad-hoc pill vocabularies -- `.chip`, `.dc-chip`,
`.rp-sev-chip`, `.pill` -- onto `.bubble.state` (a still reading) and `.bubble.filter` (pressable,
aria-pressed required). This file is the ratchet that keeps them from growing back:

  * no legacy pill class is attached by any web asset, and none survives in the live DOM;
  * ONE `.bubble` base rule owns radius, padding, type and height, and no variant re-declares
    them (the `×` remove control used a larger font and made remove-pills 2px taller);
  * the computed geometry swept across every view by `scripts/jsdom_render.js` is a single
    signature -- that check is pinned here so it cannot be deleted quietly.

The computed sweep lives in the harness because only an executed stylesheet can answer it; this
file holds the source contract it measures against.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / "weirvern" / "admin" / "web"
LEGACY = {"chip", "dc-chip", "rp-sev-chip", "pill"}
# The one pill's numbers. A second set is how status and filter pills came to look like two
# systems on adjacent tabs.
BASE = {
    "padding": "4px 8px",
    "border-radius": "999px",
    "font-size": "var(--fs-1)",
    "line-height": "1",
    "height": "auto",
}


def _strip_css_comments(css: str) -> str:
    return re.sub(r"/\*.*?\*/", "", css, flags=re.S)


def _class_tokens(text: str):
    """Every class token a markup/JS file attaches, from class="..." and class: "..." / `...`."""
    for m in re.finditer(r'class(?:Name)?\s*(?:=|:)\s*[`"\']([^`"\']*)[`"\']', text):
        yield from m.group(1).split()


def _rules(css: str):
    """(selector, declarations, inside_media) for every innermost rule."""
    out, stack, buf, media = [], [], "", 0
    for ch in css:
        if ch == "{":
            sel = buf.strip()
            stack.append(sel)
            if sel.startswith("@media"):
                media += 1
            buf = ""
        elif ch == "}":
            sel = stack.pop() if stack else ""
            if sel.startswith("@media"):
                media = max(0, media - 1)
            elif sel:
                out.append((sel, buf.strip(), media > 0))
            buf = ""
        else:
            buf += ch
    return out


def test_no_legacy_pill_class_is_attached_by_any_web_asset():
    offenders = []
    for path in sorted(WEB.glob("*.js")) + [WEB / "index.html"]:
        text = path.read_text(encoding="utf-8")
        bad = sorted({t for t in _class_tokens(text) if t in LEGACY})
        if bad:
            offenders.append(f"{path.name}: {bad}")
    assert not offenders, (
        "a legacy pill class is still attached; the console has one pill vocabulary "
        "(.bubble.state / .bubble.filter):\n  " + "\n  ".join(offenders))


def test_no_legacy_pill_selector_survives_in_the_stylesheet():
    css = _strip_css_comments((WEB / "style.css").read_text(encoding="utf-8"))
    # \b keeps `.chips` (the layout container) legal -- it is not a pill.
    hits = sorted(set(re.findall(r"\.(chip|dc-chip|rp-sev-chip|pill)\b", css)))
    assert not hits, f"the stylesheet still styles a retired pill: {hits}"


def test_one_bubble_rule_owns_the_geometry():
    css = _strip_css_comments((WEB / "style.css").read_text(encoding="utf-8"))
    bases = [decls for sel, decls, _media in _rules(css) if sel == ".bubble"]
    assert len(bases) == 1, f"expected one `.bubble` base rule, found {len(bases)}"
    for prop, value in BASE.items():
        assert re.search(rf"(?<![-\w]){re.escape(prop)}\s*:\s*{re.escape(value)}", bases[0]), (
            f"the one bubble geometry lost `{prop}: {value}`")
    assert "border: 1px solid currentColor" in bases[0]


def test_no_bubble_variant_invents_its_own_size():
    """Radius/padding/type/height belong to the base. The `×` is the one sanctioned exception:
    it is icon-shaped, but it INHERITS the pill's type so it cannot change the box height."""
    css = _strip_css_comments((WEB / "style.css").read_text(encoding="utf-8"))
    size_props = ("padding", "border-radius", "font-size", "height", "line-height")
    offenders = []
    for sel, decls, in_media in _rules(css):
        if ".bubble" not in sel or "::" in sel:
            continue
        if sel in (".bubble", ".bubble .bubble-x"):
            continue
        # A PHONE RULE MAY TRADE PADDING FOR THE 44px TOUCH FLOOR (and only that): the control
        # is still the same pill, raised to the same sanctioned minimum every control gets.
        if in_media and "min-height: 44px" in decls:
            continue
        for prop in size_props:
            if re.search(rf"(?<![-\w]){prop}\s*:", decls):
                offenders.append(f"{sel} sets {prop}")
    assert not offenders, (
        "a bubble variant re-declared the one geometry: " + "; ".join(offenders))
    x_rule = next(decls for sel, decls, _media in _rules(css) if sel == ".bubble .bubble-x")
    assert "font-size: inherit" in x_rule, (
        "the remove control must inherit the pill's type -- a larger × grows the box")


def test_the_computed_sweep_is_still_installed_in_the_harness():
    """The source pins above cannot see the cascade. The harness walks every view and measures
    every `.bubble`; this pin keeps that sweep (and its no-legacy-in-DOM companion) in CI."""
    harness = (ROOT / "scripts" / "jsdom_render.js").read_text(encoding="utf-8")
    assert "the console has one bubble geometry in every view" in harness
    assert "no legacy pill class survives in the live DOM" in harness
    for prop in ("borderTopLeftRadius", "paddingTop", "paddingRight", "paddingBottom",
                 "paddingLeft", "height", "fontSize"):
        assert f"cs.{prop}" in harness, f"the sweep no longer measures {prop}"
