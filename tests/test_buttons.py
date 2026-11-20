"""BTN-1: ONE button system.

The console grew button scales ad hoc: `.small`, `.review-act`, `.tab`, `.pager-btn`,
`.info-btn`, a `button.small` override inside Sluice, and a mobile block that re-sized four
classes independently -- three buttons in one row could be three heights. Size is not
hierarchy. Every button derives from ONE base, whose three numbers are CSS variables; a
variant may change colour, never size.

This test block-parses the stylesheet (media queries included) and fails when any button
selector invents a size of its own outside the documented exceptions.
"""
from __future__ import annotations

import re
from pathlib import Path

WEB = Path(__file__).resolve().parents[1] / "weirvern" / "admin" / "web"

BUTTON_CLASSES = (
    "primary", "danger", "quiet", "tab", "review-act", "pager-btn", "info-btn",
    "setting-help-btn", "user-act", "icon-btn", "sheet-close", "gate-linkish",
    "bubble", "wl-adopt",
)
# EXCEPTIONS with a reason, never convenience:
#   the base rule itself carries the size (it IS the system);
#   icon buttons and the pill's remove control are icon-shaped by nature;
#   the bubble is a pill (999px) whose height is still the base's variable;
#   `gate-linkish` is a button DELIBERATELY dressed as a text link (US-4's grammar).
SIZE_PROPS = ("font-size", "padding", "height", "min-height", "border-radius", "min-width")
ALLOW_SIZE = {"button", ".setting-help-btn", ".info-btn", ".bubble", ".bubble .bubble-x",
              ".gate-linkish", ".tab", ".icon-btn",
              #   .pager-btn: the pager is icon-sized at desktop; its mobile rule raises the
              #     width to the 44px touch floor, which is the same sanctioned exception the
              #     icon buttons carry, not a new button size.
              ".pager-btn"}


def _rules(css: str):
    """(selector, declarations, inside_media) for every innermost rule."""
    # COMMENTS FIRST: a prose comment mentioning a property must never be read as a rule.
    css = re.sub(r"/\*.*?\*/", "", css, flags=re.S)
    out, stack, buf, media_depth = [], [], "", 0
    i = 0
    while i < len(css):
        ch = css[i]
        if ch == "{":
            sel = buf.strip()
            buf = ""
            stack.append(sel)
            if sel.startswith("@media"):
                media_depth += 1
            i += 1
            continue
        if ch == "}":
            decls = buf.strip()
            sel = stack.pop() if stack else ""
            if sel.startswith("@media"):
                media_depth = max(0, media_depth - 1)
            elif sel:
                out.append((sel, decls, media_depth > 0))
            buf = ""
            i += 1
            continue
        buf += ch
        i += 1
    return out


def test_one_height_variable():
    css = (WEB / "style.css").read_text()
    assert css.count("--btn-h:") == 2, "one desktop declaration and one mobile override"
    base = css.split("\nbutton {", 1)[1].split("}", 1)[0]
    assert "height: var(--btn-h)" in base, "the base must take its height from the variable"
    assert "padding: 0 var(--btn-px)" in base
    assert "border-radius: var(--btn-r)" in base


def _button_token(sel: str) -> str | None:
    """The first compound in `sel` that is a button (element or a known class)."""
    for token in re.split(r"[\s>+~,]+", sel.strip()):
        t = token.strip()
        if not t:
            continue
        if t == "button" or re.match(r"^button[.:[]", t):
            return t
        classes = re.findall(r"\.([a-z0-9-]+)", t)
        if classes and classes[-1] in BUTTON_CLASSES:
            return t
    return None


def test_no_button_selector_invents_a_size():
    css = (WEB / "style.css").read_text()
    offenders = []
    for sel, decls, _media in _rules(css):
        sel = sel.strip()
        if "::" in sel:
            continue          # a pseudo-element is decoration, not the control
        token = _button_token(sel)
        if token is None:
            continue
        if sel in ALLOW_SIZE:
            continue
        for prop in SIZE_PROPS:
            if re.search(rf"(?<![-\w]){re.escape(prop)}\s*:", decls):
                offenders.append(f"{sel.strip()} sets {prop}")
    assert not offenders, (
        "these button selectors set their own size instead of deriving from the base: "
        + "; ".join(offenders))


def test_content_sized_button_panels_are_not_squeezed_into_the_button_height():
    """A tile is a panel that happens to be a button (BF-7, and the severity tiles).

    The base rule gives every button `height: var(--btn-h)` (28px) and `white-space: nowrap`.
    A tile carries a label and a 27px number -- more than 28px -- so the fixed height pushed
    the content out of the rounded panel on the live box (fleet tiles, then the severity
    tiles: "anomalies has the same issue as weirlings"). Every such panel sizes itself.
    """
    css = (WEB / "style.css").read_text()
    css = re.sub(r"/\*.*?\*/", "", css, flags=re.S)
    base = re.search(r"(?m)^button\s*\{([^}]*)\}", css)
    assert base and "--btn-h" in base.group(1), "the button base lost its height variable"
    panels = {
        "#wl-summary .stat": r"#wl-summary\s+\.stat\s*\{([^}]*)\}",
        ".sev-tiles .tile": r"\.sev-tiles\s+\.tile\s*\{([^}]*)\}",
    }
    for label, pattern in panels.items():
        rule = re.search(pattern, css)
        assert rule, f"{label} rule is gone"
        decls = rule.group(1)
        assert "height: auto" in decls, f"{label} inherits the 28px button height again"
        assert "white-space: normal" in decls, f"{label} inherits the button's nowrap"


def test_the_old_scales_are_gone():
    html = (WEB / "index.html").read_text()
    js = "\n".join(p.read_text() for p in sorted(WEB.glob("*.js")))
    css = (WEB / "style.css").read_text()
    assert 'class="small"' not in html and 'class: "small"' not in js, \
        "the `.small` scale survived somewhere in the markup or scripts"
    assert "button.small {" not in css
    assert "button.primary { padding" not in css, "a primary button still has its own size"


def test_the_vocabulary_is_closed():
    """Every button class in the markup is in the allowlist -- a new class means a new look,
    which means the system grew a second vocabulary."""
    html = (WEB / "index.html").read_text()
    js = "\n".join(p.read_text() for p in sorted(WEB.glob("*.js")))
    used = set()
    for m in re.finditer(r'class="([^"]*)"', html):
        for c in m.group(1).split():
            used.add(c)
    for m in re.finditer(r'class: "([a-z0-9 -]+)"', js):
        for c in m.group(1).split():
            used.add(c)
    buttonish = {c for c in used
                 if c in BUTTON_CLASSES or c in ("btn", "small", "large", "mini")}
    unknown = {c for c in buttonish if c not in BUTTON_CLASSES and c != "btn"}
    assert not unknown, f"unknown button classes: {sorted(unknown)}"
