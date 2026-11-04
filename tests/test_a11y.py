"""TH-6: the accessibility and polish guarantees, pinned at the source level.

Each assertion replaces a promise with a test: the sweep that added these could silently
lose one of them in a later rewrite, and nothing else would notice (a missing focus ring
is invisible until a keyboard user finds it).
"""
import re
from pathlib import Path

WEB = Path(__file__).resolve().parents[1] / "weirvern" / "admin" / "web"


def _css() -> str:
    return (WEB / "style.css").read_text()


def _html() -> str:
    return (WEB / "index.html").read_text()


def test_the_ua_is_told_the_page_is_dark():
    root = _css()[_css().index(":root {"):_css().index("\n}", _css().index(":root {"))]
    assert "color-scheme: dark" in root


def test_a_visible_focus_ring_exists_and_is_the_documented_exception():
    css = _css()
    assert re.search(r":focus-visible \{ outline: none; box-shadow: 0 0 0 2px var\(--accent\); \}", css), \
        "the base focus-visible ring changed shape -- update this pin and docs/theme.md"
    # every control that opts its own outline out owns a keyboard ring of its own
    for sel in ("#palette-input:focus-visible", ".gate-field input:focus-visible"):
        assert sel in css, f"{sel} lost its companion ring"


def test_reduced_motion_neutralises_animation_everywhere():
    assert "prefers-reduced-motion: reduce" in _css()
    block = _css()[_css().index("prefers-reduced-motion"):]
    assert "*, *::before, *::after" in block[:200]


def test_scrollbars_are_themed_on_every_scrolling_surface():
    css = _css()
    for surface in ("html {", "nav { overflow-x: auto;", ".sheet, #palette-results {"):
        idx = css.index(surface)
        chunk = css[idx:idx + 260]
        assert "scrollbar-color" in chunk, f"{surface} scrolls without a themed scrollbar"


def test_staged_and_apply_status_are_announced():
    html = _html()
    for el_id in ("st-stage-note", "st-apply-results"):
        m = re.search(rf'id="{el_id}"[^>]*>', html)
        assert m, f"{el_id} vanished"
        assert 'aria-live="polite"' in m.group(0) and 'role="status"' in m.group(0), \
            f"{el_id} stopped announcing changes"


def test_no_hex_lives_outside_the_root_block_except_the_two_documented_ones():
    """docs/theme.md section 8's rule, as a test: tokens are the API. The allowed exceptions
    are the focus ring and the chip recipe's #fff lightening -- anything else is a new colour
    smuggled in past the token table."""
    css = _css()
    start = css.index(":root {")
    root = css[start:css.index("\n}", start)]
    rest = css[:start] + css[start + len(root):]
    found = set(re.findall(r"#[0-9a-fA-F]{3,8}", rest))
    assert found <= {"#66a8ff", "#fff"}, f"un-tokened colours appeared: {sorted(found)}"
    # and the legacy var()-fallbacks are gone (the sweep that removed them)
    assert not re.search(r"var\(--[a-z0-9-]+,\s*#", rest), "var() hex fallbacks crept back in"


def test_theme_doc_carries_the_phase_3_recipes_and_the_a11y_section():
    doc = Path(__file__).resolve().parents[1] / "docs" / "theme.md"
    text = doc.read_text()
    for needle in ("Command palette", "Grouped nav", "Micro sparkline",
                   "Phase 3 — LANDED", "## 9. Accessibility guarantees"):
        assert needle in text, f"theme.md lost: {needle}"
