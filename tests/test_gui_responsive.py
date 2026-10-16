"""The GUI's responsive contract: one console for a desk and for a pocket (2026-10-16).

jsdom has no layout engine and its getComputedStyle ignores @media rules (measured), so the
breakpoint BEHAVIOUR is verified in a real browser; the jsdom harness holds the base rules and
the JS half (the per-table scroll boxes). What a machine must hold here is the source contract,
so deleting the responsive section fails before a phone finds it. Each assertion names the
failure it makes catchable: iOS zooming the page on every tap (missing 16px controls), tables
dragging the page sideways (missing scroll boxes), and a settings control sitting off-screen
from its label (missing stacking).
"""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / "weirvern" / "admin" / "web"


def _css() -> str:
    return (WEB / "style.css").read_text(encoding="utf-8")


def test_the_viewport_meta_declares_a_device_width():
    """Without this one line a phone renders the page at ~980px wide and every rule below it
    never fires -- 'mobile support' would be a fiction."""
    html = (WEB / "index.html").read_text(encoding="utf-8")
    assert 'name="viewport"' in html
    assert "width=device-width" in html


def test_the_stylesheet_carries_both_breakpoints():
    css = _css()
    assert "@media (max-width: 720px)" in css, "the phone layout is unguarded without it"
    assert "@media (max-width: 420px)" in css, "the narrowest phones still in service"


def test_the_phone_block_carries_its_three_load_bearing_rules():
    """16px fields (iOS Safari zooms the whole page under that on focus, and every tap after
    that lands wrong), stacked settings rows (the control must not sit at the far edge of a
    phone-width row), and a shorter force-map canvas (the 460px desktop height has no
    phone-sized value)."""
    phone = _css().split("@media (max-width: 720px)")[1]
    assert "font-size: 16px" in phone
    assert ".setting { flex-direction: column" in phone
    assert ".graph { height:" in phone
    # The 16px rule must name each form family's own base selector: a bare `input` loses to
    # `.controls input` on specificity alone (measured in a browser: the first draft left the
    # search fields at 13px), so a future "simplification" back to `input { ... }` would
    # silently restore the iOS zoom with every test still green.
    assert ".controls input" in phone
    assert '#view-sluice input[type="text"]' in phone


def test_the_grid_track_can_never_exceed_the_screen():
    """`minmax(380px, 1fr)` overflowed every viewport narrower than the track's own minimum --
    a phone in portrait, a fold, a split window -- before any table was involved."""
    css = _css()
    assert "minmax(min(380px, 100%), 1fr)" in css
    assert "minmax(380px, 1fr)" not in css, "the bare 380px minimum is the overflow this caps"


def test_the_nav_strip_scrolls_and_its_tabs_do_not_squash():
    css = _css()
    assert "nav::-webkit-scrollbar" in css, "the nav must be a scrolling strip"
    assert re.search(r"\.tab\s*\{[^}]*flex:\s*none", css), (
        "tabs keep their intrinsic width inside the strip"
    )


def test_the_table_scroll_box_exists_in_both_halves():
    """The wrapper is added by wrapTables() in app.js and styled as .tablewrap: the JS and the
    CSS must ship together, or the box exists with nothing to scroll it (or vice versa)."""
    assert re.search(r"\.tablewrap\s*\{[^}]*overflow-x:\s*auto", _css())
    js = (WEB / "app.js").read_text(encoding="utf-8")
    assert "function wrapTables(" in js
    assert re.search(r"async function boot\(\)\s*\{[^}]*?wrapTables\(\);", js), (
        "wrapTables() must be called from boot(), before the first render"
    )
