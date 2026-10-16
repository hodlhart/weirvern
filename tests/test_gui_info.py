"""The "i" in a circle: one affordance, everywhere, and it really opens something.

The operator asked for it by name (2026-10-16): "use i in a circle ... users can click and get
more information". The failure classes this file makes catchable are this project's well-known
ones: a control that renders and does nothing, a panel with no button, a button pointing at a
panel that does not exist, and the old "?" glyph surviving beside the new one so readers have to
learn the same habit twice. The click behaviour itself is held by the jsdom harness (which
executes the shipping JS); this file holds the contract that needs no browser.

The panel text itself is verified by eye once and by nobody after that -- deliberately: prose
cannot be machine-checked for usefulness, and a test that pretended to would just pin adjectives.
"""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / "weirvern" / "admin" / "web"


def test_every_info_button_points_at_a_real_panel():
    html = (WEB / "index.html").read_text(encoding="utf-8")
    ids = set(re.findall(r'id="([^"]+)"', html))
    targets = re.findall(r'class="info-btn" data-info="([^"]+)"', html)
    assert len(targets) >= 8, f"only {len(targets)} view-level explainers carry the button"
    missing = [t for t in targets if t not in ids]
    assert not missing, f"these 'i' buttons open panels that do not exist: {missing}"
    for t in targets:
        before = html.split(f'id="{t}"')[0]
        assert before[-220:].find('class="info-text hidden"') != -1, (
            f"the panel behind {t} is not an info-text block (id reuse?)"
        )


def test_the_wiring_is_in_boot_and_idempotent_by_construction():
    js = (WEB / "app.js").read_text(encoding="utf-8")
    assert "function wireInfoButtons(" in js
    assert re.search(r"async function boot\(\)\s*\{[^}]*?wireInfoButtons\(\);", js), (
        "the buttons are static markup; boot() must wire them before anything renders"
    )
    assert "btn.dataset.wired" in js, "a second boot would double-toggle every panel"


def test_no_tab_leads_with_a_wall_of_prose():
    """THE OPERATOR'S RULE (2026-10-16): "debloat the tabs more by using i with circles more".

    A tab should open on data. The reading guidance belongs behind the circle beside the heading --
    which is what the circle is FOR. This pins the shape rather than the wording: a static
    paragraph (no id, so nothing rewrites it) longer than a couple of lines is prose that belongs in
    a panel, not in the flow of the page. Paragraphs WITH an id are exempt on purpose: those are the
    notes the JS fills in ("click any bar..."), which change with the operator's selection and must
    stay where the selection happens.
    """
    html = (WEB / "index.html").read_text(encoding="utf-8")
    walls = []
    for m in re.finditer(r'<p class="muted">(.*?)</p>', html, re.S):
        text = " ".join(m.group(1).split())
        if len(text) > 220:
            walls.append(text[:70] + "...")
    assert not walls, (
        "these paragraphs are still standing in the tab instead of behind an 'i': " + str(walls)
    )
    buttons = re.findall(r'class="info-btn" data-info="([^"]+)"', html)
    assert len(buttons) >= 20, (
        f"only {len(buttons)} explainers carry the circle; the tabs were debloated to put the "
        "reading guidance behind it, and a rebuild that drops them puts the prose back"
    )


def test_the_old_question_mark_glyph_is_gone():
    """Two glyphs for one habit means readers learn it twice; the operator asked for the circle-i."""
    html = (WEB / "index.html").read_text(encoding="utf-8")
    assert ">?</button>" not in html, "a help control still renders with the old glyph"
    js = (WEB / "app.js").read_text(encoding="utf-8")
    assert 'text: "?"' not in js, "the settings rows still render the old glyph"


def test_the_settings_rows_keep_their_own_help_buttons():
    """The rows' explainers are not replaced by the new mechanism -- they render from the
    SERVER's help text per row, which the harness clicks. This pins that both affordances
    coexist: circle-i beside titles (markup-driven) and circle-i on rows (payload-driven)."""
    js = (WEB / "app.js").read_text(encoding="utf-8")
    assert 'class: "setting-help-btn", text: "i"' in js
