"""US-8 pins: the palette as the console's search.

Entities from the query itself, recents that reflect the session, settings that expand before
they show, and an action that states its own unavailability. The harness drives the behaviour;
these pins hold the shape (a dropped regex or a silently swallowed click fails here first).
"""
from __future__ import annotations

from pathlib import Path

WEB = Path(__file__).resolve().parents[1] / "weirvern" / "admin" / "web"


def test_the_query_is_read_as_an_entity():
    src = (WEB / "palette.js").read_text()
    seg = src.split("function paletteEntityCommands(", 1)[1].split("\n}", 1)[0]
    for need in ("isIP", "isRule", "isName", "Open host", "DNS records for", "Open rule"):
        assert need in seg, f"the entity reader lost {need}"
    # an IP must be four bounded octets, not any dotted string
    assert "Number(o) <= 255" in seg
    # the entity's landing is its own HOME VIEW, filtered -- not a search box prefill
    assert "openHost(s)" in seg
    assert "dnApply([[\"dn-domain\", s]])" in seg
    assert "sluiceHighlightRule(s)" in seg


def test_entities_lead_the_match_and_fuzzy_is_only_a_fallback():
    src = (WEB / "palette.js").read_text()
    seg = src.split("function paletteMatch(", 1)[1].split("\n}", 1)[0]
    assert "[...entities, ...rows]" in seg, "entity rows must lead the scored list"
    assert "paletteScatter(" in seg, "the fuzzy fallback vanished"
    # the fallback runs ONLY when nothing matched as a substring
    assert seg.index("paletteScatter(") > seg.index("if (!rows.length)")


def test_recents_are_recorded_and_marked():
    src = (WEB / "palette.js").read_text()
    assert "PALETTE_RECENT_MAX" in src
    seg = src.split("function paletteRemember(", 1)[1].split("\n}", 1)[0]
    assert 'startsWith("recent ")' in seg, "re-marking a recent would double-prefix it"
    assert "[marked, ...PALETTE.recents.filter((r) => r.label !== c.label)]" in seg, \
        "a repeated command must MOVE to the front, not duplicate"
    assert "paletteRemember(c);" in src, "running a command no longer records it"
    app = (WEB / "app.js").read_text()
    seg2 = app.split("function showView(name) {", 1)[1].split("\n}", 1)[0]
    assert "paletteNoteView(name)" in seg2, \
        "views reached without the palette no longer become recents"


def test_a_setting_expands_its_card_before_it_shows():
    src = (WEB / "palette.js").read_text()
    seg = src.split('label: `Open setting ${r.label}`', 1)[1].split("},\n", 1)[0]
    assert 'classList.contains("collapsed")' in seg, \
        "the settings cards boot collapsed -- scrolling to a hidden row is a dead end"
    assert "h2.acc" in seg
    assert seg.index("collapsed") < seg.index("scrollIntoView"), \
        "the card must expand BEFORE the scroll (this order is the whole fix)"


def test_the_retrain_states_its_unavailability():
    src = (WEB / "palette.js").read_text()
    seg = src.split('label: "Force a model retrain"', 1)[1].split("});", 1)[0]
    assert "b.disabled" in seg, "a disabled retrain was clicked silently again"
    assert "mr-stand" in seg and "retrain unavailable" in seg


def test_the_visible_entry_and_key_hint():
    html = (WEB / "index.html").read_text()
    assert 'id="palette-btn"' in html
    src = (WEB / "palette.js").read_text()
    assert "palette-hint" in src, "the palette stopped teaching its own keys"
    assert "Ctrl+K" in src
