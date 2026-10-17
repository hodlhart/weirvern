"""US-7 pins: chips everywhere, URLs for everything.

The chip grammar has two families and ONE contract: `.chip` is a status pill (still); a filter
chip (`.dc-chip` / `.chip.act`) is dashed at rest and, while it HOLDS a filter, wears the accent
border plus a CHECKMARK and aria-pressed -- never colour alone. And every filter these controls
can hold rides the URL, so Copy link carries the screen and a reload returns to it.
"""
from __future__ import annotations

from pathlib import Path

WEB = Path(__file__).resolve().parents[1] / "weirvern" / "admin" / "web"


def _block(css: str, sel: str) -> str:
    return css[css.index(sel):css.index("}", css.index(sel))]


def test_filter_chips_are_visually_distinct_from_status_pills():
    css = (WEB / "style.css").read_text()
    assert "border: 1px dashed" in _block(css, ".dc-chip {"), \
        "filter chips must be dashed at rest -- a solid pill is a status"
    assert "border-style: solid" in _block(css, ".dc-chip[aria-pressed=\"true\"]"), \
        "a chip HOLDING a filter must lose the dashed ('temporary') shape"


def test_a_pressed_chip_wears_a_checkmark_not_just_colour():
    css = (WEB / "style.css").read_text()
    block = _block(css, '.dc-chip[aria-pressed="true"]::before')
    assert "\\2713" in block, "the pressed chip lost its checkmark (colour alone is not a state)"
    assert "color: var(--accent)" in block
    pressed = _block(css, '.dc-chip[aria-pressed="true"], .chip.act[aria-pressed="true"]')
    assert "border-color: var(--accent)" in pressed


def test_every_new_filter_rides_the_url():
    src = (WEB / "app.js").read_text()
    sync = src.split("function syncURL()", 1)[1].split("\n}", 1)[0]
    for key in ("as.q", "as.svc", "nw.min", "nw.labels", "nw.tracked", "dc.feed",
                "dc.sensor", "dc.proto", "dc.addr", "dc.port", "dc.f"):
        assert f'"{key}"' in sync, f"{key} no longer rides the URL"
    restore = src.split("function applyURLState()", 1)[1].split("\n}", 1)[0]
    for key in ("as.q", "as.svc", "nw.min", "nw.labels", "nw.tracked", "dc.feed", "dc.f"):
        assert f'"{key}"' in restore, f"{key} is written to the URL but never restored"


def test_the_assets_facet_is_an_exact_toggle():
    src = (WEB / "assets.js").read_text()
    seg = src.split("function renderAssetFacets(", 1)[1].split("\n}", 1)[0]
    assert '"aria-pressed"' in seg, "the facet chip no longer announces its pressed state"
    assert "ASSETS_STATE.svc = on ? \"\" : svc" in seg, \
        "the facet must TOGGLE (click again to stop filtering)"
    assert "scheduleURLSync()" in seg, "the facet filter does not ride the URL"
    filt = src.split("const rows = ASSETS_STATE.svc", 1)[1].split(";", 1)[0]
    assert "===" in filt, "the service filter must be exact, not a substring match"
    assert "renderAssetFacets(all)" in src, "a re-render must rebuild the facet chips"


def test_the_network_chip_is_a_pressed_toggle():
    html = (WEB / "index.html").read_text()
    seg = html.split('id="nw-only-tracked"', 1)[1].split(">", 1)[0]
    assert "chip act" in seg and 'aria-pressed="false"' in seg, \
        "the tracked-only chip lost its opt-in class or its pressed state"
    src = (WEB / "app.js").read_text()
    wire = src.split('const nwOnly = document.getElementById("nw-only-tracked");', 1)[1] \
               .split("});", 1)[0]
    assert "setAttribute(\"aria-pressed\"" in wire, "the toggle no longer updates aria-pressed"
    assert "scheduleURLSync()" in wire


def test_the_tracking_chip_announces_its_state():
    src = (WEB / "assets.js").read_text()
    assert 'class: "chip act"' in src
    seg = src.split('class: "chip act"', 1)[1].split("});", 1)[0]
    assert "aria-pressed" in seg, \
        "a toggle chip must carry aria-pressed (a status chip carries none)"
