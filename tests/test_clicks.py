"""US-1 pins: the chip contract (status is still; only the opting-in chip advertises a click).

The harness can drive behaviour but not stylesheets, so the chip cues live here as source
pins, beside the a11y contract's own precedent (tests/test_a11y.py).
"""
from pathlib import Path

WEB = Path(__file__).resolve().parents[1] / "weirvern" / "admin" / "web"


def test_status_chips_do_not_advertise_a_click():
    css = (WEB / "style.css").read_text()
    block = css[css.index(".chip {"):css.index(".chip.act")]
    assert "cursor: pointer" not in block, (
        "the bare .chip block advertises a pointer -- status chips would read as clickable")
    assert ".chip:hover" not in block, (
        "the bare .chip block keeps its hover wash -- a still chip must not react to hover")


def test_interactive_chips_opt_in_and_get_the_cues():
    css = (WEB / "style.css").read_text()
    act = css[css.index(".chip.act {"):]
    act = act[:act.index("}")]
    assert "cursor: pointer" in act, "the opting-in chip lost its pointer"
    hover = css[css.index(".chip.act:hover"):]
    hover = hover[:hover.index("}")]
    assert "border-color" in hover, "the opting-in chip lost its hover cue"


def test_the_tracking_chip_is_the_opted_in_one():
    """The one genuinely clickable .chip (assets' tracked-host pill) must carry the opt-in --
    and no OTHER web file may attach a click handler to a bare .chip element."""
    assets = (WEB / "assets.js").read_text()
    assert 'class: "chip act", title: "click to stop tracking this host"' in assets, (
        "the tracking chip lost its opt-in class")
    import re
    offenders = []
    for js in WEB.glob("*.js"):
        src = js.read_text()
        # A bare `.chip` span handed to an element variable that then gains a click listener:
        # cheap heuristic -- the var name on the chip line, then a listener on the same var.
        for m in re.finditer(r'const (\w+) = el\("span", \{ class: "chip"(?! act)', src):
            var = m.group(1)
            tail = src[m.end():m.end() + 400]
            if re.search(rf"\b{var}\.addEventListener\(\"click\"", tail):
                offenders.append(f"{js.name}:{var}")
    assert not offenders, f"a bare .chip element gained a click listener: {offenders}"
