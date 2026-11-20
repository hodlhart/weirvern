"""US-1 pins: the bubble contract (status is still; only the opting-in bubble advertises a click).

The harness can drive behaviour but not stylesheets, so the bubble cues live here as source pins,
beside the a11y contract's own precedent (tests/test_a11y.py). Translated from the retired
`.chip` names: a still reading is `.bubble.state`, a pressable one is `.bubble.filter`.
"""
from pathlib import Path

WEB = Path(__file__).resolve().parents[1] / "weirvern" / "admin" / "web"


def test_state_bubbles_do_not_advertise_a_click():
    css = (WEB / "style.css").read_text()
    block = css[css.index(".bubble.state {"):css.index("}", css.index(".bubble.state {"))]
    assert "cursor: pointer" not in block, (
        "the bare .bubble.state block advertises a pointer -- status readings would look clickable")
    assert "cursor: default" in block, "a still bubble must explicitly refuse the pointer"
    assert ".bubble.state:hover" not in css, (
        "a still bubble keeps a hover wash -- it must not react to hover")


def test_interactive_bubbles_opt_in_and_get_the_cues():
    css = (WEB / "style.css").read_text()
    act = css[css.index(".bubble.filter {"):]
    act = act[:act.index("}")]
    assert "cursor: pointer" in act, "the opting-in bubble lost its pointer"
    hover = css[css.index(".bubble.filter:hover"):]
    hover = hover[:hover.index("}")]
    assert "border-color" in hover, "the opting-in bubble lost its hover cue"


def test_the_tracking_bubble_is_the_opted_in_one():
    """The one genuinely clickable bubble (assets' tracked-host pill) must carry the filter
    opt-in -- and no OTHER web file may attach a click handler to a `.bubble.state` element."""
    assets = (WEB / "assets.js").read_text()
    assert 'class: "bubble filter", title: "click to stop tracking this host"' in assets, (
        "the tracking bubble lost its opt-in class")
    import re
    offenders = []
    for js in WEB.glob("*.js"):
        src = js.read_text()
        # A bare `.bubble.state` span handed to an element variable that then gains a click
        # listener: cheap heuristic -- the var name on the bubble line, then a listener on it.
        for m in re.finditer(r'const (\w+) = el\("span", \{ class: "bubble state', src):
            var = m.group(1)
            tail = src[m.end():m.end() + 400]
            if re.search(rf"\b{var}\.addEventListener\(\"click\"", tail):
                offenders.append(f"{js.name}:{var}")
    assert not offenders, f"a still .bubble.state element gained a click listener: {offenders}"
