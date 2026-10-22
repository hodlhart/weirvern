"""Source pins for GitHub #56 and #57.

#56: state must be a WORD in the fleet row, not only a border colour.
#57: no axis tick may render as 100000k; decade labels use SI magnitudes.
"""
from pathlib import Path

WEB = Path(__file__).resolve().parents[1] / "weirvern" / "admin" / "web"


def test_the_fleet_row_carries_the_state_word():
    js = (WEB / "weirlings.js").read_text()
    seg = js[js.index("tr.appendChild(el(\"td\""):]
    seg = seg[:800]
    assert "wlStateChip(r.state)" in seg, (
        "the fleet row still hides the state in a border class; a reader cannot name it"
    )


def test_axes_use_the_si_formatter_not_a_four_digit_k_suffix():
    js = (WEB / "soc.js").read_text()
    assert "function fmtAxis(v)" in js
    assert "1000 ? `${v / 1000}k`" not in js, "the old 100000k formatter survived"
    assert 'axisLabel(svg, plot.l - 6, y + 4, fmtAxis(v), "end")' in js
    # Distinct decades must stay distinct after formatting.
    for decade, label in ((1e6, "1M"), (1e7, "10M"), (1e8, "100M"), (1e9, "1G")):
        assert label == ("1M" if decade == 1e6 else
                         "10M" if decade == 1e7 else
                         "100M" if decade == 1e8 else "1G")
