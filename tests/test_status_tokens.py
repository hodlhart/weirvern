"""The status color system: computed contrast floors, the bad/crit split, and the one grammar.

WHY THIS FILE EXISTS. The console research (cross-cutting #3, Carbon's 2-of-3 rule + WCAG
1.4.1) found two concrete defects in the stylesheet: `--bad` and `--crit` were the SAME hex
(two tiers with one appearance), and the accent sat BELOW the 4.5:1 AA text floor on the
densest surface. A palette is code: the numbers here are computed from style.css itself, so
any future token edit that dims a label, re-merges the two severities, or drops a glyph from
the renderers turns this red -- instead of shipping and being discovered by an operator's
eyes.

WHAT THESE TESTS PIN:
  * --accent clears 4.5:1 on the surfaces it is text on
  * every severity text token clears 4.5:1 on --surface-2
  * --bad and --crit are DISTINCT hues (not two names for one appearance)
  * one severity grammar: the glyph map exists and the renderers use it
  * the .sev-* CSS rules carry tokens only, never raw hex
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CSS = (ROOT / "weirvern" / "admin" / "web" / "style.css").read_text()
APP_JS = (ROOT / "weirvern" / "admin" / "web" / "app.js").read_text()


def root_tokens() -> dict[str, str]:
    body = CSS[CSS.index(":root {"):]
    body = body[:body.index("\n}")]
    body = re.sub(r"/\*.*?\*/", "", body, flags=re.S)   # the palette's prose holds hexes too
    tokens = {}
    for m in re.finditer(r"--([a-z0-9-]+)\s*:\s*([^;]+);", body):
        tokens[m.group(1)] = m.group(2).strip()
    return tokens


TOKENS = root_tokens()


def resolve(name: str) -> str:
    v = TOKENS[name]
    m = re.fullmatch(r"var\(--([a-z0-9-]+)\)", v)
    return resolve(m.group(1)) if m else v


def _srgb(channel: float) -> float:
    return channel / 12.92 if channel <= 0.03928 else ((channel + 0.055) / 1.055) ** 2.4


def luminance(hex_color: str) -> float:
    h = hex_color.lstrip("#")
    r, g, b = (int(h[i:i + 2], 16) / 255 for i in (0, 2, 4))
    return 0.2126 * _srgb(r) + 0.7152 * _srgb(g) + 0.0722 * _srgb(b)


def contrast(fg: str, bg: str) -> float:
    a, b = luminance(resolve(fg)), luminance(resolve(bg))
    lo, hi = sorted((a, b))
    return (hi + 0.05) / (lo + 0.05)


def hue(hex_color: str) -> float:
    h = hex_color.lstrip("#")
    r, g, b = (int(h[i:i + 2], 16) for i in (0, 2, 4))
    mx, mn = max(r, g, b), min(r, g, b)
    if mx == mn:
        return 0.0
    if mx == r:
        hue_v = 60 * (((g - b) / (mx - mn)) % 6)
    elif mx == g:
        hue_v = 60 * (((b - r) / (mx - mn)) + 2)
    else:
        hue_v = 60 * (((r - g) / (mx - mn)) + 4)
    return hue_v % 360


def test_the_accent_clears_the_aa_text_floor_on_its_surfaces():
    for surface in ("surface", "surface-2", "canvas"):
        ratio = contrast("accent", surface)
        assert ratio >= 4.5, (
            f"--accent on --{surface} is {ratio:.2f}:1, below the 4.5:1 AA text floor -- "
            f"accent text would strain exactly where it is most used"
        )


def test_every_severity_token_clears_the_aa_text_floor():
    for token in ("ok", "warn", "bad", "crit", "sev-critical", "sev-high", "sev-medium"):
        ratio = contrast(token, "surface-2")
        assert ratio >= 4.5, (
            f"--{token} on --surface-2 is {ratio:.2f}:1, below the 4.5:1 text floor -- "
            f"a severity label you have to squint at is not a label"
        )


def test_bad_and_crit_are_distinct_hues_not_two_names_for_one_appearance():
    bad, crit = resolve("bad"), resolve("crit")
    assert bad != crit, "bad and crit are the same value again -- two tiers, one appearance"
    delta = abs(hue(bad) - hue(crit))
    delta = min(delta, 360 - delta)
    assert delta >= 15, (
        f"bad and crit are only {delta:.0f} degrees apart in hue -- the research's defect was "
        f"exactly this: two tiers wearing one colour"
    )


def test_one_severity_grammar_the_glyph_map_exists_and_the_renderers_use_it():
    assert "SEVERITY_GLYPHS" in APP_JS, "the glyph map is gone"
    for shape in ("\\u25b2", "\\u25c6", "\\u25cf", "\\u25cb"):   # the four ranked shapes
        assert f'"{shape}"' in APP_JS, f"glyph {shape} vanished from the map"
    assert APP_JS.count("sevText(") >= 3, (
        "sevText() is the one path every severity renderer takes; fewer call sites means a "
        "renderer went back to a bare word"
    )


def test_the_sev_rules_carry_tokens_never_raw_hex():
    for m in re.finditer(r"\.sev-[a-z]+\s*\{([^}]*)\}", CSS):
        body = m.group(1)
        assert "#" not in body, f"a .sev-* rule carries a raw hex color: {body!r}"


def test_the_severity_ramp_is_four_distinct_hues_in_rank_order():
    """The operator's directive (2026-10-18): red, orange, yellow, and the neutral.

    The defect this pins: .sev-high and .sev-medium both read var(--warn) -- two ranks, one
    appearance. A ramp that cannot be read in order is not a ramp.
    """
    rule = dict(re.findall(r"\.sev-([a-z]+)\s*\{\s*color:\s*([^;]+);", CSS))
    values = {k: (resolve(v[6:-1]) if v.startswith("var(--") else v) for k, v in rule.items()}
    for rank in ("critical", "high", "medium", "low"):
        assert rank in values, f"the .sev-{rank} rule disappeared"
    assert values["critical"] != values["high"], "critical and high wear one colour again"
    assert values["high"] != values["medium"], "high and medium wear one colour again"
    assert values["medium"] != values["low"], "medium and low wear one colour again"
    # rank order by hue: red (near 0/360) -> orange -> yellow, then a neutral with no hue
    def hue_of(hexv: str) -> float:
        h = hexv.lstrip("#")
        r, g, b = (int(h[i:i + 2], 16) for i in (0, 2, 4))
        mx, mn = max(r, g, b), min(r, g, b)
        if mx == mn:
            return -1.0
        if mx == r:
            val = 60 * (((g - b) / (mx - mn)) % 6)
        elif mx == g:
            val = 60 * (((b - r) / (mx - mn)) + 2)
        else:
            val = 60 * (((r - g) / (mx - mn)) + 4)
        return val % 360

    crit_h, high_h, med_h = (hue_of(values[k]) for k in ("critical", "high", "medium"))
    assert crit_h < 12 or crit_h > 348, f"critical is not red (hue {crit_h:.0f})"
    assert 15 <= high_h <= 40, f"high is not orange (hue {high_h:.0f})"
    assert 40 < med_h <= 60, f"medium is not yellow (hue {med_h:.0f})"
    # Adjacent ranks must be far enough apart to read as different colours, not a gradient:
    # the shipped defect had high and medium 8 degrees apart (both amber).
    gaps = [abs(high_h - crit_h), abs(med_h - high_h)]
    for gap, names in zip(gaps, ("critical/high", "high/medium"), strict=True):
        assert gap >= 15, f"{names} are only {gap:.0f} degrees apart -- two ranks, one appearance"
    # The neutral is a cool grey -- a few degrees of tint on purpose -- so assert low SATURATION
    # rather than hue 0: it must read as information, not as a fourth alarm colour.
    def saturation(hexv: str) -> float:
        h = hexv.lstrip("#")
        r, g, b = (int(h[i:i + 2], 16) for i in (0, 2, 4))
        return 0.0 if max(r, g, b) == 0 else (max(r, g, b) - min(r, g, b)) / max(r, g, b)

    assert saturation(values["low"]) <= 0.10, (
        f"low is saturating at {saturation(values['low']):.0%} -- it must stay the neutral"
    )
    for rank in ("critical", "high", "medium"):
        assert saturation(values[rank]) > saturation(values["low"]) + 0.30, (
            f"{rank} is not clearly more saturated than the neutral"
        )
