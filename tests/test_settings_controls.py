"""The Settings revision: natural controls, and an explanation on every row.

WHY THIS FILE EXISTS. The Settings tab used to render every editable value as a free-text box:
the operator typed a number or a word, and the first honest answer about whether it was legal
came from the server on Apply. Two defects follow from that shape, and both are the kind this
project treats as bug classes rather than cosmetics:

  1. A control that invites a value outside the legal range guarantees avoidable round trips
     ("must be between 0.0 and 1.0") and teaches the range by rejection.
  2. A value shown without an explanation forces the reader into the source to learn what it
     does -- which is the opposite of the operator's request that setup be easy.

The fix is a single registry (`cluster_config.SETTING_CONTROLS`) that says, per editable key,
which control renders and what its bounds/options are, sent to the browser WITH the settings
payload. The browser never decides what is legal; it renders the server's stated bounds. The
registry and the write-path validator share one numeric table (`NUMERIC_RANGES`), so a control
whose `max` said 2.0 while `validate()` refused 1.5 cannot exist -- that divergence is the test
below with the most teeth.

These tests pin:
  * every rendered row carries a non-trivial explanation (the "?" help);
  * every editable key has a control spec, and every spec kind is one the front end implements;
  * the numeric bounds/step ARE the validator's own table, not a second copy;
  * select options are exactly what the validator accepts (a dropdown that cannot produce a
    rejected value, and can produce every accepted one);
  * the route emits the registry in the ROW vocabulary, like it does for editable keys.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from weirvern.admin import cluster_config as cc
from weirvern.admin import status

WEB = Path(__file__).resolve().parent.parent / "weirvern" / "admin" / "web"

# The four kinds the front end implements in `settingControl()`. A fifth kind would render as
# nothing until the JS side learns it, so the set is asserted rather than assumed.
KNOWN_CONTROL_KINDS = {"toggle", "select", "number", "text"}


def _rows() -> dict[str, dict]:
    payload = status.settings_overview(settings=None)
    return {r["key"]: r for rows in payload["groups"].values() for r in rows}


# ── 1. the explanation is part of every row ─────────────────────────────────────────────────


def test_every_rendered_row_carries_a_plain_language_explanation():
    """THE OPERATOR'S REQUEST, as an assertion: a '?' on every setting that explains it.

    A row without help teaches the reader that the '?' is decoration. The length floor is
    deliberate -- "see docs" is technically an explanation and useless; the floor makes the
    test fail on placeholders rather than trusting review to notice.
    """
    missing = []
    for key, row in _rows().items():
        help_text = (row.get("help") or "").strip()
        if len(help_text) < 40:
            missing.append(f"{key} ({len(help_text)} chars)")
    assert not missing, (
        "these settings render without a real explanation, so their '?' would open an empty or "
        f"placeholder box: {missing}"
    )


def test_the_explanation_names_the_default_where_a_default_exists():
    """The single most useful fact about a setting an operator did not set themselves.

    Checked on a sample rather than all rows: a runtime path (model directory) has no
    "default" in the same sense, and demanding the word from prose that does not need it
    would be enforcing a format, not a property.
    """
    rows = _rows()
    for key in ("retrain_every_h", "base_threshold", "detect_interval_s", "pushover_cooldown_s"):
        assert "default" in rows[key]["help"].lower(), (
            f"{key} explains itself without stating its default"
        )


# ── 2. every editable key renders as its natural control ────────────────────────────────────


def test_every_editable_key_has_an_explicit_control_spec():
    """No fallback-to-textbox for a key someone forgot.

    The JS falls back to a text input when a spec is missing -- belt and braces at runtime --
    but that fallback is exactly the "typed into a free-text box" experience this revision
    removes, so at build time it must never be reachable for an editable key.
    """
    missing = [k for k in cc.EDITABLE_KEYS if k not in cc.SETTING_CONTROLS]
    assert not missing, (
        f"editable keys without a control spec would render as raw text boxes: {missing}"
    )


def test_every_control_kind_is_one_the_front_end_implements():
    """The registry and the renderer must agree about the vocabulary.

    `settings_controls` can express a kind (`multi`, `slider`) that `settingControl()` does not
    branch on; it would silently render the text fallback and the operator would never know a
    richer control was intended.
    """
    kinds = {spec["control"] for spec in cc.SETTING_CONTROLS.values()}
    unknown = kinds - KNOWN_CONTROL_KINDS
    assert not unknown, (
        f"the registry declares control kinds the front end cannot render: {unknown} "
        f"(implemented: {sorted(KNOWN_CONTROL_KINDS)})"
    )
    # And the front end really implements each kind it is trusted with.
    app = (WEB / "app.js").read_text()
    for kind in KNOWN_CONTROL_KINDS:
        assert f'\\"{kind}\\"' in app or f'"{kind}"' in app or f"'{kind}'" in app, (
            f"settingControl() has no branch for the {kind!r} control kind"
        )


def test_booleans_render_as_toggles_and_choices_as_dropdowns():
    """The two conversions the operator asked for by name."""
    assert cc.SETTING_CONTROLS["PUSHOVER_ENABLED"]["control"] == "toggle"
    for key in ("SENSOR_MODE", "WEIRVERN_REVERSE_DNS"):
        assert cc.SETTING_CONTROLS[key]["control"] == "select", (
            f"{key} has a small closed set of legal values; it should be chosen, not typed"
        )


# ── 3. the bounds ARE the validator's table, not a copy ─────────────────────────────────────


def test_numeric_controls_use_the_validators_own_bounds():
    """ONE table (`NUMERIC_RANGES`) feeds both sides.

    This is the test with teeth: if a future edit changes `validate()`'s range without moving
    the control's `max` (or vice versa), a control would either refuse a legal value or offer
    an illegal one. Both directions are checked here by exercising the REAL validator.
    """
    for key, (lo, hi, _what, _step) in cc.NUMERIC_RANGES.items():
        spec = cc.SETTING_CONTROLS[key]
        assert spec["control"] == "number"
        assert spec["min"] == lo and spec["max"] == hi, (
            f"{key}: control bounds ({spec['min']}..{spec['max']}) disagree with "
            f"NUMERIC_RANGES ({lo}..{hi})"
        )
        # The validator accepts both endpoints...
        cc.validate(key, str(lo))
        cc.validate(key, str(hi))
        # ...and rejects just outside them, so the control's bounds are the real ones.
        if lo > 0:
            with pytest.raises(cc.ConfigError):
                cc.validate(key, str(lo - (1 if float(lo).is_integer() else 0.01)))
        with pytest.raises(cc.ConfigError):
            cc.validate(key, str(hi + (1 if float(hi).is_integer() else 0.01)))


def test_a_control_step_exists_for_every_numeric_key():
    """A number input without a step rounds floats to integers in some browsers -- a threshold
    of 0.35 would render as 0. Step is part of the spec, not an afterthought."""
    for key, spec in cc.SETTING_CONTROLS.items():
        if spec["control"] == "number":
            assert "step" in spec and spec["step"] > 0, f"{key} has no usable step"


# ── 4. dropdown options are exactly what the validator accepts ──────────────────────────────


def test_select_options_match_what_the_validator_accepts():
    """A dropdown cannot produce a value the server rejects, and can produce every value it
    accepts -- both halves matter. Checked by running the real validator against every option
    and against a plausible non-option."""
    for key in ("SENSOR_MODE", "WEIRVERN_REVERSE_DNS"):
        opts = cc.SETTING_CONTROLS[key]["options"]
        for option in opts:
            cc.validate(key, option)  # raises if the dropdown offers an illegal value
        # And the set is CLOSED: a plausible value outside it is rejected, so the dropdown is
        # not a suggestion list.
        with pytest.raises(cc.ConfigError):
            cc.validate(key, "nonsense-mode")


def test_the_mode_dropdown_covers_exactly_the_implemented_modes():
    """`dam` was removed as a mode; the dropdown must reflect the code, not history."""
    from weirvern.admin import mode as mode_mod

    known = {mode_mod.MODE_LOCH, mode_mod.MODE_SIPHON}
    assert set(cc.SETTING_CONTROLS["SENSOR_MODE"]["options"]) == known


# ── 5. the route ships the registry, in the row vocabulary ─────────────────────────────────


def test_the_settings_route_emits_controls_under_row_keys():
    """The same boundary translation as `editable_keys`, for the same reason.

    The front end looks up `controls[rowKey]` where rowKey is a Settings-attribute name
    (base_threshold); the registry is keyed by CONFIGMAP names (BASE_THRESHOLD). If the route
    shipped the raw registry, every lookup would miss and every control would fall back to a
    text box -- passing every server-side test while the page the operator sees is unchanged.
    """
    import importlib

    web = importlib.import_module("weirvern.admin.web")

    class _Auth:
        enabled = True
        reason = ""

    class _Ctx:
        settings = None
        backend = None
        auth = _Auth()

    handler_cls = web._build_handler(_Ctx())
    emitted: dict = {}
    inst = handler_cls.__new__(handler_cls)
    inst._json = lambda payload, code=200: emitted.update(payload)
    inst._settings({})

    controls = emitted.get("controls")
    assert controls, "the settings route does not ship the control registry; the UI would fall back to text boxes"
    assert "base_threshold" in controls, (
        "controls are keyed in the ConfigMap vocabulary; the front end reads row keys "
        f"(got: {sorted(controls)[:6]}...)"
    )
    assert "BASE_THRESHOLD" not in controls
    # Every shipped control key must correspond to an editable key or a rendered row -- a
    # control for a key nobody can edit is dead weight the UI cannot use.
    row_keys = set(_rows())
    for key in controls:
        assert key in row_keys, f"control shipped for {key!r}, which is not a rendered row"


# ── 6. the Sluice Gate's own switches ──────────────────────────────────────────────────────────


def test_the_sluice_keys_are_editable_from_the_settings_tab():
    """The gate used to be ConfigMap-only: operating it meant a patch and a worker restart --
    the opposite of the standing request that everything be clickable. Each of its switches
    must be a real row, with a control, an explanation and a stated restart, or the feature
    whose whole point is deciding what traffic lives is the one you need kubectl for."""
    rows = _rows()
    for key in ("SLUICE_ENABLED", "SLUICE_IFACE", "SLUICE_CRITICALITY", "SLUICE_MAX_BLOCK_S",
                "SLUICE_INTERVAL_S"):
        assert key in cc.EDITABLE_KEYS, f"{key} is not editable"
        assert key in cc.SETTING_CONTROLS, f"{key} has no control spec"
        row = cc.to_row_key(key)
        assert row in rows, f"{key} has no rendered settings row"
        assert len((rows[row].get("help") or "").strip()) >= 40, f"{key} has no real explanation"
        assert key in cc._RESTART_FOR, f"{key} is read by the worker; the restart must be stated"
    assert cc.SETTING_CONTROLS["SLUICE_ENABLED"]["control"] == "toggle"


def test_the_criticality_dropdown_offers_exactly_the_policies_the_validator_accepts():
    from weirvern.sluice import CRITICALITY_POLICIES

    opts = cc.SETTING_CONTROLS["SLUICE_CRITICALITY"]["options"]
    assert set(opts) == set(CRITICALITY_POLICIES), (
        "the dropdown and the policy table have drifted apart; one of them is lying to the operator"
    )
    for option in opts:
        cc.validate("SLUICE_CRITICALITY", option)
    with pytest.raises(cc.ConfigError):
        cc.validate("SLUICE_CRITICALITY", "nonsense-policy")
    # Turning it on states the cost; 'off' states nothing because there is nothing to warn about.
    assert "BLOCK" in cc.validate("SLUICE_CRITICALITY", "high")
    assert cc.validate("SLUICE_CRITICALITY", "off") == ""


def test_the_gate_cannot_be_pointed_at_the_management_interface(monkeypatch):
    """The supervisor refuses this at arm time; the write path must refuse it at AUTHOR time,
    because an arm-time refusal happens where nobody is looking (inside the worker's pass)."""
    monkeypatch.setenv("MGMT_IFACE", "eth0")
    with pytest.raises(cc.ConfigError) as err:
        cc.validate("SLUICE_IFACE", "eth0")
    assert "management" in str(err.value).lower()
    cc.validate("SLUICE_IFACE", "eth1")   # a real port passes
    cc.validate("SLUICE_IFACE", "")       # empty = resolve automatically (the default)


def test_the_sluice_toggle_accepts_booleans_only():
    cc.validate("SLUICE_ENABLED", "true")
    cc.validate("SLUICE_ENABLED", "0")
    with pytest.raises(cc.ConfigError):
        cc.validate("SLUICE_ENABLED", "sure-why-not")
    assert "OPEN" in cc.validate("SLUICE_ENABLED", "true")
