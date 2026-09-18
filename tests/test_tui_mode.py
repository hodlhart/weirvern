"""The TUI's mode panel.

WHY MODE GETS ITS OWN PANEL: `loch` and `weir` are not two settings of one dial. loch
observes; weir puts Weirvern in the path, so a crashed sensor becomes a LAN outage rather
than a monitoring gap. The panel therefore has to state the impact and the missing
prerequisites BEFORE offering the switch -- and it must be POPULATED on mount, because a
panel that is blank until you press something is indistinguishable from a broken one.

These tests drive the real app headlessly rather than inspecting the source, because the
failure mode being guarded against is a widget that exists but renders nothing.
"""
from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

pytest.importorskip("textual")

from textual.widgets import Static  # noqa: E402

from weirvern.admin.tui import WeirvernTUI  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]


def _render(app) -> str:
    return str(app.query_one("#mode-status", Static).render())


def _run(coro):
    return asyncio.run(coro)


def test_the_mode_panel_is_populated_on_mount(tmp_path):
    """Empty-until-pressed is the silent-empty pattern, and worse here than elsewhere.

    This panel is what tells an operator whether the sensor is a passive observer or in
    the network path, so a blank one hides the single most consequential fact about the
    deployment.
    """
    async def go():
        app = WeirvernTUI(project_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            return _render(app)

    txt = _run(go())
    assert txt.strip(), "the mode panel rendered nothing on mount"
    assert "Mode:" in txt
    assert "Impact:" in txt, "the panel does not state the consequence of the mode"


def test_the_panel_names_both_modes_as_switchable(tmp_path):
    """The controls must exist, so the panel is not merely informational."""
    async def go():
        app = WeirvernTUI(project_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            return [b.id for b in app.query("#btn-mode-loch, #btn-mode-weir, #btn-mode-check")]

    ids = _run(go())
    assert "btn-mode-loch" in ids
    assert "btn-mode-weir" in ids
    assert "btn-mode-check" in ids


def test_weir_is_visually_marked_as_the_riskier_choice(tmp_path):
    """`weir` changes the failure mode from a monitoring gap to an outage.

    Marking it differently is not decoration: an operator scanning the panel should not
    be able to mistake the two for equivalent options.
    """
    async def go():
        app = WeirvernTUI(project_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            btn = app.query_one("#btn-mode-weir")
            return btn.variant

    assert _run(go()) == "warning"


def test_the_mode_gate_is_imported_not_reimplemented():
    """Two copies of a safety check drift, and the one that drifts is untested.

    The TUI must refuse weir for exactly the reasons the CLI does, so it imports the same
    validator rather than duplicating the rules.
    """
    src = (ROOT / "weirvern" / "admin" / "tui.py").read_text()
    assert "mode_mod.validate" in src, (
        "the TUI does not call the shared mode validator, so its gate can disagree with "
        "the CLI's"
    )
    # And it must not hardcode the blocker text.
    assert "CAP_NET_ADMIN is required" not in src, (
        "the TUI duplicates the blocker wording instead of using mode.py's"
    )


def test_switching_weir_is_refused_when_the_sensor_lacks_NET_ADMIN(tmp_path, monkeypatch):
    """The end-to-end refusal: the TUI must not be a way around the gate."""
    async def go():
        app = WeirvernTUI(project_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            # Simulate a cluster whose sensor holds NET_RAW only -- the real state of the
            # test box, and the reason weir cannot be enabled there.
            monkeypatch.setattr(app, "_sensor_caps", lambda: (False, True))
            app._set_mode("weir")
            await pilot.pause()
            return _render(app), app.query_one("#mode-status", Static)

    txt, _ = _run(go())
    assert "Cannot enable here" in txt or "cannot enable" in txt.lower(), (
        f"the TUI allowed a weir switch without NET_ADMIN; panel said: {txt!r}"
    )
    # And the config must NOT have been written.
    env = tmp_path / ".env"
    if env.exists():
        assert "SENSOR_MODE=weir" not in env.read_text(), (
            "the mode was written despite failing the gate"
        )


def test_the_gate_reads_the_cluster_not_the_repository():
    """An overlay applied on the cluster is invisible in the checked-in manifest.

    Reading the file would report the capability the repository says exists rather than
    the one the sensor actually holds -- which is the difference between a correct refusal
    and a bogus permission.
    """
    src = (ROOT / "weirvern" / "admin" / "tui.py").read_text()
    body = src[src.index("def _sensor_caps"):]
    body = body[:body.index("\n    @on(")]
    assert "kubectl" in body, "capabilities are not read from the live cluster"
    assert "cluster_available" in body, (
        "no check that a cluster is reachable; an unreachable cluster must not be read as "
        "'capabilities present'"
    )
