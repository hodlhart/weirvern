"""The TUI's mode panel.

WHY MODE GETS ITS OWN PANEL: `loch` and `siphon` are not two settings of one dial. loch
observes; siphon puts Weirvern in the path, so a crashed sensor becomes a LAN outage rather
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
            return [b.id for b in app.query("#btn-mode-loch, #btn-mode-siphon, #btn-mode-check")]

    ids = _run(go())
    assert "btn-mode-loch" in ids
    assert "btn-mode-siphon" in ids
    assert "btn-mode-check" in ids


def test_siphon_is_visually_marked_as_the_riskier_choice(tmp_path):
    """`siphon` changes the failure mode from a monitoring gap to an outage.

    Marking it differently is not decoration: an operator scanning the panel should not
    be able to mistake the two for equivalent options.
    """
    async def go():
        app = WeirvernTUI(project_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            btn = app.query_one("#btn-mode-siphon")
            return btn.variant

    assert _run(go()) == "warning"


def test_the_mode_gate_is_imported_not_reimplemented():
    """Two copies of a safety check drift, and the one that drifts is untested.

    The TUI must refuse siphon for exactly the reasons the CLI does, so it imports the same
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


def test_switching_siphon_is_refused_when_the_sensor_lacks_NET_ADMIN(tmp_path, monkeypatch):
    """The end-to-end refusal: the TUI must not be a way around the gate."""
    async def go():
        app = WeirvernTUI(project_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            # Simulate a cluster whose sensor holds NET_RAW only -- the real state of the
            # test box, and the reason siphon cannot be enabled there.
            monkeypatch.setattr(app, "_sensor_caps", lambda: (False, True))
            app._set_mode("siphon")
            await pilot.pause()
            return _render(app), app.query_one("#mode-status", Static)

    txt, _ = _run(go())
    assert "Cannot enable here" in txt or "cannot enable" in txt.lower(), (
        f"the TUI allowed a siphon switch without NET_ADMIN; panel said: {txt!r}"
    )
    # And the config must NOT have been written.
    env = tmp_path / ".env"
    if env.exists():
        assert "SENSOR_MODE=siphon" not in env.read_text(), (
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


# ── local vs cluster ────────────────────────────────────────────────────────────
#
# The TUI Config tab edits the LOCAL .env, but a Kubernetes deployment reads the
# ConfigMap. Those can disagree, and the panel previously showed only the local file --
# so it displayed ZEEK_IFACE=eth0 while the sensor was capturing on eth1, with nothing
# indicating the setting had no effect. A config panel that misrepresents which values are
# in force is worse than one that shows nothing, because it invites action that does
# nothing.


def _config_note(tmp_path, monkeypatch, local: str, cluster: dict[str, str], why: str = ""):
    """Render the Config table and return the cluster-note for ZEEK_IFACE.

    WHY THIS WRITES A FIXTURE .env INTO THE RESOLVED PROJECT DIR: `WeirvernTUI.__init__`
    calls `find_project_dir(project_dir)`, which OVERRIDES an explicit path and returns the
    real repository. Passing a tmp_path is therefore ignored, and a test that only writes
    to tmp_path silently reads the repository's own .env -- which is how an earlier version
    of these tests agreed with itself while exercising nothing.
    """
    from textual.widgets import DataTable

    real = tmp_path / ".env"

    async def go():
        app = WeirvernTUI(project_dir=tmp_path)
        # The app resolved its own project_dir; write the fixture where it will look.
        (app.project_dir / ".env").write_text(f"ZEEK_IFACE={local}\n")
        async with app.run_test() as pilot:
            await pilot.pause()
            monkeypatch.setattr(app, "_cluster_env", lambda: (cluster, why))
            app._render_config()
            await pilot.pause()
            tbl = app.query_one("#config-list", DataTable)
            for i in range(tbl.row_count):
                row = tbl.get_row_at(i)
                if str(row[0]) == "ZEEK_IFACE":
                    return str(row[2])
            return ""

    try:
        return _run(go())
    finally:
        real.unlink(missing_ok=True)


def test_the_config_table_has_a_cluster_column(tmp_path):
    from textual.widgets import DataTable

    async def go():
        app = WeirvernTUI(project_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            tbl = app.query_one("#config-list", DataTable)
            return [str(c.label) for c in tbl.columns.values()]

    cols = _run(go())
    assert any("cluster" in c.lower() for c in cols), (
        f"no cluster column, so the panel cannot show that a local edit has no effect: {cols}"
    )
    assert any("local" in c.lower() for c in cols), (
        "the value column must be labelled as LOCAL, or the distinction is invisible"
    )


def test_a_divergence_is_flagged_not_hidden(tmp_path, monkeypatch):
    """The exact case found on the test box: local eth0 vs cluster eth1."""
    note = _config_note(tmp_path, monkeypatch, local="eth0", cluster={"ZEEK_IFACE": "eth1"})
    assert "eth1" in note, f"the divergence was not surfaced; note was {note!r}"
    assert "matches" not in note


def test_an_unreadable_cluster_says_so_rather_than_implying_agreement(tmp_path, monkeypatch):
    """With no cluster the panel must not look like everything is in sync."""
    note = _config_note(tmp_path, monkeypatch, local="eth0", cluster={},
                        why="no cluster — local file only")
    assert "no cluster" in note.lower()
    assert "matches" not in note.lower(), (
        "no cluster data must never be rendered as agreement"
    )


def test_a_matching_value_is_reported_as_matching(tmp_path, monkeypatch):
    note = _config_note(tmp_path, monkeypatch, local="eth1", cluster={"ZEEK_IFACE": "eth1"})
    assert "matches" in note.lower(), f"equal values were not reported as matching: {note!r}"


def test_find_project_dir_overrides_an_explicit_path():
    """Documented because it silently broke three tests.

    Passing a directory to WeirvernTUI does NOT scope it: find_project_dir returns the real
    repository. Anything relying on project_dir for isolation is therefore reading the
    wrong .env, which makes a confident test assert nothing.
    """
    import tempfile

    from weirvern.admin.runtime import find_project_dir

    tmp = Path(tempfile.mkdtemp())
    assert find_project_dir(tmp) != tmp, (
        "find_project_dir now honours an explicit path; tests relying on the override "
        "behaviour need revisiting"
    )
