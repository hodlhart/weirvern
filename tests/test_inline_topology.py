"""Inline is a declared topology, not a mode; the trunk probe must not run on a bridge."""

from __future__ import annotations

from pathlib import Path

from weirvern.admin import sensor_agent

ROOT = Path(__file__).resolve().parents[1]


def test_the_inline_helper_is_explicit_and_has_a_teardown_guard():
    src = (ROOT / "scripts" / "weirling-inline.sh").read_text()
    for action in ("dry-run", "create", "status", "teardown"):
        assert action in src
    assert "refusing to delete a bridge this helper did not create" in src
    assert "--port-a" in src and "--port-b" in src
    assert "default route" in src


def test_deploy_weirling_has_inline_and_no_trunk_flags():
    src = (ROOT / "scripts" / "deploy-weirling.sh").read_text()
    assert "--inline" in src
    assert "--no-trunk" in src
    assert "TRUNK_DISABLE" in src
    assert "TRUNKSTATE=\"/var/lib/weirvern-weirling/inline-$ID\"" in src


def test_trunk_sync_is_skipped_for_a_bridge(monkeypatch):
    import weirvern.admin.trunk as trunk_mod

    called = []

    def fake_sync(*args, **kwargs):
        called.append((args, kwargs))
        raise AssertionError("trunk.sync must not run for a bridge")

    monkeypatch.setenv("TRUNK_DISABLE", "1")
    monkeypatch.setattr(trunk_mod, "sync", fake_sync)
    sensor_agent.sync_trunk("wvbr-test")
    assert called == []
