"""The Health performance panel must explain capacity and name its scope."""
from __future__ import annotations

from pathlib import Path

WEB = Path(__file__).resolve().parents[1] / "weirvern" / "admin" / "web"


def test_the_system_panel_renders_capacity_scope_and_secondary_facts():
    src = (WEB / "soc.js").read_text()
    assert "sysBar(" in src
    assert "sysDuration(" in src
    assert "scope_label" in src and "scope_note" in src
    assert "per_core" in src and "sys-core" in src
    assert "swap_total_bytes" in src and "memory_available_bytes" in src
    assert "network in" in src and "disk read" in src
    assert "tasks running" in src and "blocked tasks" in src

    css = (WEB / "style.css").read_text()
    for rule in (".sys-scope", ".sys-bar", ".sys-facts", ".sys-facts-grid", ".sys-core"):
        assert rule in css
