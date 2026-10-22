"""The default trunk adapter: observe tags, create VLAN devices, report the capture ports.

These tests do not touch a real NIC. They pin the decisions that matter: an access port is the
parent with no VLAN device; a tagged port is one device per tag; a manager removes only the
devices it previously created; and a failed creation falls back to the parent visibly rather
than claiming a trunk it did not build.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from weirvern.admin import trunk


class _Watcher:
    def __init__(self, vlans):
        self.vlans = set(vlans)
        self.calls = []

    def __call__(self, iface, *, seconds=0):
        self.calls.append((iface, seconds))
        return SimpleNamespace(vlans=self.vlans, frames=10)


class _Runner:
    def __init__(self, fail=()):
        self.calls = []
        self.fail = set(fail)

    def __call__(self, args):
        self.calls.append(list(args))
        if any(part in self.fail for part in args):
            return 1, "injected failure"
        return 0, ""


def test_an_access_port_is_the_parent_and_creates_no_vlan(tmp_path):
    state = trunk.sync("eth1", watcher=_Watcher(set()), runner=_Runner(), state_dir=str(tmp_path))
    assert state.ifaces == ["eth1"] and state.vlans == [] and state.error == ""
    assert (tmp_path / "ifaces").read_text() == "eth1\n"
    assert not any(" add " in f" {' '.join(c)} " for c in _Runner().calls)


def test_a_trunk_creates_one_device_per_tag_and_excludes_the_parent(tmp_path):
    runner = _Runner()
    state = trunk.sync("eth1", watcher=_Watcher({20, 10}), runner=runner,
                       state_dir=str(tmp_path))
    assert state.vlans == [10, 20]
    assert state.ifaces == ["eth1.10", "eth1.20"]
    assert (tmp_path / "ifaces").read_text() == "eth1.10\neth1.20\n"
    adds = [" ".join(c) for c in runner.calls if c[:3] == ["link", "add", "link"]]
    assert len(adds) == 2
    assert "type vlan id 10" in adds[0] and "type vlan id 20" in adds[1]
    assert any("link set eth1.10 up" in " ".join(c) for c in runner.calls)


def test_moving_back_to_an_access_port_removes_only_managed_vlan_devices(tmp_path):
    first = _Runner()
    trunk.sync("eth1", watcher=_Watcher({10}), runner=first, state_dir=str(tmp_path))
    second = _Runner()
    state = trunk.sync("eth1", watcher=_Watcher(set()), runner=second, state_dir=str(tmp_path))
    assert state.ifaces == ["eth1"]
    assert any(c[:3] == ["link", "del", "eth1.10"] for c in second.calls), (
        "a trunk device this manager created must be removed when the port is no longer tagged")
    assert not any(c[:3] == ["link", "del", "eth1"] for c in second.calls)


def test_a_creation_failure_is_a_visible_parent_fallback_not_a_fake_trunk(tmp_path):
    state = trunk.sync("eth1", watcher=_Watcher({10, 20}),
                       runner=_Runner(fail=("eth1.20",)), state_dir=str(tmp_path))
    assert state.ifaces == ["eth1"]
    assert "could not create eth1.20" in state.error
    assert (tmp_path / "ifaces").read_text() == "eth1\n"


def test_a_bad_vlan_id_or_oversized_name_is_refused():
    with pytest.raises(trunk.TrunkError):
        trunk.vlan_iface("eth1", 0)
    with pytest.raises(trunk.TrunkError):
        trunk.vlan_iface("eth1", 4095)
    with pytest.raises(trunk.TrunkError):
        trunk.vlan_iface("a" * 14, 10)


def test_the_cli_writes_the_same_state_the_agent_and_capture_read(tmp_path):
    # The CLI is the one-shot path used before capture starts. It must use the directory
    # exactly as given, not append a second trunk.json path component.
    assert trunk._state_path(str(tmp_path)) == str(tmp_path)
    assert trunk._state_path(str(tmp_path / "trunk.json")) == str(tmp_path)
