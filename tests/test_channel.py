"""The CHANNEL enforcement path, and the gate's verdict about it.

A channel is a weirling wired IN LINE: an upstream port and a downstream port joined into one
bridge, so traffic between them passes THROUGH this host. With a live channel the Sluice Gate
enforces real blocks while the sensor stays in passive `loch` mode -- no ARP forging, no redirect.
The gate must VERIFY all of that from the KERNEL (admin/channel.py) and record which enforcement
path is live ('channel' / 'siphon' / 'none'), because a gate reading ARMED over traffic that never
traverses the host is this project's most-repeated failure class.

Everything here runs against fabricated sysfs and /proc/sys trees -- no kernel, no network.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from weirvern.admin import channel as channel_mod
from weirvern.sluice import (
    ENFORCEMENT_CHANNEL,
    ENFORCEMENT_NONE,
    ENFORCEMENT_SIPHON,
    GATE_STATE_ARMED,
    GATE_STATE_DEGRADED,
    Backend,
    Rule,
    SluiceSupervisor,
    enforcement_pass,
)

SOON = datetime.now(UTC) + timedelta(minutes=30)


@pytest.fixture(autouse=True)
def _no_kernel_probes(monkeypatch):
    """Channel checks must never touch the test machine's real firewall.

    The forward-path condition shells out (iptables/nft); it is stubbed here, and the tests
    that exercise the FAILING case override it explicitly.
    """
    monkeypatch.setattr(channel_mod, "_forward_ok", lambda bridge: (True, ""))


def _live(rid: str = "r1") -> Rule:
    return Rule(rid, expires_at=SOON)


class _Store:
    """The minimum a pass needs: one live rule, a recording state write."""

    def __init__(self) -> None:
        self.written: list[object] = []

    def load_live_rules(self, client: object) -> list[Rule]:
        return [_live()]

    def derived_rules_for_detections(self, *a: object, **k: object) -> list[dict]:
        return []

    def create_rule(self, client: object, **spec: object) -> Rule:
        raise AssertionError("no detections were supplied, so nothing should be created")

    def write_gate_state(self, client: object, sensor: str, state: object) -> None:
        self.written.append(state)


class _Backend(Backend):
    name = "fake"

    def available(self) -> bool:
        return True

    def arm(self, rules: object, *, iface: str) -> tuple[bool, str]:
        return True, "simulated"

    def disarm(self) -> tuple[bool, str]:
        return True, "simulated"

    def counters(self) -> tuple[int, int]:
        return 0, 0


def _sup(iface: str = "wv-br0") -> SluiceSupervisor:
    return SluiceSupervisor(iface=iface, mgmt_iface="eth0", backend=_Backend())


def _tree(tmp_path: Path, **kw: object) -> Path:
    """A fabricated /sys/class/net for channel checks."""
    opts: dict = {
        "up": "eth2", "down": "eth3",
        "up_master": "wv-br0", "down_master": "wv-br0",
        "up_state": 3, "down_state": 3, "up_carrier": 1, "down_carrier": 1,
        "up_exists": True, "down_exists": True,
        "bridge": "wv-br0", "bridge_exists": True, "bridge_up": True,
    }
    opts.update(kw)
    root = tmp_path / "net"
    root.mkdir()
    ports = (
        (opts["up"], opts["up_exists"], opts["up_master"], opts["up_state"], opts["up_carrier"]),
        (opts["down"], opts["down_exists"], opts["down_master"], opts["down_state"],
         opts["down_carrier"]),
    )
    for name, exists, master, state, carrier in ports:
        if not exists:
            continue
        d = root / name
        d.mkdir()
        (d / "operstate").write_text("up\n")
        (d / "carrier").write_text(f"{carrier}\n")
        if master:
            (d / "brport").mkdir()
            (d / "brport" / "state").write_text(f"{state}\n")
            (d / "master").symlink_to(f"../{master}")
    if opts["bridge_exists"]:
        b = root / opts["bridge"]
        b.mkdir()
        (b / "operstate").write_text("up\n" if opts["bridge_up"] else "down\n")
    return root


def _proc(tmp_path: Path, *, nf4: str | None = "1", nf6: str | None = "1") -> Path:
    p = tmp_path / "sys"
    (p / "net" / "bridge").mkdir(parents=True)
    if nf4 is not None:
        (p / "net" / "bridge" / "bridge-nf-call-iptables").write_text(f"{nf4}\n")
    if nf6 is not None:
        (p / "net" / "bridge" / "bridge-nf-call-ip6tables").write_text(f"{nf6}\n")
    return p


# ── the checks, read from the kernel ─────────────────────────────────────────────────────────────


def test_an_undeclared_channel_is_calm_not_broken():
    """No channel configured is the DEFAULT deployment; it must read as calm, not as a problem."""
    state = channel_mod.detect("", "")
    assert state.declared is False and state.active is False
    assert state.problems == []
    assert "no channel is configured" in state.detail


def test_a_wired_live_channel_is_active(tmp_path):
    state = channel_mod.detect("eth2", "eth3", sysfs=_tree(tmp_path), proc_sys=_proc(tmp_path))
    assert state.active is True, state.problems
    assert state.bridge == "wv-br0"
    assert state.ports == ["eth2", "eth3"]
    assert "channel active" in state.detail


def test_the_same_port_twice_can_never_be_a_channel(tmp_path):
    state = channel_mod.detect("eth2", "eth2", sysfs=_tree(tmp_path), proc_sys=_proc(tmp_path))
    assert state.active is False
    assert any("same port" in p for p in state.problems)


def test_a_missing_port_names_itself(tmp_path):
    state = channel_mod.detect("eth2", "eth9", sysfs=_tree(tmp_path, down_exists=False),
                               proc_sys=_proc(tmp_path))
    assert state.active is False
    assert any("eth9" in p and "does not exist" in p for p in state.problems)


def test_a_port_on_no_bridge_is_reported_with_the_fix(tmp_path):
    state = channel_mod.detect("eth2", "eth3", sysfs=_tree(tmp_path, up_master=""),
                               proc_sys=_proc(tmp_path))
    assert state.active is False
    assert any("not enslaved" in p and "ip link set eth2 master" in p for p in state.problems)


def test_two_bridges_is_not_a_channel(tmp_path):
    state = channel_mod.detect("eth2", "eth3",
                               sysfs=_tree(tmp_path, down_master="other-br"),
                               proc_sys=_proc(tmp_path))
    assert state.active is False
    assert any("different bridges" in p for p in state.problems)


def test_a_pulled_cable_is_not_a_channel(tmp_path):
    """The kernel's own state tables make a dead channel look exactly as healthy as a live one."""
    state = channel_mod.detect("eth2", "eth3", sysfs=_tree(tmp_path, up_carrier=0),
                               proc_sys=_proc(tmp_path))
    assert state.active is False
    assert any("carrier 0" in p for p in state.problems)


def test_a_converging_bridge_is_not_yet_forwarding(tmp_path):
    state = channel_mod.detect("eth2", "eth3", sysfs=_tree(tmp_path, up_state=2),
                               proc_sys=_proc(tmp_path))
    assert state.active is False
    assert any("not forwarding yet" in p for p in state.problems)


def test_a_down_bridge_is_not_a_channel(tmp_path):
    state = channel_mod.detect("eth2", "eth3", sysfs=_tree(tmp_path, bridge_up=False),
                               proc_sys=_proc(tmp_path))
    assert state.active is False
    assert any("is down" in p for p in state.problems)


def test_bridge_nf_off_blocks_the_claim_and_carries_the_remedy(tmp_path):
    """WITHOUT bridge-nf a bridged packet never reaches the inet forward hook the gate writes to:
    the rules install, count nothing, and the panel would read ARMED. The check must refuse."""
    state = channel_mod.detect("eth2", "eth3", sysfs=_tree(tmp_path),
                               proc_sys=_proc(tmp_path, nf4="0"))
    assert state.active is False
    assert any("bridge-nf-call-iptables=0" in p and "sysctl -w" in p for p in state.problems)


def test_a_missing_bridge_nf_file_is_its_own_reason(tmp_path):
    state = channel_mod.detect("eth2", "eth3", sysfs=_tree(tmp_path),
                               proc_sys=_proc(tmp_path, nf4=None))
    assert state.active is False
    assert any("missing" in p for p in state.problems)


# ── the gate's verdict: which path is live ───────────────────────────────────────────────────────


def test_a_live_channel_arms_the_gate_while_loch(tmp_path):
    """The whole feature in one assertion: in line + passive mode == real enforcement."""
    ch = channel_mod.detect("eth2", "eth3", sysfs=_tree(tmp_path), proc_sys=_proc(tmp_path))
    assert ch.active
    store = _Store()
    state = enforcement_pass(store, _sup(), client=object(), sensor="s1",
                              sensor_mode="loch", channel=ch)
    assert state.state == GATE_STATE_ARMED, state.detail
    assert state.enforcement == ENFORCEMENT_CHANNEL
    assert "in line on the channel bridge" in state.detail
    assert store.written and getattr(store.written[0], "enforcement", "") == ENFORCEMENT_CHANNEL


def test_loch_with_no_channel_cannot_enforce():
    store = _Store()
    state = enforcement_pass(store, _sup(), client=object(), sensor="s1",
                              sensor_mode="loch", channel=channel_mod.detect("", ""))
    assert state.state == GATE_STATE_DEGRADED
    assert state.enforcement == ENFORCEMENT_NONE
    assert "not in the traffic path" in state.detail


def test_a_declared_but_dead_channel_degrades_with_the_wiring_reason(tmp_path):
    ch = channel_mod.detect("eth2", "eth3", sysfs=_tree(tmp_path, up_carrier=0),
                            proc_sys=_proc(tmp_path))
    store = _Store()
    state = enforcement_pass(store, _sup(), client=object(), sensor="s1",
                              sensor_mode="loch", channel=ch)
    assert state.state == GATE_STATE_DEGRADED
    assert state.enforcement == ENFORCEMENT_NONE
    assert "carrier 0" in state.detail, state.detail


def test_siphon_with_live_evidence_is_armed():
    store = _Store()
    state = enforcement_pass(store, _sup(), client=object(), sensor="s1",
                              sensor_mode="siphon", siphon_live=True)
    assert state.state == GATE_STATE_ARMED
    assert state.enforcement == ENFORCEMENT_SIPHON
    assert "live siphon intercept" in state.detail


def test_siphon_without_live_evidence_degrades():
    """Configured is not in the path. This is the reading the old code shipped on config alone."""
    store = _Store()
    state = enforcement_pass(store, _sup(), client=object(), sensor="s1",
                              sensor_mode="siphon", siphon_live=False)
    assert state.state == GATE_STATE_DEGRADED
    assert state.enforcement == ENFORCEMENT_NONE
    assert "NO live intercept" in state.detail


def test_siphon_with_unverifiable_evidence_degrades():
    """'Could not check' is not 'fine' -- the rule this project keeps re-learning."""
    store = _Store()
    state = enforcement_pass(store, _sup(), client=object(), sensor="s1",
                              sensor_mode="siphon", siphon_live=None)
    assert state.state == GATE_STATE_DEGRADED
    assert state.enforcement == ENFORCEMENT_NONE
    assert "could not be verified" in state.detail


def test_a_live_channel_outranks_siphon_when_both_are_live(tmp_path):
    """A channel is physics; siphon is protocol. When both are up, the channel is the path."""
    ch = channel_mod.detect("eth2", "eth3", sysfs=_tree(tmp_path), proc_sys=_proc(tmp_path))
    store = _Store()
    state = enforcement_pass(store, _sup(), client=object(), sensor="s1",
                              sensor_mode="siphon", siphon_live=True, channel=ch)
    assert state.enforcement == ENFORCEMENT_CHANNEL


def test_a_forward_drop_without_bridge_accepts_blackholes_the_channel(tmp_path, monkeypatch):
    """MEASURED: bridged traffic DOES traverse the forward hook (bridge-nf on) and the BRIDGE
    DEVICE is the name that matches. A k3s DROP policy without a scoped ACCEPT for the bridge
    would drop everything crossing the channel -- worse than a degraded gate."""
    monkeypatch.setattr(channel_mod, "_forward_ok",
                        lambda bridge: (False, f"the host firewall DROPS forwarded traffic "
                                              f"(iptables -P FORWARD DROP); fix on {bridge}."))
    state = channel_mod.detect("eth2", "eth3", sysfs=_tree(tmp_path), proc_sys=_proc(tmp_path))
    assert state.active is False
    assert any("DROPS" in p for p in state.problems)


def test_the_forward_check_is_skipped_when_bridge_nf_is_off(tmp_path, monkeypatch):
    """With bridge-nf off the bridged traffic never reaches the hook; the nf problem already
    names the real fault, and a second complaint about the firewall would be noise."""
    monkeypatch.setattr(channel_mod, "_forward_ok",
                        lambda bridge: (False, "the host firewall DROPS forwarded traffic"))
    state = channel_mod.detect("eth2", "eth3", sysfs=_tree(tmp_path),
                               proc_sys=_proc(tmp_path, nf4="0"))
    assert state.active is False
    assert not any("DROPS" in p for p in state.problems)
    assert any("bridge-nf-call-iptables=0" in p for p in state.problems)


def test_an_unspecified_mode_takes_no_verdict():
    """A caller that did not say the mode did not ask for a verdict about it (old behaviour)."""
    store = _Store()
    state = enforcement_pass(store, _sup(), client=object(), sensor="s1", channel=None)
    assert state.enforcement == ""
    assert "not in the traffic path" not in (state.detail or "")


# ── the channel flow probe: start / stop / back off, without a kernel ───────────────────────────


class _FakeProc:
    """A child-process stand-in: alive until terminated/killed, or born exited."""

    def __init__(self, alive: bool = True, rc: int = 0) -> None:
        self.returncode = None if alive else rc
        self.terminated = False
        self.killed = False

    def poll(self):
        return self.returncode

    def terminate(self):
        self.terminated = True
        self.returncode = 0

    def wait(self, timeout=None):
        return 0

    def kill(self):
        self.killed = True


class _NFChannel:
    def __init__(self, active: bool) -> None:
        self.active = active
        self.bridge = "wv-br0" if active else ""


def _nf_settings(mode: str):
    class _S:
        channel_netflow = mode
        channel_upstream = "wv-a"
        channel_downstream = "wv-b"

    return _S()


def _reset_probe():
    from weirvern import worker as worker_mod

    worker_mod._CHANNEL_NETFLOW.update({"proc": None, "iface": "", "retry_after": 0.0})
    return worker_mod


def test_the_flow_probe_starts_on_the_selected_port_and_only_once():
    """The whole feature in one tick: the probe runs on the CHOSEN port, exports to the
    deployment's own collector, in the foreground (or supervision could not see it die) --
    and a second tick with nothing changed starts nothing."""
    worker_mod = _reset_probe()
    spawns = []
    worker_mod._channel_netflow_maybe(
        _nf_settings("upstream"), channel_state=_NFChannel(True),
        spawn=lambda argv: spawns.append(argv) or _FakeProc(),
        which=lambda n: "/usr/sbin/softflowd", now=lambda: 1000.0)
    assert len(spawns) == 1
    argv = spawns[0]
    assert argv[argv.index("-i") + 1] == "wv-a"
    assert argv[argv.index("-n") + 1] == worker_mod.CHANNEL_NETFLOW_COLLECTOR
    assert "-d" in argv, "the child must run in the foreground, or supervision cannot see it die"
    worker_mod._channel_netflow_maybe(
        _nf_settings("upstream"), channel_state=_NFChannel(True),
        spawn=lambda argv: spawns.append(argv) or _FakeProc(),
        which=lambda n: "x", now=lambda: 1001.0)
    assert len(spawns) == 1, "an unchanged tick spawned a second probe"


def test_the_flow_probe_stops_when_the_selection_is_off_or_the_channel_dies():
    """'Off' must mean stopped, and a channel that went down must stop it too -- the probe
    samples a port that may no longer be carrying anything the operator asked about."""
    for mode, active in (("off", True), ("upstream", False)):
        worker_mod = _reset_probe()
        proc = _FakeProc()
        worker_mod._CHANNEL_NETFLOW.update({"proc": proc, "iface": "wv-a"})
        spawned = []
        worker_mod._channel_netflow_maybe(
            _nf_settings(mode), channel_state=_NFChannel(active),
            spawn=lambda argv, out=spawned: out.append(argv) or _FakeProc(),
            which=lambda n: "x", now=lambda: 2000.0)
        assert proc.terminated is True, f"probe kept running with mode={mode}, active={active}"
        assert spawned == [], "a stopped probe must not be replaced while it is not wanted"


def test_the_flow_probe_moves_port_when_the_selection_moves():
    worker_mod = _reset_probe()
    first, second = _FakeProc(), _FakeProc()
    seq = iter([first, second])
    spawns = []
    worker_mod._channel_netflow_maybe(
        _nf_settings("upstream"), channel_state=_NFChannel(True),
        spawn=lambda argv: spawns.append(argv) or next(seq), which=lambda n: "x",
        now=lambda: 10.0)
    worker_mod._channel_netflow_maybe(
        _nf_settings("downstream"), channel_state=_NFChannel(True),
        spawn=lambda argv: spawns.append(argv) or next(seq), which=lambda n: "x",
        now=lambda: 11.0)
    assert first.terminated is True, "the probe on the old port was left running"
    assert len(spawns) == 2 and spawns[1][spawns[1].index("-i") + 1] == "wv-b"


def test_the_flow_probe_backs_off_after_a_death_or_a_missing_binary():
    """A crash loop that writes a log line and a doomed child every tick is worse than a probe
    that is visibly not running: one warning, then a five-minute cooldown, then a retry."""
    # a dead child: one warning, no immediate respawn
    worker_mod = _reset_probe()
    dead = _FakeProc(alive=False, rc=1)
    worker_mod._CHANNEL_NETFLOW.update({"proc": dead, "iface": "wv-a"})
    spawns = []
    worker_mod._channel_netflow_maybe(
        _nf_settings("upstream"), channel_state=_NFChannel(True),
        spawn=lambda argv: spawns.append(argv) or _FakeProc(), which=lambda n: "x",
        now=lambda: 100.0)
    assert spawns == [], "respawned immediately after a crash"
    assert worker_mod._CHANNEL_NETFLOW["retry_after"] == 400.0
    worker_mod._channel_netflow_maybe(
        _nf_settings("upstream"), channel_state=_NFChannel(True),
        spawn=lambda argv: spawns.append(argv) or _FakeProc(), which=lambda n: "x",
        now=lambda: 200.0)
    assert spawns == [], "retried inside the cooldown"
    worker_mod._channel_netflow_maybe(
        _nf_settings("upstream"), channel_state=_NFChannel(True),
        spawn=lambda argv: spawns.append(argv) or _FakeProc(), which=lambda n: "x",
        now=lambda: 401.0)
    assert len(spawns) == 1, "the probe was never retried after the cooldown"

    # a missing binary: warned once on the cooldown, not once per tick
    worker_mod = _reset_probe()
    spawns.clear()
    worker_mod._channel_netflow_maybe(
        _nf_settings("upstream"), channel_state=_NFChannel(True),
        spawn=lambda argv: spawns.append(argv) or _FakeProc(), which=lambda n: None,
        now=lambda: 500.0)
    worker_mod._channel_netflow_maybe(
        _nf_settings("upstream"), channel_state=_NFChannel(True),
        spawn=lambda argv: spawns.append(argv) or _FakeProc(), which=lambda n: None,
        now=lambda: 501.0)
    assert spawns == [] and worker_mod._CHANNEL_NETFLOW["retry_after"] == 800.0
