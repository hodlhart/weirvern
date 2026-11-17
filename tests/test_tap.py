"""THE TAP — capture at the boundary, decide from evidence, never from a ConfigMap.

THE MOVE THIS FILE PINS. The capture children used to live in the worker, which runs as a
non-root uid; Kubernetes drops an added capability for a non-root container, so `add: NET_RAW`
was decorative (measured: CapEff 0000000000000000) and flows stopped while every surface looked
configured. The tap is now one module (`weirvern.tap`) launched where the privilege is real --
the Zeek DaemonSet's sidecar on the hub, the agent container on a weirling. Both launch points
and the deletion of the worker's path are asserted below, because a half-moved tap is worse than
either end state: the worker would stop supervising before the sidecar exists.

Everything here runs against fakes -- no kernel, no network, no child processes.
"""
from __future__ import annotations

import os
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


# ── fakes ────────────────────────────────────────────────────────────────────────────────────────


class _DummyPipe:
    def close(self):
        pass


class _FakeProc:
    """A child-process stand-in: alive until terminated/killed, or born exited."""

    def __init__(self, alive: bool = True, rc: int = 0) -> None:
        self.returncode = None if alive else rc
        self.terminated = False
        self.killed = False
        self.stdout = _DummyPipe()

    def poll(self):
        return self.returncode

    def terminate(self):
        self.terminated = True
        self.returncode = 0

    def wait(self, timeout=None):
        return 0

    def kill(self):
        self.killed = True


class _Result:
    def __init__(self, rc: int = 0, stderr: bytes = b"") -> None:
        self.returncode = rc
        self.stderr = stderr


class _S:
    channel_netflow = "off"
    channel_upstream = "wv-a"
    channel_downstream = "wv-b"
    capture_iface = "eth1"
    zeek_iface = "eth1"
    netflow_mode = "auto"
    netflow_iface = ""
    sensor_mode = "loch"
    siphon_netflow = False


def _settings(mode: str = "off", *, netflow_mode: str = "auto", netflow_iface: str = "",
              sensor_mode: str = "loch", siphon_netflow: bool = False) -> _S:
    obj = _S()
    obj.channel_netflow = mode
    obj.netflow_mode = netflow_mode
    obj.netflow_iface = netflow_iface
    obj.sensor_mode = sensor_mode
    obj.siphon_netflow = siphon_netflow
    return obj


def _recorder(spawns: list, procs=None):
    """A spawn factory that records argv and hands out fakes, in order."""
    seq = iter(procs) if procs else None

    def spawn(argv, **kwargs):
        spawns.append(list(argv))
        if seq is not None:
            return next(seq)
        return _FakeProc()

    return spawn


def _supervisor(tmp_path, spawns=None, procs=None, clock=None, which=None, run=None):
    from weirvern import tap

    return tap.Supervisor(
        directory=str(tmp_path),
        spawn=_recorder(spawns if spawns is not None else [], procs),
        which=which or (lambda n: f"/usr/sbin/{n}"),
        run=run,
        clock=clock or (lambda: 1000.0),
    )


def _explode(*_a, **_kw):
    raise AssertionError("the sweep must not run: there is nothing to summarise")


# ── which interface, from what evidence ──────────────────────────────────────────────────────────


def test_a_siphon_tap_starts_only_on_a_VERIFIED_LIVE_intercept():
    from weirvern import tap

    dead = tap.select_targets(netflow_mode="auto", siphon_netflow=True, sensor_mode="siphon",
                               zeek_iface="eth1", siphon_live=False)
    assert dead == [], "a tap started for an intercept that is not live"

    unknown = tap.select_targets(netflow_mode="auto", siphon_netflow=True, sensor_mode="siphon",
                                  zeek_iface="eth1", siphon_live=None)
    assert unknown == [], ("an UNVERIFIED intercept (the evidence could not be read) started a tap")

    live = tap.select_targets(netflow_mode="auto", siphon_netflow=True, sensor_mode="siphon",
                              zeek_iface="eth1", siphon_live=True)
    assert live == [tap.Target("eth1", "siphon")], "the live intercept was not metered"


def test_one_tap_per_box_the_channel_wins_when_both_are_configured():
    """An INLINE channel is one bridged upstream/downstream pair, not a per-NIC probe. Tapping
    both the channel and an intercept of the same traffic would count it twice."""
    from weirvern import tap

    targets = tap.select_targets(netflow_mode="auto", channel_netflow="upstream",
                                  channel_upstream="wv-a", channel_downstream="wv-b",
                                  siphon_netflow=True, sensor_mode="siphon", zeek_iface="eth1",
                                  channel_active=True, siphon_live=True)
    assert targets == [tap.Target("wv-a", "channel")], (
        "the channel's port did not win: two sources would be metered at once")


def test_two_selected_interfaces_get_two_taps():
    """Both NICs can meter at once; the old single holder made them mutually exclusive."""
    from weirvern import tap

    targets = tap.select_targets(netflow_mode="active", channel_netflow="off",
                                  sensor_mode="loch", netflow_iface="eth1,eth2",
                                  capture_iface="eth1", zeek_iface="eth1")
    assert targets == [tap.Target("eth1", "loch"), tap.Target("eth2", "loch")]


def test_the_tap_follows_the_SIPHON_port_not_the_zeek_port():
    """The relay runs on CAPTURE_IFACE; tapping zeek_iface meters the wrong segment."""
    from weirvern import tap

    targets = tap.select_targets(netflow_mode="auto", siphon_netflow=True, sensor_mode="siphon",
                                  capture_iface="eth2", zeek_iface="eth1", siphon_live=True)
    assert targets == [tap.Target("eth2", "siphon")]


def test_a_siphon_sensor_meters_automatically_without_the_extra_flag():
    """The operator asked the backend to derive netflow capture from the mode/interface."""
    from weirvern import tap

    targets = tap.select_targets(netflow_mode="auto", siphon_netflow=False, sensor_mode="siphon",
                                  zeek_iface="eth1", siphon_live=True)
    assert targets == [tap.Target("eth1", "siphon")]


def test_passive_netflow_selects_nothing_because_the_router_owns_the_feed():
    from weirvern import tap

    assert tap.select_targets(netflow_mode="passive", channel_netflow="upstream",
                              channel_upstream="wv-a", siphon_netflow=True, sensor_mode="siphon",
                              zeek_iface="eth1", channel_active=True, siphon_live=True) == []


def test_a_loch_sensor_in_auto_mode_does_not_tap_by_default():
    """Auto preserves the old behaviour: a passive sensor with no channel exports nothing of
    its own, and that must not change just because the code moved."""
    from weirvern import tap

    assert tap.select_targets(netflow_mode="auto", sensor_mode="loch", zeek_iface="eth1") == []


# ── the supervisor: start / stop / sweep / back off ──────────────────────────────────────────────


def test_the_probe_taps_into_rotating_segments_once(tmp_path):
    """The MEASURED architecture in one tick: a single long-lived child taps the chosen port
    into bounded rotating pcap segments, with the flags that took a live failure to learn
    (-Z root) and the ones that bound the disk (-C size, -G time, -W count)."""
    from weirvern import tap

    spawns: list = []
    sup = _supervisor(tmp_path, spawns, run=_explode)
    sup.tick(tap.select_targets(netflow_mode="active", sensor_mode="loch", zeek_iface="eth1"))

    assert len(spawns) == 1, "the only long-lived child is the capture tap"
    argv = spawns[0]
    assert "tcpdump" in argv[0]
    assert argv[argv.index("-i") + 1] == "eth1"
    for flag in ("-Z", "-C", "-G", "-W", "-w", "-U"):
        assert flag in argv, f"{flag} is part of the bounded-segment tap"
    assert argv[argv.index("-Z") + 1] == "root", "tcpdump's privilege-drop fails here; measured"
    assert argv[argv.index("-w") + 1].startswith(str(tmp_path))
    assert argv[-1] == tap.TAP_FILTER

    # A second tick with a live tap and nothing changed starts nothing else and sweeps cleanly.
    sup.tick(tap.select_targets(netflow_mode="active", sensor_mode="loch", zeek_iface="eth1"))
    assert len(spawns) == 1, "an unchanged tick spawned another tap"


def test_the_probe_stops_the_tap_and_drops_pending_segments(tmp_path):
    """'Off' must mean nothing is being collected -- including the already-captured segments
    that have not been summarised yet."""
    (tmp_path / "ch-1.pcap").write_bytes(b"x")
    (tmp_path / "ch-2.pcap").write_bytes(b"x")
    spawns: list = []
    sup = _supervisor(tmp_path, spawns)
    sup.taps = {"wv-a": {"tap": _FakeProc(), "source": "channel", "dir": str(tmp_path)}}

    sup.tick([])  # the selection is off

    assert sup.taps == {}
    assert not list(tmp_path.glob("*.pcap")), "'off' must not leave captured segments on disk"


def test_the_sweep_summarises_only_completed_segments_and_deletes_them(tmp_path):
    """The batch path, which is the one this kernel supports: softflowd reads a COMPLETED file
    perfectly (measured 30/30) while a live stream blocks it forever."""
    from weirvern import tap

    old = tmp_path / "ch-20260101-000000.pcap000"
    new = tmp_path / "ch-20260101-000030.pcap000"
    old.write_bytes(b"seg")
    new.write_bytes(b"seg")
    past = time.time() - 100.0
    os.utime(old, (past, past))
    os.utime(new, (past, past))
    calls: list = []

    def run(argv, timeout=None, capture_output=False, **kwargs):
        calls.append(list(argv))
        return _Result(0)

    done = tap.sweep_completed(run=run, probe="/usr/sbin/softflowd", directory=str(tmp_path))

    assert done == 1
    assert len(calls) == 1, "the newest segment is still being written; only completed ones go"
    assert str(old) in calls[0]
    assert not old.exists() and new.exists(), "a summarised segment must be deleted; the live one kept"
    argv = calls[0]
    assert argv[argv.index("-r") + 1] == str(old)
    assert argv[argv.index("-v") + 1] == "10", "v9 is dropped by the collector; measured"
    assert argv[argv.index("-n") + 1] == tap.TAP_COLLECTOR
    assert "-p" not in argv and "-c" not in argv, (
        "a one-shot summariser must not open a pidfile or control socket; measured: the same "
        "invocation with them hung for the runner's whole timeout")


def test_the_sweep_keeps_a_segment_it_could_not_summarise(tmp_path):
    """A failed summarise must not delete the evidence; the file stays for the next tick."""
    from weirvern import tap

    seg = tmp_path / "ch-20260101-000000.pcap"
    other = tmp_path / "ch-20260101-000030.pcap"
    for f in (seg, other):
        f.write_bytes(b"seg")
        os.utime(f, (time.time() - 100.0,) * 2)

    tap.sweep_completed(run=lambda *a, **k: _Result(1, b"boom"),
                        probe="/usr/sbin/softflowd", directory=str(tmp_path))
    assert seg.exists(), "a failed segment was deleted anyway -- the evidence is gone"


def test_the_sweep_does_nothing_below_two_segments(tmp_path):
    from weirvern import tap

    (tmp_path / "ch-only.pcap").write_bytes(b"seg")
    tap.sweep_completed(run=_explode, probe="/usr/sbin/softflowd", directory=str(tmp_path))
    assert (tmp_path / "ch-only.pcap").exists()


def test_the_tick_sweeps_a_completed_segment_even_though_its_clock_is_monotonic(tmp_path):
    """MEASURED regression: the tick's clock is monotonic while file mtimes are wall clock;
    passing the tick's clock into the sweep made `monotonic - epoch` a huge negative, every
    segment read as 'too young', and two completed segments sat unconsumed."""
    from weirvern import tap

    old = tmp_path / "ch-20260101-000000.pcap000"
    new = tmp_path / "ch-20260101-000030.pcap000"
    for f in (old, new):
        f.write_bytes(b"seg")
        os.utime(f, (time.time() - 100.0,) * 2)
    run_calls: list = []

    def run(argv, timeout=None, capture_output=False, **kwargs):
        run_calls.append(list(argv))
        return _Result(0)

    targets = tap.select_targets(netflow_mode="active", sensor_mode="loch", zeek_iface="eth1")
    sup = _supervisor(tmp_path, clock=time.monotonic, run=run)
    sup.tick(targets)   # starts the tap
    sup.tick(targets)   # tap alive -> sweeps, with WALL time

    assert run_calls and run_calls[0][run_calls[0].index("-r") + 1] == str(old), (
        "the tick's monotonic clock leaked into the sweep's wall-clock age check")


def test_the_probe_backs_off_after_a_death_or_a_missing_binary(tmp_path):
    """A crash loop that writes a log line and doomed children every tick is worse than a probe
    that is visibly not running: one warning, then a five-minute cooldown, then a retry."""
    from weirvern import tap

    targets = tap.select_targets(netflow_mode="active", sensor_mode="loch", zeek_iface="eth1")
    spawns: list = []
    clock = {"t": 100.0}
    sup = _supervisor(tmp_path, spawns, clock=lambda: clock["t"])
    sup.taps = {"eth1": {"tap": _FakeProc(alive=False, rc=1), "source": "loch",
                         "dir": str(tmp_path)}}

    sup.tick(targets)
    assert spawns == [], "respawned immediately after a crash"
    assert sup.retry_after == 400.0

    clock["t"] = 200.0
    sup.tick(targets)
    assert spawns == [], "retried inside the cooldown"

    clock["t"] = 401.0
    sup.tick(targets)
    assert len(spawns) == 1, "the probe was never retried after the cooldown"

    # A missing binary is the same class: one warning, then the cooldown.
    spawns.clear()
    missing = lambda n: None if n == "tcpdump" else "x"  # noqa: E731
    sup = _supervisor(tmp_path, spawns, clock=lambda: 500.0, which=missing)
    sup.tick(targets)
    sup.tick(targets)
    assert spawns == [] and sup.retry_after == 800.0


# ── the move itself: both launch points, and no capture path left in the worker ────────────────


def test_the_worker_no_longer_contains_a_capture_path():
    """THE SINGLE-PASS RULE. The worker must not keep a second, half-supervised tap: if it did,
    a sidecar failure would be masked by a worker that still spawns tcpdump -- or the reverse,
    which is the window this refactor exists to close.

    COMMENTS ARE EXEMPT AND CHECKED SEPARATELY. The block that explains WHY the capture left
    names tcpdump and softflowd on purpose; a substring search would forbid documenting the
    move. What must not exist is CODE that spawns them, so the check tokenises the source and
    drops comments before looking.
    """
    import io
    import tokenize

    source = (ROOT / "weirvern" / "worker.py").read_text()
    code = []
    for tok in tokenize.generate_tokens(io.StringIO(source).readline):
        if tok.type not in (tokenize.COMMENT, tokenize.NL):
            code.append(tok.string)
    executable = " ".join(code)
    for word in ("tcpdump", "softflowd", "_channel_netflow_maybe", "_CHANNEL_NETFLOW"):
        assert word not in executable, f"the worker still has capture code: {word}"

    tap_source = (ROOT / "weirvern" / "tap.py").read_text()
    assert "tcpdump" in tap_source and "softflowd" in tap_source
    assert "TAP_COLLECTOR" in tap_source


def test_the_hub_runs_the_tap_as_a_sidecar_with_a_REAL_capture_grant():
    """Root + NET_RAW in the capture pod, on the same image: the grant is only effective for a
    root container, which is the measured reason the worker could not hold it."""
    import yaml

    doc = yaml.safe_load((ROOT / "k8s" / "32-zeek.yaml").read_text())
    containers = doc["spec"]["template"]["spec"]["containers"]
    tap = next((c for c in containers if c["name"] == "tap"), None)
    assert tap is not None, "the Zeek DaemonSet has no tap sidecar"
    assert tap["command"] == ["python3", "-m", "weirvern.tap"]
    assert tap["image"] == "weirvern-worker", "the sidecar must ride the project's own image"
    ctx = tap["securityContext"]
    assert ctx["runAsUser"] == 0, "a non-root container loses the capability; measured"
    assert "NET_RAW" in ctx["capabilities"]["add"]
    assert any("configMapRef" in e for e in tap["envFrom"])
    assert any("secretRef" in e for e in tap["envFrom"]), (
        "siphon mode asks the database whether an intercept is live; the sidecar needs the "
        "same credential every other ClickHouse reader has")


def test_a_weirling_runs_the_same_module_in_its_agent_container():
    """The agent container is the unit's capture boundary (the capture container is the Zeek
    image, with no python), so the module is wired there. The CAPABILITY is opt-in per unit:
    the base manifest grants the agent nothing (in-path is a deliberate choice), and the
    in-path overlay is what gives it NET_RAW -- which is exactly the unit whose relay traffic
    is worth metering."""
    unit = (ROOT / "k8s" / "units" / "weirling-unit.yaml.template").read_text()
    overlay = (ROOT / "k8s" / "units" / "weirling-unit-siphon.yaml.template").read_text()
    agent = (ROOT / "weirvern" / "admin" / "sensor_agent.py").read_text()
    assert "_tap_supervisor" in agent and "weirvern import tap" in agent

    start = unit.index("- name: agent")
    end = unit.index("- name: gate")
    assert 'add: ["NET_RAW"]' not in unit[start:end], (
        "the base unit granted the agent a capability; in-path is supposed to be opt-in")

    start = overlay.index("- name: agent")
    end = overlay.index("\n---", start) if "\n---" in overlay[start:] else len(overlay)
    assert "NET_RAW" in overlay[start:end], (
        "no unit manifest grants the agent NET_RAW, so a weirling's tap could never open a "
        "socket")


# ── the ring's disk budget ───────────────────────────────────────────────────────────────────────


def _segment(path: Path, mb: int) -> None:
    path.write_bytes(b"\0" * (mb * 1024 * 1024))


def test_the_ring_prune_is_a_NOOP_under_budget(tmp_path):
    """On a working tap the sweep has already deleted every summarised segment: two files, ~20 KB
    measured. The guard must not touch a healthy ring."""
    from weirvern import tap

    for i in range(3):
        _segment(tmp_path / f"ch-20261117-15000{i}.pcap00{i}", 1)

    assert tap.prune_ring(directory=str(tmp_path), max_mb=16) == 0
    assert len(list(tmp_path.glob("*.pcap*"))) == 3


def test_the_ring_prune_DROPS_OLDEST_FIRST_and_never_the_live_segment(tmp_path):
    """A softflowd that starts and then hangs is the one failure with no other bound: the sweep
    keeps failing and tcpdump keeps rotating. The budget is the backstop, and the segment tcpdump
    is writing RIGHT NOW must survive -- deleting it makes the next rotation reuse an open name."""
    from weirvern import tap

    for i in range(5):
        _segment(tmp_path / f"ch-20261117-15000{i}.pcap00{i}", 1)
    (tmp_path / "notes.jsonl").write_text("not a segment")

    dropped = tap.prune_ring(directory=str(tmp_path), max_mb=2)

    assert dropped == 2, f"pruned {dropped} segments, expected the two oldest"
    remaining = sorted(p.name for p in tmp_path.glob("*.pcap*"))
    assert remaining == ["ch-20261117-150002.pcap002", "ch-20261117-150003.pcap003",
                         "ch-20261117-150004.pcap004"], remaining
    assert (tmp_path / "notes.jsonl").exists(), "the guard deleted a non-segment file"


def test_the_ring_prune_does_not_raise_on_an_empty_or_missing_ring(tmp_path):
    from weirvern import tap

    assert tap.prune_ring(directory=str(tmp_path), max_mb=1) == 0
    assert tap.prune_ring(directory=str(tmp_path / "gone"), max_mb=1) == 0
