"""NetFlow from a sensor: the intercept's own traffic, and a unit that can RECEIVE exports.

TWO FEATURES, ONE IDEA: flow records should come from wherever the traffic actually is. A sensor
that is in the path (a channel's bridge, or a live siphon intercept) can meter what crosses it, and
a sensor that has an exporter pointed at it can collect that and ship it home -- so a network's
exports do not have to reach the hub to be counted.

Both halves are gated on EVIDENCE, never on configuration, and that is what most of this file pins:
a tap started on the strength of a ConfigMap would produce records of traffic that is not flowing
through the box, landing in the table the volume baselines train on.
"""

import dataclasses
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class _Channel:
    def __init__(self, active=False, bridge=""):
        self.active = active
        self.bridge = bridge


class _Proc:
    def __init__(self, argv):
        self.argv = argv
        self.returncode = None

    def poll(self):
        return None


def _settings(**over):
    from weirvern.config import get_settings

    base = {
        "channel_netflow": "off", "siphon_netflow": True, "sensor_mode": "siphon",
        "zeek_iface": "eth1", "channel_upstream": "eth2", "channel_downstream": "eth3",
    }
    base.update(over)
    return dataclasses.replace(get_settings(), **base)


def _reset_holder():
    from weirvern import worker

    worker._CHANNEL_NETFLOW.update({"tap": None, "iface": "", "source": "", "retry_after": 0.0})


# ── the intercept as a flow source ───────────────────────────────────────────────────────────────


def test_a_siphon_tap_starts_only_on_a_VERIFIED_LIVE_intercept():
    from weirvern import worker

    spawned = []

    def fake_spawn(argv, **_kw):
        proc = _Proc(argv)
        spawned.append(proc)
        return proc

    which = lambda name: f"/usr/bin/{name}"  # noqa: E731 - a lookup table in one line

    _reset_holder()
    worker._channel_netflow_maybe(_settings(), channel_state=_Channel(), siphon_live=False,
                                  spawn=fake_spawn, which=which, now=lambda: 1000.0)
    assert not spawned, "a tap started for an intercept that is not live"
    assert worker._CHANNEL_NETFLOW["tap"] is None

    worker._channel_netflow_maybe(_settings(), channel_state=_Channel(), siphon_live=None,
                                  spawn=fake_spawn, which=which, now=lambda: 1000.0)
    assert not spawned, "an UNVERIFIED intercept (the evidence could not be read) started a tap"

    worker._channel_netflow_maybe(_settings(), channel_state=_Channel(), siphon_live=True,
                                  spawn=fake_spawn, which=which, now=lambda: 1000.0)
    assert len(spawned) == 1, "the live intercept was not metered"
    argv = spawned[0].argv
    assert "-i" in argv and argv[argv.index("-i") + 1] == "eth1", (
        "the tap is not on the interface the relay crosses")
    assert worker._CHANNEL_NETFLOW["source"] == "siphon"
    _reset_holder()


def test_one_tap_per_box_the_channel_wins_when_both_are_configured():
    """Two taps on one box would count every conversation twice, and the volume features and
    per-host baselines read that table. The channel is where the traffic actually crosses, so it
    keeps the tap; the intercept's selection waits."""
    from weirvern import worker

    spawned = []

    def fake_spawn(argv, **_kw):
        proc = _Proc(argv)
        spawned.append(proc)
        return proc

    which = lambda name: f"/usr/bin/{name}"  # noqa: E731

    _reset_holder()
    worker._channel_netflow_maybe(_settings(channel_netflow="upstream"),
                                  channel_state=_Channel(active=True, bridge="br0"),
                                  siphon_live=True, spawn=fake_spawn, which=which,
                                  now=lambda: 1000.0)
    assert len(spawned) == 1
    argv = spawned[0].argv
    assert argv[argv.index("-i") + 1] == "eth2", (
        "the channel's port did not win: two sources would be metered at once")
    assert worker._CHANNEL_NETFLOW["source"] == "channel"
    _reset_holder()


def test_the_tap_stops_when_the_intercept_ends():
    from weirvern import worker

    spawned = []

    def fake_spawn(argv, **_kw):
        proc = _Proc(argv)
        spawned.append(proc)
        return proc

    def fake_run(argv, **_kw):
        raise AssertionError("the sweep must not run: no completed segments here")

    which = lambda name: f"/usr/bin/{name}"  # noqa: E731

    _reset_holder()
    worker._channel_netflow_maybe(_settings(), channel_state=_Channel(), siphon_live=True,
                                  spawn=fake_spawn, which=which, now=lambda: 1000.0)
    assert worker._CHANNEL_NETFLOW["tap"] is not None
    # The intercept ends: the next tick must let go of the tap (and clear pending segments), not
    # keep collecting records of a segment that is no longer routing through this box.
    worker._channel_netflow_maybe(_settings(), channel_state=_Channel(), siphon_live=False,
                                  spawn=fake_spawn, which=which, run=fake_run,
                                  now=lambda: 1000.0)
    assert worker._CHANNEL_NETFLOW["tap"] is None
    assert worker._CHANNEL_NETFLOW["iface"] == ""


# ── a unit that can RECEIVE exports ───────────────────────────────────────────────────────────────


def test_the_agent_ships_what_the_collector_wrote(tmp_path, monkeypatch):
    from weirvern import ingester as ingester_mod
    from weirvern.admin import sensor_agent

    flow_file = tmp_path / "flows.jsonl"
    flow_file.write_text(json.dumps({"type": "NETFLOW_V9"}) + "\n")

    calls = {}

    def fake_tail(client, path, *, state=None, allow=""):
        calls.update({"path": path, "allow": allow})
        return 3, 4096, 1

    saved = {}
    monkeypatch.setattr(ingester_mod, "tail_and_insert", fake_tail)
    monkeypatch.setattr(ingester_mod, "load_tail_state", lambda path: object())
    monkeypatch.setattr(ingester_mod, "save_tail_state", lambda path, state: saved.update({"ok": True}))

    read = sensor_agent.ship_flows_once(object(), path=str(flow_file), allow="198.51.100.0/24")
    assert read == 3, "the rows the collector wrote were not shipped"
    assert calls["path"] == str(flow_file) and calls["allow"] == "198.51.100.0/24", (
        "the exclusion/allow filter must travel with every pass")
    assert saved.get("ok"), "the byte cursor was not checkpointed: a restart would re-insert everything"


def test_a_unit_with_no_exporter_is_not_an_error(tmp_path, monkeypatch):
    from weirvern import ingester as ingester_mod
    from weirvern.admin import sensor_agent

    def explode(*_a, **_kw):
        raise AssertionError("nothing to ship, so no query should run")

    monkeypatch.setattr(ingester_mod, "tail_and_insert", explode)
    assert sensor_agent.ship_flows_once(object(), path=str(tmp_path / "missing.jsonl")) == 0


def test_the_shipper_cannot_take_the_heartbeat_down(monkeypatch):
    """The heartbeat is the unit's LIVENESS -- it is how the fleet view knows this sensor exists.
    Flow shipping is a convenience on top, so a dead database, a missing client or a raising pass
    is a log line and a retry, never a crash."""
    import threading

    from weirvern import db
    from weirvern.admin import sensor_agent

    calls = {"n": 0}

    def failing_connect(*_a, **_kw):
        calls["n"] += 1
        raise RuntimeError("hub unreachable")

    monkeypatch.setattr(db, "connect", failing_connect)
    stop = threading.Event()

    def stopper():
        stop.wait(0.2)
        stop.set()

    threading.Thread(target=stopper, daemon=True).start()
    sensor_agent._flow_shipper(_settings(), stop)  # must return normally
    assert calls["n"] >= 1, "the shipper never even tried to connect"


def test_the_unit_and_the_script_carry_the_collector_and_ship_it_disabled():
    unit = (ROOT / "k8s/units/weirling-unit.yaml.template").read_text()
    script = (ROOT / "scripts/deploy-weirling.sh").read_text()
    agent = (ROOT / "weirvern/admin/sensor_agent.py").read_text()

    assert "WEIRLING_NETFLOW" in unit and 'value: "0"' in unit, (
        "the unit must ship with shipping DISABLED: an exporter pointed at a box that is not "
        "shipping is a silent hole")
    assert "netsampler/goflow2" in unit and "netflow://:2055" in unit, (
        "the unit has no collector, so an exporter on that segment has nowhere to send")
    assert "WEIRLING_FLOW_FILE" in unit and "/flows/flows.jsonl" in unit
    assert "--netflow" in script and "weirvern-netflow-" in script
    assert "WEIRLING_NETFLOW" in agent and "FLOW_SHIP_INTERVAL_S" in agent


def test_the_tap_follows_the_SIPHON_port_not_the_zeek_port():
    """The relay runs on CAPTURE_IFACE; tapping zeek_iface meters the wrong segment."""
    from weirvern import worker

    spawned = []

    def fake_spawn(argv, **_kw):
        proc = _Proc(argv)
        spawned.append(proc)
        return proc

    _reset_holder()
    worker._channel_netflow_maybe(_settings(capture_iface="eth2"),
                                  channel_state=_Channel(), siphon_live=True,
                                  spawn=fake_spawn, which=lambda n: f"/usr/bin/{n}",
                                  now=lambda: 1000.0)
    assert len(spawned) == 1
    argv = spawned[0].argv
    assert argv[argv.index("-i") + 1] == "eth2", (
        "the tap followed the Zeek port instead of the siphon capture port")
    _reset_holder()


def test_a_siphon_sensor_meters_automatically_without_the_extra_flag():
    """The operator asked the backend to derive netflow capture from the mode/interface."""
    from weirvern import worker

    spawned = []

    def fake_spawn(argv, **_kw):
        proc = _Proc(argv)
        spawned.append(proc)
        return proc

    _reset_holder()
    worker._channel_netflow_maybe(_settings(siphon_netflow=False, sensor_mode="siphon"),
                                  channel_state=_Channel(), siphon_live=True,
                                  spawn=fake_spawn, which=lambda n: f"/usr/bin/{n}",
                                  now=lambda: 1000.0)
    assert len(spawned) == 1, "siphon mode did not start its flow capture automatically"
    _reset_holder()
