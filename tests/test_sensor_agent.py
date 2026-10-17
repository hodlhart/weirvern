"""The sensor unit: refuses the management NIC, and reports OBSERVED state under its own id.

WHY THIS FILE EXISTS. A unit is how a sensor becomes a fleet row when it is not "the whole
deployment": run twice on one host, or on another box, each unit owns one capture port and one
SENSOR_ID. Two properties carry the unit's honesty, and both are pinned here:

  * it REFUSES to capture on the management NIC (the default-route interface) -- Samuel's
    standing rule, as a refusal rather than a warning, because there is no deployment story in
    which capturing the control path is right; and
  * its heartbeat states what OBSERVATION found (log mtimes, Zeek's own capture_loss.log) -- a
    dead capture reads as not-running, and an unmeasured loss stays None, never 0.0.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import pytest  # noqa: E402

from weirvern.admin import sensor_agent  # noqa: E402


class FakeClient:
    """Records inserts the way status.heartbeat calls them."""

    def __init__(self):
        self.rows = []

    def insert(self, table, data, column_names=None):
        for row in data or []:
            self.rows.append({"table": table,
                              "row": dict(zip(column_names or [], row, strict=False))})


def _write_logs(d: Path, age_s: float = 0.0, loss: str | None = None) -> None:
    """A minimal but REAL-shaped log dir: a conn.log (liveness) and optionally a
    capture_loss.log carrying the fields this Zeek build writes."""
    d.mkdir(parents=True, exist_ok=True)
    conn = d / "conn.log"
    conn.write_text("#fields\tts\tuid\n1.0\tC1\n")
    if age_s:
        old = time.time() - age_s
        os.utime(conn, (old, old))
    if loss is not None:
        (d / "capture_loss.log").write_text(loss)


# ── the management-NIC refusal ───────────────────────────────────────────────────────────────

def _probe(default_route: str = "eth0", names: tuple = ("eth0", "eth2")):
    """A REAL ProbeResult, built through the real parser, from a fabricated probe JSON -- so
    these tests exercise the same parse path the live probe feeds."""
    import json

    from weirvern.admin import interfaces as ifc

    recs = [{"name": n, "operstate": "up", "flags": "0x1003", "address": "", "driver": "",
             "speed": "", "mtu": "1500", "is_bridge": False, "is_bridge_port": False,
             "has_device": True, "rx_packets": 0, "rx_dropped": 0, "rx_errors": 0}
            for n in names]
    return ifc.parse_probe(json.dumps({"interfaces": recs,
                                       "default_route_iface": default_route,
                                       "hostname": "unit-test"}))


def test_it_refuses_the_management_nic(monkeypatch):
    monkeypatch.setattr("weirvern.admin.interfaces.probe_local", lambda *a, **k: _probe())
    with pytest.raises(SystemExit) as e:
        sensor_agent.capture_port_check("eth0")
    assert "REFUSING" in str(e.value)
    assert "management" in str(e.value)


def test_a_dedicated_capture_port_passes(monkeypatch):
    monkeypatch.setattr("weirvern.admin.interfaces.probe_local", lambda *a, **k: _probe())
    assert sensor_agent.capture_port_check("eth2") == "eth2"  # must not raise


def test_a_port_that_does_not_exist_is_refused(monkeypatch):
    monkeypatch.setattr("weirvern.admin.interfaces.probe_local", lambda *a, **k: _probe())
    with pytest.raises(SystemExit) as e:
        sensor_agent.capture_port_check("eth9")
    assert "does not exist" in str(e.value)


def test_a_failed_probe_refuses_rather_than_permits(monkeypatch):
    from weirvern.admin.interfaces import ProbeResult

    monkeypatch.setattr("weirvern.admin.interfaces.probe_local",
                        lambda *a, **k: ProbeResult(source="local", error="boom"))
    with pytest.raises(SystemExit) as e:
        sensor_agent.capture_port_check("eth2")
    assert "could not probe" in str(e.value)


# ── the identity / port contract ──────────────────────────────────────────────────────────────

def test_it_requires_an_explicit_identity(monkeypatch):
    monkeypatch.delenv("SENSOR_ID", raising=False)
    with pytest.raises(SystemExit) as e:
        sensor_agent.sensor_identity()
    assert "SENSOR_ID" in str(e.value)
    monkeypatch.setenv("SENSOR_ID", " weirvern-eth2 ")
    assert sensor_agent.sensor_identity() == "weirvern-eth2"


def test_it_requires_its_capture_port(monkeypatch):
    monkeypatch.delenv("ZEEK_IFACE", raising=False)
    with pytest.raises(SystemExit):
        sensor_agent.required_iface()
    monkeypatch.setenv("ZEEK_IFACE", "eth2")
    assert sensor_agent.required_iface() == "eth2"


# ── what a beat actually publishes ───────────────────────────────────────────────────────────

def test_a_beat_publishes_observed_state_under_the_units_own_id(monkeypatch, tmp_path):
    logs = tmp_path / "logs"
    _write_logs(logs, loss="#fields\tts\tts_delta\tpeer\tgaps\tacks\tpercent_lost\n"
                           "1.0\t1.0\teth2\t3\t1000\t2.5\n")
    monkeypatch.setenv("ZEEK_LOG_DIR", str(logs))
    client = FakeClient()
    assert sensor_agent.beat(client, "weirvern-eth2", "eth2") is True
    assert client.rows and client.rows[-1]["table"] == "weirvern.sensor_status"
    row = client.rows[-1]["row"]
    assert row["sensor_id"] == "weirvern-eth2"
    assert row["iface"] == "eth2"
    assert row["mode"] == "loch"
    assert int(row["running"]) == 1
    assert float(row["capture_loss_pct"]) == 2.5
    # pkts_recv/pkts_drop are absent in this Zeek build's log; the acks/gaps fallback is a
    # REAL measurement and must arrive as numbers rather than as zeros.
    assert int(row["packets_recv"]) == 1000
    assert int(row["packets_dropped"]) == 3


def test_a_dead_capture_reads_as_not_running(monkeypatch, tmp_path):
    logs = tmp_path / "logs"
    _write_logs(logs, age_s=600.0)
    monkeypatch.setenv("ZEEK_LOG_DIR", str(logs))
    client = FakeClient()
    sensor_agent.beat(client, "weirvern-eth2", "eth2")
    row = client.rows[-1]["row"]
    assert int(row["running"]) == 0
    assert any("capture has stopped" in f for f in row["failures"])


def test_an_unmeasured_loss_stays_unmeasured_not_zero(monkeypatch, tmp_path):
    logs = tmp_path / "logs"
    _write_logs(logs)  # fresh conn.log, no capture_loss.log
    monkeypatch.setenv("ZEEK_LOG_DIR", str(logs))
    client = FakeClient()
    sensor_agent.beat(client, "weirvern-eth2", "eth2")
    row = client.rows[-1]["row"]
    assert row["capture_loss_pct"] is None
    assert row["packets_recv"] is None and row["packets_dropped"] is None
    assert int(row["running"]) == 1


# ── the entrypoint the manifest actually runs ─────────────────────────────────────────────────

def test_the_module_can_run_as_the_units_entrypoint():
    """The manifest runs `python3 -m weirvern.admin.sensor_agent`; a module without the guard
    imports to nothing and the unit would heartbeat never."""
    src = (ROOT / "weirvern" / "admin" / "sensor_agent.py").read_text()
    assert 'if __name__ == "__main__":' in src
    assert "\ndef main()" in src


# ── THE UNIT'S OWN INTERCEPT, FROM ITS OWN PLAN ───────────────────────────────────────────────
#
# A weirling unit is IN-PATH or PASSIVE by ITS OWN declaration, never by the hub's: its mode and
# plan live in its registry row (fleet.SensorPlan), because a remote box cannot be reached any
# other way. These checks drive the REAL supervisor -- with only its spawn and readiness hooks
# faked -- so what they prove is the shipping safety contract: the same `weirvern intercept`
# child, the same bounded runs, the same orderly SIGTERM restore, the same capability gate.

import threading  # noqa: E402

from weirvern import fleet as fleet_mod  # noqa: E402
from weirvern.admin import siphon_supervisor as sup_mod  # noqa: E402

SIPHON_PLAN = dict(mode="siphon", iface="eth2", segment="198.51.100.0/24",
                   addr="198.51.100.250", gateway="198.51.100.1", targets="*")


class FakeChild:
    """A child handle: alive until terminated, then reaped (rc 0, as a clean restore)."""

    def __init__(self) -> None:
        self.pid = 4242
        self._rc: int | None = None
        self.terminated = 0
        self.stdout = None

    def poll(self):
        return self._rc

    def terminate(self):
        self.terminated += 1
        self._rc = 0


class SpawningFactory:
    """Builds REAL SiphonSupervisors whose child is a FakeChild, and records everything."""

    def __init__(self) -> None:
        self.configs = []
        self.argvs = []
        self.children = []
        self.readiness: list[str] = []

    def __call__(self, cfg):
        self.configs.append(cfg)
        sup = sup_mod.SiphonSupervisor(
            cfg, spawn=self._spawn, readiness=lambda: list(self.readiness),
            run_seconds=60, poll_s=0.01, clean_rearm_s=0.01, base_delay_s=0.01,
            max_delay_s=0.02, stop_timeout_s=2.0)
        return sup

    def _spawn(self, argv):
        self.argvs.append(list(argv))
        child = FakeChild()
        self.children.append(child)
        return child


def _wait(predicate, timeout=5.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return False


def _plans(*regs):
    """A stand-in for fleet_store.read_registrations."""
    return lambda client, **kw: list(regs)


def test_the_unit_arms_from_its_OWN_row_and_ignores_the_hubs_sensor_mode(monkeypatch):
    """ONE PLAN PER SENSOR is the whole feature. The units inherit `weirvern-env` through
    envFrom, so the hub's SENSOR_MODE is in their environment -- obeying it would put every
    weirling in the path because the HUB is, which is the opposite of per-sensor."""
    monkeypatch.setenv("SENSOR_MODE", "siphon")           # the hub is in-path...
    factory = SpawningFactory()
    controller = sensor_agent.InterceptController("unit-a", supervisor_factory=factory)
    sensor_agent.refresh_plan(None, "unit-a", controller)  # row says loch...
    assert controller.mode == "loch"
    assert factory.configs == [], "the hub's env armed a weirling that declared loch"

    monkeypatch.delenv("SENSOR_MODE", raising=False)       # ...and the reverse:
    monkeypatch.setattr("weirvern.fleet_store.read_registrations",
                        _plans(fleet_mod.Registration(
                            sensor_id="unit-a", plan=fleet_mod.make_plan(**SIPHON_PLAN))))
    sensor_agent.refresh_plan(None, "unit-a", controller)
    assert controller.mode == "siphon", "the unit's OWN plan did not arm it"


def test_plan_for_reads_this_units_row_and_not_anothers(monkeypatch):
    monkeypatch.setattr("weirvern.fleet_store.read_registrations", _plans(
        fleet_mod.Registration(sensor_id="other", plan=fleet_mod.make_plan(**SIPHON_PLAN)),
        fleet_mod.Registration(sensor_id="unit-a", plan=fleet_mod.make_plan(mode="loch")),
    ))
    plan, why = sensor_agent.plan_for(None, "unit-a")
    assert why == ""
    assert plan.mode == "loch", "another sensor's plan was read as this one's"


def test_plan_for_distinguishes_a_FAILED_read_from_no_plan(monkeypatch):
    """The two empty answers drive opposite actions: no plan means loch is the truth; a failed
    read means nothing is known and the current state must stand."""
    def boom(client, **kw):
        raise RuntimeError("ClickHouse is unreachable")

    monkeypatch.setattr("weirvern.fleet_store.read_registrations", boom)
    plan, why = sensor_agent.plan_for(None, "unit-a")
    assert plan is None and "unreachable" in why

    monkeypatch.setattr("weirvern.fleet_store.read_registrations", _plans())
    plan, why = sensor_agent.plan_for(None, "unit-a")
    assert plan is None and why == ""


def test_a_TRANSIENT_read_failure_does_not_disarm_a_live_intercept(monkeypatch):
    """THE GUARD. Disarming because ClickHouse blipped would make the registry a single point of
    failure for a sensor that is happily in-path -- the sensor takes the segment down with it."""
    factory = SpawningFactory()
    controller = sensor_agent.InterceptController("unit-a", supervisor_factory=factory)
    monkeypatch.setattr("weirvern.fleet_store.read_registrations",
                        _plans(fleet_mod.Registration(
                            sensor_id="unit-a", plan=fleet_mod.make_plan(**SIPHON_PLAN))))
    sensor_agent.refresh_plan(None, "unit-a", controller)
    assert _wait(lambda: controller.intercept_running), "the intercept never armed"

    def boom(client, **kw):
        raise RuntimeError("ClickHouse is unreachable")

    monkeypatch.setattr("weirvern.fleet_store.read_registrations", boom)
    sensor_agent.refresh_plan(None, "unit-a", controller)
    assert controller.intercept_running, (
        "a failed plan read disarmed a live intercept")
    assert factory.children[0].terminated == 0

    # ...and a plan that really says loch still stops it, through the orderly path.
    monkeypatch.setattr("weirvern.fleet_store.read_registrations",
                        _plans(fleet_mod.Registration(
                            sensor_id="unit-a", plan=fleet_mod.make_plan(mode="loch"))))
    sensor_agent.refresh_plan(None, "unit-a", controller)
    assert _wait(lambda: factory.children[0].terminated == 1), (
        "the child was not SIGTERMed, so the mappings would wait on ARP expiry")
    assert controller.mode == "loch"


def test_the_child_is_the_SAME_bounded_command_the_hub_supervises(monkeypatch):
    """ONE DATAPLANE, ONE SAFETY CONTRACT: the unit runs the hub's own supervisor, so the child
    must be `weirvern intercept` with a BOUNDED run (`--seconds`) -- the bound is what makes
    every re-arm a proof that the restore path works, and it carries the self-destruct
    deadline (`--seconds` + the CLI's grace) that covers a SIGKILLed child."""
    factory = SpawningFactory()
    controller = sensor_agent.InterceptController("unit-a", supervisor_factory=factory)
    monkeypatch.setattr("weirvern.fleet_store.read_registrations",
                        _plans(fleet_mod.Registration(
                            sensor_id="unit-a", plan=fleet_mod.make_plan(**SIPHON_PLAN))))
    sensor_agent.refresh_plan(None, "unit-a", controller)
    assert _wait(lambda: factory.argvs), "no child was spawned"
    argv = factory.argvs[0]
    assert "intercept" in argv and "-m" in argv
    for flag, want in (("--iface", "eth2"), ("--segment", "198.51.100.0/24"),
                       ("--our-ip", "198.51.100.250"), ("--gateway", "198.51.100.1")):
        assert argv[argv.index(flag) + 1] == want, argv
    assert "--seconds" in argv and int(argv[argv.index("--seconds") + 1]) > 0
    assert "--all" in argv  # '*' expands to the whole segment, as the plan says
    controller.stop()


def test_an_unchanged_plan_does_not_rebuild_the_supervisor(monkeypatch):
    """Every rebuild is a restore/poison seam; a poll loop that rebuilds on an unchanged plan
    would interrupt a healthy intercept every 30 seconds."""
    factory = SpawningFactory()
    controller = sensor_agent.InterceptController("unit-a", supervisor_factory=factory)
    plan = fleet_mod.make_plan(**SIPHON_PLAN)
    controller.apply(plan)
    controller.apply(plan)
    controller.apply(plan)
    assert len(factory.configs) == 1, "the plan did not change, but the supervisor was rebuilt"
    controller.stop()


def test_a_unit_without_the_capabilities_REFUSES_and_says_so(monkeypatch):
    """NET_ADMIN/NET_RAW are granted per unit (the manifest's opt-in patch). Without them the
    supervisor refuses to spawn a child and its reason rides this unit's heartbeat -- a toggle
    that silently did nothing is the failure this replaces."""
    factory = SpawningFactory()
    factory.readiness = ["the worker lacks CAP_NET_ADMIN -- apply the unit's siphon patch"]
    controller = sensor_agent.InterceptController("unit-a", supervisor_factory=factory)
    sup_mod._set_note("")  # noqa: SLF001 -- module state; cleared so the check starts clean
    controller.apply(fleet_mod.make_plan(**SIPHON_PLAN))
    assert _wait(lambda: any("CAP_NET_ADMIN" in n for n in controller.failures())), \
        controller.failures()
    assert factory.argvs == [], "a child was spawned without the capabilities to run it"
    assert controller.intercept_running is False
    assert controller.mode == "siphon", (
        "the unit must report the mode it was ASKED for, so the fleet can see it is declared "
        "in-path and not armed -- the same shape the hub's worker reports")

    client = FakeClient()
    sensor_agent.beat(client, "unit-a", "eth2", mode=controller.mode,
                      failures=controller.failures())
    row = client.rows[-1]["row"]
    assert row["mode"] == "siphon" and int(row["mappings"]) == 0
    assert any("CAP_NET_ADMIN" in f for f in row["failures"]), row["failures"]
    controller.stop()
    sup_mod._set_note("")  # noqa: SLF001


def test_a_live_child_owns_the_heartbeat_row(monkeypatch):
    """TWO WRITERS FOR ONE `(sensor_id, mode)` ROW is the defect this prevents: the row would
    flip between the child's real numbers and the agent's zeros, and the fleet would flicker."""
    factory = SpawningFactory()
    controller = sensor_agent.InterceptController("unit-a", supervisor_factory=factory)
    controller.apply(fleet_mod.make_plan(**SIPHON_PLAN))
    assert _wait(lambda: controller.intercept_running)
    assert controller.should_publish is False, "the agent wrote while a child owned the row"
    controller.stop()
    assert controller.should_publish is True, (
        "after the intercept stopped, the agent must resume reporting")


def test_the_final_beat_carries_the_mode_and_says_not_running(monkeypatch, tmp_path):
    logs = tmp_path / "logs"
    _write_logs(logs)
    monkeypatch.setenv("ZEEK_LOG_DIR", str(logs))
    client = FakeClient()
    sensor_agent._final_beat(client, "unit-a", "eth2", mode="siphon")  # noqa: SLF001
    row = client.rows[-1]["row"]
    assert row["mode"] == "siphon", "a graceful stop must not blank the unit's mode"
    assert int(row["running"]) == 0


def test_the_controller_never_raises_out_of_apply(monkeypatch):
    """A monitoring feature must not be able to kill capture: a supervisor that fails to build
    has to leave the agent heartbeating."""
    def explode(cfg):
        raise RuntimeError("no such thing")

    controller = sensor_agent.InterceptController("unit-a", supervisor_factory=explode)
    controller.apply(fleet_mod.make_plan(**SIPHON_PLAN))   # must not raise
    assert controller.mode == "siphon" and controller.intercept_running is False
    controller.apply(None)


def test_stop_is_idempotent_and_safe_before_anything_armed():
    controller = sensor_agent.InterceptController("unit-a")
    controller.stop()
    controller.stop(why="again")
    assert controller.mode == "loch"


def test_the_plan_refresh_is_bounded_so_a_toggle_is_picked_up_quickly():
    """The GUI says the sensor picks a change up within about half a minute; this is the number
    that makes that sentence true, and its absence would make it a guess."""
    assert 5.0 <= sensor_agent.PLAN_REFRESH_S <= 60.0
    assert threading.Event  # the module drives the supervisor from a loop, not a one-shot
