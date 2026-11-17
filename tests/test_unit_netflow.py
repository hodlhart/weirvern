"""NetFlow from a unit: the collector it can host, and the records it can ship home.

THE OTHER HALF IS IN `test_tap.py`. Producing flow records from a sensor's own capture (tcpdump
segments -> softflowd -> IPFIX) used to be tested here because the worker owned it; since
2026-11-17 it is `weirvern.tap`, launched at the capture boundary, and its decision table and
supervision live there. This file keeps what is still the UNIT's: a collector a segment's
exporter can reach, and the shipper that carries its rows to the hub.

Both halves ship DISABLED: an exporter pointed at a box that is not shipping is a silent hole,
and a tap on a box whose file nothing reads is a file that grows forever.
"""

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _settings(**over):
    import dataclasses

    from weirvern.config import get_settings

    return dataclasses.replace(get_settings(), **over)


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
    monkeypatch.setattr(ingester_mod, "save_tail_state",
                        lambda path, state: saved.update({"ok": True}))

    read = sensor_agent.ship_flows_once(object(), path=str(flow_file), allow="198.51.100.0/24")
    assert read == 3, "the rows the collector wrote were not shipped"
    assert calls["path"] == str(flow_file) and calls["allow"] == "198.51.100.0/24", (
        "the exclusion/allow filter must travel with every pass")
    assert saved.get("ok"), (
        "the byte cursor was not checkpointed: a restart would re-insert everything")


def test_a_unit_with_no_exporter_is_not_an_error(tmp_path, monkeypatch):
    from weirvern import ingester as ingester_mod
    from weirvern.admin import sensor_agent

    def explode(*_a, **_kw):
        raise AssertionError("nothing to ship, so no query should run")

    monkeypatch.setattr(ingester_mod, "tail_and_insert", explode)
    assert sensor_agent.ship_flows_once(object(), path=str(tmp_path / "missing.jsonl")) == 0


def test_the_shipper_cannot_take_the_heartbeat_down(monkeypatch):
    """The heartbeat is the unit's LIVENESS -- it is how the fleet view knows this sensor exists.
    Flow shipping is a convenience on top, so a dead transport, a missing client or a raising pass
    is a log line and a retry, never a crash."""
    import threading

    from weirvern import db
    from weirvern.admin import sensor_agent

    calls = {"n": 0}

    def failing_connect(*_a, **_kw):
        calls["n"] += 1
        raise RuntimeError("hub unreachable")

    # THE LAB ESCAPE, so this test drives the ClickHouse path it is about. Without it the shipper
    # stops at the mTLS refusal (covered by the next test), which is a different failure.
    monkeypatch.setenv("WEIRLING_ALLOW_DIRECT_CLICKHOUSE", "1")
    monkeypatch.delenv("WEIRLING_GATEWAY_URL", raising=False)
    monkeypatch.setattr(db, "connect", failing_connect)
    stop = threading.Event()

    def stopper():
        stop.wait(0.2)
        stop.set()

    threading.Thread(target=stopper, daemon=True).start()
    sensor_agent._flow_shipper(_settings(), stop)  # must return normally
    assert calls["n"] >= 1, "the shipper never even tried to connect"


def test_a_shipper_with_NO_CA_SURVIVES_THE_REFUSAL_TOO(monkeypatch, caplog):
    """The same guarantee for the mTLS rule: a unit that cannot authenticate must LOG and return,
    not raise out of the shipping thread -- the heartbeat still owns the unit's liveness."""
    import logging
    import threading

    from weirvern.admin import sensor_agent

    for var in ("WEIRLING_GATEWAY_URL", "WEIRLING_CLIENT_CERT", "WEIRLING_CLIENT_KEY",
                "WEIRLING_ROOT_CA", "WEIRLING_ALLOW_DIRECT_CLICKHOUSE"):
        monkeypatch.delenv(var, raising=False)
    stop = threading.Event()

    def stopper():
        stop.wait(0.2)
        stop.set()

    threading.Thread(target=stopper, daemon=True).start()
    with caplog.at_level(logging.WARNING, logger="weirvern.sensor_agent"):
        sensor_agent._flow_shipper(_settings(), stop)  # must return normally
    assert "shipping pass failed" in caplog.text, caplog.text
    assert "mTLS" in caplog.text.replace("mtls", "mTLS"), caplog.text


# ── the manifest contract ────────────────────────────────────────────────────────────────────────


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


def test_a_unit_that_ships_also_PRODUCES_from_its_own_capture():
    """The two halves are one switch. `WEIRLING_NETFLOW` starts the shipper AND the tap thread;
    a unit that is not shipping must not spend CPU summarising packets into a file nobody reads.

    The tap thread must read THIS unit's mode, never `SENSOR_MODE` (which describes the hub's
    sensor and arrives through envFrom -- the exact leak the per-weirling plan exists to stop).
    """
    agent = (ROOT / "weirvern/admin/sensor_agent.py").read_text()
    assert "def _tap_supervisor" in agent
    body = agent[agent.index("def _tap_supervisor"):]
    body = body[:body.index("def main()")]
    assert "sensor_mode=controller.mode" in body, (
        "the unit's tap is reading a mode other than its own plan's")
    assert "siphon_live=controller.intercept_running" in body, (
        "the unit has direct evidence of its intercept; it must not fall back to a config read")
    # Started inside the shipping branch, after the controller exists.
    startup = agent[agent.index("    controller = InterceptController(sid)"):]
    startup = startup[:startup.index("    client = None")]
    assert "if flow_shipping_enabled():" in startup and "_tap_supervisor" in startup
