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
