"""Sensor-side adoption: key/CSR stays local, gateway mode is opt-in, legacy path remains."""
from __future__ import annotations

import json
import os
import stat

import pytest

from weirvern import fleet
from weirvern import weirling_client as wc
from weirvern.admin import sensor_agent


class _Response:
    def __init__(self, payload):
        self._payload = payload
        self._read = False

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self):
        return json.dumps(self._payload).encode()


def test_enroll_writes_private_key_chain_and_root(tmp_path, monkeypatch):
    seen = {}

    def fake_open(request, context, timeout=15.0):
        seen["url"] = request.full_url
        seen["body"] = json.loads(request.data)
        return _Response({
            "sensor_id": "sensor-a",
            "certificate": "LEAF",
            "intermediate": "INTERMEDIATE",
            "ca": "ROOT",
            "expires_at": "2027-01-01T00:00:00+00:00",
        })

    monkeypatch.setattr(wc, "_open", fake_open)
    result = wc.enroll("https://hub.example:30443", "one-time", "sensor-a", str(tmp_path),
                       address="198.51.100.2", segment="lab")
    assert result.sensor_id == "sensor-a"
    assert seen["url"].endswith("/v1/enroll")
    assert seen["body"]["token"] == "one-time"
    assert "BEGIN CERTIFICATE REQUEST" in seen["body"]["csr"]
    assert (tmp_path / "weirling.crt").read_text() == "LEAF\nINTERMEDIATE"
    assert (tmp_path / "weirling.key").read_text().startswith("-----BEGIN PRIVATE KEY-----")
    assert (tmp_path / "root-ca.crt").read_text() == "ROOT"
    assert stat.S_IMODE(os.stat(tmp_path / "weirling.key").st_mode) == 0o600


def test_gateway_plan_maps_the_nics_field_without_a_database():
    client = wc.GatewayClient("https://hub.example:30443", "c", "k", "ca")
    assert client.is_gateway is True
    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(client, "_request", lambda *a, **k: {"sensor_id": "s", "plan": None})
    assert client.plan() is None
    monkeypatch.undo()


def test_gateway_client_reads_a_plan_payload(monkeypatch):
    client = wc.GatewayClient("https://hub.example:30443", "c", "k", "ca")
    payload = {"sensor_id": "s", "enabled": True,
               "plan": {"mode": "siphon", "iface": "eth1", "segment": "198.51.100.0/24",
                        "addr": "198.51.100.2", "gateway": "198.51.100.1", "targets": "",
                        "nics": '[{"iface":"eth1","siphon":true}]'}}
    monkeypatch.setattr(client, "_request", lambda *a, **k: payload)
    plan = client.plan()
    assert isinstance(plan, fleet.SensorPlan)
    assert plan.iface == "eth1"
    assert plan.nics.startswith("[")


def test_gateway_mode_refuses_partial_certificate_env(monkeypatch):
    monkeypatch.setenv("WEIRLING_GATEWAY_URL", "https://hub.example:30443")
    monkeypatch.delenv("WEIRLING_CLIENT_CERT", raising=False)
    monkeypatch.delenv("WEIRLING_CLIENT_KEY", raising=False)
    monkeypatch.delenv("WEIRLING_ROOT_CA", raising=False)
    with pytest.raises(SystemExit):
        sensor_agent.gateway_client()


def test_gateway_plan_and_heartbeat_use_the_client(monkeypatch):
    plan = fleet.SensorPlan(mode="loch", iface="eth1")
    sent = {}

    class FakeGateway:
        is_gateway = True

        def plan(self):
            return plan

        def heartbeat(self, fields):
            sent.update(fields)
            return True

    gateway = FakeGateway()
    got, why = sensor_agent.plan_for(gateway, "sensor-a")
    assert (got, why) == (plan, "")
    monkeypatch.setattr("weirvern.admin.sensorwatch.observe",
                        lambda **kwargs: {"mode": "loch", "iface": "eth1", "running": True})
    monkeypatch.setattr("weirvern.admin.status.sensor_interfaces", lambda: ["eth1"])
    assert sensor_agent.beat(gateway, "sensor-a", "eth1") is True
    assert sent["iface"] == "eth1"
