"""A remote Sluice gate must enforce the hub's rules without a database credential."""
from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from weirvern import sluice_store
from weirvern.gateway_gate import GatewayGateStore
from weirvern.sluice import GateState, Rule

ROOT = Path(__file__).resolve().parents[1]


def test_rule_wire_round_trip_preserves_expiry_and_resolved_addresses():
    rule = Rule(rule_id="r1", src_cidr="10.0.0.7/32", domain="example.com",
                resolved_ips=["192.0.2.10"], expires_at=datetime(2030, 1, 1, tzinfo=UTC))
    back = sluice_store.rule_from_wire(sluice_store.rule_to_wire(rule))
    assert back.rule_id == "r1"
    assert back.resolved_ips == ["192.0.2.10"]
    assert back.expires_at == datetime(2030, 1, 1, tzinfo=UTC)
    assert back.is_live()


def test_gate_store_reads_rules_and_writes_state_without_a_clickhouse_client():
    calls = []

    class Gateway:
        def gate_rules(self):
            return {"rules": [{"rule_id": "r1", "src_cidr": "10.0.0.7/32",
                               "mode": "block", "resolved_ips": []}], "problems": []}

        def gate_state(self):
            return {"state": "disarmed"}

        def gate_write_state(self, state):
            calls.append(("state", state))
            return True

        def gate_write_events(self, events):
            calls.append(("events", events))
            return {"written": len(events)}

    store = GatewayGateStore(Gateway())
    rules = store.load_live_rules()
    assert [r.rule_id for r in rules] == ["r1"]
    assert store.load_gate_state(None, "sensor") == {"state": "disarmed"}
    store.write_gate_state(None, "sensor", GateState(state="armed", iface="eth1"))
    assert calls[0][1]["iface"] == "eth1"
    assert store.write_events(None, [{"rule_id": "r1"}]) == 1


def test_worker_uses_a_gateway_store_before_opening_a_database():
    src = (ROOT / "weirvern" / "worker.py").read_text()
    branch = src.index("WEIRLING_GATEWAY_URL")
    connect = src.index("client = db.connect(settings)")
    assert branch < connect
    assert "GatewayGateStore" in src
    assert "derive=False, store=store" in src


def test_gateway_exposes_rules_state_and_events_routes():
    src = (ROOT / "weirvern" / "weirling_gateway.py").read_text()
    for route in ("/v1/gate/rules", "/v1/gate/state", "/v1/gate/events"):
        assert route in src
    assert "sluice_store.rule_to_wire" in src
    assert "write_gate_state" in src
