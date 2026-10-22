"""A remote Sluice gate that reads rules and writes state through the mTLS gateway.

WHY A STORE ADAPTER. `enforcement_pass` takes a store-shaped object rather than importing
ClickHouse so the decision layer stays testable. The hub passes `sluice_store`; a remote
gate passes this adapter. The gate then runs the SAME compiler, supervisor and safety
checks, but its rules arrive from the hub and its state returns there. No database
credential is placed on the sensor.
"""
from __future__ import annotations

from typing import Any

from weirvern import sluice_store
from weirvern.sluice import Rule

REMOTE_GATE = True


def _rule_from_wire(row: dict[str, Any]) -> Rule:
    return sluice_store.rule_from_wire(row)


class GatewayGateStore:
    """The subset of `sluice_store` used by the gate pass, backed by mTLS calls."""

    def __init__(self, gateway) -> None:
        self.gateway = gateway

    def load_live_rules(self, _client=None) -> list[Rule]:
        payload = self.gateway.gate_rules()
        return [_rule_from_wire(row) for row in payload.get("rules", []) if isinstance(row, dict)]

    def attach_resolved_ips(self, _client, rules: list[Rule], **_kw) -> tuple[list[Rule], list[str]]:
        # The gateway resolves domain rules against the hub's reverse DNS map before sending
        # them; the Rule objects already carry `resolved_ips`. A missing list is an empty one.
        return rules, []

    def derived_rules_for_detections(self, *_a, **_kw) -> list[dict]:
        return []

    def create_rule(self, *_a, **_kw):
        raise RuntimeError("a remote gate enforces the hub's rules and never creates one")

    def load_gate_state(self, _client, sensor: str) -> dict:
        return self.gateway.gate_state()

    def write_gate_state(self, _client, sensor: str, state) -> None:
        self.gateway.gate_write_state({
            "state": state.state,
            "iface": state.iface,
            "mgmt_iface": state.mgmt_iface,
            "rules_active": int(state.rules_active),
            "rules_total": int(state.rules_total),
            "packets_blocked": int(state.packets_blocked),
            "bytes_blocked": int(state.bytes_blocked),
            "detail": state.detail,
            "backend": state.backend,
            "backend_expected": state.backend_expected,
            "enforcement": state.enforcement,
        })

    def write_events(self, _client, events: list[dict]) -> int:
        return int(self.gateway.gate_write_events(events).get("written") or 0)
