"""Per-sensor, per-NIC configuration: one plan per interface, not one plan per hub.

WHY THIS EXISTS. A sensor can have several NICs, and they do not have to do the same
thing: eth1 may capture + intercept, eth2 may capture + enforce, a third may be passive.
The old model had one SENSOR_MODE, one CAPTURE_IFACE and one SLUICE_IFACE, so configuring
the second NIC overwrote the first and only one siphon could exist.

THE PLAN IS DATA, NOT A UI CONCERN. The hub worker and every weirling agent read the same
shape. A NIC may carry several roles -- capture, siphon, sluice -- because those are
independent mechanisms; only the management NIC is refused for every active role.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field

ROLES = ("capture", "siphon", "sluice")


class NicPlanError(ValueError):
    """The plan document is malformed or asks for an impossible combination."""


@dataclass
class NicPlan:
    iface: str
    capture: bool = False
    siphon: bool = False
    sluice: bool = False
    segment: str = ""
    addr: str = ""
    gateway: str = ""
    targets: str = "*"

    @property
    def roles(self) -> list[str]:
        return [r for r in ROLES if getattr(self, r)]

    @property
    def armed_mode(self) -> str:
        return "siphon" if self.siphon else "loch"

    def siphon_problems(self) -> list[str]:
        if not self.siphon:
            return []
        missing = [name for name, value in (
            ("segment", self.segment), ("addr", self.addr), ("gateway", self.gateway))
            if not str(value or "").strip()]
        if missing:
            return [f"{self.iface} is missing " + ", ".join(missing)]
        return []


@dataclass
class NicPlanSet:
    plans: dict[str, NicPlan] = field(default_factory=dict)

    @classmethod
    def from_json(cls, raw: str) -> NicPlanSet:
        if not str(raw or "").strip():
            return cls()
        try:
            data = json.loads(raw)
        except (TypeError, ValueError) as exc:
            raise NicPlanError(f"plans are not valid JSON: {exc}") from exc
        if not isinstance(data, dict):
            raise NicPlanError("plans must be a JSON object keyed by interface")
        plans: dict[str, NicPlan] = {}
        for iface, value in data.items():
            if not isinstance(value, dict):
                raise NicPlanError(f"{iface}: plan must be an object")
            plans[str(iface)] = NicPlan(
                iface=str(iface),
                capture=bool(value.get("capture")),
                siphon=bool(value.get("siphon")) or str(value.get("mode") or "") == "siphon",
                sluice=bool(value.get("sluice")),
                segment=str(value.get("segment") or ""),
                addr=str(value.get("addr") or value.get("our_ip") or ""),
                gateway=str(value.get("gateway") or ""),
                targets=str(value.get("targets") or "*"),
            )
        return cls(plans=plans)

    def capture_ifaces(self) -> list[str]:
        return [i for i, p in self.plans.items() if p.capture]

    def siphon_ifaces(self) -> list[str]:
        return [i for i, p in self.plans.items() if p.siphon]

    def sluice_ifaces(self) -> list[str]:
        return [i for i, p in self.plans.items() if p.sluice]

    def validate(self, *, mgmt_iface: str = "") -> list[str]:
        problems: list[str] = []
        for iface, plan in self.plans.items():
            if mgmt_iface and iface == mgmt_iface and plan.roles:
                problems.append(f"{iface} is the management interface and cannot carry {', '.join(plan.roles)}")
            if not plan.roles:
                continue
            if plan.siphon:
                problems.extend(plan.siphon_problems())
            if plan.sluice and not (plan.siphon or plan.capture):
                # A sluice-only NIC can still block traffic it forwards only if something
                # else routes it; that is a valid bridge/routed topology, so this is not
                # a refusal. Kept as a property of the plan rather than guessed by the gate.
                pass
        return problems
