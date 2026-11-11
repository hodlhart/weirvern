"""PR-2: automatic canary promotion and rollback, inside the operator-approved envelope.

This module is deliberately a pure policy. It does not read ClickHouse or write a card; it takes
the evidence a canary run produced and returns one action with the reasons. That keeps the hard
part testable and keeps the caller responsible for the durable ledger and card transition.

NO GLOBAL UN-SHADOW. A promotion is per candidate and is reversible; `ML_SHADOW=false` is not a
promotion mechanism.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

POLICY_VERSION = "pr2-v1"
SHADOW_MIN_DAYS = 14
CANARY_MAX_P95_RATIO = 1.2
MAX_IN_FLIGHT = 1
ACTIONS = ("freeze", "hold", "block", "rollback", "promote", "none")


@dataclass(frozen=True)
class CanaryEvidence:
    candidate_id: str
    artifact_hash: str
    model_card_status: str
    generator_version: str
    gate_report_id: str
    gate_promote: bool
    shadow_days: float
    shadow_pageable: int
    soak_ok: bool
    canary_days: float
    canary_requests: int
    canary_errors: int
    canary_p95_s: float | None
    baseline_p95_s: float | None
    telemetry_fresh: bool
    kill_switch: bool
    extra: dict[str, Any] = field(default_factory=dict)


def _reasons(evidence: CanaryEvidence, active_in_flight: int) -> list[str]:
    reasons: list[str] = []
    if evidence.kill_switch:
        return ["kill switch is active; automation is frozen"]
    if active_in_flight >= MAX_IN_FLIGHT:
        reasons.append("another promotion is in flight")
    if evidence.model_card_status != "canary":
        reasons.append(f"model card status is {evidence.model_card_status}, not canary")
    if not evidence.artifact_hash:
        reasons.append("candidate artifact hash is missing")
    if not evidence.generator_version:
        reasons.append("generator version is missing")
    if not evidence.telemetry_fresh:
        reasons.append("telemetry is stale or degraded")
    if evidence.shadow_days < SHADOW_MIN_DAYS or not evidence.soak_ok:
        reasons.append(f"shadow soak is {evidence.shadow_days:.1f} days; "
                       f"requires {SHADOW_MIN_DAYS} days and a passed soak")
    if evidence.shadow_pageable > 0:
        reasons.append(f"shadow soak emitted {evidence.shadow_pageable} pageable alerts")
    if evidence.canary_errors > 0:
        reasons.append(f"canary errors: {evidence.canary_errors}")
    if (evidence.canary_p95_s is not None and evidence.baseline_p95_s is not None
            and evidence.baseline_p95_s > 0
            and evidence.canary_p95_s > evidence.baseline_p95_s * CANARY_MAX_P95_RATIO):
        reasons.append("canary p95 latency exceeds the tolerated ratio")
    return reasons


def decide(evidence: CanaryEvidence, *, active_in_flight: int = 0) -> dict[str, Any]:
    """Return exactly one action. The order is the safety order, not a score."""
    reasons = _reasons(evidence, active_in_flight)
    bad_input = (not evidence.telemetry_fresh or not evidence.generator_version
                 or evidence.model_card_status != "canary" or not evidence.artifact_hash)
    short_soak = (evidence.shadow_days < SHADOW_MIN_DAYS or not evidence.soak_ok
                  or evidence.shadow_pageable > 0)
    red_canary = (evidence.canary_errors > 0 or not evidence.gate_promote
                  or (evidence.canary_p95_s is not None
                      and evidence.baseline_p95_s is not None
                      and evidence.baseline_p95_s > 0
                      and evidence.canary_p95_s > evidence.baseline_p95_s * CANARY_MAX_P95_RATIO))
    if evidence.kill_switch:
        action = "freeze"
    elif bad_input:
        action = "block"
    elif short_soak or active_in_flight >= MAX_IN_FLIGHT:
        action = "hold"
    elif red_canary:
        action = "rollback"
    else:
        action = "promote"
    return {
        "action": action,
        "reasons": reasons or ["all policy checks passed"],
        "policy_version": POLICY_VERSION,
        "candidate_id": evidence.candidate_id,
        "artifact_hash": evidence.artifact_hash,
        "decided_at": datetime.now(UTC).isoformat(),
        "max_in_flight": MAX_IN_FLIGHT,
        "shadow_min_days": SHADOW_MIN_DAYS,
        "canary_max_p95_ratio": CANARY_MAX_P95_RATIO,
        "gate_report_id": evidence.gate_report_id,
    }


def next_card_status(current: str, action: str) -> str:
    """The only status transitions the policy is allowed to make."""
    if action == "promote":
        return "production"
    if action == "rollback":
        return "shadow"
    if action == "freeze":
        return current
    if action == "hold":
        return current
    return current


def ledger_entry(decision: dict[str, Any], *, previous_status: str,
                 next_status: str) -> dict[str, Any]:
    if decision.get("action") not in ACTIONS:
        raise ValueError(f"unknown promotion action: {decision.get('action')!r}")
    return {
        "kind": "promotion",
        "policy_version": decision["policy_version"],
        "candidate_id": decision["candidate_id"],
        "artifact_hash": decision["artifact_hash"],
        "action": decision["action"],
        "reasons": decision["reasons"],
        "gate_report_id": decision.get("gate_report_id"),
        "previous_status": previous_status,
        "next_status": next_status,
        "decided_at": decision["decided_at"],
    }


__all__ = [
    "ACTIONS", "CANARY_MAX_P95_RATIO", "CanaryEvidence", "MAX_IN_FLIGHT", "POLICY_VERSION",
    "SHADOW_MIN_DAYS", "decide", "ledger_entry", "next_card_status",
]
