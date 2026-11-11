"""GT-4: canary and honeypot positives are machine evidence with one event per hit.

A canary is only useful if touching it is inherently suspicious. The event carries the timestamp,
source, service/token id and a stable fingerprint; an authorised health check is tagged and
excluded before it can become a positive. A canary hit can never be counted as benign background.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

SERVICES = {
    "canary-ssh": {"port": 2222, "token": "ssh-token"},
    "canary-http": {"port": 8080, "token": "http-token"},
}
AUTHORIZED_MARKER = "health"


@dataclass(frozen=True)
class CanaryHit:
    src_addr: str
    service_id: str
    token: str
    fingerprint: str
    observed_at: datetime
    authorized: bool = False


def fingerprint(service_id: str, token: str) -> str:
    return hashlib.sha256(f"{service_id}:{token}".encode()).hexdigest()[:16]


def event_from_hit(hit: CanaryHit, *, generator_version: str) -> dict[str, Any] | None:
    if hit.service_id not in SERVICES:
        raise ValueError(f"unknown canary service: {hit.service_id!r}")
    if hit.token != SERVICES[hit.service_id]["token"]:
        raise ValueError("canary token does not match the service")
    if hit.authorized:
        return None
    return {
        "src_addr": hit.src_addr,
        "window_start": hit.observed_at.isoformat(),
        "label": "attack",
        "label_source": "canary",
        "confidence": 1.0,
        "provenance": f"canary hit on {hit.service_id}",
        "scenario_id": hit.service_id,
        "generator_version": generator_version,
        "service_id": hit.service_id,
        "token_id": hashlib.sha256(hit.token.encode()).hexdigest()[:12],
        "fingerprint": hit.fingerprint or fingerprint(hit.service_id, hit.token),
        "generated_at": datetime.now(UTC).isoformat(),
    }


def health(events: list[dict[str, Any]]) -> dict[str, Any]:
    per: dict[str, int] = {}
    for event in events:
        service = str(event.get("service_id") or "unknown")
        per[service] = per.get(service, 0) + 1
    return {"services": sorted(SERVICES), "hits": per,
            "state": "not measured" if not events else "observed"}


__all__ = ["AUTHORIZED_MARKER", "SERVICES", "CanaryHit", "event_from_hit", "fingerprint", "health"]
