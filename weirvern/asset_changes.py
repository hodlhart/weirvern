"""Asset-posture changes: the small, deterministic layer between Nmap and ML.

WHY THIS IS NOT A MODEL YET
---------------------------
A new open port is an observation, not a learned anomaly. The scanner can report it with high
confidence before there is any labelled history to train on. This module therefore produces a
stable change record; a future AssetPostureModel can learn from reviewed changes without
redefining what a change means.
"""
from __future__ import annotations

import hashlib
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ServiceChange:
    kind: str
    port: int
    protocol: str
    old_value: str
    new_value: str
    confidence: str
    evidence: str

    @property
    def change_key(self) -> str:
        raw = "|".join((
            self.kind, str(self.port), self.protocol, self.old_value, self.new_value,
        ))
        return hashlib.sha1(raw.encode()).hexdigest()


def _service_key(row: Any) -> tuple[int, str]:
    return int(row[0] or 0), str(row[1] or "tcp").lower()


def _describe(service: str, product: str, version: str) -> str:
    bits = [part for part in (service, product, version) if part]
    return " ".join(bits) if bits else "open service"


def detect_service_changes(previous: Iterable[Any], current: Iterable[Any]) -> list[ServiceChange]:
    """Compare two Nmap service snapshots by (port, protocol).

    A closed port is LOW confidence: the host may be down, a probe may have failed, or a firewall
    may have changed. A new open port is HIGH confidence because Nmap observed a live listener.
    The caller must not feed a failed scan into this function.
    """
    old = {_service_key(row): row for row in previous}
    new = {_service_key(row): row for row in current}
    changes: list[ServiceChange] = []

    for key in sorted(new.keys() - old.keys()):
        row = new[key]
        port, protocol = key
        changes.append(ServiceChange(
            kind="port_opened", port=port, protocol=protocol,
            old_value="", new_value=_describe(str(row[2] or ""), str(row[3] or ""), str(row[4] or "")),
            confidence="high", evidence=f"Nmap observed a new listener on {protocol}/{port}",
        ))

    for key in sorted(old.keys() - new.keys()):
        row = old[key]
        port, protocol = key
        changes.append(ServiceChange(
            kind="port_closed", port=port, protocol=protocol,
            old_value=_describe(str(row[2] or ""), str(row[3] or ""), str(row[4] or "")),
            new_value="", confidence="low",
            evidence=f"{protocol}/{port} was absent from the latest successful scan; confirm the host was up",
        ))

    for key in sorted(old.keys() & new.keys()):
        before, after = old[key], new[key]
        port, protocol = key
        old_service = (str(before[2] or ""), str(before[3] or ""), str(before[4] or ""))
        new_service = (str(after[2] or ""), str(after[3] or ""), str(after[4] or ""))
        if old_service == new_service:
            continue
        if old_service[1] != new_service[1]:
            kind, confidence = "service_changed", "medium"
        elif old_service[2] != new_service[2]:
            kind, confidence = "version_changed", "medium"
        else:
            kind, confidence = "service_changed", "medium"
        changes.append(ServiceChange(
            kind=kind, port=port, protocol=protocol,
            old_value=_describe(*old_service), new_value=_describe(*new_service),
            confidence=confidence,
            evidence=f"Nmap service fingerprint on {protocol}/{port} changed",
        ))
    return changes
