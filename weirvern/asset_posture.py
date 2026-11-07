"""AssetPostureModel: a small, explainable first model over Nmap change history.

WHY THIS MODEL IS DELIBERATELY SIMPLE
-------------------------------------
There are no reviewed labels yet. A deep model would have nothing to learn from; it would only
launder a deterministic opinion through a classifier. This model learns the *fleet's port
frequency* from `asset_service_history` and combines it with the change's own kind, confidence,
and service sensitivity. Every point of the score has a reason the operator can read.

It is a SHADOW model: it writes a score and a band, never a block. The first reviewed changes
become the labels for a later version.
"""
from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

MODEL_VERSION = "asset-posture-1"

# Ports that should never be exposed quietly. This is not a claim that every other port is safe;
# it is the small set where a new listener changes the risk conversation immediately.
SENSITIVE_PORTS = {
    22: "SSH",
    23: "Telnet",
    445: "SMB",
    2375: "Docker API (plaintext)",
    2376: "Docker API (TLS)",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    5985: "WinRM (HTTP)",
    5986: "WinRM (HTTPS)",
    6379: "Redis",
    9200: "Elasticsearch",
    10250: "Kubelet",
    6443: "Kubernetes API",
}

KIND_WEIGHT = {
    "port_opened": 0.40,
    "service_changed": 0.32,
    "version_changed": 0.20,
    "port_closed": 0.10,
}


@dataclass(frozen=True)
class PostureScore:
    score: float
    band: str
    reasons: tuple[str, ...]
    features: dict[str, float]
    model_version: str = MODEL_VERSION


def _band(score: float) -> str:
    if score < 0.35:
        return "expected"
    if score < 0.60:
        return "watch"
    if score < 0.80:
        return "suspicious"
    return "high"


class AssetPostureModel:
    """Learned port-frequency baseline plus an explainable change prior."""

    def __init__(self, port_frequency: Mapping[str, float] | None = None):
        self.port_frequency = dict(port_frequency or {})

    @classmethod
    def fit(cls, history: Iterable[Any]) -> AssetPostureModel:
        """Fit from `asset_service_history` rows: (port, protocol, service, ...).

        Frequency is per observation, not per host: a port that appears on every host every day
        is a baseline, while a port that has appeared once in a year is a novelty signal.
        """
        counts: Counter[str] = Counter()
        total = 0
        for row in history:
            try:
                port = int(row[0] or 0)
            except (TypeError, ValueError):
                continue
            if port <= 0:
                continue
            protocol = str(row[1] or "tcp").lower()
            counts[f"{protocol}/{port}"] += 1
            total += 1
        if not total:
            return cls()
        return cls({key: value / total for key, value in counts.items()})

    def score(self, change: Any, *, host_services: Iterable[Any] = ()) -> PostureScore:
        """Score one `ServiceChange` without mutating it.

        `host_services` is the host's current service snapshot; it answers "is this port new to
        this host" without another query in the caller's hot path.
        """
        kind = str(getattr(change, "kind", "") or "")
        port = int(getattr(change, "port", 0) or 0)
        protocol = str(getattr(change, "protocol", "tcp") or "tcp").lower()
        confidence = str(getattr(change, "confidence", "medium") or "medium").lower()

        reasons: list[str] = []
        score = KIND_WEIGHT.get(kind, 0.25)
        reasons.append(f"{kind.replace('_', ' ')} has a base weight of {score:.2f}")

        sensitive = SENSITIVE_PORTS.get(port)
        if sensitive:
            score += 0.20
            reasons.append(f"{protocol}/{port} is a sensitive service ({sensitive})")

        frequency = self.port_frequency.get(f"{protocol}/{port}")
        if frequency is None:
            score += 0.15
            reasons.append(f"{protocol}/{port} has not been seen in the fitted history")
        elif frequency < 0.002:
            score += 0.10
            reasons.append(f"{protocol}/{port} is rare in the fitted history ({frequency:.4f})")
        else:
            reasons.append(f"{protocol}/{port} is established in the fleet ({frequency:.4f})")

        host_ports = {int(row[0] or 0) for row in host_services if row}
        if host_ports and port not in host_ports:
            score += 0.08
            reasons.append("the port is not in the host's current service snapshot")

        if confidence == "high":
            score += 0.08
            reasons.append("Nmap observed the change with high confidence")
        elif confidence == "low":
            score -= 0.10
            reasons.append("the observation is low confidence; confirm the host was up")

        score = max(0.0, min(1.0, round(score, 3)))
        return PostureScore(
            score=score,
            band=_band(score),
            reasons=tuple(reasons),
            features={
                "kind_weight": KIND_WEIGHT.get(kind, 0.25),
                "sensitive_port": 1.0 if sensitive else 0.0,
                "port_frequency": float(frequency or 0.0),
                "new_to_host": 1.0 if host_ports and port not in host_ports else 0.0,
                "confidence_high": 1.0 if confidence == "high" else 0.0,
            },
        )
