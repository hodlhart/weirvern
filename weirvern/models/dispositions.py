"""CE-2: every shadow channel gets one disposition, and a missing budget is not a promotion.

A channel with no generated-ground-truth fixed-budget result cannot be promoted. It can still be
merged into a named feature consumer or retired with a reason; what it cannot do is stay shadow
forever with a blank disposition.
"""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

POLICY_VERSION = "ce2-v1"
DISPOSITIONS = ("promote", "merge", "retire")

# The list is deliberately explicit. A channel absent from this list is a visible omission, not a
# silent default.
INVENTORY: tuple[dict[str, Any], ...] = (
    {"channel": "HDBSCAN", "unique_signal": "density-based novelty at a different resolution",
     "source": "ml_candidate_scores", "consumer": "", "disposition": "retire",
     "reason": "duplicate decision with the density detector it replaced; no fixed-budget win, "
     "so it adds cost without a "
               "distinct decision"},
    {"channel": "FlowSpecialist", "unique_signal": "flow-shape specialist",
     "source": "flows_aggregated", "consumer": "CROSS_SECTIONAL_FEATURES", "disposition": "merge",
     "reason": "its flow-shape columns already feed the production cross-sectional vector"},
    {"channel": "DNSSpecialist", "unique_signal": "DNS query shape and tunnel cadence",
     "source": "zeek_dns", "consumer": "ZEEK_CROSS_SECTIONAL_FEATURES (dns triple)",
     "disposition": "merge",
     "reason": "the DNS triple is already in the production vector; a second scorer duplicates it"},
    {"channel": "TLSSpecialist", "unique_signal": "JA4/JA3 handshake families",
     "source": "zeek_ssl", "consumer": "ZEEK_CROSS_SECTIONAL_FEATURES", "disposition": "merge",
     "reason": "JA4 integrity and family features feed the shared vector; keep one scorer"},
    {"channel": "BeaconSpecialist", "unique_signal": "periodicity and low-jitter callbacks",
     "source": "flows_aggregated_temporal", "consumer": "activity_regularity / burstiness",
     "disposition": "merge", "reason": "the temporal pair is already a production feature"},
    {"channel": "GraphSpecialist", "unique_signal": "host-to-host graph expansion",
     "source": "flows", "consumer": "", "disposition": "retire",
     "reason": "no named consumer and no fixed-budget result; retaining it would be a shadow "
               "channel with no decision"},
    {"channel": "External exposure", "unique_signal": "internet-facing service exposure",
     "source": "asset_scans", "consumer": "", "disposition": "retire",
     "reason": "asset posture answers this without a model score; a second alert path would "
               "duplicate the inventory"},
    {"channel": "Temporal", "unique_signal": "change in activity over time",
     "source": "flows_aggregated_temporal", "consumer": "activity_regularity / burstiness",
     "disposition": "merge", "reason": "the temporal features are already consumed by the baseline"},
    {"channel": "change-point", "unique_signal": "regime boundary detection",
     "source": "ml_changepoints", "consumer": "", "disposition": "retire",
     "reason": "no fixed-budget win and no feature consumer; a notice is not a separate alert"},
    {"channel": "asset posture", "unique_signal": "inventory and service drift",
     "source": "asset_scans", "consumer": "asset posture view", "disposition": "merge",
     "reason": "it is an operator view, not a fused-score model; keep it out of the ensemble"},
)


def build_record(*, inventory: tuple[dict[str, Any], ...] = INVENTORY,
                 review_date: str = "2027-02-11", now: datetime | None = None) -> dict[str, Any]:
    rows = []
    for item in inventory:
        disposition = str(item.get("disposition") or "").lower()
        if disposition not in DISPOSITIONS:
            raise ValueError(f"blank or invalid disposition for {item.get('channel')!r}")
        if disposition == "promote":
            raise ValueError(
                f"{item.get('channel')} cannot be promoted without generated-ground-truth evidence"
            )
        if disposition == "merge" and not item.get("consumer"):
            raise ValueError(f"{item.get('channel')} merge has no named consumer")
        if disposition == "retire" and not item.get("reason"):
            raise ValueError(f"{item.get('channel')} retirement has no reason")
        rows.append({
            "channel": item["channel"],
            "unique_signal": item.get("unique_signal", "not stated"),
            "source": item.get("source", "not stated"),
            "verification_coverage": "not measured",
            "budget_result": "not measured",
            "disposition": disposition,
            "consumer": item.get("consumer", ""),
            "reason": item.get("reason", ""),
            "review_date": review_date,
            "policy_version": POLICY_VERSION,
        })
    return {
        "generated_at": (now or datetime.now(UTC)).isoformat(),
        "policy_version": POLICY_VERSION,
        "review_date": review_date,
        "channels": rows,
        "promotions": [r["channel"] for r in rows if r["disposition"] == "promote"],
        "note": "No channel is promoted without a generated-ground-truth fixed-budget win.",
    }


def validate(record: dict[str, Any]) -> list[str]:
    failures = []
    channels = record.get("channels") or []
    if not channels:
        failures.append("inventory is empty")
    for row in channels:
        if row.get("disposition") not in DISPOSITIONS:
            failures.append(f"blank disposition: {row.get('channel')}")
    return failures


__all__ = ["DISPOSITIONS", "INVENTORY", "POLICY_VERSION", "build_record", "validate"]
