"""Feature engineering.

Consolidates the v14 FeatureEngineer (host aggregates) with the v19 Phase 2
features (diversity + temporal). Pure functions — no DB access, unit-testable.

Feature sets (order matters — must match the training queries in models/):
  HOST_FEATURES        — 10 features, always available
  IF_FEATURES          — 14 features: host + diversity (isolation forest)
  DBSCAN_FEATURES      — 8 features: host + diversity + temporal (DBSCAN)
"""
from __future__ import annotations

import math
from typing import Any

HOST_FEATURES = [
    "log_bytes",
    "log_packets",
    "bytes_per_packet",
    "hour_sin",
    "hour_cos",
    "dow_sin",
    "dow_cos",
    "is_business_hours",
    "log_unique_dsts",
    "log_flow_count",
]

IF_FEATURES = HOST_FEATURES + [
    "log_unique_dst_ports",
    "port_entropy",
    "bytes_stddev_norm",
    "connection_density",
]

DBSCAN_FEATURES = [
    "log_bytes",
    "log_packets",
    "log_unique_dsts",
    "log_flow_count",
    "log_unique_dst_ports",
    "port_entropy",
    "activity_regularity",
    "burstiness",
]


def _safe_log1p(v: float) -> float:
    return math.log1p(max(float(v), 0.0))


def extract_features(flow: dict[str, Any], diversity: dict[str, Any] | None = None,
                     temporal: dict[str, Any] | None = None) -> dict[str, float]:
    """Build the full feature dict for one aggregated flow row.

    `flow` keys expected: total_bytes, total_packets, unique_dst_ips, flow_count,
    window_start (datetime). `diversity`/`temporal` are the per-host metric
    dicts from the diversity/temporal tables (any missing → safe defaults).
    """
    total_bytes = float(flow.get("total_bytes", 0) or 0)
    total_packets = float(flow.get("total_packets", 0) or 0)
    unique_dsts = float(flow.get("unique_dst_ips", 0) or 0)
    flow_count = float(flow.get("flow_count", 0) or 0)

    f: dict[str, float] = {
        "log_bytes": _safe_log1p(total_bytes),
        "log_packets": _safe_log1p(total_packets),
        "bytes_per_packet": total_bytes / max(total_packets, 1.0),
        "log_unique_dsts": _safe_log1p(unique_dsts),
        "log_flow_count": _safe_log1p(flow_count),
    }

    # Temporal cyclic encoding
    try:
        dt = flow["window_start"]
        hour = dt.hour
        dow = dt.weekday()
    except (KeyError, AttributeError):
        hour, dow = 0, 0
    f["hour_sin"] = math.sin(2 * math.pi * hour / 24)
    f["hour_cos"] = math.cos(2 * math.pi * hour / 24)
    f["dow_sin"] = math.sin(2 * math.pi * dow / 7)
    f["dow_cos"] = math.cos(2 * math.pi * dow / 7)
    f["is_business_hours"] = 1.0 if 8 <= hour <= 18 and dow < 5 else 0.0

    # Diversity metrics (Phase 2)
    if diversity:
        f["log_unique_dst_ports"] = _safe_log1p(diversity.get("unique_dst_ports", 0) or 0)
        f["port_entropy"] = float(diversity.get("port_entropy", 0.0) or 0.0)
        bytes_stddev = float(diversity.get("bytes_stddev", 0.0) or 0.0)
        f["bytes_stddev_norm"] = bytes_stddev / max(total_bytes, 1.0)
        unique_connections = float(diversity.get("unique_connections", 0.0) or 0.0)
        f["connection_density"] = unique_connections / max(flow_count, 1.0)
    else:
        f["log_unique_dst_ports"] = 0.0
        f["port_entropy"] = 0.0
        f["bytes_stddev_norm"] = 0.0
        f["connection_density"] = 1.0

    # Temporal metrics (Phase 2)
    if temporal:
        f["activity_regularity"] = float(temporal.get("activity_regularity", 1.0) or 1.0)
        f["burstiness"] = float(temporal.get("burstiness", 1.0) or 1.0)
    else:
        f["activity_regularity"] = 1.0
        f["burstiness"] = 1.0

    return f


def feature_vector(features: dict[str, float], names: list[str]) -> list[float]:
    """Ordered vector for sklearn — matches the order used at train time."""
    return [features.get(n, 0.0) for n in names]
