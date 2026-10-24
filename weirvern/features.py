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

from weirvern.zeek_features import ZEEK_DBSCAN_FEATURES, ZEEK_FEATURES

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

# Zeek-derived features are APPENDED to the NetFlow ones, never interleaved.
#
# WHY THE ORDER MATTERS AND WHY THEY GO LAST: a model records its `feature_columns` and
# rebuilds its input vector by name, so inserting a feature in the middle would silently
# reinterpret every column after it for any model trained before the change -- the vector
# would still have the right LENGTH, so nothing would raise, and every prediction would be
# quietly wrong. Appending keeps existing vectors valid up to the new tail.
#
# WHY ZEEK ADDS SOMETHING THE NETFLOW FEATURES CANNOT: bytes/packets/diversity describe
# VOLUME and BREADTH. They cannot see what the traffic IS. Measured on the live deployment,
# one host-window showed 89 connections of which 88 were unanswered SYNs, with zero response
# bytes -- a scan, and one that NetFlow reports as modest traffic. Zeek's conn_state shows
# it directly.
IF_FEATURES = HOST_FEATURES + [
    "log_unique_dst_ports",
    "port_entropy",
    "bytes_stddev_norm",
    "connection_density",
] + ZEEK_FEATURES

DBSCAN_FEATURES = [
    "log_bytes",
    "log_packets",
    "log_unique_dsts",
    "log_flow_count",
    "log_unique_dst_ports",
    "port_entropy",
    "activity_regularity",
    "burstiness",
] + ZEEK_DBSCAN_FEATURES

# ── THE FEATURE SCHEMA VERSION (review round 2026-10-15) ─────────────────────────────────────
#
# Bump when the SHAPE of any feature list above changes -- a feature added, removed or
# reordered. Detector artifacts are versioned by this in their FILENAME
# (models/base.artifact_path -> `<name>_v{N}.pkl`), so a bump moves to a new file and leaves
# the previous artifacts on disk instead of overwriting the only copy; and load() refuses an
# artifact whose recorded schema disagrees with the running code, which routes the detector
# into its normal retrain path. Before this, `_v1` was a literal while the code comment
# claimed versioning, and a feature-set change could keep loading an incompatible artifact
# that scored 0.0 for hours (or, same width, silently reinterpreted every column).
# BUMPED TO 2 (2026-10-16): DBSCAN\'s Zeek subset gained the JA4 pair (zeek_ja4_count,
# zeek_ja4_novelty), so the DBSCAN vector changed SHAPE from 14 to 16 columns. v1 artifacts are
# refused at load and the detectors retrain into `_v2.pkl` files; the v1 files stay on disk, and
# a rollback reverts this bump rather than deleting them.
# BUMPED TO 3 (2026-10-16): the same subset gained the DNS triple (count, mean query entropy,
# rcode error ratio) -- "make sure dns is added to all ml as well". DBSCAN\'s vector changed
# shape from 16 to 19 columns; v2 artifacts are refused at load and the detector retrains into
# `_v3.pkl` on its normal cadence (or immediately from Models -> force a retrain). The v2
# files stay on disk.
# BUMPED TO 4 (2026-10-24): the production feature block gained the DNS shape and graph
# relationship features -- eight DNS and five graph columns appended after the JA4 novelty
# feature. The vector changes from 50 to 63 Zeek columns (the full IF vector grows by the same
# thirteen); v3 artifacts are refused at load, so every detector retrains into `_v4.pkl` rather
# than scoring a vector whose tail it was never fitted on. The previous artifacts remain on disk.
FEATURE_SCHEMA_VERSION = 4


def _safe_log1p(v: float) -> float:
    return math.log1p(max(float(v), 0.0))


def extract_features(flow: dict[str, Any], diversity: dict[str, Any] | None = None,
                     temporal: dict[str, Any] | None = None,
                     zeek: dict[str, Any] | None = None,
                     zeek_baseline: dict[str, Any] | None = None) -> dict[str, float]:
    """Build the full feature dict for one aggregated flow row.

    `flow` keys expected: total_bytes, total_packets, unique_dst_ips, flow_count,
    window_start (datetime). `diversity`/`temporal` are the per-host metric
    dicts from the diversity/temporal tables (any missing → safe defaults).

    `zeek` is the per-(host, 5-minute window) Zeek summary row -- see
    weirvern/zeek_features.py. `zeek_baseline` is the host's longer-window service and
    fingerprint history, which is what makes novelty measurable rather than mere variety.

    WHEN `zeek` IS None OR EMPTY, THE ZEEK FEATURES ARE ZERO AND `zeek_present` IS 0. That
    flag is part of the vector on purpose: "Zeek did not observe this host-window" and "Zeek
    observed it and there was nothing unusual" are different facts, and only the second is
    evidence of normality. Without the flag the model would learn that a whole class of hosts
    is defined by empty features, which is an artefact of two sensors seeing different
    traffic rather than a property of the network. Measured on the test box: 35 Zeek hosts
    against 88 NetFlow hosts with an overlap of 2, so this is the common case there.
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

    # ── TEMPORAL CYCLIC ENCODING, ON CLICKHOUSE'S DAY NUMBERING (audit: scale mismatch) ────────
    #
    # `dow` MUST be ClickHouse's `toDayOfWeek`, which is Monday=1 .. Sunday=7, NOT Python's
    # `datetime.weekday()`, which is Monday=0 .. Sunday=6. The training queries in
    # models/detectors.py encode the day with:
    #
    #     sin(2*pi()*toDayOfWeek(a.window_start)/7)
    #
    # and this function encoded the same window with a day number ONE LOWER. MEASURED against the
    # cluster for a Wednesday window, which both agree is day-index 3 vs 2:
    #
    #     from ClickHouse: dow_sin  0.4338837  dow_cos -0.9009689
    #     from this module: dow_sin  0.9749279  dow_cos -0.2225209
    #
    # So the model was trained on one point on the weekly circle and asked to score another. Every
    # score was computed on a vector that does not mean what the training row meant: the model was
    # not wrong, it was answering a different question. That is the whole of the "train/score scale
    # mismatch", and it is silent -- the vector has the right length and every number is a valid
    # number, so nothing raises and no metric looks wrong.
    #
    # `toDayOfWeek` IS ALSO WHAT MAKES THE WEEKDAY RANGE NON-CONTIGUOUS-AT-THE-EDGE, which is why
    # the value is converted to Python's convention FIRST and then used for everything downstream.
    # Writing the sine with CH's number but leaving `is_business_hours` on Python's would put the
    # two halves of the same time encoding on different calendars.
    try:
        dt = flow["window_start"]
        hour = dt.hour
        # `isoweekday()` is Monday=1..Sunday=7 -- the SAME numbering as ClickHouse's toDayOfWeek,
        # and the only Python accessor that is. Using it directly is what keeps this readable as
        # "the same number the query uses".
        dow = dt.isoweekday()
    except (KeyError, AttributeError):
        hour, dow = 0, 0
    f["hour_sin"] = math.sin(2 * math.pi * hour / 24)
    f["hour_cos"] = math.cos(2 * math.pi * hour / 24)
    f["dow_sin"] = math.sin(2 * math.pi * dow / 7)
    f["dow_cos"] = math.cos(2 * math.pi * dow / 7)
    # ClickHouse: `toDayOfWeek(...) < 6` -> Mon..Fri, because 6 is Saturday. The same five days in
    # Python's numbering would be `< 5`, so this predicate now reads on the SAME number as the
    # query rather than on a translated one. A test pins the two against each other for all 7 days.
    f["is_business_hours"] = 1.0 if 8 <= hour <= 18 and dow < 6 else 0.0

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

    # Zeek-derived features. Imported here rather than at module scope only for the pure
    # function, so this module stays importable without the Zeek query builders.
    from weirvern.zeek_features import extract_zeek_features

    f.update(extract_zeek_features(zeek or {}, zeek_baseline))

    return f


def feature_vector(features: dict[str, float], names: list[str]) -> list[float]:
    """Ordered vector for sklearn — matches the order used at train time."""
    return [features.get(n, 0.0) for n in names]
