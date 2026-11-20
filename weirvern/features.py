"""Feature engineering.

Consolidates the v14 FeatureEngineer (host aggregates) with the v19 Phase 2
features (diversity + temporal). Pure functions — no DB access, unit-testable.

Feature sets (order matters — must match the training queries in models/):
  HOST_FEATURES            — 10 features, always available
  IF_FEATURES              — 14 features: host + diversity (isolation forest)
  CROSS_SECTIONAL_FEATURES — 19 features: host + diversity + temporal + the Zeek subset
                             (kNN distance and LOF, which share the vector -- and nothing else)
"""
from __future__ import annotations

import math
from typing import Any

from weirvern.zeek_features import ZEEK_CROSS_SECTIONAL_FEATURES, ZEEK_FEATURES

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

CROSS_SECTIONAL_FEATURES = [
    "log_bytes",
    "log_packets",
    "log_unique_dsts",
    "log_flow_count",
    "log_unique_dst_ports",
    "port_entropy",
    "activity_regularity",
    "burstiness",
] + ZEEK_CROSS_SECTIONAL_FEATURES

# EVERY COLUMN THE ENSEMBLE CAN CONSUME, once each: the wide vector plus the two temporal features
# only the cross-sectional pair uses. This is the denominator for a window's telemetry coverage (see
# models/missing.py) — the question it answers is "how much of what the models look at was actually
# measured for this host-window", so it must span every detector, not just the wide pair. 79 columns
# today; the number is not written down anywhere that can drift.
TELEMETRY_FEATURES = IF_FEATURES + [
    name for name in CROSS_SECTIONAL_FEATURES if name not in IF_FEATURES
]

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
# BUMPED TO 2 (2026-10-16): the cross-sectional Zeek subset gained the JA4 pair (zeek_ja4_count,
# zeek_ja4_novelty), so that vector changed SHAPE from 14 to 16 columns. v1 artifacts are
# refused at load and the detectors retrain into `_v2.pkl` files; the v1 files stay on disk, and
# a rollback reverts this bump rather than deleting them.
# BUMPED TO 3 (2026-10-16): the same subset gained the DNS triple (count, mean query entropy,
# rcode error ratio) -- "make sure dns is added to all ml as well". That vector changed
# shape from 16 to 19 columns; v2 artifacts are refused at load and the detector retrains into
# `_v3.pkl` on its normal cadence (or immediately from Models -> force a retrain). The v2
# files stay on disk.
# BUMPED TO 4 (2026-10-24): the production feature block gained the DNS shape and graph
# relationship features -- eight DNS and five graph columns appended after the JA4 novelty
# feature. The vector changes from 50 to 63 Zeek columns (the full IF vector grows by the same
# thirteen); v3 artifacts are refused at load, so every detector retrains into `_v4.pkl` rather
# than scoring a vector whose tail it was never fitted on. The previous artifacts remain on disk.
FEATURE_SCHEMA_VERSION = 5


def _safe_log1p(v: float) -> float:
    return math.log1p(max(float(v), 0.0))


def _number(source: dict[str, Any] | None, key: str, default: float,
            preserve_missing: bool) -> float | None:
    """One numeric value from a source dict, or None when it was not measured.

    With `preserve_missing` False this reproduces the historical `float(x.get(k, d) or d)`
    exactly, including the way a NULL in ClickHouse collapsed into the default. With it True,
    an absent key or a None value is None — the caller decides how to impute, and 0 is no
    longer allowed to mean both "zero" and "we never read this".
    """
    if source is None:
        return None if preserve_missing else float(default)
    raw = source.get(key)
    if raw is None:
        return None if preserve_missing else float(default)
    try:
        return float(raw)
    except (TypeError, ValueError):
        return None if preserve_missing else float(default)


def extract_features(flow: dict[str, Any], diversity: dict[str, Any] | None = None,
                     temporal: dict[str, Any] | None = None,
                     zeek: dict[str, Any] | None = None,
                     zeek_baseline: dict[str, Any] | None = None,
                     *, preserve_missing: bool = False) -> dict[str, float | None]:
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

    `preserve_missing=True` changes what "missing" produces: the absent source becomes None
    (and `zeek_present` None too), which the missing-aware scorer imputes from the training
    median against an explicit indicator. A measured zero stays 0 in both modes. The default
    is False, so every existing caller gets the historical constants unchanged.
    """
    # THE FOUR FLOW TOTALS ARE ALWAYS PRESENT for a row that reached the ensemble — they are
    # the group-by keys' own aggregates. `preserve_missing` still honours a genuinely absent
    # key, because an aggregate row assembled by a caller that did not select it is not the
    # same fact as a host that moved zero bytes.
    total_bytes = _number(flow, "total_bytes", 0.0, preserve_missing)
    total_packets = _number(flow, "total_packets", 0.0, preserve_missing)
    unique_dsts = _number(flow, "unique_dst_ips", 0.0, preserve_missing)
    flow_count = _number(flow, "flow_count", 0.0, preserve_missing)

    f: dict[str, float | None] = {
        "log_bytes": None if total_bytes is None else _safe_log1p(total_bytes),
        "log_packets": None if total_packets is None else _safe_log1p(total_packets),
        "bytes_per_packet": (None if total_bytes is None or total_packets is None
                             else total_bytes / max(total_packets, 1.0)),
        "log_unique_dsts": None if unique_dsts is None else _safe_log1p(unique_dsts),
        "log_flow_count": None if flow_count is None else _safe_log1p(flow_count),
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
        has_window = True
    except (KeyError, AttributeError):
        hour, dow = 0, 0
        has_window = False
    if preserve_missing and not has_window:
        # Without a window there is no time of day to encode. The historical zeros are a
        # timestamp of midnight, which is a MEASUREMENT the caller never supplied.
        f["hour_sin"] = f["hour_cos"] = None
        f["dow_sin"] = f["dow_cos"] = None
        f["is_business_hours"] = None
    else:
        f["hour_sin"] = math.sin(2 * math.pi * hour / 24)
        f["hour_cos"] = math.cos(2 * math.pi * hour / 24)
        f["dow_sin"] = math.sin(2 * math.pi * dow / 7)
        f["dow_cos"] = math.cos(2 * math.pi * dow / 7)
        # ClickHouse: `toDayOfWeek(...) < 6` -> Mon..Fri, because 6 is Saturday. The same five
        # days in Python's numbering would be `< 5`, so this predicate now reads on the SAME
        # number as the query rather than on a translated one. A test pins the two against each
        # other for all 7 days.
        f["is_business_hours"] = 1.0 if 8 <= hour <= 18 and dow < 6 else 0.0

    # Diversity metrics (Phase 2)
    if diversity:
        ports = _number(diversity, "unique_dst_ports", 0.0, preserve_missing)
        entropy = _number(diversity, "port_entropy", 0.0, preserve_missing)
        bytes_stddev = _number(diversity, "bytes_stddev", 0.0, preserve_missing)
        unique_connections = _number(diversity, "unique_connections", 0.0, preserve_missing)
        f["log_unique_dst_ports"] = None if ports is None else _safe_log1p(ports)
        f["port_entropy"] = entropy
        f["bytes_stddev_norm"] = (
            None if bytes_stddev is None or total_bytes is None
            else bytes_stddev / max(total_bytes, 1.0)
        )
        f["connection_density"] = (
            None if unique_connections is None or flow_count is None
            else unique_connections / max(flow_count, 1.0)
        )
    else:
        # No diversity table for this window: four features were not measured. With the flag
        # off this stays the historical constants (0/0/0/1.0) the models were trained on;
        # with it on they are None and the scorer imputes the training-time neutral.
        f["log_unique_dst_ports"] = None if preserve_missing else 0.0
        f["port_entropy"] = None if preserve_missing else 0.0
        f["bytes_stddev_norm"] = None if preserve_missing else 0.0
        f["connection_density"] = None if preserve_missing else 1.0

    # Temporal metrics (Phase 2)
    if temporal:
        f["activity_regularity"] = _number(temporal, "activity_regularity", 1.0,
                                           preserve_missing)
        f["burstiness"] = _number(temporal, "burstiness", 1.0, preserve_missing)
    else:
        f["activity_regularity"] = None if preserve_missing else 1.0
        f["burstiness"] = None if preserve_missing else 1.0

    # Zeek-derived features. Imported here rather than at module scope only for the pure
    # function, so this module stays importable without the Zeek query builders.
    from weirvern.zeek_features import extract_zeek_features

    f.update(extract_zeek_features(zeek or {}, zeek_baseline,
                                   preserve_missing=preserve_missing))

    return f


def feature_vector(features: dict[str, float | None], names: list[str],
                   *, preserve_missing: bool = False) -> list[float | None]:
    """Ordered vector for sklearn — matches the order used at train time.

    `preserve_missing` is the flag's second half: with it False the vector is exactly what it
    always was (a missing key is 0.0), and with it True a missing key stays None so the
    preprocessor can impute the training-time neutral and record that it did.
    """
    if preserve_missing:
        return [features.get(name) for name in names]
    return [features.get(name, 0.0) for name in names]
