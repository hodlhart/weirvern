"""Explainability: which raw measurement made this window look anomalous?

WHY THIS MODULE EXISTS. `weirvern.schema/001_weirvern.sql` declares five
explainability columns on `netflow_anomalies`:

    primary_deviation_feature, primary_deviation_zscore, deviation_magnitude,
    feature_contributions, baseline_comparison

and until now `worker.detection_sweep` wrote placeholders into four of them:

    v["model_agreement"], _explain_primary(f, v), 0.0, 0.0, "{}", ""

`_explain_primary` returned the name of a DETECTOR (its docstring claimed a
feature), and `primary_deviation_zscore`, `feature_contributions` and
`baseline_comparison` were hardcoded `0.0`, `{}` and `""`. So the schema promised
explainability that nothing computed, and an operator opening an anomaly saw a
row of zeros where the reason should be.

This matters beyond tidiness. "Which feature drove this?" is the question you ask
BEFORE you can hunt a threat: without it there is no way to move from "the
ensemble scored this 0.91" to "this host sent 3.6 GB to one destination when its
normal maximum is 65 MB", and no way to map behaviour onto an ATT&CK technique.

DESIGN CHOICES, and why they are these:

1. DEVIATION IS MEASURED AGAINST THE HOST'S OWN BASELINE, not against global
   statistics. A backup server moving 50 GB hourly is normal for that host and
   would top any global ranking; per-host comparison is what makes a deviation
   meaningful. The baseline is the AdaptiveBaselineDetector's, which already
   computes per-host mean, stddev and p95/p99/p999 percentiles.

2. Z-SCORES ARE COMPUTED HERE RATHER THAN READ FROM THE MODELS. The detectors
   reduce to a single score and discard the per-feature detail: normalize_zscore
   computes a z-score internally and returns a squashed value; the Isolation
   Forest returns a path-length score with no feature attribution. So the
   z-scores are computed from the baseline statistics instead of being recovered
   from a score that no longer contains them.

3. CONTRIBUTIONS ARE REPORTED AS DIRECTIONS, not just magnitudes. "bytes are 55x
   the host's normal" and "bytes are 55x BELOW normal" are different findings
   (exfiltration vs a service that went quiet), and a bare absolute magnitude
   cannot distinguish them.

4. IT DEGRADES HONESTLY. With no baseline for a host, there is nothing to compare
   against, and the result says so rather than inventing a number. A missing
   explanation must not look like a zero deviation.
"""
from __future__ import annotations

from typing import Any

# The measurements worth explaining, in the order they are reported. These are
# RAW window measurements rather than derived model features: a human reading an
# alert needs "bytes", not "log1p(bytes)".
EXPLAINED_MEASUREMENTS = [
    "total_bytes",
    "total_packets",
    "unique_dst_ips",
    "flow_count",
    "avg_bytes",
    "avg_packets",
]

# Mapping from a raw measurement to the baseline statistic naming it. The baseline
# stores avg/stddev for bytes, packets and destination count; avg_bytes and
# avg_packets are per-flow means, which a per-host-window baseline does not track,
# so they are deliberately absent (see _BASELINE_KEYS).
_BASELINE_KEYS = {
    "total_bytes": ("avg_bytes", "stddev_bytes"),
    "total_packets": ("avg_packets", "stddev_packets"),
    "unique_dst_ips": ("avg_unique_dsts", "stddev_unique_dsts"),
}

# Percentile keys per measurement, used for the human-readable comparison.
_PERCENTILE_KEYS = {
    "total_bytes": ("p95_bytes", "p99_bytes", "p999_bytes"),
    "total_packets": ("p95_packets", "p99_packets", "p999_packets"),
}

# Below this, a z-score is noise. Reporting "0.3 sigma" as a contribution buries
# the real signal in a list of non-findings.
MIN_ABS_Z = 1.0

# A stddev of zero means every sample was identical; dividing by it is undefined.
# Substituting 1.0 would silently manufacture a z-score equal to the raw delta,
# so instead the deviation is capped at this and flagged as such.
_ZERO_STDDEV_FLOOR = 1.0


def _as_float(v: Any) -> float | None:
    """Coerce to float, returning None for absent/unparseable values.

    None means "unknown", which is different from 0.0 ("measured as zero") and must
    stay distinguishable all the way to the alert text.
    """
    if v is None or v == "":
        return None
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _humanise(n: float) -> str:
    """Compact magnitude for alert text: 3.6 GB rather than 3865470566."""
    for unit, div in (("TB", 1e12), ("GB", 1e9), ("MB", 1e6), ("KB", 1e3)):
        if abs(n) >= div:
            return f"{n / div:.1f} {unit}"
    return f"{n:.0f}"


def explain(features_or_flow: dict[str, Any],
            baseline: dict[str, float] | None) -> dict[str, Any]:
    """Build the five explainability fields for one anomaly row.

    Args:
        features_or_flow: the aggregated window row (raw measurements).
        baseline: this host's baseline stats, or None when the host is unknown.

    Returns a dict with exactly the keys the schema declares:
        primary_deviation_feature, primary_deviation_zscore, deviation_magnitude,
        feature_contributions, baseline_comparison
    """
    empty = {
        "primary_deviation_feature": "",
        "primary_deviation_zscore": 0.0,
        "deviation_magnitude": 0.0,
        "feature_contributions": "{}",
        "baseline_comparison": "",
    }

    if not baseline:
        # Honest absence. A host with no baseline (too few observations) has
        # nothing to deviate FROM, and a fabricated number here would be read as
        # a measurement. The worker is expected to say so rather than show 0.0.
        empty["baseline_comparison"] = "no baseline for this host"
        return empty

    contributions: dict[str, dict[str, Any]] = {}
    for name in EXPLAINED_MEASUREMENTS:
        keys = _BASELINE_KEYS.get(name)
        if not keys:
            continue
        actual = _as_float(features_or_flow.get(name))
        mean = _as_float(baseline.get(keys[0]))
        stddev = _as_float(baseline.get(keys[1]))
        if actual is None or mean is None or stddev is None:
            continue

        # A zero stddev means the host has been perfectly constant. Report the
        # deviation as unknown-and-flagged rather than inventing one.
        degenerate = stddev <= 0.0
        sd = stddev if stddev > _ZERO_STDDEV_FLOOR else _ZERO_STDDEV_FLOOR
        z = (actual - mean) / sd

        pct_keys = _PERCENTILE_KEYS.get(name, ())
        percentiles = {k: baseline.get(k) for k in pct_keys if baseline.get(k) is not None}
        # Which percentile band the value landed in, for the human sentence.
        band = ""
        p95, p99, p999 = (percentiles.get(k) for k in pct_keys) if pct_keys else (None, None, None)
        if p999 is not None and actual >= float(p999):
            band = "above p99.9"
        elif p99 is not None and actual >= float(p99):
            band = "above p99"
        elif p95 is not None and actual >= float(p95):
            band = "above p95"

        contributions[name] = {
            "z": round(z, 2),
            "actual": actual,
            "baseline_mean": round(mean, 2),
            "direction": "above" if z > 0 else ("below" if z < 0 else "at"),
            "ratio": round(actual / mean, 2) if mean else None,
            # Distinguishes "exactly as expected" from "not computable".
            "zero_variance": degenerate,
            "band": band,
        }

    if not contributions:
        empty["baseline_comparison"] = "baseline present but no comparable measurements"
        return empty

    # The primary deviation is the largest |z|. Ties break on the order of
    # EXPLAINED_MEASUREMENTS so the same window always names the same feature
    # (a flapping explanation is worse than a fixed arbitrary one).
    primary = max(
        contributions.items(),
        key=lambda kv: (abs(kv[1]["z"]), -EXPLAINED_MEASUREMENTS.index(kv[0])),
    )
    p_name, p = primary

    # Magnitude: |z| capped for display sanity, plus whether it is a real
    # deviation at all. A window can pass the ensemble gate on a structural
    # signature while every measurement sits near its baseline (a pure SYN scan
    # moves no bytes), and that case must not claim a large feature deviation.
    magnitude = round(abs(p["z"]), 2)
    meaningful = magnitude >= MIN_ABS_Z

    comparison = _comparison_sentence(p_name, p)

    return {
        "primary_deviation_feature": p_name if meaningful else "",
        "primary_deviation_zscore": round(p["z"], 2),
        "deviation_magnitude": magnitude,
        "feature_contributions": _json(contributions),
        "baseline_comparison": comparison,
    }


def _comparison_sentence(name: str, d: dict[str, Any]) -> str:
    """One human sentence naming the measurement, its direction and the ratio."""
    actual, mean = d["actual"], d["baseline_mean"]
    readable = name.replace("_", " ")
    # Bytes-scale values read better as magnitudes than as raw integers.
    if name in ("total_bytes", "avg_bytes"):
        shown = f"{_humanise(actual)} vs {_humanise(mean)} normal"
    else:
        shown = f"{actual:.0f} vs {mean:.0f} normal"
    if d["zero_variance"]:
        return (f"{readable} {shown} (z={d['z']}, host baseline has zero variance, "
                f"so the deviation is approximate)")
    band = f" [{d['band']}]" if d["band"] else ""
    ratio = f", {d['ratio']}x" if d["ratio"] not in (None, 0) else ""
    return f"{readable} {d['direction']} normal: {shown}{ratio}{band}"


def _json(obj: Any) -> str:
    """Compact JSON. sort_keys so two identical rows produce identical strings,
    which keeps the column diffable."""
    import json
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def summarise(explanation: dict[str, Any]) -> str:
    """One-line summary for logs and alert bodies."""
    feature = explanation.get("primary_deviation_feature") or ""
    if not feature:
        detail = explanation.get("baseline_comparison") or "no dominant deviation"
        return f"no single dominant feature ({detail})"
    z = explanation.get("primary_deviation_zscore", 0.0)
    return f"{feature} at z={z}"


__all__ = ["EXPLAINED_MEASUREMENTS", "explain", "summarise"]
