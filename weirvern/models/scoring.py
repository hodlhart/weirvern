"""Score normalization for detector outputs.

Each detector produces a raw signal; these convert it to a comparable [0, 0.99]
"anomaly score" before ensemble fusion. Kept as pure functions for testing.
"""
from __future__ import annotations

import math


def normalize_zscore(z: float, k: float = 0.4, shift: float = 2.5) -> float:
    """Sigmoid over log-scaled z-score. 0 below ~2.5 sigma, saturates at 0.99."""
    if z <= shift:
        return 0.0
    return min(0.99, 1.0 / (1.0 + math.exp(-k * math.log1p(z - shift))))


def normalize_isolation_forest(s: float) -> float:
    """sklearn IF score_samples: negative = anomalous. Scale to [0, 0.99].

    NOTE: this fixed-multiplier form is kept only as a fallback for detectors
    without calibration data. In practice `IsolationForestDetector` ships
    calibration percentiles and uses `calibrate_isolation_forest` instead —
    the multiplier form saturates on ordinary traffic (any slightly negative
    training score maps to ~0.8), which made benign hosts score as high as a
    port scanner and drowned out DBSCAN in the ensemble.
    """
    if s >= 0:
        return 0.0
    return min(0.99, abs(s) * 1.6)


def calibrate_isolation_forest(s: float, cal: dict[str, float]) -> float:
    """Percentile-calibrated IF scoring against the training score distribution.

    `cal` holds score_samples percentiles from training (p01/p05/p50 = the
    1st/5th/50th percentile). Ordinary traffic sits at/above p50 -> 0.0, so
    only genuinely rare observations score high:
      >= p50        -> 0.0            (normal half of training data)
      p50 .. p05    -> 0.0 .. 0.60
      p05 .. p01    -> 0.60 .. 0.85
      < p01         -> 0.85 .. 0.99
    """
    if not cal or "p50" not in cal:
        return normalize_isolation_forest(s)
    p50, p05, p01 = cal["p50"], cal["p05"], cal["p01"]
    if s >= p50:
        return 0.0
    if s >= p05:
        return 0.60 * ((p50 - s) / (p50 - p05 + 1e-9))
    if s >= p01:
        return 0.60 + 0.25 * ((p05 - s) / (p05 - p01 + 1e-9))
    # Below the 1st percentile: scale into 0.85..0.99 by how far past p01
    span = max(abs(p01), 1e-9)
    return min(0.99, 0.85 + 0.14 * min(1.0, abs(s - p01) / span))


def normalize_probability(p: float) -> float:
    """Classifier probability → score, zero below 0.5.

    NOTE: fallback only. `GradientBoostingDetector` ships percentile
    calibration and uses `calibrate_probability` — raw predict_proba is
    distorted by class-imbalance sample weights (a 15x positive class weight
    pushed benign windows to ~0.97 anomaly probability, producing
    false-positive "high" alerts on ordinary traffic).
    """
    if p <= 0.5:
        return 0.0
    return min(0.99, (p - 0.5) * 1.98)


def calibrate_probability(p: float, cal: dict[str, float]) -> float:
    """Percentile-calibrated classifier scoring against the training distribution.

    `cal` holds predict_proba percentiles from the training set (p50/p90/p94).
    Anomalous traffic is the TOP tail (contamination ~6% => p94+):
      <= p50        -> 0.0            (ordinary traffic)
      p50 .. p90    -> 0.0 .. 0.60
      p90 .. p94    -> 0.60 .. 0.85
      > p94         -> 0.85 .. 0.99
    """
    if not cal or "p50" not in cal:
        return normalize_probability(p)
    p50, p90, p94 = cal["p50"], cal.get("p90", cal["p50"]), cal.get("p94", cal.get("p90", cal["p50"]))
    if p <= p50:
        return 0.0
    if p <= p90:
        return 0.60 * ((p - p50) / (p90 - p50 + 1e-9))
    if p <= p94:
        return 0.60 + 0.25 * ((p - p90) / (p94 - p90 + 1e-9))
    return min(0.99, 0.85 + 0.14 * min(1.0, (p - p94) / max(1.0 - p94, 1e-9)))


def score_by_percentile(v: float, p95: float, p99: float, p999: float) -> float:
    """Piecewise-linear percentile scoring: 0 ≤ p95, 0.3–0.6 (p95→p99),
    0.6–0.85 (p99→p999), 0.85–0.99 above p999."""
    if v <= p95:
        return 0.0
    if v <= p99:
        return 0.3 + ((v - p95) / (p99 - p95 + 1e-9)) * 0.3
    if v <= p999:
        return 0.6 + ((v - p99) / (p999 - p99 + 1e-9)) * 0.25
    return min(0.99, 0.85 + ((v - p999) / (p999 + 1e-9)) * 0.1)


def calibrate_distance(d: float, cal: dict[str, float]) -> float:
    """Percentile-calibrated DBSCAN distance scoring.

    WHY THIS EXISTS: DBSCAN's score was `min(0.99, distance / 5.0)` -- a magic divisor
    unrelated to the data. Feature vectors are standardized, so distances are in
    sigma-units whose scale depends entirely on how tight the clusters were at train
    time: tight clusters (typical distances ~1.5) mapped everything to <=0.3 and the
    detector could never corroborate; loose ones saturated everything at 0.99. Every
    other detector here grades against percentiles of its own training distribution;
    this gives DBSCAN the same treatment.

    `cal` holds distances of the TRAINING samples to their nearest cluster centre
    (p50/p95/p99). Grading mirrors score_by_percentile's tiers so the detectors stay
    comparable:
      <= p50   -> 0.0              (the normal half of training data)
      p50..p95 -> 0.0 .. 0.6
      p95..p99 -> 0.6 .. 0.85
      > p99    -> 0.85 .. 0.99
    """
    if not cal or "p50" not in cal:
        # No calibration (an artifact trained before this existed): keep the old shape
        # so behaviour is unchanged until the next retrain replaces it.
        return min(0.99, d / 5.0)
    p50, p95, p99 = cal["p50"], cal.get("p95", cal["p50"]), cal.get("p99", cal.get("p95", cal["p50"]))
    if d <= p50:
        return 0.0
    if d <= p95:
        return 0.60 * ((d - p50) / (p95 - p50 + 1e-9))
    if d <= p99:
        return 0.60 + 0.25 * ((d - p95) / (p99 - p95 + 1e-9))
    return min(0.99, 0.85 + 0.14 * min(1.0, (d - p99) / max(p99, 1e-9)))
