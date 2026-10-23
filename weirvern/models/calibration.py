"""Calibration for the existing detector scores.

WHY THIS MODULE EXISTS. A detector score is a ranking, not a false-alarm rate. The console had a
global BASE_THRESHOLD and adaptive multipliers, while the live score distributions saturated
(DBSCAN at 0.99 on half of its stored detections). This module computes a conformal threshold
against a reference distribution, so an operator can ask for a target alerts/day and then MEASURE
whether the system met it.

HONEST LIMIT: the reference here is the stored detector scores in `netflow_anomalies` (and the
near-miss rows), NOT every host-window the models scored. It is a calibration of the alert tail,
not a calibration of all traffic. `reference_source` carries that sentence into the table; a
later candidate-score store can widen it.

No new detector. No alert path change. The worker's calibration pass is shadow-only.
"""
from __future__ import annotations

import math
from collections.abc import Iterable
from dataclasses import dataclass

import numpy as np
from clickhouse_connect.driver.client import Client

from weirvern import __version__
from weirvern.clock import utcnow
from weirvern.config import Settings

# The models whose scores the console already stores. IF and GB are listed separately here
# because their distributions differ; corroboration independence is an ENSEMBLE question, not a
# calibration one.
MODEL_COLUMNS = (
    ("Isolation Forest", "isolation_forest_score"),
    ("Gradient Boosting", "gradient_boosting_score"),
    ("DBSCAN", "dbscan_score"),
    ("Adaptive Baseline", "baseline_score"),
)


@dataclass(frozen=True)
class Calibration:
    threshold: float
    target_far: float
    sample_count: int
    validation_count: int
    observed_far: float
    p50: float
    p95: float
    p99: float
    statistic: str = "conformal"


def _clean(scores: Iterable[float]) -> np.ndarray:
    return np.asarray([float(s) for s in scores if s is not None and math.isfinite(float(s))],
                      dtype=float)


def conformal_threshold(reference: Iterable[float], target_far: float) -> float:
    """The split-conformal threshold for a target false-alarm rate.

    For n reference scores and target α, the threshold is the ⌈(n+1)(1-α)⌉-th smallest score.
    Finite-sample validity assumes exchangeability; this project uses it as a measured budget,
    not a mystical guarantee.
    """
    ref = np.sort(_clean(reference))
    if ref.size == 0:
        return float("nan")
    alpha = min(max(float(target_far), 1e-6), 0.5)
    rank = int(math.ceil((ref.size + 1) * (1.0 - alpha)))
    return float(ref[min(max(rank - 1, 0), ref.size - 1)])


def conformal_pvalue(score: float, reference: Iterable[float]) -> float:
    """(1 + #{reference >= score}) / (n + 1) -- small means unusual."""
    ref = _clean(reference)
    if ref.size == 0:
        return float("nan")
    return float((1 + int((ref >= float(score)).sum())) / (ref.size + 1))


def fit(reference: Iterable[float], target_far: float) -> Calibration | None:
    """Fit on the even half, measure on the odd half. Returns None when there is too little data."""
    ref = _clean(reference)
    if ref.size < 20:
        return None
    calibration, validation = ref[::2], ref[1::2]
    threshold = conformal_threshold(calibration, target_far)
    if not math.isfinite(threshold):
        return None
    observed = float((validation >= threshold).mean()) if validation.size else float("nan")
    return Calibration(
        threshold=threshold,
        target_far=float(target_far),
        sample_count=int(ref.size),
        validation_count=int(validation.size),
        observed_far=observed,
        p50=float(np.percentile(ref, 50)),
        p95=float(np.percentile(ref, 95)),
        p99=float(np.percentile(ref, 99)),
    )


def _score_rows(client: Client, column: str, days: int = 30) -> list[float]:
    # The score name is one of the literal MODEL_COLUMNS values, never user input.
    if column not in {c for _, c in MODEL_COLUMNS}:
        raise ValueError(f"unknown score column {column!r}")
    res = client.query(
        "SELECT " + column + " FROM weirvern.netflow_anomalies "
        "WHERE detected_at >= now() - INTERVAL %(d)s DAY AND " + column + " > 0",
        parameters={"d": int(days)},
    )
    return [float(r[0]) for r in res.result_rows if r and r[0] is not None]


def run(client: Client, settings: Settings, *, days: int = 30) -> list[dict]:
    """Write one shadow calibration row per model. Never raises past the caller's guard."""
    target = float(getattr(settings, "ml_target_far", 0.01) or 0.01)
    rows: list[dict] = []
    for model_name, column in MODEL_COLUMNS:
        scores = _score_rows(client, column, days=days)
        cal = fit(scores, target)
        if cal is None:
            continue
        rows.append({
            "model_name": model_name,
            "scope": "global",
            "subject": "all stored detections",
            "statistic": cal.statistic,
            "target_far": cal.target_far,
            "threshold": cal.threshold,
            "p50": cal.p50,
            "p95": cal.p95,
            "p99": cal.p99,
            "sample_count": cal.sample_count,
            "validation_count": cal.validation_count,
            "observed_far": cal.observed_far,
            "reference_source": "stored anomaly scores (tail only), not all scored windows",
            "model_version": __version__,
        })
    if not rows:
        return []
    columns = ["model_name", "scope", "subject", "statistic", "target_far", "threshold",
               "p50", "p95", "p99", "sample_count", "validation_count", "observed_far",
               "reference_source", "model_version"]
    client.insert(
        "weirvern.ml_calibration",
        [[r[c] for c in columns] for r in rows],
        column_names=columns,
    )
    # The same rows append to history; the Replacing table gives the readable current state.
    client.insert(
        "weirvern.ml_calibration_history",
        [[utcnow()] + [r[c] for c in columns] for r in rows],
        column_names=["computed_at"] + columns,
    )
    return rows


__all__ = ["Calibration", "MODEL_COLUMNS", "conformal_pvalue", "conformal_threshold", "fit", "run"]
