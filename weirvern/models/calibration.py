"""Calibration for the existing detector scores.

WHY THIS MODULE EXISTS. A detector score is a ranking, not a false-alarm rate. The console had a
global BASE_THRESHOLD and adaptive multipliers, while the live score distributions saturated
(DBSCAN at 0.99 on half of its stored detections). This module computes a conformal threshold
against a reference distribution, so an operator can ask for a target alerts/day and then MEASURE
whether the system met it.

HONEST LIMIT: `run` prefers `ml_window_scores` — every host-window the ensemble scored **before**
the alert threshold. If that population is not yet available (a fresh deployment), it names the
fallback explicitly and calibrates on the stored alert tail. `reference_source` carries which
denominator was used into the table; it is never silently presented as all traffic.

No new detector. No alert path change. The worker's calibration pass is shadow-only.
"""
from __future__ import annotations

import logging
import math
from collections.abc import Iterable
from dataclasses import dataclass

import numpy as np
from clickhouse_connect.driver.client import Client

from weirvern import __version__
from weirvern.clock import utcnow
from weirvern.config import FUSED_MODEL, Settings

logger = logging.getLogger(__name__)

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
    # THE CEILING IS THE POINT. A target FAR is only expressible down to 1/(n+1) of the reference:
    # with 6,489 scores and a 1% target the threshold lands on the top few samples, and when it
    # lands AT the maximum nothing in the population can ever exceed it. Recording the ceiling lets
    # a caller tell "no alerts because the network is quiet" from "no alerts because the bar is
    # above every score the detector produces", which is the same defect shape this project keeps
    # finding: a failure rendered as a benign state.
    ceiling: float = float("nan")

    @property
    def saturated(self) -> bool:
        """True when the fitted threshold is at or above every reference score.

        The target false-alarm rate is then below what this sample can express, and a decision
        that uses this threshold will fire on nothing until the population grows or the target is
        relaxed. It is not an error: it is a measurement that has run out of resolution.
        """
        return bool(math.isfinite(self.ceiling) and self.threshold >= self.ceiling)


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
        ceiling=float(ref.max()),
    )


def eligibility_from_rows(rows, target_far: float, multiple: float) -> dict[str, bool]:
    """Map the latest calibration rows to an eligibility decision per model.

    A model is eligible when its measured false-alarm rate is within `target_far * multiple`.
    Missing/non-finite calibration is NOT a reason to quarantine every detector: it leaves the
    model eligible, because the gate is an operator-enabled safety rail, not a second failure mode.
    """
    out: dict[str, bool] = {}
    for model, observed, target in rows:
        if str(model) == FUSED_MODEL:
            # The fused score is the decision's own number, not a detector: it can never be
            # "barred from the fused score" without making the gate circular.
            continue
        try:
            obs = float(observed)
            tgt = float(target if target is not None else target_far)
        except (TypeError, ValueError):
            continue
        if not math.isfinite(obs) or not math.isfinite(tgt) or tgt <= 0:
            continue
        out[str(model)] = bool(obs <= tgt * float(multiple))
    return out


def eligibility(client: Client, settings: Settings) -> dict[str, bool]:
    """Read the latest calibration rows and return model name -> eligible.

    A calibration older than the model's newest artifact is NOT evidence about the current
    model. Such a model is returned ineligible until calibration is rerun against scores from
    the retrained artifact; this is the holdout lock that keeps a retrain from silently
    re-enabling a model on its old calibration.
    """
    res = client.query(
        "SELECT model_name, observed_far, target_far, computed_at FROM weirvern.ml_calibration FINAL "
        "WHERE computed_at = (SELECT max(computed_at) FROM weirvern.ml_calibration)"
    )
    rows = res.result_rows
    out = eligibility_from_rows(
        [(row[0], row[1], row[2]) for row in rows],
        float(getattr(settings, "ml_target_far", 0.01) or 0.01),
        float(getattr(settings, "ml_eligibility_multiple", 3.0) or 3.0),
    )
    try:
        trained = client.query(
            "SELECT model_type, max(trained_at) FROM weirvern.ml_models GROUP BY model_type"
        )
        latest_train = {str(name): when for name, when in trained.result_rows}
        for row in rows:
            name, when = str(row[0]), row[3]
            model_when = latest_train.get(name)
            if model_when is not None and when is not None and model_when > when:
                out[name] = False
    except Exception as exc:  # noqa: BLE001
        logger.warning("eligibility: could not read model artifact dates (stale gate skipped): %s",
                       exc)

    # PR-1: a calibration score is not permission to serve. The model must also have a current
    # card whose status is `production`. This is deliberately fail-closed: a missing table, a
    # retired card and a name nobody registered all produce False. A deployment can see why in
    # the Models view and in this log line rather than discovering it as silent silence.
    try:
        from weirvern.models import cards as _cards  # noqa: PLC0415
        registered = _cards.registration(client)
    except Exception as exc:  # noqa: BLE001
        logger.warning("eligibility: could not read model cards; no model is registered: %s", exc)
        registered = {}
    barred = sorted(name for name in out if not registered.get(name, False))
    if barred:
        logger.warning("eligibility: %s barred by model card: %s", len(barred), ", ".join(barred))
    for name in list(out):
        if not registered.get(name, False):
            out[name] = False
    return out


def record_population(client: Client, population: Iterable[dict], *,
                      model_version: str) -> int:
    """Persist RAW per-model scores for every scored host-window.

    `population` is the caller-owned sink filled by `ensemble.detect_flows`. A row is stored
    before thresholds, agreement, severity, or episodes; this is the denominator calibration
    needs. The write is best-effort by contract: the caller catches and logs, because a
    measurement failure must not stop detection.
    """
    rows: list[list] = []
    now = utcnow()
    for sample in population:
        start = sample.get("window_start")
        src = str(sample.get("src_addr") or "")
        if start is None or not src:
            continue
        for model_name, score in (sample.get("scores") or {}).items():
            try:
                value = float(score)
            except (TypeError, ValueError):
                continue
            if not math.isfinite(value):
                continue
            rows.append([start, src, str(model_name), value, str(model_version), now])
    if not rows:
        return 0
    client.insert(
        "weirvern.ml_window_scores", rows,
        column_names=["window_start", "src_addr", "model_name", "score",
                      "model_version", "computed_at"],
    )
    return len(rows)


def _population_scores(client: Client, days: int,
                       model_version: str | None = None) -> dict[str, list[float]]:
    """All scored host-window scores per model, deduped by the Replacing table.

    SCOPED TO `model_version` WHEN GIVEN, and that scoping is a correctness requirement rather than
    a tidiness one. A reference that spans a model or aggregation change calibrates today's detector
    against an older engine's distribution, so the threshold it produces is a mixture of two regimes
    and belongs to neither. Measured on the live engine: the population carried rows from eight
    distinct versions inside one rolling week, and restricting the reference to post-change scores
    moved the 1% threshold from 0.8165 to 0.7327 while the highest score the current engine had
    produced was 0.853, which is the difference between an engine that can alert and one that cannot.

    A deployment that has not applied 038 yet has no population; return an empty mapping so
    `run` takes its named fallback instead of failing the whole shadow pass.
    """
    sql = ("SELECT model_name, score FROM weirvern.ml_window_scores FINAL "
           "WHERE computed_at >= now() - INTERVAL %(d)s DAY")
    params: dict[str, object] = {"d": int(days)}
    if model_version:
        sql += " AND model_version = %(v)s"
        params["v"] = str(model_version)
    try:
        res = client.query(sql, parameters=params)
    except Exception as exc:  # noqa: BLE001
        logger.warning("calibration population unavailable (%s); using named fallback", exc)
        return {}
    out: dict[str, list[float]] = {}
    for model_name, score in res.result_rows:
        try:
            value = float(score)
        except (TypeError, ValueError):
            continue
        if math.isfinite(value):
            out.setdefault(str(model_name), []).append(value)
    return out


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


def run(client: Client, settings: Settings, *, days: int | None = None) -> list[dict]:
    """Write one shadow calibration row per model. Never raises past the caller's guard.

    The primary reference is `ml_window_scores`: every host-window the ensemble scored, before
    the alert threshold. The anomaly tail is a labelled fallback for a deployment that has not
    produced population rows yet; `reference_source` states which one was used.
    """
    target = float(getattr(settings, "ml_target_far", 0.01) or 0.01)
    window_days = int(days if days is not None else
                      getattr(settings, "ml_calibration_days", 7) or 7)
    population = _population_scores(client, window_days, __version__)
    rows: list[dict] = []
    for model_name, column in MODEL_COLUMNS:
        scores = population.get(model_name) or []
        source = (f"all scored host-windows (ml_window_scores), model {__version__}, "
                  f"last {window_days} days")
        subject = "all scored host-windows"
        if len(scores) < 20:
            scores = _score_rows(client, column, days=30)
            source = "fallback: stored anomaly scores (tail only); population rows unavailable"
            subject = "fallback stored detections"
        cal = fit(scores, target)
        if cal is None:
            continue
        if cal.saturated:
            # Say so where an operator reads it, rather than storing a threshold that silently
            # cannot be crossed and leaving the cause to be rediscovered.
            source += (f"; SATURATED at the reference ceiling ({cal.ceiling:.4f}): the target FAR "
                       f"is below what {cal.sample_count} samples can express")
        rows.append({
            "model_name": model_name,
            "scope": "global",
            "subject": subject,
            "statistic": cal.statistic,
            "target_far": cal.target_far,
            "threshold": cal.threshold,
            "p50": cal.p50,
            "p95": cal.p95,
            "p99": cal.p99,
            "sample_count": cal.sample_count,
            "validation_count": cal.validation_count,
            "observed_far": cal.observed_far,
            "reference_source": source,
            "model_version": __version__,
        })
    fused = population.get(FUSED_MODEL) or []
    if len(fused) >= 20:
        cal = fit(fused, target)
        if cal is not None:
            source = (f"the fused score itself (ml_window_scores), model {__version__}, "
                      f"last {window_days} days")
            if cal.saturated:
                source += (f"; SATURATED at the reference ceiling ({cal.ceiling:.4f}): the target "
                           f"FAR is below what {cal.sample_count} samples can express")
            rows.append({
                "model_name": FUSED_MODEL,
                "scope": "global",
                "subject": "the fused score the decision compares",
                "statistic": cal.statistic,
                "target_far": cal.target_far,
                "threshold": cal.threshold,
                "p50": cal.p50,
                "p95": cal.p95,
                "p99": cal.p99,
                "sample_count": cal.sample_count,
                "validation_count": cal.validation_count,
                "observed_far": cal.observed_far,
                "reference_source": source,
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


__all__ = ["Calibration", "MODEL_COLUMNS", "conformal_pvalue", "conformal_threshold",
           "eligibility", "eligibility_from_rows", "fit", "record_population", "run"]


def calibrated_bar(client: Client, settings: Settings) -> float | None:
    """The calibrated threshold for the fused score, or None when there is not a usable one.

    RETURNS NONE RATHER THAN A GUESS. A missing, stale, saturated or unreadable calibration means the
    caller falls back to its own threshold; inventing a number here would put an unmetered bar in
    front of every alert while looking exactly like a calibrated one.
    """
    max_age_h = float(getattr(settings, "ml_calibration_max_age_hours", 24) or 24)
    try:
        res = client.query(
            "SELECT threshold, reference_source FROM weirvern.ml_calibration FINAL "
            "WHERE model_name = %(m)s AND computed_at >= now() - INTERVAL %(h)s HOUR "
            "ORDER BY computed_at DESC LIMIT 1",
            parameters={"m": FUSED_MODEL, "h": int(max_age_h)},
        )
        rows = res.result_rows
    except Exception as exc:  # noqa: BLE001
        logger.warning("calibrated bar unavailable (%s); the decision keeps its own threshold", exc)
        return None
    if not rows:
        return None
    try:
        value = float(rows[0][0])
    except (TypeError, ValueError, IndexError):
        return None
    source = str(rows[0][1] or "")
    if "SATURATED" in source.upper():
        # A threshold at the reference ceiling cannot be crossed, so using it would silence the
        # engine and report a met budget. Fall back and let the saturation be visible in the row.
        logger.warning("calibrated bar ignored: the calibration is saturated (%s)", source)
        return None
    if not math.isfinite(value) or value <= 0:
        return None
    return value
