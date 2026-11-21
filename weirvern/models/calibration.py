"""Calibration for the existing detector scores.

WHY THIS MODULE EXISTS. A detector score is a ranking, not a false-alarm rate. The console had a
global BASE_THRESHOLD and adaptive multipliers, while the live score distributions saturated
(one detector sat at 0.99 on half of its stored detections). This module computes a conformal
threshold
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
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any

import numpy as np
from clickhouse_connect.driver.client import Client

from weirvern import __version__
from weirvern.clock import utcnow
from weirvern.config import FUSED_MODEL, Settings
from weirvern.features import CROSS_SECTIONAL_FEATURES, IF_FEATURES, TELEMETRY_FEATURES
from weirvern.models.eval_report import wilson

logger = logging.getLogger(__name__)

# The models whose scores the console already stores. IF and GB are listed separately here
# because their distributions differ; corroboration independence is an ENSEMBLE question, not a
# calibration one.
#
# THE REMOVED DENSITY DETECTOR IS NOT IN THIS LIST. Its stored score was degenerate -- 97.89% of
# 27,454 rows at 0.99 or above, p50 = p99 = max = 0.99 -- so a calibration row for it measured a
# step function, not a detector. It has no code left to write one.
MODEL_COLUMNS = (
    ("Isolation Forest", "isolation_forest_score"),
    ("Gradient Boosting", "gradient_boosting_score"),
    ("Adaptive Baseline", "baseline_score"),
)

# WHAT `run` CALIBRATES, in this order. This is the model list the calibration pass walks; it is
# not the same as MODEL_COLUMNS, which is the LEGACY fallback read of the alert tail's columns.
# A cross-sectional detector (KNN distance, LOF) has no netflow_anomalies column yet -- its
# population comes from ml_window_scores, where `record_population` stores every score under its
# own name -- so it belongs here and not in MODEL_COLUMNS.
POPULATION_MODELS = (
    "Isolation Forest",
    "Gradient Boosting",
    "KNN distance",
    "LOF",
    "Adaptive Baseline",
)

# THE EXPECTED WIDTH OF EACH MODEL'S VECTOR. One narrow job: recovering the counts behind a
# `coverage` ratio that was written before schema 058 stored them. It is not a second feature
# definition -- each detector returns exactly these lists from `expected_feature_columns()`, and
# a test pins that equality. A detector with no vector contract (Adaptive Baseline) and the fused
# score are measured over the telemetry union, exactly as the ensemble measures them.
MODEL_EXPECTED_FEATURES = {
    "Isolation Forest": len(IF_FEATURES),
    "Gradient Boosting": len(IF_FEATURES),
    "KNN distance": len(CROSS_SECTIONAL_FEATURES),
    "LOF": len(CROSS_SECTIONAL_FEATURES),
    "Adaptive Baseline": len(TELEMETRY_FEATURES),
    FUSED_MODEL: len(TELEMETRY_FEATURES),
}


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


def _finite(value: Any) -> float | None:
    """A finite float, or None. Absence is never zero."""
    try:
        out = float(value)
    except (TypeError, ValueError):
        return None
    return out if math.isfinite(out) else None


def _counts_pair(value: Any) -> tuple[int, int] | None:
    """(observed, expected) from a caller- or table-supplied pair, or None when unusable.

    A pair is only trusted when it is internally consistent -- 0 <= observed <= expected and a
    positive denominator -- because a malformed one would produce a coverage ratio that looks
    measured and divides by a vector that never existed.
    """
    if not isinstance(value, (tuple, list)) or len(value) != 2:
        return None
    try:
        observed, expected = int(value[0]), int(value[1])
    except (TypeError, ValueError):
        return None
    if expected <= 0 or observed < 0 or observed > expected:
        return None
    return observed, expected


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


# ── A THRESHOLD PER POPULATION THE DETECTOR ACTUALLY SEES ─────────────────────────────────────
#
# WHY THIS LAYER EXISTS. A host-window with 11 of its 19 columns absent is not a different KIND of
# observation, but every cross-sectional score built on that shorter vector is systematically
# SMALLER for it. Measured on the deployment before this existed: with one pooled threshold,
# partial-coverage windows alerted at 0.00% while fully observed windows alerted at 2.3-2.5%, so
# 35% of the population was silently unalertable while the headline false-alarm rate looked
# healthy. The coverage stratum has to be part of the calibration key.
#
# THE KEY IS COVERAGE, NOT THE MODEL. Nothing here knows which detector produced a score: the
# input is (score, stratum) pairs and the output is one threshold per stratum. A model may
# register how its stored rows map to a key (see ScoreContract); the default is the
# observed/expected column count `record_population` already writes beside every score.
#
# HOW MANY WINDOWS A STRATUM NEEDS. Split-conformal at a 0.01 target needs a calibration half of
# at least 199 scores for the ⌈(n+1)·0.99⌉ rank to sit BELOW the maximum -- with fewer, the
# threshold IS the maximum and nothing can cross it (the saturation `Calibration.saturated`
# names). `fit` splits the reference even/odd, so a stratum needs ~400 reference windows to
# express a 1% budget at all. Below that the stratum explicitly falls back to the pooled
# threshold instead of storing a bar that cannot fire.
MIN_STRATUM_SAMPLES = 400


def coverage_stratum(coverage: Any = None, observed: Any = None,
                     expected: Any = None) -> str:
    """The calibration stratum for one window: its measured-column count, or a ratio bucket.

    Counts are authoritative: `19/19` says exactly how much of the vector was measured, and two
    windows with the same count saw the same dimensions (the deployment's absent sources are
    all-or-nothing families, so 8/19 and 16/19 are the real levels). A row that carries only the
    ratio -- written before schema 058 stored the counts -- is bucketed to two decimals, which
    keeps 0.4211 and 0.42 in one stratum.

    An unknown coverage (None) returns "" -- the pooled stratum. Absence of a measurement must
    not be bucketed as if it were one.
    """
    counts = _counts_pair((observed, expected))
    if counts is not None:
        return f"{counts[0]}/{counts[1]}"
    cov = _finite(coverage)
    if cov is None or not 0.0 <= cov <= 1.0:
        return ""
    return f"{cov:.2f}"


def _row_score(row: Sequence[Any]) -> float | None:
    """`score` from a (score, coverage, observed, expected) population row."""
    return row[0] if len(row) > 0 else None


def _row_stratum(row: Sequence[Any]) -> str:
    """The coverage stratum of a population row, by the same rule every consumer uses."""
    return coverage_stratum(row[1] if len(row) > 1 else None,
                            row[2] if len(row) > 2 else None,
                            row[3] if len(row) > 3 else None)


@dataclass(frozen=True)
class ScoreContract:
    """How ONE model's stored row becomes (score, stratum), registered by the model itself.

    This is the seam that keeps the calibration layer model-agnostic: `run` asks the registry
    how to read a row and never branches on a detector name. A model that stores its score
    somewhere other than column 0 -- or derives its stratum from something other than coverage --
    registers its own contract; everything else gets COVERAGE_CONTRACT.
    """

    score: Callable[[Sequence[Any]], float | None]
    stratum: Callable[[Sequence[Any]], str]


COVERAGE_CONTRACT = ScoreContract(score=_row_score, stratum=_row_stratum)
_MODEL_CONTRACTS: dict[str, ScoreContract] = {}


def register_model_contract(model_name: str, contract: ScoreContract) -> None:
    """Register a model's row reader. Idempotent; the newest registration wins."""
    _MODEL_CONTRACTS[str(model_name)] = contract


def contract_for(model_name: str) -> ScoreContract:
    """The contract a model registered, or the generic coverage contract."""
    return _MODEL_CONTRACTS.get(str(model_name), COVERAGE_CONTRACT)


@dataclass(frozen=True)
class StratifiedCalibration:
    """One pooled calibration plus a threshold for every coverage stratum observed.

    `strata` contains an entry for EVERY stratum the reference saw. A stratum whose own
    reference was too small to resolve the target maps to the POOLED Calibration and is listed
    in `fallbacks` with its window count -- so a reader can tell "this stratum was measured and
    met its own budget" from "this stratum borrowed the pooled bar because it could not
    resolve one". Both are usable; only the first is a measurement of that stratum.
    """

    pooled: Calibration
    strata: dict[str, Calibration] = field(default_factory=dict)
    fallbacks: dict[str, int] = field(default_factory=dict)
    min_samples: int = MIN_STRATUM_SAMPLES

    def for_stratum(self, stratum: str | None) -> Calibration:
        """The calibration that governs this stratum, falling back to the pooled one."""
        return self.strata.get(str(stratum or ""), self.pooled)

    def threshold_for(self, stratum: str | None) -> float:
        return float(self.for_stratum(stratum).threshold)

    def threshold(self, stratum: str | None = None) -> float:
        """Alias with the argument first-class: `strat.threshold("8/19")`."""
        return self.threshold_for(stratum)


def fit_stratified(rows: Iterable[tuple[float, str]], target_far: float, *,
                   min_samples: int = MIN_STRATUM_SAMPLES) -> StratifiedCalibration | None:
    """Fit the pooled threshold and one threshold per coverage stratum.

    `rows` is (score, stratum) and nothing else -- no model name, no feature list. The pooled
    threshold is fitted exactly as `fit` always did, so an unstratified caller gets the same
    number it always got; every stratum with enough reference windows is then fitted on its own
    even/odd split.

    A stratum is a FALLBACK (not an error) when:
      * it has fewer than `min_samples` reference windows, or
      * its own conformal threshold lands at its reference ceiling (a saturated bar cannot fire,
        and storing one would reproduce the silent-detector defect this layer exists to end).
    """
    pairs: list[tuple[float, str]] = []
    for score, stratum in rows:
        try:
            value = float(score)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            continue
        if math.isfinite(value):
            pairs.append((value, str(stratum or "")))
    if len(pairs) < 20:
        return None
    pooled = fit([p[0] for p in pairs], target_far)
    if pooled is None:
        return None

    groups: dict[str, list[float]] = {}
    for value, key in pairs:
        if key:
            groups.setdefault(key, []).append(value)

    strata: dict[str, Calibration] = {}
    fallbacks: dict[str, int] = {}
    for key in sorted(groups):
        group = groups[key]
        if len(group) < int(min_samples):
            strata[key] = pooled
            fallbacks[key] = len(group)
            continue
        cal = fit(group, target_far)
        if cal is None or cal.saturated:
            strata[key] = pooled
            fallbacks[key] = len(group)
            continue
        strata[key] = cal
    return StratifiedCalibration(pooled=pooled, strata=strata, fallbacks=fallbacks,
                                 min_samples=int(min_samples))


def eligibility(client: Client, settings: Settings) -> dict[str, bool]:
    """Read the evidence and return model name -> may contribute to the fused score.

    THE CARD VETO IS GONE. `ml_model_cards` is a hand-curated registry: it is written only when
    somebody edits a card, so it goes stale the moment the engine retrains, and a model that has
    no card at all (the two cross-sectional detectors when they shipped) was barred by ABSENCE.
    A card states intent; it cannot measure a false-alarm rate. Eligibility is derived from the
    engine's own measurements -- freshness, recorded coverage, realised FAR -- and then from the
    measured alert budget, in `weirvern.models.eligibility`, which is the one implementation the
    engine and the Detectors table both read.

    RETURNED MAPPING: every detector the engine knows, with True only for the ones that may set the
    fused score. The caller (`ensemble.contributing_scores`) excludes, rather than zeroes, the rest.
    """
    from weirvern.models import eligibility as _eligibility  # noqa: PLC0415

    report = _eligibility.evaluate(client, settings, persist=True)
    eligible = report.eligible
    out = sorted(name for name, ok in eligible.items() if not ok)
    if out:
        logger.warning("ML eligibility: %d detector(s) not contributing: %s",
                       len(out), ", ".join(out))
    return eligible


def eligibility_scales(client: Client, settings: Settings) -> tuple[dict[str, bool],
                                                                    dict[str, float]]:
    """Eligibility AND the per-detector calibrated thresholds, from ONE evaluation.

    The fusion needs both: the membership (`eligible`) and, for each member, the threshold that
    puts its score on the common calibrated scale (`Report.thresholds`). Reading them from one
    `evaluate` call matters -- two reads could see different calibration rows and normalise a
    score against a threshold the gate did not admit it with.

    A detector contributing without a usable threshold is simply absent from `thresholds`; the
    fusion then falls back to its raw scale rather than mixing units.
    """
    from weirvern.models import eligibility as _eligibility  # noqa: PLC0415

    report = _eligibility.evaluate(client, settings, persist=True)
    eligible = report.eligible
    out = sorted(name for name, ok in eligible.items() if not ok)
    if out:
        logger.warning("ML eligibility: %d detector(s) not contributing: %s",
                       len(out), ", ".join(out))
    return eligible, dict(report.thresholds)


def record_population(client: Client, population: Iterable[dict], *,
                      model_version: str) -> int:
    """Persist RAW per-model scores for every scored host-window.

    `population` is the caller-owned sink filled by `ensemble.detect_flows`. A row is stored
    before thresholds, agreement, severity, or episodes; this is the denominator calibration
    needs. The write is best-effort by contract: the caller catches and logs, because a
    measurement failure must not stop detection.

    COVERAGE TRAVELS WITH ITS COUNTS. `coverage` is `observed / expected` from
    `missing.coverage_counts`; `coverage_observed` and `coverage_expected` are the two integers
    it divides, so a later calibration row can state '10 of 77' instead of a ratio of an
    unknown vector. None (NULL) still means "not measured" -- never zero.
    """
    rows: list[list] = []
    now = utcnow()
    for sample in population:
        start = sample.get("window_start")
        src = str(sample.get("src_addr") or "")
        if start is None or not src:
            continue
        # None means coverage was not measured (the flag was off for this sweep); 0 would
        # claim a fully imputed window. The column is Nullable for exactly this distinction.
        # Prefer this MODEL's own coverage (its vector may be much narrower than the window's
        # union); fall back to the window figure when the caller did not supply one.
        cov = sample.get("coverage")
        window_counts = _counts_pair(sample.get("coverage_counts"))
        per_model = sample.get("model_coverage")
        if not isinstance(per_model, dict):
            per_model = {}
        per_counts = sample.get("model_coverage_counts")
        if not isinstance(per_counts, dict):
            per_counts = {}
        excluded = 1 if sample.get("excluded") else 0
        for model_name, score in (sample.get("scores") or {}).items():
            counts = _counts_pair(per_counts.get(model_name)) or window_counts
            coverage_value: float | None = None
            observed: int | None = None
            expected: int | None = None
            try:
                if counts is not None:
                    observed, expected = counts
                    coverage_value = observed / expected if expected else None
                else:
                    chosen = per_model.get(model_name)
                    if chosen is None:
                        chosen = cov
                    coverage_value = None if chosen is None else float(chosen)
            except (TypeError, ValueError):
                coverage_value = None
                observed = None
                expected = None
            try:
                value = float(score)
            except (TypeError, ValueError):
                continue
            if not math.isfinite(value):
                continue
            rows.append([start, src, str(model_name), value, str(model_version), now,
                         coverage_value, observed, expected, excluded])
    if not rows:
        return 0
    client.insert(
        "weirvern.ml_window_scores", rows,
        column_names=["window_start", "src_addr", "model_name", "score",
                      "model_version", "computed_at", "coverage", "coverage_observed",
                      "coverage_expected", "excluded"],
    )
    return len(rows)


def _usable_rows(rows: Iterable[Sequence[Any]],
                 min_coverage: float | None) -> tuple[list[Sequence[Any]], int]:
    """The rows that may calibrate, and how many were excluded for coverage.

    Split out of `usable_scores` because the STRATIFIED pass needs the whole row (score AND the
    coverage counts that name its stratum), not only the score. One filter, so the pooled and
    per-stratum references can never disagree about which windows were evidence.
    """
    floor = None
    if min_coverage is not None:
        try:
            value = float(min_coverage)
        except (TypeError, ValueError):
            value = 0.0
        floor = value if math.isfinite(value) and value > 0 else None

    kept: list[Sequence[Any]] = []
    excluded = 0
    for row in rows:
        cov = row[1] if len(row) > 1 else None
        if cov is not None and floor is not None:
            try:
                if float(cov) < floor:
                    excluded += 1
                    continue
            except (TypeError, ValueError):
                pass
        score = row[0] if len(row) > 0 else None
        try:
            value = float(score) if score is not None else float("nan")
        except (TypeError, ValueError):
            continue
        if math.isfinite(value):
            kept.append(row)
    return kept, excluded


def usable_scores(rows: Iterable[Sequence[Any]],
                  min_coverage: float | None) -> tuple[list[float], int]:
    """Split a population into (scores to calibrate on, excluded-window count).

    A WINDOW WHOSE TELEMETRY WAS INCOMPLETE IS NOT EVIDENCE about the detector's false-alarm
    rate. Its score was computed from a vector that was mostly imputed, so including it in
    the reference would fit the threshold to a population the detector cannot actually see —
    and including it in the validation half would measure the imputer, not the model. Both
    halves come from the same list here, so one split covers the fit and the FAR measurement.

    `coverage is None` means coverage was not measured (the flag was off when the row was
    written) and is NOT an exclusion: absent evidence about coverage is not evidence of
    insufficient coverage. A floor of None or 0 excludes nothing.

    A row is `(score, coverage)` or `(score, coverage, observed, expected)`; the wider form is
    what `_population_scores` reads now, and the narrow one is still accepted so a caller (or a
    deployment on the older schema) cannot be broken by a column it does not have.
    """
    kept, excluded = _usable_rows(rows, min_coverage)
    scores: list[float] = []
    for row in kept:
        try:
            scores.append(float(row[0]))
        except (TypeError, ValueError, IndexError):
            continue
    return scores, excluded


def coverage_evidence(rows: Iterable[Sequence[Any]],
                      expected: int | None = None) -> dict[str, Any]:
    """What the reference population's coverage was, in the form a calibration row stores.

    ONE DEFINITION OF 'EXPECTED'. The counts are the ones `missing.coverage_counts` produced
    when the window was scored and `record_population` wrote beside the score; nothing here
    re-derives a feature list. A row that carries the counts is authoritative and its integers
    are summed, so `coverage` is exactly `coverage_observed / coverage_expected` over the
    reference -- the share of the expected matrix that was actually measured.

    A row written between the flag flip and the counts column has only the ratio. That ratio was
    produced by `observed / expected` for this model, so with `expected` supplied the integer
    count is recovered exactly (one division, reversed) rather than guessed; `recovered` says
    how many rows needed it, and `run` puts that fact in `reference_source`. A row with neither
    counts nor a ratio is NOT counted at all -- coverage stays None and the row reads as
    unrecorded, which is the only honest answer for history.
    """
    total_observed = total_expected = 0
    counted = 0
    recovered = 0
    windows = 0
    ratios: list[float] = []
    for row in rows:
        windows += 1
        cov = _finite(row[1] if len(row) > 1 else None)
        counts = _counts_pair((row[2] if len(row) > 2 else None,
                               row[3] if len(row) > 3 else None))
        if counts is not None:
            total_observed += counts[0]
            total_expected += counts[1]
            counted += 1
            continue
        if cov is None or not 0.0 <= cov <= 1.0:
            continue
        if expected and expected > 0:
            observed = int(round(cov * expected))
            if 0 <= observed <= expected:
                total_observed += observed
                total_expected += expected
                counted += 1
                recovered += 1
                continue
        ratios.append(cov)
    if counted and total_expected:
        mean_observed = total_observed / counted
        mean_expected = total_expected / counted
        return {
            "coverage": total_observed / total_expected,
            "coverage_observed": total_observed,
            "coverage_expected": total_expected,
            "coverage_detail": f"{mean_observed:.0f}/{mean_expected:.0f}",
            "counted": counted,
            "recovered": recovered,
            "reference_windows": windows,
        }
    if ratios:
        return {
            "coverage": sum(ratios) / len(ratios),
            "coverage_observed": None,
            "coverage_expected": None,
            "coverage_detail": "",
            "counted": 0,
            "recovered": 0,
            "reference_windows": windows,
        }
    return {
        "coverage": None,
        "coverage_observed": None,
        "coverage_expected": None,
        "coverage_detail": "",
        "counted": 0,
        "recovered": 0,
        "reference_windows": windows,
    }


def _population_scores(client: Client, days: int,
                       model_version: str | None = None
                       ) -> dict[str, list[tuple[Any, Any, Any, Any]]]:
    """All scored host-window scores per model, deduped by the Replacing table.

    SCOPED TO `model_version` WHEN GIVEN, and that scoping is a correctness requirement rather than
    a tidiness one. A reference that spans a model or aggregation change calibrates today's detector
    against an older engine's distribution, so the threshold it produces is a mixture of two regimes
    and belongs to neither. Measured on the live engine: the population carried rows from eight
    distinct versions inside one rolling week, and restricting the reference to post-change scores
    moved the 1% threshold from 0.8165 to 0.7327 while the highest score the current engine had
    produced was 0.853, which is the difference between an engine that can alert and one that cannot.

    Coverage rides alongside the score (NULL when it was not measured, which is every row written
    before the flag existed), and so do the counts it was computed from. `usable_scores` decides
    what to do with the coverage; `coverage_evidence` turns the counts into the calibration row.

    A deployment that has not applied the coverage migrations has no such columns; the read falls
    back through the column sets it does have and says so, rather than failing the shadow pass.
    """
    base = " FROM weirvern.ml_window_scores FINAL WHERE computed_at >= now() - INTERVAL %(d)s DAY"
    params: dict[str, object] = {"d": int(days)}
    if model_version:
        base += " AND model_version = %(v)s"
        params["v"] = str(model_version)
    rows: list = []
    for columns in (", coverage, coverage_observed, coverage_expected",
                    ", coverage",
                    ""):
        try:
            rows = client.query("SELECT model_name, score" + columns + base,
                                parameters=params).result_rows
            break
        except Exception as exc:  # noqa: BLE001
            logger.warning("calibration population read without %s (%s); falling back",
                           columns.strip(", ") or "coverage", exc)
    out: dict[str, list[tuple[Any, Any, Any, Any]]] = {}
    for row in rows:
        model_name, score = row[0], row[1]
        cov = row[2] if len(row) > 2 else None
        observed = row[3] if len(row) > 3 else None
        expected = row[4] if len(row) > 4 else None
        out.setdefault(str(model_name), []).append((score, cov, observed, expected))
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

    WITH MISSING-DATA HANDLING ON, windows below the coverage floor are removed before the
    conformal fit, so they contribute to neither the threshold nor the measured FAR. The count
    that was removed rides in `reference_source` (an operator reads it there) and in the
    `excluded_windows` column (the Detectors table reads it there).
    """
    target = float(getattr(settings, "ml_target_far", 0.01) or 0.01)
    window_days = int(days if days is not None else
                      getattr(settings, "ml_calibration_days", 7) or 7)
    min_coverage = getattr(settings, "ml_min_feature_coverage", None)
    # THE MODE IS PART OF THE MEASUREMENT. Two false-alarm rates computed over vectors of
    # different widths are not comparable, so every row states which path produced its reference.
    missing_mode = "on" if bool(getattr(settings, "ml_missing_features", False)) else "off"
    population = _population_scores(client, window_days, __version__)
    rows: list[dict] = []

    def _coverage_source_note(evidence: dict[str, Any], total: int) -> str:
        """What the coverage figure covers, stated where an operator reads the row.

        A mean over the measured windows is not a statement about the unmeasured ones. Saying
        which is which is the difference between "this FAR was measured on 10 of 77 columns" and
        the same number silently read as if it had been measured on all of them.
        """
        if evidence["coverage"] is None:
            return "; coverage not measured for this reference (no feature vector recorded)"
        if evidence["recovered"]:
            return (f"; coverage counts recovered from the recorded ratio for "
                    f"{evidence['recovered']} of {total} reference window(s)")
        if evidence["counted"] < total:
            return (f"; coverage measured on {evidence['counted']} of {total} "
                    f"reference window(s)")
        return ""

    def _row(model_name: str, cal: Calibration, source: str, subject: str,
             reference: Sequence[Any], excluded: int,
             *, scope: str = "global") -> dict:
        # `coverage` is taken over the WHOLE reference population, before the exclusion --
        # that is the evidence about whether this detector has enough telemetry to be
        # calibrated at all. A mean over the kept rows would sit above the floor by
        # construction and could never say "insufficient".
        evidence = coverage_evidence(reference, MODEL_EXPECTED_FEATURES.get(model_name))
        note = _coverage_source_note(evidence, len(reference))
        if evidence["coverage"] is None and "fallback" in source.lower():
            # SAY WHY, NOT ONLY THAT IT IS MISSING. The fallback reads `netflow_anomalies`,
            # whose rows are the alert tail and carry no feature vector, so there is nothing to
            # measure coverage against. Before this, the row said "not measured" and left the
            # operator to guess whether the instrument or the data was at fault.
            note = ("; coverage not measured for this reference: the fallback reads stored "
                    "anomaly scores (the alert tail), which carry no feature vector")
        source += note
        # THE FAR IS A PROPORTION, SO IT IS STORED WITH ITS DENOMINATOR AND ITS INTERVAL. A row
        # that says 0.045 and nothing else cannot be judged: on 110 windows that is 2%-10%, and
        # the eligibility rule now refuses to decide on an interval that wide.
        successes = int(round(max(0.0, min(1.0, float(cal.observed_far))) * cal.validation_count))
        bounds = wilson(successes, int(cal.validation_count))
        return {
            "model_name": model_name,
            "scope": scope,
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
            "far_lower": bounds[0] if bounds else None,
            "far_upper": bounds[1] if bounds else None,
            "reference_source": source,
            "model_version": __version__,
            # NULL, never a number, when the reference carried no coverage: history that was
            # not measured must read as unrecorded rather than as 100%.
            "coverage": evidence["coverage"],
            "coverage_observed": evidence["coverage_observed"],
            "coverage_expected": evidence["coverage_expected"],
            "coverage_detail": evidence["coverage_detail"],
            "missing_mode": missing_mode,
            "excluded_windows": int(excluded),
        }

    def _stratum_rows(model_name: str, stratified: StratifiedCalibration,
                      source: str, subject: str,
                      kept: list[Sequence[Any]], contract: ScoreContract) -> list[dict]:
        """One row per coverage stratum, so the Detectors table can say WHICH population failed.

        These are written with `scope = "coverage"` and `subject = "<observed>/<expected>"`; the
        pooled row keeps `scope = "global"`, which is the only row `eligibility` and the console's
        model summary read. A stratum that could not resolve the target says so in
        `reference_source` and carries the pooled threshold -- the explicit fallback, visible in
        the table rather than inferred from a missing row.
        """
        out: list[dict] = []
        for key in sorted(stratified.strata):
            scal = stratified.strata[key]
            group = [row for row in kept if contract.stratum(row) == key]
            note = source
            if key in stratified.fallbacks:
                note += (f"; FELL BACK to the pooled threshold: {stratified.fallbacks[key]} "
                         f"reference window(s) in this stratum cannot resolve a {target:.2%} "
                         f"budget (a stratum needs {stratified.min_samples}; the conformal rank "
                         f"lands on the maximum below that)")
            out.append(_row(model_name, scal, note, key, list(group), 0, scope="coverage"))
        return out

    for model_name in POPULATION_MODELS:
        column = dict(MODEL_COLUMNS).get(model_name)
        contract = contract_for(model_name)
        reference: list[tuple[Any, Any, Any, Any]] = population.get(model_name) or []
        source = (f"all scored host-windows (ml_window_scores), model {__version__}, "
                  f"last {window_days} days")
        subject = "all scored host-windows"
        kept, excluded = _usable_rows(reference, min_coverage)
        scores: list[float] = []
        for row in kept:
            value = contract.score(row)
            if value is None:
                continue
            number = float(value)
            if math.isfinite(number):
                scores.append(number)
        if len(scores) < 20 and column is not None:
            reference = [(score, None, None, None)
                         for score in _score_rows(client, column, days=30)]
            kept, excluded = _usable_rows(reference, min_coverage)
            scores = [float(row[0]) for row in kept]
            source = "fallback: stored anomaly scores (tail only); population rows unavailable"
            subject = "fallback stored detections"
        if len(scores) < 20:
            # NOT A CALIBRATION. A model with no population rows has nothing to measure; say so
            # once in the log rather than writing a threshold fitted to four scores.
            logger.info("calibration: no reference for %s (%d usable score(s)); skipped",
                        model_name, len(scores))
            continue
        if excluded:
            source += (f"; excluded {excluded} window(s) below the "
                       f"{float(min_coverage if min_coverage is not None else 0.0):.2f} "
                       f"coverage floor")
        pairs: list[tuple[float, str]] = []
        for row in kept:
            value = contract.score(row)
            if value is None:
                continue
            number = float(value)
            if math.isfinite(number):
                pairs.append((number, contract.stratum(row)))
        stratified = fit_stratified(pairs, target)
        if stratified is None:
            continue
        cal = stratified.pooled
        pooled_source = source
        if cal.saturated:
            # Say so where an operator reads it, rather than storing a threshold that silently
            # cannot be crossed and leaving the cause to be rediscovered.
            pooled_source += (f"; SATURATED at the reference ceiling ({cal.ceiling:.4f}): the "
                              f"target FAR is below what {cal.sample_count} samples can express")
        rows.append(_row(model_name, cal, pooled_source, subject, reference, excluded))
        rows.extend(_stratum_rows(model_name, stratified, source, subject, kept, contract))

    reference = population.get(FUSED_MODEL) or []
    scores, excluded = usable_scores(reference, min_coverage)
    if len(scores) >= 20:
        fused_cal = fit(scores, target)
        if fused_cal is not None:
            source = (f"the fused score itself (ml_window_scores), model {__version__}, "
                      f"last {window_days} days")
            if excluded:
                source += (f"; excluded {excluded} window(s) below the "
                           f"{float(min_coverage if min_coverage is not None else 0.0):.2f} "
                           f"coverage floor")
            if fused_cal.saturated:
                source += (f"; SATURATED at the reference ceiling ({fused_cal.ceiling:.4f}): the "
                           f"target FAR is below what {fused_cal.sample_count} samples can express")
            rows.append(_row(FUSED_MODEL, fused_cal, source,
                             "the fused score the decision compares", reference, excluded))
    if not rows:
        return []
    columns = ["model_name", "scope", "subject", "statistic", "target_far", "threshold",
               "p50", "p95", "p99", "sample_count", "validation_count", "observed_far",
               "far_lower", "far_upper",
               "reference_source", "model_version", "coverage", "coverage_observed",
               "coverage_expected", "coverage_detail", "missing_mode", "excluded_windows"]
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


__all__ = ["Calibration", "COVERAGE_CONTRACT", "MIN_STRATUM_SAMPLES", "MODEL_COLUMNS",
           "MODEL_EXPECTED_FEATURES", "POPULATION_MODELS", "ScoreContract",
           "StratifiedCalibration", "calibrated_bar", "conformal_pvalue", "conformal_threshold",
           "contract_for", "coverage_evidence", "coverage_stratum", "eligibility",
           "eligibility_scales",
           "fit", "fit_stratified", "record_population", "register_model_contract", "run",
           "usable_scores"]


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
