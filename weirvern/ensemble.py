"""Ensemble fusion — combines detector scores into one explainable verdict.

Lesson v14.11→v19: the fusion logic (weights, agreement, adaptive thresholds)
was rewritten in every version and duplicated across drafts. It now lives in
exactly one place and is fully unit-tested.
"""
from __future__ import annotations

import logging
import math
from typing import Any

from weirvern.config import FUSED_MODEL, ModelConfig, Settings
from weirvern.features import TELEMETRY_FEATURES, extract_features
from weirvern.models.base import BaseDetector
from weirvern.models.detectors import AdaptiveBaselineDetector
from weirvern.models.missing import DEFAULT_MIN_COVERAGE, coverage_counts

logger = logging.getLogger(__name__)

# A detector score at/above this counts as a STRONG independent signal.
# Two-or-more strong signals are required to escalate to high/critical severity
# (see severity_of for the measured rationale).
#
# THE DEFAULT ONLY. The live value comes from Settings.strong_signal (env STRONG_SIGNAL),
# because this was editable through the GUI/ConfigMap while nothing read the env var --
# an edit that validated, restarted the worker, and changed nothing. The constant remains
# for callers that have no Settings (tests, tools).
STRONG_SIGNAL = 0.85


def strong_signal_threshold(settings: Settings | None = None) -> float:
    """The corroboration bar in force: the configured value, else the constant."""
    if settings is None:
        return STRONG_SIGNAL
    return float(getattr(settings, "strong_signal", STRONG_SIGNAL) or STRONG_SIGNAL)


# The ceiling every fused score is capped at. NAMED BECAUSE IT IS HALF OF AN INVARIANT (audit F186):
# `detection_confidence_factor` multiplies a capped score by `thin_window_floor`, so the reachable
# maximum for a thin window is THIS times that floor -- and a floor below base_threshold/this makes a
# whole category of windows unalertable. See `assert_thin_floor_is_reachable`.
MAX_FUSED_SCORE = 0.99

# A detector "detected" a window at a score STRICTLY above this bar: it feeds the agreement
# ratio, the near-miss rows' own `model_agreement`, and the human-readable
# `detected_by_models` string. One constant because those three uses had drifted copies.
DETECTED_BY_SCORE = 0.20

# ── WHAT COUNTS AS AN INDEPENDENT CORROBORATING MODEL ────────────────────────────────────────
#
# Gradient Boosting is trained on the Isolation Forest's own labels (see
# GradientBoostingDetector.train: `teacher.predict(Xs)`). It is a STUDENT of the forest, so a high
# score from both is one observation stated twice -- not two independent observations. Counting
# both as corroboration is how ordinary gateway traffic with a 1.3x byte change reached
# `critical` on the live cluster.
#
# KNN distance and LOF are two DIFFERENT cross-sectional questions and are separate families on
# purpose: kNN asks "how far is the k-th neighbour?" (global distance), LOF asks "how much denser
# is my neighbourhood than my neighbours'?" (local density ratio). They share a feature vector and
# nothing else, and the bake-off measured them as nearly uncorrelated. The Adaptive Baseline learns
# a third thing again.
MODEL_FAMILIES: dict[str, str] = {
    "Isolation Forest": "forest",
    "Gradient Boosting": "forest",   # semi-supervised student of Isolation Forest
    "KNN distance": "distance",
    "LOF": "local-density",
    "Adaptive Baseline": "baseline",
}


def strong_model_families(scores: dict[str, float], bar: float) -> int:
    """How many INDEPENDENT families have a detector at or above the strong-signal bar."""
    return len({
        MODEL_FAMILIES.get(name, name)
        for name, score in scores.items()
        if float(score) >= float(bar)
    })


# A material univariate deviation, in robust-ish sigma units from the host's own baseline.
# Not every real attack moves a volume measurement (a zero-byte SYN scan does not), which is why
# the signature and novelty channels below can establish materiality on their own.
MATERIAL_Z_CRITICAL = 3.0
MATERIAL_Z_HIGH = 2.0


def fuse_scores(scores: dict[str, float], weights: dict[str, float] | None = None,
                mode: str = "max") -> float:
    """Ensemble fusion.

    RATIONALE (empirically established against live ClickHouse data):
    Each detector covers a different attack family — Isolation Forest finds
    novel traffic shapes, Gradient Boosting finds learned behavior patterns,
    KNN distance finds windows far from the population, LOF finds local
    density outliers, Adaptive Baseline finds per-host volume deviations. A
    confident specialist often fires ALONE: the density detector this ensemble
    used to carry scored a seeded port scan at 0.99 while the volume-oriented
    models scored ~0.0 (correctly — a scan moves no bytes).

    The legacy mean-fusion averaged that 0.99 down to 0.405, BELOW benign
    hosts (0.543), so the scan went unalerted. Averaging silently means "no
    alert unless most models agree", which discards every attack family only
    one model can see.

    mode="max" (default): the reported score is the strongest detector signal.
      Per-detector weights are NOT applied here — scaling a confident detector
      down by weight re-introduces exactly the dilution this replaced.
      False-positive control lives in the agreement gate and severity tiers instead.
    mode="mean": legacy weighted average, retained for A/B comparison only.
    """
    if not scores:
        return 0.0
    if mode == "mean":
        w = weights or {}
        total = sum(w.get(n, 1.0) for n in scores)
        return float(min(MAX_FUSED_SCORE, sum(scores[n] * w.get(n, 1.0) for n in scores) / total))
    return float(min(MAX_FUSED_SCORE, max(scores.values())))


def calibrated_scores(scores: dict[str, float],
                      thresholds: dict[str, float] | None,
                      bar: float) -> dict[str, float]:
    """Put every detector's score on ONE scale: its own calibrated threshold maps to `bar`.

    WHY THIS EXISTS. `max` fusion over raw scores is only comparable when the members are. With one
    eligible detector the fused score IS that detector's raw score, and `BASE_THRESHOLD` 0.35 then
    means whatever that detector happens to emit: measured live on 2026-11-20, KNN alone exceeded
    0.35 on 79.2% of windows while its own calibrated 1% threshold sat near 0.96 on the same scale.
    Adding or removing a detector changed the meaning of the bar because it changed the units.

    THE MAP. `score * bar / threshold_i` is monotone, so ranking inside a detector is untouched and
    its calibrated threshold lands exactly on `bar`. 0.35 therefore means "this detector at its
    calibrated false-alarm point" whether the membership is one, two or five. The result is capped
    at MAX_FUSED_SCORE so the thin-window invariant (`MAX_FUSED_SCORE * floor >= bar`) still holds.

    A detector with no usable threshold keeps its raw score: inventing a scale for an uncalibrated
    detector would put a number in front of every alert that looks calibrated and is not. Callers
    should only take this path when every contributing detector has one.
    """
    if not thresholds:
        return dict(scores)
    scale = float(bar)
    out: dict[str, float] = {}
    for name, score in scores.items():
        threshold = thresholds.get(name)
        try:
            value = float(score)
        except (TypeError, ValueError):
            continue
        try:
            t = float(threshold) if threshold is not None else 0.0
        except (TypeError, ValueError):
            t = 0.0
        if math.isfinite(t) and t > 0:  # noqa: PLR2004 - a threshold is a positive score
            out[name] = float(min(MAX_FUSED_SCORE, max(0.0, value * scale / t)))
        else:
            out[name] = value
    return out


def contributing_scores(scores: dict[str, float],
                        eligible: dict[str, bool] | None = None) -> dict[str, float]:
    """Scores that may set the fused result.

    EXCLUDED, NOT ZEROED. A model that is not eligible is REMOVED from the mapping, not replaced
    with 0.0. In max fusion the two are equivalent, but in mean fusion a zero drags the average
    down -- i.e. an uncalibrated detector would still change the decision while being reported as
    "not contributing". The operator's rule is that such a model is excluded from the fused score
    entirely.

    A MODEL ABSENT FROM A NON-EMPTY `eligible` MAPPING IS NOT ELIGIBLE. `eligibility()` returns a
    row only for a model that has a calibration measurement; "no row" is "no met budget", the same
    rule `detector_status` applies. This is what keeps a freshly trained, not-yet-calibrated kNN
    or LOF OUT of the fused score on its first cycle instead of letting it win `max` fusion while
    it has no measured false-alarm rate. The empty mapping is different: a deployment that has
    produced no calibration rows at all still runs detection, and every detector contributes.
    """
    if not eligible:
        return dict(scores)
    return {name: score for name, score in scores.items() if eligible.get(name, False)}


def detection_confidence_factor(flow: dict, cfg) -> float:
    """Damp scores computed from statistically thin windows.

    MEASURED PROBLEM: windows with only 3-4 flows produced false-positive
    'critical' alerts. With so few observations, a single heavy-tailed flow
    (a backup, a streaming session) dominates the window's mean/stddev, so the
    derived features look extreme even though the host is behaving normally.
    Measured on live data: benign 3-flow windows scored GB=0.96 while the host's
    own 60+ flow windows scored ~0.0.

    Genuine attacks do not depend on this: the seeded port scan presented 305
    flows / 300 ports, and the exfil presented 3.6 GB against a 65 MB host
    baseline — both statistically overwhelming.

    Returns a multiplier in [floor, 1.0]. Windows at/above
    `min_flows_for_full_confidence` are untouched.

    ── THE FLOOR CANNOT BE BELOW base_threshold / MAX_FUSED_SCORE (audit F186) ──────────────────

    A MULTIPLIER FLOOR AND AN ABSOLUTE THRESHOLD ARE NOT THE SAME KIND OF NUMBER, and they shipped
    as the same value (0.35), which hid the relationship between them. `fuse_scores` caps every
    score at MAX_FUSED_SCORE = 0.99, so the best a thin window can reach is

        0.99 * thin_window_floor

    and if that is below `base_threshold`, the window is not scored low -- it is UNREACHABLE, no
    matter how loud the signal. With floor 0.35: 0.99 * 0.35 = 0.3465 against a bar of 0.35, short by
    0.0035. MEASURED ON THE LIVE CLUSTER: 23 of 23 near misses scored exactly 0.3465 across six
    unrelated hosts -- a constant score is not a coincidence, it is a ceiling -- and 566 of 567
    windows in a 6-hour span (99.8%, carrying 99.98% of the bytes) had too few flows to clear it.

    The instrument was checked before the finding was trusted: the counts were taken from the
    COLLAPSED per-window aggregates (`_collapse_partial_aggregates`), because F181 established that
    the raw table is fragmented per insert block and a per-block read would have understated the
    counts. After collapsing, 25 of 25 windows were still under `min_flows_for_full_confidence`.

    The floor is now above the derived minimum, and `assert_thin_floor_is_reachable` makes the
    relationship checked rather than implied, so the two constants cannot drift apart again in
    silence.
    """
    flows = float(flow.get("flow_count", 0) or 0)
    min_flows = float(cfg.min_flows_for_full_confidence)
    if flows >= min_flows or min_flows <= 0:
        return 1.0
    ratio = flows / min_flows
    return float(max(cfg.thin_window_floor, ratio))


def assert_thin_floor_is_reachable(cfg, base_threshold: float) -> None:
    """Raise if a maximally-signalled thin window cannot clear the bar.

    THE RELATIONSHIP, in one place so it cannot drift: `thin_window_floor` is a MULTIPLIER on a capped
    score, `base_threshold` is an absolute score, and a thin window is only reachable when

        MAX_FUSED_SCORE * cfg.thin_window_floor >= base_threshold

    A violation is not a tuning preference -- it is a category of windows that cannot alert whatever
    the detectors report, which is why this raises instead of warning. Called once per sweep rather
    than per flow: the cost is a comparison, and the alternative is discovering it from a constant
    score on every near miss, months later.
    """
    ceiling = MAX_FUSED_SCORE * float(cfg.thin_window_floor)
    if ceiling < float(base_threshold):
        raise ValueError(
            f"a window below min_flows_for_full_confidence ({cfg.min_flows_for_full_confidence}) "
            f"cannot reach the alert threshold. The best such a window can score is "
            f"{MAX_FUSED_SCORE} * thin_window_floor ({cfg.thin_window_floor}) = {round(ceiling, 4)}, "
            f"but the bar is {base_threshold}. Raise thin_window_floor above "
            f"{round(float(base_threshold) / MAX_FUSED_SCORE, 6)} or lower base_threshold; otherwise "
            f"every thin window is silently unalertable no matter how strong its signal (audit F186)"
        )


def signature_corroboration(flow: dict, scores: dict[str, float], diversity: dict | None,
                            cfg, strong_signal: float | None = None) -> bool:
    """Is a lone strong detector corroborated by a direct structural signature?

    MEASURED PROBLEM: a pure SYN port scan (305 flows, 0 bytes, 300 ports) was
    scored strongly by the density detector (0.99) but weakly by the volume/shape models
    (IF 0.48, GB 0.01) — because a scan moves no bytes, so there is nothing for
    them to be anomalous about. Requiring two strong detectors therefore left the
    scan at 'medium'. Those models are not disagreeing; they have no opinion.

    So a single strong specialist IS treated as corroborated when the window
    carries a direct structural signature of the family that specialist covers
    (diversity metrics are computed from the raw flows, independent of the ML
    scoring — they are evidence, not inference).

    `strong_signal` is the configured corroboration bar (Settings.strong_signal);
    None falls back to the module default so existing callers are unchanged.

    Returns True when the lone strong signal is backed by such a signature.
    """
    bar = STRONG_SIGNAL if strong_signal is None else float(strong_signal)
    strong = {n: s for n, s in scores.items() if s >= bar}
    if len(strong) != 1 or not diversity:
        return False
    ports = float(diversity.get("unique_dst_ports", 0) or 0)
    entropy = float(diversity.get("port_entropy", 0.0) or 0.0)
    # Port-scan / lateral-movement signature: many distinct ports, wide spread.
    return ports >= cfg.port_scan_min_ports and entropy >= cfg.port_scan_min_entropy


def severity_of(score: float, strong_models: int = 0, signature: bool = False, *,
                strong_families: int | None = None,
                deviation_magnitude: float | None = None,
                novelty: bool = False) -> str:
    """Severity tiers, gated on INDEPENDENT corroboration AND measured materiality.

    `strong_models` is the raw count of detectors at or above STRONG_SIGNAL, retained for the
    console and the near-miss record. `strong_families` is the count of independent model
    families; severity uses it when supplied, because Isolation Forest and its Gradient Boosting
    student are one observation, not two.

    `deviation_magnitude` is the largest absolute z-score the window has against the host's own
    baseline. When it is supplied, high/critical also require a MATERIAL deviation (3 sigma for
    critical, 2 sigma for high), unless a direct structural signature (a port scan) or a novelty
    observation (a TLS fingerprint the host has never used) is present. A model score without a
    material measurement is a lead, not an incident -- and on the live cluster 163 of 276
    `critical` rows carried less than 1 sigma of measured deviation. `None` means "not measured
    yet" and preserves the legacy behaviour for callers that have no explanation; the worker
    always supplies the measured value.

    The signature carries NO agreement argument: it is direct evidence, and a lone specialist
    backed by one is allowed to escalate.
    """
    families = strong_models if strong_families is None else int(strong_families)
    corroborated = families >= 2 or (families >= 1 and signature)
    material_critical = (
        signature or novelty or deviation_magnitude is None
        or float(deviation_magnitude) >= MATERIAL_Z_CRITICAL
    )
    material_high = (
        signature or novelty or deviation_magnitude is None
        or float(deviation_magnitude) >= MATERIAL_Z_HIGH
    )
    if score >= 0.95 and corroborated and material_critical:
        return "critical"
    if score >= 0.85 and corroborated and material_high:
        return "high"
    if score >= 0.70 or (score >= 0.60 and families >= 1):
        return "medium"
    return "low"


def severity_basis(score: float, strong_families: int, signature: bool = False,
                    deviation_magnitude: float | None = None,
                    novelty: bool = False) -> str:
    """A visible, plain-language reason for the severity label.

    The operator must be able to read WHY a row says critical/high without hovering. This is
    the sentence that distinguishes a measured incident from a lead that was capped, and it is
    stored beside the severity so the row cannot drift from its explanation.

    Keep it short enough for a table's why line; the full explanation stays in
    `baseline_comparison`/`feature_contributions`.
    """
    parts: list[str] = []
    if strong_families:
        parts.append(f"{int(strong_families)} independent famil"
                     f"{'y' if int(strong_families) == 1 else 'ies'}")
    if signature:
        parts.append("structural signature")
    if novelty:
        parts.append("new TLS fingerprint")
    if deviation_magnitude is None:
        parts.append("deviation not measured")
    else:
        parts.append(f"{float(deviation_magnitude):.1f}σ")
    material = bool(signature or novelty
                    or (deviation_magnitude is not None
                        and float(deviation_magnitude) >= MATERIAL_Z_CRITICAL))
    if not material:
        return "score only — " + ", ".join(parts) + " (capped below incident)"
    if score < 0.60 or (score < 0.70 and strong_families < 1):
        return "score below alert band; " + ", ".join(parts)
    if score < 0.85:
        return "medium band; " + ", ".join(parts)
    return ", ".join(parts)


def fusion_excluded(settings: Any) -> set[str]:
    """Model names the operator has removed from the fusion.

    Kept separate from eligibility on purpose: see the comment on `ml_fusion_exclude` in config.
    """
    raw = str(getattr(settings, "ml_fusion_exclude", "") or "")
    return {part.strip() for part in raw.split(",") if part.strip()}


def adaptive_threshold_for(flow: dict[str, Any], base: float) -> float:
    """v18+ pattern-aware sensitivity reduction.

    Statistical attack-like patterns lower the bar (floor 0.20):
      - many flows to few destinations (scanning / lateral movement)
      - small bytes-per-flow with high flow count (probes)
      - extreme volume (exfiltration)
      - single-dest high flow count (credential stuffing)
    """
    threshold = base
    flow_count = float(flow.get("flow_count", 0) or 0)
    unique_dsts = float(flow.get("unique_dst_ips", 1) or 1)
    total_bytes = float(flow.get("total_bytes", 0) or 0)
    bytes_per_flow = total_bytes / max(flow_count, 1.0)

    if flow_count > 50 and unique_dsts < 5:
        threshold *= 0.6
    if flow_count > 30 and bytes_per_flow < 1000:
        threshold *= 0.55
    if total_bytes > 50_000_000:
        threshold *= 0.7
    if flow_count > 100 and unique_dsts == 1:
        threshold *= 0.65
    return max(0.20, threshold)


def detect_flows(
    flows: list[dict[str, Any]],
    detectors: list[BaseDetector],
    settings: Settings,
    cfg: ModelConfig,
    near_misses: list[dict[str, Any]] | None = None,
    eligible: dict[str, bool] | None = None,
    score_population: list[dict[str, Any]] | None = None,
    calibrated_bar: float | None = None,
    thresholds: dict[str, float] | None = None,
) -> list[dict[str, Any]]:
    """Run the full ensemble over recent aggregate flows; return verdict rows.

    Each verdict carries per-model scores, agreement, adaptive threshold used,
    explainability fields, and a severity — everything the alerting layer and
    ClickHouse row need.

    SCORE POPULATION (PRD-2). When `score_population` is provided, EVERY scored host-window's
    raw per-model scores are appended before the threshold/agreement gate. This is the
    denominator for calibration; without it, calibration can only see the alert tail. The list is
    a caller-owned sink, so the ensemble stays a pure function of its inputs.

    NEAR MISSES (soc-2). The two `continue` paths below used to throw their scores away, so
    "what almost alerted" was unanswerable -- the audit's note that the data "exists, it just
    is not queried" was wrong: measured, the scores were computed and discarded. When the
    caller passes a `near_misses` list, every window dropped by the BAND (scored within
    reach of the bar) or by the AGREEMENT GATE (cleared the bar, too few models agreed) is
    appended to it: identity, score, the threshold it faced, which reason dropped it, and
    the per-detector scores. The caller decides whether and where to store them; passing
    None (every existing caller) changes nothing.
    """
    # Index diversity/temporal data if the caller supplied it (worker joins);
    # flows here are already enriched by the worker.
    baseline_det = next((d for d in detectors if isinstance(d, AdaptiveBaselineDetector)), None)
    # ONE reading of the missing-data settings for the whole pass (default OFF).
    missing_mode = bool(getattr(cfg, "missing_features", False))
    coverage_floor = getattr(cfg, "min_feature_coverage", DEFAULT_MIN_COVERAGE)
    coverage_floor = (DEFAULT_MIN_COVERAGE if coverage_floor is None
                      else float(coverage_floor))

    # Map detector display names to config weight keys (unknown detector
    # names fall back to weight 1.0 — a sweep must never crash on a name).
    NAME_TO_KEY = {
        "Isolation Forest": "isolation_forest",
        "Gradient Boosting": "gradient_boosting",
        "KNN distance": "knn",
        "LOF": "lof",
        "Adaptive Baseline": "adaptive_baseline",
    }

    def _weight_of(name: str, weights: dict[str, float]) -> float:
        return weights.get(NAME_TO_KEY.get(name, name), 1.0)

    results: list[dict[str, Any]] = []
    for flow in flows:
        src = flow.get("src_addr")
        if not src or (flow.get("total_bytes") or 0) < 0:
            continue

        # v20 fix: the worker attaches _diversity/_temporal per flow; without
        # this, port_entropy/burstiness/etc. silently fell back to defaults
        # and the Phase 2 detectors scored on 10 host features only.
        # THE ZEEK ROW MUST BE PASSED, or the Zeek features default to zero at scoring
        # time while the models were trained on their real values -- the model would be
        # evaluated on a different distribution than it was fitted on, and nothing would
        # raise. `_zeek` is attached by the worker alongside _diversity/_temporal, and a
        # host Zeek never saw is a legitimate None rather than an error: the presence flag
        # in the vector records that.
        features = extract_features(
            flow, flow.get("_diversity") or None, flow.get("_temporal") or None,
            flow.get("_zeek") or None,
            (baseline_det.baselines.get(src) if baseline_det else None),
            preserve_missing=missing_mode,
        )
        # HOW MUCH OF THE VECTOR WAS MEASURED, once per window over the union of everything
        # the four detectors consume (`None` with the flag off: not measured is not zero), and
        # once per detector over its OWN vector, because the cross-sectional pair's 19 columns and
        # the wide pair's 77 are covered differently. Both feed calibration; the per-detector number is
        # what a detector's row reports. THE COUNTS RIDE WITH THE RATIO: calibration stores
        # '10 of 77' so a false-alarm rate can never be read without knowing what it was
        # measured on. They come from `coverage_counts`, the same count `coverage` divides.
        window_counts = coverage_counts(features, TELEMETRY_FEATURES) if missing_mode else None
        window_coverage = (window_counts[0] / window_counts[1]) if window_counts else None
        model_coverage: dict[str, float] | None = None
        model_coverage_counts: dict[str, tuple[int, int]] | None = None
        if missing_mode:
            model_coverage = {}
            model_coverage_counts = {}
            for det in detectors:
                declared: Any = getattr(det, "expected_feature_columns", None)
                names = list(declared()) if callable(declared) else []
                counts = coverage_counts(features, names or TELEMETRY_FEATURES)
                model_coverage_counts[det.name] = counts
                model_coverage[det.name] = counts[0] / counts[1] if counts[1] else 1.0
        scores: dict[str, float] = {}
        for det in detectors:
            scores[det.name] = det.predict(flow, features)

        # PRD-2: keep the RAW score for every scored window, before the threshold or the
        # agreement gate. Calibration needs the population, not the alert tail.
        sample: dict[str, Any] | None = None
        if score_population is not None and flow.get("window_start") is not None:
            sample = {
                "window_start": flow["window_start"],
                "src_addr": src,
                "scores": dict(scores),
                "coverage": window_coverage,
                "coverage_counts": window_counts,
                "model_coverage": model_coverage,
                "model_coverage_counts": model_coverage_counts,
                "excluded": bool(window_coverage is not None
                                 and window_coverage < coverage_floor),
            }

        has_baseline = bool(baseline_det and src in baseline_det.baselines)
        # Weights are applied only in "mean" fusion mode (see fuse_scores).
        weights = dict(cfg.weights)
        if baseline_det is not None:
            weights["adaptive_baseline"] = cfg.weight_baseline if has_baseline else cfg.weight_baseline_missing

        contributing = contributing_scores(scores, eligible)
        excluded = fusion_excluded(settings)
        if excluded:
            # Zeroed rather than deleted, so the evidence record still names every detector that
            # scored the window while an excluded model cannot win `max` fusion.
            contributing = {n: (0.0 if n in excluded else s) for n, s in contributing.items()}
        final_score = fuse_scores(
            contributing,
            {n: _weight_of(n, weights) for n in scores},
            mode=cfg.fusion_mode,
        )

        # ── TWO NUMBERS, ON PURPOSE ───────────────────────────────────────────────────────────
        #
        # `final_score` stays the RAW fused score: it is what severity tiers, confidence, the
        # stored anomaly score and the operator all read, and rescaling it would silently move
        # every one of those. `decision_score` is the same max taken over CALIBRATED scores, where
        # each detector's own 1% threshold maps to `base_threshold`; that is the number the alert
        # bar compares. With one eligible detector the raw comparison was the detector's own
        # quantile and paged on 79.2% of windows; the calibrated one pages on its measured tail.
        active_members = [n for n in contributing if n not in excluded]
        scales = thresholds or {}
        scales_active = bool(scales) and bool(active_members) and all(
            scales.get(n) is not None and float(scales[n]) > 0 for n in active_members)
        scaled_contributing: dict[str, float] | None = None
        if scales_active:
            scaled_contributing = calibrated_scores(
                contributing, thresholds, float(getattr(settings, "base_threshold", 0.35)))
            decision_score = fuse_scores(
                scaled_contributing,
                {n: _weight_of(n, weights) for n in scores},
                mode=cfg.fusion_mode,
            )
        else:
            decision_score = final_score

        # Damp statistically thin windows (see detection_confidence_factor)
        damping = detection_confidence_factor(flow, cfg)
        final_score = round(final_score * damping, 4)
        decision_score = round(decision_score * damping, 4)

        # THE FUSED SCORE JOINS THE POPULATION, because it is the number the decision compares and
        # therefore the only one a calibrator can turn into an alert budget. Recorded pre-threshold,
        # like the per-model scores beside it. It is the DECISION score: a calibration of a raw max
        # over a membership that changes cannot describe the bar the decision actually uses.
        if sample is not None and score_population is not None:
            sample["scores"][FUSED_MODEL] = decision_score
            score_population.append(sample)

        if scales_active:
            # The calibrated scale IS the budget: each detector's own 1% point sits on
            # `base_threshold`, so a per-window reduction on top of it would spend a budget
            # nobody selected. The raw threshold reported beside a near miss is the threshold of
            # the detector that got closest on the calibrated scale, so score and bar stay in the
            # same units for a reader.
            threshold = float(getattr(settings, "base_threshold", 0.35))
            top = max(active_members,
                      key=lambda n: (scaled_contributing or {}).get(n, 0.0), default=None)
            raw_threshold = float((thresholds or {})[top]) if top is not None else threshold
            top_raw_score = float(scores.get(top, 0.0)) if top is not None else 0.0
        else:
            if calibrated_bar is not None and math.isfinite(calibrated_bar) and calibrated_bar > 0:
                # The calibrated threshold IS the chosen alerts-per-day, so no per-window
                # reduction is applied on top of it: a reduction there would spend a budget
                # nobody selected, which is how the measured false-alarm rate came to describe a
                # threshold nothing alerted at.
                threshold = float(calibrated_bar)
            else:
                threshold = adaptive_threshold_for(flow, settings.base_threshold)
            raw_threshold = threshold
            top_raw_score = final_score
        bar = strong_signal_threshold(settings)
        # A direct structural signature can corroborate a lone specialist. It is evaluated from
        # the RAW scores: an ineligible model may still be the one that saw the scan, and the
        # signature is the reason the exception exists. If the contribution gate pushed the
        # fused score below the bar, the signature restores the raw strongest signal.
        signature = signature_corroboration(flow, scores, flow.get("_diversity"), cfg,
                                            strong_signal=bar)
        if decision_score < threshold:
            if signature:
                # RAW scores, minus the fusion exclusions. Eligibility is deliberately ignored here
                # (a barred model may be the one that saw the scan), but an excluded model must not
                # come back through this door, or the exclusion would only apply to the fused path
                # and the score would still be set by the model we removed.
                restore = max((s for n, s in scores.items() if n not in excluded), default=0.0)
                final_score = round(max(final_score, restore), 4)
                # The signature is direct evidence, so it clears the calibrated bar too; leaving
                # decision_score below it would alert on a number the gate never accepted.
                decision_score = max(decision_score, threshold)
            else:
                # NEAR MISS (band): scored close to the bar but under it. The band floor is
                # threshold * near_miss_band -- measured against the threshold this host faced,
                # not the global default, so a host with a raised adaptive bar does not flood
                # the table with its ordinary traffic.
                if near_misses is not None and decision_score >= threshold * cfg.near_miss_band:
                    near_misses.append({
                        "window_start": flow["window_start"],
                        "window_end": flow.get("window_end"),
                        "src_addr": src,
                        "anomaly_score": round(top_raw_score, 4),
                        "threshold_used": round(raw_threshold, 4),
                        "reason": "below-threshold",
                        "model_agreement": round(
                            len([n for n, s in contributing_scores(scores, eligible).items()
                                 if s > DETECTED_BY_SCORE])
                            / max(1, len(detectors)), 4),
                        "isolation_forest_score": round(scores.get("Isolation Forest", 0.0), 4),
                        "gradient_boosting_score": round(scores.get("Gradient Boosting", 0.0), 4),
                        "baseline_score": round(scores.get("Adaptive Baseline", 0.0), 4),
                        "detected_by_models": ", ".join(
                            n for n, s in scores.items() if s > DETECTED_BY_SCORE),
                    })
                continue

        detected_by = [n for n, s in scores.items() if s > DETECTED_BY_SCORE]
        # ── A MISSING DETECTOR MUST NOT LOOSEN THE GATE (audit F043) ─────────────────────────────
        #
        # This used to divide by the number of detectors that reported READY, so a detector that
        # failed to train removed itself from the denominator -- and agreement is a RATIO, so losing
        # detectors made it LARGER. MEASURED by driving the real ensemble with the same flow and the
        # same scores, varying only readiness:
        #
        #     all 4 ready (healthy)   score=0.550  agreement=0.25  -> SUPPRESSED
        #     one detector failed    score=0.550  agreement=0.33  -> ALERT
        #     two detectors failed   score=0.550  agreement=0.50  -> ALERT
        #     only IF ready           score=0.550  agreement=1.00  -> ALERT, confidence 0.550
        #
        # So a broken model turned a window the ensemble had DELIBERATELY SUPPRESSED into an alert
        # that looked BETTER corroborated than a healthy one -- the confidence is score*agreement, so
        # the fewer detectors that worked, the higher the reported confidence. The failure is silent
        # in the worst direction: it manufactures alerts, and its alerts look more certain.
        #
        # THE DENOMINATOR IS THE ENSEMBLE, NOT THE SURVIVORS. `build_detectors` always constructs
        # four, so the size of the intended ensemble is what a reader of "3 of 4 models agreed"
        # expects, and a detector that did not train is a detector that did not agree. `max(1, ...)`
        # keeps the ratio defined when the list is empty for any reason.
        active = max(1, len(detectors))
        agreement = len([n for n, s in contributing_scores(scores, eligible).items()
                         if s > DETECTED_BY_SCORE]) / active

        # ── THE GATE MUST BIND AT EVERY TIER (review round 2026-10-15) ───────────────────────
        #
        # The gate reads settings.min_agreement (MIN_AGREEMENT); this used to be hardcoded,
        # and a setting nothing reads is this repo's oldest bug class -- that part stands.
        # But the hardcoded PAIR (0.33 below 0.6, 0.25 at or above) had a second defect,
        # measured: with four detectors the smallest non-zero agreement is exactly one
        # detector's share, 1/4 = 0.25 == the top-tier bar -- and max-fusion means any window
        # scoring >= 0.6 already has one detector above DETECTED_BY_SCORE. So
        # `agreement < min_agreement` could never be true at the top tier: a lone detector's
        # word alerted at medium, and the window never appeared in near_misses because it was
        # never dropped. That was the false-positive control the fusion rationale says lives
        # in the agreement gate -- and it did not run.
        #
        # The solo share is now excluded at every tier: a window whose agreement does not
        # EXCEED one detector's share is gated unless the system's one deliberate exemption
        # holds -- a lone strong specialist backed by a DIRECT structural signature (see
        # signature_corroboration; the zero-byte port scan is the measured case that must
        # keep alerting). The configured bar itself is untouched: below it, gating is by the
        # operator's number; the solo exclusion is a floor underneath, so no configuration
        # can silently disable the gate the way 0.25 did.
        solo = 1.0 / active
        min_agreement = (
            settings.min_agreement if final_score < 0.6
            else max(cfg.min_agreement_floor, settings.min_agreement - cfg.min_agreement_margin)
        )

        # Strong corroboration: how many detectors independently scored high. Gates escalation
        # to high/critical (see severity_of docstring), and rescues a lone specialist from the
        # solo exclusion. The bar is the CONFIGURED one (STRONG_SIGNAL /
        # Settings.strong_signal), which the GUI and ConfigMap advertise as editable --
        # reading the constant here meant an operator's edit validated and then changed
        # nothing.
        strong_scores = contributing_scores(scores, eligible)
        strong_models = sum(1 for s in strong_scores.values() if s >= bar)
        strong_families = strong_model_families(strong_scores, bar)
        # `signature` was computed before the threshold above; it uses the RAW scores on purpose.

        if not signature and (agreement < min_agreement or agreement <= solo):
            # NEAR MISS (agreement gate): cleared the score bar and was dropped anyway
            # because too few detectors agreed. A lone-specialist window that never got
            # corroboration is precisely what a tuning loop needs to see -- it is the
            # difference between "nothing was there" and "we decided not to look".
            if near_misses is not None:
                near_misses.append({
                    "window_start": flow["window_start"],
                    "window_end": flow.get("window_end"),
                    "src_addr": src,
                    "anomaly_score": round(final_score, 4),
                    "threshold_used": round(raw_threshold, 4),
                    "reason": "agreement-gate",
                    "model_agreement": round(agreement, 4),
                    "isolation_forest_score": round(scores.get("Isolation Forest", 0.0), 4),
                    "gradient_boosting_score": round(scores.get("Gradient Boosting", 0.0), 4),
                    "baseline_score": round(scores.get("Adaptive Baseline", 0.0), 4),
                    "detected_by_models": ",".join(detected_by),
                })
            continue

        results.append({
            "window_start": flow["window_start"],
            "window_end": flow.get("window_end"),
            "src_addr": src,
            "anomaly_score": round(final_score, 4),
            "confidence": round(final_score * agreement, 4),
            "isolation_forest_score": round(scores.get("Isolation Forest", 0.0), 4),
            "gradient_boosting_score": round(scores.get("Gradient Boosting", 0.0), 4),
            "baseline_score": round(scores.get("Adaptive Baseline", 0.0), 4),
            "model_agreement": round(agreement, 4),
            "detected_by_models": ",".join(detected_by),
            "severity": severity_of(final_score, strong_models, signature,
                                     strong_families=strong_families),
            "strong_models": strong_models,
            "strong_families": strong_families,
            "signature": signature,
            "threshold_used": round(raw_threshold, 4),
        })
    return results
