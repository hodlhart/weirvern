"""Ensemble fusion — combines detector scores into one explainable verdict.

Lesson v14.11→v19: the fusion logic (weights, agreement, adaptive thresholds)
was rewritten in every version and duplicated across drafts. It now lives in
exactly one place and is fully unit-tested.
"""
from __future__ import annotations

import logging
from functools import lru_cache
from typing import Any

from weirvern.config import ModelConfig, Settings
from weirvern.features import extract_features
from weirvern.models.base import BaseDetector
from weirvern.models.detectors import AdaptiveBaselineDetector

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


@lru_cache(maxsize=8192)
def _detector_catalog() -> tuple[str, ...]:
    return (
        "Isolation Forest",
        "Gradient Boosting",
        "DBSCAN",
        "Adaptive Baseline",
    )


# The ceiling every fused score is capped at. NAMED BECAUSE IT IS HALF OF AN INVARIANT (audit F186):
# `detection_confidence_factor` multiplies a capped score by `thin_window_floor`, so the reachable
# maximum for a thin window is THIS times that floor -- and a floor below base_threshold/this makes a
# whole category of windows unalertable. See `assert_thin_floor_is_reachable`.
MAX_FUSED_SCORE = 0.99


def fuse_scores(scores: dict[str, float], weights: dict[str, float] | None = None,
                mode: str = "max") -> float:
    """Ensemble fusion.

    RATIONALE (empirically established against live ClickHouse data):
    Each detector covers a different attack family — Isolation Forest finds
    novel traffic shapes, Gradient Boosting finds learned behavior patterns,
    DBSCAN finds density/port-diversity outliers (e.g. port scans), Adaptive
    Baseline finds per-host volume deviations. A confident specialist often
    fires ALONE: DBSCAN scored a seeded port scan at 0.99 while the
    volume-oriented models scored ~0.0 (correctly — a scan moves no bytes).

    The legacy mean-fusion averaged that 0.99 down to 0.405, BELOW benign
    hosts (0.543), so the scan went unalerted. Averaging silently means "no
    alert unless most models agree", which discards every attack family only
    one model can see.

    mode="max" (default): the reported score is the strongest detector signal.
      Per-detector weights are NOT applied here — scaling a confident detector
      down by weight (e.g. DBSCAN 0.65) re-introduces exactly the dilution this
      replaced. False-positive control lives in the agreement gate and severity
      tiers instead.
    mode="mean": legacy weighted average, retained for A/B comparison only.
    """
    if not scores:
        return 0.0
    if mode == "mean":
        w = weights or {}
        total = sum(w.get(n, 1.0) for n in scores)
        return float(min(MAX_FUSED_SCORE, sum(scores[n] * w.get(n, 1.0) for n in scores) / total))
    return float(min(MAX_FUSED_SCORE, max(scores.values())))


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
    scored strongly by DBSCAN (0.99) but weakly by the volume/shape models
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


def severity_of(score: float, agreement: float, strong_models: int = 0,
                signature: bool = False) -> str:
    """Severity tiers, gated on STRONG corroboration.

    `strong_models` = how many detectors scored >= STRONG_SIGNAL (0.85).

    Why this gate exists (measured on live ClickHouse data): the legacy
    agreement ratio counted any model above 0.20, so a window with ONE strong
    detector (GB 0.96) plus two weak ones (IF 0.70, DBSCAN 0.31) passed
    "agreement" and was reported as critical. Those windows were ordinary
    low-activity traffic — three benign hosts reached 'critical' that way.
    Genuine attacks showed two-or-more strongly-agreeing detectors (port scan:
    IF 0.87 + DBSCAN 0.99; exfil: all four >= 0.99).

    So 'high' and 'critical' require at least two strongly-agreeing detectors,
    OR one strong detector corroborated by a direct structural signature
    (see signature_corroboration) — the latter covers attack families that only
    one model can see, such as a zero-byte port scan.
    """
    corroborated = strong_models >= 2 or (strong_models >= 1 and signature)
    if score >= 0.95 and corroborated:
        return "critical"
    if score >= 0.85 and corroborated:
        return "high"
    if score >= 0.70 or (score >= 0.60 and strong_models >= 1):
        return "medium"
    return "low"


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
) -> list[dict[str, Any]]:
    """Run the full ensemble over recent aggregate flows; return verdict rows.

    Each verdict carries per-model scores, agreement, adaptive threshold used,
    explainability fields, and a severity — everything the alerting layer and
    ClickHouse row need.

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

    # Map detector display names to config weight keys (unknown detector
    # names fall back to weight 1.0 — a sweep must never crash on a name).
    NAME_TO_KEY = {
        "Isolation Forest": "isolation_forest",
        "Gradient Boosting": "gradient_boosting",
        "DBSCAN": "dbscan",
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
        )
        scores: dict[str, float] = {}
        for det in detectors:
            scores[det.name] = det.predict(flow, features)

        has_baseline = bool(baseline_det and src in baseline_det.baselines)
        # Weights are applied only in "mean" fusion mode (see fuse_scores).
        weights = dict(cfg.weights)
        if baseline_det is not None:
            weights["adaptive_baseline"] = cfg.weight_baseline if has_baseline else cfg.weight_baseline_missing

        final_score = fuse_scores(
            dict(scores),
            {n: _weight_of(n, weights) for n in scores},
            mode=cfg.fusion_mode,
        )

        # Damp statistically thin windows (see detection_confidence_factor)
        final_score = round(final_score * detection_confidence_factor(flow, cfg), 4)

        threshold = adaptive_threshold_for(flow, settings.base_threshold)
        if final_score < threshold:
            # NEAR MISS (band): scored close to the bar but under it. The band floor is
            # threshold * near_miss_band -- measured against the threshold this host faced,
            # not the global default, so a host with a raised adaptive bar does not flood
            # the table with its ordinary traffic.
            if near_misses is not None and final_score >= threshold * cfg.near_miss_band:
                near_misses.append({
                    "window_start": flow["window_start"],
                    "window_end": flow.get("window_end"),
                    "src_addr": src,
                    "anomaly_score": round(final_score, 4),
                    "threshold_used": round(threshold, 4),
                    "reason": "below-threshold",
                    "model_agreement": round(
                        len([n for n, s in scores.items() if s > 0.20])
                        / max(1, len(detectors)), 4),
                    "isolation_forest_score": round(scores.get("Isolation Forest", 0.0), 4),
                    "gradient_boosting_score": round(scores.get("Gradient Boosting", 0.0), 4),
                    "dbscan_score": round(scores.get("DBSCAN", 0.0), 4),
                    "baseline_score": round(scores.get("Adaptive Baseline", 0.0), 4),
                    "detected_by_models": ",".join(n for n, s in scores.items() if s > 0.20),
                })
            continue

        detected_by = [n for n, s in scores.items() if s > 0.20]
        # ── A MISSING DETECTOR MUST NOT LOOSEN THE GATE (audit F043) ─────────────────────────────
        #
        # This used to divide by the number of detectors that reported READY, so a detector that
        # failed to train removed itself from the denominator -- and agreement is a RATIO, so losing
        # detectors made it LARGER. MEASURED by driving the real ensemble with the same flow and the
        # same scores, varying only readiness:
        #
        #     all 4 ready (healthy)   score=0.550  agreement=0.25  -> SUPPRESSED
        #     DBSCAN failed to train  score=0.550  agreement=0.33  -> ALERT
        #     GB and DBSCAN failed    score=0.550  agreement=0.50  -> ALERT
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
        agreement = len(detected_by) / active

        # The agreement gate now reads settings.min_agreement (MIN_AGREEMENT)
        # instead of hardcoding the value.
        #
        # THE BUG: this line used to be `min_agreement = 0.33 if final_score < 0.6
        # else 0.25`, while config.py parsed and validated a MIN_AGREEMENT setting
        # that NOTHING read. So the setting was documented in the README table,
        # shipped in .env.example, and surfaced in `weirvern tune` — and changing
        # it did nothing at all, silently. An operator tuning it would see no
        # effect and have no way to tell whether the value was applied.
        #
        # The two-tier behaviour is preserved EXACTLY rather than approximated:
        # the original hardcoded pair was 0.33 / 0.25, a 0.08 offset, so the
        # high-score tier is `MIN_AGREEMENT - margin` (see the config comments for
        # why a multiplier would have shifted the default path by 0.0025). Raising
        # MIN_AGREEMENT now raises both tiers, and the floor keeps a silly value
        # from disabling the gate.
        min_agreement = (
            settings.min_agreement if final_score < 0.6
            else max(cfg.min_agreement_floor, settings.min_agreement - cfg.min_agreement_margin)
        )
        if agreement < min_agreement:
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
                    "threshold_used": round(threshold, 4),
                    "reason": "agreement-gate",
                    "model_agreement": round(agreement, 4),
                    "isolation_forest_score": round(scores.get("Isolation Forest", 0.0), 4),
                    "gradient_boosting_score": round(scores.get("Gradient Boosting", 0.0), 4),
                    "dbscan_score": round(scores.get("DBSCAN", 0.0), 4),
                    "baseline_score": round(scores.get("Adaptive Baseline", 0.0), 4),
                    "detected_by_models": ",".join(detected_by),
                })
            continue

        # Strong corroboration: how many detectors independently scored high.
        # Gates escalation to high/critical (see severity_of docstring).
        # The bar is the CONFIGURED one (STRONG_SIGNAL / Settings.strong_signal), which the
        # GUI and ConfigMap advertise as editable -- reading the constant here meant an
        # operator's edit validated and then changed nothing.
        bar = strong_signal_threshold(settings)
        strong_models = sum(1 for s in scores.values() if s >= bar)
        # Or a lone specialist backed by a direct structural signature.
        signature = signature_corroboration(flow, scores, flow.get("_diversity"), cfg,
                                            strong_signal=bar)

        results.append({
            "window_start": flow["window_start"],
            "window_end": flow.get("window_end"),
            "src_addr": src,
            "anomaly_score": round(final_score, 4),
            "confidence": round(final_score * agreement, 4),
            "isolation_forest_score": round(scores.get("Isolation Forest", 0.0), 4),
            "gradient_boosting_score": round(scores.get("Gradient Boosting", 0.0), 4),
            "dbscan_score": round(scores.get("DBSCAN", 0.0), 4),
            "baseline_score": round(scores.get("Adaptive Baseline", 0.0), 4),
            "model_agreement": round(agreement, 4),
            "detected_by_models": ",".join(detected_by),
            "severity": severity_of(final_score, agreement, strong_models, signature),
            "strong_models": strong_models,
            "signature": signature,
            "threshold_used": round(threshold, 4),
        })
    return results
