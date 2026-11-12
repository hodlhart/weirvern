"""Ripple ensemble: calibrated, abstaining fusion of multi-scale evidence.

This is deliberately NOT another detector. It consumes evidence that already exists in the
shadow channels (flow, DNS, TLS, beacon, graph, temporal, change-point) and answers one question:

    is there enough independent, calibrated, fresh evidence to call this a ripple?

Design rules:
  * a missing or stale channel is UNKNOWN, never zero;
  * one family cannot make a ripple on its own;
  * one scale is an observation, not a ripple;
  * the combined p-value is Fisher's, with a Bonferroni guard for the number of channels;
  * every result carries the evidence the operator needs to see why.

The page decision is separate. A `ripple` result is a candidate incident; `pageable` is policy.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any

SCALES = ("5m", "1h", "24h")
DEFAULT_MAX_P = 0.05
DEFAULT_MAX_FRESHNESS_S = 900
DEFAULT_MIN_FAMILIES = 2
DEFAULT_MIN_SCALES = 2


@dataclass(frozen=True)
class ChannelEvidence:
    channel: str
    family: str
    scale: str
    model_id: str
    model_version: str
    score: float
    pvalue: float
    freshness_s: float
    present: bool = True

    def valid(self, *, max_freshness_s: float = DEFAULT_MAX_FRESHNESS_S) -> bool:
        return (
            self.present
            and self.scale in SCALES
            and math.isfinite(self.pvalue)
            and 0.0 < self.pvalue <= 1.0
            and math.isfinite(self.freshness_s)
            and 0.0 <= self.freshness_s <= max_freshness_s
        )


@dataclass
class RippleResult:
    status: str
    reason: str
    confidence: float
    combined_p: float
    families: list[str] = field(default_factory=list)
    scales: list[str] = field(default_factory=list)
    contributors: list[dict[str, Any]] = field(default_factory=list)
    unknown: list[dict[str, str]] = field(default_factory=list)
    pageable: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "reason": self.reason,
            "confidence": round(self.confidence, 6),
            "combined_p": round(self.combined_p, 6),
            "families": self.families,
            "scales": self.scales,
            "contributors": self.contributors,
            "unknown": self.unknown,
            "pageable": self.pageable,
        }


def fisher_combined_p(pvalues: list[float]) -> float:
    """Fisher's method; small p means the channels agree that something is unusual."""
    clean = [float(p) for p in pvalues if math.isfinite(float(p)) and 0.0 < float(p) <= 1.0]
    if not clean:
        return 1.0
    statistic = -2.0 * sum(math.log(p) for p in clean)
    # Survival function of chi-square with 2k degrees of freedom (k channels).
    k = len(clean)
    half = statistic / 2.0
    term = 1.0
    total = 1.0
    for i in range(1, k):
        term *= half / i
        total += term
    return float(min(1.0, math.exp(-half) * total))


def fuse(
    channels: list[ChannelEvidence],
    *,
    max_p: float = DEFAULT_MAX_P,
    max_freshness_s: float = DEFAULT_MAX_FRESHNESS_S,
    min_families: int = DEFAULT_MIN_FAMILIES,
    min_scales: int = DEFAULT_MIN_SCALES,
    pageable: bool = False,
) -> RippleResult:
    """Fuse channel evidence into a ripple candidate, observation or unknown.

    `unknown` is returned when no valid channel exists. Channels that are present but stale are
    named in `unknown`, so the result never turns a dead feed into a quiet zero.
    """
    unknown: list[dict[str, str]] = []
    valid: list[ChannelEvidence] = []
    for ch in channels:
        if ch.valid(max_freshness_s=max_freshness_s):
            valid.append(ch)
            continue
        # THE REASON NAMES THE ACTUAL DEFECT. This used to check the p-value first, so a
        # channel that was simply absent (present=False, pvalue=nan) was reported as
        # "no p-value" -- which reads like a broken model rather than a feed that never
        # reported. The distinction is the whole point of the unknown contract.
        if not ch.present:
            reason = "missing"
        elif not math.isfinite(ch.pvalue):
            reason = "no p-value"
        else:
            reason = "stale"
        unknown.append({"channel": ch.channel, "family": ch.family, "reason": reason})

    if not valid:
        return RippleResult(
            status="unknown", reason="no fresh calibrated channel", confidence=0.0,
            combined_p=1.0, unknown=unknown,
        )

    # Conservative family-wise guard: many channels should not manufacture significance.
    raw_p = fisher_combined_p([ch.pvalue for ch in valid])
    combined_p = min(1.0, raw_p * max(1, len(valid)))
    families = sorted({ch.family for ch in valid})
    scales = sorted({ch.scale for ch in valid}, key=SCALES.index)
    contributors = [
        {"channel": ch.channel, "family": ch.family, "scale": ch.scale,
         "model_id": ch.model_id, "model_version": ch.model_version,
         "score": round(float(ch.score), 6), "pvalue": round(float(ch.pvalue), 6)}
        for ch in sorted(valid, key=lambda c: c.pvalue)
    ]

    if combined_p > max_p:
        return RippleResult("observation", "combined evidence does not clear the ripple bar",
                            confidence=1.0 - combined_p, combined_p=combined_p,
                            families=families, scales=scales, contributors=contributors,
                            unknown=unknown)
    if len(families) < min_families:
        return RippleResult("observation", "one family cannot make a ripple",
                            confidence=1.0 - combined_p, combined_p=combined_p,
                            families=families, scales=scales, contributors=contributors,
                            unknown=unknown)
    if len(scales) < min_scales:
        return RippleResult("observation", "one scale is a burst, not a ripple",
                            confidence=1.0 - combined_p, combined_p=combined_p,
                            families=families, scales=scales, contributors=contributors,
                            unknown=unknown)

    return RippleResult("ripple", "independent calibrated evidence across families and scales",
                        confidence=1.0 - combined_p, combined_p=combined_p,
                        families=families, scales=scales, contributors=contributors,
                        unknown=unknown, pageable=pageable)


def empirical_pvalue(score: float, reference: list[float]) -> float:
    """Rank-based p-value: no distribution assumption, and an empty reference is not zero."""
    ref = [float(x) for x in reference if math.isfinite(float(x))]
    if not ref:
        return float("nan")
    return float((1 + sum(1 for x in ref if x >= float(score))) / (len(ref) + 1))


def evidence_from_shadow(
    rows: list[dict[str, Any]],
    *,
    reference_by_model: dict[str, list[float]],
    family_by_model: dict[str, str] | None = None,
    scale_by_model: dict[str, str] | None = None,
) -> list[ChannelEvidence]:
    """Turn shadow rows (model_name, score, computed_at, freshness_s) into channel evidence.

    The p-value is empirical against that model's own reference population, not a raw score.
    A model with no reference is skipped rather than given a fabricated p-value.
    """
    out: list[ChannelEvidence] = []
    for row in rows:
        model = str(row.get("model_name") or row.get("channel") or "")
        ref = reference_by_model.get(model) or []
        p = empirical_pvalue(float(row.get("score") or 0.0), ref)
        if not math.isfinite(p):
            continue
        out.append(ChannelEvidence(
            channel=str(row.get("channel") or model),
            family=str((family_by_model or {}).get(model) or row.get("family") or model),
            scale=str((scale_by_model or {}).get(model) or row.get("scale") or "5m"),
            model_id=model,
            model_version=str(row.get("model_version") or "unknown"),
            score=float(row.get("score") or 0.0),
            pvalue=p,
            freshness_s=float(row.get("freshness_s") or 0.0),
            present=bool(row.get("present", True)),
        ))
    return out


__all__ = ["ChannelEvidence", "DEFAULT_MAX_FRESHNESS_S", "DEFAULT_MAX_P", "RippleResult",
           "SCALES", "empirical_pvalue", "evidence_from_shadow", "fisher_combined_p", "fuse"]
