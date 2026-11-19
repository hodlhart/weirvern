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
from datetime import UTC, datetime, timedelta
from typing import Any

SCALES = ("5m", "1h", "24h")
DEFAULT_MAX_P = 0.05
DEFAULT_MAX_FRESHNESS_S = 900
DEFAULT_MIN_FAMILIES = 2
DEFAULT_MIN_SCALES = 2

# ── the multi-scale evidence layer (phase 1) ────────────────────────────────────────────────
#
# A ripple here is a small, statistically significant change in one channel for one host,
# measured against that host's OWN trailing history. The scales below are the lengths of the
# window being compared; `7d` is declared because the algorithm supports it, but it produces
# no evidence at this deployment's retention (see ripple_evidence.SCALE_SECONDS and the
# inventory in that module). Declaring it is honest; inventing a baseline for it would not be.
EVIDENCE_SCALES = ("1h", "6h", "24h", "7d")
EVIDENCE_SCALE_SECONDS = {"1h": 3600, "6h": 21600, "24h": 86400, "7d": 604800}

#: One grouping window for phase 1. Evidence from one hour is one ripple candidate.
RIPPLE_WINDOW_S = 3600

#: A single channel must be this extreme to stand alone. Two channels only need `max_p`.
DEFAULT_EXTREME_P = 0.01


def _round(value: float, digits: int = 6) -> float | None:
    """JSON has no NaN: a measurement that was not taken is reported as null, not a number."""
    return round(float(value), digits) if math.isfinite(float(value)) else None


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
    # ── phase-1 measurement, all optional so the shadow path constructs this unchanged ──────
    #: The host and the instant the measurement ended. The fusion path keys by host in a dict
    #: and did not need these; a stored evidence row does, and a ripple groups on them.
    host: str = ""
    observed_at: datetime | None = None
    #: The statistic itself and the host's baseline median it was ranked against. Both are
    #: carried because an explanation that states a number without its baseline is not evidence.
    value: float = float("nan")
    baseline_median: float = float("nan")
    sample_count: int = 0
    coverage: float = 0.0
    direction: str = ""

    def as_dict(self) -> dict[str, Any]:
        """The shape the API and the Models card read. `p_value` is spelled out here."""
        return {
            "channel": self.channel,
            "family": self.family,
            "scale": self.scale,
            "model_id": self.model_id,
            "value": _round(self.value),
            "baseline_median": _round(self.baseline_median),
            "p_value": _round(self.pvalue, 8),
            "sample_count": int(self.sample_count),
            "coverage": _round(self.coverage, 4),
            "direction": self.direction,
            "observed_at": self.observed_at.isoformat() if self.observed_at else "",
        }

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


def empirical_pvalue_two_sided(score: float, reference: list[float]) -> float:
    """The share of the host's own history that is at least as far from normal as this value.

    ONE-SIDED WOULD MISS HALF THE SIGNAL. A host going quiet is a change: a DNS channel that
    falls to zero because malware switched to DoH, or a connection count that collapses while a
    beacon moves to a different protocol, are exactly what an operator needs to see. So both
    tails are measured and the smaller one is reported -- the standard empirical two-sided
    p-value. It is conservative for small references by construction (the +1 in each tail), and
    an empty reference returns NaN rather than a fabricated 1.0.
    """
    ref = [float(x) for x in reference if math.isfinite(float(x))]
    if not ref:
        return float("nan")
    n = len(ref)
    upper = (1 + sum(1 for x in ref if x >= float(score))) / (n + 1)
    lower = (1 + sum(1 for x in ref if x <= float(score))) / (n + 1)
    return float(min(1.0, min(upper, lower)))


@dataclass(frozen=True)
class Ripple:
    """One host, one window, and the evidence that lined up inside it.

    WHAT THE SCORE IS, EXACTLY. `score = -log10(corrected_p)` where

        corrected_p = min(1, Fisher(one p per significant channel) * tests_in_window)

    and `tests_in_window` is the number of DISTINCT channels measured for that host in that
    window (not the number of scales: one channel measured at three scales is one view, and
    counting it three times is how a single signal would manufacture corroboration). Fisher is
    applied to each channel's strongest scale. Higher score = stronger combined evidence; 2.0
    means "about one in a hundred after the guard". The score is a ranking aid, not a
    probability, and this pass never pages on it.
    """

    host: str
    window_start: datetime
    window_end: datetime
    score: float
    combined_p: float
    channels: tuple[str, ...]
    explanation: str
    evidence: tuple[ChannelEvidence, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "window_start": self.window_start.isoformat(),
            "window_end": self.window_end.isoformat(),
            "score": round(float(self.score), 4),
            "combined_p": round(float(self.combined_p), 8),
            "channels": list(self.channels),
            "explanation": self.explanation,
            "evidence": [item.as_dict() for item in self.evidence],
        }


def _window_start(moment: datetime, window_s: int) -> datetime:
    """Floor an instant to its grouping window, in UTC, without relying on local time."""
    aware = moment.replace(tzinfo=UTC) if moment.tzinfo is None else moment.astimezone(UTC)
    epoch = int(aware.timestamp())
    return datetime.fromtimestamp((epoch // window_s) * window_s, tz=UTC)


def _fmt(value: float) -> str:
    """A number a person can read: no exponent for ordinary counts, three digits otherwise."""
    if not math.isfinite(float(value)):
        return "not measured"
    if abs(float(value)) >= 1000:
        return f"{float(value):,.0f}"
    return f"{float(value):.4g}"


def _explain(host: str, window_start: datetime, chosen: list[ChannelEvidence]) -> str:
    """One sentence naming every channel that moved, each with the baseline it moved from.

    The rule is deliberate: a value without its own median is a number, not evidence. Every
    clause therefore reads "<channel> <value> vs median <baseline> (p=..., <direction> at
    <scale>)", and the sentence never ends in a bare score.
    """
    parts = []
    for item in sorted(chosen, key=lambda e: (e.pvalue, e.channel)):
        parts.append(
            f"{item.channel} {_fmt(item.value)} vs median {_fmt(item.baseline_median)} "
            f"(p={item.pvalue:.3g}, {item.direction or 'changed'} at {item.scale})"
        )
    return f"ripple on {host} at {window_start:%Y-%m-%d %H:%M} UTC: " + "; ".join(parts) + "."


def group_evidence(
    evidence: list[ChannelEvidence],
    *,
    window_s: int = RIPPLE_WINDOW_S,
    max_p: float = DEFAULT_MAX_P,
    extreme_p: float = DEFAULT_EXTREME_P,
    min_channels: int = 2,
) -> list[Ripple]:
    """Group one host's evidence in one time window into ripples, newest window first.

    THE TWO WAYS A RIPPLE FORMS (phase 1):
      (a) two or more distinct channels are significant (p <= `max_p`) in the same window; or
      (b) one channel is significant at an extreme p (p <= `extreme_p`).

    A ripple is not a verdict about an attack and this function never pages. It is the unit an
    operator reads: several measurements that moved together, named, with the history each was
    measured against.
    """
    buckets: dict[tuple[str, datetime], list[ChannelEvidence]] = {}
    for item in evidence:
        if not item.host or item.observed_at is None or not item.present:
            continue
        if not math.isfinite(item.pvalue) or not 0.0 < item.pvalue <= 1.0:
            continue
        buckets.setdefault((item.host, _window_start(item.observed_at, window_s)),
                           []).append(item)

    out: list[Ripple] = []
    for (host, start), items in buckets.items():
        # ONE VIEW PER CHANNEL: keep each channel's strongest scale, so a channel measured at
        # three scales cannot vote three times for itself.
        strongest: dict[str, ChannelEvidence] = {}
        for item in items:
            held = strongest.get(item.channel)
            if held is None or item.pvalue < held.pvalue:
                strongest[item.channel] = item
        significant = [item for item in strongest.values() if item.pvalue <= max_p]
        alone = len(significant) == 1 and significant[0].pvalue <= extreme_p
        if len(significant) < min_channels and not alone:
            continue

        combined = fisher_combined_p([item.pvalue for item in significant])
        # THE GUARD: every channel measured in this window is a test that was run, not only the
        # ones that came out significant. Without it, a host with fifty channels would produce
        # a "ripple" from noise alone on a long enough timeline.
        corrected = min(1.0, combined * max(1, len(strongest)))
        score = -math.log10(max(corrected, 1e-12))
        contributors = tuple(sorted(
            (item for item in items if item.channel in {s.channel for s in significant}),
            key=lambda e: (e.pvalue, e.channel, e.scale)))
        out.append(Ripple(
            host=host,
            window_start=start,
            window_end=start + timedelta(seconds=int(window_s)),
            score=score,
            combined_p=corrected,
            channels=tuple(sorted({item.channel for item in significant})),
            explanation=_explain(host, start, significant),
            evidence=contributors,
        ))
    out.sort(key=lambda r: (r.window_start, r.host), reverse=True)
    return out


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


__all__ = ["ChannelEvidence", "DEFAULT_EXTREME_P", "DEFAULT_MAX_FRESHNESS_S", "DEFAULT_MAX_P",
           "EVIDENCE_SCALES", "EVIDENCE_SCALE_SECONDS", "RIPPLE_WINDOW_S", "Ripple",
           "RippleResult", "SCALES", "empirical_pvalue", "empirical_pvalue_two_sided",
           "evidence_from_shadow", "fisher_combined_p", "fuse", "group_evidence"]
