"""Ripple ensemble: calibrated, abstaining fusion of multi-scale evidence.

This is deliberately NOT another detector. It consumes evidence that already exists in the
shadow channels (flow, DNS, TLS, beacon, graph, temporal, change-point) and answers one question:

    is there enough independent, calibrated, fresh evidence to call this a ripple?

Design rules:
  * a missing or stale channel is UNKNOWN, never zero;
  * a family is one measurement, not one channel: two views of the same events cannot
    corroborate each other;
  * one family cannot make a ripple on its own except at the extreme bar (p <= 0.001);
  * one scale is an observation, not a ripple;
  * an empirical p-value at the baseline's resolution floor is a bound, not a result: a
    baseline too short to express the bar is reported as too short, never as significance;
  * the combined score is the joint surprise of the supporting families, and every result
    carries the evidence the operator needs to see why.

The page decision is separate. A `ripple` result is a candidate incident; `pageable` is policy.
"""
from __future__ import annotations

import math
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from weirvern.monitored import in_scope as _in_scope

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

#: A baseline shorter than this cannot support a decision at any scale. The number is a floor,
#: not a preference: see `pvalue_floor`, which is 1/(n+1). At 29 windows the smallest p the test
#: can express is 1/30 = 0.033; calling that "significant" is reading the test's resolution as a
#: result. Thirty windows is the minimum, and the per-scale map exists so a future scale with a
#: different cost can set its own floor instead of inheriting this one silently.
MIN_BASELINE_SAMPLES = 30
MIN_BASELINE_BY_SCALE: dict[str, int] = {scale: MIN_BASELINE_SAMPLES for scale in EVIDENCE_SCALES}

#: THE EMPIRICAL TEST'S RESOLUTION LIMIT, and the point at which the parametric tail takes over.
#: p = 1/(n+1) needs n >= `windows_for_bar()` = 100 to express a value below 0.01; below that a
#: rank-based p is a bound, not a measurement. The selection rule is explicit and one-way: use
#: the empirical p whenever n >= this, and the fitted tail only below it. `p_method` on every row
#: records which one produced the number.
EMPIRICAL_MIN_WINDOWS = 100

#: The `p_method` values a row can carry. 'empirical' is assumption-free; 'negbin'/'poisson' are
#: the fitted tail; 'insufficient' means the baseline could not support either and the row has no
#: p-value (never p=0, never p=1).
P_METHOD_EMPIRICAL = "empirical"
P_METHOD_NEGBIN = "negbin"
P_METHOD_POISSON = "poisson"
P_METHOD_INSUFFICIENT = "insufficient"
PARAMETRIC_METHODS = frozenset({P_METHOD_NEGBIN, P_METHOD_POISSON})
P_METHODS = frozenset({P_METHOD_EMPIRICAL, *PARAMETRIC_METHODS, P_METHOD_INSUFFICIENT})

#: THE NEW RIPPLE BAR. A family is significant at `DEFAULT_FAMILY_MAX_P`; two independent
#: families are required, or ONE family at `DEFAULT_EXTREME_P`. `DEFAULT_MIN_RIPPLE_SCORE` is
#: the joint-surprise bar: 3.0 is exactly one family at 0.001, and two families at 0.01 score
#: 4.0. Together the family rule and the score rule stop two barely-significant views of one
#: host from becoming a ripple.
DEFAULT_FAMILY_MAX_P = 0.01
DEFAULT_EXTREME_P = 0.001
DEFAULT_MIN_RIPPLE_SCORE = 3.0


#: THE CRITICALITY BANDS (2026-11-20). THE BAR THEY DESCRIBE IS THE RIPPLE BAR ABOVE:
#: two DISTINCT families at p <= `DEFAULT_FAMILY_MAX_P` (0.01), or ONE family at
#: `DEFAULT_EXTREME_P` (0.001), with `score = sum(-log10 p) >= DEFAULT_MIN_RIPPLE_SCORE` (3.0).
#: Every threshold below is that bar's own arithmetic, not a new number:
#:
#:   * two families at the family bar score 2 * -log10(0.01) = 4.0;
#:   * three families at the family bar score 3 * -log10(0.01) = 6.0, which is also two
#:     families at the extreme bar.
#:
#: So a single family that only just clears the 3.0 bar is LOW; the standard two-family ripple
#: is MEDIUM (as is one family whose own surprise reaches 4.0); three or more families, or a
#: score at/above 6.0, is HIGH. `severity_bands()` is the ONE definition; the API exposes its
#: return value and the page renders those numbers rather than restating them in JavaScript.
def severity_bands() -> dict[str, dict[str, Any]]:
    """The ripple bar as criticality bands, in the engine's own numbers.

    The returned table is serialised into `/api/ripples` as `severity_bands`; a UI that prints
    a threshold reads it from there. `bar` repeats the grouping constants so the legend can
    name the family p-value the bar uses without importing them into the browser.
    """
    family_score = -math.log10(DEFAULT_FAMILY_MAX_P)
    return {
        "low": {"min_score": DEFAULT_MIN_RIPPLE_SCORE, "min_families": 1},
        "medium": {"min_score": round(2 * family_score, 6),
                   "min_families": DEFAULT_MIN_FAMILIES},
        "high": {"min_score": round(3 * family_score, 6), "min_families": 3},
        "bar": {"family_max_p": DEFAULT_FAMILY_MAX_P,
                "extreme_p": DEFAULT_EXTREME_P,
                "min_score": DEFAULT_MIN_RIPPLE_SCORE,
                "min_families": DEFAULT_MIN_FAMILIES},
    }


def severity_band(score: float, families: Iterable[str] | None = None) -> str:
    """One band for one ripple, from `score` and the distinct `families` behind it.

    A row whose score is below the bar is LOW rather than decorated: the grouping contract
    should have refused it, and a display must not promote a number the engine would not.
    The band names match the console's existing severity classes (`sev-low`/`medium`/`high`).
    """
    bands = severity_bands()
    count = len(set(families or ()))
    try:
        value = float(score)
    except (TypeError, ValueError):
        return "low"
    if not math.isfinite(value) or value + 1e-9 < bands["low"]["min_score"]:
        return "low"
    if count >= bands["high"]["min_families"] or value + 1e-9 >= bands["high"]["min_score"]:
        return "high"
    if count >= bands["medium"]["min_families"] or value + 1e-9 >= bands["medium"]["min_score"]:
        return "medium"
    return "low"


#: CHANNEL -> FAMILY. A family is ONE collection pipeline observing ONE population of events.
#: `flow_bytes` and `flow_volume` are the byte sum and the row count of the SAME flow records;
#: they are two units for one measurement, so they can never corroborate each other. The same
#: rule collapses the other views of a pipeline (conn_volume / conn_dst_diversity /
#: conn_service_diversity / conn_reset_ratio, all `conn`; the DNS views, all `dns`; the identity
#: views, all `identity`). Different pipelines (flow vs conn vs dns vs identity) are separate
#: families: they are collected by different code paths, can disagree because of sampling or
#: visibility, and therefore carry information the other does not.
#:
#: THE FOUR LATER FAMILIES ARE INDEPENDENT, NOT MORE VIEWS (2026-11-19). The operator asked
#: "do we need more channels? we have lots of data", and the answer is only where the new
#: channel observes something the existing four cannot:
#:
#:   tls    the TLS handshake itself: the SNI the client asked for and the JA4 fingerprint it
#:          offered. flow/conn see that a connection happened and how big it was; dns sees the
#:          name that was resolved BEFORE it. Neither sees what the client offered on the wire,
#:          so a new client stack reusing the same DNS answer and the same flow profile is
#:          invisible to all four existing families and visible here.
#:   http   application request metadata: the Host header and the User-Agent. conn sees the TCP
#:          connection, not the request on it; dns sees the resolution, not the request. A host
#:          that keeps its connections and its DNS exactly as they were but starts sending a
#:          user-agent it has never sent is a change only this family can report.
#:   ssh    the SSH banner exchange (client/server version pair). conn counts the session and
#:          its bytes; it does not parse the banner, so an upgraded SSH client on a host whose
#:          connection volume is unchanged moves this family and no other.
#:   notice Zeek's OWN CONCLUSIONS (`notice` and `weird`), not a protocol observation. This is
#:          the only family produced by an analyst (Zeek's scripts) rather than by a parser, and
#:          its population is sensor findings rather than traffic; no flow/conn/dns/identity
#:          channel can corroborate a notice because none of them emit one.
#:
#: WITHIN a new family the same one-measurement rule applies: http_host_diversity and
#: http_ua_novelty are two fields of the SAME zeek_http request, and zeek_notice_volume and
#: zeek_weird_volume are two outputs of the same Zeek finding pipeline, so neither pair may
#: corroborate itself.
CHANNEL_FAMILIES: dict[str, str] = {
    "flow_volume": "flow",
    "flow_bytes": "flow",
    "flow_dst_diversity": "flow",
    # The destination END of the same flow records: one family, because inbound and outbound
    # volume are two views of one measurement and must never corroborate each other.
    "flow_in_volume": "flow",
    "flow_in_bytes": "flow",
    "flow_in_peer_diversity": "flow",
    "conn_volume": "conn",
    "conn_dst_diversity": "conn",
    "conn_service_diversity": "conn",
    "conn_reset_ratio": "conn",
    "dns_volume": "dns",
    "dns_query_diversity": "dns",
    "dns_nxdomain_ratio": "dns",
    "dns_reverse_ratio": "dns",
    "kerberos_volume": "identity",
    "kerberos_service_diversity": "identity",
    "ntlm_volume": "identity",
    "ntlm_user_diversity": "identity",
    "smb_file_volume": "identity",
    "smb_path_diversity": "identity",
    # ── the four independent families added 2026-11-19 ─────────────────────────────────────
    "tls_fingerprint_diversity": "tls",
    "http_host_diversity": "http",
    "http_ua_novelty": "http",
    "ssh_version_change": "ssh",
    "zeek_notice_volume": "notice",
    "zeek_weird_volume": "notice",
}


def channel_family(channel: str, family: str = "") -> str:
    """The family a channel belongs to, with the map winning over a stale stored label.

    A stored row written before this map existed still has a family, and the map is what makes
    `flow_bytes` and `flow_volume` one measurement. Unknown channels keep their own family so a
    new source is never silently folded into an existing one.
    """
    return CHANNEL_FAMILIES.get(channel) or family or channel


def pvalue_floor(sample_count: int) -> float:
    """The smallest two-sided empirical p-value `sample_count` baseline windows can express.

    p = (1 + #{at least as extreme}) / (n + 1), so the floor is 1/(n+1). At n=20 the floor is
    0.0476: the test is saying "this is the most extreme value I can represent", not "p is
    about five percent". A caller that wants to claim p <= alpha needs a floor below alpha;
    `baseline_short` is how a row says it cannot.
    """
    n = max(0, int(sample_count))
    return 1.0 / (n + 1)


def min_baseline_samples(scale: str) -> int:
    """The per-scale baseline minimum. Thirty everywhere today, tunable per scale tomorrow."""
    return MIN_BASELINE_BY_SCALE.get(scale, MIN_BASELINE_SAMPLES)


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
    #: THE TEST'S OWN RESOLUTION. `p_floor = 1/(sample_count+1)` is the smallest two-sided
    #: empirical p this row could have produced. `baseline_short` says the sample count is below
    #: the per-scale minimum, so the row is a measurement but cannot support a ripple decision.
    p_floor: float = float("nan")
    baseline_short: bool = False
    #: WHICH TEST PRODUCED `pvalue`. 'empirical' (rank-based, n >= 100), 'negbin' or 'poisson'
    #: (the fitted tail, n < 100), or 'insufficient' (no p-value exists; `pvalue` is NaN).
    #: Defaulting to 'empirical' keeps every pre-existing construction honest: before the tail
    #: existed, every row was empirical by construction.
    p_method: str = P_METHOD_EMPIRICAL
    #: The fitted parameters, as text, for a parametric row (empty otherwise). A reader can see
    #: the mean, variance, dispersion index and size that produced the p without a second query.
    p_detail: str = ""

    def floor(self) -> float:
        """The attainable floor, computed from the row when the writer did not carry it."""
        if math.isfinite(float(self.p_floor)) and self.p_floor > 0.0:
            return float(self.p_floor)
        return pvalue_floor(self.sample_count)

    def at_floor(self) -> bool:
        """True when the measurement sits at the EMPIRICAL baseline's resolution limit.

        A parametric row's p is not a rank and has no such limit, so it is never "at the floor"
        even when it is small. The empirical 1/(n+1) bound is still reported in `p_floor` for
        every row, so a reader can compare the two resolutions.
        """
        if self.p_method in PARAMETRIC_METHODS:
            return False
        if not math.isfinite(float(self.pvalue)):
            return False
        floor = self.floor()
        return floor > 0.0 and float(self.pvalue) <= floor * (1.0 + 1e-9)

    def resolves(self, alpha: float) -> bool:
        """Whether this row's test can express a p-value strictly below `alpha`.

        The fitted tail can, down to `ripple_tail.TAIL_P_FLOOR` (1e-6); the empirical test can
        only when its 1/(n+1) floor is below alpha. An 'insufficient' row cannot at all.
        """
        if self.p_method in PARAMETRIC_METHODS:
            return True
        if self.p_method == P_METHOD_INSUFFICIENT:
            return False
        return self.floor() < float(alpha)

    def as_dict(self) -> dict[str, Any]:
        """The shape the API and the Models card read. `p_value` is spelled out here."""
        return {
            "channel": self.channel,
            "family": channel_family(self.channel, self.family),
            "scale": self.scale,
            "model_id": self.model_id,
            "value": _round(self.value),
            "baseline_median": _round(self.baseline_median),
            "p_value": _round(self.pvalue, 8),
            "p_floor": _round(self.floor(), 8),
            "p_method": self.p_method,
            "p_detail": self.p_detail,
            "at_floor": self.at_floor(),
            "baseline_short": bool(self.baseline_short),
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

    WHAT THE SCORE IS, EXACTLY. `score = sum(-log10(p))` over one p-value per significant
    FAMILY: the joint surprise of the independent measurements, i.e. `-log10(product p)`.
    Two families at 0.01 score 4.0; one family at exactly 0.001 scores 3.0. Only the strongest
    member of each family contributes, so `flow_bytes` and `flow_volume` cannot add a second
    p-value for one set of flow records. `combined_p` is Fisher's calibrated combination of the
    same p-values and is reported alongside; the score is the ranking/bar quantity, not a
    probability, and this pass never pages on it.
    """

    host: str
    window_start: datetime
    window_end: datetime
    score: float
    combined_p: float
    channels: tuple[str, ...]
    explanation: str
    families: tuple[str, ...] = ()
    single_family: bool = False
    evidence: tuple[ChannelEvidence, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "window_start": self.window_start.isoformat(),
            "window_end": self.window_end.isoformat(),
            "score": round(float(self.score), 4),
            "combined_p": round(float(self.combined_p), 8),
            "channels": list(self.channels),
            "families": list(self.families),
            "single_family": self.single_family,
            "severity": severity_band(self.score, self.families),
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


def _explain(host: str, window_start: datetime, chosen: list[ChannelEvidence],
             families: tuple[str, ...], single_family: bool) -> str:
    """One sentence naming the subject, the family, and what each family measured.

    The rule is deliberate: a value without its own median is a number, not evidence, and a
    p-value without the family and the baseline behind it is exactly the bare 0.05 this layer
    exists to stop printing. Every clause therefore reads "<family> family: <channel> <value>
    vs median <baseline> (<direction> at <scale>, p=... over N baseline windows)". When the
    p-value is the attainable floor it is printed as a bound with the floor named, never as if
    it were a measured probability.
    """
    parts = []
    for item in sorted(chosen, key=lambda e: (e.pvalue, e.channel)):
        family = channel_family(item.channel, item.family)
        if item.p_method in PARAMETRIC_METHODS:
            # THE FITTED TAIL IS NAMED. A reader must be able to tell a modelled p from a rank,
            # and the model's parameters ride in the row (`p_detail`) for the sheet.
            p_text = (f"p={item.pvalue:.3g} from a {item.p_method} tail over "
                      f"{item.sample_count} baseline windows")
        elif item.at_floor():
            p_text = (f"p<={item.pvalue:.3g}, the floor for {item.sample_count} baseline "
                      f"windows")
        else:
            p_text = f"p={item.pvalue:.3g} over {item.sample_count} baseline windows"
        parts.append(
            f"{family} family: {item.channel} {_fmt(item.value)} vs median "
            f"{_fmt(item.baseline_median)} ({item.direction or 'changed'} at {item.scale}; "
            f"{p_text})"
        )
    if single_family:
        lead = (f"ripple on {host} at {window_start:%Y-%m-%d %H:%M} UTC — single family "
                f"{families[0]} at the extreme bar, not cross-family corroboration")
    else:
        lead = (f"ripple on {host} at {window_start:%Y-%m-%d %H:%M} UTC — "
                f"{len(families)} independent families: {', '.join(families)}")
    return lead + ": " + "; ".join(parts) + "."


def _usable(item: ChannelEvidence, *, max_p: float) -> bool:
    """Whether a row is allowed to support a ripple at all.

    THREE REFUSALS, ALL LOUD IN THE DATA. Too few baseline windows is a short baseline. A
    non-finite p-value is an insufficient (or failed) fit, and must never be read as quiet. A
    row whose p-value is at the EMPIRICAL floor when the floor is not below `max_p` cannot claim
    `max_p`; the test is out of resolution. A parametric row is not subject to the last refusal:
    its p is a fitted tail, not a rank, and `resolves()` says so. The bar itself is unchanged.
    """
    if item.baseline_short or item.sample_count < min_baseline_samples(item.scale):
        return False
    if not math.isfinite(item.pvalue) or not 0.0 < item.pvalue <= 1.0:
        return False
    if item.p_method == P_METHOD_INSUFFICIENT:
        return False
    return not (item.p_method == P_METHOD_EMPIRICAL and item.at_floor()
                and not item.resolves(max_p))


def group_evidence(
    evidence: list[ChannelEvidence],
    *,
    window_s: int = RIPPLE_WINDOW_S,
    max_p: float = DEFAULT_FAMILY_MAX_P,
    extreme_p: float = DEFAULT_EXTREME_P,
    min_families: int = DEFAULT_MIN_FAMILIES,
    min_score: float = DEFAULT_MIN_RIPPLE_SCORE,
    monitored: Iterable[Any] = (),
) -> list[Ripple]:
    """Group one host's evidence in one time window into ripples, newest window first.

    THE TWO WAYS A RIPPLE FORMS (phase 1):
      (a) two or more distinct FAMILIES are significant (p <= `max_p`) in the same window; or
      (b) exactly one family is significant at the extreme bar (p <= `extreme_p`).
    In both cases `score >= min_score` after the multiple-test guard.

    A FAMILY IS ONE MEASUREMENT. Only the strongest member of each family is allowed to support
    a ripple, so `flow_bytes` and `flow_volume` -- the byte sum and the row count of the same
    flow records -- cannot add up to two pieces of evidence. When a ripple is formed by one
    family under rule (b), the explanation says so; it is one signal at an extreme bar, not
    independent corroboration.

    ONLY MONITORED SUBJECTS. `monitored` is the operator's monitored-network list. A host
    outside it is a peer, not an asset, and is never the subject of a ripple. An empty list is
    not a licence: it produces no ripples rather than treating every address as ours.

    A ripple is not a verdict about an attack and this function never pages. It is the unit an
    operator reads: several measurements that moved together, named, with the history each was
    measured against.
    """
    nets = tuple(monitored)
    if not nets:
        return []
    buckets: dict[tuple[str, datetime], list[ChannelEvidence]] = {}
    for item in evidence:
        if not item.host or item.observed_at is None or not item.present:
            continue
        if not _in_scope(item.host, list(nets)):
            continue
        buckets.setdefault((item.host, _window_start(item.observed_at, window_s)),
                           []).append(item)

    out: list[Ripple] = []
    for (host, start), items in buckets.items():
        # ONE VIEW PER FAMILY: keep each family's strongest member, so two views of one
        # measurement cannot vote twice and a channel measured at three scales cannot vote
        # three times for itself.
        strongest: dict[str, ChannelEvidence] = {}
        for item in items:
            if not _usable(item, max_p=max_p):
                continue
            family = channel_family(item.channel, item.family)
            held = strongest.get(family)
            if held is None or (item.pvalue, item.channel) < (held.pvalue, held.channel):
                strongest[family] = item
        significant = [item for item in strongest.values() if item.pvalue <= max_p]
        alone = len(significant) == 1 and significant[0].pvalue <= extreme_p
        if len(significant) < min_families and not alone:
            continue

        # SCORE IS THE JOINT SURPRISE OF THE SUPPORTING FAMILIES: the sum of -log10(p), which
        # is -log10(product of the p-values). Two independent families at 0.01 score 4.0; one
        # family at exactly 0.001 scores 3.0. Fisher's calibrated p is still reported as
        # `combined_p`, but the score is deliberately the evidence product: a multiplicity
        # multiplier on top of the family rule would make the stated 0.001 boundary
        # unreachable whenever another family happened to be measured and quiet.
        combined = fisher_combined_p([item.pvalue for item in significant])
        score = sum(-math.log10(max(item.pvalue, 1e-12)) for item in significant)
        if score + 1e-9 < min_score:
            continue
        chosen = sorted(significant, key=lambda e: (e.pvalue, e.channel))
        families = tuple(sorted({channel_family(item.channel, item.family)
                                 for item in significant}))
        out.append(Ripple(
            host=host,
            window_start=start,
            window_end=start + timedelta(seconds=int(window_s)),
            score=score,
            combined_p=combined,
            channels=tuple(item.channel for item in chosen),
            explanation=_explain(host, start, chosen, families, alone),
            families=families,
            single_family=alone,
            evidence=tuple(chosen),
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


__all__ = ["CHANNEL_FAMILIES", "ChannelEvidence", "DEFAULT_EXTREME_P", "DEFAULT_FAMILY_MAX_P",
           "DEFAULT_MAX_FRESHNESS_S", "DEFAULT_MAX_P", "DEFAULT_MIN_RIPPLE_SCORE",
           "EMPIRICAL_MIN_WINDOWS", "EVIDENCE_SCALES", "EVIDENCE_SCALE_SECONDS",
           "MIN_BASELINE_BY_SCALE", "MIN_BASELINE_SAMPLES", "PARAMETRIC_METHODS", "P_METHODS",
           "P_METHOD_EMPIRICAL", "P_METHOD_INSUFFICIENT", "P_METHOD_NEGBIN", "P_METHOD_POISSON",
           "RIPPLE_WINDOW_S", "Ripple", "RippleResult", "SCALES", "channel_family",
           "empirical_pvalue", "empirical_pvalue_two_sided", "evidence_from_shadow",
           "fisher_combined_p", "fuse", "group_evidence", "min_baseline_samples", "pvalue_floor",
           "severity_band", "severity_bands"]
