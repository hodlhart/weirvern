"""Which detectors may set the fused score: measured evidence first, then a measured budget.

WHY THIS MODULE EXISTS. Eligibility used to be answered twice from `ml_model_cards`: the engine's
gate (`calibration.eligibility`) and the Detectors table both consulted a hand-curated registry.
That registry is written only when somebody edits a card, so it goes stale the moment the engine
retrains -- and on 2026-11-20 it had no row at all for the two detectors that had just shipped,
which barred them from the fused score by ABSENCE. A card is a statement of intent (owner, approved
version, rollback); it is not a measurement, and it must not be able to veto a working detector.

THE EVIDENCE RULE. A detector is ELIGIBLE when all three hold, each measured by the engine:

  1. FRESH -- its newest calibration row is no older than the retrain interval (plus the calibration
     grace, because the calibration pass runs after the retrain that produced the artifact; a strict
     boundary would blink every detector out for the minutes between the two).
  2. COVERED -- that row recorded `coverage_observed` and `coverage_expected`. NULL means coverage
     was never measured, and an unmeasured vector is not evidence about the detector.
  3. IN BUDGET -- its realised FAR is within `target_far * ML_ELIGIBILITY_MULTIPLE`, which is the
     tolerance the deployment configures, not one this module chooses. The comparison is made on
     the WILSON UPPER BOUND at 95%, never on the point estimate, and only once the validation
     sample is large enough to answer the question.

WHY THE INTERVAL AND THE MINIMUM SAMPLE. A realised FAR is a binomial proportion: 5 exceedances in
110 validation windows is 0.045, but its 95% interval is roughly 0.020-0.102 -- the same reading is
compatible with a 2% detector and a 10% one, and it cannot separate the 1% target from the 3%
tolerance. Measured live on 2026-11-20: the SAME detector read 0.000 seven minutes before it read
0.045, and the point estimate benched the whole layer. So a sample below
`ML_ELIGIBILITY_MIN_WINDOWS` (300: the smallest n at which a detector realising the 1% target has
an upper bound of 2.9%, inside the 3% tolerance) cannot fail a detector at all -- the state is
`calibrating (n=X, need Y)` and the detector keeps whatever state it held. Above the floor, the
detector fails only when the UPPER bound exceeds the tolerance, so a noisy point estimate cannot
bench it either.

A failing check names itself (`no calibration row`, `coverage not recorded`, `FAR 0.083 (95% CI
0.058-0.117, n=420) above the 0.030 tolerance`) so the table can say WHY a detector is out, and a
FAR is never printed without the sample size and interval it came from. A model with no evidence is
never eligible: an unmeasured false-alarm rate is not a met budget.

THE PROMOTION GUARD. Being calibrated is not the same as being safe to add. Measured on the live
24-hour population, admitting both cross-sectional detectors took the share of windows at or above
`BASE_THRESHOLD` from 25.6% to 42.8% -- a doubling of the page load from an automatic decision
nobody made. So a calibrated detector is promoted only when the fused alert rate WITH it stays
inside `ML_FUSED_ALERT_BUDGET` (default 0.30: the measured 25.6% baseline plus headroom, below the
measured 42.8% doubling). Otherwise it is `calibrated, held for budget` with both rates shown, and
the next evaluation promotes it automatically once the rate fits -- no human, no stored approval.

INCUMBENTS ARE NOT DEMOTED. The guard governs promotions. A detector already in the fused set (the
first evaluation seeds that set from the registry the card gate used to admit; afterwards the
recorded state is the truth) keeps contributing even while the ensemble is over budget, because
dropping a working detector is not a budget decision -- it is a detection outage. A stale detector
still falls out: freshness is evidence, not seniority.
"""
from __future__ import annotations

import json
import logging
import math
import os
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field, replace
from typing import Any

from weirvern.config import FUSED_MODEL
from weirvern.models.eval_report import wilson

logger = logging.getLogger(__name__)

STATE_ELIGIBLE = "eligible"
STATE_HELD = "held-for-budget"
STATE_EXCLUDED = "excluded-from-fusion"
STATE_NOT_ELIGIBLE = "not-eligible"
# A MEASUREMENT THAT HAS NOT RUN LONG ENOUGH IS NOT A FAILURE. Below the minimum validation
# sample, the FAR interval is too wide to separate the target from the tolerance, so the state
# names the sample and the detector keeps whatever state it held. It is deliberately not a
# promotion state: `save_state` preserves the held state rather than recording this one.
STATE_CALIBRATING = "calibrating"

# The policy target when a calibration row carries none. Mirrors `Settings.ml_target_far`; the
# caller passes the live setting so an environment override is never replaced by this.
DEFAULT_TARGET_FAR = 0.01
DEFAULT_ELIGIBILITY_MULTIPLE = 3.0
# The share of a detector's vector that must be measured for its calibration to be evidence about
# the detector. Mirrors `Settings.ml_min_feature_coverage` / `models.missing.DEFAULT_MIN_COVERAGE`.
DEFAULT_MIN_COVERAGE = 0.15
# The fused alert-rate ceiling. See the module docstring: 0.30 is the measured 25.6% baseline plus
# headroom, and it is below the measured 42.8% both-eligible case this guard exists to stop.
DEFAULT_FUSED_ALERT_BUDGET = 0.30
# A promotion is justified by a measurement, so it needs a population behind it. A HOLD does not:
# a small sample showing the rate over budget is already reason to wait.
DEFAULT_MIN_BUDGET_WINDOWS = 200
DEFAULT_BUDGET_LOOKBACK_H = 24
# THE SMALLEST SAMPLE THAT CAN ANSWER THE QUESTION. At a 1% realised FAR, n=300 puts the Wilson
# 95% upper bound at 2.9%, inside the default 3% tolerance; at n=110 even a PERFECT record (0
# exceedances) has an upper bound of 3.4% and cannot pass, while 5/110 spans 2.0-10.2%. Below this
# floor the rule is not a budget decision, so it is not allowed to fail a detector.
DEFAULT_MIN_VALIDATION_WINDOWS = 300
# The file the worker writes beside the artifacts. JSON rather than a table because it is a
# decision log, not a measurement, and the worker already persists its control state this way.
PROMOTION_STATE_FILE = "detector_promotions.json"


@dataclass(frozen=True)
class Evidence:
    """What the engine measured about one detector, and whether it is enough to run it."""

    name: str
    calibrated: bool
    reason: str = ""
    age_hours: float | None = None
    observed_far: float | None = None
    target_far: float | None = None
    tolerance: float | None = None
    coverage: float | None = None
    coverage_observed: int | None = None
    coverage_expected: int | None = None
    # THE DENOMINATOR AND THE INTERVAL. A realised FAR is a binomial proportion and is not
    # interpretable without them: `validation_count` is n, and `far_lower`/`far_upper` are the
    # Wilson 95% bounds on that n. `calibrating` says the sample is below the floor, so the FAR
    # was not allowed to decide anything.
    validation_count: int | None = None
    min_validation_windows: int = DEFAULT_MIN_VALIDATION_WINDOWS
    far_lower: float | None = None
    far_upper: float | None = None
    # The detector's own conformal threshold, in the detector's own score space. The fusion uses
    # it to map every detector onto one scale (see `ensemble.calibrated_scores`): without it a
    # raw `max` over a membership of one is on a different scale from a `max` over five.
    threshold: float | None = None
    calibrating: bool = False

    @property
    def n(self) -> int:
        return int(self.validation_count or 0)

    def interval_text(self) -> str:
        """`0.020-0.102, n=110`, or `n=0` when the row never recorded a sample.

        Never omitted from a sentence that quotes a FAR: the point estimate alone is what let a
        110-window reading read as 4.5% when it could not tell 1% from 10%.
        """
        if self.validation_count is None or self.validation_count <= 0:
            return "n=0"
        if self.far_lower is None or self.far_upper is None:
            return f"n={int(self.validation_count)}"
        return (f"95% CI {self.far_lower:.3f}-{self.far_upper:.3f}, "
                f"n={int(self.validation_count)}")


@dataclass(frozen=True)
class Rate:
    """The paired measurement the budget guard reads.

    `windows` is the population in which EVERY compared model scored; a window where the candidate
    has no score cannot say what the candidate would do, so it is excluded rather than counted as
    a zero (which would understate the promotion it is being judged for).
    """

    windows: int
    without_hits: int
    with_hits: int

    @property
    def rate_without(self) -> float | None:
        return (self.without_hits / self.windows) if self.windows else None

    @property
    def rate_with(self) -> float | None:
        return (self.with_hits / self.windows) if self.windows else None


@dataclass(frozen=True)
class Decision:
    """One detector's promotion decision, with the numbers it was made from."""

    name: str
    state: str
    reason: str = ""
    evidence: Evidence | None = None
    windows: int = 0
    rate_without: float | None = None
    rate_with: float | None = None
    budget: float | None = None
    # THE SAMPLE STATUS TRAVELS WITH THE DECISION. A calibrating detector is still, effectively,
    # in the state it held (eligible, held, or out); the sentence has to say both facts.
    calibrating: bool = False
    held_state: str = ""

    @property
    def contributing(self) -> bool:
        return self.state == STATE_ELIGIBLE

    @property
    def validation_count(self) -> int:
        return int(self.evidence.validation_count or 0) if self.evidence else 0

    @property
    def min_validation_windows(self) -> int:
        return int(self.evidence.min_validation_windows) if self.evidence else 0

    def calibrating_text(self) -> str:
        return (f"calibrating (n={self.validation_count}, "
                f"need {self.min_validation_windows})")

    def sentence(self) -> str:
        """The one line the Detectors table renders for this decision.

        A FAR is never quoted without its interval and sample size. Below the sample floor the
        sentence says `calibrating`, names the n it has and the n it needs, and then says which
        state the detector keeps -- it is never rendered as a failure the measurement cannot
        support.
        """
        if self.state == STATE_ELIGIBLE:
            if self.calibrating:
                return f"{STATE_ELIGIBLE} ({self.reason or self.calibrating_text()})"
            return STATE_ELIGIBLE
        if self.state == STATE_EXCLUDED:
            return "calibrated, excluded from fusion (ML_FUSION_EXCLUDE)"
        if self.state == STATE_HELD:
            if self.calibrating:
                return f"{self.reason or self.calibrating_text()}; held for budget"
            if self.rate_with is None or self.rate_without is None:
                return f"calibrated, held for budget ({self.reason})"
            return (f"calibrated, held for budget (fused {self.rate_with:.1%} with it vs "
                    f"{self.rate_without:.1%} without; budget {(self.budget or 0.0):.1%})")
        if self.state == STATE_CALIBRATING:
            return self.reason or self.calibrating_text()
        return f"not contributing: {self.reason}"


@dataclass
class Report:
    """Every decision from one evaluation, plus the settings that produced them."""

    decisions: dict[str, Decision] = field(default_factory=dict)
    budget: float = DEFAULT_FUSED_ALERT_BUDGET
    bar: float = 0.35
    windows: int = 0
    seeded: bool = False
    # The per-detector conformal thresholds of the contributing detectors, in their own score
    # spaces. The caller hands them to the fusion so a score is compared on the detector's
    # calibrated scale rather than on the raw number it happens to emit.
    thresholds: dict[str, float] = field(default_factory=dict)

    @property
    def eligible(self) -> dict[str, bool]:
        """The mapping the ensemble consumes: contributors only, absent means ineligible."""
        return {name: d.contributing for name, d in self.decisions.items()}

    def contributing_names(self) -> list[str]:
        return sorted(name for name, d in self.decisions.items() if d.contributing)


def _number(value: Any) -> float | None:
    """A finite float, or None. A blank/garbage cell is absence, never zero."""
    try:
        out = float(value)
    except (TypeError, ValueError):
        return None
    return out if math.isfinite(out) else None


def _count(value: Any) -> int | None:
    number = _number(value)
    return None if number is None else int(round(number))


def evidence_from_row(
    name: str,
    row: dict[str, Any] | None,
    *,
    target_far: float = DEFAULT_TARGET_FAR,
    multiple: float = DEFAULT_ELIGIBILITY_MULTIPLE,
    retrain_every_h: float = 6.0,
    grace_h: float = 0.0,
    min_coverage: float = DEFAULT_MIN_COVERAGE,
    min_validation_windows: int = DEFAULT_MIN_VALIDATION_WINDOWS,
) -> Evidence:
    """Apply the three evidence checks to one model's newest calibration row.

    `row` carries `observed_far`, `target_far`, `coverage`, `coverage_observed`,
    `coverage_expected`, `validation_count`, `threshold` and `age_hours` (computed by ClickHouse,
    so no timezone arithmetic happens here -- a naive datetime read back from the driver is a wall
    clock in the server's zone, and comparing it to `utcnow()` is how this project produced a
    five-hour sweep window once).

    ORDER: the row's existence first, then freshness, then coverage, then the rate. Each is a
    different remedy, and the first failing one is the one the operator is sent to.

    THE RATE IS A BINOMIAL PROPORTION, NOT A SCALAR. `observed_far * validation_count` is the
    number of exceedances; its Wilson 95% interval is what the tolerance is compared with, and
    only when the sample reaches `min_validation_windows`. Below that floor the detector is
    `calibrating` and the caller keeps whatever state it held -- a 110-window reading that says
    0.045 is compatible with anything from 2% to 10% and must not be allowed to bench a detector.
    """
    if not row:
        return Evidence(name=name, calibrated=False, reason="no calibration row",
                        min_validation_windows=int(min_validation_windows))
    observed = _number(row.get("observed_far"))
    target = _number(row.get("target_far"))
    target = float(target_far) if target is None else target
    tolerance = float(target) * float(multiple)
    age = _number(row.get("age_hours"))
    coverage = _number(row.get("coverage"))
    cov_observed = _count(row.get("coverage_observed"))
    cov_expected = _count(row.get("coverage_expected"))
    n = _count(row.get("validation_count"))
    threshold = _number(row.get("threshold"))
    far_lower = _number(row.get("far_lower"))
    far_upper = _number(row.get("far_upper"))
    detail = Evidence(
        name=name, calibrated=False, age_hours=age, observed_far=observed, target_far=target,
        tolerance=tolerance, coverage=coverage, coverage_observed=cov_observed,
        coverage_expected=cov_expected, validation_count=n,
        min_validation_windows=int(min_validation_windows),
        far_lower=far_lower, far_upper=far_upper, threshold=threshold,
    )
    if observed is None:
        return replace(detail, reason="no calibration row")
    if age is not None and age > float(retrain_every_h) + float(grace_h):
        return replace(detail,
                       reason=f"calibration stale ({age:.1f}h old, "
                              f"{float(retrain_every_h):.0f}h retrain interval)")
    # NULL COVERAGE IS NEVER COMPLETE. The row was written before coverage existed (or with the
    # flag off), and a FAR measured on a vector nobody described is not evidence about this model.
    if cov_observed is None or cov_expected is None:
        return replace(detail, reason="coverage not recorded")
    if cov_expected <= 0:
        return replace(detail, reason="coverage not recorded")
    if coverage is None:
        coverage = cov_observed / cov_expected
    if coverage < float(min_coverage):
        return replace(detail,
                       reason=f"coverage {coverage:.2f} below the {float(min_coverage):.2f} floor")

    # THE INTERVAL IS DERIVED FROM THE STORED ROW WHEN IT CARRIES ONE, and recomputed from
    # (observed, n) when it does not. A row written before schema 060 has no bounds columns; the
    # sample count and rate are still enough to compute the same interval here, so an older row is
    # not forced into `calibrating` merely for missing two columns.
    if n is None or n <= 0:
        return replace(detail, calibrating=True,
                       reason=f"calibrating (n={int(n or 0)}, "
                              f"need {int(min_validation_windows)})")
    successes = int(round(max(0.0, min(1.0, float(observed))) * n))
    if far_lower is None or far_upper is None:
        bounds = wilson(successes, n)
        if bounds is not None:
            far_lower, far_upper = bounds
    detail = replace(detail, validation_count=n, far_lower=far_lower, far_upper=far_upper)

    if n < int(min_validation_windows):
        # NOT A FAILURE, AND NOT A PASS. State the sample and the interval it produced; the
        # caller keeps the detector in whatever state it held.
        interval = (f"; FAR {observed:.3f}"
                    + (f", 95% CI {far_lower:.3f}-{far_upper:.3f}" if far_lower is not None
                       and far_upper is not None else ""))
        return replace(detail, calibrating=True, calibrated=False,
                       reason=f"calibrating (n={n}, need {int(min_validation_windows)})"
                              f"{interval}")

    # A GENUINELY BAD RATE STILL FAILS, even at a large sample: the point estimate is above the
    # tolerance AND the interval's upper bound confirms it cannot be explained by noise.
    if far_upper is not None and far_upper > tolerance:
        return replace(detail,
                       reason=f"FAR {observed:.3f} (95% CI {far_lower:.3f}-{far_upper:.3f}, "
                              f"n={n}) above the {tolerance:.3f} tolerance "
                              f"({float(multiple):g} x {target:.3f} target)")
    return replace(detail, calibrated=True)


def _quote(name: str) -> str:
    """A SQL string literal from a detector name. Names are ours; escaping is belt and braces."""
    return "'" + str(name).replace("\\", "\\\\").replace("'", "''") + "'"


def budget_sql(members: Iterable[str], candidate: str, *, bar: float,
               thresholds: dict[str, float] | None = None,
               hours: int = DEFAULT_BUDGET_LOOKBACK_H) -> str:
    """The paired fused-rate measurement for one candidate.

    One row: the population size, the hits with the candidate and the hits without it. The inner
    query keeps only windows where EVERY compared model scored (`uniqExact`), so the two rates
    share a denominator and the difference is attributable to the candidate.

    THE SCORES ARE COMPARED ON THE CALIBRATED SCALE, which is the scale the decision uses. Each
    detector's raw score is multiplied by `bar / threshold_i`, so its own 1% threshold lands on
    `bar`. Without that, a budget measured as `max(raw score) >= 0.35` would judge an ensemble by a
    bar that means 80% for one detector and 3% for another -- the exact defect the fusion
    normalisation fixes. A detector with no threshold keeps its raw score (k=1), which is the
    honest reading of "not calibrated".

    The thin-window damping is not reconstructed (it only lowers scores, so this measurement is the
    conservative one for a budget guard).
    """
    names = [str(n) for n in members]
    scale = thresholds or {}

    def _k(name: str) -> float:
        value = _number(scale.get(name))
        if value is None or value <= 0:
            return 1.0
        return float(bar) / float(value)

    all_names = (*names, str(candidate))
    terms = [f"maxIf(score * {_k(n):.10g}, model_name = {_quote(n)})" for n in all_names]
    without_terms = [f"maxIf(score * {_k(n):.10g}, model_name = {_quote(n)})" for n in names]
    fused = f"greatest({', '.join(terms)})" if terms else "0"
    without = f"greatest({', '.join(without_terms)})" if without_terms else "0"
    models = ", ".join(_quote(n) for n in all_names)
    expected = len(names) + 1
    return f"""  # nosec B608 - detector names come from the engine roster; only integers/floats interpolate
        SELECT count() AS windows,
               countIf(fused >= {float(bar)}) AS with_hits,
               countIf(without_candidate >= {float(bar)}) AS without_hits
        FROM (
            SELECT window_start, src_addr,
                   {fused} AS fused,
                   {without} AS without_candidate
            FROM weirvern.ml_window_scores FINAL
            WHERE computed_at >= now() - INTERVAL {int(hours)} HOUR
              AND model_name IN ({models})
            GROUP BY window_start, src_addr
            HAVING uniqExact(model_name) = {int(expected)}
        )
    """


def measure_rate(client: Any, members: Iterable[str], candidate: str, *, bar: float,
                 thresholds: dict[str, float] | None = None,
                 hours: int = DEFAULT_BUDGET_LOOKBACK_H) -> Rate | None:
    """Run `budget_sql` and return the rate, or None when the population could not be read."""
    try:
        rows = client.query(budget_sql(members, candidate, bar=bar, thresholds=thresholds,
                                       hours=hours)).result_rows
    except Exception as exc:  # noqa: BLE001
        logger.warning("promotion guard: could not measure the fused rate for %s: %s", candidate, exc)
        return None
    if not rows:
        return None
    try:
        windows, with_hits, without_hits = rows[0][0], rows[0][1], rows[0][2]
    except (IndexError, TypeError):
        return None
    return Rate(windows=int(windows or 0), with_hits=int(with_hits or 0),
                without_hits=int(without_hits or 0))


def promotion_plan(
    calibrated: Iterable[Evidence],
    incumbents: Iterable[str],
    measure: Callable[[tuple[str, ...], str], Rate | None],
    *,
    budget: float = DEFAULT_FUSED_ALERT_BUDGET,
    min_windows: int = DEFAULT_MIN_BUDGET_WINDOWS,
    bar: float = 0.35,
) -> dict[str, Decision]:
    """Decide which calibrated detectors may contribute, under a measured alert budget.

    INCUMBENTS ARE ADMITTED FIRST and never held; they are what the deployment is already running.
    Candidates are tried cheapest-first (the smallest increase in the fused rate is tried before a
    large one), so the budget admits as many detectors as it can. A candidate is held when the
    paired measurement puts the fused rate above `budget`, and promoted when it does not -- the
    promotion needs `min_windows` behind it, because an absent measurement is not a met budget.
    """
    by_name = {ev.name: ev for ev in calibrated}
    accepted = [name for name in incumbents if name in by_name]
    # A CALIBRATING CANDIDATE IS NOT A CANDIDATE. It has not been in the ensemble and its sample
    # is too small to judge, so it has no claim on the budget; only an incumbent may hold a state
    # through a calibration gap.
    candidates = [name for name in by_name
                  if name not in accepted and not by_name[name].calibrating]

    # Cheapest first: measure each candidate against the incumbent set, then admit in that order.
    # The rate is monotone in the member set (max fusion), so this greedy is the maximal admission
    # under the budget rather than an arbitrary one.
    trial: dict[str, Rate | None] = {
        name: measure(tuple(accepted), name) for name in candidates
    }

    def decision_for(name: str, **kwargs: Any) -> Decision:
        ev = by_name[name]
        return Decision(name=name, evidence=ev, budget=budget,
                        calibrating=bool(ev.calibrating), **kwargs)

    def trial_rate(name: str) -> float:
        rate = trial.get(name)
        value = rate.rate_with if rate is not None else None
        return float(value) if value is not None else math.inf

    order = sorted(candidates, key=lambda n: (trial_rate(n), n))

    decisions: dict[str, Decision] = {
        name: decision_for(name, state=STATE_ELIGIBLE) for name in accepted
    }
    for name in order:
        rate = measure(tuple(accepted), name)
        if rate is None or rate.rate_with is None or rate.windows == 0:
            decisions[name] = decision_for(
                name, state=STATE_HELD, reason="the fused rate could not be measured")
            continue
        if rate.rate_with > float(budget):
            decisions[name] = decision_for(
                name, state=STATE_HELD, windows=rate.windows,
                rate_without=rate.rate_without, rate_with=rate.rate_with)
            continue
        if rate.windows < int(min_windows):
            # UNDER BUDGET BUT NOT YET PROVEN. A hold is always safe; a promotion is a claim, and
            # a claim needs a population. It promotes on a later sweep by itself.
            decisions[name] = decision_for(
                name, state=STATE_HELD, windows=rate.windows,
                rate_without=rate.rate_without, rate_with=rate.rate_with,
                reason=f"budget not measurable yet ({rate.windows} scored windows, "
                       f"{int(min_windows)} needed)")
            continue
        decisions[name] = decision_for(
            name, state=STATE_ELIGIBLE, windows=rate.windows,
            rate_without=rate.rate_without, rate_with=rate.rate_with)
        accepted.append(name)
    return decisions


def load_state(model_dir: str | None) -> dict[str, str]:
    """The recorded promotion state: model name -> state. Missing/unreadable is empty."""
    if not model_dir:
        return {}
    path = os.path.join(str(model_dir), PROMOTION_STATE_FILE)
    try:
        with open(path, encoding="utf-8") as handle:  # noqa: PTH123 - one small read
            data = json.load(handle)
    except (OSError, ValueError):
        return {}
    detectors = data.get("detectors") if isinstance(data, dict) else None
    if not isinstance(detectors, dict):
        return {}
    out: dict[str, str] = {}
    for name, entry in detectors.items():
        state = entry.get("state") if isinstance(entry, dict) else entry
        if str(state or "") in (STATE_ELIGIBLE, STATE_HELD, STATE_EXCLUDED, STATE_NOT_ELIGIBLE):
            out[str(name)] = str(state)
    return out


def save_state(model_dir: str | None, decisions: dict[str, Decision], *,
               budget: float, bar: float, windows: int,
               prior: dict[str, str] | None = None) -> None:
    """Record the decisions for the next evaluation. Best-effort: a write failure is not fatal.

    The state is what makes the guard a PROMOTION guard: without it every evaluation would have
    to reconstruct who was already running, and the first over-budget ensemble would hold the
    detectors it inherited instead of only the new ones.

    CALIBRATING IS NOT A PROMOTION STATE. An under-sampled measurement decides nothing, so the
    detector's prior state is written back unchanged rather than replaced by `calibrating`; that
    is what "stays in whatever state it held" means across evaluations. A detector with no prior
    state and no verdict is simply omitted, and the next evaluation treats it as unrecorded.
    """
    if not model_dir:
        return
    from weirvern.clock import utcnow  # noqa: PLC0415

    held = prior or {}
    entries: dict[str, dict[str, Any]] = {}
    for name, decision in sorted(decisions.items()):
        state = decision.state
        if state in (STATE_CALIBRATING, STATE_NOT_ELIGIBLE):
            # NOT A VERDICT ABOUT RUNNING. Preserve what was recorded before this evaluation; an
            # evidence failure is recomputed every sweep, so writing it here would make a
            # transient reading sticky and lose the detector's promotion history.
            previous = held.get(name)
            if not previous:
                continue
            state = previous
        entries[name] = {
            "state": state,
            "reason": decision.reason,
            "rate_without": decision.rate_without,
            "rate_with": decision.rate_with,
            "windows": decision.windows,
            # THE SAMPLE BEHIND THE STATE, so a reader can tell a verdict from a gap.
            "validation_count": decision.validation_count,
            "far_lower": decision.evidence.far_lower if decision.evidence else None,
            "far_upper": decision.evidence.far_upper if decision.evidence else None,
        }
    payload = {
        "updated_at": utcnow().isoformat(),
        "budget": float(budget),
        "bar": float(bar),
        "windows": int(windows),
        "detectors": entries,
    }
    path = os.path.join(str(model_dir), PROMOTION_STATE_FILE)
    try:
        with open(path, "w", encoding="utf-8") as handle:  # noqa: PTH123 - one small write
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
    except OSError as exc:
        logger.warning("promotion guard: could not record %s: %s", path, exc)


def _calibration_rows(client: Any) -> dict[str, dict[str, Any]]:
    """The newest pooled calibration per model, with the AGE measured by ClickHouse."""
    base = (
        "SELECT model_name, observed_far, target_far, coverage, coverage_observed, "
        "coverage_expected, computed_at, dateDiff('second', computed_at, now()) / 3600.0 "
        "AS age_hours, validation_count, threshold"
    )
    # THE FAR INTERVAL COLUMNS ARRIVED IN SCHEMA 060. A deployment that has not applied it must
    # still be able to run the gate: the bounds are recomputed from (observed_far,
    # validation_count) by `evidence_from_row`, so the fallback loses nothing but the stored copy.
    res = None
    columns = ""
    for columns in (", far_lower, far_upper", ""):
        try:
            res = client.query(
                base + columns + " FROM weirvern.ml_calibration FINAL "
                # ONLY THE POOLED ROW: per-stratum rows measure a sub-population and are written
                # beside it.
                "WHERE scope = 'global' AND computed_at = (SELECT max(computed_at) "
                "FROM weirvern.ml_calibration)"
            )
            break
        except Exception as exc:  # noqa: BLE001
            if columns:
                logger.warning("eligibility: interval columns unavailable (%s); recomputing", exc)
                continue
            raise
    assert res is not None  # the loop either breaks with a result or re-raises
    width = 12 if columns else 10
    out: dict[str, dict[str, Any]] = {}
    for row in res.result_rows:
        values = list(row) + [None] * max(0, width - len(row))
        name = str(values[0])
        out[name] = {
            "observed_far": values[1], "target_far": values[2], "coverage": values[3],
            "coverage_observed": values[4], "coverage_expected": values[5], "computed_at": values[6],
            "age_hours": (float(values[7]) if values[7] is not None else None),
            "validation_count": values[8], "threshold": values[9],
            "far_lower": values[10] if columns else None,
            "far_upper": values[11] if columns else None,
        }
    return out


def _latest_training(client: Any) -> dict[str, str]:
    """When the engine last trained each model. Empty on a read failure (evidence, not a gate)."""
    try:
        res = client.query(
            "SELECT model_type, max(trained_at) FROM weirvern.ml_models GROUP BY model_type")
    except Exception as exc:  # noqa: BLE001
        logger.warning("eligibility: could not read training dates (holdout lock skipped): %s", exc)
        return {}
    return {str(name): str(when) for name, when in res.result_rows}


def _stamp(value: Any) -> str:
    """A comparable timestamp from either spelling, or \"\" when there is nothing to compare."""
    return str(value or "").strip().replace("T", " ")[:19]


def _seed_incumbents(client: Any, calibrated: Iterable[str]) -> list[str]:
    """The one-time migration seed: the set the retired card gate was admitting.

    READ ONCE, when no promotion record exists, and never again. It is not a gate: an unreadable
    registry seeds nothing and every calibrated model is tried against the budget instead.
    """
    names = [str(n) for n in calibrated]
    try:
        from weirvern.models import cards as cards_mod  # noqa: PLC0415

        allowed = cards_mod.production_allowed(cards_mod.status_map(cards_mod.current_cards(client)))
    except Exception as exc:  # noqa: BLE001
        # AN UNREADABLE REGISTRY SEEDS NOTHING. Treating "I could not read the cards" as "every
        # card says production" would make the first evaluation a no-op guard and admit exactly
        # the alert-rate doubling this guard exists to stop, so the budget decides instead.
        logger.warning("promotion guard: no recorded state and the card registry is unreadable "
                       "(%s); seeding nothing, so every calibrated detector faces the budget", exc)
        return []
    seeded = [name for name in names if allowed.get(name, False)]
    if not seeded:
        # THE SAME RULE FOR AN EMPTY REGISTRY. No card admitting a detector is not a licence to
        # admit them all: the seed migrates what the old gate was running, and it was running
        # nothing. Every calibrated detector is therefore a candidate for the measured budget.
        logger.warning("promotion guard: no recorded state and no card admits any detector; "
                       "seeding nothing, so every calibrated detector faces the budget")
    return seeded


def evaluate(client: Any, settings: Any, *, names: Iterable[str] | None = None,
             persist: bool = False) -> Report:
    """Read the evidence, apply the budget guard, and return every detector's decision.

    `names` is the engine's roster. When omitted, every model with a calibration or training row is
    considered -- the caller that renders a table passes the roster so a model the engine no longer
    builds cannot appear.
    """
    target_far = float(getattr(settings, "ml_target_far", DEFAULT_TARGET_FAR) or DEFAULT_TARGET_FAR)
    multiple = float(getattr(settings, "ml_eligibility_multiple", DEFAULT_ELIGIBILITY_MULTIPLE)
                     or DEFAULT_ELIGIBILITY_MULTIPLE)
    retrain_h = float(getattr(settings, "retrain_every_h", 6) or 6)
    grace_h = float(getattr(settings, "ml_calibration_grace_h", 1.0) or 0.0)
    min_coverage = float(getattr(settings, "ml_min_feature_coverage", DEFAULT_MIN_COVERAGE)
                         or DEFAULT_MIN_COVERAGE)
    budget = float(getattr(settings, "ml_fused_alert_budget", DEFAULT_FUSED_ALERT_BUDGET)
                   or DEFAULT_FUSED_ALERT_BUDGET)
    min_windows = int(getattr(settings, "ml_fused_budget_min_windows", DEFAULT_MIN_BUDGET_WINDOWS)
                      or DEFAULT_MIN_BUDGET_WINDOWS)
    lookback_h = int(getattr(settings, "ml_fused_budget_hours", DEFAULT_BUDGET_LOOKBACK_H)
                     or DEFAULT_BUDGET_LOOKBACK_H)
    bar = float(getattr(settings, "base_threshold", 0.35) or 0.35)
    min_validation = int(getattr(settings, "ml_eligibility_min_windows",
                                  DEFAULT_MIN_VALIDATION_WINDOWS)
                         or DEFAULT_MIN_VALIDATION_WINDOWS)

    rows = _calibration_rows(client)
    trained = _latest_training(client)
    roster = [str(n) for n in names] if names is not None else sorted(
        (set(rows) | set(trained)) - {FUSED_MODEL})

    # THE RECORDED STATE IS READ BEFORE THE EVIDENCE, because an under-sampled measurement has to
    # keep the state the detector already held. Reading it afterwards (as this did) made a
    # `calibrating` verdict impossible to express.
    state = load_state(getattr(settings, "model_dir", ""))
    seeded = not bool(state)

    evidence: dict[str, Evidence] = {}
    for name in roster:
        ev = evidence_from_row(
            name, rows.get(name), target_far=target_far, multiple=multiple,
            retrain_every_h=retrain_h, grace_h=grace_h, min_coverage=min_coverage,
            min_validation_windows=min_validation)
        # THE HOLDOUT LOCK, kept from the previous gate: a calibration computed before the newest
        # artifact measured a model that is no longer serving. Freshness alone cannot see this when
        # a retrain and a calibration land in the same interval.
        cal_when, train_when = _stamp((rows.get(name) or {}).get("computed_at")), _stamp(
            trained.get(name))
        if ev.calibrated and train_when and cal_when and cal_when < train_when:
            ev = Evidence(**{**ev.__dict__, "calibrated": False,
                             "reason": "calibration older than the artifact"})
        evidence[name] = ev

    decisions: dict[str, Decision] = {}
    held_through_calibration: list[str] = []
    for name in roster:
        ev = evidence[name]
        prior = state.get(name, "")
        if ev.calibrated:
            continue  # the promotion guard decides
        if ev.calibrating:
            # KEEP THE STATE IT HELD. `calibrating` is a fact about the measurement, not a verdict
            # about the detector; an incumbent stays in the fused set while its next sample fills.
            if prior == STATE_ELIGIBLE:
                decisions[name] = Decision(name=name, state=STATE_ELIGIBLE, evidence=ev,
                                           budget=budget, calibrating=True,
                                           reason=ev.reason, held_state=prior)
                held_through_calibration.append(name)
            elif prior == STATE_HELD:
                decisions[name] = Decision(name=name, state=STATE_HELD, evidence=ev,
                                           budget=budget, calibrating=True,
                                           reason=ev.reason, held_state=prior)
            else:
                decisions[name] = Decision(name=name, state=STATE_CALIBRATING, evidence=ev,
                                           budget=budget, calibrating=True,
                                           reason=ev.reason, held_state=prior)
            continue
        decisions[name] = Decision(name=name, state=STATE_NOT_ELIGIBLE,
                                   reason=ev.reason, evidence=ev, budget=budget,
                                   held_state=prior)

    # THE FUSION EXCLUSION IS NOT ELIGIBILITY. A model the operator removed from the fusion can be
    # perfectly calibrated; it is zeroed in the fused score by `ML_FUSION_EXCLUDE`, and measuring it
    # as a member would overstate every rate a promotion is judged against.
    from weirvern.ensemble import fusion_excluded  # noqa: PLC0415

    excluded = fusion_excluded(settings)
    for name in roster:
        if name not in excluded:
            continue
        current = decisions.get(name)
        if evidence[name].calibrated or (current is not None and current.contributing):
            decisions[name] = Decision(name=name, state=STATE_EXCLUDED, evidence=evidence[name],
                                       budget=budget)
    calibrated = [name for name in roster
                  if evidence[name].calibrated and name not in excluded
                  and name != FUSED_MODEL]
    held_through_calibration = [n for n in held_through_calibration if n not in excluded]

    # THE PROMOTION GUARD. Incumbents come from the recorded state; with no record, from the set the
    # retired card gate was admitting (a one-time seed, not a gate).
    if seeded:
        incumbents = _seed_incumbents(client, calibrated)
    else:
        incumbents = [name for name in calibrated if state.get(name) == STATE_ELIGIBLE]
    incumbents += [name for name in held_through_calibration if name not in incumbents]

    def measure(members: tuple[str, ...], candidate: str) -> Rate | None:
        # THE BUDGET IS MEASURED ON THE SAME CALIBRATED SCALE THE DECISION USES. Each compared
        # detector contributes its threshold so `bar` means its own 1% point, not a raw number
        # whose meaning changes with the membership.
        scales: dict[str, float] = {}
        for n in (*members, candidate):
            value = evidence[n].threshold
            if value is not None and float(value) > 0:
                scales[n] = float(value)
        return measure_rate(client, members, candidate, bar=bar, thresholds=scales,
                            hours=lookback_h)

    planned_evidence = [evidence[name] for name in calibrated]
    # An incumbent that is merely calibrating still counts as an accepted member: it is in the
    # fused set, so a candidate has to be measured against it.
    planned_evidence += [replace(evidence[name], calibrated=True)
                         for name in held_through_calibration if name not in calibrated]
    planned = promotion_plan(
        planned_evidence, incumbents, measure,
        budget=budget, min_windows=min_windows, bar=bar)
    decisions.update(planned)
    windows = max((d.windows for d in planned.values()), default=0)
    thresholds = {
        name: float(decision.evidence.threshold)
        for name, decision in decisions.items()
        if decision.contributing and decision.evidence is not None
        and decision.evidence.threshold is not None
        and float(decision.evidence.threshold) > 0
    }
    report = Report(decisions=decisions, budget=budget, bar=bar, windows=windows,
                    seeded=seeded, thresholds=thresholds)
    if persist:
        save_state(getattr(settings, "model_dir", ""), decisions, budget=budget, bar=bar,
                   windows=windows, prior=state)
    held = sorted(name for name, d in decisions.items() if d.state == STATE_HELD)
    if held:
        logger.warning("ML eligibility: %d calibrated detector(s) held for budget: %s",
                       len(held), ", ".join(held))
    calibrating = sorted(name for name, d in decisions.items() if d.calibrating)
    if calibrating:
        logger.info("ML eligibility: %d detector(s) calibrating (sample below the %d-window "
                    "floor): %s", len(calibrating), min_validation, ", ".join(calibrating))
    return report


__all__ = [
    "Decision", "Evidence", "Rate", "Report", "DEFAULT_BUDGET_LOOKBACK_H",
    "DEFAULT_ELIGIBILITY_MULTIPLE", "DEFAULT_FUSED_ALERT_BUDGET", "DEFAULT_MIN_BUDGET_WINDOWS",
    "DEFAULT_MIN_COVERAGE", "DEFAULT_MIN_VALIDATION_WINDOWS", "DEFAULT_TARGET_FAR",
    "PROMOTION_STATE_FILE", "STATE_CALIBRATING", "STATE_ELIGIBLE", "STATE_HELD",
    "STATE_NOT_ELIGIBLE", "budget_sql", "evaluate", "evidence_from_row", "load_state",
    "measure_rate", "promotion_plan", "save_state", "wilson",
]
