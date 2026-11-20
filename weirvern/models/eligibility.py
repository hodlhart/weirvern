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
     tolerance the deployment configures, not one this module chooses.

A failing check names itself (`no calibration row`, `coverage not recorded`, `FAR 0.083 above the
0.030 tolerance`) so the table can say WHY a detector is out. A model with no evidence is never
eligible: an unmeasured false-alarm rate is not a met budget.

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

logger = logging.getLogger(__name__)

STATE_ELIGIBLE = "eligible"
STATE_HELD = "held-for-budget"
STATE_EXCLUDED = "excluded-from-fusion"
STATE_NOT_ELIGIBLE = "not-eligible"

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

    @property
    def contributing(self) -> bool:
        return self.state == STATE_ELIGIBLE

    def sentence(self) -> str:
        """The one line the Detectors table renders for this decision."""
        if self.state == STATE_ELIGIBLE:
            return STATE_ELIGIBLE
        if self.state == STATE_EXCLUDED:
            return "calibrated, excluded from fusion (ML_FUSION_EXCLUDE)"
        if self.state == STATE_HELD:
            if self.rate_with is None or self.rate_without is None:
                return f"calibrated, held for budget ({self.reason})"
            return (f"calibrated, held for budget (fused {self.rate_with:.1%} with it vs "
                    f"{self.rate_without:.1%} without; budget {(self.budget or 0.0):.1%})")
        return f"not contributing: {self.reason}"


@dataclass
class Report:
    """Every decision from one evaluation, plus the settings that produced them."""

    decisions: dict[str, Decision] = field(default_factory=dict)
    budget: float = DEFAULT_FUSED_ALERT_BUDGET
    bar: float = 0.35
    windows: int = 0
    seeded: bool = False

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
) -> Evidence:
    """Apply the three evidence checks to one model's newest calibration row.

    `row` carries `observed_far`, `target_far`, `coverage`, `coverage_observed`,
    `coverage_expected` and `age_hours` (computed by ClickHouse, so no timezone arithmetic happens
    here -- a naive datetime read back from the driver is a wall clock in the server's zone, and
    comparing it to `utcnow()` is how this project produced a five-hour sweep window once).

    ORDER: the row's existence first, then freshness, then coverage, then the rate. Each is a
    different remedy, and the first failing one is the one the operator is sent to.
    """
    if not row:
        return Evidence(name=name, calibrated=False, reason="no calibration row")
    observed = _number(row.get("observed_far"))
    target = _number(row.get("target_far"))
    target = float(target_far) if target is None else target
    tolerance = float(target) * float(multiple)
    age = _number(row.get("age_hours"))
    coverage = _number(row.get("coverage"))
    cov_observed = _count(row.get("coverage_observed"))
    cov_expected = _count(row.get("coverage_expected"))
    detail = Evidence(
        name=name, calibrated=False, age_hours=age, observed_far=observed, target_far=target,
        tolerance=tolerance, coverage=coverage, coverage_observed=cov_observed,
        coverage_expected=cov_expected,
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
    if observed > tolerance:
        return replace(detail,
                       reason=f"FAR {observed:.3f} above the {tolerance:.3f} tolerance "
                              f"({float(multiple):g} x {target:.3f} target)")
    return replace(detail, calibrated=True)


def _quote(name: str) -> str:
    """A SQL string literal from a detector name. Names are ours; escaping is belt and braces."""
    return "'" + str(name).replace("\\", "\\\\").replace("'", "''") + "'"


def budget_sql(members: Iterable[str], candidate: str, *, bar: float,
               hours: int = DEFAULT_BUDGET_LOOKBACK_H) -> str:
    """The paired fused-rate measurement for one candidate.

    One row: the population size, the hits with the candidate and the hits without it. The inner
    query keeps only windows where EVERY compared model scored (`uniqExact`), so the two rates
    share a denominator and the difference is attributable to the candidate.

    The fused score here is the max over the member scores at `bar`, which is what `max` fusion
    does at the decision point; the thin-window damping is not reconstructed (it only lowers
    scores, so this measurement is the conservative one for a budget guard).
    """
    names = [str(n) for n in members]
    models = ", ".join(_quote(n) for n in (*names, candidate))
    without = (f"maxIf(score, model_name IN ({', '.join(_quote(n) for n in names)}))"
               if names else "0")
    expected = len(names) + 1
    return f"""  # nosec B608 - detector names come from the engine roster; only integers/floats interpolate
        SELECT count() AS windows,
               countIf(fused >= {float(bar)}) AS with_hits,
               countIf(without_candidate >= {float(bar)}) AS without_hits
        FROM (
            SELECT window_start, src_addr,
                   max(score) AS fused,
                   {without} AS without_candidate
            FROM weirvern.ml_window_scores FINAL
            WHERE computed_at >= now() - INTERVAL {int(hours)} HOUR
              AND model_name IN ({models})
            GROUP BY window_start, src_addr
            HAVING uniqExact(model_name) = {int(expected)}
        )
    """


def measure_rate(client: Any, members: Iterable[str], candidate: str, *, bar: float,
                 hours: int = DEFAULT_BUDGET_LOOKBACK_H) -> Rate | None:
    """Run `budget_sql` and return the rate, or None when the population could not be read."""
    try:
        rows = client.query(budget_sql(members, candidate, bar=bar, hours=hours)).result_rows
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
    candidates = [name for name in by_name if name not in accepted]

    # Cheapest first: measure each candidate against the incumbent set, then admit in that order.
    # The rate is monotone in the member set (max fusion), so this greedy is the maximal admission
    # under the budget rather than an arbitrary one.
    trial: dict[str, Rate | None] = {
        name: measure(tuple(accepted), name) for name in candidates
    }

    def trial_rate(name: str) -> float:
        rate = trial.get(name)
        value = rate.rate_with if rate is not None else None
        return float(value) if value is not None else math.inf

    order = sorted(candidates, key=lambda n: (trial_rate(n), n))

    decisions: dict[str, Decision] = {
        name: Decision(name=name, state=STATE_ELIGIBLE, evidence=by_name[name], budget=budget)
        for name in accepted
    }
    for name in order:
        rate = measure(tuple(accepted), name)
        if rate is None or rate.rate_with is None or rate.windows == 0:
            decisions[name] = Decision(
                name=name, state=STATE_HELD, evidence=by_name[name], budget=budget,
                reason="the fused rate could not be measured")
            continue
        if rate.rate_with > float(budget):
            decisions[name] = Decision(
                name=name, state=STATE_HELD, evidence=by_name[name], budget=budget,
                windows=rate.windows, rate_without=rate.rate_without, rate_with=rate.rate_with)
            continue
        if rate.windows < int(min_windows):
            # UNDER BUDGET BUT NOT YET PROVEN. A hold is always safe; a promotion is a claim, and
            # a claim needs a population. It promotes on a later sweep by itself.
            decisions[name] = Decision(
                name=name, state=STATE_HELD, evidence=by_name[name], budget=budget,
                windows=rate.windows, rate_without=rate.rate_without, rate_with=rate.rate_with,
                reason=f"budget not measurable yet ({rate.windows} scored windows, "
                       f"{int(min_windows)} needed)")
            continue
        decisions[name] = Decision(
            name=name, state=STATE_ELIGIBLE, evidence=by_name[name], budget=budget,
            windows=rate.windows, rate_without=rate.rate_without, rate_with=rate.rate_with)
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
               budget: float, bar: float, windows: int) -> None:
    """Record the decisions for the next evaluation. Best-effort: a write failure is not fatal.

    The state is what makes the guard a PROMOTION guard: without it every evaluation would have
    to reconstruct who was already running, and the first over-budget ensemble would hold the
    detectors it inherited instead of only the new ones.
    """
    if not model_dir:
        return
    from weirvern.clock import utcnow  # noqa: PLC0415

    payload = {
        "updated_at": utcnow().isoformat(),
        "budget": float(budget),
        "bar": float(bar),
        "windows": int(windows),
        "detectors": {
            name: {
                "state": decision.state,
                "reason": decision.reason,
                "rate_without": decision.rate_without,
                "rate_with": decision.rate_with,
                "windows": decision.windows,
            }
            for name, decision in sorted(decisions.items())
        },
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
    res = client.query(
        "SELECT model_name, observed_far, target_far, coverage, coverage_observed, "
        "coverage_expected, computed_at, dateDiff('second', computed_at, now()) AS age_s "
        "FROM weirvern.ml_calibration FINAL "
        # ONLY THE POOLED ROW: per-stratum rows measure a sub-population and are written beside it.
        "WHERE scope = 'global' AND computed_at = (SELECT max(computed_at) "
        "FROM weirvern.ml_calibration)"
    )
    out: dict[str, dict[str, Any]] = {}
    for row in res.result_rows:
        name = str(row[0])
        out[name] = {
            "observed_far": row[1], "target_far": row[2], "coverage": row[3],
            "coverage_observed": row[4], "coverage_expected": row[5], "computed_at": row[6],
            "age_hours": (float(row[7]) / 3600.0) if row[7] is not None else None,
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
        logger.warning("promotion guard: no recorded state and the card registry is unreadable "
                       "(%s); seeding every calibrated detector as an incumbent", exc)
        return names
    seeded = [name for name in names if allowed.get(name, False)]
    if not seeded:
        logger.warning("promotion guard: no recorded state and no card admits any detector; "
                       "seeding every calibrated detector as an incumbent")
        return names
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

    rows = _calibration_rows(client)
    trained = _latest_training(client)
    roster = [str(n) for n in names] if names is not None else sorted(
        (set(rows) | set(trained)) - {FUSED_MODEL})

    evidence: dict[str, Evidence] = {}
    for name in roster:
        ev = evidence_from_row(
            name, rows.get(name), target_far=target_far, multiple=multiple,
            retrain_every_h=retrain_h, grace_h=grace_h, min_coverage=min_coverage)
        # THE HOLDOUT LOCK, kept from the previous gate: a calibration computed before the newest
        # artifact measured a model that is no longer serving. Freshness alone cannot see this when
        # a retrain and a calibration land in the same interval.
        cal_when, train_when = _stamp((rows.get(name) or {}).get("computed_at")), _stamp(
            trained.get(name))
        if ev.calibrated and train_when and cal_when and cal_when < train_when:
            ev = Evidence(**{**ev.__dict__, "calibrated": False,
                             "reason": "calibration older than the artifact"})
        evidence[name] = ev

    calibrated = [name for name in roster if evidence[name].calibrated and name != FUSED_MODEL]
    decisions: dict[str, Decision] = {}
    for name in roster:
        if not evidence[name].calibrated:
            decisions[name] = Decision(name=name, state=STATE_NOT_ELIGIBLE,
                                       reason=evidence[name].reason, evidence=evidence[name],
                                       budget=budget)

    # THE FUSION EXCLUSION IS NOT ELIGIBILITY. A model the operator removed from the fusion can be
    # perfectly calibrated; it is zeroed in the fused score by `ML_FUSION_EXCLUDE`, and measuring it
    # as a member would overstate every rate a promotion is judged against.
    from weirvern.ensemble import fusion_excluded  # noqa: PLC0415

    excluded = fusion_excluded(settings)
    for name in calibrated:
        if name in excluded:
            decisions[name] = Decision(name=name, state=STATE_EXCLUDED, evidence=evidence[name],
                                       budget=budget)
    calibrated = [name for name in calibrated if name not in excluded]

    # THE PROMOTION GUARD. Incumbents come from the recorded state; with no record, from the set the
    # retired card gate was admitting (a one-time seed, not a gate).
    state = load_state(getattr(settings, "model_dir", ""))
    seeded = not bool(state)
    if seeded:
        incumbents = _seed_incumbents(client, calibrated)
    else:
        incumbents = [name for name in calibrated if state.get(name) == STATE_ELIGIBLE]

    def measure(members: tuple[str, ...], candidate: str) -> Rate | None:
        return measure_rate(client, members, candidate, bar=bar, hours=lookback_h)

    planned = promotion_plan(
        [evidence[name] for name in calibrated], incumbents, measure,
        budget=budget, min_windows=min_windows, bar=bar)
    decisions.update(planned)
    windows = max((d.windows for d in planned.values()), default=0)
    report = Report(decisions=decisions, budget=budget, bar=bar, windows=windows, seeded=seeded)
    if persist:
        save_state(getattr(settings, "model_dir", ""), decisions, budget=budget, bar=bar,
                   windows=windows)
    held = sorted(name for name, d in decisions.items() if d.state == STATE_HELD)
    if held:
        logger.warning("ML eligibility: %d calibrated detector(s) held for budget: %s",
                       len(held), ", ".join(held))
    return report


__all__ = [
    "Decision", "Evidence", "Rate", "Report", "DEFAULT_BUDGET_LOOKBACK_H",
    "DEFAULT_ELIGIBILITY_MULTIPLE", "DEFAULT_FUSED_ALERT_BUDGET", "DEFAULT_MIN_BUDGET_WINDOWS",
    "DEFAULT_MIN_COVERAGE", "DEFAULT_TARGET_FAR", "PROMOTION_STATE_FILE", "STATE_ELIGIBLE",
    "STATE_HELD", "STATE_NOT_ELIGIBLE", "budget_sql", "evaluate", "evidence_from_row",
    "load_state", "measure_rate", "promotion_plan", "save_state",
]
