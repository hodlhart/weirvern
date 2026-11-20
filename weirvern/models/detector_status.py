"""What the Detectors table says, derived from evidence and nothing else.

WHY THIS MODULE EXISTS. The Models tab used to answer "is this detector contributing?" from
`ml_model_cards.status`, a hand-curated value seeded once and edited only when somebody remembered
to. It went stale the moment the engine retrained, and on 2026-11-20 it had no row at all for the
two cross-sectional detectors -- so they were barred by ABSENCE, not by any measurement. A card is a
statement of intent (owner, approved version, rollback); it is documentation, not a gate.

WHAT IS EVIDENCE. Four facts, each from a different place:

  * a training row in `ml_models` (the engine's own log, one per training);
  * an artifact on disk (the engine only writes one after a successful fit);
  * a calibration row that records its own COVERAGE (observed/expected, never NULL), so a
    false-alarm rate can be read with the vector it was measured on;
  * the promotion guard's measured decision (`models.eligibility`): whether adding this detector
    keeps the fused alert rate inside the configured budget.

The rule is deliberately fail-closed on those measurements: a model with no row, or with a row that
never recorded its coverage, is not contributing, because an unmeasured false-alarm rate is not a
met budget. The STATUS sentence names the missing fact (`not contributing: coverage not recorded`)
rather than borrowing a number, so the operator is sent to the right remedy.

A model removed from the engine does not appear at all. The caller passes the engine's roster
(`detectors.DETECTOR_NAMES`), so a name that only survives in the training log -- a detector that no
longer exists -- cannot be resurrected as a row. That is what "removed" means: no row, not a row
that says retired.

Pure functions, no client: the caller reads the sources and passes them in, which is what lets the
tests exercise every status without a live ClickHouse.
"""
from __future__ import annotations

import math
from dataclasses import replace
from typing import Any

from weirvern.config import FUSED_MODEL
from weirvern.models.eligibility import (
    STATE_ELIGIBLE,
    STATE_HELD,
    STATE_NOT_ELIGIBLE,
    Decision,
    evidence_from_row,
)

# The policy target when no calibration row carries one. Mirrors `Settings.ml_target_far`; the
# caller passes the live setting so an environment override is never silently replaced by this.
DEFAULT_TARGET_FAR = 0.01
DEFAULT_ELIGIBILITY_MULTIPLE = 3.0
# The share of the vector that must be measured for a calibration to be evidence about the
# detector. Mirrors models.missing.DEFAULT_MIN_COVERAGE and Settings.ml_min_feature_coverage;
# the caller passes the live setting so an override is never silently replaced by this.
DEFAULT_MIN_COVERAGE = 0.15
DEFAULT_RETRAIN_EVERY_H = 6.0
DEFAULT_GRACE_H = 1.0

NOT_TRAINED = "not trained"
ELIGIBLE = "eligible"
# A REFUSED FIT IS NOT A QUIET DETECTOR. A cross-sectional model whose reference cannot produce a
# distinguishable score is refused at train time (no artifact, no calibration row). Reporting that
# as "not trained" would be indistinguishable from a model that has not been reached yet, and
# reporting it as anything resembling "eligible" would be a lie about a score nobody has.
REFUSED = "not trained: degenerate reference"
# A detector can be trained, correctly calibrated and within its false-alarm budget, and still have
# no opinion about most of the traffic because most of its vector was never measured. That is a
# different fact from "not contributing" (a measured overrun) and from "not trained", and rendering
# it as either would send an operator to the wrong remedy.
INSUFFICIENT_TELEMETRY = "insufficient telemetry — no score"


def _number(value: Any) -> float | None:
    """A finite float, or None. A blank/garbage cell is absence, never zero."""
    try:
        out = float(value)
    except (TypeError, ValueError):
        return None
    return out if math.isfinite(out) else None


def _count(value: Any) -> int | None:
    """A column count, or None. None stays None: an unrecorded count is not zero columns."""
    number = _number(value)
    return None if number is None else int(round(number))


def _trained_at(training: dict[str, Any] | None) -> str:
    return str((training or {}).get("trained_at") or "")


def coverage_note(row: dict[str, Any]) -> str:
    """How much of the detector's vector the calibration was measured on, in words.

    A FALSE-ALARM RATE IS ONLY READABLE BESIDE ITS COVERAGE. '0.0097 against 0.01' sounds like a
    met budget until you learn it was measured on ten of seventy-seven columns, most of them
    imputed. The counts come from the calibration row (measured by `missing.coverage_counts` at
    scoring time); the ratio is only a fallback for rows written before the counts existed.

    A NULL coverage is `coverage not recorded` -- NEVER complete. Rendering an unmeasured vector
    as 77/77 would turn "we did not look" into "we looked at everything", which is the exact
    defect `ml_missing_features` exists to end.
    """
    coverage_value = _number(row.get("coverage"))
    if coverage_value is None:
        return "coverage not recorded"
    detail = str(row.get("coverage_detail") or "").strip()
    observed = expected = None
    if "/" in detail:
        left, _, right = detail.partition("/")
        try:
            observed, expected = int(round(float(left))), int(round(float(right)))
        except ValueError:
            observed = expected = None
    if observed is None or expected is None or expected <= 0:
        return f"coverage {coverage_value:.2f} (counts not recorded)"
    imputed = max(expected - observed, 0)
    return f"{observed} of {expected} inputs ({imputed} imputed)"


def _stamp(value: Any) -> str:
    """A comparable timestamp from either spelling, or \"\" when there is nothing to compare.

    `ml_models.trained_at` can arrive as `2026-11-19 08:21:17` and calibration as ISO with a `T`.
    Comparing the two spellings as raw strings would order them wrongly, so both are normalised to
    the same `YYYY-MM-DD HH:MM:SS` shape before the holdout lock looks at them.
    """
    return str(value or "").strip().replace("T", " ")[:19]


def detector_rows(
    training: dict[str, dict[str, Any]],
    artifacts: dict[str, dict[str, Any]],
    calibration: dict[str, dict[str, Any]],
    *,
    target_far: float = DEFAULT_TARGET_FAR,
    multiple: float = DEFAULT_ELIGIBILITY_MULTIPLE,
    min_coverage: float = DEFAULT_MIN_COVERAGE,
    outcomes: dict[str, str] | None = None,
    decisions: dict[str, Decision] | None = None,
    known_names: tuple[str, ...] | list[str] | None = None,
    retrain_every_h: float = DEFAULT_RETRAIN_EVERY_H,
    grace_h: float = DEFAULT_GRACE_H,
) -> list[dict[str, Any]]:
    """One row per detector the ENGINE builds, from the union of its log and the calibration.

    `decisions` is `models.eligibility.evaluate`'s output: the promotion guard's measured answer,
    including the two rates behind a `held for budget` sentence. Without it the row still applies
    the evidence rule, but the budget is unreported -- the pure-function callers (tests, a console
    with no score population) do not invent one.

    `known_names` is the engine roster. A name that is no longer built is NOT emitted: a removed
    detector has no row, and the table cannot resurrect one from the training log.

    `outcomes` is `model_name -> last training outcome` from `ml_models` metrics. It is how a
    REFUSED fit (`degenerate-reference`) reaches the table as that sentence instead of as an
    ordinary "not trained".
    """
    outcomes = outcomes or {}
    names = (set(training) | set(calibration)) - {FUSED_MODEL}
    if known_names is not None:
        names &= {str(name) for name in known_names}
    roster = sorted(names)

    rows: list[dict[str, Any]] = []
    for name in roster:
        trained = _trained_at(training.get(name))
        artifact = artifacts.get(name) or {}
        cal = calibration.get(name) or {}
        observed = _number(cal.get("observed_far"))
        measured_target = _number(cal.get("target_far"))
        measured_coverage = _number(cal.get("coverage"))
        outcome = str(outcomes.get(name) or "")
        # A REFUSED FIT IS NOT A TRAINED MODEL. The row exists in the engine's log (it says why),
        # but `training_sample_count` is 0 and no artifact was written; counting the timestamp as
        # "trained" would put a model in the table that cannot score a single window.
        is_trained = bool(trained) and outcome != "degenerate-reference"
        evidence = evidence_from_row(
            name, cal, target_far=target_far, multiple=multiple,
            retrain_every_h=retrain_every_h, grace_h=grace_h, min_coverage=min_coverage)
        # THE HOLDOUT LOCK (calibration.eligibility's rule, kept in step here): a calibration
        # computed BEFORE the newest artifact is not evidence about the model serving now. Without
        # this the table could call a just-retrained model eligible on its predecessor's score.
        cal_when = _stamp(cal.get("computed_at"))
        train_when = _stamp(trained)
        calibration_stale = bool(train_when and cal_when and cal_when < train_when)
        if calibration_stale and evidence.calibrated:
            evidence = replace(evidence, calibrated=False,
                               reason="calibration older than the artifact")
        calibrated = bool(evidence.calibrated)
        decision = (decisions or {}).get(name)
        held = bool(decision is not None and decision.state == STATE_HELD)
        # INSUFFICIENT TELEMETRY IS NOT A PASS AND NOT AN OVERRUN. A calibration whose reference
        # population sat below the coverage floor measured the imputer, not the detector.
        insufficient = bool(measured_coverage is not None
                            and measured_coverage < float(min_coverage))
        contributing = bool(calibrated and not held and not insufficient and is_trained)
        row: dict[str, Any] = {
            "name": name,
            "trained_at": trained if is_trained else "",
            "samples": int((training.get(name) or {}).get("samples") or 0) if is_trained else 0,
            "artifact_written_at": str(artifact.get("written_at") or ""),
            "observed_far": observed,
            # A model with no calibration row still shows the policy target it will be measured
            # against, so the column is never a bare number and never an empty promise.
            "target_far": measured_target if measured_target is not None else float(target_far),
            # THE TOLERANCE IS A COLUMN, NOT A SENTENCE. `target_far` alone cannot tell an operator
            # whether 6.5% is inside the policy: the multiple is what turns a target into a bar.
            "far_tolerance": float(evidence.tolerance or 0.0),
            "eligible": contributing,
            # THE COVERAGE EVIDENCE, carried on the row so the status is derived from a number
            # rather than from a sentence, and so the table can show why it said what it said.
            "coverage": measured_coverage,
            "coverage_detail": str(cal.get("coverage_detail") or ""),
            "coverage_observed": _count(cal.get("coverage_observed")),
            "coverage_expected": _count(cal.get("coverage_expected")),
            "missing_mode": str(cal.get("missing_mode") or ""),
            "excluded_windows": int(_number(cal.get("excluded_windows")) or 0),
        }
        # `min_coverage` is a DERIVED key, not a column: the schema audit's producer scan sees
        # `row["key"] = ...` assignments, so spelling it out is what keeps it from being
        # reported as a name nothing produces.
        row["min_coverage"] = float(min_coverage)
        # THE DERIVED KEYS ARE ASSIGNED, NOT ONLY READ. The schema audit's producer scan sees
        # `row["key"] = ...` and not dict literals, and it is right to: this row is built by a
        # caller and is not a table. Spelling the keys out keeps them from being reported as
        # phantom columns -- the same reason `attach_reviews` assigns its own row keys.
        row["trained"] = is_trained
        row["artifact_version"] = str(artifact.get("version") or "")
        row["calibration_stale"] = calibration_stale
        row["insufficient_telemetry"] = insufficient
        row["calibration_age_h"] = evidence.age_hours
        row["coverage_note"] = coverage_note(row)
        row["status"] = _status(row, evidence=evidence, decision=decision, outcome=outcome)
        # THE SENTENCE AND THE BOOLEAN CANNOT DISAGREE: a row is `contributing` exactly when its
        # status is the eligible sentence. Deriving one from the other is what stops a table that
        # reads "not trained" from counting the model as a contributor.
        contributing = row["status"] == ELIGIBLE
        row["contributing"] = contributing
        row["eligible"] = contributing
        rows.append(row)
    return rows


def _status(row: dict[str, Any], *, evidence: Any, decision: Decision | None,
            outcome: str = "") -> str:
    """The one status sentence, in the order the remedies belong.

    A detector that never trained and left no artifact says so before anything else, because a
    false-alarm rate for a model that does not exist would be a measurement of nothing. Then the
    evidence checks (each names its own missing fact), then the promotion guard's measured decision,
    which is the only state that carries two rates.
    """
    if str(outcome or "") == "degenerate-reference":
        return REFUSED
    if not row.get("trained") and not row.get("artifact_version"):
        return NOT_TRAINED
    if row.get("insufficient_telemetry"):
        return INSUFFICIENT_TELEMETRY
    if decision is not None:
        if decision.state == STATE_HELD:
            return decision.sentence()
        if decision.state == STATE_NOT_ELIGIBLE:
            return f"not contributing: {decision.reason}"
        if decision.state == STATE_ELIGIBLE:
            return ELIGIBLE
        # Any other state (a fusion exclusion) is decided by configuration, and its sentence says
        # which one -- never a budget number it was not judged against.
        return decision.sentence()
    if not evidence.calibrated:
        return f"not contributing: {evidence.reason}"
    return ELIGIBLE


def detector_summary(rows: list[dict[str, Any]],
                     fused: dict[str, Any] | None) -> str:
    """One line: how many detectors are eligible, then the fused score against its target.

    NEVER A NUMBER WITHOUT ITS TARGET. The fused row is the number the decision actually compares,
    so it is quoted with the target it was calibrated for. When there is no fused row the sentence
    says `nothing measured yet` rather than falling back to a count with no reading behind it.

    The count is over the rows given, so the caller can pass the same list the table renders and
    the heading cannot disagree with it.
    """
    total = len(rows)
    contributing = sum(1 for row in rows if row.get("contributing"))
    if not total:
        return "nothing measured yet"
    head = f"{total} detector{'s' if total != 1 else ''}: {contributing} eligible."
    observed = _number((fused or {}).get("observed_far"))
    target = _number((fused or {}).get("target_far"))
    if observed is None or target is None:
        return f"{head} Nothing measured yet: the fused score has no calibration row."
    return f"{head} Fused false-alarm rate {observed:.2f} against a {target:.2f} target."


__all__ = [
    "DEFAULT_ELIGIBILITY_MULTIPLE", "DEFAULT_GRACE_H", "DEFAULT_MIN_COVERAGE",
    "DEFAULT_RETRAIN_EVERY_H", "DEFAULT_TARGET_FAR", "ELIGIBLE", "INSUFFICIENT_TELEMETRY",
    "NOT_TRAINED", "REFUSED", "coverage_note", "detector_rows", "detector_summary",
]
