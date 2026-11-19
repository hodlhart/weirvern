"""What the Detectors table says, derived from evidence and nothing else.

WHY THIS MODULE EXISTS. The Models tab used to answer "is this detector contributing?" from
`ml_model_cards.status`, a hand-curated value seeded once and edited only when somebody remembered
to. It went stale the moment the engine retrained: DBSCAN's card still said `retired` while DBSCAN
was training every six hours and writing a new artifact. An operator read "retired" beside a training
timestamp from that morning and could not tell which one to believe.

SO THE STORED STATUS IS NOT EVIDENCE. Four facts are, and each comes from a different place:

  * a training row in `ml_models` (the engine's own log, one per training);
  * an artifact on disk (the engine only writes one after a successful fit);
  * a calibration row measuring the false-alarm rate against its target;
  * the card registry, which keeps its existing VETO: a model whose card is not `production` is
    barred from the fused score. That is the one thing the card is still allowed to say, and it
    can only say no -- the word `retired` is never rendered, because the card is not the authority
    on whether a detector runs. The engine training it is.

The rule is deliberately fail-closed on calibration: a model with no row is not contributing,
because an unmeasured false-alarm rate is not a met budget. `eligibility_from_rows` already returns
only the models it saw, so asking it for a name it did not return is how the missing row becomes
"no" without a second convention.

Pure functions, no client: the caller reads the four sources and passes them in, which is what lets
the tests exercise every status without a live ClickHouse.
"""
from __future__ import annotations

import math
from typing import Any

from weirvern.config import FUSED_MODEL
from weirvern.models.calibration import eligibility_from_rows
from weirvern.models.cards import production_allowed

# The policy target when no calibration row carries one. Mirrors `Settings.ml_target_far`; the
# caller passes the live setting so an environment override is not silently replaced by this.
DEFAULT_TARGET_FAR = 0.01
DEFAULT_ELIGIBILITY_MULTIPLE = 3.0
# The share of the vector that must be measured for a calibration to be evidence about the
# detector. Mirrors models.missing.DEFAULT_MIN_COVERAGE and Settings.ml_min_feature_coverage;
# the caller passes the live setting so an override is never silently replaced by this.
DEFAULT_MIN_COVERAGE = 0.15

NOT_TRAINED = "not trained"
CONTRIBUTING = "contributing"
BARRED = "trained, barred by model card"
# THE FIFTH STATE. A detector can be trained, correctly calibrated and within its false-alarm
# budget, and still have no opinion about most of the traffic because most of its vector was
# never measured. That is a different fact from "not contributing" (a measured overrun) and
# from "not trained", and rendering it as either would send an operator to the wrong remedy.
INSUFFICIENT_TELEMETRY = "insufficient telemetry — no score"


def _number(value: Any) -> float | None:
    """A finite float, or None. A blank/garbage cell is absence, never zero."""
    try:
        out = float(value)
    except (TypeError, ValueError):
        return None
    return out if math.isfinite(out) else None


def _trained_at(training: dict[str, Any] | None) -> str:
    return str((training or {}).get("trained_at") or "")


def detector_status(row: dict[str, Any]) -> str:
    """The one status sentence, derived from the row's evidence.

    ORDER MATTERS. A detector that never trained and left no artifact says so before anything
    else, because a false-alarm rate for a model that does not exist would be a measurement of
    nothing. Then coverage: a calibration measured over a population that was mostly imputed
    is not evidence about the detector's false-alarm rate, so it is reported as insufficient
    telemetry rather than as a budget overrun or a pass. Next the measured budget, then the
    card veto: a model can be within its budget and still barred, and saying "not contributing"
    alone would hide which gate stopped it.

    A missing calibration row is worded as such. It must NOT print a number, and it must not
    borrow the target as if a measurement had happened -- `0.00 vs 0.01` would read as a pass.
    """
    observed = _number(row.get("observed_far"))
    target = _number(row.get("target_far"))
    if not row.get("trained") and not row.get("artifact_version"):
        return NOT_TRAINED
    cov = _number(row.get("coverage"))
    floor = _number(row.get("min_coverage"))
    if cov is not None and floor is not None and cov < floor:
        return INSUFFICIENT_TELEMETRY
    if not row.get("eligible"):
        prefix = "trained, " if row.get("trained") else ""
        if row.get("calibration_stale"):
            return prefix + "not contributing (calibration older than the artifact)"
        if observed is None or target is None:
            return prefix + "not contributing (no calibration row)"
        return f"{prefix}not contributing (FAR {observed:.2f} vs {target:.2f})"
    if row.get("barred"):
        return BARRED
    return CONTRIBUTING


def _stamp(value: Any) -> str:
    """A comparable timestamp from either spelling, or "" when there is nothing to compare.

    `ml_models.trained_at` can arrive as `2026-11-19 08:21:17` and calibration as ISO with a `T`.
    Comparing the two spellings as raw strings would order them wrongly, so both are normalised to
    the same `YYYY-MM-DD HH:MM:SS` shape before the holdout lock looks at them.
    """
    text = str(value or "").strip().replace("T", " ")
    return text[:19]


def detector_rows(
    training: dict[str, dict[str, Any]],
    artifacts: dict[str, dict[str, Any]],
    calibration: dict[str, dict[str, Any]],
    card_statuses: dict[str, str],
    *,
    target_far: float = DEFAULT_TARGET_FAR,
    multiple: float = DEFAULT_ELIGIBILITY_MULTIPLE,
    min_coverage: float = DEFAULT_MIN_COVERAGE,
) -> list[dict[str, Any]]:
    """One row per detector the ENGINE knows, from the union of its log and the calibration.

    `card_statuses` is `model_name -> status` straight from the registry. It is consumed only by
    `production_allowed`, so the string `retired` can influence `barred` and can never reach the
    rendered row: `status` is computed from `barred`, not copied from the card.

    THE UNION IS BY NAME, and `__fused__` is excluded: it is the decision's own score, not a
    detector, and it would otherwise appear as a fifth row nobody can retrain.
    """
    allowed = production_allowed(card_statuses)
    names = (set(training) | set(calibration)) - {FUSED_MODEL}
    cal_rows = [
        (name, (calibration.get(name) or {}).get("observed_far"),
         (calibration.get(name) or {}).get("target_far"))
        for name in sorted(names)
    ]
    eligible = eligibility_from_rows(cal_rows, float(target_far), float(multiple))

    rows: list[dict[str, Any]] = []
    for name in sorted(names):
        trained = _trained_at(training.get(name))
        artifact = artifacts.get(name) or {}
        cal = calibration.get(name) or {}
        observed = _number(cal.get("observed_far"))
        measured_target = _number(cal.get("target_far"))
        measured_coverage = _number(cal.get("coverage"))
        is_trained = bool(trained)
        is_barred = not bool(allowed.get(name, False))
        is_eligible = bool(eligible.get(name, False))
        # INSUFFICIENT TELEMETRY IS NOT A PASS AND NOT AN OVERRUN. A calibration whose reference
        # population sat below the coverage floor measured the imputer, not the detector; it
        # cannot make the model eligible, and the row says so in words rather than borrowing a
        # false-alarm rate that has no denominator behind it.
        insufficient = bool(measured_coverage is not None
                            and measured_coverage < float(min_coverage))
        if insufficient:
            is_eligible = False
        # THE HOLDOUT LOCK (calibration.eligibility's rule, kept in step here): a calibration
        # computed BEFORE the newest artifact is not evidence about the model serving now. Without
        # this the table could call a just-retrained model contributing on its predecessor's score.
        cal_when = _stamp(cal.get("computed_at"))
        train_when = _stamp(trained)
        calibration_stale = bool(train_when and cal_when and cal_when < train_when)
        if calibration_stale:
            is_eligible = False
        row: dict[str, Any] = {
            "name": name,
            "trained_at": trained,
            "samples": int((training.get(name) or {}).get("samples") or 0),
            "artifact_written_at": str(artifact.get("written_at") or ""),
            "observed_far": observed,
            # A model with no calibration row still shows the policy target it will be measured
            # against, so the column is never a bare number and never an empty promise.
            "target_far": measured_target if measured_target is not None else float(target_far),
            "eligible": is_eligible,
            # THE COVERAGE EVIDENCE, carried on the row so the status is derived from a number
            # rather than from a sentence, and so the table can show why it said what it said.
            "coverage": measured_coverage,
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
        row["barred"] = is_barred
        row["calibration_stale"] = calibration_stale
        row["insufficient_telemetry"] = insufficient
        row["contributing"] = bool(is_trained and is_eligible and not is_barred)
        row["status"] = detector_status(row)
        rows.append(row)
    return rows


def detector_summary(rows: list[dict[str, Any]],
                     fused: dict[str, Any] | None) -> str:
    """One line: how many detectors contribute, then the fused score against its target.

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
    head = f"{total} detector{'s' if total != 1 else ''}: {contributing} contributing."
    observed = _number((fused or {}).get("observed_far"))
    target = _number((fused or {}).get("target_far"))
    if observed is None or target is None:
        return f"{head} Nothing measured yet: the fused score has no calibration row."
    return f"{head} Fused false-alarm rate {observed:.2f} against a {target:.2f} target."


__all__ = [
    "BARRED", "CONTRIBUTING", "DEFAULT_ELIGIBILITY_MULTIPLE", "DEFAULT_MIN_COVERAGE",
    "DEFAULT_TARGET_FAR", "INSUFFICIENT_TELEMETRY", "NOT_TRAINED",
    "detector_rows", "detector_status", "detector_summary",
]
