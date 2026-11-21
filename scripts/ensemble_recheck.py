#!/usr/bin/env python3
"""Re-check the five-detector ensemble and the fused rate against the live deployment.

WHY THIS EXISTS. The Models card and the Ripples card must report MEASURED state, not the last
known one. This script runs the same eligibility evaluation the worker runs (`persist=False`,
read-only), prints every detector's state with the numbers the sentence was made from, and
measures the fused alert rate on the freshest population the deployment actually holds.

WHAT IT REPORTS
  * per detector: eligibility state and reason; FAR with its Wilson 95% interval and n; the
    calibration's age; the coverage the gate saw; the conformal threshold; and the newest pooled
    row even when it is not the newest row in the table (which is how a detector that stopped
    being calibrated shows up as stale rather than absent).
  * the fused rate: the share of host-windows whose fused decision score is at or above the bar,
    with n and a Wilson interval, against the 1% target and the 30% alert budget, plus the age and
    size of the population it was measured on.

RUN (inside the worker pod):

    kubectl -n weirvern exec deploy/weirvern-worker -- python3 /tmp/ensemble_recheck.py \
        --out /tmp/ensemble_recheck.json
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import UTC, datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from weirvern import db  # noqa: E402
from weirvern.config import FUSED_MODEL, Settings  # noqa: E402
from weirvern.models import eligibility  # noqa: E402
from weirvern.models.detectors import DETECTOR_NAMES  # noqa: E402
from weirvern.models.eval_report import wilson  # noqa: E402


def _bounds(successes: int, total: int) -> list[float] | None:
    if total <= 0:
        return None
    out = wilson(successes, total)
    return None if out is None else [round(float(value), 6) for value in out]


def _newest_rows(client, scope: str) -> dict[str, dict]:
    """The newest row per model in `scope`, with the age ClickHouse measured."""
    rows = client.query(
        "SELECT model_name, computed_at, dateDiff('second', computed_at, now()) / 3600.0 AS age_h, "
        "       observed_far, far_lower, far_upper, validation_count, threshold, coverage, "
        "       coverage_observed, coverage_expected, reference_source "
        "FROM weirvern.ml_calibration FINAL WHERE scope = %(scope)s "
        "ORDER BY model_name, computed_at DESC",
        parameters={"scope": scope},
    ).result_rows
    out: dict[str, dict] = {}
    for row in rows:
        name = str(row[0])
        if name in out:
            continue
        out[name] = {
            "computed_at": str(row[1]), "age_hours": round(float(row[2] or 0.0), 3),
            "observed_far": None if row[3] is None else round(float(row[3]), 6),
            "far_lower": None if row[4] is None else round(float(row[4]), 6),
            "far_upper": None if row[5] is None else round(float(row[5]), 6),
            "validation_count": None if row[6] is None else int(row[6]),
            "threshold": None if row[7] is None else round(float(row[7]), 6),
            "coverage": None if row[8] is None else round(float(row[8]), 6),
            "coverage_observed": None if row[9] is None else int(row[9]),
            "coverage_expected": None if row[10] is None else int(row[10]),
            "reference_source": str(row[11] or ""),
        }
    return out


def _fused_rate(client, *, bar: float, hours: int | None = None) -> dict:
    """The share of host-windows at/above `bar` on the newest stored fused score.

    `hours` restricts the measurement to the freshest N hours of WINDOW time (anchored on the
    newest window, not on `now`): a stalled collector must not make an old population look new,
    and the whole-table rate and the freshest-day rate answer different questions.
    """
    where = ""
    parameters: dict = {"bar": float(bar), "name": FUSED_MODEL}
    if hours is not None:
        where = (" AND window_start >= (SELECT max(window_start) - INTERVAL %(hours)s HOUR "
                 "FROM weirvern.ml_window_scores WHERE model_name = %(name)s)")
        parameters["hours"] = int(hours)
    got = client.query(
        "SELECT count(), countIf(score >= %(bar)s), min(window_start), max(window_start), "
        "       max(computed_at) "
        "FROM weirvern.ml_window_scores WHERE model_name = %(name)s" + where,
        parameters=parameters,
    ).result_rows
    windows, hits, first, last, computed = (list(got[0]) + [None] * 5)[:5] if got else [0] * 5
    windows, hits = int(windows or 0), int(hits or 0)
    return {
        "bar": float(bar), "windows": windows, "hits": hits,
        "rate": round(hits / windows, 6) if windows else None,
        "rate_interval": _bounds(hits, windows),
        "hours": hours,
        "first_window": str(first) if first else None,
        "last_window": str(last) if last else None,
        "computed_at": str(computed) if computed else None,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default="/tmp/ensemble_recheck.json")
    args = parser.parse_args()

    settings = Settings()
    client = db.connect(settings, retries=3, delay_s=2.0)
    target = float(getattr(settings, "ml_target_far", 0.01) or 0.01)
    budget = float(getattr(settings, "ml_fused_alert_budget", 0.30) or 0.30)
    bar = float(getattr(settings, "base_threshold", 0.35) or 0.35)

    report = eligibility.evaluate(client, settings, names=DETECTOR_NAMES, persist=False)
    pooled = _newest_rows(client, "global")
    coverage_rows = _newest_rows(client, "coverage")

    detectors: dict[str, dict] = {}
    for name in DETECTOR_NAMES:
        decision = report.decisions.get(name)
        evidence = decision.evidence if decision is not None else None
        row = pooled.get(name)
        detectors[name] = {
            "state": decision.state if decision is not None else "no-decision",
            "sentence": decision.sentence() if decision is not None else "",
            "contributing": bool(decision.contributing) if decision is not None else False,
            "reason": decision.reason if decision is not None else "",
            "far": None if evidence is None or evidence.observed_far is None
                   else round(float(evidence.observed_far), 6),
            "far_lower": None if evidence is None or evidence.far_lower is None
                         else round(float(evidence.far_lower), 6),
            "far_upper": None if evidence is None or evidence.far_upper is None
                         else round(float(evidence.far_upper), 6),
            "validation_count": None if evidence is None else evidence.validation_count,
            "age_hours": None if evidence is None or evidence.age_hours is None
                         else round(float(evidence.age_hours), 3),
            "coverage": None if evidence is None or evidence.coverage is None
                        else round(float(evidence.coverage), 6),
            "coverage_observed": None if evidence is None else evidence.coverage_observed,
            "coverage_expected": None if evidence is None else evidence.coverage_expected,
            "threshold": None if evidence is None or evidence.threshold is None
                         else round(float(evidence.threshold), 6),
            "calibrating": bool(decision.calibrating) if decision is not None else False,
            # THE TABLE'S OWN NEWEST ROW, which may be older than the pooled snapshot. This is
            # how a detector that stopped being calibrated is visible instead of absent.
            "newest_pooled_row": row,
            "newest_coverage_row": coverage_rows.get(name),
        }
    fused_calibration = pooled.get(FUSED_MODEL)
    fused_bar = (fused_calibration or {}).get("threshold") or bar
    payload = {
        "generated_at": datetime.now(UTC).isoformat(),
        "roster": list(DETECTOR_NAMES),
        "declared_detectors": len(DETECTOR_NAMES),
        "target_far": target,
        "eligibility_multiple": float(getattr(settings, "ml_eligibility_multiple", 3.0) or 3.0),
        "tolerance": round(target * float(getattr(settings, "ml_eligibility_multiple", 3.0)
                                          or 3.0), 6),
        "fused_alert_budget": budget,
        "base_threshold": bar,
        "eligibility_report": {
            "budget": report.budget, "bar": report.bar, "windows": report.windows,
            "seeded": report.seeded, "contributing": report.contributing_names(),
            "thresholds": {name: round(value, 6) for name, value in report.thresholds.items()},
        },
        "detectors": detectors,
        "fused": {
            "calibration": fused_calibration,
            "rate_at_base_threshold": _fused_rate(client, bar=bar),
            "rate_at_fused_threshold": _fused_rate(client, bar=float(fused_bar)),
            "freshest_24h_at_base_threshold": _fused_rate(client, bar=bar, hours=24),
            "freshest_24h_at_fused_threshold": _fused_rate(client, bar=float(fused_bar),
                                                           hours=24),
            "target_far": target,
            "alert_budget": budget,
        },
    }
    text = json.dumps(payload, indent=2, sort_keys=True, default=str)
    with open(args.out, "w", encoding="utf-8") as handle:
        handle.write(text + "\n")
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
