#!/usr/bin/env python3
"""Fixed-budget evaluation for a model candidate.

USAGE
    python scripts/eval_budget.py --days 7 --budget-per-day 10 \
        --candidate-model HDBSCAN --labels /path/to/labels.json --output /tmp/report.json

Reads the stored population (`ml_window_scores`, written by the calibration shadow pass) and a
candidate (`ml_candidate_scores`). It NEVER writes to either table. A label file is required for
precision/detection; without one the report says so and the promotion gate refuses.

LABEL FILE
    [{"src_addr": "198.51.100.10", "window_start": "2026-11-10T20:00:00",
      "label": "attack", "start": "2026-11-10T19:55:00", "scenario": "port_scan"},
     {"src_addr": "198.51.100.13", "window_start": "2026-11-10T20:00:00",
      "label": "benign"}]

The seeded-attack harness (`scripts/eval_detection.py`) is the source of truth for scenario
coverage; this harness turns its labelled windows and the live population into a same-budget
comparison. Both must agree before a candidate is promoted.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from weirvern.models.evaluation import (  # noqa: E402
    DEFAULT_BASELINE_MODELS,
    Window,
    build_windows,
    labels_from_json,
    load_candidate_scores,
    load_window_scores,
    measure,
    promote,
)


def _print_report(baseline, candidate, decision) -> None:
    print("# Fixed-budget evaluation")
    print()
    print(f"budget: {baseline.budget_per_day} alerts/day · days: {baseline.days} · "
          f"windows: {baseline.windows}")
    print()
    print("| metric | baseline | candidate |")
    print("|---|---:|---:|")
    for key in ("selected", "alerts_per_day", "raw_alerts_per_day", "precision",
                "detection_rate", "false_alarms_per_host_day", "episode_count",
                "latency_min", "explanation_coverage"):
        b = getattr(baseline, key)
        c = getattr(candidate, key)
        print(f"| {key} | {b if b is not None else 'not measured'} | "
              f"{c if c is not None else 'not measured'} |")
    print()
    print(f"decision: {'PROMOTE' if decision.promote else 'REJECT'}")
    for reason in decision.reasons:
        print(f"- {reason}")
    print()
    print("baseline distribution:", json.dumps(baseline.distribution, sort_keys=True))
    print("candidate distribution:", json.dumps(candidate.distribution, sort_keys=True))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--days", type=int, default=7)
    ap.add_argument("--budget-per-day", type=int, default=10)
    ap.add_argument("--baseline-models", default=",".join(DEFAULT_BASELINE_MODELS))
    ap.add_argument("--candidate-model", default="HDBSCAN")
    ap.add_argument("--labels", default="")
    ap.add_argument("--output", default="")
    args = ap.parse_args()

    from weirvern import db
    from weirvern.config import Settings

    settings = Settings()
    try:
        client = db.connect(settings, retries=2, delay_s=1)
        client.command("SELECT 1")
    except Exception as exc:  # noqa: BLE001
        print(f"cannot reach ClickHouse: {exc}", file=sys.stderr)
        return 2

    baseline_models = tuple(m.strip() for m in args.baseline_models.split(",") if m.strip())
    if not baseline_models:
        print("--baseline-models cannot be empty", file=sys.stderr)
        return 2
    t0 = time.perf_counter()
    try:
        base_rows = load_window_scores(client, days=args.days, models=baseline_models)
        if args.candidate_model in baseline_models:
            cand_rows = [r for r in base_rows if r.model_name == args.candidate_model]
        else:
            cand_rows = load_candidate_scores(client, args.candidate_model, days=args.days)
    except Exception as exc:  # noqa: BLE001
        print(f"population read failed: {exc}", file=sys.stderr)
        return 2
    if not base_rows:
        print("no baseline population rows in the requested window", file=sys.stderr)
        return 2
    labels = labels_from_json(args.labels) if args.labels else []
    baseline_windows = build_windows(base_rows)
    candidate_scores = {(r.window_start, r.src_addr): r.score for r in cand_rows}
    candidate_windows: dict[tuple, Window] = {}
    for key, window in baseline_windows.items():
        candidate_windows[key] = Window(
            window.window_start, window.src_addr,
            {args.candidate_model: float(candidate_scores.get(key, 0.0))},
        )
    baseline = measure(baseline_windows, models=baseline_models,
                       budget_per_day=args.budget_per_day, name="baseline", labels=labels,
                       days=args.days)
    candidate = measure(candidate_windows, models=(args.candidate_model,),
                        budget_per_day=args.budget_per_day, name=args.candidate_model,
                        labels=labels, days=args.days)
    decision = promote(baseline, candidate)
    elapsed = time.perf_counter() - t0
    _print_report(baseline, candidate, decision)
    print(f"runtime: {elapsed:.2f}s")
    print(f"command: python scripts/eval_budget.py --days {args.days} "
          f"--budget-per-day {args.budget_per_day} --baseline-models {','.join(baseline_models)} "
          f"--candidate-model {args.candidate_model}"
          + (f" --labels {args.labels}" if args.labels else ""))
    if args.output:
        Path(args.output).write_text(json.dumps({
            "baseline": baseline.as_dict(), "candidate": candidate.as_dict(),
            "decision": decision.as_dict(), "runtime_s": round(elapsed, 3),
            "command": f"python scripts/eval_budget.py --days {args.days} "
                       f"--budget-per-day {args.budget_per_day}",
        }, indent=2))
    return 0 if decision.promote else 1


if __name__ == "__main__":
    raise SystemExit(main())
