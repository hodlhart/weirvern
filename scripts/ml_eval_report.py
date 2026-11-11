#!/usr/bin/env python3
"""Archive a reproducible fixed-budget evaluation report.

This wraps the JSON produced by `scripts/eval_budget.py`; it does not re-run the harness. The
operator supplies the report inputs, the label corpus and the pinned metadata, and the archive
fails closed on missing corpus, empty population, weak-only labels or a regression against the
previous report.

Usage:
    env -u PYTHONPATH .venv/bin/python scripts/ml_eval_report.py \
      --baseline /tmp/baseline.json --candidate /tmp/candidate.json \
      --decision /tmp/decision.json --labels /tmp/auto_labels.json \
      --seed 42 --scenario-version fnd3-2026-11 --generator-version demo-1.2 \
      --days 7 --budget-per-day 10
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from weirvern.models.eval_report import build_report, file_sha256, write_report  # noqa: E402


def _load(path: Path) -> dict:
    return json.loads(path.read_text())


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--decision", type=Path, required=True)
    parser.add_argument("--labels", type=Path, required=True)
    parser.add_argument("--previous", type=Path)
    parser.add_argument("--seed", default="not recorded")
    parser.add_argument("--scenario-version", default="")
    parser.add_argument("--generator-version", default="")
    parser.add_argument("--auto-label-version", default="")
    parser.add_argument("--days", type=int, default=7)
    parser.add_argument("--budget-per-day", type=int, default=10)
    parser.add_argument("--command", default="")
    parser.add_argument("--out-dir", type=Path, default=ROOT / "docs" / "eval-reports")
    parser.add_argument("--no-write", action="store_true")
    args = parser.parse_args()

    labels = _load(args.labels)
    if not isinstance(labels, list):
        raise SystemExit("--labels must be a JSON list")
    metadata = {
        "command": args.command or " ".join(sys.argv),
        "seed": args.seed,
        "scenario_version": args.scenario_version,
        "generator_version": args.generator_version,
        "auto_label_version": args.auto_label_version or file_sha256(args.labels)[:16],
        "days": args.days,
        "budget_per_day": args.budget_per_day,
    }
    report = build_report(
        baseline=_load(args.baseline), candidate=_load(args.candidate),
        decision=_load(args.decision), labels=labels, metadata=metadata,
        previous=_load(args.previous) if args.previous else None,
        generated_at=datetime.now(UTC),
    )
    if not args.no_write:
        json_path, md_path = write_report(report, args.out_dir)
        report["archive"] = {"json": str(json_path), "markdown": str(md_path)}
    print(json.dumps(report, indent=2, sort_keys=True, default=str))
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
