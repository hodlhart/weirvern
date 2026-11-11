#!/usr/bin/env python3
"""One automatic promotion tick: read canary evidence, decide, append the ledger.

The caller (cron or the worker's policy loop) supplies the evidence JSON. This script never asks
for approval and never edits a model card directly; it records the action that the policy chose.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from weirvern.models import ledger, promotion  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--evidence", type=Path, required=True)
    ap.add_argument("--ledger", type=Path, default=ROOT / "docs" / "ledger" / "ml-decisions.jsonl")
    ap.add_argument("--current-status", default="canary")
    args = ap.parse_args()
    raw = json.loads(args.evidence.read_text())
    evidence = promotion.CanaryEvidence(**raw)
    decision = promotion.decide(evidence)
    entry = promotion.ledger_entry(
        decision, previous_status=args.current_status,
        next_status=promotion.next_card_status(args.current_status, decision["action"]),
    )
    ledger.append(args.ledger, entry)
    print(json.dumps(entry, indent=2, sort_keys=True))
    return 0 if decision["action"] == "promote" else 1


if __name__ == "__main__":
    raise SystemExit(main())
