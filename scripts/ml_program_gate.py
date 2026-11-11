#!/usr/bin/env python3
"""Run the PR-3 program gate and append its result to the ML decision ledger.

The gate is read-only. It fails on every non-done phase card, a model card without identity and
missing verification evidence; the failure is the output, not an exception.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from weirvern.models import ledger  # noqa: E402


def _boards() -> dict[str, list[dict]]:
    out = {}
    for board in ledger.PHASE_BOARDS:
        try:
            proc = subprocess.run(
                ["hermes", "kanban", "--board", board, "list", "--json"],
                capture_output=True, text=True, timeout=20,
            )
            out[board] = json.loads(proc.stdout or "[]") if proc.returncode == 0 else []
        except (OSError, subprocess.TimeoutExpired, ValueError):
            out[board] = []
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ledger", type=Path, default=ROOT / "docs" / "ledger" / "ml-decisions.jsonl")
    ap.add_argument("--model-cards", type=Path,
                    help="JSON list of model cards; omitted means no cards are available")
    ap.add_argument("--verification", type=Path,
                    help="JSON with verified_attack_windows and verified_negative_hours")
    ap.add_argument("--out", type=Path, default=ROOT / "docs" / "ledger" / "program-gate.json")
    args = ap.parse_args()
    cards = json.loads(args.model_cards.read_text()) if args.model_cards else []
    verification = json.loads(args.verification.read_text()) if args.verification else None
    result = ledger.gate(boards=_boards(), model_cards=cards, verification=verification)
    result.update({"kind": "program-gate", "generated_at": datetime.now(UTC).isoformat()})
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2, sort_keys=True, default=str) + "\n")
    ledger.append(args.ledger, result)
    print(json.dumps(result, indent=2, sort_keys=True, default=str))
    return 0 if result["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
