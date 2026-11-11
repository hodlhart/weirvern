"""PR-3: the automatic decision ledger and the program gate.

The ledger is append-only JSONL: promotion, rejection, freeze and retirement all leave a row with
the policy version, the evidence reference and the review date. The program gate is deliberately
allowed to fail: an unaccounted blocked card or missing model card is not a warning.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

PHASE_BOARDS = ("wv-ml-truth", "wv-ml-candidates", "wv-ml-promotion", "wv-ml-ops")
DONE = "done"
RETIRE_AFTER_FAILED_REVIEWS = 2


def append(path: Path, entry: dict[str, Any]) -> dict[str, Any]:
    path.parent.mkdir(parents=True, exist_ok=True)
    body = dict(entry)
    body.setdefault("recorded_at", datetime.now(UTC).isoformat())
    with open(path, "a") as fh:
        fh.write(json.dumps(body, sort_keys=True, default=str) + "\n")
    return body


def read(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    out = []
    for line in path.read_text().splitlines():
        if not line.strip():
            continue
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    return out


def _field(row: dict[str, Any], key: str, default: Any = "") -> Any:
    try:
        return row[key]
    except KeyError:
        return default


def retirement_decision(reviews: list[dict[str, Any]]) -> dict[str, Any]:
    """Two consecutive failed reviews retire a model; no deletion, and the record names why."""
    ordered = sorted(reviews, key=lambda r: str(_field(r, "generated_at")))
    last = ordered[-RETIRE_AFTER_FAILED_REVIEWS:]
    failures = [r for r in last if str(r.get("status") or "").lower() == "fail"]
    if len(last) == RETIRE_AFTER_FAILED_REVIEWS and len(failures) == RETIRE_AFTER_FAILED_REVIEWS:
        return {"retire": True, "reason": "two consecutive failed reviews",
                "review_ids": [_field(r, "review_id") for r in last]}
    return {"retire": False, "reason": "retirement threshold not met", "review_ids": []}


def gate(*, boards: dict[str, list[dict[str, Any]]], model_cards: list[dict[str, Any]],
         verification: dict[str, Any] | None = None,
         expected_boards: tuple[str, ...] = PHASE_BOARDS) -> dict[str, Any]:
    blocked: list[dict[str, str]] = []
    for board in expected_boards:
        cards = boards.get(board)
        if cards is None or not cards:
            blocked.append({"board": board, "id": "—", "title": "board missing or empty",
                            "status": "missing"})
            continue
        for card in cards:
            status = str(card.get("status") or "unknown").lower()
            if status != DONE:
                blocked.append({"board": board, "id": str(card.get("id") or "—"),
                                "title": str(card.get("title") or "untitled"),
                                "status": status})
    missing_cards = [str(c.get("model_name") or "unnamed")
                     for c in model_cards if not c.get("status") or not c.get("artifact_hash")]
    verify_failures: list[str] = []
    if not verification:
        verify_failures.append("verification evidence is missing")
    else:
        if int(verification.get("verified_attack_windows") or 0) < 1:
            verify_failures.append("no verified attack windows")
        if float(verification.get("verified_negative_hours") or 0) <= 0:
            verify_failures.append("no verified negative hours")
    failures = [f"{b['board']} {b['id']} {b['title']} ({b['status']})" for b in blocked]
    failures += [f"model card missing identity: {name}" for name in missing_cards]
    failures += verify_failures
    return {
        "status": "pass" if not failures else "fail",
        "failures": failures,
        "blocked_cards": blocked,
        "missing_model_cards": missing_cards,
        "verification_failures": verify_failures,
        "gate_version": "pr3-v1",
    }


__all__ = ["PHASE_BOARDS", "RETIRE_AFTER_FAILED_REVIEWS", "append", "gate", "read",
           "retirement_decision"]
