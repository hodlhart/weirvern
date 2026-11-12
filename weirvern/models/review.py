"""OP-3: the monthly program review is a decision record, not a dashboard screenshot.

A review that passes while a phase card is blocked is a lie with a timestamp. This module keeps
the failure reason in the same object as the numbers, so the archive can be read later without
reconstructing which board was incomplete.
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

# ONE source of truth for the phase set: the gate and the review must judge the same boards,
# or a review can pass while the gate fails on a board it never looked at.
from weirvern.models.ledger import PHASE_BOARDS  # noqa: E402

DONE = "done"


def _phase_failures(boards: dict[str, list[dict[str, Any]]],
                    expected: tuple[str, ...]) -> list[dict[str, str]]:
    failures: list[dict[str, str]] = []
    for board in expected:
        cards = boards.get(board)
        if cards is None:
            failures.append({"board": board, "id": "—", "title": "board not found",
                             "status": "missing"})
            continue
        if not cards:
            failures.append({"board": board, "id": "—", "title": "board has no cards",
                             "status": "missing"})
            continue
        for card in cards:
            status = str(card.get("status") or "unknown").lower()
            if status != DONE:
                failures.append({
                    "board": board,
                    "id": str(card.get("id") or "—"),
                    "title": str(card.get("title") or "untitled"),
                    "status": status,
                })
    return failures


def _verification_failures(verification: dict[str, Any] | None) -> list[str]:
    if not verification:
        return ["verification report is missing; unlabelled zero is not a clean result"]
    reasons: list[str] = []
    if not verification.get("available"):
        reasons.append("verification report is unavailable")
    try:
        attacks = int(verification.get("verified_attack_windows") or 0)
        negative_hours = float(verification.get("verified_negative_hours") or 0)
    except (TypeError, ValueError):
        attacks, negative_hours = 0, 0.0
    if attacks < 1:
        reasons.append("no verified attack windows")
    if negative_hours <= 0:
        reasons.append("no verified negative hours")
    if not verification.get("generator_version"):
        reasons.append("generator version is not recorded")
    return reasons


def build_report(*, generated_at: datetime, boards: dict[str, list[dict[str, Any]]],
                 slo: dict[str, Any], coverage: dict[str, Any],
                 cards: list[dict[str, Any]], calibration: list[dict[str, Any]],
                 verification: dict[str, Any] | None = None,
                 expected_boards: tuple[str, ...] = PHASE_BOARDS,
                 next_review: str | None = None,
                 review_id: str | None = None) -> dict[str, Any]:
    phase = _phase_failures(boards, expected_boards)
    verify_reasons = _verification_failures(verification)
    failures = [f"{f['board']} {f['id']} {f['title']} ({f['status']})" for f in phase]
    failures.extend(verify_reasons)
    status = "pass" if not failures else "fail"
    return {
        "review_id": review_id or generated_at.strftime("ml-program-%Y-%m-%d"),
        "generated_at": generated_at.isoformat(),
        "next_review": next_review,
        "status": status,
        "failures": failures,
        "blocked_cards": phase,
        "verification_failures": verify_reasons,
        "slo": slo,
        "coverage": coverage,
        "model_cards": cards,
        "calibration": calibration,
        "verification": verification or {"available": False, "reason": "not supplied"},
        "decision": ("continue" if status == "pass" else
                     "fix: complete the named phase cards and attach verified evidence"),
        "note": "A model is never deleted by this review; retirement is a status and a provenance trail.",
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        f"# ML program review — {report['generated_at'][:10]}",
        "",
        f"- **Status:** {report['status']}",
        f"- **Review id:** `{report['review_id']}`",
        f"- **Next review:** {report.get('next_review') or 'not scheduled'}",
        f"- **Decision:** {report['decision']}",
        "",
        "## Failures",
    ]
    lines += [f"- {item}" for item in report["failures"]] or ["- none"]
    lines += ["", "## Blocked or missing phase cards"]
    if report["blocked_cards"]:
        lines += [f"- `{c['id']}` [{c['board']}] {c['title']} — **{c['status']}**"
                  for c in report["blocked_cards"]]
    else:
        lines.append("- none")
    lines += ["", "## Sources"]
    for source in (report.get("coverage") or {}).get("sources", []):
        lines.append(f"- {source.get('name')}: rows={source.get('rows')} state={source.get('state')} "
                     f"usable={source.get('usable')}")
    lines += ["", "## Model cards"]
    for card in report.get("model_cards") or []:
        lines.append(f"- {card.get('model_name')}: {card.get('status')} "
                     f"hash={card.get('artifact_hash')}")
    lines += ["", "## Verification", f"- {report['verification']}", ""]
    return "\n".join(lines)


def write_report(report: dict[str, Any], out_dir: Path) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    base = out_dir / report["review_id"]
    json_path = base.with_suffix(".json")
    md_path = base.with_suffix(".md")
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True, default=str) + "\n")
    md_path.write_text(render_markdown(report))
    return json_path, md_path


def latest_report(root: Path) -> dict[str, Any]:
    directory = root / "docs" / "reviews"
    files = sorted(directory.glob("ml-program-*.json"))
    if not files:
        return {"available": False, "reason": "no archived monthly review"}
    try:
        data = json.loads(files[-1].read_text())
    except (OSError, ValueError) as exc:
        return {"available": False, "reason": f"latest review is unreadable: {type(exc).__name__}"}
    data["available"] = True
    data["path"] = str(files[-1])
    return data


__all__ = ["PHASE_BOARDS", "build_report", "latest_report", "render_markdown", "write_report"]
