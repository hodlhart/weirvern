#!/usr/bin/env python3
"""Run and archive the monthly ML program review.

Usage:
    env -u PYTHONPATH .venv/bin/python scripts/ml_monthly_review.py
    ... --verification /path/to/verification.json --no-write
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from weirvern.config import Settings  # noqa: E402
from weirvern.db import connect  # noqa: E402
from weirvern.models import cards, quality, review, source_coverage  # noqa: E402


def _boards() -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = {}
    for board in review.PHASE_BOARDS:
        try:
            proc = subprocess.run(
                ["hermes", "kanban", "--board", board, "list", "--json"],
                capture_output=True, text=True, timeout=20,
            )
            if proc.returncode != 0:
                continue
            data = json.loads(proc.stdout or "[]")
            out[board] = data if isinstance(data, list) else []
        except (OSError, subprocess.TimeoutExpired, ValueError):
            continue
    return out


def _calibration(client: Any) -> list[dict[str, Any]]:
    try:
        rows = client.query(
            "SELECT model_name, model_version, observed_far, target_far, computed_at "
            "FROM weirvern.ml_calibration FINAL ORDER BY computed_at DESC LIMIT 20"
        ).result_rows
    except Exception:  # noqa: BLE001
        return []
    names = ("model_name", "model_version", "observed_far", "target_far", "computed_at")
    return [dict(zip(names, row, strict=False)) for row in rows]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--verification", type=Path,
                        help="JSON with verified_attack_windows, verified_negative_hours, "
                             "generator_version")
    parser.add_argument("--out-dir", type=Path, default=ROOT / "docs" / "reviews")
    parser.add_argument("--no-write", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    verification = None
    if args.verification:
        verification = json.loads(args.verification.read_text())

    settings = Settings()
    client = connect(settings, retries=3, delay_s=1.0)
    try:
        slo = quality.report(client)
        coverage = source_coverage.collect(client)
        card_rows = cards.current_cards(client)
        calibration = _calibration(client)
    finally:
        client.close()

    now = datetime.now(UTC)
    next_review = (now + timedelta(days=30)).date().isoformat()
    # A review is a tracked document. Host addresses belong in the live view, not in a file
    # that gets committed: the sanitation gate rejects real private addresses in the tree.
    # Keep the unknown-role COUNT; the names stay available from /api/ml/coverage.
    roles = coverage.get("roles")
    if isinstance(roles, dict):
        roles["top_unknown"] = []
        roles["top_unknown_redacted"] = "live view only; not written to the archive"
    report = review.build_report(
        generated_at=now, boards=_boards(), slo=slo, coverage=coverage,
        cards=card_rows, calibration=calibration, verification=verification,
        next_review=next_review,
    )
    if not args.no_write:
        json_path, md_path = review.write_report(report, args.out_dir)
        report["archive"] = {"json": str(json_path), "markdown": str(md_path)}
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(review.render_markdown(report))
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
