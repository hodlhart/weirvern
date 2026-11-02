#!/usr/bin/env python3
"""Dry-run/backfill the severity contract for historical anomalies.

The code path decides severity at write time. Rows written before 0.20.0 keep the old label
unless an operator explicitly asks for this script. The default is a DRY RUN: it reports the
before/after counts and writes nothing.

THE FORMULA IS DELIBERATELY THE SAME AS `ensemble.severity_of` where the stored columns allow it:
independent families (IF and GB are one family) plus a material deviation (critical >=3σ,
high >=2σ). A novelty observation was never stored for historical rows, so this backfill can
only be MORE conservative than the live path; it cannot invent a novelty that was not recorded.
State that in the card result.

Usage:
    python scripts/backfill_ml_severity.py --hours 168
    python scripts/backfill_ml_severity.py --hours 168 --apply
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from weirvern import db  # noqa: E402
from weirvern.config import get_settings  # noqa: E402

FAMILIES = (
    "(greatest(isolation_forest_score >= 0.85, gradient_boosting_score >= 0.85)"
    " + (dbscan_score >= 0.85) + (baseline_score >= 0.85))"
)
NEW_SEVERITY = (
    "multiIf("
    "anomaly_score >= 0.95 AND " + FAMILIES + " >= 2 "
    "AND deviation_magnitude >= 3, 'critical', "
    "anomaly_score >= 0.85 AND " + FAMILIES + " >= 2 "
    "AND deviation_magnitude >= 2, 'high', "
    "anomaly_score >= 0.70 OR (anomaly_score >= 0.60 AND " + FAMILIES + " >= 1), 'medium', "
    "'low')"
)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--hours", type=float, default=168)
    ap.add_argument("--apply", action="store_true", help="write the new labels; default is dry-run")
    args = ap.parse_args()
    settings = get_settings()
    client = db.connect(settings)
    since = f"now() - INTERVAL {int(args.hours)} HOUR"
    where = f"detected_at >= {since}"
    q = (
        "SELECT severity, " + NEW_SEVERITY + " AS new_severity, count() AS n "
        "FROM weirvern.netflow_anomalies WHERE " + where + " "
        "GROUP BY severity, new_severity ORDER BY severity, new_severity"
    )
    rows = client.query(q).result_rows
    before: dict[str, int] = {}
    after: dict[str, int] = {}
    changed = 0
    for old, new, n in rows:
        before[str(old)] = before.get(str(old), 0) + int(n)
        after[str(new)] = after.get(str(new), 0) + int(n)
        if str(old) != str(new):
            changed += int(n)
    print(json.dumps({
        "dry_run": not args.apply,
        "hours": args.hours,
        "before": before,
        "after": after,
        "changed_rows": changed,
        "formula": (
            "independent families (IF+GB=forest, DBSCAN=density, baseline=baseline) + "
            "material deviation (critical >=3σ, high >=2σ); "
            "novelty cannot be recovered from history"
        ),
    }, indent=2, sort_keys=True))
    if args.apply:
        # ClickHouse mutations are asynchronous; the operator can watch system.mutations.
        client.command(
            "ALTER TABLE weirvern.netflow_anomalies UPDATE severity = " + NEW_SEVERITY
            + " WHERE " + where + " AND severity != " + NEW_SEVERITY
        )
        print("submitted severity backfill mutation", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
