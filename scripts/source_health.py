#!/usr/bin/env python3
"""SOURCE COVERAGE AND CLOCK GATE.

A source that has stopped is not a source producing zero events. This script reports, per
collected source, how many rows exist, the newest event, and the age measured against
ClickHouse's own clock. It exits non-zero when a required source is empty, stale, or has a
timestamp in the future beyond the clock-skew allowance.

This is deliberately small and dependency-free. The heavy coverage proof (which tables reach
the models) is `audit_ml_coverage.py`; this is the freshness/clock half that makes a green
coverage number mean "recent data", not "a table with old rows in it".

Usage:
    WEIRVERN_SENSOR_HOST=root@<sensor> python scripts/source_health.py
    ... --stale-seconds 900 --skew-seconds 120 --json

Exit: 0 all required sources healthy; 1 a required source failed; 2 could not query at all.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CHQ = ROOT / "scripts" / "chq.py"

# A source is a table plus the column that says when its newest row happened. Keeping this
# list explicit is the point: a new table must be added here, or it is invisible to the gate.
SOURCES = (
    ("flows", "timestamp", True),
    ("flows_aggregated", "window_start", True),
    ("netflow_anomalies", "detected_at", True),
    ("ml_window_scores", "computed_at", True),
    ("zeek_conn", "ts", False),
    ("zeek_dns", "ts", False),
    ("zeek_ssl", "ts", False),
    ("zeek_notice", "ts", False),
    ("sensor_status", "ts", False),
)


@dataclass(frozen=True)
class SourceReading:
    source: str
    rows: int | None
    newest: str | None
    age_seconds: float | None
    status: str
    reason: str = ""

    @property
    def ok(self) -> bool:
        return self.status == "ok"


def classify(source: str, rows: int | None, newest: str | None, age: float | None,
             stale_seconds: int, skew_seconds: int, required: bool) -> SourceReading:
    """Classify one source without touching the database.

    `rows is None` means the read failed or was not attempted. That is `unknown`; it is never
    converted to zero. A future timestamp is a clock fault even when the table is full.
    """
    if rows is None:
        return SourceReading(source, None, newest, age, "unknown", "not measured")
    if rows == 0:
        return SourceReading(source, 0, None, None, "empty", "no rows")
    if age is None:
        return SourceReading(source, rows, newest, None, "unknown", "no usable timestamp")
    if age < -skew_seconds:
        return SourceReading(source, rows, newest, age, "clock_skew",
                             f"newest event is {-age:.0f}s in the future")
    if age > stale_seconds:
        return SourceReading(source, rows, newest, age, "stale",
                             f"newest event is {age:.0f}s old; bound is {stale_seconds}s")
    return SourceReading(source, rows, newest, age, "ok")


def _run_query(sql: str) -> tuple[int, str]:
    env = dict(os.environ)
    proc = subprocess.run(
        [sys.executable, str(CHQ), "--tsv", sql],
        capture_output=True, text=True, timeout=120, env=env,
    )
    return proc.returncode, ((proc.stdout or "") + (proc.stderr or "")).strip()


def read_source(source: str, column: str, stale_seconds: int, skew_seconds: int,
                required: bool) -> SourceReading:
    # Identifiers are from the fixed SOURCES list, never user input. The column is quoted so a
    # reserved-looking name cannot silently change the query.
    sql = (
        f"SELECT count(), max(`{column}`), now(), "
        f"dateDiff('second', max(`{column}`), now()) "
        f"FROM weirvern.`{source}`"
    )
    rc, out = _run_query(sql)
    if rc != 0:
        return SourceReading(source, None, None, None, "unknown", out[:300] or "query failed")
    # chq.py can prefix kubectl's "Defaulted container" line; take the last tab-separated row.
    line = ""
    for candidate in out.splitlines():
        if candidate.count("\t") >= 3:
            line = candidate
    if not line:
        return SourceReading(source, None, None, None, "unknown", "no usable result row")
    parts = line.split("\t")
    try:
        rows = int(parts[0])
        newest = parts[1] or None
        age = float(parts[3]) if parts[3] not in ("", "\\N", "None") else None
    except (TypeError, ValueError):
        return SourceReading(source, None, None, None, "unknown", f"unparseable row: {line[:200]}")
    return classify(source, rows, newest, age, stale_seconds, skew_seconds, required)


def collect(stale_seconds: int, skew_seconds: int) -> list[SourceReading]:
    readings: list[SourceReading] = []
    for source, column, required in SOURCES:
        readings.append(read_source(source, column, stale_seconds, skew_seconds, required))
    return readings


def as_payload(readings: list[SourceReading]) -> dict:
    required_by_name = {source: required for source, _column, required in SOURCES}
    required_failures = [
        r.source for r in readings
        if required_by_name.get(r.source, True) and not r.ok
    ]
    return {
        "ok": not required_failures,
        "required_failures": required_failures,
        "sources": [r.__dict__ for r in readings],
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--stale-seconds", type=int, default=900)
    ap.add_argument("--skew-seconds", type=int, default=120)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    if not os.environ.get("WEIRVERN_SENSOR_HOST"):
        print("WEIRVERN_SENSOR_HOST is not set; refusing to guess a host", file=sys.stderr)
        return 2
    readings = collect(args.stale_seconds, args.skew_seconds)
    payload = as_payload(readings)
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        print(f"{'source':24} {'rows':>12} {'newest':20} {'age_s':>8} status")
        for r in readings:
            age = "" if r.age_seconds is None else f"{r.age_seconds:.0f}"
            print(f"{r.source:24} {r.rows if r.rows is not None else 'unknown':>12} "
                  f"{r.newest or '-':20} {age:>8} {r.status}")
            if r.reason:
                print(f"  {r.reason}")
    return 0 if payload["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
