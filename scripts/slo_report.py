#!/usr/bin/env python3
"""SLO REPORT: measure the promises in production-readiness.md, and say unknown when unmeasured.

The console's health probes answer "is this component alive". This answers the separate question
"is the service within the SLO we wrote down". It deliberately does not invent a percentage when a
source is absent: alert delivery with Pushover disabled is `not_configured`, not green.

Run from the management host (needs ssh + kubectl on the target):
    WEIRVERN_SENSOR_HOST=root@<node> python scripts/slo_report.py
    ... --json
Exit: 0 all required SLOs pass; 1 at least one SLO is outside its bound or unknown.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CHQ = ROOT / "scripts" / "chq.py"
DEFAULT_BACKUP_DIR = Path("/home/admin/weirvern-backups")


@dataclass(frozen=True)
class Slo:
    name: str
    value: float | None
    unit: str
    status: str
    detail: str
    runbook: str

    @property
    def ok(self) -> bool:
        return self.status == "ok"


def assess(name: str, value: float | None, limit: float, unit: str, direction: str,
           runbook: str, missing: str = "not measured") -> Slo:
    """One SLO: `max` means value must be <= limit; `min` means value must be >= limit."""
    if value is None:
        return Slo(name, None, unit, "unknown", missing, runbook)
    if direction == "max":
        ok = value <= limit
        detail = f"{value:.1f}{unit} <= {limit:.1f}{unit}"
    else:
        ok = value >= limit
        detail = f"{value:.1f}{unit} >= {limit:.1f}{unit}"
    return Slo(name, value, unit, "ok" if ok else "breach", detail, runbook)


def _chq(sql: str) -> tuple[float | None, float]:
    """Run a one-row query; return (first numeric value or None, elapsed seconds)."""
    start = time.monotonic()
    env = dict(os.environ)
    proc = subprocess.run([sys.executable, str(CHQ), "--tsv", sql],
                          capture_output=True, text=True, timeout=60, env=env)
    elapsed = time.monotonic() - start
    if proc.returncode != 0:
        return None, elapsed
    for line in reversed(proc.stdout.splitlines()):
        if "\t" in line or line.strip():
            cell = line.split("\t")[0].strip()
            try:
                return float(cell), elapsed
            except ValueError:
                continue
    return None, elapsed


def _query(sql: str) -> float | None:
    value, _ = _chq(sql)
    return value


def certificate_days(host: str, port: int) -> float | None:
    try:
        out = subprocess.run(
            ["openssl", "s_client", "-connect", f"{host}:{port}", "-servername", host],
            input="", capture_output=True, text=True, timeout=15,
        ).stdout
        cert = subprocess.run(["openssl", "x509", "-noout", "-enddate"],
                              input=out, capture_output=True, text=True, timeout=15).stdout
        raw = cert.strip().split("=", 1)[1]
        expires = datetime.strptime(raw, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=UTC)
        return (expires - datetime.now(UTC)).total_seconds() / 86400.0
    except Exception:
        return None


def backup_age_hours(directory: Path) -> float | None:
    try:
        files = sorted(directory.glob("*.tar.gz.gpg"), key=lambda p: p.stat().st_mtime)
        if not files:
            return None
        return (time.time() - files[-1].stat().st_mtime) / 3600.0
    except OSError:
        return None


def collect(host: str = "weirvern.home") -> list[Slo]:
    ingest = _query("SELECT dateDiff('second', max(timestamp), now()) FROM weirvern.flows")
    models = _query("SELECT dateDiff('second', max(trained_at), now()) FROM weirvern.ml_models")
    scored = _query("SELECT dateDiff('second', max(computed_at), now()) FROM weirvern.ml_window_scores")
    _, latency_s = _chq("SELECT count() FROM weirvern.flows")
    delivered = _query("SELECT countIf(sent = 1 AND sent_at > now() - INTERVAL 1 HOUR) "
                       "FROM weirvern.alert_events")
    reasons = _query("SELECT count() FROM weirvern.alert_events "
                     "WHERE sent_at > now() - INTERVAL 1 HOUR AND reason = 'log-only'")
    cert = certificate_days(host, 443)
    backup = backup_age_hours(DEFAULT_BACKUP_DIR)

    slos = [
        assess("ingest_freshness", ingest, 300, "s", "max",
               "docs/runbooks/source-coverage.md", "no flow timestamp"),
        assess("query_latency", latency_s, 2.0, "s", "max",
               "docs/runbooks/production-readiness.md", "query did not run"),
        assess("worker_model_freshness", scored, 900, "s", "max",
               "docs/runbooks/source-coverage.md", "no model score timestamp"),
        assess("model_training_freshness", models, 21600, "s", "max",
               "docs/runbooks/production-readiness.md", "no training timestamp"),
        assess("tls_expiry_console", cert, 14, "d", "min",
               "docs/runbooks/security-surface.md", "certificate unreadable"),
        assess("backup_age", backup, 36, "h", "max",
               "docs/runbooks/release-dr-drill.md", "no encrypted backup found"),
    ]
    # Alert delivery is a real SLO, but Pushover disabled means the delivery channel does not
    # exist. Reporting "0 alerts" as green would be a lie; report not_configured separately.
    pushover = os.environ.get("PUSHOVER_ENABLED", "0") == "1"
    if not pushover:
        slos.append(Slo("alert_delivery", None, "alerts", "not_configured",
                        "PUSHOVER_ENABLED is 0; alerts are recorded log-only",
                        "docs/runbooks/production-readiness.md"))
    elif delivered is None:
        slos.append(Slo("alert_delivery", None, "alerts", "unknown",
                        "could not read alert_events", "docs/runbooks/production-readiness.md"))
    else:
        slos.append(Slo("alert_delivery", delivered, "alerts", "ok" if delivered > 0 else "breach",
                        f"{int(delivered)} successful deliveries in the last hour; {int(reasons or 0)} log-only",
                        "docs/runbooks/production-readiness.md"))
    return slos


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--host", default="weirvern.home")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    if not os.environ.get("WEIRVERN_SENSOR_HOST"):
        print("WEIRVERN_SENSOR_HOST is not set; refusing to guess a host", file=sys.stderr)
        return 2
    slos = collect(args.host)
    if args.json:
        print(json.dumps({"ok": all(s.ok for s in slos),
                          "slos": [s.__dict__ for s in slos]}, indent=2))
    else:
        print(f"{'SLO':28} {'VALUE':>10} STATUS  DETAIL")
        for s in slos:
            value = "-" if s.value is None else f"{s.value:.1f}"
            print(f"{s.name:28} {value:>10} {s.status:8} {s.detail}")
            print(f"  runbook: {s.runbook}")
    return 0 if all(s.ok for s in slos) else 1


if __name__ == "__main__":
    raise SystemExit(main())
