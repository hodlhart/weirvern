#!/usr/bin/env python3
"""CVE GATE: block a release on the vulnerabilities we can actually fix.

A raw severity count is not a gate. Debian base images routinely carry High findings with no
fixed version; failing every one makes the gate noise and teaches people to bypass it. This
script blocks only findings at or above the chosen severity where a fixed package exists, and
prints the rest as an explicitly accepted inventory. Exceptions belong in a dated allowlist
elsewhere, not in a silent `|| true` in CI.

Usage:
    python scripts/cve_gate.py scan.json [scan2.json ...] --fail-on critical
    python scripts/cve_gate.py scan.json --fail-on high --json

Exit: 0 no blocking findings; 1 blocking findings; 2 unreadable input.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

RANK = {"Negligible": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}


def summarize(doc: dict, threshold: str = "Critical") -> dict:
    matches = doc.get("matches") or []
    counts = Counter()
    blocking = []
    for m in matches:
        vuln = m.get("vulnerability") or {}
        sev = str(vuln.get("severity") or "Unknown")
        counts[sev] += 1
        fix = vuln.get("fix") or {}
        fixed = str(fix.get("state") or "") == "fixed" and bool(fix.get("versions"))
        if fixed and RANK.get(sev, -1) >= RANK[threshold]:
            artifact = m.get("artifact") or {}
            blocking.append({
                "id": vuln.get("id"),
                "severity": sev,
                "package": artifact.get("name"),
                "version": artifact.get("version"),
                "fix": fix.get("versions"),
            })
    return {
        "threshold": threshold,
        "counts": dict(sorted(counts.items(), key=lambda kv: RANK.get(kv[0], -1))),
        "blocking": blocking,
        "ok": not blocking,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("scans", nargs="+")
    ap.add_argument("--fail-on", default="Critical", choices=("Critical", "High", "Medium"))
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    results = []
    for name in args.scans:
        try:
            doc = json.loads(Path(name).read_text())
        except (OSError, json.JSONDecodeError) as exc:
            print(f"{name}: cannot read scan: {exc}", file=sys.stderr)
            return 2
        results.append((name, summarize(doc, args.fail_on)))
    if args.json:
        print(json.dumps({n: r for n, r in results}, indent=2))
    else:
        failed = False
        for name, r in results:
            print(f"{name}: {r['counts']}")
            for b in r["blocking"]:
                print(f"  BLOCK {b['severity']} {b['id']} {b['package']} {b['version']} -> {b['fix']}")
            failed = failed or not r["ok"]
        print("CVE GATE PASS" if not failed else "CVE GATE FAIL")
    return 0 if all(r["ok"] for _n, r in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
