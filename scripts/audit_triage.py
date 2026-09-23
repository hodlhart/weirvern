#!/usr/bin/env python3
"""Triage findings from an independent audit against the code, and record the verdict.

WHY THIS EXISTS. An independent reviewer -- a model, a colleague, a tool -- produces findings, and
the temptation is to fix them. That is backwards. Measured across twelve audit passes on this
codebase: 180 findings were reported, and the ones sampled at HIGH severity were largely describing
code that ALREADY GUARDS the case, because the reviewer read the comments and inferred the code
from them. Acting on those would have meant "fixing" correct code, adding redundant guards, and
burning the trust that the real findings need.

So every finding is TRIAGED before it is acted on, and the verdict is recorded here. Three verdicts:

  CONFIRMED   reproduced against the code or the running system; it is a real defect.
  REFUTED     the guard exists; the finding describes the comment rather than the code.
  UNPROVEN    could not be settled from the text (needs a live system, a fixture, or time).

WHY RECORD THE REFUTED ONES. A refuted finding is not wasted work: it is evidence about the
REVIEWER. Twelve passes that produce false positives at HIGH severity tell you to sample before
acting, and the pattern of what they got wrong tells you what to double-check next time. Deleting
them loses that.

Usage:
    audit_triage.py list [severity]        -- the findings, with any recorded verdict
    audit_triage.py verdict <id> <v> [note]-- record one
    audit_triage.py summary                -- counts by severity and verdict
"""

from __future__ import annotations

import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
FINDINGS = ROOT / "docs" / "audit-findings.json"
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")


def load() -> dict:
    if not FINDINGS.exists():
        return {"findings": []}
    return json.loads(FINDINGS.read_text())


def save(data: dict) -> None:
    FINDINGS.parent.mkdir(parents=True, exist_ok=True)
    FINDINGS.write_text(json.dumps(data, indent=2) + "\n")


def cmd_list(severity: str | None) -> int:
    data = load()
    rows = data["findings"]
    if severity:
        rows = [r for r in rows if r["severity"] == severity.upper()]
    rows.sort(key=lambda r: (SEVERITIES.index(r["severity"]), r.get("area", "")))
    for r in rows:
        v = r.get("verdict") or "-"
        print(f"  [{r['severity']:8s}] [{v:9s}] {r['id']:4s} {r.get('area',''):16s} {r['title'][:74]}")
        if r.get("note"):
            print(f"            {r['note'][:110]}")
    print(f"  {len(rows)} finding(s)")
    return 0


def cmd_verdict(fid: str, verdict: str, note: str) -> int:
    data = load()
    verdict = verdict.upper()
    if verdict not in ("CONFIRMED", "REFUTED", "UNPROVEN"):
        print(f"  verdict must be CONFIRMED, REFUTED or UNPROVEN (got {verdict!r})")
        return 2
    for r in data["findings"]:
        if r["id"] == fid:
            r["verdict"] = verdict
            r["note"] = note
            save(data)
            print(f"  {fid} -> {verdict}")
            return 0
    print(f"  no finding with id {fid!r}")
    return 1


def cmd_summary() -> int:
    data = load()
    rows = data["findings"]
    by_sev: dict[str, int] = {}
    by_verdict: dict[str, int] = {}
    for r in rows:
        by_sev[r["severity"]] = by_sev.get(r["severity"], 0) + 1
        v = r.get("verdict") or "UNTRIAGED"
        by_verdict[v] = by_verdict.get(v, 0) + 1
    print("  by severity:  " + "  ".join(f"{s}={by_sev.get(s,0)}" for s in SEVERITIES))
    print("  by verdict:   " + "  ".join(f"{k}={v}" for k, v in sorted(by_verdict.items())))
    untriaged = [r for r in rows if not r.get("verdict") and r["severity"] in ("CRITICAL", "HIGH")]
    if untriaged:
        print(f"  {len(untriaged)} CRITICAL/HIGH finding(s) still untriaged:")
        for r in untriaged:
            print(f"    [{r['severity']:8s}] {r['id']:4s} {r['title'][:80]}")
    return 0


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    cmd = sys.argv[1]
    if cmd == "list":
        return cmd_list(sys.argv[2] if len(sys.argv) > 2 else None)
    if cmd == "verdict":
        if len(sys.argv) < 4:
            print("  usage: audit_triage.py verdict <id> <CONFIRMED|REFUTED|UNPROVEN> [note]")
            return 2
        return cmd_verdict(sys.argv[2], sys.argv[3], " ".join(sys.argv[4:]))
    if cmd == "summary":
        return cmd_summary()
    print(__doc__)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
