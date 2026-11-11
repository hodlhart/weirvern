"""The CVE gate blocks fixable Critical/High findings, not inventory noise."""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("cve_gate", ROOT / "scripts" / "cve_gate.py")
assert SPEC and SPEC.loader
cve_gate = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = cve_gate
SPEC.loader.exec_module(cve_gate)


def _scan(*rows):
    return {"matches": [
        {"vulnerability": {"id": i, "severity": s, "fix": {"state": f, "versions": v}},
         "artifact": {"name": p, "version": "1"}}
        for i, s, p, f, v in rows
    ]}


def test_a_fixable_critical_blocks():
    r = cve_gate.summarize(_scan(("CVE-1", "Critical", "python", "fixed", ["3.11.18"])), "Critical")
    assert not r["ok"] and r["blocking"][0]["id"] == "CVE-1"


def test_a_wont_fix_critical_is_inventory_not_a_blocker():
    r = cve_gate.summarize(_scan(("CVE-2", "Critical", "libc", "wont-fix", [])), "Critical")
    assert r["ok"], "a finding with no fix is recorded, not used to block every release"


def test_high_does_not_block_when_threshold_is_critical():
    r = cve_gate.summarize(_scan(("CVE-3", "High", "zlib", "fixed", ["2"])), "Critical")
    assert r["ok"]


def test_high_blocks_when_threshold_is_high():
    r = cve_gate.summarize(_scan(("CVE-4", "High", "zlib", "fixed", ["2"])), "High")
    assert not r["ok"]


def test_counts_survive_even_when_not_blocking():
    r = cve_gate.summarize(_scan(("CVE-5", "High", "zlib", "wont-fix", [])), "Critical")
    assert r["counts"] == {"High": 1}
