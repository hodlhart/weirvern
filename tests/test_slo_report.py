"""SLO gates fail unknown, not green."""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("slo_report", ROOT / "scripts" / "slo_report.py")
assert SPEC and SPEC.loader
slo = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = slo
SPEC.loader.exec_module(slo)


def test_a_missing_measurement_is_unknown_not_ok():
    s = slo.assess("ingest_freshness", None, 300, "s", "max", "runbook")
    assert s.status == "unknown" and not s.ok


def test_a_fresh_source_passes():
    s = slo.assess("ingest_freshness", 30, 300, "s", "max", "runbook")
    assert s.ok and s.status == "ok"


def test_a_stale_source_breaches_and_says_the_bound():
    s = slo.assess("ingest_freshness", 301, 300, "s", "max", "runbook")
    assert not s.ok and "301" in s.detail and "300" in s.detail


def test_a_minimum_direction_is_respected():
    s = slo.assess("tls_expiry_console", 3, 14, "d", "min", "runbook")
    assert not s.ok and s.status == "breach"
