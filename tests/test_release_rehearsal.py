"""Release rehearsals and load tools stay bounded and read-only.

Source assertions because the live drills need a running cluster; the drills themselves were run
against the box and their results are in the runbooks.
"""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_canary_is_bounded_and_cleans_up():
    src = (ROOT / "scripts" / "canary_rehearsal.sh").read_text()
    assert "kind: Pod" in src
    assert "kind: Service" not in src and "kind: Ingress" not in src
    assert "trap " in src and "delete namespace" in src


def test_canary_names_the_cross_namespace_database():
    src = (ROOT / "scripts" / "canary_rehearsal.sh").read_text()
    assert "clickhouse.weirvern.svc.cluster.local" in src


def test_soak_monitor_does_not_write_the_deployment():
    src = (ROOT / "scripts" / "soak_monitor.sh").read_text()
    for verb in ("kubectl apply", "kubectl delete", "kubectl set", "scale deploy"):
        assert verb not in src


def test_soak_monitor_reports_unmeasured_instead_of_zero():
    src = (ROOT / "scripts" / "soak_monitor.sh").read_text()
    assert "not measured" in src
    assert "SOAK PASS" in src and "SOAK FAIL" in src


def test_load_profile_is_read_only_and_token_safe():
    src = (ROOT / "scripts" / "load_profile_read.py").read_text()
    assert "urlopen" in src
    assert "POST" not in src and "PUT" not in src and "DELETE" not in src
    assert "token_file" in src
