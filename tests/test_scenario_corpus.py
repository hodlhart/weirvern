"""FND-3 scenario corpus: deterministic generation and a guard proof.

The ClickHouse harness proves the scenarios are detected end-to-end; this file proves the
fixture is deterministic and that the scenario checker fails closed when a scenario's verdict
is missing -- the guard that would catch a broken detector in CI.
"""
from __future__ import annotations

import importlib.util
import json
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

from weirvern.tools.demo_flows import SCENARIO_HOSTS, generate

ROOT = Path(__file__).resolve().parent.parent


def _eval_module():
    spec = importlib.util.spec_from_file_location(
        "weirvern_eval_detection", ROOT / "scripts" / "eval_detection.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_scenario_fixture_is_opt_in_and_deterministic():
    def hosts_from(new_scenarios: bool) -> set[str]:
        with tempfile.NamedTemporaryFile("r", suffix=".jsonl", delete=False) as fh:
            path = fh.name
        try:
            generate(SimpleNamespace(
                minutes=8, devices=4, output=path, seed=42, scanner=True, scan_ports=10,
                beacon=True, exfil=True, new_scenarios=new_scenarios, attack_start_minute=4,
                start=1_700_000_000,
            ))
            rows = [json.loads(line) for line in Path(path).read_text().splitlines()]
            return {row["src_addr"] for row in rows}
        finally:
            Path(path).unlink(missing_ok=True)

    base = hosts_from(False)
    expanded = hosts_from(True)
    assert not (set(SCENARIO_HOSTS.values()) & base), "the opt-out fixture grew new attack hosts"
    assert set(SCENARIO_HOSTS.values()) <= expanded, "the opt-in fixture is missing a scenario host"
    # Same seed twice, same host set: generation is a function of its inputs.
    assert expanded == hosts_from(True)


def test_scenario_checker_fails_closed_when_a_verdict_is_missing():
    eval_mod = _eval_module()
    start = datetime(2026, 1, 1, tzinfo=UTC)
    by_host = {
        spec["host"]: [{"src_addr": spec["host"], "window_start": start,
                        "severity": "medium"}]
        for spec in eval_mod.SCENARIO_SPECS
    }
    rows = eval_mod.scenario_results(by_host, start)
    assert len(rows) == len(eval_mod.SCENARIO_SPECS)
    assert all(row["passed"] for row in rows), "a complete scenario set did not pass"

    missing = dict(by_host)
    missing.pop(eval_mod.SCENARIO_SPECS[0]["host"])
    broken = eval_mod.scenario_results(missing, start)
    assert not broken[0]["passed"], "the checker passed with a scenario's verdict removed"
    assert broken[0]["severity"] == ""
