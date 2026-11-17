"""The scorecard's arithmetic, tested without a ClickHouse.

The replay itself is exercised by the eval harness tests and by running the script; what
needs pinning here is the part that turns verdicts into the four numbers, because a metric
that is quietly wrong is worse than no metric -- it is a number someone will cite.
"""
from __future__ import annotations

import importlib.util
from datetime import datetime, timedelta
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "scorecard.py"


def _load():
    spec = importlib.util.spec_from_file_location("wv_scorecard", _SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


mod = _load()


def verdict(host: str, severity: str, score: float, window: str = "2026-11-16T23:00:00") -> dict:
    return {"src_addr": host, "severity": severity, "anomaly_score": score,
            "window_start": window}


_START = datetime(2026, 11, 16, 23, 0)


def scenario(passed: bool, latency: float | None, key: str = "port_scan") -> dict:
    """A scenario row shaped like `scenario_results` returns one."""
    return {"key": key, "passed": passed, "severity": "high", "start": _START,
            "first_detection": (_START + timedelta(minutes=latency))
            if latency is not None else None}


def test_ranking_puts_severity_before_score_and_score_before_time():
    # A low-severity verdict with a perfect score must NOT outrank a critical one. Operators
    # read severity first; a score-ordered list would put the noise at the top and the metric
    # would then measure the sort rather than the detector.
    verdicts = [
        verdict("a", "low", 0.99),
        verdict("b", "critical", 0.61),
        verdict("c", "high", 0.80),
        verdict("d", "high", 0.90, "2026-11-16T23:05:00"),
    ]
    assert [v["src_addr"] for v in mod.rank_verdicts(verdicts)] == ["b", "d", "c", "a"]


def test_ranking_is_stable_on_identical_keys():
    # Two rows identical in every ranked field must not swap between runs, or the determinism
    # check fails on the sort rather than on detection.
    rows = [verdict("b", "high", 0.7), verdict("a", "high", 0.7)]
    assert [v["src_addr"] for v in mod.rank_verdicts(list(rows))] == ["a", "b"]
    assert [v["src_addr"] for v in mod.rank_verdicts(list(reversed(rows)))] == ["a", "b"]


def test_measure_counts_only_attackers_in_the_top_twenty():
    attackers = {"10.0.0.1", "10.0.0.2"}
    verdicts = [verdict("10.0.0.1", "critical", 0.9), verdict("10.0.0.9", "critical", 0.9),
                verdict("10.0.0.2", "high", 0.8)]
    result = mod.measure(verdicts, attack_hosts=attackers,
                         scenario_rows=[scenario(True, 4.0)], minutes=300)
    assert result["top20_size"] == 3
    assert result["top20_hits"] == 2
    assert result["precision_at_20"] == pytest.approx(0.667, abs=1e-3)


def test_measure_normalises_episodes_to_a_day():
    verdicts = [verdict(f"10.0.0.{i}", "low", 0.1) for i in range(10)]
    result = mod.measure(verdicts, attack_hosts=set(), scenario_rows=[], minutes=300)
    assert result["episodes"] == 10
    assert result["episodes_per_day"] == pytest.approx(48.0)


def test_measure_takes_the_median_latency_not_the_worst():
    # The median is the number to quote: one slow scenario must not move the headline, and one
    # fast one must not hide a slow set. Latency is measured to the END of the first bucket.
    rows = [scenario(True, 2.0, "a"), scenario(True, 4.0, "b"), scenario(False, 30.0, "c")]
    result = mod.measure([], attack_hosts=set(), scenario_rows=rows, minutes=300)
    assert result["time_to_detect_min"] == pytest.approx(9.0)
    assert result["canary_recall"] == pytest.approx(0.667, abs=1e-3)
    assert result["canaries"] == 3 and result["canaries_passed"] == 2


def test_a_detection_in_the_attacks_own_bucket_is_five_minutes_not_zero():
    # The bucket start can precede the attack, so a raw delta clamps to 0.0 and every immediate
    # detection looks like a stopped clock. The first moment a verdict could exist is the end of
    # that bucket, and the scorecard says so.
    rows = [scenario(True, -3.0, "port_scan")]
    result = mod.measure([], attack_hosts=set(), scenario_rows=rows, minutes=300)
    assert result["time_to_detect_min"] == pytest.approx(5.0)
    assert result["time_to_detect_resolution_min"] == pytest.approx(5.0)


def test_measure_says_unknown_rather_than_zero():
    # "no verdicts" and "perfectly quiet" are different states. Returning 0.0 for precision on
    # an empty ranking would read as a catastrophic score instead of an absent measurement.
    result = mod.measure([], attack_hosts={"10.0.0.1"}, scenario_rows=[], minutes=300)
    assert result["precision_at_20"] is None
    assert result["time_to_detect_min"] is None
    assert result["canary_recall"] is None
    assert result["episodes_per_day"] == 0.0


def test_drift_is_relative_and_zero_for_identical_runs():
    assert mod.drift(100.0, 100.0) == 0.0
    # Relative to the LARGER of the two, so a 2-point spread on 100/102 is 1.96%.
    assert mod.drift(100.0, 102.0) == pytest.approx(2 / 102)
    assert mod.drift(0.0, 0.0) == 0.0
    # An absent metric on one side is not a small drift; it is an incomparable run.
    assert mod.drift(None, 5.0) == float("inf")
    assert mod.drift(None, None) == 0.0
