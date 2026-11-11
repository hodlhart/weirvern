"""CE-3: an evaluation report must fail closed and never infer live precision from labels."""
from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from weirvern.models import eval_report

ROOT = Path(__file__).resolve().parents[1]


def _inputs():
    baseline = {"windows": 100, "selected": 20, "precision": 0.5, "detection_rate": 0.5,
                "alerts_per_day": 10, "false_alarms_per_host_day": 0.2, "episode_count": 4}
    candidate = {"windows": 100, "selected": 20, "precision": 0.7, "detection_rate": 0.7,
                 "alerts_per_day": 10, "false_alarms_per_host_day": 0.1, "episode_count": 4}
    decision = {"promote": True, "reasons": []}
    labels = [{"src_addr": "198.51.100.10", "window_start": "2026-11-10T20:00:00",
               "label": "attack", "label_source": "synthetic"},
              {"src_addr": "198.51.100.11", "window_start": "2026-11-10T20:00:00",
               "label": "benign", "label_source": "background"}]
    metadata = {"command": "test", "seed": 42, "scenario_version": "fnd3-v1",
                "generator_version": "demo-v1", "auto_label_version": "al-1",
                "days": 7, "budget_per_day": 10}
    return baseline, candidate, decision, labels, metadata


def test_complete_evidence_passes_and_records_intervals():
    baseline, candidate, decision, labels, metadata = _inputs()
    out = eval_report.build_report(baseline=baseline, candidate=candidate, decision=decision,
                                   labels=labels, metadata=metadata,
                                   generated_at=datetime(2026, 11, 11, tzinfo=UTC))
    assert out["status"] == "pass"
    assert out["live_precision"] == "not measured"
    assert out["confidence_intervals"]["precision"] is not None


def test_missing_generator_and_weak_only_labels_fail():
    baseline, candidate, decision, labels, metadata = _inputs()
    metadata["generator_version"] = ""
    for label in labels:
        label["label_source"] = "weak"
    out = eval_report.build_report(baseline=baseline, candidate=candidate, decision=decision,
                                   labels=labels, metadata=metadata)
    assert out["status"] == "fail"
    assert any("generator version" in failure for failure in out["failures"])
    assert any("weak-only" in failure or "no verified labels" in failure for failure in out["failures"])


def test_empty_population_and_rejected_decision_fail():
    baseline, candidate, decision, labels, metadata = _inputs()
    candidate["windows"] = 0
    decision["promote"] = False
    out = eval_report.build_report(baseline=baseline, candidate=candidate, decision=decision,
                                   labels=labels, metadata=metadata)
    assert any("candidate population" in failure for failure in out["failures"])
    assert any("promotion decision" in failure for failure in out["failures"])


def test_previous_regression_is_named():
    baseline, candidate, decision, labels, metadata = _inputs()
    previous = {"candidate": {"precision": 0.9, "detection_rate": 0.9}}
    out = eval_report.build_report(baseline=baseline, candidate=candidate, decision=decision,
                                   labels=labels, metadata=metadata, previous=previous)
    assert out["status"] == "fail"
    assert out["comparison"]["regressions"]


def test_wilson_interval_is_bounded():
    interval = eval_report.wilson(7, 10)
    assert interval is not None
    low, high = interval
    assert 0 <= low < high <= 1


def test_the_report_surface_is_wired():
    web = (ROOT / "weirvern" / "admin" / "web_api.py").read_text()
    assert "eval-report" in web or "eval_report" in web
