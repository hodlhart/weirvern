"""GT-1: auto-label artifacts round-trip and weak-only evidence cannot pass."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from weirvern.models import auto_labels, evaluation


def _scenario(i=0):
    return {"src_addr": f"198.51.100.{210 + i}", "window_start": "2026-11-11T00:00:00+00:00",
            "scenario_id": f"s{i}", "provenance": "simulator", "confidence": 0.99}


def test_verified_synthetic_and_canary_labels_round_trip():
    art = auto_labels.build(
        scenarios=[_scenario()],
        canary_events=[{"src_addr": "198.51.100.240", "window_start": "2026-11-11T00:05:00+00:00",
                        "service_id": "canary-ssh"}],
        background=[{"src_addr": "198.51.100.20", "window_start": "2026-11-11T00:00:00+00:00"}],
        weak_labels=[{"src_addr": "198.51.100.21", "window_start": "2026-11-11T00:00:00+00:00",
                      "label": "unknown"}],
        generator_version="scenario-2026-11",
    )
    assert art["summary"]["verified"] == 3
    assert art["summary"]["weak"] == 1
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        json.dump(art["rows"], fh)
        path = fh.name
    try:
        labels = evaluation.labels_from_json(path)
        assert len(labels) == 4
    finally:
        Path(path).unlink(missing_ok=True)


def test_weak_only_and_missing_generator_are_refused():
    try:
        auto_labels.build(scenarios=[], weak_labels=[
            {"src_addr": "198.51.100.21", "window_start": "2026-11-11T00:00:00+00:00"}],
            generator_version="scenario-2026-11")
    except ValueError as exc:
        assert "weak-only" in str(exc) or "no verified" in str(exc)
    else:
        raise AssertionError("weak-only artifact was accepted")
    try:
        auto_labels.build(scenarios=[_scenario()], generator_version="")
    except ValueError as exc:
        assert "generator version" in str(exc)
    else:
        raise AssertionError("missing generator version was accepted")


def test_authorized_canary_health_check_is_excluded():
    art = auto_labels.build(
        scenarios=[_scenario()],
        canary_events=[{"src_addr": "198.51.100.240", "window_start": "2026-11-11T00:05:00+00:00",
                        "service_id": "canary-ssh", "authorized": True}],
        generator_version="scenario-2026-11",
    )
    assert art["summary"]["sources"].get("canary") is None
