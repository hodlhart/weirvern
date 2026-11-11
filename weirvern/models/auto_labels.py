"""GT-1: machine-generated ground truth, with the human label queue removed.

Synthetic scenarios, canary hits and clean background are the only verified sources. Weak
detector/IOC labels are retained as weak evidence and are never promoted to verified. A missing
generator version or an empty corpus fails the artifact instead of producing an empty success.

This module builds and validates the artifact; `scripts/eval_budget.py` consumes the same rows.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

FIELDS = ("src_addr", "window_start", "label", "label_source", "confidence",
          "provenance", "scenario_id", "generator_version", "generated_at")
VERIFIED_SOURCES = frozenset({"synthetic", "canary", "background"})
LABELS = frozenset({"attack", "benign", "unknown"})


def _row(*, src_addr: str, window_start: str, label: str, label_source: str,
         confidence: float, provenance: str, scenario_id: str,
         generator_version: str, generated_at: str) -> dict[str, Any]:
    if label not in LABELS:
        raise ValueError(f"invalid label: {label!r}")
    if label_source not in VERIFIED_SOURCES | {"weak"}:
        raise ValueError(f"invalid label_source: {label_source!r}")
    if label_source in VERIFIED_SOURCES and not generator_version:
        raise ValueError("a verified label requires a generator version")
    return {
        "src_addr": str(src_addr), "window_start": str(window_start), "label": label,
        "label_source": label_source, "confidence": float(confidence),
        "provenance": provenance, "scenario_id": scenario_id,
        "generator_version": generator_version, "generated_at": generated_at,
    }


def build(*, scenarios: list[dict[str, Any]], canary_events: list[dict[str, Any]] | None = None,
          background: list[dict[str, Any]] | None = None,
          weak_labels: list[dict[str, Any]] | None = None,
          generator_version: str, now: datetime | None = None) -> dict[str, Any]:
    if not generator_version:
        raise ValueError("generator version is required")
    stamp = (now or datetime.now(UTC)).isoformat()
    rows: list[dict[str, Any]] = []
    for scenario in scenarios:
        rows.append(_row(
            src_addr=str(scenario["src_addr"]), window_start=str(scenario["window_start"]),
            label="attack", label_source="synthetic", confidence=float(scenario.get("confidence", 0.99)),
            provenance=str(scenario.get("provenance") or f"scenario {scenario.get('scenario_id')}"),
            scenario_id=str(scenario.get("scenario_id") or "unknown"),
            generator_version=generator_version, generated_at=stamp,
        ))
    for event in canary_events or []:
        if event.get("authorized"):
            continue
        rows.append(_row(
            src_addr=str(event["src_addr"]), window_start=str(event["window_start"]),
            label="attack", label_source="canary", confidence=1.0,
            provenance=str(event.get("service_id") or "canary"),
            scenario_id=str(event.get("service_id") or "canary"),
            generator_version=generator_version, generated_at=stamp,
        ))
    for event in background or []:
        rows.append(_row(
            src_addr=str(event["src_addr"]), window_start=str(event["window_start"]),
            label="benign", label_source="background", confidence=float(event.get("confidence", 0.9)),
            provenance=str(event.get("provenance") or "clean background replay"),
            scenario_id=str(event.get("scenario_id") or "background"),
            generator_version=generator_version, generated_at=stamp,
        ))
    for weak in weak_labels or []:
        rows.append(_row(
            src_addr=str(weak["src_addr"]), window_start=str(weak["window_start"]),
            label=str(weak.get("label") or "unknown"), label_source="weak",
            confidence=float(weak.get("confidence", 0.5)),
            provenance=str(weak.get("provenance") or "weak labeling function"),
            scenario_id=str(weak.get("scenario_id") or "weak"),
            generator_version=generator_version, generated_at=stamp,
        ))
    summary = summarize(rows)
    if not summary["verified"]:
        raise ValueError("no verified labels; weak-only evidence cannot form ground truth")
    return {"generator_version": generator_version, "generated_at": stamp, "rows": rows,
            "summary": summary}


def summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    sources: dict[str, int] = {}
    for row in rows:
        sources[row["label_source"]] = sources.get(row["label_source"], 0) + 1
    verified = sum(1 for row in rows if row["label_source"] in VERIFIED_SOURCES)
    return {"total": len(rows), "verified": verified,
            "weak": sources.get("weak", 0), "sources": sources,
            "contamination_risk": "unknown"}


def write_artifact(artifact: dict[str, Any], path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(artifact, indent=2, sort_keys=True, default=str) + "\n")
    return path


__all__ = ["FIELDS", "LABELS", "VERIFIED_SOURCES", "build", "summarize", "write_artifact"]
