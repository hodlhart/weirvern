"""CE-3: a reproducible fixed-budget report is an archive, not a console print.

The report refuses to be green when the corpus is missing, the population is empty, the
generator version is stale, or every selected label is weak. Live precision is never inferred
from synthetic labels; it stays `not measured` unless a canary or oracle covers it.
"""
from __future__ import annotations

import hashlib
import json
import math
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

VERIFIED_SOURCES = frozenset({"synthetic", "canary", "background"})
MIN_POPULATION_WINDOWS = 1
MIN_SELECTED = 1


def wilson(successes: int, total: int, z: float = 1.96) -> tuple[float, float] | None:
    if total <= 0:
        return None
    p = successes / total
    denom = 1 + z * z / total
    centre = (p + z * z / (2 * total)) / denom
    margin = z * math.sqrt((p * (1 - p) + z * z / (4 * total)) / total) / denom
    return (max(0.0, centre - margin), min(1.0, centre + margin))


def _labels_summary(labels: list[dict[str, Any]]) -> dict[str, Any]:
    verified = [x for x in labels
                if str(x.get("label_source") or "").lower() in VERIFIED_SOURCES]
    weak = [x for x in labels if str(x.get("label_source") or "").lower() == "weak"]
    return {
        "total": len(labels),
        "verified": len(verified),
        "weak": len(weak),
        "sources": sorted({str(x.get("label_source") or "unknown").lower() for x in labels}),
    }


def file_sha256(path: str | Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_report(*, baseline: dict[str, Any], candidate: dict[str, Any],
                 decision: dict[str, Any], labels: list[dict[str, Any]],
                 metadata: dict[str, Any], previous: dict[str, Any] | None = None,
                 generated_at: datetime | None = None) -> dict[str, Any]:
    now = generated_at or datetime.now(UTC)
    failures: list[str] = []
    if not baseline.get("windows"):
        failures.append("baseline population is empty")
    if not candidate.get("windows"):
        failures.append("candidate population is empty")
    if not metadata.get("generator_version"):
        failures.append("generator version is missing")
    if not metadata.get("scenario_version"):
        failures.append("scenario version is missing")
    summary = _labels_summary(labels)
    if summary["total"] == 0:
        failures.append("label corpus is missing or empty")
    elif summary["verified"] == 0:
        failures.append("no verified labels: weak-only labels cannot back a report")
    if summary["weak"] and summary["verified"] == 0:
        failures.append("weak-only corpus")
    selected = int(candidate.get("selected") or 0)
    if selected < MIN_SELECTED:
        failures.append("candidate selected no windows")
    if not decision.get("promote"):
        failures.append("promotion decision is not a pass")
    precision = candidate.get("precision")
    detection = candidate.get("detection_rate")
    precision_ci = wilson(round(float(precision or 0) * selected), selected) if precision is not None else None
    detection_ci = wilson(round(float(detection or 0) * selected), selected) if detection is not None else None
    previous = previous or {}
    previous_candidate = previous.get("candidate") or {}
    comparison: dict[str, Any] = {"available": bool(previous_candidate), "regressions": []}
    if previous_candidate:
        for key in ("precision", "detection_rate"):
            old = previous_candidate.get(key)
            new = candidate.get(key)
            if old is not None and new is not None and float(new) < float(old):
                comparison["regressions"].append(f"{key} fell from {old} to {new}")
        if comparison["regressions"]:
            failures.append("previous-report comparison found a regression")
    if selected < 20:
        comparison["underpowered"] = True
        comparison["note"] = "fewer than 20 selected windows; a win is directional, not powered"
    status = "pass" if not failures else "fail"
    report_id = f"eval-{now.strftime('%Y-%m-%dT%H%M%SZ')}"
    return {
        "report_id": report_id,
        "generated_at": now.isoformat(),
        "status": status,
        "failures": failures,
        "command": metadata.get("command", ""),
        "seed": metadata.get("seed"),
        "scenario_version": metadata.get("scenario_version"),
        "generator_version": metadata.get("generator_version"),
        "auto_label_version": metadata.get("auto_label_version", "not recorded"),
        "days": metadata.get("days"),
        "budget_per_day": metadata.get("budget_per_day"),
        "baseline": baseline,
        "candidate": candidate,
        "decision": decision,
        "labels": summary,
        "confidence_intervals": {"precision": precision_ci, "detection_rate": detection_ci},
        "comparison": comparison,
        "live_precision": "not measured",
        "note": "Synthetic/canary labels are evaluation evidence, not a live false-positive rate.",
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        f"# Fixed-budget evaluation — {report['generated_at'][:10]}",
        "",
        f"- **Status:** {report['status']}",
        f"- **Report:** `{report['report_id']}`",
        f"- **Seed:** {report.get('seed')}",
        f"- **Scenario version:** {report.get('scenario_version')}",
        f"- **Generator version:** {report.get('generator_version')}",
        f"- **Auto-label version:** {report.get('auto_label_version')}",
        f"- **Days / budget:** {report.get('days')} / {report.get('budget_per_day')}",
        f"- **Live precision:** {report.get('live_precision')}",
        "",
        "## Failures",
    ]
    lines += [f"- {item}" for item in report["failures"]] or ["- none"]
    lines += ["", "## Metrics", "| metric | baseline | candidate |",
              "|---|---:|---:|"]
    for key in ("selected", "alerts_per_day", "precision", "detection_rate",
                "false_alarms_per_host_day", "episode_count"):
        lines.append(f"| {key} | {report['baseline'].get(key)} | {report['candidate'].get(key)} |")
    lines += ["", "## Labels", json.dumps(report["labels"], sort_keys=True), ""]
    return "\n".join(lines)


def write_report(report: dict[str, Any], out_dir: Path) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    base = out_dir / report["report_id"]
    json_path = base.with_suffix(".json")
    md_path = base.with_suffix(".md")
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True, default=str) + "\n")
    md_path.write_text(render_markdown(report))
    return json_path, md_path


def latest_report(root: Path) -> dict[str, Any]:
    files = sorted((root / "docs" / "eval-reports").glob("eval-*.json"))
    if not files:
        return {"available": False, "reason": "no archived evaluation report"}
    try:
        data = json.loads(files[-1].read_text())
    except (OSError, ValueError) as exc:
        return {"available": False, "reason": f"latest evaluation report is unreadable: {type(exc).__name__}"}
    data["available"] = True
    data["path"] = str(files[-1])
    return data


__all__ = ["build_report", "file_sha256", "latest_report", "render_markdown", "wilson", "write_report"]
