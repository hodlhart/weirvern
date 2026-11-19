"""Model cards: the durable identity of anything allowed to influence an alert.

WHY THIS MODULE EXISTS. `ml_models` records training runs, and a retrain every few hours makes
the newest run look like "the model". It is not: a promoted model is a specific artifact, built
under a specific feature schema, calibrated at a specific time, with a named evaluation and a
rollback path. This module is the one place that reads the card and answers "may this name
contribute to the fused score?".

FAIL-CLOSED ON PURPOSE. If the card table cannot be read, no model is treated as registered.
The caller may choose to continue detection with a warning (the worker's eligibility gate logs
that the gate was skipped), but it must not quietly assume a missing card means production.
"""
from __future__ import annotations

from typing import Any

CARD_STATUSES = ("shadow", "canary", "production", "retired")

PRODUCTION = "production"
RETIRED = "retired"


def _rows(client: Any) -> list[dict[str, Any]]:
    """Latest card per model. ReplacingMergeTree(updated_at) makes FINAL the truth."""
    res = client.query(
        "SELECT model_id, model_name, version, artifact_hash, training_window_start, "
        "training_window_end, feature_version, calibration_version, eval_report_id, status, "
        "owner, approved_by, approved_at, rollback_ref, intended_use, out_of_scope, "
        "known_limitations, updated_at "
        "FROM weirvern.ml_model_cards FINAL ORDER BY model_name"
    )
    columns = (
        "model_id", "model_name", "version", "artifact_hash", "training_window_start",
        "training_window_end", "feature_version", "calibration_version", "eval_report_id",
        "status", "owner", "approved_by", "approved_at", "rollback_ref", "intended_use",
        "out_of_scope", "known_limitations", "updated_at",
    )
    return [dict(zip(columns, row, strict=False)) for row in res.result_rows]


def status_map(rows: list[dict[str, Any]]) -> dict[str, str]:
    """model_name -> status; the pure half, so the eligibility rule is testable."""
    out: dict[str, str] = {}
    for row in rows:
        name = str(row.get("model_name") or "").strip()
        status = str(row.get("status") or "").strip().lower()
        if name:
            out[name] = status
    return out


def production_allowed(statuses: dict[str, str]) -> dict[str, bool]:
    """Only a current card with status `production` may influence the fused score.

    A retired, shadow or canary card is not a production model even if its artifact still
    exists on disk. An unregistered name has no key and is therefore false.
    """
    return {name: status == PRODUCTION for name, status in statuses.items()}


def current_cards(client: Any) -> list[dict[str, Any]]:
    return _rows(client)


def registration(client: Any) -> dict[str, bool]:
    return production_allowed(status_map(_rows(client)))


def require_production(client: Any, names: list[str]) -> dict[str, bool]:
    """The names the caller is about to use, with a card-backed yes/no for each."""
    registered = registration(client)
    return {name: bool(registered.get(name, False)) for name in names}


def artifact_inventory(model_dir: str) -> dict[str, dict[str, Any]]:
    """The newest artifact on disk per model: file, version, mtime, short hash.

    WHY THIS EXISTS (operator, 2026-11-19: "make sure that the models tab reflects our newest
    build of the ml engine data"). `ml_model_cards` is a curated registry, seeded once and written
    only when someone edits a card; the engine saves a new artifact every retrain. Reading only
    the registry made the console show v4 / 2026-11-11 while v5 files sat on disk from that
    morning. This returns what is actually installed so the two can be compared out loud.
    """
    import hashlib  # noqa: PLC0415
    import os  # noqa: PLC0415
    import re  # noqa: PLC0415

    out: dict[str, dict[str, Any]] = {}
    pattern = re.compile(r"^(?P<name>.+)_v(?P<version>\d+)\.pkl$")
    try:
        entries = os.listdir(model_dir)
    except OSError:
        return out
    for entry in entries:
        m = pattern.match(entry)
        if not m:
            continue
        path = os.path.join(model_dir, entry)
        try:
            stat = os.stat(path)
            with open(path, "rb") as fh:            # noqa: PTH123 -- one read, no path object
                digest = hashlib.sha256(fh.read()).hexdigest()[:16]
        except OSError:
            continue
        version = int(m.group("version"))
        name = m.group("name")
        if name in out and out[name]["version_num"] >= version:
            continue
        from datetime import UTC, datetime  # noqa: PLC0415

        out[name] = {"file": entry, "version": f"v{version}", "version_num": version,
                     "written_at": datetime.fromtimestamp(stat.st_mtime, UTC).isoformat(),
                     "hash": digest, "bytes": stat.st_size}
    return out


__all__ = [
    "artifact_inventory",
    "CARD_STATUSES", "PRODUCTION", "RETIRED", "current_cards", "production_allowed",
    "registration", "require_production", "status_map",
]
