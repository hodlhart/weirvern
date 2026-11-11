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


__all__ = [
    "CARD_STATUSES", "PRODUCTION", "RETIRED", "current_cards", "production_allowed",
    "registration", "require_production", "status_map",
]
