"""Source coverage and role truth before a model is trained, scored or promoted.

A QUIET CONSOLE IS NOT COVERAGE. This module answers two questions separately:

  * which raw sources are present, how many rows they hold, how old the newest row is, and
    whether that makes them usable; and
  * which hosts have no role, by name and count, instead of folding `unknown` into
    `workstation`.

It returns `not measured` for an empty source, `unknown` when the read failed, and never turns
either into a zero that looks like a healthy network. `promotion_allowed` consumes the same
report, so the fixed-budget gate cannot promote a model whose required flow source is missing.
"""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

# Required sources feed the flow ensemble. Zeek tables are optional context: an absent Zeek
# sensor is reported, but it does not by itself make a flow-only deployment unready.
SOURCES: dict[str, tuple[str, str | None, bool]] = {
    "flows": ("weirvern.flows", "time_flow_start", True),
    "flows_aggregated": ("weirvern.flows_aggregated", "window_start", True),
    "zeek_conn": ("weirvern.zeek_conn", "ts", False),
    "zeek_ssl": ("weirvern.zeek_ssl", "ts", False),
    "zeek_dns": ("weirvern.zeek_dns", "ts", False),
    "zeek_notice": ("weirvern.zeek_notice", "ts", False),
}

FRESH_SECONDS = 900


def _state(rows: int | None, last: Any) -> tuple[str, str]:
    if rows is None:
        return "unknown", "the source could not be read"
    if rows <= 0:
        return "not measured", "no records in the source"
    if last is None:
        return "unknown", "the source has rows but no readable newest row"
    moment = last
    if isinstance(moment, str):
        try:
            moment = datetime.fromisoformat(moment.replace("Z", "+00:00"))
        except ValueError:
            return "unknown", "the newest row has no readable timestamp"
    if not isinstance(moment, datetime):
        return "unknown", "the newest row has no readable timestamp"
    now = datetime.now(UTC)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    age = (now - moment.astimezone(UTC)).total_seconds()
    if age < -300:
        return "failed", "the newest row is in the future (clock fault)"
    if age > FRESH_SECONDS:
        return "stale", f"newest row is {int(age // 60)} min old"
    return "fresh", f"newest row is {int(age)} s old"


def summarise(sources: list[dict[str, Any]], roles: dict[str, Any] | None) -> dict[str, Any]:
    """Pure shape for the API and the promotion gate; no ClickHouse access here."""
    required = [row["name"] for row in sources if row["required"]]
    missing = [row["name"] for row in sources if row["required"] and not row["usable"]]
    return {
        "available": True,
        "sources": sources,
        "required": required,
        "promotion_ok": not missing,
        "required_missing": missing,
        "roles": roles or {"counts": [], "unknown": None, "top_unknown": [],
                           "reason": "the role table could not be read"},
        # A model can only be as usable as its required sources. This is a statement about
        # data, not about the model's accuracy.
        "models": [
            {"name": name, "usable": not missing,
             "reason": "" if not missing else "required source missing: " + ", ".join(missing)}
            for name in ("Adaptive Baseline", "Isolation Forest", "Gradient Boosting", "DBSCAN")
        ],
    }


def collect(client: Any) -> dict[str, Any]:
    sources: list[dict[str, Any]] = []
    for name, (table, column, required) in SOURCES.items():
        try:
            if column:
                row = client.query(
                    f"SELECT count(), max({column}) FROM {table}"
                ).result_rows
                values = row[0] if row else (None, None)
                rows, last = values[0], values[1]
            else:
                row = client.query(f"SELECT count() FROM {table}").result_rows
                rows, last = (row[0][0], None) if row else (None, None)
            count = int(rows) if rows is not None else None
        except Exception:  # noqa: BLE001 - a source failure is data, not a crash
            count, last = None, None
        state, reason = _state(count, last)
        sources.append({
            "name": name, "table": table, "column": column, "required": required,
            "rows": count, "last": last, "state": state,
            "usable": state == "fresh", "reason": reason,
        })
    try:
        rows = client.query(
            "SELECT role, count() FROM weirvern.host_roles FINAL GROUP BY role"
        ).result_rows
        counts: list[dict[str, Any]] = [
            {"role": str(role or "unknown"), "count": int(count or 0)}
            for role, count in rows
        ]
        unknown = sum(item["count"] for item in counts
                      if item["role"].strip().lower() in ("", "unknown"))
        top = client.query(
            "SELECT host FROM weirvern.host_roles FINAL "
            "WHERE lower(role) IN ('', 'unknown') ORDER BY host LIMIT 10"
        ).result_rows
        roles = {"counts": sorted(counts, key=lambda item: (-item["count"], item["role"])),
                 "unknown": unknown, "top_unknown": [str(row[0]) for row in top]}
    except Exception as exc:  # noqa: BLE001
        roles = {"counts": [], "unknown": None, "top_unknown": [],
                 "reason": f"the role table could not be read: {type(exc).__name__}"}
    return summarise(sources, roles)


__all__ = ["FRESH_SECONDS", "SOURCES", "collect", "summarise"]
