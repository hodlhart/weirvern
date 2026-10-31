"""Active learning: review feedback becomes a bounded, expiring adjustment.

A disposition is not training data. It is a small, attributable adjustment to a host/role
budget or threshold, with before/after values, a reason, a reviewer and an expiry. This module
keeps the adjustment separate from normal model training, supports revert and expiry, and
selects a bounded uncertain queue for review. It never writes the alert path.
"""
from __future__ import annotations

import datetime
from collections.abc import Sequence
from typing import Any
from uuid import uuid4

from clickhouse_connect.driver.client import Client

from weirvern.clock import utcnow

METRIC_BOUNDS = {
    "page_budget": (0.0, 10.0),
    "threshold": (0.0, 1.0),
    "score_weight": (0.0, 1.0),
}
DEFAULT_EXPIRY_DAYS = 14


def _clamp(metric: str, value: float) -> float:
    low, high = METRIC_BOUNDS.get(metric, (0.0, 1.0))
    return max(low, min(high, float(value)))


def build_adjustment(
    *, scope: str, subject: str, metric: str, before_value: float, after_value: float,
    reason: str, reviewer: str = "operator",
    review_window_start: datetime.datetime | None = None, review_src_addr: str = "",
    expiry_days: int = DEFAULT_EXPIRY_DAYS, now: datetime.datetime | None = None,
) -> dict[str, Any]:
    """Create a validated adjustment record; no model or threshold is changed here."""
    if not scope or not subject or not reason.strip():
        raise ValueError("scope, subject and reason are required")
    if metric not in METRIC_BOUNDS:
        raise ValueError(f"unknown metric {metric!r}")
    before = _clamp(metric, before_value)
    after = _clamp(metric, after_value)
    if before == after:
        raise ValueError("before_value and after_value must differ")
    if expiry_days < 1 or expiry_days > 365:
        raise ValueError("expiry_days must be between 1 and 365")
    created = (now or utcnow()).replace(microsecond=0)
    return {
        "adjustment_id": uuid4().hex,
        "created_at": created,
        "reviewer": reviewer or "operator",
        "scope": scope,
        "subject": subject,
        "metric": metric,
        "before_value": before,
        "after_value": after,
        "reason": reason.strip()[:500],
        "review_window_start": review_window_start,
        "review_src_addr": review_src_addr,
        "expiry": created + datetime.timedelta(days=int(expiry_days)),
        "reverted_at": None,
        "revert_reason": "",
        "active": 1,
    }


def is_effective(adjustment: dict, *, now: datetime.datetime | None = None) -> bool:
    """Active, unexpired and not reverted. An expired row is retained as provenance."""
    if not int(adjustment.get("active", 0)):
        return False
    if adjustment.get("reverted_at") is not None:
        return False
    expiry = adjustment.get("expiry")
    if expiry is None:
        return False
    moment = now or utcnow()
    if hasattr(expiry, "tzinfo") and expiry.tzinfo is not None and moment.tzinfo is None:
        moment = moment.replace(tzinfo=expiry.tzinfo)
    if hasattr(moment, "tzinfo") and moment.tzinfo is not None and expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=moment.tzinfo)
    return expiry > moment


def effective_value(base_value: float, adjustment: dict,
                    *, now: datetime.datetime | None = None) -> float:
    """Replay: the adjusted value only while the record is effective, otherwise base."""
    if not is_effective(adjustment, now=now):
        return float(base_value)
    return float(adjustment["after_value"])


def revert(adjustment: dict, *, reason: str = "",
           now: datetime.datetime | None = None) -> dict:
    """Return a reverted copy, retaining the before/after for provenance."""
    out = dict(adjustment)
    out["active"] = 0
    out["reverted_at"] = (now or utcnow()).replace(microsecond=0)
    out["revert_reason"] = reason.strip()[:500]
    return out


def select_uncertain(rows: Sequence[dict], *, low: float, high: float,
                     budget: int = 20) -> list[dict]:
    """Bounded review queue: scores inside the uncertain band, closest to its midpoint first."""
    if high <= low:
        raise ValueError("high must be greater than low")
    if budget < 1:
        return []
    midpoint = (low + high) / 2.0
    band = [row for row in rows if low <= float(row.get("score", 0.0)) <= high]
    band.sort(key=lambda row: (abs(float(row.get("score", 0.0)) - midpoint),
                               str(row.get("src_addr", ""))))
    return band[:min(int(budget), 100)]


def write_adjustment(client: Client, adjustment: dict) -> bool:
    """Insert one adjustment; the adjustment store is not a training table."""
    client.insert(
        "weirvern.ml_review_adjustments",
        [[adjustment["adjustment_id"], adjustment["created_at"], adjustment["reviewer"],
          adjustment["scope"], adjustment["subject"], adjustment["metric"],
          adjustment["before_value"], adjustment["after_value"], adjustment["reason"],
          adjustment.get("review_window_start"), adjustment.get("review_src_addr", ""),
          adjustment["expiry"], adjustment.get("reverted_at"), adjustment.get("revert_reason", ""),
          int(adjustment.get("active", 1))]],
        column_names=["adjustment_id", "created_at", "reviewer", "scope", "subject", "metric",
                      "before_value", "after_value", "reason", "review_window_start",
                      "review_src_addr", "expiry", "reverted_at", "revert_reason", "active"],
    )
    return True


def adjustment_index(client: Client, *, hours: int = 72) -> tuple[dict[tuple, dict], str | None]:
    """Latest adjustment per (window_start, src_addr), for the review cell's provenance."""
    try:
        since = utcnow() - datetime.timedelta(hours=max(1, int(hours)))
        rows = client.query(
            "SELECT adjustment_id, created_at, reviewer, scope, subject, metric, "
            "before_value, after_value, reason, review_window_start, review_src_addr, "
            "expiry, reverted_at, revert_reason, active "
            "FROM weirvern.ml_review_adjustments FINAL "
            "WHERE created_at >= %(since)s ORDER BY created_at",
            parameters={"since": since},
        ).result_rows
        idx: dict[tuple, dict] = {}
        for row in rows:
            key = (row[9], str(row[10]))
            idx[key] = {
                "adjustment_id": row[0], "reviewer": row[2], "scope": row[3],
                "subject": row[4], "metric": row[5], "before_value": row[6],
                "after_value": row[7], "reason": row[8], "expiry": row[11],
                "reverted_at": row[12], "revert_reason": row[13], "active": row[14],
                "effective": is_effective({"active": row[14], "expiry": row[11],
                                           "reverted_at": row[12]}),
            }
        return idx, None
    except Exception as exc:  # noqa: BLE001
        return {}, f"adjustment provenance unavailable: {type(exc).__name__}"


__all__ = ["DEFAULT_EXPIRY_DAYS", "METRIC_BOUNDS", "adjustment_index", "build_adjustment",
           "effective_value", "is_effective", "revert", "select_uncertain", "write_adjustment"]
