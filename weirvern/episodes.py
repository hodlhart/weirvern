"""Incident episodes and the per-host page budget.

The anomaly table is a list of five-minute windows. An operator does not review windows, they
review an incident: consecutive windows for the same host, separated by no more than a configured
gap, are one episode. This module builds that view, chooses at most one pageable window per
episode, and enforces a per-host daily page budget.

DESIGN RULES
------------
* Raw `netflow_anomalies` rows are never changed or deleted.
* An episode is one host, one span, many windows. Its severity is the highest severity it
  contains; its score is the maximum window score.
* Only high/critical episodes can page, and only within the host budget. Medium/low, later
  windows in the same episode, and over-budget episodes remain visible but are log-only.
* `page_window` is the one window that earns the page (highest score). A claim writes
  `paged_at`; a later refresh preserves it so the same episode cannot page twice.
* A failure to build/read episodes never suppresses detection: the caller catches and treats
  the page as allowed, and says why in the log.
"""
from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any

from clickhouse_connect.driver.client import Client

from weirvern.clock import utcnow
from weirvern.config import Settings

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
EPISODE_COLUMNS = [
    "src_addr", "episode_start", "episode_end", "first_detected", "last_detected",
    "occurrences", "window_count", "max_score", "severity", "severity_rank", "role",
    "page_window", "pageable", "page_reason", "paged_at", "updated_at",
]


def _naive_utc(value: Any) -> datetime:
    """Normalise ClickHouse/Python timestamps for ordering; naive UTC internally."""
    if isinstance(value, datetime):
        if value.tzinfo is not None:
            return value.astimezone(UTC).replace(tzinfo=None)
        return value
    text = str(value).strip().replace("Z", "+00:00")
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(UTC).replace(tzinfo=None)
    return parsed


def _rank(severity: str) -> int:
    return SEVERITY_RANK.get(str(severity or "").lower(), 0)


def _max_severity(values: Iterable[str]) -> str:
    return max((str(v or "").lower() for v in values), key=_rank, default="low")


def build_episodes(rows: list[dict[str, Any]], gap_minutes: int = 30) -> list[dict[str, Any]]:
    """Group anomaly rows by host and a start-to-start gap.

    The gap is measured between the previous window's END and the next window's START. A
    continuous five-minute series has zero gap and is one episode; a 31-minute silence starts a
    new episode. Inputs may be dicts with datetime or ISO strings; output is naive-UTC values.
    """
    gap = float(gap_minutes) * 60.0
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        src = str(row.get("src_addr") or "")
        start_raw = row.get("window_start")
        if not src or start_raw is None:
            continue
        start = _naive_utc(start_raw)
        end = _naive_utc(row.get("window_end") or start)
        grouped.setdefault(src, []).append({
            "src_addr": src,
            "window_start": start,
            "window_end": max(start, end),
            "detected_at": _naive_utc(row.get("detected_at") or start),
            "anomaly_score": float(row.get("anomaly_score") or 0.0),
            "severity": str(row.get("severity") or "low").lower(),
            "role": str(row.get("role") or ""),
        })

    episodes: list[dict[str, Any]] = []
    for items in grouped.values():
        items.sort(key=lambda item: (item["window_start"], item["window_end"]))
        current: list[dict[str, Any]] = []
        last_end: datetime | None = None
        for item in items:
            if current and last_end is not None and (item["window_start"] - last_end).total_seconds() > gap:
                episodes.append(_finish_episode(current))
                current = []
            current.append(item)
            last_end = item["window_end"] if last_end is None else max(last_end, item["window_end"])
        if current:
            episodes.append(_finish_episode(current))
    episodes.sort(key=lambda ep: (ep["episode_start"], ep["src_addr"]))
    return episodes


def _finish_episode(items: list[dict[str, Any]]) -> dict[str, Any]:
    starts = [item["window_start"] for item in items]
    ends = [item["window_end"] for item in items]
    # The winning window is the strongest score; ties go to the earliest window so the result
    # is stable across identical refreshes.
    winner = max(items, key=lambda item: (item["anomaly_score"], -item["window_start"].timestamp()))
    severity = _max_severity(item["severity"] for item in items)
    return {
        "src_addr": items[0]["src_addr"],
        "episode_start": min(starts),
        "episode_end": max(ends),
        "first_detected": min(item["detected_at"] for item in items),
        "last_detected": max(item["detected_at"] for item in items),
        "occurrences": len(items),
        "window_count": len(set(starts)),
        "max_score": max(item["anomaly_score"] for item in items),
        "severity": severity,
        "severity_rank": _rank(severity),
        "role": next((item["role"] for item in items if item["role"]), ""),
        "page_window": winner["window_start"],
        "pageable": 0,
        "page_reason": "",
        "paged_at": None,
    }


def apply_budget(episodes: list[dict[str, Any]], *, per_host_budget: int,
                 min_severity: str = "high",
                 paged_by_host: dict[str, int] | None = None) -> list[dict[str, Any]]:
    """Mark at most `per_host_budget` pageable high/critical episodes per host.

    `paged_by_host` is the count of already-paged episodes in the window. It is consumed by the
    budget so a second new episode cannot page after the first has used the host's allowance.
    The function mutates and returns the episode dicts for the caller's convenience.
    """
    floor = _rank(min_severity)
    supplied = paged_by_host is not None
    paged = dict(paged_by_host or {})
    by_host: dict[str, list[dict[str, Any]]] = {}
    for episode in episodes:
        if episode.get("paged_at"):
            episode["pageable"] = 0
            episode["page_reason"] = "paged"
            if not supplied:
                paged[episode["src_addr"]] = paged.get(episode["src_addr"], 0) + 1
        elif int(episode.get("severity_rank") or 0) < floor:
            episode["pageable"] = 0
            episode["page_reason"] = "below-min-severity"
        else:
            by_host.setdefault(episode["src_addr"], []).append(episode)

    for src, candidates in by_host.items():
        remaining = max(0, int(per_host_budget) - int(paged.get(src, 0)))
        candidates.sort(key=lambda ep: (-int(ep["severity_rank"]), -float(ep["max_score"]),
                                        ep["episode_start"]))
        for index, episode in enumerate(candidates):
            if index < remaining:
                episode["pageable"] = 1
                episode["page_reason"] = "within-budget"
            else:
                episode["pageable"] = 0
                episode["page_reason"] = "budget"
    return episodes


def _existing(client: Client, hours: int = 24) -> dict[tuple[str, datetime], dict[str, Any]]:
    result = client.query(
        "SELECT src_addr, episode_start, page_window, pageable, page_reason, paged_at "
        "FROM weirvern.alert_episodes FINAL "
        "WHERE episode_start >= now() - INTERVAL %(h)s HOUR",
        parameters={"h": int(hours)},
    )
    names = list(result.column_names)
    out: dict[tuple[str, datetime], dict[str, Any]] = {}
    for row in result.result_rows:
        item = dict(zip(names, row, strict=False))
        out[(str(item["src_addr"]), _naive_utc(item["episode_start"]))] = item
    return out


def _roles(client: Client) -> dict[str, str]:
    try:
        result = client.query("SELECT host, role FROM weirvern.host_roles FINAL")
        return {str(host): str(role or "") for host, role in result.result_rows}
    except Exception:  # noqa: BLE001 - roles are context, never a reason to stop detection
        return {}


def refresh(client: Client, settings: Settings, *, hours: int = 24) -> dict[str, int]:
    """Rebuild the recent episode view and write it to `alert_episodes`.

    ReplacingMergeTree rows are reinserted with `updated_at`; `paged_at` from the previous view
    is preserved so a refresh cannot reset a claimed page. A zero-row window is a valid empty
    result, not an error.
    """
    result = client.query(
        "SELECT detected_at, window_start, window_end, src_addr, anomaly_score, severity "
        "FROM weirvern.netflow_anomalies "
        "WHERE window_start >= now() - INTERVAL %(h)s HOUR",
        parameters={"h": int(hours)},
    )
    columns = list(result.column_names)
    rows = [dict(zip(columns, row, strict=False)) for row in result.result_rows]
    roles = _roles(client)
    for row in rows:
        row["role"] = roles.get(str(row.get("src_addr") or ""), "")

    episodes = build_episodes(rows, int(settings.episode_gap_minutes))
    previous = _existing(client, hours=hours)
    paged_by_host: dict[str, int] = {}
    for episode in episodes:
        key = (episode["src_addr"], episode["episode_start"])
        prior = previous.get(key)
        if prior:
            if prior.get("paged_at") is not None:
                episode["paged_at"] = prior["paged_at"]
                episode["page_window"] = prior["page_window"]
            else:
                # Keep a previously chosen window if the max moved by a few points; this avoids
                # a moving target when a later window is only marginally stronger.
                episode["page_window"] = prior.get("page_window") or episode["page_window"]
        if episode.get("paged_at"):
            paged_by_host[episode["src_addr"]] = paged_by_host.get(episode["src_addr"], 0) + 1

    apply_budget(
        episodes,
        per_host_budget=int(settings.episode_page_budget),
        min_severity=str(settings.episode_page_min_severity),
        paged_by_host=paged_by_host,
    )
    now = utcnow()
    values = [[episode[col] for col in EPISODE_COLUMNS[:-1]] + [now] for episode in episodes]
    if values:
        client.insert("weirvern.alert_episodes", values, column_names=EPISODE_COLUMNS)
    return {
        "episodes": len(episodes),
        "pageable": sum(1 for episode in episodes if episode.get("pageable")),
    }


def claim(client: Client, verdict: dict[str, Any], settings: Settings) -> bool:
    """Return True only for the one pageable window of an unclaimed episode.

    If the episode view is unavailable, this returns True: detection must not disappear because
    the budgeting read failed. The caller logs the exception and the reason.
    """
    src = str(verdict.get("src_addr") or "")
    start_raw = verdict.get("window_start")
    if not src or start_raw is None:
        return True
    at = _naive_utc(start_raw)
    result = client.query(
        "SELECT src_addr, episode_start, episode_end, first_detected, last_detected, "
        "occurrences, window_count, max_score, severity, severity_rank, role, page_window, "
        "pageable, page_reason, paged_at "
        "FROM weirvern.alert_episodes FINAL "
        "WHERE src_addr = %(src)s AND episode_start <= %(at)s AND episode_end >= %(at)s "
        "ORDER BY episode_start DESC LIMIT 1",
        parameters={"src": src, "at": at},
    )
    if not result.result_rows:
        return True
    names = list(result.column_names)
    episode = dict(zip(names, result.result_rows[0], strict=False))
    if episode.get("paged_at") is not None:
        return False
    if not int(episode.get("pageable") or 0):
        return False
    if _naive_utc(episode.get("page_window")) != at:
        return False
    now = utcnow()
    episode.update({"pageable": 0, "page_reason": "paged", "paged_at": now,
                    "updated_at": now})
    client.insert("weirvern.alert_episodes",
                  [[episode[col] for col in EPISODE_COLUMNS]],
                  column_names=EPISODE_COLUMNS)
    return True


__all__ = ["SEVERITY_RANK", "apply_budget", "build_episodes", "claim", "refresh"]
