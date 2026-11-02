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
from datetime import UTC, datetime, timedelta
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
# A superseded row is kept as history but is not an active episode. Using the existing
# `page_reason` value avoids a destructive migration and lets every reader filter one predicate.
SUPERSEDED_REASON = "superseded"


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


def _overlaps(one: dict[str, Any], other: dict[str, Any]) -> bool:
    return (
        _naive_utc(one["episode_start"]) <= _naive_utc(other["episode_end"])
        and _naive_utc(other["episode_start"]) <= _naive_utc(one["episode_end"])
    )


def _merge_overlapping(episodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Collapse overlapping rebuilt episodes for the same host before comparing with history.

    `build_episodes` should already return disjoint intervals, but live anomaly rows can carry
    mixed naive/aware timestamps from different ingesters; that produced two rebuilt episodes for
    one host whose intervals overlapped. Never write two active episodes for overlapping
    intervals: merge them here first.
    """
    by_host: dict[str, list[dict[str, Any]]] = {}
    for episode in episodes:
        by_host.setdefault(str(episode.get("src_addr") or ""), []).append(episode)
    out: list[dict[str, Any]] = []
    for rows in by_host.values():
        current: dict[str, Any] | None = None
        for episode in sorted(rows, key=lambda item: _naive_utc(item["episode_start"])):
            if current is None:
                current = episode
                continue
            if not _overlaps(current, episode):
                out.append(current)
                current = episode
                continue
            current["episode_start"] = min([current["episode_start"], episode["episode_start"]],
                                           key=_naive_utc)
            current["episode_end"] = max([current["episode_end"], episode["episode_end"]],
                                         key=_naive_utc)
            current["first_detected"] = min(
                [current["first_detected"], episode["first_detected"]], key=_naive_utc)
            current["last_detected"] = max(
                [current["last_detected"], episode["last_detected"]], key=_naive_utc)
            current["occurrences"] = max(int(current.get("occurrences") or 0),
                                         int(episode.get("occurrences") or 0))
            current["window_count"] = max(int(current.get("window_count") or 0),
                                          int(episode.get("window_count") or 0))
            if float(episode.get("max_score") or 0.0) > float(current.get("max_score") or 0.0):
                current["max_score"] = episode["max_score"]
                current["page_window"] = episode["page_window"]
            if int(episode.get("severity_rank") or 0) > int(current.get("severity_rank") or 0):
                current["severity"] = episode["severity"]
                current["severity_rank"] = episode["severity_rank"]
            if not current.get("role") and episode.get("role"):
                current["role"] = episode["role"]
            if episode.get("paged_at") is not None and current.get("paged_at") is None:
                current["paged_at"] = episode["paged_at"]
        if current is not None:
            out.append(current)
    return out


def merge_with_previous(
    episodes: list[dict[str, Any]], previous: Iterable[dict[str, Any]]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Merge a rebuilt episode with older copies of the same incident.

    THE DEFECT THIS REPLACES. `refresh` used to key an episode on
    `(src_addr, episode_start)` after reading only a 24-hour window. For a host that stayed
    anomalous, the oldest window fell out of that window every five minutes, so the computed
    start moved forward and the next refresh inserted a NEW key. `ReplacingMergeTree` cannot
    collapse different keys. The live table reached 2,487 rows for 19 hosts in 24 hours, while
    the same anomaly rows collapsed to 68 episodes.

    This function keeps the earliest start and the latest end of every overlapping group, and
    returns the older rows separately so `refresh` can mark them `superseded` without deleting
    any history. A row whose key IS the canonical key is not marked: the canonical insert
    replaces that row directly.

    `occurrences` and `window_count` use the maximum, not a sum: the old rows are duplicates of
    the same anomaly windows, so summing them would count the incident twice.
    """
    episodes = _merge_overlapping(episodes)
    prior_by_host: dict[str, list[dict[str, Any]]] = {}
    for row in previous:
        prior_by_host.setdefault(str(row.get("src_addr") or ""), []).append(dict(row))

    superseded: list[dict[str, Any]] = []

    # COLLAPSE DUPLICATES THAT EXISTED BEFORE THIS REFRESH, even when they sit before the
    # current episode and therefore never overlap it. The first live run exposed this: old
    # rows whose last window ended just before the current incident's gap survived forever,
    # because merge only compared them with the new episode. Overlap alone is the duplicate
    # test -- two distinct incidents separated by the episode gap do not overlap.
    for host_rows in prior_by_host.values():
        kept: list[dict[str, Any]] = []
        for prior in sorted(host_rows, key=lambda item: _naive_utc(item["episode_start"])):
            if any(_overlaps(prior, earlier) for earlier in kept):
                if str(prior.get("page_reason") or "") != SUPERSEDED_REASON:
                    old = dict(prior)
                    old["pageable"] = 0
                    old["page_reason"] = SUPERSEDED_REASON
                    superseded.append(old)
            else:
                kept.append(prior)

    seen_superseded: set[tuple[str, datetime]] = {
        (str(row.get("src_addr") or ""), _naive_utc(row["episode_start"]))
        for row in superseded
    }

    def _mark_superseded(prior: dict[str, Any]) -> None:
        key = (str(prior.get("src_addr") or ""), _naive_utc(prior["episode_start"]))
        if key in seen_superseded:
            return
        seen_superseded.add(key)
        superseded.append(prior)

    for episode in episodes:
        src = str(episode.get("src_addr") or "")
        overlaps = [p for p in prior_by_host.get(src, []) if _overlaps(episode, p)]
        if not overlaps:
            continue

        start = min([episode["episode_start"]] + [p["episode_start"] for p in overlaps],
                    key=_naive_utc)
        end = max([episode["episode_end"]] + [p["episode_end"] for p in overlaps],
                  key=_naive_utc)
        episode["episode_start"] = start
        episode["episode_end"] = end
        episode["first_detected"] = min(
            [episode["first_detected"]] + [p["first_detected"] for p in overlaps],
            key=_naive_utc
        )
        episode["last_detected"] = max(
            [episode["last_detected"]] + [p["last_detected"] for p in overlaps],
            key=_naive_utc
        )
        episode["occurrences"] = max(
            [int(episode.get("occurrences") or 0)]
            + [int(p.get("occurrences") or 0) for p in overlaps]
        )
        episode["window_count"] = max(
            [int(episode.get("window_count") or 0)]
            + [int(p.get("window_count") or 0) for p in overlaps]
        )
        episode["max_score"] = max(
            [float(episode.get("max_score") or 0.0)]
            + [float(p.get("max_score") or 0.0) for p in overlaps]
        )
        best = max(
            [episode] + overlaps,
            key=lambda item: (int(item.get("severity_rank") or 0),
                              float(item.get("max_score") or 0.0)),
        )
        episode["severity"] = best.get("severity") or episode.get("severity") or "low"
        episode["severity_rank"] = int(best.get("severity_rank") or _rank(episode["severity"]))
        episode["role"] = next(
            (str(item.get("role")) for item in [episode] + overlaps if item.get("role")), ""
        )

        paged = next((p for p in overlaps if p.get("paged_at") is not None), None)
        if paged:
            episode["paged_at"] = paged["paged_at"]
            window = paged.get("page_window")
            if window is not None and _naive_utc(start) <= _naive_utc(window) <= _naive_utc(end):
                episode["page_window"] = window

        canonical_key = (src, _naive_utc(start))
        for prior in overlaps:
            if str(prior.get("page_reason") or "") == SUPERSEDED_REASON:
                continue
            if (str(prior.get("src_addr") or ""), _naive_utc(prior["episode_start"])) == canonical_key:
                continue
            old = dict(prior)
            old["pageable"] = 0
            old["page_reason"] = SUPERSEDED_REASON
            _mark_superseded(old)
    return _merge_overlapping(episodes), superseded


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
        "SELECT " + ", ".join(EPISODE_COLUMNS) + " "
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

    THE LOOKBACK IS NOT THE DISPLAY WINDOW. The builder reads a longer history
    (`episode_lookback_h`, default 30 days) so a continuous incident keeps ONE start timestamp
    even as the last-24-hours display window slides. It then writes only episodes that ended
    inside the display window, plus `superseded` rows for older overlapping copies.

    ReplacingMergeTree rows are reinserted with `updated_at`; `paged_at` from the previous view
    is preserved so a refresh cannot reset a claimed page. A zero-row window is a valid empty
    result, not an error.
    """
    lookback = max(int(hours), int(getattr(settings, "episode_lookback_h", hours)))
    result = client.query(
        "SELECT detected_at, window_start, window_end, src_addr, anomaly_score, severity "
        "FROM weirvern.netflow_anomalies "
        "WHERE window_start >= now() - INTERVAL %(h)s HOUR",
        parameters={"h": lookback},
    )
    columns = list(result.column_names)
    rows = [dict(zip(columns, row, strict=False)) for row in result.result_rows]
    roles = _roles(client)
    for row in rows:
        row["role"] = roles.get(str(row.get("src_addr") or ""), "")

    now = utcnow()
    cutoff = _naive_utc(now) - timedelta(hours=int(hours))
    episodes = [
        episode for episode in build_episodes(rows, int(settings.episode_gap_minutes))
        if _naive_utc(episode["episode_end"]) >= cutoff
    ]
    previous = _existing(client, hours=lookback)
    episodes, superseded = merge_with_previous(episodes, previous.values())

    # A previous view written by the timezone-shifted build can carry an end or last-seen window
    # in the future. That both inflates the incident duration and makes the incident view's upper
    # bound hide it. Clamp to the current clock before applying the budget.
    now_naive = _naive_utc(now)
    for episode in episodes:
        for field in ("episode_end", "last_detected"):
            value = episode.get(field)
            if value is not None and _naive_utc(value) > now_naive:
                episode[field] = now if getattr(value, "tzinfo", None) else now_naive
        page_window = episode.get("page_window")
        if page_window is not None and _naive_utc(page_window) > now_naive:
            episode["page_window"] = episode["episode_end"]

    # Any older row that still carries a future end/last-seen value cannot be a current
    # incident. It is left over from the shifted-key generation; retire it as history instead of
    # letting it inflate the active count while the upper-bounded incident view hides it.
    seen_superseded = {
        (str(row.get("src_addr") or ""), _naive_utc(row["episode_start"]))
        for row in superseded
    }
    for prior in previous.values():
        if str(prior.get("page_reason") or "") == SUPERSEDED_REASON:
            continue
        stale = (
            _naive_utc(prior["episode_end"]) > now_naive
            or _naive_utc(prior["last_detected"]) > now_naive
        )
        if not stale:
            continue
        key = (str(prior.get("src_addr") or ""), _naive_utc(prior["episode_start"]))
        if key in seen_superseded:
            continue
        old = dict(prior)
        old["pageable"] = 0
        old["page_reason"] = SUPERSEDED_REASON
        superseded.append(old)
        seen_superseded.add(key)

    paged_by_host: dict[str, int] = {}
    for prior in previous.values():
        if (str(prior.get("page_reason") or "") != SUPERSEDED_REASON
                and prior.get("paged_at") is not None
                and _naive_utc(prior["episode_end"]) >= cutoff):
            host = str(prior.get("src_addr") or "")
            paged_by_host[host] = paged_by_host.get(host, 0) + 1

    apply_budget(
        episodes,
        per_host_budget=int(settings.episode_page_budget),
        min_severity=str(settings.episode_page_min_severity),
        paged_by_host=paged_by_host,
    )
    # Superseded rows are history, never active episodes. Their updated_at is deliberately one
    # millisecond before the canonical row so a same-key canonical write wins deterministically.
    superseded_values = [
        [row[col] for col in EPISODE_COLUMNS[:-1]] + [now] for row in superseded
    ]
    if superseded_values:
        client.insert("weirvern.alert_episodes", superseded_values, column_names=EPISODE_COLUMNS)
    canonical_updated = now + timedelta(milliseconds=1)
    values = [
        [episode[col] for col in EPISODE_COLUMNS[:-1]] + [canonical_updated]
        for episode in episodes
    ]
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
        "AND page_reason != 'superseded' "
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


__all__ = ["SEVERITY_RANK", "SUPERSEDED_REASON", "apply_budget", "build_episodes", "claim",
           "merge_with_previous", "refresh"]
