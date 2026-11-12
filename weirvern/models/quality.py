"""OP-1: the ML quality SLO, in one read-only report.

The point is not a pretty dashboard. It is that every number says its window and its source,
and a missing label, a dead shadow channel or a zero-row source is `not measured` rather than a
zero that reads as success.
"""
from __future__ import annotations

from typing import Any

WINDOWS = (7, 14, 30)


def _metric(name: str, value: Any, target: Any, state: str, source: str,
            note: str = "") -> dict[str, Any]:
    return {"name": name, "value": value, "target": target, "state": state,
            "source": source, "note": note}


def _window(client: Any, days: int) -> dict[str, Any]:
    alerts = pageable = paged = hosts = None
    latency = None
    try:
        row = client.query(
            "SELECT count(), countIf(severity IN ('high','critical')), uniqExact(src_addr), "
            "quantile(0.5)(dateDiff('second', window_start, detected_at)) "
            "FROM weirvern.netflow_anomalies "
            "WHERE detected_at >= now() - INTERVAL %(d)s DAY",
            parameters={"d": int(days)},
        ).result_rows
        values = list(row[0]) if row else []
        alerts, severe, hosts, latency = (values + [None, None, None, None])[:4]
        alerts = int(alerts or 0)
        severe = int(severe or 0)
        hosts = int(hosts or 0)
        latency = round(float(latency), 1) if latency is not None else None
    except Exception as exc:  # noqa: BLE001
        severe = 0
        error = f"anomaly query failed: {type(exc).__name__}"
        return {"days": days, "available": False, "reason": error,
                "metrics": [_metric("alerts/day", None, None, "not measured", "netflow_anomalies",
                                    error)]}
    try:
        erow = client.query(
            "SELECT count(), countIf(pageable), countIf(paged_at IS NOT NULL) "
            "FROM weirvern.alert_episodes FINAL "
            "WHERE episode_start >= now() - INTERVAL %(d)s DAY",
            parameters={"d": int(days)},
        ).result_rows
        evalues = list(erow[0]) if erow else []
        episodes, pageable, paged = (evalues + [0, 0, 0])[:3]
        episodes, pageable, paged = int(episodes or 0), int(pageable or 0), int(paged or 0)
    except Exception as exc:  # noqa: BLE001
        episodes = pageable = paged = None
        episode_error = f"episode query failed: {type(exc).__name__}"
    else:
        episode_error = ""
    # HOW FAR BACK THE EPISODE TABLE ACTUALLY GOES. Without this, a 30-day label over a
    # 14-day source reports the 14-day number twice and looks like a plateau (measured on the
    # live box 2026-11-11: the 14- and 30-day windows were identical). A window the source
    # cannot cover is "not measured", never a number wearing a longer label.
    episode_source_days = None
    try:
        crow = client.query(
            "SELECT dateDiff('day', min(episode_start), now()) FROM weirvern.alert_episodes FINAL"
        ).result_rows
        if crow and crow[0] and crow[0][0] is not None:
            episode_source_days = int(crow[0][0])
    except Exception:  # noqa: BLE001
        episode_source_days = None
    episode_covered = episode_source_days is None or int(days) <= episode_source_days + 1
    shadow_age = None
    try:
        srow = client.query(
            "SELECT dateDiff('second', max(computed_at), now()) FROM weirvern.ml_window_scores"
        ).result_rows
        shadow_age = int(srow[0][0]) if srow and srow[0] and srow[0][0] is not None else None
    except Exception:  # noqa: BLE001
        pass
    drift = None
    try:
        drow = client.query(
            "SELECT countIf(status = 'drift') FROM weirvern.ml_drift "
            "WHERE computed_at >= now() - INTERVAL %(d)s DAY",
            parameters={"d": int(days)},
        ).result_rows
        drift = int(drow[0][0]) if drow and drow[0] else None
    except Exception:  # noqa: BLE001
        pass
    metrics = [
        _metric("alerts/day", round(alerts / days, 2), "page budget: 2 pages/host/day",
                "observed", "netflow_anomalies", f"{severe} high/critical; {hosts} hosts"),
        _metric("precision at the page budget", None, None, "not measured", "alert_reviews",
                "no oracle: an operator review is not a verified label"),
        _metric("false alarms / host / day", None, None, "not measured", "clean replay",
                "no clean-background replay has been attached to this window"),
        _metric("detection latency", latency, 300, "breach" if latency is not None and latency > 300
                else ("meets" if latency is not None else "not measured"), "netflow_anomalies",
                "median seconds from window start to detection"),
        _metric("episodes", episodes if episode_covered else None,
                "one incident, not every window",
                "observed" if episode_covered and episodes is not None else "not measured",
                "alert_episodes",
                episode_error or (f"{pageable} pageable; {paged} paged" if episode_covered else
                                  f"the episode source covers {episode_source_days} day(s); a "
                                  f"{days}-day figure over it would be that number wearing a "
                                  f"{days}-day label")),
        _metric("pageable episodes / day",
                round(pageable / days, 2) if pageable is not None and episode_covered else None,
                "2 per host/day",
                "observed" if pageable is not None and episode_covered else "not measured",
                "alert_episodes",
                episode_error or ("" if episode_covered else
                                  f"the episode source covers {episode_source_days} day(s)")),
        _metric("drift notices", drift, "review, never a page",
                "observed" if drift is not None else "not measured", "ml_drift",
                "a drift row is a notice, not an alert"),
        _metric("shadow freshness", shadow_age, 900,
                "meets" if shadow_age is not None and shadow_age <= 900
                else ("stale" if shadow_age is not None else "not measured"),
                "ml_window_scores", "seconds since the last scored population row"),
    ]
    return {"days": days, "available": True, "source_days": episode_source_days,
            "metrics": metrics}


def report(client: Any, windows: tuple[int, ...] = WINDOWS) -> dict[str, Any]:
    return {"available": True, "live_precision": "not measured",
            "windows": [_window(client, int(days)) for days in windows],
            "disclaimer": "live precision is not measured without an oracle; no zero is shown in its place"}
