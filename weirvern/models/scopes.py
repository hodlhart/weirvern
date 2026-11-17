"""The HOST scope: what each host's own history says it should be doing, right now.

WHY PER-HOST AND PER-HOUR. A fleet-wide baseline calls a torrent node an anomaly every night
(measured: 5,944 peers in four days, a 25x diurnal swing, 19 to 45 percent of the whole alert
volume). The same volume at the same hour is not news; the same volume at an hour the host is
normally asleep is. So the profile is per host AND per hour of the day, from the host's own last
two weeks, and the comparison is against the hour we are in rather than the day's average.

MEDIAN AND P90, NOT MEAN AND SIGMA. Traffic is heavy-tailed: one 15.9 GB peer in a day moves a
mean far enough that the next ordinary day looks quiet. The median is unchanged by that peer,
and the 90th percentile gives the departure line without pretending the distribution is normal.

THIS IS ONE OF THREE SCOPES. The host profile is the most specific. A class profile (hosts that
share a peer or domain set) and a segment profile (the subnet's own envelope) sit above it, and a
broader scope EXPLAINS a narrower one: a peer that is new to a host but routine for its class is
not novelty. They are not built yet; when they are, this module is the input to them, because
every class and segment profile is a union of host rows.
"""
from __future__ import annotations

import statistics
from typing import Any

# Two weeks: long enough to see a weekly rhythm twice, short enough that a host rebuilt or
# renumbered last month does not drag an obsolete profile along.
DEFAULT_DAYS = 14


def host_hour_profiles(client: Any, days: int = DEFAULT_DAYS) -> dict[str, dict[int, dict[str, float]]]:
    """Per host, per hour of day: median bytes, p90 bytes, median peers.

    Reads `flows_aggregated`, which already holds per-window, per-source aggregates -- the same
    rows the panel draws -- so this adds no scan of raw flows.
    """
    rows = client.query(
        "SELECT src_addr, toHour(window_start) AS hour, "
        "       quantile(0.5)(total_bytes) AS med_bytes, "
        "       quantile(0.9)(total_bytes) AS p90_bytes, "
        "       quantile(0.5)(unique_dst_ips) AS med_peers "
        "FROM weirvern.flows_aggregated "
        "WHERE window_start >= now() - INTERVAL %(days)s DAY "
        "GROUP BY src_addr, hour",
        parameters={"days": int(days)},
    ).result_rows
    out: dict[str, dict[int, dict[str, float]]] = {}
    for src, hour, med_bytes, p90_bytes, med_peers in rows or []:
        host = str(src or "")
        if not host:
            continue
        out.setdefault(host, {})[int(hour)] = {
            "median_bytes": float(med_bytes or 0),
            "p90_bytes": float(p90_bytes or 0),
            "median_peers": float(med_peers or 0),
        }
    return out


def rank_departures(client: Any, *, recent_minutes: int = 60, days: int = DEFAULT_DAYS,
                    limit: int = 12) -> list[dict[str, Any]]:
    """Hosts whose last hour is furthest from their own profile for THAT hour.

    The ratio is to the host's own p90 for this hour of day, so a host that always talks to
    thousands of peers scores about 1 while a sleeper host that suddenly uploads scores high.
    A host with no profile row for this hour is reported as `new_hour` rather than scored: it has
    no history to depart from, and inventing one would be the fleet-wide mistake again.
    """
    profiles = host_hour_profiles(client, days=days)
    now_hour = int(client.query("SELECT toHour(now())").result_rows[0][0])
    recent = client.query(
        "SELECT src_addr, sum(total_bytes) AS bytes, max(unique_dst_ips) AS peers "
        "FROM weirvern.flows_aggregated "
        "WHERE window_start >= now() - INTERVAL %(m)s MINUTE "
        "GROUP BY src_addr",
        parameters={"m": int(recent_minutes)},
    ).result_rows
    out: list[dict[str, Any]] = []
    for src, bytes_now, peers_now in recent or []:
        host = str(src or "")
        prof = (profiles.get(host) or {}).get(now_hour)
        if prof is None:
            out.append({"host": host, "state": "new_hour", "bytes": int(bytes_now or 0),
                        "peers": int(peers_now or 0), "ratio": None, "hour": now_hour})
            continue
        p90 = prof["p90_bytes"] or prof["median_bytes"]
        ratio = (float(bytes_now or 0) / p90) if p90 > 0 else None
        out.append({
            "host": host, "state": "scored", "hour": now_hour,
            "bytes": int(bytes_now or 0), "peers": int(peers_now or 0),
            "median_bytes": prof["median_bytes"], "p90_bytes": prof["p90_bytes"],
            "median_peers": prof["median_peers"], "ratio": round(ratio, 2) if ratio else None,
        })
    scored = [r for r in out if r["ratio"] is not None]
    fresh = [r for r in out if r["ratio"] is None]
    scored.sort(key=lambda r: r["ratio"], reverse=True)
    return (scored + fresh)[:int(limit)]


def summarise(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """What a report line says, computed once so the panel and a digest cannot disagree."""
    scored = [r for r in rows if r.get("ratio") is not None]
    ratios = [r["ratio"] for r in scored if r["ratio"] is not None]
    return {
        "hosts_scored": len(scored),
        "hosts_without_history": len(rows) - len(scored),
        "median_ratio": round(statistics.median(ratios), 2) if ratios else None,
        "worst_ratio": max(ratios) if ratios else None,
        "quiet_control": "a host whose peers are in the thousands and whose ratio stays near 1 "
                         "is the control that the profile is doing its job",
    }
