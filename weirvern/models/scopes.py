"""The HOST scope: what each host's own history says it should be doing, right now.

WHY PER-HOST AND PER-HOUR. A fleet-wide baseline calls a torrent node an anomaly every night
(measured: 5,944 peers in four days, a 25x diurnal swing, 19 to 45 percent of the whole alert
volume). The same volume at the same hour is not news; the same volume at an hour the host is
normally asleep is. So the profile is per host AND per hour of the day, from the host's own last
two weeks, compared against the hour we are in rather than the day's average.

READS `flows_window`, NOT `flows_aggregated`. The latter is a plain MergeTree behind a
materialized view, and a ClickHouse MView fires once per inserted block, so its GROUP BY runs
within a block rather than across the window: one host-window appears many times. The
AggregatingMergeTree has the same shape without that defect, but its columns are STATES, so
every read merges them first (`sumMerge`, `uniqMerge`, `countMerge`) and computes quantiles over
the merged buckets.

MEDIAN AND P90, NOT MEAN AND SIGMA. Traffic is heavy-tailed; one 15.9 GB peer in a day moves a
mean far enough that the next ordinary day looks quiet.

ONLY HOSTS OF OURS. The scope is the same one the asset inventory uses -- networks flagged
monitored -- because a profile of a stranger is not a profile of the network.
"""
from __future__ import annotations

import statistics
from datetime import UTC, datetime, timedelta
from typing import Any

DEFAULT_DAYS = 14
# A profile is only comparable with data from the same capture regime: the mirrored port saw the
# whole segment, the in-path sensor sees the hosts its plan names, and mixing them made every host
# read far below its own p90 minutes after the switch (measured median ratio 0.38). Callers name an
# era; the default is the current regime by assumption, stated rather than guessed.
DEFAULT_ERA_HOURS = 6


def era_start(hours: int = DEFAULT_ERA_HOURS) -> str:
    """An ISO timestamp the queries can filter on: this capture regime only."""
    return (datetime.now(UTC) - timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%S")


def _scope(client: Any) -> str:
    from weirvern import monitored as monitored_mod  # noqa: PLC0415

    return monitored_mod.sql_predicate("src_addr", monitored_mod.networks(client))


def _merged(sql: str, client: Any, params: dict[str, Any]) -> list[Any]:
    return client.query(sql, parameters=params).result_rows or []


def host_hour_profiles(client: Any, *, days: int = DEFAULT_DAYS, era: str | None = None
                       ) -> dict[str, dict[int, dict[str, float]]]:
    """Per host, per hour of day: median bytes, p90 bytes, median peers, from merged buckets."""
    era = era or era_start(days * 24)
    rows = _merged(
        "SELECT src_addr, toHour(window_start) AS hour, "
        "       quantile(0.5)(bytes) AS med_bytes, quantile(0.9)(bytes) AS p90_bytes, "
        "       quantile(0.5)(peers) AS med_peers "
        "FROM ("
        "  SELECT src_addr, window_start, sumMerge(total_bytes) AS bytes, "
        "         uniqMerge(unique_dst_ips) AS peers "
        "  FROM weirvern.flows_window "
        f"  WHERE window_start >= %(era)s AND {_scope(client)} "
        "  GROUP BY src_addr, window_start"
        ") GROUP BY src_addr, hour",
        client, {"era": era},
    )
    out: dict[str, dict[int, dict[str, float]]] = {}
    for src, hour, med_bytes, p90_bytes, med_peers in rows:
        host = str(src or "")
        if host:
            out.setdefault(host, {})[int(hour)] = {
                "median_bytes": float(med_bytes or 0),
                "p90_bytes": float(p90_bytes or 0),
                "median_peers": float(med_peers or 0),
            }
    return out


def recent_hour(client: Any, *, minutes: int = 60, era: str | None = None) -> dict[str, dict[str, int]]:
    """What each of our hosts has actually done in the last `minutes`, from merged buckets."""
    era = era or era_start(24)
    rows = _merged(
        "SELECT src_addr, sum(bytes) AS bytes, max(peers) AS peers FROM ("
        "  SELECT src_addr, window_start, sumMerge(total_bytes) AS bytes, "
        "         uniqMerge(unique_dst_ips) AS peers "
        "  FROM weirvern.flows_window "
        f"  WHERE window_start >= %(era)s AND window_start >= now() - INTERVAL %(m)s MINUTE "
        f"  AND {_scope(client)} "
        "  GROUP BY src_addr, window_start"
        ") GROUP BY src_addr",
        client, {"era": era, "m": int(minutes)},
    )
    return {str(src): {"bytes": int(b or 0), "peers": int(p or 0)} for src, b, p in rows if src}


def rank_departures(client: Any, *, recent_minutes: int = 60, days: int = DEFAULT_DAYS,
                    era: str | None = None, limit: int = 12) -> list[dict[str, Any]]:
    """Hosts whose last hour is furthest from their own p90 for THIS hour.

    A host with no row for this hour is `new_hour` rather than scored: inventing a baseline is the
    fleet-wide mistake in miniature.
    """
    profiles = host_hour_profiles(client, days=days, era=era)
    recent = recent_hour(client, minutes=recent_minutes, era=era)
    now_hour = int(client.query("SELECT toHour(now())").result_rows[0][0])
    out: list[dict[str, Any]] = []
    for host, now in recent.items():
        prof = (profiles.get(host) or {}).get(now_hour)
        if prof is None:
            out.append({"host": host, "state": "new_hour", "hour": now_hour,
                        "bytes": now["bytes"], "peers": now["peers"], "ratio": None})
            continue
        p90 = prof["p90_bytes"] or prof["median_bytes"]
        ratio = (now["bytes"] / p90) if p90 > 0 else None
        out.append({"host": host, "state": "scored", "hour": now_hour,
                    "bytes": now["bytes"], "peers": now["peers"],
                    "median_bytes": prof["median_bytes"], "p90_bytes": prof["p90_bytes"],
                    "median_peers": prof["median_peers"],
                    "ratio": round(ratio, 2) if ratio is not None else None})
    scored = sorted((r for r in out if r["ratio"] is not None),
                    key=lambda r: r["ratio"], reverse=True)
    fresh = [r for r in out if r["ratio"] is None]
    return (scored + fresh)[:int(limit)]


def peer_sets(client: Any, *, era: str, hours: int = 24) -> dict[str, set[str]]:
    """Each host's peers inside one era, from raw flows. The window table has no destination."""
    from weirvern import monitored as monitored_mod  # noqa: PLC0415

    ours = monitored_mod.sql_predicate("src_addr", monitored_mod.networks(client))
    rows = client.query(
        "SELECT src_addr, groupUniqArray(dst_addr) FROM weirvern.flows "
        "WHERE timestamp >= %(era)s AND timestamp >= now() - INTERVAL %(h)s HOUR "
        f"AND {ours} GROUP BY src_addr",
        parameters={"era": era, "h": int(hours)},
    ).result_rows
    return {str(src): {str(p) for p in (peers or [])} for src, peers in rows or [] if src}


def class_profiles(sets: dict[str, set[str]], *, min_shared: int = 3,
                   min_overlap: float = 0.4) -> list[dict[str, Any]]:
    """Hosts that look alike, judged by the OVERLAP of their peer sets.

    "All the iPhones talk to the same endpoints" is a class, and the size of each set is
    irrelevant -- which is the point on a chatty host. The test is containment, not strict
    Jaccard, so one busy member cannot drag a quiet sibling out of its class.
    """
    hosts = sorted(sets)
    groups: list[dict[str, Any]] = []
    seen: set[str] = set()
    for i, host in enumerate(hosts):
        if host in seen:
            continue
        members = [host]
        for other in hosts[i + 1:]:
            if other in seen:
                continue
            a, b = sets[host], sets[other]
            shared = len(a & b)
            if shared >= min_shared and shared / (min(len(a), len(b)) or 1) >= min_overlap:
                members.append(other)
        if len(members) > 1:
            seen.update(members)
            union: set[str] = set()
            for m in members:
                union |= sets[m]
            groups.append({"members": sorted(members), "peers": len(union),
                           "shared": len(set.intersection(*(sets[m] for m in members)))})
    return groups


def explain(host: str, peers: set[str], classes: list[dict[str, Any]],
            sets: dict[str, set[str]]) -> dict[str, Any]:
    """A peer new to a host but routine for its class is NOT novelty: the composition rule."""
    for group in classes:
        if host in group["members"]:
            siblings: set[str] = set()
            for m in group["members"]:
                if m != host:
                    siblings |= sets.get(m, set())
            novel = peers - siblings
            return {"host": host, "class": group["members"],
                    "explained": len(peers) - len(novel),
                    "novel": sorted(novel)[:20], "novel_count": len(novel)}
    return {"host": host, "class": [], "explained": 0,
            "novel": sorted(peers)[:20], "novel_count": len(peers)}


def summarise(rows: list[dict[str, Any]]) -> dict[str, Any]:
    scored = [r for r in rows if r.get("ratio") is not None]
    ratios = [r["ratio"] for r in scored]
    return {
        "hosts_scored": len(scored),
        "hosts_without_history": len(rows) - len(scored),
        "median_ratio": round(statistics.median(ratios), 2) if ratios else None,
        "worst_ratio": max(ratios) if ratios else None,
        "quiet_control": "a host whose peers are in the thousands and whose ratio stays near 1 "
                         "is the control that the profile is doing its job",
    }
