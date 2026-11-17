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
from typing import Any

DEFAULT_DAYS = 14
# A profile is only comparable with data from the same capture regime: the mirrored port saw the
# whole segment, the in-path sensor sees the hosts its plan names, and mixing them made every host
# read far below its own p90 minutes after the switch (measured median ratio 0.38). Callers name an
# era; the default is the current regime by assumption, stated rather than guessed.
DEFAULT_ERA_HOURS = 6


def era_start(client: Any, hours: int = DEFAULT_ERA_HOURS) -> str:
    """The era boundary, taken from the DATABASE clock, not this process's.

    MEASURED 2026-11-17: the first live run returned nothing. The container is UTC and ClickHouse
    runs on the deployment's local clock, so an era computed here was six hours ahead of the rows
    and filtered every one of them out. A timestamp compared against another clock is the same
    class of bug as the naive/aware drain cursor; taking it from `now()` on the server removes the
    question.
    """
    row = client.query("SELECT toString(now() - INTERVAL %(h)s HOUR)",
                       parameters={"h": int(hours)}).result_rows[0]
    return str(row[0])


def _scope(client: Any) -> str:
    from weirvern import monitored as monitored_mod  # noqa: PLC0415

    return monitored_mod.sql_predicate("src_addr", monitored_mod.networks(client))


def _merged(sql: str, client: Any, params: dict[str, Any]) -> list[Any]:
    return client.query(sql, parameters=params).result_rows or []


def host_hour_profiles(client: Any, *, days: int = DEFAULT_DAYS, era: str | None = None
                       ) -> dict[str, dict[int, dict[str, float]]]:
    """Per host, per hour of day: median bytes, p90 bytes, median peers, from merged buckets."""
    era = era or era_start(client, days * 24)
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
    era = era or era_start(client, 24)
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


def rank_from(profiles: dict[str, dict[int, dict[str, float]]],
              recent: dict[str, dict[str, int]], now_hour: int, *, limit: int = 12,
              key: str = "host") -> list[dict[str, Any]]:
    """The ranking rule itself, over profiles and a recent window. Pure, so a control can call it.

    Split out of `rank_departures` for one reason: the exfil control has to exercise THE RULE the
    product uses, not a re-implementation of it. A control that re-implements the thing it checks
    passes when both are wrong.
    """
    out: list[dict[str, Any]] = []
    for host, now in recent.items():
        prof = (profiles.get(host) or {}).get(now_hour)
        if prof is None:
            out.append({key: host, "state": "new_hour", "hour": now_hour,
                        "bytes": now["bytes"], "peers": now["peers"], "ratio": None})
            continue
        p90 = prof["p90_bytes"] or prof["median_bytes"]
        ratio = (now["bytes"] / p90) if p90 > 0 else None
        out.append({key: host, "state": "scored", "hour": now_hour,
                    "bytes": now["bytes"], "peers": now["peers"],
                    "median_bytes": prof["median_bytes"], "p90_bytes": prof["p90_bytes"],
                    "median_peers": prof["median_peers"],
                    "ratio": round(ratio, 2) if ratio is not None else None})
    scored = sorted((r for r in out if r["ratio"] is not None),
                    key=lambda r: r["ratio"], reverse=True)
    fresh = [r for r in out if r["ratio"] is None]
    return (scored + fresh)[:int(limit)]


def rank_departures(client: Any, *, recent_minutes: int = 60, days: int = DEFAULT_DAYS,
                    era: str | None = None, limit: int = 12) -> list[dict[str, Any]]:
    """Hosts whose last hour is furthest from their own p90 for THIS hour.

    A host with no row for this hour is `new_hour` rather than scored: inventing a baseline is the
    fleet-wide mistake in miniature.
    """
    profiles = host_hour_profiles(client, days=days, era=era)
    recent = recent_hour(client, minutes=recent_minutes, era=era)
    now_hour = int(client.query("SELECT toHour(now())").result_rows[0][0])
    return rank_from(profiles, recent, now_hour, limit=limit)


def _quantile(values: list[float], q: float) -> float:
    """Nearest-rank over a small list -- no numpy, and one point is its own p90."""
    if not values:
        return 0.0
    ordered = sorted(values)
    if len(ordered) == 1:
        return float(ordered[0])
    return float(ordered[min(len(ordered) - 1, int(round(q * (len(ordered) - 1))))])


def segment_of(host: str, *, bits: int = 24) -> str | None:
    """The subnet that contains a host, as a network string. None if the address does not parse."""
    import ipaddress  # noqa: PLC0415

    try:
        return str(ipaddress.ip_network(f"{host}/{int(bits)}", strict=False))
    except (ValueError, TypeError):
        return None


def segment_hour_profiles(client: Any, *, bits: int = 24, days: int = DEFAULT_DAYS,
                          era: str | None = None, recent_minutes: int = 60
                          ) -> tuple[dict[str, dict[int, dict[str, float]]], dict[str, dict[str, int]]]:
    """The SAME merged host-window rows, summed into the subnet that contains them.

    WHY A SEGMENT AT ALL, when every host already has a profile. Two reasons that the host view
    cannot answer. A single host that departs can be a backup, a Steam download, a phone syncing
    photos; a whole /24 departing at once cannot be any of those, so the segment is the coarse
    control that keeps the per-host view honest. And a segment is the smallest unit that survives a
    DHCP churn: the address a host held last week may be someone else's this week, while the subnet
    keeps its shape (measured on this deployment: 17 monitored hosts across two /24s).

    WHAT IS AGGREGATED AND WHAT IS NOT. Bytes are summed across the hosts of a segment in the same
    window -- volume is additive. Peers are NOT: `uniqMerge` gives each host its own distinct
    destination count and the distinct count of the union cannot be recovered from the parts, so
    the segment carries the WIDEST host's peer count and says so. That is a floor on the segment's
    true peer diversity, never an overstatement, and it is the number the class work needs anyway
    (a segment is not "chatty" because three of its hosts each see the same gateway).

    The recent/long split is computed by the DATABASE (`if(window_start >= now() - INTERVAL ...)`),
    never in Python: comparing a Python clock with a ClickHouse timestamp is the recurring defect
    that cost a day of detection twice.
    """
    era = era or era_start(client, days * 24)
    rows = _merged(
        "SELECT src_addr, window_start, toHour(window_start) AS hour, "
        "       sumMerge(total_bytes) AS bytes, uniqMerge(unique_dst_ips) AS peers, "
        "       if(window_start >= now() - INTERVAL %(m)s MINUTE, 1, 0) AS recent "
        "FROM weirvern.flows_window "
        f"WHERE window_start >= %(era)s AND {_scope(client)} "
        "GROUP BY src_addr, window_start, hour, recent",
        client, {"era": era, "m": int(recent_minutes)},
    )
    folded: dict[tuple[str, Any], dict[str, Any]] = {}
    for src, window_start, hour, bytes_, peers, is_recent in rows:
        segment = segment_of(str(src or ""), bits=bits)
        if not segment:
            continue
        slot = folded.setdefault((segment, window_start), {
            "bytes": 0.0, "peers": 0.0, "hour": int(hour), "recent": False})
        slot["bytes"] += float(bytes_ or 0)
        slot["peers"] = max(slot["peers"], float(peers or 0))
        slot["recent"] = slot["recent"] or bool(is_recent)

    by_hour: dict[str, dict[int, list[tuple[float, float]]]] = {}
    recent: dict[str, dict[str, int]] = {}
    for (segment, _window), slot in folded.items():
        by_hour.setdefault(segment, {}).setdefault(slot["hour"], []).append(
            (slot["bytes"], slot["peers"]))
        if slot["recent"]:
            agg = recent.setdefault(segment, {"bytes": 0, "peers": 0})
            agg["bytes"] += int(slot["bytes"])
            agg["peers"] = max(agg["peers"], int(slot["peers"]))

    profiles: dict[str, dict[int, dict[str, float]]] = {}
    for segment, hours in by_hour.items():
        for hour, samples in hours.items():
            profiles.setdefault(segment, {})[hour] = {
                "median_bytes": _quantile([b for b, _ in samples], 0.5),
                "p90_bytes": _quantile([b for b, _ in samples], 0.9),
                "median_peers": _quantile([p for _, p in samples], 0.5),
            }
    return profiles, recent


def rank_segments(client: Any, *, bits: int = 24, recent_minutes: int = 60,
                  days: int = DEFAULT_DAYS, era: str | None = None, limit: int = 12
                  ) -> list[dict[str, Any]]:
    """Segments whose last hour is furthest from their own p90 for THIS hour."""
    profiles, recent = segment_hour_profiles(
        client, bits=bits, days=days, era=era, recent_minutes=recent_minutes)
    now_hour = int(client.query("SELECT toHour(now())").result_rows[0][0])
    return rank_from(profiles, recent, now_hour, limit=limit, key="segment")


def summarise_segments(rows: list[dict[str, Any]]) -> dict[str, Any]:
    scored = [r for r in rows if r.get("ratio") is not None]
    ratios = [r["ratio"] for r in scored]
    return {
        "segments_scored": len(scored),
        "segments_without_history": len(rows) - len(scored),
        "median_ratio": round(statistics.median(ratios), 2) if ratios else None,
        "worst_ratio": max(ratios) if ratios else None,
        "note": "a segment that departs as a whole is not a backup; peers are the widest host's",
    }


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
