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

    ONLY HOSTS OF OURS. The aggregate carries a row per (source, destination) pair, and since the
    sensor moved in path it sees both directions, so external peers appear as `src_addr` too.
    Measured immediately after the switch: the top "hosts" by departure were eight public
    addresses and one of ours. The scope is the same one the asset inventory uses -- networks
    flagged monitored -- because an ML profile of a stranger is not a profile of the network.
    """
    from weirvern import monitored as monitored_mod  # noqa: PLC0415

    ours = monitored_mod.sql_predicate("src_addr", monitored_mod.networks(client))
    rows = client.query(
        "SELECT src_addr, toHour(window_start) AS hour, "
        "       quantile(0.5)(total_bytes) AS med_bytes, "
        "       quantile(0.9)(total_bytes) AS p90_bytes, "
        "       quantile(0.5)(unique_dst_ips) AS med_peers "
        "FROM weirvern.flows_aggregated "
        "WHERE window_start >= now() - INTERVAL %(days)s DAY "
        f"AND {ours} "
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
    from weirvern import monitored as monitored_mod  # noqa: PLC0415

    recent = client.query(
        "SELECT src_addr, sum(total_bytes) AS bytes, max(unique_dst_ips) AS peers "
        "FROM weirvern.flows_aggregated "
        "WHERE window_start >= now() - INTERVAL %(m)s MINUTE "
        f"AND {monitored_mod.sql_predicate('src_addr', monitored_mod.networks(client))} "
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


# ── THE ERA MARKER ──────────────────────────────────────────────────────────────────────────────
#
# A profile is only comparable with data from the same capture regime. The mirrored port saw the
# whole segment; the in-path sensor sees eleven hosts. Mixing them made every host read far below
# its own p90 minutes after the switch (measured: median ratio 0.38). So every profile carries the
# instant its era began, and a caller that does not name one gets the last six hours -- the current
# regime by assumption, stated rather than guessed.
DEFAULT_ERA_HOURS = 6


def era_start(hours: int = DEFAULT_ERA_HOURS) -> str:
    """An ISO timestamp the queries can filter on: `<that instant>` means "this regime only"."""
    from datetime import UTC, datetime, timedelta

    return (datetime.now(UTC) - timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%S")


def peer_sets(client, *, since: str, hours: int = 24) -> dict[str, set[str]]:
    """Each host's peers inside one era, from raw flows. The aggregate has no dst_addr."""
    from weirvern import monitored as monitored_mod  # noqa: PLC0415

    ours = monitored_mod.sql_predicate("src_addr", monitored_mod.networks(client))
    rows = client.query(
        "SELECT src_addr, groupUniqArray(dst_addr) "
        "FROM weirvern.flows "
        "WHERE timestamp >= %(since)s "
        f"  AND timestamp >= now() - INTERVAL %(h)s HOUR AND {ours} "
        "GROUP BY src_addr",
        parameters={"since": since, "h": int(hours)},
    ).result_rows
    return {str(src): {str(p) for p in (peers or [])} for src, peers in rows or [] if src}


def class_profiles(sets: dict[str, set[str]], *, min_shared: int = 3,
                   min_overlap: float = 0.4) -> list[dict[str, Any]]:
    """Hosts that look alike, judged by the OVERLAP of their peer sets.

    "All the iPhones talk to the same endpoints" is a class: the size of each set is irrelevant,
    which is the whole point on a chatty host. Two hosts join when they share at least `min_shared`
    peers and the smaller set is at least `min_overlap` covered -- a containment test rather than a
    strict Jaccard, so one busy member does not drag a quiet sibling out of its class.
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
            smaller = min(len(a), len(b)) or 1
            if shared >= min_shared and shared / smaller >= min_overlap:
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
    """Does a broader scope explain this host's peer? The composition rule, in one function.

    A peer that is new to a host but routine for its class is NOT novelty: that is the chatty-host
    problem, and the fix is to ask the larger scope before alerting on the smaller one.
    """
    for group in classes:
        if host in group["members"]:
            siblings: set[str] = set()
            for m in group["members"]:
                if m != host:
                    siblings |= sets.get(m, set())
            novel = peers - siblings
            return {"host": host, "class": group["members"],
                    "explained": len(peers) - len(novel), "novel": sorted(novel)[:20],
                    "novel_count": len(novel)}
    return {"host": host, "class": [], "explained": 0, "novel": sorted(peers)[:20],
            "novel_count": len(peers)}
