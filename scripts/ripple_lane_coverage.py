#!/usr/bin/env python3
"""Before/after coverage of the Normalize Alert join, measured on the live deployment.

WHY THIS EXISTS. The feed's Alert column joins a row to `ml_ripple_evidence` by the row's LANE.
Until 2026-11-21 that rule was a hard-coded family pair -- `{"dns"}` for a DNS row, `{"conn",
"flow"}` for everything else -- so a Zeek session row could only ever carry conn/flow evidence,
and every tls/http/ssh/identity/notice ripple for the same host and hour was invisible on it.
The replacement derives each lane's families from the ChannelSpecs' own tables and their live
`required_columns` (`ripple_evidence.feed_lane_families`).

WHAT IT PRINTS, per lane and in total:
  * rows and distinct hosts in the window;
  * rows and hosts that match at least one evidence key under the OLD rule and under the NEW one;
  * the evidence keys (host, family, hour) that are actually reachable, old vs new;
  * the channels/families each row type can be evaluated against, old vs new.

The two rules are evaluated against the SAME live snapshot, so the difference is the rule and not
a change in the data. One key per (host, family, hour) is counted once: this measures reach, not
row multiplication.

RUN (inside the worker pod, where ClickHouse credentials and the shipping package exist):

    kubectl -n weirvern exec deploy/weirvern-worker -- python3 /tmp/ripple_lane_coverage.py \
        --hours 24 --out /tmp/ripple_lane_coverage.json
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from collections import defaultdict
from datetime import UTC, datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from weirvern import db, normalize_store  # noqa: E402
from weirvern.config import Settings  # noqa: E402
from weirvern.models import ripple_evidence as rev  # noqa: E402

#: The rule as shipped at sha-a252162 (2026-11-21), kept here as the "before" side of the pair.
OLD_LANE_FAMILIES: dict[str, frozenset[str]] = {
    "dns": frozenset({"dns"}),
    "flow": frozenset({"conn", "flow"}),
    "zeek": frozenset({"conn", "flow"}),
}


def _hour_key(value) -> str:
    if isinstance(value, datetime):
        return value.replace(minute=0, second=0, microsecond=0, tzinfo=None).isoformat(sep=" ")
    text = str(value or "").replace("T", " ")[:19]
    try:
        return datetime.fromisoformat(text).replace(minute=0, second=0,
                                                   microsecond=0).isoformat(sep=" ")
    except ValueError:
        return ""


def _feed_rows(client, *, hours: int, limit: int = 20000) -> list[dict]:
    """The feed's own three lane queries, with the same substitutions `feed()` makes."""
    lanes = []
    flow = (normalize_store.FLOW_LANE_T.replace("{prefix}", normalize_store._PREFIX)
            .replace("{back}", str(hours)).replace("{ahead}", "0").replace("{min_flows}", "2"))
    dns = (normalize_store.DNS_LANE_T.replace("{back}", str(hours)).replace("{ahead}", "0")
           .replace("{min_flows}", "2"))
    zeek = (normalize_store.ZEEK_LANE_T.replace("{back}", str(hours)).replace("{ahead}", "0")
            .replace("{min_flows}", "2"))
    lanes.extend([flow, dns, zeek])
    sql = (
        "SELECT source, first_seen, last_seen, src_addr FROM ("
        + " UNION ALL ".join(lanes) + ") ORDER BY bytes_total DESC LIMIT " + str(int(limit))
    )
    result = client.query(sql)
    return [dict(zip(result.column_names, row, strict=False)) for row in result.result_rows]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--hours", type=int, default=24)
    parser.add_argument("--out", default="/tmp/ripple_lane_coverage.json")
    args = parser.parse_args()

    settings = Settings()
    client = db.connect(settings, retries=3, delay_s=2.0)
    moment = datetime.now(UTC).replace(microsecond=0)
    since = moment.timestamp() - args.hours * 3600

    available = rev.available_channels(client)
    new_families = {lane: rev.feed_lane_families(lane, available=available)
                    for lane in ("flow", "dns", "zeek")}
    new_channels = {lane: rev.feed_lane_channels(lane, available=available)
                    for lane in ("flow", "dns", "zeek")}

    keys: dict[str, set[tuple[str, str, str]]] = defaultdict(set)
    rows = client.query(
        "SELECT src_addr, channel, family, window_start FROM weirvern.ml_ripple_evidence FINAL "
        "WHERE window_start >= %(since)s",
        parameters={"since": datetime.fromtimestamp(since, UTC)},
    ).result_rows
    for host, channel, family, when in rows:
        fam = rev.channel_family(str(channel or "").lower(), str(family or "").lower())
        keys[str(host or "")].add((str(host or ""), fam, _hour_key(when)))

    feed = _feed_rows(client, hours=args.hours)
    report: dict = {
        "generated_at": moment.isoformat(),
        "hours": args.hours,
        "evidence_keys": sum(len(value) for value in keys.values()),
        "evidence_hosts": len([host for host in keys if host]),
        "lanes": {},
        "channels": {
            lane: {
                "old": sorted({spec.channel for spec in rev.SPECS
                               if spec.family in OLD_LANE_FAMILIES.get(lane, frozenset())}),
                "new": sorted(new_channels[lane]),
            }
            for lane in ("flow", "dns", "zeek")
        },
    }
    total = {"rows": 0, "rows_old": 0, "rows_new": 0, "rows_gained": 0,
             "hosts_old": set(), "hosts_new": set(), "keys_old": set(), "keys_new": set()}
    for lane in ("flow", "dns", "zeek"):
        lane_rows = [row for row in feed if str(row.get("source") or "") == lane]
        stats = {"rows": len(lane_rows), "rows_old": 0, "rows_new": 0, "rows_gained": 0,
                 "rows_newly_alerting": 0,
                 "old_families": sorted(OLD_LANE_FAMILIES.get(lane, frozenset())),
                 "new_families": sorted(new_families[lane]),
                 "gained_by_family": defaultdict(set)}
        hosts: set[str] = set()
        hosts_old: set[str] = set()
        hosts_new: set[str] = set()
        hosts_newly_alerting: set[str] = set()
        keys_old: set[tuple[str, str, str]] = set()
        keys_new: set[tuple[str, str, str]] = set()
        for row in lane_rows:
            host = str(row.get("src_addr") or "")
            hosts.add(host)
            hours = {h for h in (_hour_key(row.get("first_seen")),
                                 _hour_key(row.get("last_seen"))) if h}
            held = keys.get(host, set())
            old_hits = {key for key in held
                        if key[1] in OLD_LANE_FAMILIES.get(lane, frozenset())
                        and key[2] in hours}
            new_hits = {key for key in held if key[1] in new_families[lane] and key[2] in hours}
            if old_hits:
                stats["rows_old"] += 1
                hosts_old.add(host)
            if new_hits:
                stats["rows_new"] += 1
                hosts_new.add(host)
            if new_hits and not old_hits:
                stats["rows_newly_alerting"] += 1
                hosts_newly_alerting.add(host)
            if new_hits - old_hits:
                stats["rows_gained"] += 1
                for key in new_hits - old_hits:
                    stats["gained_by_family"][key[1]].add(key)
            keys_old |= old_hits
            keys_new |= new_hits
        stats.update({
            "hosts": len(hosts), "hosts_old": len(hosts_old), "hosts_new": len(hosts_new),
            "hosts_gained": len(hosts_new - hosts_old),
            "hosts_newly_alerting": len(hosts_newly_alerting),
            "keys_old": len(keys_old), "keys_new": len(keys_new),
            "keys_gained": len(keys_new - keys_old),
            "gained_by_family": {family: len(value)
                                 for family, value in sorted(stats["gained_by_family"].items())},
        })
        report["lanes"][lane] = stats
        total["rows"] += stats["rows"]
        total["rows_old"] += stats["rows_old"]
        total["rows_new"] += stats["rows_new"]
        total["rows_gained"] += stats["rows_gained"]
        total["hosts_old"] |= hosts_old
        total["hosts_new"] |= hosts_new
        total["keys_old"] |= keys_old
        total["keys_new"] |= keys_new
    report["totals"] = {
        "rows": total["rows"], "rows_old": total["rows_old"], "rows_new": total["rows_new"],
        "rows_gained": total["rows_gained"],
        "hosts_old": len(total["hosts_old"]), "hosts_new": len(total["hosts_new"]),
        "hosts_gained": len(total["hosts_new"] - total["hosts_old"]),
        "keys_old": len(total["keys_old"]), "keys_new": len(total["keys_new"]),
        "keys_gained": len(total["keys_new"] - total["keys_old"]),
    }
    text = json.dumps(report, indent=2, sort_keys=True, default=str)
    with open(args.out, "w", encoding="utf-8") as handle:
        handle.write(text + "\n")
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
