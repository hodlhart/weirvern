"""ClickHouse side of the Normalize tab: the feed, the entries, and the seeds the baseline reads.

The feed is ONE query with two lanes (flows and DNS) unioned in the database, because the tab's
whole premise is that an operator reads traffic, not two separate lists. Every filter is applied
server-side so a week-long window cannot push a hundred thousand rows into the browser.
"""
from __future__ import annotations

import logging
from collections.abc import Sequence
from datetime import datetime
from typing import Any

from clickhouse_connect.driver.client import Client

from weirvern import normalize

logger = logging.getLogger(__name__)

# A /24 for IPv4 and the address itself otherwise. IPv6 is left whole: a /64 is the smallest
# block worth calling a segment, but slicing the text of a v6 literal by '.' is meaningless, and
# a wrong segment is worse than a coarse one.
_PREFIX = (
    "if(position(dst_addr, '.') > 0, "
    "concat(splitByChar('.', dst_addr)[1], '.', splitByChar('.', dst_addr)[2], '.', "
    "splitByChar('.', dst_addr)[3], '.0/24'), dst_addr)"
)

FLOW_LANE_T = """
SELECT
    'flow'                                    AS source,
    max(timestamp)                            AS last_seen,
    min(timestamp)                            AS first_seen,
    src_addr,
    {prefix}                                  AS dst_prefix,
    dst_port,
    proto,
    ''                                        AS dns_name,
    toUInt16(0)                               AS dns_qtype,
    count()                                   AS flows,
    sum(bytes)                                AS bytes_total,
    sum(packets)                              AS packets_total,
    avg(bytes)                                AS avg_bytes,
    varPop(bytes)                             AS var_bytes,
    avg(packets)                              AS avg_packets,
    varPop(packets)                           AS var_packets,
    count(DISTINCT toStartOfFiveMinute(timestamp)) AS samples
FROM weirvern.flows
WHERE timestamp >= now() - INTERVAL {hours} HOUR
GROUP BY src_addr, dst_prefix, dst_port, proto
HAVING flows >= {min_flows}
"""

DNS_LANE_T = """
SELECT
    'dns'                                     AS source,
    max(ts)                                   AS last_seen,
    min(ts)                                   AS first_seen,
    src_addr,
    ''                                        AS dst_prefix,
    toUInt16(0)                               AS dst_port,
    toUInt8(0)                                AS proto,
    query                                     AS dns_name,
    qtype                                     AS dns_qtype,
    count()                                   AS flows,
    sum(query_len)                            AS bytes_total,
    toUInt64(0)                               AS packets_total,
    avg(query_len)                            AS avg_bytes,
    varPop(query_len)                         AS var_bytes,
    0.0                                       AS avg_packets,
    0.0                                       AS var_packets,
    count(DISTINCT toStartOfFiveMinute(ts))   AS samples
FROM weirvern.zeek_dns
WHERE ts >= now() - INTERVAL {hours} HOUR
GROUP BY src_addr, dns_name, dns_qtype
HAVING flows >= {min_flows}
"""


def _escape(value: str) -> str:
    """The feed takes user text; it reaches SQL only as a quoted literal, escaped here."""
    return str(value).replace("\\", "\\\\").replace("'", "\\'")


def feed(client: Client, *, hours: int = 24, source: str = "", segment: str = "",
         port: int = 0, min_bytes: int = 0, query: str = "", limit: int = 400) -> dict[str, Any]:
    """Near-similar traffic, newest first, with what has already been normalized marked."""
    hours = max(1, min(int(hours), 24 * 14))
    lanes = []
    flow_lane = (FLOW_LANE_T.replace("{prefix}", _PREFIX)
                 .replace("{hours}", str(hours)).replace("{min_flows}", "2"))
    dns_lane = DNS_LANE_T.replace("{hours}", str(hours)).replace("{min_flows}", "2")
    if source in ("", "flow"):
        lanes.append(flow_lane)
    if source in ("", "dns"):
        lanes.append(dns_lane)
    if not lanes:
        lanes = [flow_lane, dns_lane]
    body = " UNION ALL ".join(lanes)
    where = ["1 = 1"]
    if segment:
        where.append(f"dst_prefix LIKE '%{_escape(segment)}%'")
    if port:
        where.append(f"dst_port = {int(port)}")
    if min_bytes:
        where.append(f"bytes_total >= {int(min_bytes)}")
    if query:
        q = _escape(query)
        where.append(
            f"(positionCaseInsensitive(src_addr, '{q}') > 0 OR "
            f"positionCaseInsensitive(dst_prefix, '{q}') > 0 OR "
            f"positionCaseInsensitive(dns_name, '{q}') > 0)"
        )
    sql = f"""
        SELECT source, last_seen, first_seen, src_addr, dst_prefix, dst_port, proto, dns_name,
               dns_qtype, flows, bytes_total AS bytes, packets_total AS packets, avg_bytes,
               var_bytes, avg_packets, var_packets, samples
        FROM ({body})
        WHERE {' AND '.join(where)}
        ORDER BY bytes_total DESC
        LIMIT {max(1, min(int(limit), 2000))}
    """
    try:
        result = client.query(sql)
        rows = [dict(zip(result.column_names, r, strict=False)) for r in result.result_rows]
    except Exception as exc:  # noqa: BLE001
        logger.warning("normalize feed failed: %s", exc)
        return {"available": False, "reason": str(exc), "rows": [], "entries": [], "summary": {}}

    live = entries(client)
    by_flow = {(e["src_addr"], e["dst_prefix"], int(e["dst_port"]), int(e["proto"]))
               for e in live if e["source"] == "flow"}
    by_dns = {(e["src_addr"], e["dns_name"], int(e["dns_qtype"]))
              for e in live if e["source"] == "dns"}
    for r in rows:
        if r["source"] == "flow":
            flow_key = (r["src_addr"], r["dst_prefix"], int(r["dst_port"]), int(r["proto"]))
            r["normalized"] = flow_key in by_flow
        else:
            dns_key = (r["src_addr"], r["dns_name"], int(r["dns_qtype"]))
            r["normalized"] = dns_key in by_dns
        for k in ("last_seen", "first_seen"):
            if isinstance(r.get(k), datetime):
                r[k] = r[k].isoformat()
    return {"available": True, "reason": "", "rows": rows, "entries": live,
            "summary": normalize.summarise(live)}


def entries(client: Client, *, include_removed: bool = False) -> list[dict[str, Any]]:
    """Current state per entry, newest first. FINAL because removal supersedes a row."""
    where = "" if include_removed else "WHERE status = 'active'"
    try:
        result = client.query(
            "SELECT entry_id, created_at, created_by, source, status, src_addr, dst_prefix, "
            "dst_port, proto, dns_name, dns_qtype, flows, bytes, samples, first_seen, last_seen, "
            "note FROM weirvern.normal_traffic FINAL "
            f"{where} ORDER BY created_at DESC LIMIT 2000"
        )
        rows = [dict(zip(result.column_names, r, strict=False)) for r in result.result_rows]
    except Exception as exc:  # noqa: BLE001
        logger.warning("normalize entries failed: %s", exc)
        return []
    for r in rows:
        for k in ("created_at", "first_seen", "last_seen"):
            if isinstance(r.get(k), datetime):
                r[k] = r[k].isoformat()
    return rows


def write(client: Client, rows: Sequence[dict[str, Any]]) -> int:
    """Insert rows (new entries or removals). Returns how many were sent."""
    if not rows:
        return 0
    cols = ["entry_id", "created_at", "created_by", "source", "status", "removed_at",
            "removed_by", "src_addr", "dst_prefix", "dst_port", "proto", "dns_name",
            "dns_qtype", "flows", "bytes", "packets", "samples", "avg_bytes", "var_bytes",
            "avg_packets", "var_packets", "first_seen", "last_seen", "note"]
    client.insert("weirvern.normal_traffic", [[r.get(c) for c in cols] for r in rows],
                  column_names=cols)
    return len(rows)


def seeds(client: Client) -> dict[str, list[dict[str, Any]]]:
    """Active flow entries grouped by host — what the baseline trainer pools into its statistics."""
    out: dict[str, list[dict[str, Any]]] = {}
    for r in entries(client):
        if r["source"] == "flow" and r.get("samples", 0):
            out.setdefault(r["src_addr"], []).append(r)
    return out


def domains(client: Client) -> dict[str, list[str]]:
    """Active DNS entries grouped by host — the domains the host is allowed to be known for."""
    out: dict[str, list[str]] = {}
    for r in entries(client):
        if r["source"] == "dns" and r.get("dns_name"):
            out.setdefault(r["src_addr"], []).append(r["dns_name"])
    return out
