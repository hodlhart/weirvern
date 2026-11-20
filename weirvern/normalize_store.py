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
from weirvern.admin import timewindow
from weirvern.models import ripple as _ripple

logger = logging.getLogger(__name__)

_ALERT_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def _hour_key(value: Any) -> str:
    """The UTC hour a timestamp falls in, as a comparable string ('' when unreadable).

    ONE REPRESENTATION FOR BOTH INPUTS. ClickHouse returns an aware datetime for a DateTime
    column (the deployment's tz, e.g. ``...16:00:00-06:00``) while the feed's own rows carry the
    ISO string of the same value. The datetime branch used to keep the offset and the string
    branch dropped it, so the Alert join compared "16:00:00-06:00" with "16:00:00" and matched
    NOTHING -- every Normalize row read the em dash on a live deployment. Both branches now
    produce the same wall-clock hour, offset-free, which is the form the two sources share.
    """
    if isinstance(value, datetime):
        return (value.replace(minute=0, second=0, microsecond=0, tzinfo=None)
                .isoformat(sep=" "))
    text = str(value or "").replace("T", " ")[:19]
    try:
        return datetime.fromisoformat(text).replace(minute=0, second=0, microsecond=0).isoformat(sep=" ")
    except ValueError:
        return ""


def _annotate_alerts(client: Client, rows: list[dict[str, Any]], *, hours: int) -> dict[str, Any]:
    """Which alert the row's own activity raised: Ripple, Anomaly, both, or a measured neither.

    SERVER-SIDE, ONE TRUTH (operator, 2026-11-20: "normalize needs an Alert column"). The feed
    row is matched against the SAME two sources the Alerts tab reads:

      * `ml_ripple_evidence` for the host, the feed lane's channel (`dns` for a DNS row,
        `conn`/`flow` for a flow or Zeek row) and the hour the traffic was last seen;
      * `netflow_anomalies` for the host and that same hour.

    Both reads obey the console's global window (`timewindow.w`), so an absolute range answered
    here is the range the rest of the page answers. A FAILED READ IS NOT "NO ALERT": it sets
    `available: false` and the column says the join could not be read.
    """
    w = timewindow.w(hours)
    params = {"since": w["since"], "until": w["until"]}
    ripples: set[tuple[str, str, str]] = set()
    models: dict[tuple[str, str], str] = {}
    errors: dict[str, str] = {}
    try:
        res = client.query(
            "SELECT DISTINCT src_addr, channel, family, window_start "
            "FROM weirvern.ml_ripple_evidence FINAL "
            "WHERE window_start >= %(since)s AND window_start <= %(until)s",
            parameters=params,
        )
        for r in getattr(res, "result_rows", None) or []:
            # THE EVIDENCE ROW IS KEYED BY CHANNEL, THE FEED LANE BY FAMILY. A stored channel is
            # `conn_volume`, `dns_nxdomain_ratio`, `flow_bytes` -- not the lane name the feed
            # uses. Comparing them literally matched NOTHING on the live box (measured
            # 2026-11-20: 4,225 evidence keys, 0 matches), so every row claimed no ripple. The
            # canonical map is `ripple.CHANNEL_FAMILIES`, not a second table here.
            family = _ripple.channel_family(str(r[1] or "").lower(), str(r[2] or "").lower())
            ripples.add((str(r[0] or ""), family, _hour_key(r[3])))
    except Exception as exc:  # noqa: BLE001 - one source, never the feed
        logger.warning("normalize alert join (ripples) failed: %s", exc)
        errors["ripples"] = f"{type(exc).__name__}: {str(exc)[:120]}"
    try:
        res = client.query(
            "SELECT src_addr, window_start, severity FROM weirvern.netflow_anomalies "
            "WHERE window_start >= %(since)s AND window_start <= %(until)s LIMIT 50000",
            parameters=params,
        )
        for r in getattr(res, "result_rows", None) or []:
            key = (str(r[0] or ""), _hour_key(r[1]))
            band = str(r[2] or "").lower()
            if _ALERT_RANK.get(band, 0) > _ALERT_RANK.get(models.get(key, ""), 0):
                models[key] = band
    except Exception as exc:  # noqa: BLE001
        logger.warning("normalize alert join (model anomalies) failed: %s", exc)
        errors["models"] = f"{type(exc).__name__}: {str(exc)[:120]}"

    for r in rows:
        src = str(r.get("src_addr") or "")
        keys = {k for k in (_hour_key(r.get("first_seen")), _hour_key(r.get("last_seen"))) if k}
        channels = {"dns"} if r.get("source") == "dns" else {"conn", "flow"}
        ripple_hit = sorted({h for (host, ch, h) in ripples
                             if host == src and ch in channels and h in keys})
        model_hits = sorted({h for (host, h) in models if host == src and h in keys})
        kinds = []
        if ripple_hit:
            kinds.append("Ripple")
        if model_hits:
            kinds.append("Anomaly")
        r["alert_kind"] = " + ".join(kinds) if kinds else "—"
        r["alert_band"] = max((models.get((src, h), "") for h in model_hits),
                              key=lambda b: _ALERT_RANK.get(b, 0), default="")
        r["alert_ref"] = {
            "host": src,
            "kinds": kinds,
            "ripple_window": ripple_hit[0] if ripple_hit else "",
            "model_window": model_hits[0] if model_hits else "",
        }
    return {"available": not errors, "errors": errors}

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
    any(dst_addr)                             AS dst_host,
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
WHERE timestamp >= now() - INTERVAL {back} HOUR
  AND timestamp < now() - INTERVAL {ahead} HOUR
GROUP BY src_addr, dst_prefix, dst_port, proto
HAVING flows >= {min_flows}
"""

DNS_LANE_T = """
SELECT
    'dns'                                     AS source,
    max(ts)                                   AS last_seen,
    min(ts)                                   AS first_seen,
    src_addr,
    ''                                        AS dst_host,
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
WHERE ts >= now() - INTERVAL {back} HOUR AND ts < now() - INTERVAL {ahead} HOUR
GROUP BY src_addr, dns_name, dns_qtype
HAVING flows >= {min_flows}
"""


# THE ZEEK LANE (operator, 2026-11-19: "normalize has nothing for zeek"). NetFlow sees packets;
# Zeek saw the session and named the service. A normalized service is as much a claim about what
# is normal as a normalized port, and it carries the responder's own byte counts rather than a
# sampler's estimate. `dns_name` carries the label for every source: a domain for DNS, the service
# for Zeek (http, ssl, ssh, dns) -- one column, one meaning: WHAT this row is, not just where.
ZEEK_LANE_T = """
SELECT
    'zeek'                                    AS source,
    max(ts)                                   AS last_seen,
    min(ts)                                   AS first_seen,
    src_addr,
    any(dst_addr)                             AS dst_host,
    if(position(dst_addr, '.') > 0,
       concat(splitByChar('.', dst_addr)[1], '.', splitByChar('.', dst_addr)[2], '.',
              splitByChar('.', dst_addr)[3], '.0/24'), dst_addr)   AS dst_prefix,
    dst_port,
    multiIf(proto = 'tcp', toUInt16(6), proto = 'udp', toUInt16(17),
            proto = 'icmp', toUInt16(1), toUInt16(0))  AS proto,
    service                                   AS dns_name,
    toUInt16(0)                               AS dns_qtype,
    count()                                   AS flows,
    sum(orig_bytes + resp_bytes)              AS bytes_total,
    sum(orig_pkts + resp_pkts)                AS packets_total,
    avg(orig_bytes + resp_bytes)              AS avg_bytes,
    varPop(orig_bytes + resp_bytes)           AS var_bytes,
    avg(orig_pkts + resp_pkts)                AS avg_packets,
    varPop(orig_pkts + resp_pkts)             AS var_packets,
    count(DISTINCT toStartOfFiveMinute(ts))   AS samples
FROM weirvern.zeek_conn
WHERE ts >= now() - INTERVAL {back} HOUR
  AND ts < now() - INTERVAL {ahead} HOUR
  AND service != ''
GROUP BY src_addr, dst_prefix, dst_port, proto, service
HAVING flows >= {min_flows}
"""


def _escape(value: str) -> str:
    """The feed takes user text; it reaches SQL only as a quoted literal, escaped here."""
    return str(value).replace("\\", "\\\\").replace("'", "\\'")


def feed(client: Client, *, hours: int = 24, source: str = "", segment: str = "",
         port: int = 0, min_bytes: int = 0, query: str = "", limit: int = 400,
         offset: int = 0) -> dict[str, Any]:
    """Near-similar traffic, newest first, with what has already been normalized marked.

    `offset` pages BACKWARDS in time: page 2 is the window immediately before page 1. The feed is
    a long list, and every long list in this console carries the same pager (operator, 2026-11-19).
    """
    hours = max(1, min(int(hours), 24 * 14))
    offset = max(0, min(int(offset), 500))
    ahead, back = hours * offset, hours * (offset + 1)
    lanes = []
    flow_lane = (FLOW_LANE_T.replace("{prefix}", _PREFIX)
                 .replace("{back}", str(back)).replace("{ahead}", str(ahead))
                 .replace("{min_flows}", "2"))
    dns_lane = (DNS_LANE_T.replace("{back}", str(back)).replace("{ahead}", str(ahead))
                .replace("{min_flows}", "2"))
    zeek_lane = (ZEEK_LANE_T.replace("{back}", str(back)).replace("{ahead}", str(ahead))
                 .replace("{min_flows}", "2"))
    if source in ("", "flow"):
        lanes.append(flow_lane)
    if source in ("", "dns"):
        lanes.append(dns_lane)
    if source in ("", "zeek"):
        lanes.append(zeek_lane)
    if not lanes:
        lanes = [flow_lane, dns_lane, zeek_lane]
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
        SELECT source, last_seen, first_seen, src_addr, dst_host, dst_prefix,
               dst_port, proto, dns_name,
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
        if r["source"] in ("flow", "zeek"):
            flow_key = (r["src_addr"], r["dst_prefix"], int(r["dst_port"]), int(r["proto"]))
            r["normalized"] = flow_key in by_flow
        else:
            dns_key = (r["src_addr"], r["dns_name"], int(r["dns_qtype"]))
            r["normalized"] = dns_key in by_dns
        for k in ("last_seen", "first_seen"):
            if isinstance(r.get(k), datetime):
                r[k] = r[k].isoformat()
    # IS THERE ANYTHING OLDER TO PAGE TO? Ask for one row before this window's start rather than
    # guessing from the page size: an empty page that still offers "older" is a dead arrow.
    older = False
    try:
        probe = client.query(
            "SELECT count() FROM ("
            f"SELECT ts FROM weirvern.flows WHERE ts < now() - INTERVAL {back} HOUR LIMIT 1"
            ")")
        older = bool(probe.result_rows and probe.result_rows[0][0])
    except Exception as exc:  # noqa: BLE001
        logger.debug("normalize older probe failed: %s", exc)

    newest = rows[0]["last_seen"] if rows else ""
    # THE ALERT COLUMN, JOINED SERVER-SIDE (operator, 2026-11-20). It is computed after the row
    # set is final so the column describes exactly the rows on this page.
    alerts = _annotate_alerts(client, rows, hours=hours)
    return {"available": True, "reason": "", "rows": rows, "entries": live,
            "summary": normalize.summarise(live),
            "alert_available": alerts["available"],
            "alert_reason": "; ".join(f"{k}: {v}" for k, v in alerts["errors"].items()),
            "window": {"offset": offset, "hours": hours, "newest": newest, "older": older}}


def entries(client: Client, *, include_removed: bool = False) -> list[dict[str, Any]]:
    """Current state per entry, newest first. FINAL because removal supersedes a row."""
    where = "" if include_removed else "WHERE status = 'active'"
    try:
        result = client.query(
            # EVERY COLUMN the writer needs: a removal re-writes the whole row, and a partial
            # read produced `int(None)` on the missing numbers the first time this ran live.
            "SELECT entry_id, created_at, created_by, source, status, removed_at, removed_by, "
            "src_addr, dst_prefix, dst_port, proto, dns_name, dns_qtype, flows, bytes, packets, "
            "samples, avg_bytes, var_bytes, avg_packets, var_packets, first_seen, last_seen, note "
            "FROM weirvern.normal_traffic FINAL "
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
