"""Time-series and breakdown queries behind the SOC views (Netflow, Zeek, Health).

WHY A SEPARATE MODULE. `status.py` answers "what is the current state" -- the dashboard
panels, the health checks, the heartbeat. These answer "what SHAPE is the traffic", which
is a different question with a different failure mode: a trend query that returns nothing
is indistinguishable from a quiet network, and a chart drawn from an empty series looks
like a rendering bug.

So every helper here returns `{"available": bool, "reason": str, "points": [...]}` rather
than a bare list. A panel can then say WHICH of the two states it is in -- "the sensor has
recorded nothing yet" versus "the query could not run" -- because those need different
actions from the person reading it, and conflating them is the "empty panel looks like a
quiet network" defect this project has shipped more than once.

BUCKETING IS DONE IN CLICKHOUSE, not in the browser. A day of per-minute buckets is 1440
points; the browser would have to aggregate them anyway, and doing it in SQL means the
transfer is bounded by the requested bucket count rather than by traffic volume.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

# Bucket widths in seconds, chosen so a bucket count stays readable on a chart. toStartOfInterval
# is given the width directly, so no date arithmetic is done in Python.
_BUCKET_FOR_HOURS = [
    (1, 60),        # 1h   -> 1-minute
    (6, 300),       # 6h   -> 5-minute
    (24, 900),      # 24h  -> 15-minute
    (72, 3600),     # 3d   -> hourly
    (336, 21600),   # 14d  -> 6-hourly
]


def _bucket_seconds(hours: int) -> int:
    for limit, width in _BUCKET_FOR_HOURS:
        if hours <= limit:
            return width
    return _BUCKET_FOR_HOURS[-1][1]


def _unavailable(reason: str, **extra) -> dict:
    """The shape every helper returns when it cannot answer.

    Deliberately NOT an empty list: a caller must be able to distinguish "no data" from
    "the query failed", and an empty series cannot express that difference.
    """
    return {"available": False, "reason": reason, "points": [], **extra}


def flow_volume_series(client, hours: int = 24) -> dict:
    """Bytes and flows per time bucket from the aggregated flows.

    Reads `flows_aggregated`, the same table `top_talkers` uses, because the raw `flows`
    table holds one row per flow and bucketing that is both slower and unnecessary -- the
    aggregate already carries window_start, total_bytes and flow_count.
    """
    width = _bucket_seconds(hours)
    try:
        rows = client.query(
            "SELECT toStartOfInterval(window_start, INTERVAL %(w)s SECOND) AS bucket, "
            "sum(total_bytes) AS bytes, sum(flow_count) AS flows "
            "FROM weirvern.flows_aggregated "
            "WHERE window_start >= now() - INTERVAL %(h)s HOUR "
            "GROUP BY bucket ORDER BY bucket",
            parameters={"w": width, "h": hours},
        ).result_rows
    except Exception as exc:  # noqa: BLE001
        logger.warning("flow_volume_series failed: %s", exc)
        return _unavailable(f"flow volume query failed: {type(exc).__name__}")
    return {
        "available": True,
        "reason": "",
        "hours": hours,
        "bucket_s": width,
        "points": [
            {"t": r[0].isoformat() if hasattr(r[0], "isoformat") else str(r[0]),
             "bytes": int(r[1] or 0), "flows": int(r[2] or 0)}
            for r in rows
        ],
    }


def protocol_mix(client, hours: int = 24, limit: int = 12) -> dict:
    """Flows and bytes per IP protocol.

    READS RAW `flows`, NOT `flows_aggregated`, AND THAT IS NOT A PREFERENCE. The aggregate
    table has no `proto` or `dst_port` column -- it stores per-window volume per source, so
    a protocol breakdown cannot come from it. An earlier version of this module queried
    `flows_aggregated.proto` and would have raised "Unknown expression or identifier" at
    runtime, which is precisely the bug that made Top Talkers permanently empty in this
    project. The columns were checked against the shipped schema before shipping.

    `flows` is also the right table on its own merits here: protocol and port are
    per-FLOW facts, and the aggregate has already discarded them.

    `proto` is stored as the numeric IP protocol; the label is applied here so every
    consumer shows the same names.
    """
    names = {6: "TCP", 17: "UDP", 1: "ICMP", 47: "GRE", 50: "ESP", 51: "AH", 132: "SCTP"}
    try:
        rows = client.query(
            "SELECT proto, sum(bytes) AS bytes, count() AS flows "
            "FROM weirvern.flows "
            "WHERE timestamp >= now() - INTERVAL %(h)s HOUR "
            "GROUP BY proto ORDER BY bytes DESC LIMIT %(n)s",
            parameters={"h": hours, "n": limit},
        ).result_rows
    except Exception as exc:  # noqa: BLE001
        logger.warning("protocol_mix failed: %s", exc)
        return _unavailable(f"protocol query failed: {type(exc).__name__}")
    return {
        "available": True,
        "reason": "",
        "points": [
            {"proto": int(r[0] or 0), "label": names.get(int(r[0] or 0), f"proto {r[0]}"),
             "bytes": int(r[1] or 0), "flows": int(r[2] or 0)}
            for r in rows
        ],
    }


def top_ports(client, hours: int = 24, limit: int = 12) -> dict:
    """Busiest destination ports.

    Reads raw `flows` for the same reason as `protocol_mix`: the aggregate has no
    `dst_port` column.

    Excludes port 0, which in NetFlow means "not recorded" rather than a real port, and
    including it produces a bar labelled 0 that dominates every real service.
    """
    try:
        rows = client.query(
            "SELECT dst_port, proto, sum(bytes) AS bytes, count() AS flows "
            "FROM weirvern.flows "
            "WHERE timestamp >= now() - INTERVAL %(h)s HOUR AND dst_port > 0 "
            "GROUP BY dst_port, proto ORDER BY bytes DESC LIMIT %(n)s",
            parameters={"h": hours, "n": limit},
        ).result_rows
    except Exception as exc:  # noqa: BLE001
        logger.warning("top_ports failed: %s", exc)
        return _unavailable(f"port query failed: {type(exc).__name__}")
    return {
        "available": True,
        "reason": "",
        "points": [
            {"port": int(r[0] or 0), "proto": int(r[1] or 0),
             "bytes": int(r[2] or 0), "flows": int(r[3] or 0)}
            for r in rows
        ],
    }


def destination_spread(client, hours: int = 24, limit: int = 12) -> dict:
    """How wide each host's fan-out got, using the precomputed unique_dst_ips.

    max() rather than sum(), for the reason documented on `top_talkers`: the aggregate
    stores distinct destinations PER WINDOW, so summing across windows counts the same
    destination again in every window. The honest reading is the widest single window.
    """
    try:
        rows = client.query(
            "SELECT src_addr, max(unique_dst_ips) AS dsts, sum(flow_count) AS flows "
            "FROM weirvern.flows_aggregated "
            "WHERE window_start >= now() - INTERVAL %(h)s HOUR "
            "GROUP BY src_addr ORDER BY dsts DESC LIMIT %(n)s",
            parameters={"h": hours, "n": limit},
        ).result_rows
    except Exception as exc:  # noqa: BLE001
        logger.warning("destination_spread failed: %s", exc)
        return _unavailable(f"destination spread query failed: {type(exc).__name__}")
    return {
        "available": True,
        "reason": "",
        "points": [
            {"src_addr": str(r[0]), "destinations": int(r[1] or 0), "flows": int(r[2] or 0)}
            for r in rows
        ],
    }


# The Zeek logs the sensor can write, and the table each lands in. Kept in one place so the
# GUI cannot claim a log the ingester does not map -- the schema audit checks this pairing.
ZEEK_LOGS: list[tuple[str, str]] = [
    ("conn", "zeek_conn"),
    ("dns", "zeek_dns"),
    ("http", "zeek_http"),
    ("ssl", "zeek_ssl"),
    ("ssh", "zeek_ssh"),
    ("notice", "zeek_notice"),
    ("files", "zeek_files"),
    ("weird", "zeek_weird"),
    ("kerberos", "zeek_kerberos"),
    ("ntlm", "zeek_ntlm"),
    ("dce_rpc", "zeek_dce_rpc"),
    ("smb_files", "zeek_smb_files"),
    ("smb_mapping", "zeek_smb_mapping"),
    ("dhcp", "zeek_dhcp"),
    ("ldap_search", "zeek_ldap_search"),
    ("quic", "zeek_quic"),
    ("tunnel", "zeek_tunnel"),
    ("x509", "zeek_x509"),
]


# Which column holds the peer address in each Zeek log. NOT uniformly `src_addr`:
# `zeek_dhcp` keys its peers as client_addr/server_addr, and assuming src_addr there is the
# mistake that made `zeek_window_summary_sql` unrunnable (Code 47), so the mapping is explicit
# and this comment records why it exists.
_ADDR_COLUMN: dict[str, str] = {
    "zeek_dhcp": "client_addr",
    "zeek_ldap_search": "src_addr",
}


def zeek_counts(client, hours: int = 24) -> dict:
    """Row count per Zeek table, so a chart can show which logs are actually arriving.

    ONE QUERY PER TABLE INSIDE A SINGLE UNION would fail entirely if one table is missing,
    hiding the seventeen that exist. Each count is therefore issued separately and a
    failing table is REPORTED as unreadable rather than dropped -- a table that cannot be
    counted and a table with no rows are different facts, and the panel says which.
    """
    out: list[dict] = []
    unreadable: list[str] = []
    for label, table in ZEEK_LOGS:
        try:
            # ONE QUERY, THREE NUMBERS, because a bare zero is unreadable on its own.
            #
            # "http 0" in the window has two completely different meanings and the panel could not
            # tell them apart: either http.log has NEVER produced a row (a policy or analyzer
            # problem worth fixing) or it produced rows earlier and none in this window (the
            # segment simply had no HTTP traffic). An operator seeing a wall of zeros concluded
            # the dashboard was broken; the truth was that the interesting protocol data is OLDER
            # than the default 24h window -- http/ssh/files rows existed, from ~40h earlier.
            #
            # So the count carries its own context: `total` (all time) and `last_ts` (when it was
            # last written). The panel can then say "0 in this window, last row 40h ago" instead of
            # leaving the reader to guess. Same principle as everywhere else here: state what is
            # absent and why.
            rows = client.query(
                f"SELECT countIf(ts >= now() - INTERVAL %(h)s HOUR) AS in_window, "  # noqa: S608
                f"count() AS total, max(ts) AS last_ts FROM weirvern.{table}",
                parameters={"h": hours},
            ).result_rows
            in_window = int(rows[0][0] or 0)
            total = int(rows[0][1] or 0)
            last = rows[0][2]
            out.append({
                "log": label,
                "table": table,
                "rows": in_window,
                "total": total,
                "last_ts": last.isoformat() if hasattr(last, "isoformat") else (str(last) if last else ""),
                # The three states a zero can be in. Computed here so every consumer reads the
                # same words rather than each inventing its own.
                "state": (
                    "empty-forever" if total == 0
                    else "idle" if in_window == 0
                    else "active"
                ),
            })
        except Exception as exc:  # noqa: BLE001
            logger.debug("zeek count failed for %s: %s", table, exc)
            unreadable.append(label)
    if not out:
        return _unavailable("no Zeek table could be counted", unreadable=unreadable)
    return {"available": True, "reason": "", "points": out, "unreadable": unreadable}


def zeek_timeline(client, hours: int = 24) -> dict:
    """Rows per bucket across the Zeek logs that are worth trending.

    A SUBSET ON PURPOSE. `conn` alone dwarfs every protocol log, and putting them on one
    axis makes the rest a flat line -- the chart would be technically correct and
    useless. The high-volume logs are separate series so a protocol log's shape is
    visible against its own history.
    """
    width = _bucket_seconds(hours)
    trended = ["conn", "dns", "ssl", "http", "ssh", "notice"]
    series: dict[str, list[dict]] = {}
    for label in trended:
        table = dict(ZEEK_LOGS)[label]
        try:
            rows = client.query(
                f"SELECT toStartOfInterval(ts, INTERVAL %(w)s SECOND) AS bucket, count() "  # noqa: S608
                f"FROM weirvern.{table} "
                "WHERE ts >= now() - INTERVAL %(h)s HOUR GROUP BY bucket ORDER BY bucket",
                parameters={"w": width, "h": hours},
            ).result_rows
            series[label] = [
                {"t": r[0].isoformat() if hasattr(r[0], "isoformat") else str(r[0]),
                 "n": int(r[1] or 0)}
                for r in rows
            ]
        except Exception as exc:  # noqa: BLE001
            logger.debug("zeek timeline failed for %s: %s", table, exc)
    if not series:
        return _unavailable("no Zeek log could be read for the timeline")
    return {"available": True, "reason": "", "hours": hours, "bucket_s": width,
            "series": series}


def zeek_services(client, hours: int = 24, limit: int = 15) -> dict:
    """Observed services, from conn.log's service field.

    `service` is a comma-joined set in Zeek (e.g. "http,ssl"), so the split happens here
    and each service is counted individually -- otherwise "ssl" and "http,ssl" appear as
    different services and the chart understates the real ones.
    """
    try:
        rows = client.query(
            "SELECT arrayJoin(splitByChar(',', service)) AS svc, count() AS n "
            "FROM weirvern.zeek_conn "
            "WHERE ts >= now() - INTERVAL %(h)s HOUR AND service != '' "
            "GROUP BY svc ORDER BY n DESC LIMIT %(n)s",
            parameters={"h": hours, "n": limit},
        ).result_rows
    except Exception as exc:  # noqa: BLE001
        logger.warning("zeek_services failed: %s", exc)
        return _unavailable(f"service query failed: {type(exc).__name__}")
    return {"available": True, "reason": "",
            "points": [{"service": str(r[0]), "n": int(r[1] or 0)} for r in rows]}


def zeek_dns_names(client, hours: int = 24, limit: int = 20) -> dict:
    """Most-queried names.

    Excludes single-label lookups (no dot) by default: NetBIOS and mDNS chatter fills the
    list on a LAN and buries the names an analyst is looking for. The exclusion is stated
    in the payload so the panel can say so out loud rather than silently filtering.
    """
    try:
        rows = client.query(
            "SELECT query, count() AS n, uniqExact(src_addr) AS askers "
            "FROM weirvern.zeek_dns "
            "WHERE ts >= now() - INTERVAL %(h)s HOUR AND position(query, '.') > 0 "
            "GROUP BY query ORDER BY n DESC LIMIT %(n)s",
            parameters={"h": hours, "n": limit},
        ).result_rows
    except Exception as exc:  # noqa: BLE001
        logger.warning("zeek_dns_names failed: %s", exc)
        return _unavailable(f"DNS query failed: {type(exc).__name__}")
    return {"available": True, "reason": "",
            "filtered": "single-label names (no dot) excluded",
            "points": [{"query": str(r[0]), "n": int(r[1] or 0), "askers": int(r[2] or 0)}
                       for r in rows]}


def ingestion_series(client, hours: int = 24) -> dict:
    """Rows per bucket per pipeline stage: raw flows, aggregated windows, alerts, retrains.

    This is the chart that answers "is the pipeline healthy" at a glance, and it is the
    reason a Health view needs its own endpoint: /api/healthz answers a single boolean so
    that a slow database cannot restart the GUI. That is correct for a liveness probe and
    useless for an operator asking whether data is still arriving.
    """
    width = _bucket_seconds(hours)
    stages: dict[str, list[dict]] = {}
    sources = [
        # `flows` keys its time on `timestamp`, NOT `ts` -- the same wrong-name trap as
        # `flows_aggregated.proto`. Checked against the shipped schema.
        ("flows", "weirvern.flows", "timestamp"),
        ("windows", "weirvern.flows_aggregated", "window_start"),
        ("anomalies", "weirvern.netflow_anomalies", "detected_at"),
        ("models", "weirvern.ml_models", "trained_at"),
    ]
    for label, table, tscol in sources:
        try:
            rows = client.query(
                f"SELECT toStartOfInterval({tscol}, INTERVAL %(w)s SECOND) AS bucket, count() "  # noqa: S608
                f"FROM {table} "
                f"WHERE {tscol} >= now() - INTERVAL %(h)s HOUR GROUP BY bucket ORDER BY bucket",
                parameters={"w": width, "h": hours},
            ).result_rows
            stages[label] = [
                {"t": r[0].isoformat() if hasattr(r[0], "isoformat") else str(r[0]),
                 "n": int(r[1] or 0)}
                for r in rows
            ]
        except Exception as exc:  # noqa: BLE001
            logger.debug("ingestion series failed for %s: %s", table, exc)
    if not stages:
        return _unavailable("no pipeline table could be read")
    return {"available": True, "reason": "", "hours": hours, "bucket_s": width,
            "series": stages}


def flows_matching(client, port: int | None = None, proto: int | None = None,
                   hours: int = 24, limit: int = 25) -> dict:
    """The hosts behind one destination port and/or one IP protocol, for click-through.

    WHY THIS IS THE DRILL-DOWN. `top_ports` answers "which ports carry the most bytes" and
    `protocol_mix` answers "how much of the traffic is TCP" -- and both end there. The next
    question an analyst has is "which hosts, and to where", which needs the source and
    destination addresses. Without that the charts are a report rather than a way in.

    READS RAW `flows`, because `flows_aggregated` has no dst_port, no proto and no dst_addr --
    all three are per-FLOW facts the aggregate has already discarded.

    BOTH FILTERS ARE OPTIONAL AND INDEPENDENT: a port click supplies `port`, a protocol click
    supplies `proto`, and supplying neither would return every flow, which is a legitimate
    request but not a drill-down. At least one is required here so a caller cannot accidentally
    ask for the whole table and get a slow page.

    `port > 0` is enforced for the same reason as in `top_ports`: NetFlow uses 0 for "not
    recorded", and including it produces a bar that dominates every real service.
    """
    if port is None and proto is None:
        return _unavailable("give a port or a protocol to drill into")

    where = ["timestamp >= now() - INTERVAL %(h)s HOUR"]
    params: dict = {"h": hours, "n": limit}
    if port is not None:
        where.append("dst_port = %(port)s")
        params["port"] = int(port)
    if proto is not None:
        where.append("proto = %(proto)s")
        params["proto"] = int(proto)
    clause = " AND ".join(where)

    try:
        # Grouped by destination so the answer is "host X sent N bytes to Y:port", which is
        # actionable; a bare per-source total would not say where the traffic went.
        rows = client.query(
            f"SELECT src_addr, dst_addr, dst_port, sum(bytes) AS bytes, count() AS flows "  # noqa: S608
            f"FROM weirvern.flows WHERE {clause} "
            "GROUP BY src_addr, dst_addr, dst_port ORDER BY bytes DESC LIMIT %(n)s",
            parameters=params,
        ).result_rows
        # The total, so the panel can say how much of it is shown. A capped list that does not
        # say it was capped looks complete.
        total_rows = client.query(
            f"SELECT count() FROM weirvern.flows WHERE {clause}",  # noqa: S608
            parameters={k: v for k, v in params.items() if k != "n"},
        ).result_rows
        distinct_rows = client.query(
            f"SELECT uniqExact((src_addr, dst_addr)) FROM weirvern.flows WHERE {clause}",  # noqa: S608
            parameters={k: v for k, v in params.items() if k != "n"},
        ).result_rows
    except Exception as exc:  # noqa: BLE001
        logger.warning("flows_matching failed: %s", exc)
        return _unavailable(f"flow drill-down failed: {type(exc).__name__}")

    out = [
        {"src_addr": str(r[0]), "dst_addr": str(r[1]), "dst_port": int(r[2] or 0),
         "bytes": int(r[3] or 0), "flows": int(r[4] or 0)}
        for r in rows
    ]
    total_pairs = int(distinct_rows[0][0] or 0) if distinct_rows else len(out)
    return {
        "available": True,
        "reason": "",
        "port": port,
        "proto": proto,
        "hours": hours,
        "points": out,
        "total_flows": int(total_rows[0][0] or 0) if total_rows else 0,
        "total_pairs": total_pairs,
        # Stated, not implied, for the same reason the graph reports truncation.
        "truncated": total_pairs > len(out),
    }

def zeek_log_hosts(client, table: str, label: str, hours: int = 24, limit: int = 25) -> dict:
    """Which hosts appear in ONE Zeek log, and how often, for click-through from the Zeek view.

    WHY THIS IS THE DRILL-DOWN. A bar chart of row counts per log answers "is ssl.log busy"
    and nothing else. The question an analyst actually has next is "busy with WHOM", and that
    needs the address column -- which differs per table (`zeek_dhcp` keys its peers as
    client_addr, not src_addr), so the column is looked up rather than assumed.

    THE TABLE NAME COMES FROM A CALLER-SUPPLIED LABEL, so it is resolved through ZEEK_LOGS
    rather than interpolated. `web.py` does the same lookup, and this second check is the
    backstop: a table name reaching an f-string is how a read-only endpoint becomes a way to
    query arbitrary relations.
    """
    import logging as _logging

    resolved = dict(ZEEK_LOGS).get(label)
    if resolved != table:
        # The label and the table must agree with ZEEK_LOGS, or something is passing us
        # unvalidated input.
        raise ValueError(f"log {label!r} does not map to table {table!r} in ZEEK_LOGS")

    addrcol = _ADDR_COLUMN.get(table, "src_addr")
    try:
        rows = client.query(
            f"SELECT toString({addrcol}) AS addr, count() AS n "  # noqa: S608 - table from ZEEK_LOGS, not input
            f"FROM weirvern.{table} "
            "WHERE ts >= now() - INTERVAL %(h)s HOUR "
            f"AND toString({addrcol}) != '' AND toString({addrcol}) != '-' "
            "GROUP BY addr ORDER BY n DESC LIMIT %(n)s",
            parameters={"h": hours, "n": limit},
        ).result_rows
    except Exception as exc:  # noqa: BLE001
        _logging.getLogger(__name__).warning("zeek_log_hosts failed for %s: %s", table, exc)
        return _unavailable(f"{label} query failed: {type(exc).__name__}", log=label, points=[])
    return {
        "available": True, "reason": "", "log": label, "table": table, "hours": hours,
        "points": [{"addr": str(r[0]), "n": int(r[1] or 0)} for r in rows],
    }


def table_sizes(client, limit: int = 14) -> dict:
    """Row and byte counts per table, from system.parts.

    system.tables would need `total_rows` which is not populated for every engine, so
    parts are summed instead -- that is the actual on-disk figure, which is what an
    operator checking disk pressure wants.
    """
    try:
        rows = client.query(
            "SELECT table, sum(rows) AS n, sum(bytes_on_disk) AS b "
            "FROM system.parts WHERE database = 'weirvern' AND active "
            "GROUP BY table ORDER BY b DESC LIMIT %(n)s",
            parameters={"n": limit},
        ).result_rows
    except Exception as exc:  # noqa: BLE001
        logger.warning("table_sizes failed: %s", exc)
        return _unavailable(f"table size query failed: {type(exc).__name__}")
    return {"available": True, "reason": "",
            "points": [{"table": str(r[0]), "rows": int(r[1] or 0), "bytes": int(r[2] or 0)}
                       for r in rows]}


def alert_audit(client, hours: int = 24, limit: int = 100) -> dict:
    """THE ALERT AUDIT TRAIL (soc-8): every alert decision, not just the delivered ones.

    The worker writes EVERY decision to `alert_events` -- sent, suppressed by cooldown,
    dropped at the rate cap, and the log-only path when Pushover is not configured. That
    is a complete account of "what did the alerting layer decide, and why did it not
    reach me", and until now the GUI surfaced it as a single count on the Health probe
    row. A suppressed alert was therefore invisible: the operator saw "0 alerts" with no
    way to learn that three fired and were eaten by a cooldown.

    Two views, because they answer different questions:
      * `by_reason` -- the outcome breakdown ("what did the layer DO"). `sent=0` on a
        non-log-only reason is the suppressed case and is called out in the note text.
      * `recent`    -- the events themselves, newest first, with the message that would
        have been sent (or was). Capped; an unbounded audit list is a way to make the
        database do arbitrary work from an HTTP request.

    Returns the standard {available, reason, points} shape, plus the two lists. The
    unavailable case carries a reason so the panel never renders an empty audit as
    "nothing was suppressed", which would be a much stronger and possibly false claim.
    """
    base = {"available": True, "reason": "", "by_reason": [], "recent": [], "suppressed": 0}
    try:
        by_reason = client.query(
            "SELECT reason, sent, count() AS n, max(sent_at) AS last_at "
            "FROM weirvern.alert_events "
            "WHERE sent_at >= now() - INTERVAL %(h)s HOUR "
            "GROUP BY reason, sent ORDER BY n DESC",
            parameters={"h": hours},
        ).result_rows
        recent = client.query(
            "SELECT sent_at, src_addr, severity, score, sent, reason, message "
            "FROM weirvern.alert_events "
            "WHERE sent_at >= now() - INTERVAL %(h)s HOUR "
            "ORDER BY sent_at DESC LIMIT %(n)s",
            parameters={"h": hours, "n": limit},
        ).result_rows
    except Exception as exc:  # noqa: BLE001
        logger.warning("alert_audit failed: %s", exc)
        base["available"] = False
        base["reason"] = f"alert audit query failed: {type(exc).__name__}"
        return base

    base["by_reason"] = [
        {"reason": str(r[0]), "sent": bool(r[1]), "count": int(r[2] or 0),
         "last_at": str(r[3])[:19] if r[3] is not None else ""}
        for r in by_reason
    ]
    # SUPPRESSED is deliberately not "sent == falsy": the log-only path is also sent=0,
    # and counting it as suppressed would claim alerts were withheld when nothing was
    # configured to withhold them. Suppression is the reasons that MEAN withheld.
    base["suppressed"] = sum(
        p["count"] for p in base["by_reason"]
        if p["reason"] in ("cooldown", "cap") and not p["sent"]
    )
    base["recent"] = [
        {"sent_at": str(r[0])[:19], "src_addr": str(r[1]), "severity": str(r[2]),
         "score": float(r[3] or 0), "sent": bool(r[4]), "reason": str(r[5]),
         "message": str(r[6])}
        for r in recent
    ]
    return base
