"""Asset inventory and connection-graph queries behind the Hosts and Network views.

WHY A THIRD MODULE. `status.py` answers "what is the current state" (heartbeat, health, the
dashboard panels). `soc.py` answers "what SHAPE is the traffic" (volume, protocol mix, per-log
counts). These answer "WHICH HOSTS exist and HOW ARE THEY CONNECTED", which is a different
question again and needs different tables: the per-host view is built from the aggregate plus
every Zeek protocol log, and the graph view needs per-EDGE facts (src -> dst), which only the
raw `flows` table holds.

THE TWO VIEWS SHARE ONE HONESTY RULE, and it is the rule this codebase keeps having to relearn:
an endpoint that could not be read is NOT an endpoint with nothing on it. Every helper returns
`{"available": bool, "reason": str, ...}` and NAMES the sources it could not read, so the panel
can say "three Zeek logs were unreadable" instead of drawing a host with no activity. A host
list that silently omits the logs it failed to query is worse than no list, because an analyst
reads absence as evidence.

HOSTNAMES ARE RESOLVED AT THE READ LAYER and always carried ALONGSIDE the address, never
instead of it. The user's standing instruction is explicit: keep the source IP too. A name is a
convenience and it can be wrong, change, or be shared by several addresses; the address is the
fact. `resolve_names` therefore returns a mapping and every payload includes both.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

# The Zeek tables that carry an observed HOST identity, and which column holds the address.
# Listed here rather than derived so the set is auditable; every entry is a table the ingester
# actually writes (checked by scripts/audit_schema.py).
_ZEEK_HOST_TABLES: list[tuple[str, str]] = [
    ("zeek_conn", "src_addr"),
    ("zeek_dns", "src_addr"),
    ("zeek_ssl", "src_addr"),
    ("zeek_http", "src_addr"),
    ("zeek_ssh", "src_addr"),
    ("zeek_notice", "src_addr"),
    ("zeek_weird", "src_addr"),
    ("zeek_kerberos", "src_addr"),
    ("zeek_ntlm", "src_addr"),
    ("zeek_dce_rpc", "src_addr"),
    ("zeek_smb_files", "src_addr"),
    ("zeek_smb_mapping", "src_addr"),
    ("zeek_dhcp", "client_addr"),   # keys its peers as client_addr/server_addr, NOT src_addr
    ("zeek_ldap_search", "src_addr"),
    ("zeek_quic", "src_addr"),
    ("zeek_tunnel", "src_addr"),
]


def _unavailable(reason: str, **extra) -> dict:
    """The shape every helper returns when it cannot answer.

    Not an empty list: a caller must be able to tell "no data" from "the query failed".
    """
    return {"available": False, "reason": reason, **extra}


def _rows(client, sql: str, params: dict, what: str) -> list | None:
    """Run a query, returning None (and logging which one) if it fails.

    A failed source must be reportable, so callers collect None and name it rather than
    treating it as an empty result.
    """
    try:
        return client.query(sql, parameters=params).result_rows
    except Exception as exc:  # noqa: BLE001
        logger.warning("%s failed: %s", what, exc)
        return None


def asset_inventory(client, hours: int = 24, limit: int = 200) -> dict:
    """Every host we have seen, with a per-host summary, for the asset inventory view.

    BUILT FROM THREE SOURCES AND HONEST ABOUT EACH:

      * `flows_aggregated` -- bytes, flows, distinct destinations, and first/last seen.
      * the raw `flows` table -- outbound vs inbound byte split, which the aggregate cannot
        give because it stores per-window volume per SOURCE only.
      * every Zeek host table -- which protocols each host actually spoke, so the inventory
        lists "http, ssl, dns" and not just a byte count.

    A host seen only in Zeek (a DHCP lease, a notice) still appears: the inventory is meant to
    be the list of things that exist on the wire, not the list of things that moved bytes.

    `hours` bounds the TRAFFIC columns only. A host whose last packet was three days ago is
    still an asset, so it appears with zeroed counters rather than being dropped -- and the
    payload says how many such hosts there are, so the panel can explain the zeros.
    """
    hosts: dict[str, dict] = {}

    def _h(addr: str) -> dict:
        return hosts.setdefault(addr, {
            "addr": addr, "name": "", "bytes": 0, "flows": 0, "dst_count": 0,
            "first_seen": "", "last_seen": "", "services": [], "anomalies": 0,
        })

    # ---- 1. Volume and windowed activity from the aggregate.
    agg = _rows(
        client,
        "SELECT src_addr, sum(total_bytes) AS bytes, sum(flow_count) AS flows, "
        "       max(unique_dst_ips) AS dsts, min(window_start) AS first, max(window_end) AS last "
        "FROM weirvern.flows_aggregated "
        "WHERE window_start >= now() - INTERVAL %(h)s HOUR "
        "GROUP BY src_addr ORDER BY bytes DESC LIMIT %(n)s",
        {"h": hours, "n": limit},
        "asset inventory (aggregate)",
    )
    read_ok = {"aggregate": agg is not None}

    for r in agg or []:
        h = _h(str(r[0]))
        h["bytes"] = int(r[1] or 0)
        h["flows"] = int(r[2] or 0)
        h["dst_count"] = int(r[3] or 0)
        h["first_seen"] = r[4].isoformat() if hasattr(r[4], "isoformat") else str(r[4] or "")
        h["last_seen"] = r[5].isoformat() if hasattr(r[5], "isoformat") else str(r[5] or "")

    # ---- 2. Direction split from the RAW flows table. The aggregate has no dst_addr, so an
    #         inbound/outbound split is impossible without this. Recorded honestly if it fails.
    direction = _rows(
        client,
        "SELECT addr, sum(outbound) AS out_b, sum(inbound) AS in_b FROM ("
        "  SELECT src_addr AS addr, bytes AS outbound, 0 AS inbound FROM weirvern.flows "
        "  WHERE timestamp >= now() - INTERVAL %(h)s HOUR "
        "  UNION ALL "
        "  SELECT dst_addr AS addr, 0 AS outbound, bytes AS inbound FROM weirvern.flows "
        "  WHERE timestamp >= now() - INTERVAL %(h)s HOUR "
        ") GROUP BY addr ORDER BY out_b DESC LIMIT %(n)s",
        {"h": hours, "n": limit},
        "asset inventory (direction split)",
    )
    read_ok["direction"] = direction is not None
    for r in direction or []:
        h = _h(str(r[0]))
        h["bytes_out"] = int(r[1] or 0)
        h["bytes_in"] = int(r[2] or 0)

    # ---- 3. Which protocols each host spoke, from every Zeek host table.
    zeek_unreadable: list[str] = []
    for table, addrcol in _ZEEK_HOST_TABLES:
        rows = _rows(
            client,
            # `toString(...)` because zeek_dhcp's address column is IPv4 while the others are
            # String; comparing the raw column against a string literal raises a type error on
            # the IPv4 ones. The '-' sentinel is Zeek's "unset" and is excluded rather than
            # counted as a host, which would create a host literally named "-".
            f"SELECT {addrcol} AS addr, count() AS n FROM weirvern.{table} "  # noqa: S608
            "WHERE ts >= now() - INTERVAL %(h)s HOUR "
            f"AND toString({addrcol}) != '' AND toString({addrcol}) != '-' "
            "GROUP BY addr ORDER BY n DESC LIMIT %(n)s",
            {"h": hours, "n": limit},
            f"asset inventory ({table})",
        )
        if rows is None:
            zeek_unreadable.append(table)
            continue
        # The log name is the service label an analyst recognises (zeek_ssl -> ssl).
        service = table.removeprefix("zeek_")
        for r in rows:
            h = _h(str(r[0]))
            if service not in h["services"]:
                h["services"].append(service)
            h[f"{service}_events"] = int(r[1] or 0)

    # ---- 4. Anomaly counts, so the inventory can be sorted by suspicion as well as volume.
    anom = _rows(
        client,
        "SELECT src_addr, count() AS n FROM weirvern.netflow_anomalies "
        "WHERE detected_at >= now() - INTERVAL %(h)s HOUR "
        "GROUP BY src_addr ORDER BY n DESC LIMIT %(n)s",
        {"h": hours, "n": limit},
        "asset inventory (anomalies)",
    )
    read_ok["anomalies"] = anom is not None
    for r in anom or []:
        _h(str(r[0]))["anomalies"] = int(r[1] or 0)

    if not hosts:
        missing = [k for k, ok in read_ok.items() if not ok]
        reason = "no host has been seen in this window"
        if missing:
            reason = f"no host could be read; failed sources: {', '.join(missing)}"
        return _unavailable(reason, hosts=[], unreadable=zeek_unreadable)

    ordered = sorted(
        hosts.values(),
        key=lambda h: (h["anomalies"], h["bytes"]),
        reverse=True,
    )
    return {
        "available": True,
        "reason": "",
        "hours": hours,
        "count": len(ordered),
        "hosts": ordered,
        "unreadable": zeek_unreadable,
        "sources_read": [k for k, ok in read_ok.items() if ok],
        "sources_failed": [k for k, ok in read_ok.items() if not ok],
    }


def connection_graph(client, hours: int = 24, limit: int = 400) -> dict:
    """Nodes and edges for the Network view's connection graph.

    READS RAW `flows` because the graph needs per-EDGE facts. `flows_aggregated` has no
    dst_addr, so it can say how many destinations a host reached but not WHICH ones -- and a
    graph of "how many" is not a graph.

    SELF-EDGES ARE EXCLUDED (src_addr = dst_addr): broadcast and multicast traffic produces
    them constantly on a LAN and they render as a node loop, which reads as a rendering fault.

    NODES CARRY THEIR DEGREE, because a force layout that does not know how connected a node
    is produces a hairball. The degree is computed here and shipped, so the layout in the
    browser is drawing a measured quantity rather than guessing.

    `truncated` IS REPORTED. The limit is a hard cap on edges; without saying so, a busy
    segment would silently lose hosts and the graph would look complete while being partial.
    """
    edges = _rows(
        client,
        "SELECT src_addr, dst_addr, sum(bytes) AS bytes, count() AS flows "
        "FROM weirvern.flows "
        "WHERE timestamp >= now() - INTERVAL %(h)s HOUR "
        "  AND src_addr != '' AND dst_addr != '' "
        "  AND src_addr != dst_addr "
        "GROUP BY src_addr, dst_addr ORDER BY bytes DESC LIMIT %(n)s",
        {"h": hours, "n": limit},
        "connection graph",
    )
    if edges is None:
        return _unavailable("the connection query failed (see the worker log for the reason)")

    # Does more exist than we are returning? Asking for one more than the cap would be the
    # usual trick, but a count of DISTINCT pairs is cheap here and exact.
    total_rows = _rows(
        client,
        "SELECT uniqExact((src_addr, dst_addr)) FROM weirvern.flows "
        "WHERE timestamp >= now() - INTERVAL %(h)s HOUR "
        "  AND src_addr != '' AND dst_addr != '' AND src_addr != dst_addr",
        {"h": hours},
        "connection graph (total)",
    )
    total = int(total_rows[0][0] or 0) if total_rows else len(edges)

    nodes: dict[str, dict] = {}
    out_edges: list[dict] = []

    def _n(addr: str) -> dict:
        return nodes.setdefault(addr, {"id": addr, "degree": 0, "bytes": 0})

    for r in edges:
        src, dst = str(r[0]), str(r[1])
        b, f = int(r[2] or 0), int(r[3] or 0)
        out_edges.append({"source": src, "target": dst, "bytes": b, "flows": f})
        # Degree counts INCIDENT edges, so it is bumped on both ends -- a leaf has degree 1
        # even though it appears as a target only, which is what a layout wants.
        _n(src)["degree"] += 1
        _n(dst)["degree"] += 1
        _n(src)["bytes"] += b
        _n(dst)["bytes"] += b

    if not nodes:
        return _unavailable("no host-to-host traffic in this window",
                            nodes=[], edges=[], total_edges=total)

    # Names are attached if a resolver is available, but never instead of the address.
    names = resolve_names(client, list(nodes))
    for addr, node in nodes.items():
        node["name"] = names.get(addr, "")

    max_degree = max(n["degree"] for n in nodes.values())
    max_bytes = max((n["bytes"] for n in nodes.values()), default=1) or 1
    for node in nodes.values():
        # Normalised 0..1 sizes, computed once here so the browser does no scaling maths and
        # two clients cannot disagree about the layout.
        node["degree_norm"] = node["degree"] / max_degree if max_degree else 0.0
        node["bytes_norm"] = node["bytes"] / max_bytes

    return {
        "available": True,
        "reason": "",
        "hours": hours,
        "nodes": sorted(nodes.values(), key=lambda n: n["degree"], reverse=True),
        "edges": out_edges,
        "total_edges": total,
        "truncated": total > len(out_edges),
    }


def resolve_names(client, addrs: list[str], limit: int = 400) -> dict[str, str]:
    """Reverse-DNS names, as a mapping. Never a substitute for the address.

    REUSES `weirvern.admin.revdns` RATHER THAN QUERYING ZEEK's dns.log, and the reason is a
    measurement: on this segment the PTR answers are simply not in `weirvern.zeek_dns`. The
    23,422 qtype=12 rows are mDNS/SVCB service discovery (`_eero-ebid._tcp.local`,
    `_companion-link._tcp.local`) and their `answers` field is the `-` unset sentinel; the
    in-addr.arpa lookups carry no answer at all. Reading names from that table would have
    produced an empty name for every host while looking like a working query -- the exact
    "panel is empty and nobody knows why" failure this module exists to avoid.

    `revdns` already owns the whole policy: it resolves PRIVATE addresses by default so the
    lookup stays on the LAN, resolves public addresses only when WEIRVERN_REVERSE_DNS=all is
    set explicitly (each such lookup sends the address to a resolver), supports "off", caches
    positive AND negative results with different TTLs, and bounds each lookup with a socket
    timeout so a slow resolver cannot stall a page render. A host with no name keeps "" and
    the UI shows the address alone -- "" means "not seen", not "unknown host".

    The `client` argument is accepted for signature symmetry with the other helpers and is
    deliberately unused: names do not come from the database.
    """
    del client  # names are resolved live, not stored
    from weirvern.admin import revdns

    if not addrs:
        return {}
    out: dict[str, str] = {}
    for addr in addrs[:limit]:
        try:
            name = revdns.lookup(addr)
        except Exception as exc:  # noqa: BLE001 - a name is never worth failing a page for
            logger.debug("reverse lookup failed for %s: %s", addr, exc)
            continue
        if name:
            out[addr] = name
    return out


def host_zeek_activity(client, addr: str, hours: int = 24) -> dict:
    """Per-log event counts for ONE host, for the Host drill-down and the Zeek view.

    Separate from `asset_inventory` because the drill-down is per-host and does not want to
    pay for the whole segment's counts. A per-source filter on an indexed time column is
    cheap; counting sixteen tables for every host on every page load is not.
    """
    if not addr:
        return _unavailable("no address given")
    out: list[dict] = []
    unreadable: list[str] = []
    for table, addrcol in _ZEEK_HOST_TABLES:
        rows = _rows(
            client,
            f"SELECT count() AS n FROM weirvern.{table} "  # noqa: S608
            "WHERE ts >= now() - INTERVAL %(h)s HOUR AND toString(" + addrcol + ") = %(a)s",
            {"h": hours, "a": addr},
            f"host zeek activity ({table})",
        )
        if rows is None:
            unreadable.append(table)
            continue
        n = int(rows[0][0] or 0)
        # A log the host never appears in is omitted rather than listed as zero: sixteen
        # zero rows would bury the three that matter.
        if n:
            out.append({"log": table.removeprefix("zeek_"), "table": table, "events": n})
    if not out and unreadable:
        return _unavailable(
            f"no Zeek log could be read for this host; failed: {', '.join(unreadable)}",
            unreadable=unreadable,
        )
    return {"available": True, "reason": "", "addr": addr, "hours": hours,
            "logs": sorted(out, key=lambda d: d["events"], reverse=True),
            "unreadable": unreadable}


def top_edges_for(client, addrs: list[str], hours: int = 24, limit: int = 200) -> dict:
    """Edges touching a chosen set of hosts, for "track only these hosts" on the Network view.

    FILTERING HAPPENS IN CLICKHOUSE, not in the browser. A busy segment has far more edges
    than a page should hold, and sending them all so the client can discard most is the
    pattern that makes a graph view get slower the more useful it becomes.

    An EMPTY selection is not a filter -- it means "no restriction", which is what an operator
    expects from a cleared multi-select. Returning nothing would make the graph vanish and
    read as a failure. The payload says which reading applied.
    """
    if not addrs:
        return _unavailable("no hosts selected (an empty selection shows the whole graph)",
                            nodes=[], edges=[])
    edges = _rows(
        client,
        "SELECT src_addr, dst_addr, sum(bytes) AS bytes, count() AS flows "
        "FROM weirvern.flows "
        "WHERE timestamp >= now() - INTERVAL %(h)s HOUR "
        "  AND src_addr != dst_addr "
        "  AND (src_addr IN %(a)s OR dst_addr IN %(a)s) "
        "GROUP BY src_addr, dst_addr ORDER BY bytes DESC LIMIT %(n)s",
        {"h": hours, "n": limit, "a": tuple(addrs)},
        "tracked-host edges",
    )
    if edges is None:
        return _unavailable("the tracked-host query failed")

    nodes: dict[str, dict] = {}

    def _n(a: str) -> dict:
        return nodes.setdefault(a, {"id": a, "degree": 0, "bytes": 0, "selected": a in set(addrs)})

    out = []
    for r in edges:
        src, dst, b, f = str(r[0]), str(r[1]), int(r[2] or 0), int(r[3] or 0)
        out.append({"source": src, "target": dst, "bytes": b, "flows": f})
        _n(src)["degree"] += 1
        _n(dst)["degree"] += 1
        _n(src)["bytes"] += b
        _n(dst)["bytes"] += b

    names = resolve_names(client, list(nodes))
    for a, node in nodes.items():
        node["name"] = names.get(a, "")

    return {"available": True, "reason": "", "hours": hours, "tracked": list(addrs),
            "nodes": sorted(nodes.values(), key=lambda n: n["degree"], reverse=True),
            "edges": out}
