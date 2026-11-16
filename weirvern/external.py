"""External peer exposure: a read-only view, never an alert entity.

The operator-facing rule this module enforces (and the reason it exists at all):

    An address outside every declared scope is a PEER DIMENSION of a monitored host,
    not a host with its own baseline.

The research note in `references/baseline-ml-design.md` states the same contract: external
traffic is aggregated against the internal destination or presented as a peer view; it does not
become thousands of monitored hosts. This module produces that peer view. It never writes
`netflow_anomalies`, `alert_events`, or Sluice state.

Counts are NAMED, NOT FABRICATED. A failed query leaves its value `None` and records a reason;
zero would be indistinguishable from a quiet window.
"""
from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from clickhouse_connect.driver.client import Client

from weirvern import networks


def _scope_params(scopes: Iterable[networks.Scope], prefix: str = "s") -> dict[str, str]:
    """Parameter names for ClickHouse `isIPAddressInRange` calls."""
    return {f"{prefix}{i}": scope.cidr for i, scope in enumerate(scopes)}


def _external_clause(column: str, scopes: Iterable[networks.Scope],
                     prefix: str = "s") -> str:
    """SQL: `column` is outside every declared scope."""
    return " AND ".join(
        f"NOT isIPAddressInRange({column}, %({prefix}{i})s)"
        for i, _ in enumerate(scopes)
    )


def _monitored_clause(column: str, scopes: Iterable[networks.Scope],
                      prefix: str = "m") -> str:
    """SQL: `column` is inside a monitored scope."""
    monitored = [s for s in scopes if networks.is_monitored(s)]
    return " OR ".join(
        f"isIPAddressInRange({column}, %({prefix}{i})s)"
        for i, _ in enumerate(monitored)
    )


def _prefix_expr(column: str) -> str:
    """A /24 for IPv4 and the literal address for IPv6, without a GeoIP dependency.

    IPv4 space is the overwhelming majority of the peer population here. A prefix is a
    presentation/aggregation key only; the exact addresses remain in the rows and links.
    """
    return (
        f"if(position({column}, '.') > 0, "
        f"arrayStringConcat(arraySlice(splitByChar('.', {column}), 1, 3), '.'), {column})"
    )


def _int(value: Any) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _query_counts(client: Client, *, peer: str, local: str, scopes: list[networks.Scope],
                  params: dict[str, str], hours: int,
                  local_addr: str = "") -> dict[str, Any]:
    """Peers/bytes/flows, concentration and prefixes for one direction, from ONE scan.

    WHY ONE SCAN. This used to run three separate aggregates over the same raw range -- a
    uniqExact/sum/count, a per-peer share, and a per-prefix breakdown -- for each direction, so a
    single /api/networks request issued SIX full scans of a day of `weirvern.flows` (276M rows/day
    here). Measured live 2026-11-16: the route took 41.6s under light load and 105s under heavy, on
    a tab that only draws five rows per direction.

    The three answers come from one grouping instead. `GROUP BY peer, prefix` keeps the peer grain
    (every row is one external peer) and carries the prefix alongside it, so:
      * peers = row count            (exact; each peer appears once)
      * bytes/flows = column sums    (additive across peers)
      * share = max / sum            (still per-peer, because the grain IS the peer)
      * prefixes = regrouped in Python, which costs nothing next to a second table scan
    A peer's prefix is a function of its own address, so no peer can contribute to two prefixes and
    the totals stay exact.

    THE ROW COUNT IS BOUNDED BY THE PEER COUNT, which is the number the payload already reports:
    measured 3,474 inbound and 4,126 outbound peers over 24h on this deployment. A segment with
    millions of external peers would want this aggregated server-side twice instead, and the
    `peers` reading is what would say so.
    """
    where = f"{_external_clause(peer, scopes, 'e')} AND ({_monitored_clause(local, scopes, 'm')})"
    if local_addr:
        where += f" AND {local} = %(addr)s"
        params = dict(params, addr=local_addr)
    base = (
        "FROM weirvern.flows WHERE time_flow_start >= now() - INTERVAL "
        f"{int(hours)} HOUR AND {where}"
    )
    out: dict[str, Any] = {"peers": None, "bytes": None, "flows": None,
                           "top_peer_share": None, "top_prefixes": [], "error": ""}
    try:
        rows = client.query(
            f"SELECT {peer} AS peer, {_prefix_expr(peer)} AS prefix, "
            f"sum(bytes) AS bytes, count() AS flows {base} "
            "GROUP BY peer, prefix",
            parameters=params,
        ).result_rows
    except Exception as exc:  # noqa: BLE001
        out["error"] = f"{type(exc).__name__}: {exc}"[:200]
        return out

    if not rows:
        # An empty range is a READING of zero, not a failure: say so with numbers.
        out.update({"peers": 0, "bytes": 0, "flows": 0, "top_peer_share": 0.0, "top_prefixes": []})
        return out

    by_prefix: dict[str, dict[str, int]] = {}
    total_bytes = 0
    total_flows = 0
    largest_peer = 0
    for r in rows:
        # `_int` answers None for a value it cannot parse; a missing byte count is zero bytes here,
        # not an arithmetic error that would take the whole panel out.
        peer_bytes = _int(r[2]) or 0
        peer_flows = _int(r[3]) or 0
        total_bytes += peer_bytes
        total_flows += peer_flows
        largest_peer = max(largest_peer, peer_bytes)
        bucket = by_prefix.setdefault(str(r[1]), {"peers": 0, "bytes": 0})
        bucket["peers"] += 1
        bucket["bytes"] += peer_bytes

    out["peers"] = len(rows)
    out["bytes"] = total_bytes
    out["flows"] = total_flows
    out["top_peer_share"] = (largest_peer / total_bytes) if total_bytes else 0.0
    out["top_prefixes"] = [
        {"prefix": prefix, "peers": v["peers"], "bytes": v["bytes"]}
        for prefix, v in sorted(by_prefix.items(), key=lambda kv: kv[1]["bytes"], reverse=True)[:5]
    ]
    return out


def overview(client: Client, scopes: list[networks.Scope] | None = None,
             hours: int = 24) -> dict[str, Any]:
    """External exposure behind the Network coverage card.

    Inbound means external source -> monitored destination. Outbound means monitored source ->
    external destination. Neither direction creates an alert entity; this is a reading.
    """
    scopes = list(networks.load_scopes(client) if scopes is None else scopes)
    hours = max(1, min(int(hours or 24), 168))
    empty: dict[str, Any] = {"peers": None, "bytes": None, "flows": None, "top_peer_share": None,
                             "top_prefixes": [], "error": ""}
    result: dict[str, Any] = {
        "available": True,
        "hours": hours,
        "observed_only": True,
        "note": "External addresses are peer dimensions; they are not alert entities.",
        "inbound": dict(empty),
        "outbound": dict(empty),
        "errors": [],
    }
    if not scopes:
        result["available"] = False
        result["note"] = "No networks are declared, so external exposure is not scoped."
        return result
    monitored = [s for s in scopes if networks.is_monitored(s)]
    if not monitored:
        result["available"] = False
        result["note"] = "No monitored scope: there is no internal endpoint to attribute exposure to."
        return result
    params = _scope_params(scopes, "s")
    # `_query_counts` uses its own prefixes and expects the same CIDRs; pass one parameter set
    # containing all aliases, or ClickHouse rejects a missing parameter.
    params.update({f"e{i}": s.cidr for i, s in enumerate(scopes)})
    params.update({f"m{i}": s.cidr for i, s in enumerate(monitored)})
    result["inbound"] = _query_counts(
        client, peer="src_addr", local="dst_addr", scopes=scopes, params=params,
        hours=hours)
    result["outbound"] = _query_counts(
        client, peer="dst_addr", local="src_addr", scopes=scopes, params=params,
        hours=hours)
    for direction in ("inbound", "outbound"):
        if result[direction].get("error"):
            result["errors"].append(f"{direction}: {result[direction]['error']}")
    return result


def host_overview(client: Client, addr: str, scopes: list[networks.Scope] | None = None,
                  hours: int = 24) -> dict[str, Any]:
    """The same peer-dimension reading for ONE monitored endpoint.

    Used by the host page after an external peer is clicked. An address outside a monitored
    scope returns `available: false`; it is not silently treated as a local host.
    """
    scopes = list(networks.load_scopes(client) if scopes is None else scopes)
    hours = max(1, min(int(hours or 24), 168))
    addr = str(addr or "").strip()
    out: dict[str, Any] = {
        "available": False, "addr": addr, "hours": hours, "observed_only": True,
        "note": "External addresses are peer dimensions; they are not alert entities.",
        "inbound": {}, "outbound": {}, "errors": [],
    }
    if not scopes or not addr:
        out["reason"] = "no scopes or address"
        return out
    monitored = [s for s in scopes if networks.is_monitored(s)]
    if not any(_contains(scope, addr) for scope in monitored):
        out["reason"] = "this address is not inside a monitored scope"
        return out
    params = _scope_params(scopes, "s")
    params.update({f"e{i}": s.cidr for i, s in enumerate(scopes)})
    params.update({f"m{i}": s.cidr for i, s in enumerate(monitored)})
    out["inbound"] = _query_counts(
        client, peer="src_addr", local="dst_addr", scopes=scopes, params=params,
        hours=hours, local_addr=addr)
    out["outbound"] = _query_counts(
        client, peer="dst_addr", local="src_addr", scopes=scopes, params=params,
        hours=hours, local_addr=addr)
    out["available"] = True
    out["reason"] = ""
    for direction in ("inbound", "outbound"):
        if out[direction].get("error"):
            out["errors"].append(f"{direction}: {out[direction]['error']}")
    return out


def _contains(scope: networks.Scope, addr: str) -> bool:
    try:
        import ipaddress

        network = scope.network
        return network is not None and ipaddress.ip_address(addr) in network
    except (ValueError, TypeError):
        return False
