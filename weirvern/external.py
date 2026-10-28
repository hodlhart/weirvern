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
    """Peers/bytes/flows for one direction, with a top-peer concentration share."""
    # Both directions are "an external peer touching a monitored local endpoint". Only the
    # columns swap: inbound peer=src/local=dst, outbound peer=dst/local=src.
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
        row = client.query(
            f"SELECT uniqExact({peer}) AS peers, sum(bytes) AS bytes, count() AS flows {base}",
            parameters=params,
        ).result_rows
        if row:
            out["peers"], out["bytes"], out["flows"] = (
                _int(row[0][0]), _int(row[0][1]), _int(row[0][2]))
    except Exception as exc:  # noqa: BLE001
        out["error"] = f"{type(exc).__name__}: {exc}"[:200]
        return out
    try:
        share = client.query(
            "SELECT max(peer_bytes) / sum(peer_bytes) AS share FROM ("
            f"SELECT {peer} AS peer, sum(bytes) AS peer_bytes {base} GROUP BY peer)",
            parameters=params,
        ).result_rows
        if share and share[0][0] is not None:
            out["top_peer_share"] = float(share[0][0])
    except Exception as exc:  # noqa: BLE001
        out["error"] = f"concentration {type(exc).__name__}: {exc}"[:200]
    try:
        rows = client.query(
            f"SELECT {_prefix_expr(peer)} AS prefix, uniqExact({peer}) AS peers, "
            f"sum(bytes) AS bytes {base} GROUP BY prefix ORDER BY bytes DESC LIMIT 5",
            parameters=params,
        ).result_rows
        out["top_prefixes"] = [
            {"prefix": str(r[0]), "peers": _int(r[1]), "bytes": _int(r[2])}
            for r in rows
        ]
    except Exception as exc:  # noqa: BLE001
        out["error"] = f"prefixes {type(exc).__name__}: {exc}"[:200]
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
