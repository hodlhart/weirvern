"""External exposure shadow channel.

EXTERNAL ADDRESSES ARE PEER DIMENSIONS, NOT HOSTS. This channel answers one question that the
per-host ensemble cannot: "is a monitored endpoint's outside-facing population changing shape?"
It writes only to `ml_candidate_scores` (the existing append-only shadow store). It never writes
`netflow_anomalies`, `alert_events`, or Sluice state, and it never creates an external entity.

The score is a RANKING, not a probability. It is the maximum percentile of the measured features
inside the sampled population; a high rank is a lead to inspect, not an incident. Promotion is a
separate decision after the backtest described in docs/research/external-peer-layer.md.
"""
from __future__ import annotations

import json
import statistics
from typing import Any

from clickhouse_connect.driver.client import Client

from weirvern import __version__, networks
from weirvern.clock import utcnow

MODEL_NAME = "External exposure"
SHADOW_HOURS = 24
MAX_ROWS = 5000


def _direction_sql(peer_col: str, local_col: str, scopes: list[networks.Scope],
                   *, prefix: str) -> str:
    """The peer/local predicate for one direction, with ClickHouse parameters."""
    not_external = " AND ".join(
        f"NOT isIPAddressInRange({peer_col}, %({prefix}e{i})s)"
        for i, _ in enumerate(scopes)
    )
    monitored = [s for s in scopes if networks.is_monitored(s)]
    inside = " OR ".join(
        f"isIPAddressInRange({local_col}, %({prefix}m{i})s)"
        for i, _ in enumerate(monitored)
    )
    return f"{not_external} AND ({inside})"


def _percentile(values: list[float]) -> list[float]:
    """Monotone percentile ranks in [0, 1], ties sharing the average position."""
    if not values:
        return []
    order = sorted(range(len(values)), key=lambda i: values[i])
    out = [0.0] * len(values)
    i = 0
    while i < len(order):
        j = i
        while j + 1 < len(order) and values[order[j + 1]] == values[order[i]]:
            j += 1
        rank = (i + j) / 2.0 / max(len(values) - 1, 1)
        for k in range(i, j + 1):
            out[order[k]] = rank
        i = j + 1
    return out


def _feature_rows(client: Client, scopes: list[networks.Scope], *, hours: int,
                  limit: int = MAX_ROWS) -> dict[tuple[Any, str], dict[str, Any]]:
    """Inbound/outbound features for monitored endpoints, keyed by (window, local address)."""
    if not scopes:
        return {}
    params: dict[str, str] = {}
    for i, scope in enumerate(scopes):
        params[f"ie{i}"] = scope.cidr
        params[f"oe{i}"] = scope.cidr
    for i, scope in enumerate(scopes):
        if networks.is_monitored(scope):
            params[f"im{i}"] = scope.cidr
            params[f"om{i}"] = scope.cidr
    inbound_where = _direction_sql("src_addr", "dst_addr", scopes, prefix="i")
    outbound_where = _direction_sql("dst_addr", "src_addr", scopes, prefix="o")
    base_in = (
        "FROM weirvern.flows WHERE time_flow_start >= now() - INTERVAL "
        f"{int(hours)} HOUR AND {inbound_where}"
    )
    base_out = (
        "FROM weirvern.flows WHERE time_flow_start >= now() - INTERVAL "
        f"{int(hours)} HOUR AND {outbound_where}"
    )
    out: dict[tuple[Any, str], dict[str, Any]] = {}

    def _collect(base: str, peer: str, local: str, side: str, params_: dict[str, str]) -> None:
        # First aggregate to one row per peer, so max(peer_bytes) is the top peer; then collapse
        # to host-window. This is deliberately two stages: summing raw flow rows first would make
        # a peer that appears many times look larger than a single large conversation.
        rows = client.query(
            "SELECT window_start, host, uniqExact(peer) AS peers, sum(peer_bytes) AS bytes, "
            "       sum(peer_flows) AS flows, max(peer_bytes) / sum(peer_bytes) AS top_share "
            "FROM ("
            f"  SELECT toStartOfFiveMinute(time_flow_start) AS window_start, {local} AS host, "
            f"         {peer} AS peer, sum(bytes) AS peer_bytes, count() AS peer_flows "
            f"  {base} GROUP BY window_start, host, peer"
            ") GROUP BY window_start, host ORDER BY bytes DESC LIMIT " + str(int(limit)),
            parameters=params_,
        ).result_rows
        port_rows = client.query(
            f"SELECT toStartOfFiveMinute(time_flow_start) AS window_start, {local} AS host, "
            f"       uniqExact(dst_port) AS ports {base} GROUP BY window_start, host",
            parameters=params_,
        ).result_rows
        ports = {(r[0], str(r[1])): int(r[2]) for r in port_rows}
        for r in rows:
            key = (r[0], str(r[1]))
            row = out.setdefault(key, {"host": str(r[1]), "window_start": r[0]})
            row[f"{side}_peers"] = int(r[2] or 0)
            row[f"{side}_bytes"] = int(r[3] or 0)
            row[f"{side}_flows"] = int(r[4] or 0)
            row[f"{side}_top_share"] = float(r[5] or 0.0)
            row[f"{side}_ports"] = ports.get(key, 0)

    # A single parameter set can carry all four aliases; ClickHouse requires every placeholder
    # used by the SQL to be present.
    _collect(base_in, "src_addr", "dst_addr", "inbound", params)
    _collect(base_out, "dst_addr", "src_addr", "outbound", params)
    return out


def run(client: Client, *, hours: int = SHADOW_HOURS, limit: int = MAX_ROWS) -> dict[str, Any]:
    """Write the latest external-exposure ranking to the shadow table. Never raises past caller."""
    scopes = networks.load_scopes(client)
    if not scopes:
        return {"available": False, "reason": "no declared scopes", "rows": 0}
    if not any(networks.is_monitored(s) for s in scopes):
        return {"available": False, "reason": "no monitored scope", "rows": 0}
    rows = _feature_rows(client, scopes, hours=hours, limit=limit)
    if not rows:
        return {"available": False, "reason": "no external peer rows in the window", "rows": 0}
    keys = list(rows)
    names = [
        "inbound_peers", "inbound_bytes", "inbound_flows", "inbound_ports", "inbound_top_share",
        "outbound_peers", "outbound_bytes", "outbound_flows", "outbound_ports", "outbound_top_share",
    ]
    ranks: dict[str, list[float]] = {}
    for name in names:
        values = [float(rows[k].get(name, 0) or 0) for k in keys]
        ranks[name] = _percentile(values)
    scored: list[tuple[float, tuple[Any, str], dict[str, Any]]] = []
    for i, key in enumerate(keys):
        score = max(ranks[name][i] for name in names)
        scored.append((score, key, rows[key]))
    scored.sort(key=lambda item: item[0], reverse=True)
    scored = scored[:limit]
    when = utcnow()
    out_rows = []
    for score, _key, row in scored:
        evidence = {name: row.get(name) for name in names}
        out_rows.append([
            row["window_start"], row["host"], MODEL_NAME, float(score), 1,
            json.dumps(evidence, sort_keys=True), __version__, when,
        ])
    client.insert(
        "weirvern.ml_candidate_scores", out_rows,
        column_names=["window_start", "src_addr", "model_name", "score", "rank",
                      "evidence", "model_version", "computed_at"],
    )
    scores = [item[0] for item in scored]
    return {
        "available": True, "rows": len(out_rows), "hosts": len({r[1] for r in out_rows}),
        "hours": hours, "score_p50": float(statistics.median(scores)) if scores else 0.0,
        "score_max": float(max(scores)) if scores else 0.0,
        "model_name": MODEL_NAME, "model_version": __version__,
    }


__all__ = ["MODEL_NAME", "SHADOW_HOURS", "MAX_ROWS", "run"]
