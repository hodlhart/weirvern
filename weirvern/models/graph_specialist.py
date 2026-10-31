"""The graph/peer specialist: fan-out, new edges, reciprocity and peer rarity.

The tabular model sees a host's counts; it does not see that one host suddenly talks to forty
peers that never talked to it. This specialist builds a bounded host graph from `zeek_conn`
edges and scores the source-side shape into `ml_candidate_scores`. It never writes the alert
table and never pages.
"""
from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Sequence
from typing import Any

from clickhouse_connect.driver.client import Client

from weirvern import __version__, networks
from weirvern.clock import utcnow

MODEL_NAME = "GraphSpecialist"


def _ratio(num: float, den: float) -> float:
    return float(num) / float(den) if den else 0.0


def features_from_edges(
    edges: Sequence[tuple[str, str]],
    host: str,
    *,
    seen_edges: set[tuple[str, str]] | None = None,
    peer_counts: dict[str, int] | None = None,
) -> dict[str, Any]:
    """Pure source-centric graph features. No edges means the host is absent."""
    out_edges = [(str(src), str(dst)) for src, dst in edges if str(src) == str(host)]
    if not out_edges:
        return {"present": False, "out_degree": 0.0}
    dsts = {dst for _, dst in out_edges}
    in_edges = [(str(src), str(dst)) for src, dst in edges if str(dst) == str(host)]
    edge_set = {(str(src), str(dst)) for src, dst in edges}
    reciprocity = _ratio(sum(1 for src, dst in out_edges if (dst, src) in edge_set),
                         len(out_edges))
    new_ratio = 0.0
    if seen_edges is not None:
        new_ratio = _ratio(sum(1 for edge in out_edges if edge not in seen_edges),
                           len(out_edges))
    rarity = 0.0
    if peer_counts and dsts:
        total = max(1, sum(peer_counts.values()))
        rarity = 1.0 - max((peer_counts.get(dst, 0) / total for dst in dsts), default=0.0)
    return {
        "present": True,
        "out_degree": float(len(dsts)),
        "in_degree": float(len({src for src, _ in in_edges})),
        "edge_count": float(len(out_edges)),
        "new_edge_ratio": new_ratio,
        "new_edge_known": seen_edges is not None,
        "peer_rarity": rarity,
        "peer_rarity_known": peer_counts is not None,
        "reciprocity": reciprocity,
        "fanout_norm": float(min(1.0, len(dsts) / 50.0)),
    }


def score(features: dict, *, use_graph_shape: bool = True) -> tuple[float, str]:
    """Bounded 0..1 score; fan-out + novelty + rarity - reciprocity."""
    if not features.get("present"):
        return 0.0, "no outbound edges in this window (host absent)"
    if not use_graph_shape:
        degree = float(features.get("out_degree", 0.0))
        return (round(min(1.0, degree / 100.0) * 0.25, 4),
                f"degree-only: out_degree={int(degree)} (graph shape ablated)")
    fanout = float(features.get("fanout_norm", 0.0))
    new_edge = float(features.get("new_edge_ratio", 0.0))
    rarity = float(features.get("peer_rarity", 0.0))
    reciprocity = float(features.get("reciprocity", 0.0))
    value = 0.40 * fanout + 0.30 * new_edge + 0.10 * rarity + 0.20 * (1.0 - reciprocity)
    value = round(min(1.0, value), 4)
    evidence = (
        f"out_degree={int(features.get('out_degree', 0.0))}; "
        f"in_degree={int(features.get('in_degree', 0.0))}; "
        f"new_edge={new_edge:.2f}{'' if features.get('new_edge_known') else ' (unknown)'}; "
        f"peer_rarity={rarity:.2f}{'' if features.get('peer_rarity_known') else ' (unknown)'}; "
        f"reciprocity={reciprocity:.2f}"
    )
    return value, evidence


def query_sql(minutes: int = 15, scope_filter: str = "") -> str:
    """Edges from `zeek_conn` in the window; a host with no edges is absent."""
    minutes = max(1, min(int(minutes), 7 * 24 * 60))
    return (
        "SELECT c.src_addr, c.dst_addr, count() AS edge_count "
        "FROM weirvern.zeek_conn AS c "
        f"WHERE c.ts >= now() - INTERVAL {minutes} MINUTE {scope_filter} "
        "GROUP BY c.src_addr, c.dst_addr"
    )


def score_rows(rows: Iterable[tuple], *, seen_edges: set[tuple[str, str]] | None = None,
               peer_counts: dict[str, int] | None = None) -> list[dict]:
    """Pure scoring over `(src, dst, count)` rows; one candidate per source host."""
    grouped: dict[str, list[tuple[str, str]]] = {}
    counts: Counter[str] = Counter()
    all_edges: list[tuple[str, str]] = []
    for src, dst, count in rows:
        src_s, dst_s = str(src), str(dst)
        all_edges.append((src_s, dst_s))
        grouped.setdefault(src_s, []).append((src_s, dst_s))
        counts[dst_s] += int(count)
    out: list[dict] = []
    for host in grouped:
        features = features_from_edges(all_edges, host, seen_edges=seen_edges,
                                       peer_counts=dict(counts) if peer_counts is None
                                       else peer_counts)
        value, evidence = score(features)
        out.append({"src_addr": host, "score": value, "evidence": evidence,
                    "features": features, "window_start": None})
    out.sort(key=lambda r: (-r["score"], r["src_addr"]))
    for rank, row in enumerate(out, 1):
        row["rank"] = rank
    return out


def run(client: Client, *, minutes: int = 15,
        scope_filter: str | None = None) -> dict:
    """Score graph shape into `ml_candidate_scores`; never touch the alert path."""
    if scope_filter is None:
        scope_filter = networks.training_filter(client, alias="c")
    try:
        rows = client.query(query_sql(minutes, scope_filter)).result_rows
    except Exception as exc:  # noqa: BLE001
        return {"available": False, "reason": f"graph query failed: {type(exc).__name__}",
                "rows": 0}
    if not rows:
        return {"available": False, "reason": "no Zeek connection edges in the window",
                "rows": 0}
    scored = score_rows(rows)
    # A graph score is per source but has no natural window in this query; use the query time
    # so the candidate store keeps a stable key.
    window = utcnow().replace(second=0, microsecond=0)
    out = []
    for row in scored:
        out.append([window, row["src_addr"], MODEL_NAME, float(row["score"]),
                    int(row["rank"]), row["evidence"], __version__, utcnow()])
    client.insert(
        "weirvern.ml_candidate_scores", out,
        column_names=["window_start", "src_addr", "model_name", "score", "rank",
                      "evidence", "model_version", "computed_at"],
    )
    scores = [row["score"] for row in scored]
    return {
        "available": True, "reason": "", "rows": len(scored),
        "hosts": len(scored), "score_p50": round(float(sorted(scores)[len(scores) // 2]), 4),
        "score_max": round(float(max(scores)), 4), "model_version": __version__,
        "source": "weirvern.zeek_conn (source-side graph)",
    }


__all__ = ["MODEL_NAME", "features_from_edges", "query_sql", "run", "score", "score_rows"]
