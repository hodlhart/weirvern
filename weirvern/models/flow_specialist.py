"""The raw-flow specialist: connection shape, not just aggregate volume.

Why this exists: `flows_aggregated` reduces a scan to a byte count, so a zero-byte SYN sweep
looks small and a busy server looks large. The raw `flows` table still carries the per-flow
TCP flags, byte count and duration. This specialist scores those shapes into the existing
`ml_candidate_scores` shadow store; it never writes the alert table and never alerts.

The score is intentionally a transparent, bounded rule over measured ratios, not a trained
black box. It is the positive/negative fixture for SRC-3; a learned model can replace the
scoring later without changing the evidence or the store.
"""
from __future__ import annotations

from collections.abc import Iterable
from time import perf_counter

from clickhouse_connect.driver.client import Client

from weirvern import __version__, networks
from weirvern.clock import utcnow

MODEL_NAME = "FlowSpecialist"


def _ratio(num: float, den: float) -> float:
    return float(num) / float(den) if den else 0.0


def features_from_counts(
    *,
    flows: int,
    zero_bytes: int,
    syn: int,
    rst: int,
    unique_dsts: int,
    unique_ports: int,
    short_lived: int,
    total_bytes: int,
    total_packets: int,
) -> dict[str, float]:
    """The connection-shape features, with every denominator guarded.

    A host with no flows has no row (presence is absence, not a zero vector); these functions
    assume at least one flow and say so through the guarded ratios rather than dividing.
    """
    return {
        "flows": float(flows),
        "zero_byte_ratio": _ratio(zero_bytes, flows),
        "syn_ratio": _ratio(syn, flows),
        "rst_ratio": _ratio(rst, flows),
        "short_ratio": _ratio(short_lived, flows),
        "unique_dsts": float(unique_dsts),
        "unique_ports": float(unique_ports),
        "avg_bytes": _ratio(total_bytes, flows),
        "bytes_per_packet": _ratio(total_bytes, total_packets),
    }


def score(features: dict[str, float], *, use_raw_shape: bool = True) -> tuple[float, str]:
    """Bounded 0..1 score and a readable evidence string.

    With `use_raw_shape=False` only volume remains. That is the source-ablation control: a
    zero-byte scan should fall while a volume burst still rises.
    """
    flows = float(features.get("flows", 0.0))
    if not use_raw_shape:
        volume = min(1.0, flows / 500.0) * 0.5
        avg = min(1.0, float(features.get("avg_bytes", 0.0)) / 1_000_000.0) * 0.5
        value = round(min(1.0, volume + avg), 4)
        return value, f"volume-only: flows={int(flows)}, avg_bytes={int(features.get('avg_bytes', 0))}"

    zero = float(features.get("zero_byte_ratio", 0.0))
    syn = float(features.get("syn_ratio", 0.0))
    rst = float(features.get("rst_ratio", 0.0))
    ports = float(features.get("unique_ports", 0.0))
    dsts = float(features.get("unique_dsts", 0.0))
    short = float(features.get("short_ratio", 0.0))
    # The two strongest scan signatures are zero-byte replies and a SYN-heavy fan-out.
    value = (0.45 * zero + 0.30 * syn + 0.10 * min(ports / 100.0, 1.0)
             + 0.05 * min(dsts / 50.0, 1.0) + 0.05 * rst + 0.05 * short)
    value = round(min(1.0, value), 4)
    evidence = (
        f"flows={int(flows)}; zero_byte={zero:.2f}; syn={syn:.2f}; rst={rst:.2f}; "
        f"unique_dsts={int(dsts)}; unique_ports={int(ports)}; short={short:.2f}; "
        f"bytes_per_packet={float(features.get('bytes_per_packet', 0.0)):.1f}"
    )
    return value, evidence


def query_sql(minutes: int = 15, scope_filter: str = "") -> str:
    """The raw-flow aggregate for the last `minutes`, one row per host-window.

    The table is the 3-day raw flow store, not the 7-day aggregate. A host with no raw flows
    is simply absent; the caller reports that as no candidates rather than padding zeros.
    """
    minutes = max(1, min(int(minutes), 3 * 24 * 60))
    return (
        "SELECT toStartOfFiveMinute(f.time_flow_start) AS window_start, f.src_addr, "
        "count() AS flows, "
        "countIf(f.bytes = 0) AS zero_bytes, "
        "countIf(bitAnd(f.tcp_flags, 2) != 0) AS syn, "
        "countIf(bitAnd(f.tcp_flags, 4) != 0) AS rst, "
        "uniq(f.dst_addr) AS unique_dsts, "
        "uniq(f.dst_port) AS unique_ports, "
        "countIf(dateDiff('millisecond', f.time_flow_start, f.time_flow_end) < 1000) AS short_lived, "
        "sum(f.bytes) AS total_bytes, "
        "sum(f.packets) AS total_packets "
        "FROM weirvern.flows AS f "
        f"WHERE f.time_flow_start >= now() - INTERVAL {minutes} MINUTE "
        f"{scope_filter} "
        "GROUP BY window_start, f.src_addr"
    )


def score_rows(rows: Iterable[tuple], *, use_raw_shape: bool = True) -> list[dict]:
    """Pure scoring over query rows; also the test seam for the ablation."""
    out: list[dict] = []
    for source_row in rows:
        (window_start, src_addr, flows, zero_bytes, syn, rst, unique_dsts, unique_ports,
         short_lived, total_bytes, total_packets) = source_row
        features = features_from_counts(
            flows=int(flows), zero_bytes=int(zero_bytes), syn=int(syn), rst=int(rst),
            unique_dsts=int(unique_dsts), unique_ports=int(unique_ports),
            short_lived=int(short_lived), total_bytes=int(total_bytes),
            total_packets=int(total_packets),
        )
        value, evidence = score(features, use_raw_shape=use_raw_shape)
        out.append({"window_start": window_start, "src_addr": str(src_addr),
                    "score": value, "evidence": evidence, "features": features})
    # Rank is a per-window ordering over the returned candidate set, not a global score.
    out.sort(key=lambda r: (str(r["window_start"]), -r["score"], r["src_addr"]))
    rank_by_window: dict[str, int] = {}
    for candidate in out:
        key = str(candidate["window_start"])
        rank_by_window[key] = rank_by_window.get(key, 0) + 1
        candidate["rank"] = rank_by_window[key]
    return out


def run(client: Client, *, minutes: int = 15,
        scope_filter: str | None = None) -> dict:
    """Score the last window into `ml_candidate_scores`; never touch the alert path."""
    if scope_filter is None:
        scope_filter = networks.training_filter(client, alias="f")
    sql = query_sql(minutes, scope_filter)
    started = perf_counter()
    try:
        rows = client.query(sql).result_rows
    except Exception as exc:  # noqa: BLE001
        return {"available": False, "reason": f"raw-flow query failed: {type(exc).__name__}",
                "rows": 0, "elapsed_ms": round((perf_counter() - started) * 1000, 1)}
    if not rows:
        return {"available": False, "reason": "no raw flows in the window",
                "rows": 0, "elapsed_ms": round((perf_counter() - started) * 1000, 1)}
    scored = score_rows(rows)
    out = []
    now = utcnow()
    for row in scored:
        out.append([
            row["window_start"], row["src_addr"], MODEL_NAME, float(row["score"]),
            int(row["rank"]), row["evidence"], __version__, now,
        ])
    client.insert(
        "weirvern.ml_candidate_scores", out,
        column_names=["window_start", "src_addr", "model_name", "score", "rank",
                      "evidence", "model_version", "computed_at"],
    )
    scores = [row["score"] for row in scored]
    return {
        "available": True,
        "reason": "",
        "rows": len(scored),
        "windows": len({str(row["window_start"]) for row in scored}),
        "score_p50": round(float(sorted(scores)[len(scores) // 2]), 4),
        "score_max": round(float(max(scores)), 4),
        "elapsed_ms": round((perf_counter() - started) * 1000, 1),
        "model_version": __version__,
        "source": "weirvern.flows (raw connection shape)",
    }


__all__ = ["MODEL_NAME", "features_from_counts", "query_sql", "run", "score", "score_rows"]
