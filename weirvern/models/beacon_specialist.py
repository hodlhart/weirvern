"""The beacon/periodicity specialist: regular callbacks, not regular volume.

The tabular ensemble sees a five-minute aggregate. A beacon can move almost no data and still
be perfectly periodic, so this specialist scores the inter-arrival shape of a host's flow
times into the shadow candidate store. It never writes the alert table and never pages.
"""
from __future__ import annotations

import statistics
from collections.abc import Iterable, Sequence
from time import perf_counter

from clickhouse_connect.driver.client import Client

from weirvern import __version__, networks
from weirvern.clock import utcnow

MODEL_NAME = "BeaconSpecialist"


def intervals(times: Sequence[float]) -> list[float]:
    """Positive inter-arrival gaps in seconds; duplicate timestamps are real but not gaps."""
    ordered = sorted(float(t) for t in times)
    return [b - a for a, b in zip(ordered, ordered[1:], strict=False) if b > a]


def features_from_times(times: Sequence[float], sizes: Sequence[float] | None = None
                        ) -> dict[str, float | bool]:
    """Pure inter-arrival features. Fewer than four events is not a beacon, it is a sample.

    `sizes` is optional. When supplied, a large median payload is evidence against a beacon:
    a periodic backup and a periodic C2 callback have the same gaps but not the same bytes.
    """
    count = len(times)
    if count < 4:
        return {"present": False, "event_count": float(count)}
    gaps = intervals(times)
    if not gaps:
        return {"present": False, "event_count": float(count)}
    median = statistics.median(gaps)
    mean = statistics.fmean(gaps)
    stdev = statistics.pstdev(gaps) if len(gaps) > 1 else 0.0
    cv = stdev / mean if mean else 0.0
    tolerance = max(1.0, median * 0.20)
    periodic = sum(1 for gap in gaps if abs(gap - median) <= tolerance) / len(gaps)
    out: dict[str, float | bool] = {
        "present": True,
        "event_count": float(count),
        "gap_count": float(len(gaps)),
        "median_gap_s": float(median),
        "mean_gap_s": float(mean),
        "gap_cv": float(cv),
        "periodicity": float(periodic),
        "regularity": float(max(0.0, 1.0 - min(cv, 1.0))),
        "span_s": float(max(times) - min(times)),
        "count_norm": float(min(1.0, len(gaps) / 20.0)),
        "payload_known": sizes is not None,
    }
    if sizes:
        median_size = statistics.median(float(s) for s in sizes)
        out["median_payload_bytes"] = float(median_size)
        # A beacon is a small callback; a backup is not. 1 MiB is the boundary, not a claim
        # that every 1 MiB flow is benign.
        out["small_payload"] = float(max(0.0, 1.0 - min(median_size / 1_000_000.0, 1.0)))
    else:
        out["median_payload_bytes"] = 0.0
        out["small_payload"] = 0.0
    return out


def score(features: dict, *, use_periodicity: bool = True) -> tuple[float, str]:
    """Bounded 0..1 score; a burst with no positive gaps is absent, not perfectly regular."""
    if not features.get("present"):
        return 0.0, "not enough distinct events in this window (absent)"
    count = int(features.get("event_count", 0.0))
    if not use_periodicity:
        return (round(min(1.0, count / 100.0) * 0.25, 4),
                f"count-only: events={count} (periodicity ablated)")
    periodicity = float(features.get("periodicity", 0.0))
    regularity = float(features.get("regularity", 0.0))
    count_norm = float(features.get("count_norm", 0.0))
    small_payload = float(features.get("small_payload", 0.0))
    # Without payload evidence the score still works on timing alone; the payload term is
    # applied only when a caller supplied sizes, so an unmeasured payload is not a fake zero.
    if features.get("payload_known"):
        value = 0.40 * periodicity + 0.25 * regularity + 0.10 * count_norm + 0.25 * small_payload
    else:
        value = 0.50 * periodicity + 0.30 * regularity + 0.20 * count_norm
    value = round(min(1.0, value), 4)
    evidence = (
        f"events={int(features.get('event_count', 0.0))}; "
        f"median_gap={float(features.get('median_gap_s', 0.0)):.1f}s; "
        f"gap_cv={float(features.get('gap_cv', 0.0)):.2f}; "
        f"periodicity={periodicity:.2f}; regularity={regularity:.2f}; "
        f"median_payload={float(features.get('median_payload_bytes', 0.0)):.0f}B"
        f"{'' if features.get('payload_known') else ' (unknown)'}; "
        f"span={float(features.get('span_s', 0.0)):.0f}s"
    )
    return value, evidence


def query_sql(minutes: int = 60, scope_filter: str = "") -> str:
    """Raw flow times per source/destination pair; a pair with no flows is absent."""
    minutes = max(1, min(int(minutes), 3 * 24 * 60))
    return (
        "SELECT f.src_addr, f.dst_addr, min(f.time_flow_start) AS window_start, "
        "count() AS event_count, groupArray(f.time_flow_start) AS times, "
        "groupArray(f.bytes) AS sizes "
        "FROM weirvern.flows AS f "
        f"WHERE f.time_flow_start >= now() - INTERVAL {minutes} MINUTE {scope_filter} "
        "GROUP BY f.src_addr, f.dst_addr "
        "HAVING event_count >= 4 ORDER BY event_count DESC LIMIT 500"
    )


def _epochs(times: Iterable) -> list[float]:
    out = []
    for value in times:
        if hasattr(value, "timestamp"):
            out.append(float(value.timestamp()))
        else:
            out.append(float(value))
    return out


def score_rows(rows: Iterable[tuple]) -> list[dict]:
    """Pure scoring over query rows; each row is one source/destination pair."""
    out: list[dict] = []
    for source_row in rows:
        (src_addr, dst_addr, window_start, event_count, times, sizes) = source_row
        features = features_from_times(_epochs(times or []),
                                       [float(s) for s in (sizes or [])])
        value, evidence = score(features)
        out.append({
            "window_start": window_start,
            "src_addr": str(src_addr),
            "dst_addr": str(dst_addr),
            "event_count": int(event_count),
            "score": value,
            "evidence": evidence,
            "features": features,
        })
    out.sort(key=lambda r: (str(r["window_start"]), -r["score"], r["src_addr"], r["dst_addr"]))
    rank_by_window: dict[str, int] = {}
    for candidate in out:
        key = str(candidate["window_start"])
        rank_by_window[key] = rank_by_window.get(key, 0) + 1
        candidate["rank"] = rank_by_window[key]
    return out


def run(client: Client, *, minutes: int = 60,
        scope_filter: str | None = None) -> dict:
    """Score raw-flow periodicity into `ml_candidate_scores`; never touch the alert path."""
    if scope_filter is None:
        scope_filter = networks.training_filter(client, alias="f")
    started = perf_counter()
    try:
        rows = client.query(query_sql(minutes, scope_filter)).result_rows
    except Exception as exc:  # noqa: BLE001
        return {"available": False, "reason": f"flow-time query failed: {type(exc).__name__}",
                "rows": 0, "elapsed_ms": round((perf_counter() - started) * 1000, 1)}
    if not rows:
        return {"available": False, "reason": "no flow-time pairs in the window",
                "rows": 0, "elapsed_ms": round((perf_counter() - started) * 1000, 1)}
    scored = score_rows(rows)
    now = utcnow()
    out = []
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
        "available": True, "reason": "", "rows": len(scored),
        "pairs": len(scored), "hosts": len({row["src_addr"] for row in scored}),
        "score_p50": round(float(sorted(scores)[len(scores) // 2]), 4),
        "score_max": round(float(max(scores)), 4),
        "elapsed_ms": round((perf_counter() - started) * 1000, 1),
        "model_version": __version__,
        "source": "weirvern.flows (inter-arrival shape)",
    }


__all__ = ["MODEL_NAME", "features_from_times", "intervals", "query_sql", "run", "score",
           "score_rows"]
