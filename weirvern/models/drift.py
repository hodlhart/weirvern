"""Drift monitoring: a score-distribution shift is a notice, never a page.

The fixed-budget gate catches a model that is wrong at one point in time. Drift catches a model
whose input or score distribution has moved since it was calibrated. This module compares a
current time split against the preceding split per model/host, writes `weirvern.ml_drift`, and
returns a retrain recommendation. It never retrains, never alerts and never writes the alert
table.
"""
from __future__ import annotations

import bisect
import math
import statistics
from collections.abc import Iterable, Sequence
from datetime import timedelta

from clickhouse_connect.driver.client import Client

from weirvern import __version__
from weirvern.clock import utcnow

MODEL_NAME = "DriftMonitor"
WATCH_THRESHOLD = 0.10
DRIFT_THRESHOLD = 0.25


def psi(baseline: Sequence[float], current: Sequence[float], bins: int = 10) -> float:
    """Population Stability Index with baseline quantile edges.

    Empty or tiny samples return 0.0; they are not evidence of stability, and `run` refuses to
    score a pair below its minimum sample count. Quantile edges keep the comparison robust to a
    few extreme values.
    """
    if len(baseline) < 2 or len(current) < 2:
        return 0.0
    ordered = sorted(float(v) for v in baseline)
    edges = sorted({ordered[min(len(ordered) - 1, int(i * len(ordered) / bins))]
                    for i in range(1, bins)})
    if not edges:
        return 0.0
    base_counts = [0] * (len(edges) + 1)
    cur_counts = [0] * (len(edges) + 1)
    for value in ordered:
        base_counts[bisect.bisect_right(edges, value)] += 1
    for value in current:
        cur_counts[bisect.bisect_right(edges, float(value))] += 1
    total_b = max(1, len(ordered))
    total_c = max(1, len(current))
    score = 0.0
    for b, c in zip(base_counts, cur_counts, strict=False):
        bp = max(b / total_b, 1e-4)
        cp = max(c / total_c, 1e-4)
        score += (cp - bp) * math.log(cp / bp)
    return round(score, 6)


def classify(score: float) -> str:
    """Three words the operator can act on; `drift` only recommends a review."""
    if score >= DRIFT_THRESHOLD:
        return "drift"
    if score >= WATCH_THRESHOLD:
        return "watch"
    return "stable"


def retrain_policy(rows: Iterable[dict], *, threshold: float = DRIFT_THRESHOLD) -> dict:
    """A review recommendation, never an automatic retrain."""
    drifting = sorted({str(row.get("model_name", "")) for row in rows
                       if float(row.get("drift_score", 0.0)) >= threshold})
    return {
        "trigger": bool(drifting),
        "models": drifting,
        "threshold": threshold,
        "automatic": False,
        "reason": ("drift review recommended for " + ", ".join(drifting)
                   if drifting else "no model is above the drift threshold"),
    }


def _split_sql(table: str, column: str, start: str, end: str) -> str:
    return (
        f"SELECT model_name, src_addr, groupArray(score) AS scores "
        f"FROM {table} WHERE {column} >= '{start}' AND {column} < '{end}' "
        "GROUP BY model_name, src_addr"
    )


def run(client: Client, *, hours: int = 24, baseline_hours: int = 24,
        min_samples: int = 10) -> dict:
    """Compare current and preceding model/host score distributions; notice only."""
    hours = max(1, min(int(hours), 24 * 30))
    baseline_hours = max(1, min(int(baseline_hours), 24 * 30))
    now = utcnow().replace(microsecond=0)
    current_start = now - timedelta(hours=hours)
    baseline_start = current_start - timedelta(hours=baseline_hours)
    fmt = "%Y-%m-%d %H:%M:%S"
    try:
        current = client.query(_split_sql("weirvern.ml_window_scores", "computed_at",
                                          current_start.strftime(fmt), now.strftime(fmt))
                               ).result_rows
        baseline = client.query(_split_sql("weirvern.ml_window_scores", "computed_at",
                                           baseline_start.strftime(fmt),
                                           current_start.strftime(fmt))).result_rows
    except Exception as exc:  # noqa: BLE001
        return {"available": False, "reason": f"drift query failed: {type(exc).__name__}",
                "rows": 0, "notices": [], "retrain": retrain_policy([])}
    cur_map = {(str(m), str(h)): [float(v) for v in scores or []]
               for m, h, scores in current}
    base_map = {(str(m), str(h)): [float(v) for v in scores or []]
                for m, h, scores in baseline}
    roles: dict[str, str] = {}
    try:
        roles = {str(host): str(role) for host, role in
                 client.query("SELECT host, role FROM weirvern.host_roles FINAL").result_rows}
    except Exception:
        roles = {}
    rows: list[dict] = []
    for key in sorted(set(cur_map) & set(base_map)):
        b, c = base_map[key], cur_map[key]
        if len(b) < min_samples or len(c) < min_samples:
            continue
        score = psi(b, c)
        status = classify(score)
        rows.append({
            "model_name": key[0], "src_addr": key[1], "role": roles.get(key[1], ""),
            "metric": "score", "baseline_value": round(statistics.fmean(b), 6),
            "current_value": round(statistics.fmean(c), 6), "drift_score": score,
            "status": status,
            "evidence": (f"baseline_n={len(b)}; current_n={len(c)}; "
                         f"baseline_mean={statistics.fmean(b):.4f}; "
                         f"current_mean={statistics.fmean(c):.4f}; psi={score:.4f}"),
            "window_start": current_start,
        })
    if rows:
        client.insert(
            "weirvern.ml_drift",
            [[now, row["window_start"], row["model_name"], row["src_addr"], row["role"],
              row["metric"], row["baseline_value"], row["current_value"],
              row["drift_score"], row["status"], row["evidence"]] for row in rows],
            column_names=["computed_at", "window_start", "model_name", "src_addr", "role",
                          "metric", "baseline_value", "current_value", "drift_score",
                          "status", "evidence"],
        )
    notices = [row for row in rows if row["status"] in ("watch", "drift")]
    return {
        "available": True, "reason": "", "rows": len(rows), "pairs": len(rows),
        "notices": notices, "retrain": retrain_policy(rows),
        "model_version": __version__,
        "source": "weirvern.ml_window_scores (time-split PSI)",
    }


__all__ = ["DRIFT_THRESHOLD", "MODEL_NAME", "WATCH_THRESHOLD", "classify", "psi",
           "retrain_policy", "run"]
