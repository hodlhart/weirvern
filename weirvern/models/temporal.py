"""Matrix-profile temporal shadow channel.

A matrix profile gives every window of a series its nearest-neighbour distance. The maximum is a
discord: a window with no similar shape in the host's own history. This is the question the
tabular detectors cannot ask, because they see one 5-minute aggregate at a time.

Shadow-only: rows go to `ml_temporal_scores`, never to alerts.
"""
from __future__ import annotations

import math

import numpy as np
from clickhouse_connect.driver.client import Client

from weirvern import __version__
from weirvern.clock import utcnow

MATRIX_PROFILE_VERSION = "mp-1"


def matrix_profile(values: list[float], m: int = 12) -> tuple[np.ndarray, int, float, int]:
    """(profile, discord_index, discord_score) for a 1-D series.

    Windows are z-normalised before comparison, so a change in level alone does not dominate the
    shape. Trivial matches within m samples are excluded. Returns an empty profile for a series
    too short to compare.
    """
    x = np.asarray(values, dtype=float)
    n = len(x)
    if n < 2 * m + 2:
        return np.empty(0), -1, 0.0, -1
    # Sliding windows, each z-normalised (zero-mean, unit-variance; a constant window stays 0).
    win = np.lib.stride_tricks.sliding_window_view(x, m)
    win = win - win.mean(axis=1, keepdims=True)
    sd = win.std(axis=1, keepdims=True)
    win = np.divide(win, sd, out=np.zeros_like(win), where=sd > 1e-12)
    # Pairwise Euclidean distance between z-normalised windows. This is O(n^2*m); the per-host
    # 72h series is ~864 points, so the bounded job is cheap and transparent.
    dist = np.linalg.norm(win[:, None, :] - win[None, :, :], axis=2)
    for i in range(len(win)):
        lo, hi = max(0, i - m + 1), min(len(win), i + m)
        dist[i, lo:hi] = np.inf
    profile = dist.min(axis=1)
    profile[~np.isfinite(profile)] = 0.0
    idx = int(np.argmax(profile))
    score = float(profile[idx]) if math.isfinite(float(profile[idx])) else 0.0
    nearest = int(np.argmin(dist[idx])) if np.isfinite(dist[idx]).any() else -1
    return profile, idx, score, nearest


def run(client: Client, *, limit_hosts: int = 25, days: int = 3) -> dict:
    """Score the bytes/packets series of the busiest local hosts and store the top discord."""
    hosts = [str(r[0]) for r in client.query(
        "SELECT src_addr, count() AS n FROM weirvern.netflow_anomalies "
        "WHERE detected_at >= now() - INTERVAL 7 DAY GROUP BY src_addr "
        "ORDER BY n DESC LIMIT " + str(int(limit_hosts))).result_rows if r and r[0]]
    written = 0
    reports = []
    for host in hosts:
        for metric in ("bytes", "packets"):
            col = "total_bytes" if metric == "bytes" else "total_packets"
            rows = client.query(
                "SELECT window_start, " + col + " FROM weirvern.flows_aggregated "
                "WHERE src_addr = %(h)s AND window_start >= now() - INTERVAL %(d)s DAY "
                "ORDER BY window_start",
                parameters={"h": host, "d": int(days)},
            ).result_rows
            values = [float(r[1] or 0) for r in rows]
            profile, idx, score, nearest = matrix_profile(values)
            if idx < 0 or not profile.size:
                continue
            matched = rows[nearest][0] if nearest >= 0 else rows[idx][0]
            client.insert(
                "weirvern.ml_temporal_scores",
                [[rows[idx][0], host, metric, score, matched, MATRIX_PROFILE_VERSION,
                  len(values), utcnow()]],
                column_names=["window_start", "src_addr", "metric", "discord_score",
                              "matched_window_start", "matrix_profile_version",
                              "series_points", "computed_at"],
            )
            written += 1
            reports.append({"host": host, "metric": metric, "score": round(score, 3),
                            "points": len(values)})
    return {"available": True, "hosts": len(hosts), "rows": written,
            "reports": sorted(reports, key=lambda r: r["score"], reverse=True)[:20],
            "model_version": __version__}


__all__ = ["MATRIX_PROFILE_VERSION", "matrix_profile", "run"]
