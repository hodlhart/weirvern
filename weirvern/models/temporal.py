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

MATRIX_PROFILE_VERSION = "mp-2"

# The longest series a profile is computed over, after bucket-averaging.
#
# ── THE MEMORY THIS BOUNDS, AND WHY IT IS NOT OPTIONAL ────────────────────────────────────────────
#
# The first version built the pairwise distance with
# `np.linalg.norm(win[:, None, :] - win[None, :, :], axis=2)`, which materialises an n x n x m float64
# array: 96 bytes per window PAIR. The comment assumed a ~864-point series (71 MB) and that was true
# while the NetFlow feed was dark. Measured live 2026-11-12, once the tap was restored: the worker
# OOM-killed at 4 GiB, then at 7 GiB, every ~35 seconds, on this one call -- a host's 3-day
# `flows_aggregated` series is thousands of points, and 8,000 points is ~6 GB of intermediate.
#
# Two independent guards, because the size of the input is not something this module controls:
#   1. the series is bucket-averaged down to MAX_POINTS, so n is bounded no matter how much traffic
#      a host produces;
#   2. the distance is accumulated in row blocks, so peak memory is blocks x n, not n x n x m.
MAX_POINTS = 2048
BLOCK_ROWS = 256


def _bounded(values: np.ndarray, max_points: int = MAX_POINTS) -> np.ndarray:
    """Bucket-average `values` down to at most `max_points`.

    Averaging (not decimation) is what keeps a burst visible: sampling every k-th point can step
    over the very window the profile exists to find. The buckets are CONSECUTIVE runs -- the
    reshape is `(-1, bucket)`, one row per bucket, mean along each row -- so the reduced series
    stays in chronological order, which the timestamp mapping in run() depends on.
    """
    n = len(values)
    if n <= max_points:
        return values
    bucket = int(math.ceil(n / max_points))
    usable = (n // bucket) * bucket
    head = values[:usable].reshape(-1, bucket)
    reduced = head.mean(axis=1)
    tail = values[usable:]
    if tail.size:
        reduced = np.append(reduced, float(tail.mean()))
    return reduced


def _windows(x: np.ndarray, m: int) -> np.ndarray:
    """Sliding windows, each z-normalised (a constant window stays zero)."""
    win = np.lib.stride_tricks.sliding_window_view(x, m).astype(float, copy=True)
    win -= win.mean(axis=1, keepdims=True)
    sd = win.std(axis=1, keepdims=True)
    return np.divide(win, sd, out=np.zeros_like(win), where=sd > 1e-12)


def matrix_profile(values: list[float], m: int = 12, *,
                   max_points: int = MAX_POINTS, block_rows: int = BLOCK_ROWS,
                   ) -> tuple[np.ndarray, int, float, int]:
    """(profile, discord_index, discord_score, nearest_index) for a 1-D series.

    Windows are z-normalised before comparison, so a change in level alone does not dominate the
    shape. Trivial matches within m samples are excluded. Returns an empty profile for a series
    too short to compare.

    Distances come from the dot-product identity ||a-b||^2 = 2m - 2<a,b> on z-normalised windows,
    evaluated a block of rows at a time. That is the same number the broadcast form computed, in a
    bounded amount of memory: the intermediate is `block_rows x n`, never `n x n x m`.
    """
    x = np.asarray(values, dtype=float)
    x = _bounded(x, max_points)
    n = len(x)
    if n < 2 * m + 2:
        return np.empty(0), -1, 0.0, -1

    win = _windows(x, m)
    count = len(win)
    profile = np.full(count, np.inf)
    nearest = np.full(count, -1, dtype=int)

    for start in range(0, count, block_rows):
        stop = min(count, start + block_rows)
        block = win[start:stop]
        # ||a-b||^2 for z-normalised a,b of length m is 2m - 2<a,b>; clamp the rounding noise.
        dist = np.sqrt(np.maximum(0.0, 2.0 * m - 2.0 * (block @ win.T)))
        # EXCLUSION ZONE: a window and its own neighbours are trivial matches, not discoveries.
        for offset, row in enumerate(range(start, stop)):
            lo, hi = max(0, row - m + 1), min(count, row + m)
            dist[offset, lo:hi] = np.inf
        best = dist.argmin(axis=1)
        profile[start:stop] = dist[np.arange(stop - start), best]
        nearest[start:stop] = best

    profile[~np.isfinite(profile)] = 0.0
    idx = int(np.argmax(profile))
    score = float(profile[idx]) if math.isfinite(float(profile[idx])) else 0.0
    return profile, idx, score, int(nearest[idx])


def _source_row(rows: list[tuple], bucket: int, bounded_index: int) -> object:
    """The original row a bounded-series index came from.

    Explicit arguments, not a closure over the loop: a function defined inside the loop and reading
    its variables is the B023 defect ruff flags here, and it is a real one -- every closure would
    see the LAST host's rows.
    """
    return rows[min(max(0, bounded_index * bucket), len(rows) - 1)][0]


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
            # `profile` indexes the BOUNDED series, so both the discord and its nearest neighbour
            # must be mapped back to a row of THIS result before they name a window. With bucket
            # averaging, bounded index j covers original rows [j*buckets, (j+1)*buckets).
            bucket = max(1, int(math.ceil(len(values) / MAX_POINTS)))

            client.insert(
                "weirvern.ml_temporal_scores",
                [[_source_row(rows, bucket, idx), host, metric, score,
                  _source_row(rows, bucket, nearest),
                  MATRIX_PROFILE_VERSION, len(values), utcnow()]],
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


__all__ = ["MATRIX_PROFILE_VERSION", "MAX_POINTS", "matrix_profile", "run"]
