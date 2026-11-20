"""Shadow candidate detectors: score, record, never alert.

The first candidate is HDBSCAN on the same feature vector the cross-sectional pair uses. It is
NOT a production
model: it writes `ml_candidate_scores` and returns a report. A candidate must beat the live model
at the same alerts/day on the seeded-attack harness before replacing it (see the ML-05 card).

THE FEATURE VECTOR IS THE PRODUCTION CROSS-SECTIONAL VECTOR, INCLUDING ZEEK AND DNS. The first version
selected only the eight NetFlow columns; that made the challenger a different model wearing the
same name. It is now `CROSS_SECTIONAL_FEATURES`: eight flow aggregates plus the eleven Zeek columns,
including the DNS triple. The vector order comes from `features.py`, not from a second list here.

THE MATRIX IS SCOPE-FILTERED. `flows_aggregated.src_addr` includes internet peers; only monitored
scopes are alertable. The first live sample had 4,565/5,000 external rows and its top GLOSH results
were external addresses -- a ranking of peers, not of hosts. `run()` therefore applies the same
`networks.training_filter_sql()` used by the production detectors.
"""
from __future__ import annotations

from datetime import timedelta

import numpy as np
from clickhouse_connect.driver.client import Client
from sklearn.cluster import HDBSCAN
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import StandardScaler

from weirvern import __version__, networks
from weirvern.clock import utcnow
from weirvern.features import CROSS_SECTIONAL_FEATURES
from weirvern.zeek_features import (
    ZEEK_CROSS_SECTIONAL_FEATURES,
    ZEEK_JOIN_ON,
    zeek_join_cte,
)

# The eight NetFlow expressions, named by their CROSS_SECTIONAL_FEATURES column. Keeping the mapping
# keyed by the feature name makes a missing column a startup assertion rather than a silent
# positional shift.
_BASE_SQL = {
    "log_bytes": "log(a.total_bytes + 1)",
    "log_packets": "log(a.total_packets + 1)",
    "log_unique_dsts": "log(a.unique_dst_ips + 1)",
    "log_flow_count": "log(a.flow_count + 1)",
    "log_unique_dst_ports": "log(coalesce(d.unique_dst_ports, 0) + 1)",
    "port_entropy": "coalesce(d.port_entropy, 0)",
    "activity_regularity": "coalesce(t.activity_regularity, 1.0)",
    "burstiness": "coalesce(t.burstiness, 1.0)",
}
assert set(CROSS_SECTIONAL_FEATURES[:8]) == set(_BASE_SQL), (
    "CROSS_SECTIONAL_FEATURES base shape changed; update _BASE_SQL and the training query together"
)


def matrix_sql(limit: int, *, scope_filter: str = "", start: str | None = None,
                end: str | None = None) -> str:
    """The 5,000-row candidate matrix, in the production cross-sectional feature order.

    `scope_filter` must be a predicate beginning with AND, as returned by
    `networks.training_filter_sql`; empty means legacy/no declarations. `start`/`end` bound the
    Zeek summary CTE; the flow side uses the same window.
    """
    if end is None:
        end = utcnow().strftime("%Y-%m-%d %H:%M:%S")
    if start is None:
        start = (utcnow() - timedelta(hours=72)).strftime("%Y-%m-%d %H:%M:%S")
    selects = [_BASE_SQL[name] for name in CROSS_SECTIONAL_FEATURES[:8]]
    selects += [f"z.{name}" for name in ZEEK_CROSS_SECTIONAL_FEATURES]
    # The aggregate side tables are fragmented by insert block, not one row per host-window.
    # Collapse each side table before joining; additive columns sum, estimates take the largest
    # available block. This mirrors the production sweep's `_collapse_partial_aggregates`.
    return (
        "WITH " + zeek_join_cte(start, end) + " "
        "SELECT a.window_start, a.src_addr, " + ", ".join(selects) + " "
        "FROM ("
        # MERGE COMBINATORS, NOT sum(). `flows_window` is an AggregatingMergeTree and those four
        # columns are AggregateFunction STATES (`sum(sum, UInt64)`, `count(count, UInt8)`,
        # `uniq(uniq, String)`), so `sum(total_bytes)` is illegal on them: ClickHouse answers
        # "Code: 43. DB::Exception: Illegal type AggregateFunction(sum, UInt64) of argument for
        # aggregate function sum", which the shadow pass catches and logs as a warning, so the
        # candidate list silently stops existing while everything else keeps running. Measured live
        # on the 2026-11-16 roll: "ML shadow pass failed (detection continues): ... Code: 43".
        #
        # sumMerge/countMerge fold the states across insert blocks, which is what the columns are
        # for; uniqMerge unions the HLL sketches, so the destination count is the true cardinality
        # across blocks rather than a sum of per-block estimates.
        "  SELECT window_start, src_addr, sumMerge(total_bytes) AS total_bytes, "
        "         sumMerge(total_packets) AS total_packets, "
        "         uniqMerge(unique_dst_ips) AS unique_dst_ips, "
        "         countMerge(flow_count) AS flow_count "
        "  FROM weirvern.flows_window "
        "  WHERE window_start >= '" + start + "' AND window_start <= '" + end + "' "
        "  GROUP BY window_start, src_addr"
        ") a "
        "LEFT JOIN ("
        "  SELECT window_start, src_addr, sum(unique_dst_ports) AS unique_dst_ports, "
        "         max(port_entropy) AS port_entropy "
        "  FROM weirvern.flows_aggregated_diversity "
        "  GROUP BY window_start, src_addr"
        ") d ON a.window_start = d.window_start AND a.src_addr = d.src_addr "
        "LEFT JOIN ("
        "  SELECT window_start, src_addr, max(activity_regularity) AS activity_regularity, "
        "         max(burstiness) AS burstiness "
        "  FROM weirvern.flows_aggregated_temporal "
        "  GROUP BY window_start, src_addr"
        ") t ON a.window_start = t.window_start AND a.src_addr = t.src_addr "
        + ZEEK_JOIN_ON + " "
        "WHERE a.total_bytes > 0 " + scope_filter + " "
        "ORDER BY sipHash64(a.src_addr, a.window_start) LIMIT " + str(int(limit))
    )


def _fit(X: np.ndarray, min_cluster_size: int = 40) -> tuple[HDBSCAN, np.ndarray, np.ndarray]:
    prep = StandardScaler()
    Xs = prep.fit_transform(SimpleImputer(strategy="median").fit_transform(np.nan_to_num(X)))
    model = HDBSCAN(min_cluster_size=int(min_cluster_size), min_samples=5,
                    store_centers="medoid", copy=True).fit(Xs)
    # sklearn stores medoid centres on `.medoids_`, NOT `.centers_` (which is only populated for
    # store_centers="centroid"). The first live run clustered 56 groups and still reported zero
    # centres because of this; the candidate was silently unusable. Read the attribute the
    # requested mode actually populates.
    if getattr(model, "medoids_", None) is not None:
        centers = np.asarray(model.medoids_, dtype=float)
    else:
        centers = np.asarray(getattr(model, "centers_", np.empty((0, Xs.shape[1]))), dtype=float)
    return model, Xs, centers


def _scores(Xs: np.ndarray, centers: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    if centers.size == 0:
        return np.zeros(len(Xs)), np.full(len(Xs), -1.0)
    dist = np.min(np.linalg.norm(Xs[:, None, :] - centers[None, :, :], axis=2), axis=1)
    # A percentile rank is monotone and bounded; it is a candidate ranking, not a probability.
    order = np.argsort(np.argsort(dist))
    score = order / max(len(dist) - 1, 1)
    return score, dist


def run(client: Client, *, limit: int = 5000, min_cluster_size: int = 40) -> dict:
    scopes = networks.load_scopes(client)
    if scopes and not any(networks.is_monitored(s) for s in scopes):
        return {"available": False, "reason": "no monitored scope; candidate cannot rank peers",
                "rows": 0, "clusters": 0}
    scope_filter = networks.training_filter_sql(scopes)
    rows = client.query(matrix_sql(limit, scope_filter=scope_filter)).result_rows
    if len(rows) < 100:
        return {"available": False, "reason": f"only {len(rows)} candidate rows; need 100",
                "rows": 0, "clusters": 0}
    labels = [row[0] for row in rows]
    hosts = [str(row[1]) for row in rows]
    X = np.asarray([r[2:] for r in rows], dtype=float)
    used_min = int(min_cluster_size)
    model, Xs, centers = _fit(X, min_cluster_size=used_min)
    # A high min_cluster_size can produce zero centres on a heterogeneous live matrix. Try two
    # smaller settings before declaring the candidate unusable; the chosen value is reported.
    for fallback in (20, 5):
        if centers.size:
            break
        if fallback >= used_min:
            continue
        used_min = fallback
        model, Xs, centers = _fit(X, min_cluster_size=fallback)
    score, dist = _scores(Xs, centers)
    n_clusters = len(set(model.labels_)) - (1 if -1 in model.labels_ else 0)
    if not centers.size:
        return {"available": True, "reason": "no cluster centres; candidate cannot score",
                "rows": len(rows), "clusters": 0, "noise": int((model.labels_ == -1).sum())}
    out = []
    for i, (when, host) in enumerate(zip(labels, hosts, strict=True)):
        out.append([
            when, host, "HDBSCAN", float(score[i]), 1,
            (f"cluster={int(model.labels_[i])}; probability={float(model.probabilities_[i]):.3f}; "
             f"distance={float(dist[i]):.3f}"),
            __version__, utcnow(),
        ])
    client.insert(
        "weirvern.ml_candidate_scores", out,
        column_names=["window_start", "src_addr", "model_name", "score", "rank",
                      "evidence", "model_version", "computed_at"],
    )
    return {
        "available": True, "reason": "", "rows": len(rows), "clusters": n_clusters,
        "noise": int((model.labels_ == -1).sum()),
        "min_cluster_size": int(used_min),
        "score_p50": float(np.percentile(score, 50)),
        "score_p99": float(np.percentile(score, 99)),
        "model_version": __version__,
        "feature_columns": len(CROSS_SECTIONAL_FEATURES),
        "scope_filtered": bool(scope_filter),
    }


__all__ = ["CROSS_SECTIONAL_FEATURES", "ZEEK_CROSS_SECTIONAL_FEATURES", "matrix_sql", "run"]
