"""Shadow candidate detectors: score, record, never alert.

The first candidate is HDBSCAN on the same 8-feature matrix DBSCAN uses. It is NOT a production
model: it writes `ml_candidate_scores` and returns a report. A candidate must beat the live model
at the same alerts/day on the seeded-attack harness before replacing it (see the ML-05 card).
"""
from __future__ import annotations

import numpy as np
from clickhouse_connect.driver.client import Client
from sklearn.cluster import HDBSCAN
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import StandardScaler

from weirvern import __version__
from weirvern.clock import utcnow

# The same 8-feature projection as DBSCANDetector (weirvern/features.py: DBSCAN_FEATURES), minus
# the Zeek tail for this first challenger. Keeping the projection explicit means a feature-list
# change is a deliberate edit here, not a silent reinterpretation.
FEATURES_SQL = (
    "log(a.total_bytes + 1), log(a.total_packets + 1), log(a.unique_dst_ips + 1), "
    "log(a.flow_count + 1), log(coalesce(d.unique_dst_ports, 0) + 1), "
    "coalesce(d.port_entropy, 0), coalesce(t.activity_regularity, 1.0), "
    "coalesce(t.burstiness, 1.0)"
)


def matrix_sql(limit: int) -> str:
    # THE AGGREGATE TABLES ARE FRAGMENTED BY INSERT BLOCK, NOT ONE ROW PER HOST-WINDOW. The first
    # candidate query joined them directly and returned 5,000 rows but only 327 unique
    # (window_start, src_addr) keys: HDBSCAN was clustering duplicate copies of the same window,
    # so its "clusters" and its A/B against DBSCAN measured duplication rather than behaviour.
    # Collapse each side table before joining; additive columns sum, estimates take the largest
    # available block. This mirrors the production sweep's `_collapse_partial_aggregates`, but
    # stays in SQL because this is a bounded shadow sample.
    return (
        "SELECT a.window_start, a.src_addr, " + FEATURES_SQL + " "
        "FROM ("
        "  SELECT window_start, src_addr, sum(total_bytes) AS total_bytes, "
        "         sum(total_packets) AS total_packets, sum(unique_dst_ips) AS unique_dst_ips, "
        "         sum(flow_count) AS flow_count "
        "  FROM weirvern.flows_aggregated "
        "  WHERE window_start >= now() - INTERVAL 72 HOUR "
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
        "WHERE a.total_bytes > 0 "
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
    rows = client.query(matrix_sql(limit)).result_rows
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
    }


__all__ = ["FEATURES_SQL", "matrix_sql", "run"]
