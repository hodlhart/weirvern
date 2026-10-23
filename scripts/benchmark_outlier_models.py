#!/usr/bin/env python3
"""Offline structural benchmark: Isolation Forest vs ECOD on the same host-window matrix.

This is not a precision/recall claim: there are no labels for these windows. It measures score
saturation, top-k overlap and runtime at a fixed k, so a later seeded-attack run can decide.
No production table is written.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from sklearn.ensemble import IsolationForest  # noqa: E402
from sklearn.impute import SimpleImputer  # noqa: E402
from sklearn.preprocessing import StandardScaler  # noqa: E402

from weirvern import db  # noqa: E402
from weirvern.config import get_settings  # noqa: E402
from weirvern.models.candidates import FEATURES_SQL  # noqa: E402
from weirvern.models.ecod import ecod_scores  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=5000)
    ap.add_argument("--top-k", type=int, default=100)
    a = ap.parse_args()
    client = db.connect(get_settings())
    rows = client.query(
        "SELECT " + FEATURES_SQL + " FROM weirvern.flows_aggregated a "
        "LEFT JOIN weirvern.flows_aggregated_diversity d "
        "  ON a.window_start = d.window_start AND a.src_addr = d.src_addr "
        "LEFT JOIN weirvern.flows_aggregated_temporal t "
        "  ON a.window_start = t.window_start AND a.src_addr = t.src_addr "
        "WHERE a.window_start >= now() - INTERVAL 72 HOUR AND a.total_bytes > 0 "
        "ORDER BY sipHash64(a.src_addr, a.window_start) LIMIT " + str(int(a.limit))
    ).result_rows
    X = SimpleImputer(strategy="median").fit_transform(np.nan_to_num(np.asarray(rows, float)))
    Xs = StandardScaler().fit_transform(X)
    t0 = time.time()
    iforest = IsolationForest(contamination=0.06, random_state=7).fit(Xs)
    if_scores = -iforest.score_samples(Xs)
    t_if = time.time() - t0
    t0 = time.time()
    ecod = ecod_scores(X)
    t_ecod = time.time() - t0
    k = min(int(a.top_k), len(X))
    if_top = set(np.argsort(if_scores)[-k:])
    ec_top = set(np.argsort(ecod)[-k:])
    report = {
        "rows": len(X), "top_k": k,
        "isolation_forest": {"p50": float(np.percentile(if_scores, 50)),
                             "p99": float(np.percentile(if_scores, 99)),
                             "seconds": round(t_if, 3)},
        "ecod": {"p50": float(np.percentile(ecod, 50)),
                 "p99": float(np.percentile(ecod, 99)),
                 "seconds": round(t_ecod, 3)},
        "top_k_overlap": len(if_top & ec_top),
        "note": "No labels; this is a structural comparison at fixed k, not a precision/recall claim.",
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
