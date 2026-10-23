"""A dependency-free ECOD challenger for offline comparison with Isolation Forest.

ECOD (Li et al.) scores a point by how far into the tail of each empirical feature distribution
it sits. This implementation is deliberately small and explicit: it is a benchmark challenger,
not a production detector, and it has no claim to COPOD's copula model.
"""
from __future__ import annotations

import numpy as np


def ecod_scores(X: np.ndarray) -> np.ndarray:
    """Higher = more extreme. Empirical two-sided tail evidence, summed across features."""
    X = np.asarray(X, dtype=float)
    if X.ndim != 2 or X.shape[0] == 0:
        return np.zeros(0)
    n, _ = X.shape
    out = np.zeros(n)
    for j in range(X.shape[1]):
        col = X[:, j]
        order = np.argsort(col, kind="stable")
        ranks = np.empty(n, dtype=float)
        ranks[order] = np.arange(1, n + 1, dtype=float)
        # Left and right empirical tail probabilities with a continuity correction; the smaller
        # tail is the evidence, so an extreme low and an extreme high score the same.
        left = (ranks) / (n + 1.0)
        right = (n - ranks + 1.0) / (n + 1.0)
        tail = np.minimum(left, right)
        out += -np.log(np.maximum(tail, 1e-12))
    return out


__all__ = ["ecod_scores"]
