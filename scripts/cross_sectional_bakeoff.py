#!/usr/bin/env python3
"""Offline bake-off of cross-sectional host-window anomaly candidates.

WHY THIS EXISTS. The density detector the ensemble used to carry produced near-binary membership
and was removed on 2026-11-20 (97.89% of 27,454 stored scores at 0.99 or above; p50 = p99 = max).
Its replacement had to answer a CROSS-SECTIONAL question -- "does this host-window look unlike the
population of host-windows?" -- and produce a score fine-grained enough to conformalise at a 0.01
target.

This script compares the candidates on the SAME 19-feature vector (``CROSS_SECTIONAL_FEATURES``)
and the SAME walk-forward split:

    kNN distance (k=10), LOF (k=20, novelty), Gaussian Mixture (diagonal, BIC),
    EllipticEnvelope (Mahalanobis), Isolation Forest on the 19 features (control).

The removed detector's measured row is kept in the published report
(`docs/research/cross-sectional-detector-2026-11-20.md`), not in this harness: it is no longer a
candidate, and re-running a deleted model would be a second implementation of it.

PROTOCOL. Fit on normal host-windows only (the same high/critical exclusion the training
queries use), calibrate a conformal threshold on a held-out slice of that same reference, then
measure the realised false-alarm rate on the NEXT day, which no candidate has seen. Both the
calibrated threshold and the naive in-sample threshold are reported, because "0.01 in-sample,
0.4 out-of-sample" is the failure mode this harness exists to expose.

No production table is written and no detector is changed. ``extract`` reads ClickHouse through
the same ssh + kubectl hop as ``scripts/chq.py``; ``run`` is pure and offline.

USAGE
    export WEIRVERN_SENSOR_HOST=root@sensor
    ./scripts/cross_sectional_bakeoff.py extract --start 2026-11-12 --end 2026-11-20 \\
        --scope 203.0.113.0/24 --scope 198.51.100.0/24 --out /tmp/bakeoff.tsv.gz
    ./scripts/cross_sectional_bakeoff.py run --data /tmp/bakeoff.tsv.gz --out /tmp/bakeoff.json
"""
from __future__ import annotations

import argparse
import csv
import gzip
import json
import math
import os
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import numpy as np

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from sklearn.covariance import EllipticEnvelope  # noqa: E402
from sklearn.ensemble import IsolationForest  # noqa: E402
from sklearn.mixture import GaussianMixture  # noqa: E402
from sklearn.neighbors import LocalOutlierFactor, NearestNeighbors  # noqa: E402
from sklearn.preprocessing import RobustScaler  # noqa: E402

from weirvern.features import CROSS_SECTIONAL_FEATURES  # noqa: E402
from weirvern.models.calibration import conformal_threshold  # noqa: E402
from weirvern.models.candidates import _BASE_SQL  # noqa: E402
from weirvern.models.missing import (  # noqa: E402
    column_neutrals,
    null_absent_zeek,
)
from weirvern.zeek_features import ZEEK_CROSS_SECTIONAL_FEATURES, ZEEK_JOIN_ON, zeek_join_cte  # noqa: E402

SENSOR_VAR = "WEIRVERN_SENSOR_HOST"
NAMESPACE = os.environ.get("WEIRVERN_NAMESPACE", "weirvern")
TARGET_FAR = 0.01
PROD_MODELS = ("Isolation Forest", "Gradient Boosting", "Adaptive Baseline")
META_COLUMNS = ("window_start", "src_addr", *CROSS_SECTIONAL_FEATURES, "flagged",
                *(f"prod_{m.split()[0].lower()}" for m in PROD_MODELS))


# ── folds ────────────────────────────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class Fold:
    """One walk-forward step: a 72 h normal reference, then the next 24 h never seen."""

    name: str
    train_start: str
    train_end: str
    test_start: str
    test_end: str


# 72 h is RETRAIN_WINDOW_H as deployed; the test day is the 24 h that follows it. The data
# retained on the box spans 2026-11-12 13:50 -> 2026-11-19 21:05, so a literal week-on-week
# split is not expressible; these four folds are the longest walk-forward the retention allows.
FOLDS: tuple[Fold, ...] = (
    Fold("F1", "2026-11-13 00:00:00", "2026-11-16 00:00:00", "2026-11-16 00:00:00", "2026-11-17 00:00:00"),
    Fold("F2", "2026-11-14 00:00:00", "2026-11-17 00:00:00", "2026-11-17 00:00:00", "2026-11-18 00:00:00"),
    Fold("F3", "2026-11-15 00:00:00", "2026-11-18 00:00:00", "2026-11-18 00:00:00", "2026-11-19 00:00:00"),
    Fold("F4", "2026-11-16 00:00:00", "2026-11-19 00:00:00", "2026-11-19 00:00:00", "2026-11-20 00:00:00"),
)


# ── extraction ──────────────────────────────────────────────────────────────────────────────
def matrix_sql(start: str, end: str, scopes: list[str]) -> str:
    """The 19-feature matrix for [start, end), in the production cross-sectional order.

    Rebuilt from the repository's own constants -- ``_BASE_SQL`` (which asserts it matches
    ``CROSS_SECTIONAL_FEATURES[:8]``), ``ZEEK_CROSS_SECTIONAL_FEATURES`` and ``zeek_join_cte`` -- so this cannot
    drift into a different feature set than the detector it is evaluating.

    The ``flagged`` column is the same predicate ``_flagged_exclusion_clause`` splices into
    every training query (high/critical netflow_anomalies for the same host and 5-minute
    bucket), carried as a marker instead of a filter so the caller can train without it and
    still measure a clean-held-out FAR.
    """
    selects = [_BASE_SQL[name] for name in CROSS_SECTIONAL_FEATURES[:8]]
    selects += [f"z.{name}" for name in ZEEK_CROSS_SECTIONAL_FEATURES]
    terms = " OR ".join(f"isIPAddressInRange(a.src_addr, '{cidr}')" for cidr in scopes)
    prod_inner = ", ".join(
        f"maxIf(score, model_name = '{m}') AS prod_{m.split()[0].lower()}" for m in PROD_MODELS
    )
    prod_outer = ", ".join(f"s.prod_{m.split()[0].lower()}" for m in PROD_MODELS)
    return (
        "WITH " + zeek_join_cte(start, end) + " "
        "SELECT a.window_start, a.src_addr, " + ", ".join(selects) + ", "
        "       if(f.src_addr != '', 1, 0) AS flagged, " + prod_outer + " "
        "FROM ("
        "  SELECT window_start, src_addr, sumMerge(total_bytes) AS total_bytes,"
        "         sumMerge(total_packets) AS total_packets,"
        "         uniqMerge(unique_dst_ips) AS unique_dst_ips,"
        "         countMerge(flow_count) AS flow_count"
        "  FROM weirvern.flows_window"
        f"  WHERE window_start >= '{start}' AND window_start < '{end}'"
        "  GROUP BY window_start, src_addr"
        ") a "
        "LEFT JOIN ("
        "  SELECT window_start, src_addr, sum(unique_dst_ports) AS unique_dst_ports,"
        "         max(port_entropy) AS port_entropy"
        "  FROM weirvern.flows_aggregated_diversity GROUP BY window_start, src_addr"
        ") d ON a.window_start = d.window_start AND a.src_addr = d.src_addr "
        "LEFT JOIN ("
        "  SELECT window_start, src_addr, max(activity_regularity) AS activity_regularity,"
        "         max(burstiness) AS burstiness"
        "  FROM weirvern.flows_aggregated_temporal GROUP BY window_start, src_addr"
        ") t ON a.window_start = t.window_start AND a.src_addr = t.src_addr "
        + ZEEK_JOIN_ON + " "
        "LEFT JOIN ("
        "  SELECT src_addr, toStartOfFiveMinutes(window_start) AS ws"
        "  FROM weirvern.netflow_anomalies"
        f"  WHERE window_start >= '{start}' AND window_start < '{end}'"
        "    AND severity IN ('high','critical')"
        "  GROUP BY src_addr, ws"
        ") f ON f.src_addr = a.src_addr AND f.ws = a.window_start "
        "LEFT JOIN ("
        "  SELECT window_start, src_addr, " + prod_inner + " "
        "  FROM weirvern.ml_window_scores FINAL"
        f"  WHERE window_start >= '{start}' AND window_start < '{end}'"
        "  GROUP BY window_start, src_addr"
        ") s ON s.window_start = a.window_start AND s.src_addr = a.src_addr "
        f"WHERE a.window_start >= '{start}' AND a.window_start < '{end}'"
        f"  AND a.total_bytes > 0 AND ({terms}) "
        "ORDER BY a.window_start, a.src_addr"
    )


def run_sql(sql: str, timeout: int = 900) -> str:
    """Run one query through ssh -> kubectl -> clickhouse-client, query on stdin.

    The query travels on stdin rather than as an argument: these statements are multi-kilobyte
    f-strings, and every attempt to quote one into a remote argv has cost an afternoon.
    """
    host = os.environ.get(SENSOR_VAR)
    if not host:
        sys.exit(
            f"{SENSOR_VAR} is not set. There is no default host on purpose (see scripts/chq.py).\n"
            "  export WEIRVERN_SENSOR_HOST=root@<sensor>"
        )
    remote = (f"kubectl -n {NAMESPACE} exec -i clickhouse-0 -- "
              "clickhouse-client --format TSV")
    proc = subprocess.run(
        ["ssh", "-o", "BatchMode=yes", host, remote],
        input=sql.encode(), capture_output=True, timeout=timeout, check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.decode(errors="replace")[-2000:])
    return proc.stdout.decode()


def cmd_extract(args: argparse.Namespace) -> int:
    sql = matrix_sql(args.start, args.end, args.scope)
    if args.sql_out:
        Path(args.sql_out).write_text(sql + "\n")
    body = run_sql(sql + "\n")
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(out, "wt", newline="") as fh:
        fh.write("\t".join(META_COLUMNS) + "\n")
        fh.write(body)
    rows = sum(1 for _ in body.splitlines())
    print(json.dumps({"out": str(out), "rows": rows, "features": len(CROSS_SECTIONAL_FEATURES),
                      "start": args.start, "end": args.end, "scopes": args.scope}, indent=2))
    return 0


# ── data ────────────────────────────────────────────────────────────────────────────────────
@dataclass
class Dataset:
    t: np.ndarray            # datetime64[m], window start
    host: np.ndarray         # object array of src_addr
    X: np.ndarray            # (n, 19) float, NaN where the source was absent
    flagged: np.ndarray      # bool, high/critical netflow_anomalies for the same bucket
    prod: dict[str, np.ndarray] = field(default_factory=dict)

    def between(self, start: str, end: str) -> Dataset:
        lo, hi = np.datetime64(start), np.datetime64(end)
        m = (self.t >= lo) & (self.t < hi)
        return Dataset(
            t=self.t[m], host=self.host[m], X=self.X[m], flagged=self.flagged[m],
            prod={k: v[m] for k, v in self.prod.items()},
        )

    def take(self, idx: np.ndarray) -> Dataset:
        return Dataset(t=self.t[idx], host=self.host[idx], X=self.X[idx],
                       flagged=self.flagged[idx],
                       prod={k: v[idx] for k, v in self.prod.items()})

    def __len__(self) -> int:
        return int(self.X.shape[0])

    def coverage(self) -> np.ndarray:
        """Share of the 19 columns actually measured, per row (production's definition)."""
        return np.isfinite(self.X).mean(axis=1)


def load_dataset(path: str) -> Dataset:
    with gzip.open(path, "rt", newline="") as fh:
        reader = csv.reader(fh, delimiter="\t")
        header = next(reader)
        rows = [r for r in reader if r]
    index = {name: i for i, name in enumerate(header)}
    missing = [c for c in META_COLUMNS if c not in index]
    if missing:
        raise SystemExit(f"{path} is missing column(s) {missing}; re-run `extract`")
    raw = np.asarray([[float(r[index[c]]) for c in CROSS_SECTIONAL_FEATURES] for r in rows], dtype=float)
    # The training queries coalesce absent sources to 0; recover "we never read this" as NaN,
    # exactly as the shipped cross-sectional detectors train when ML_MISSING_FEATURES is on.
    X = null_absent_zeek(raw, CROSS_SECTIONAL_FEATURES)
    prod: dict[str, np.ndarray] = {}
    for model in PROD_MODELS:
        key = f"prod_{model.split()[0].lower()}"
        prod[model] = np.asarray([float(r[index[key]]) if r[index[key]] != "" else float("nan")
                                  for r in rows], dtype=float)
    return Dataset(
        t=np.asarray([np.datetime64(r[index["window_start"]]) for r in rows], dtype="datetime64[m]"),
        host=np.asarray([r[index["src_addr"]] for r in rows], dtype=object),
        X=X,
        flagged=np.asarray([r[index["flagged"]] == "1" for r in rows], dtype=bool),
        prod=prod,
    )


def stable_order(host: np.ndarray, t: np.ndarray) -> np.ndarray:
    """A deterministic, uniformly-spread order over (host, window).

    Production cuts its sample with ``ORDER BY sipHash64(src_addr, window_start) LIMIT n``.
    This is the same shape without reaching into ClickHouse's hash: a stable digest of the
    same key, so the cut is identical on every run.
    """
    import hashlib  # noqa: PLC0415 - only needed here

    keys = [hashlib.blake2b(f"{h}|{w}".encode(), digest_size=8).digest() for h, w in zip(host, t, strict=True)]
    return np.argsort(np.frombuffer(b"".join(keys), dtype=">u8"))


def split_fit_calibration(order: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    """Every third row (in stable order) is the calibration slice; the rest is the fit set.

    Calibration must not be scored by a model that was fitted on it: that is the difference
    between a threshold that means 0.01 and one that means "0.01 on data the model memorised".
    """
    cal = order[::3]
    fit = np.setdiff1d(order, cal, assume_unique=False)
    return fit, cal


# ── candidates ──────────────────────────────────────────────────────────────────────────────
class StandardPrep:
    """Median impute (training-time neutral) + standardise, the production default.

    `indicators=True` appends one unscaled 0/1 column per feature saying "this value was not
    measured", which is `MissingAwarePreprocessor`'s rule applied to a model that is not the
    masked-distance one. Without it, a row with 11 absent Zeek columns sits at the median on
    those axes and reads as the most normal point in the space -- measured in this bake-off as
    an alert rate of ~0 on partially observed windows while they are 24-50% of the population.
    """

    def __init__(self, *, robust: bool = False, indicators: bool = False) -> None:
        self.robust = robust
        self.indicators = indicators
        self.neutral: np.ndarray | None = None
        self.scaler: Any = None

    def fit(self, X: np.ndarray) -> StandardPrep:
        self.neutral = column_neutrals(X) if self.neutral is None else self.neutral
        filled = np.where(np.isfinite(X), X, self.neutral)
        self.scaler = RobustScaler() if self.robust else None
        if self.scaler is None:
            from sklearn.preprocessing import StandardScaler  # noqa: PLC0415

            self.scaler = StandardScaler()
        self.scaler.fit(filled)
        return self

    def transform(self, X: np.ndarray) -> np.ndarray:
        if self.neutral is None or self.scaler is None:
            raise RuntimeError("preprocessor not fitted")
        missing = ~np.isfinite(X)
        filled = np.where(missing, self.neutral, X)
        scaled = np.asarray(self.scaler.transform(filled), dtype=float)
        if not self.indicators:
            return scaled
        return np.hstack([scaled, missing.astype(float)])


class Candidate:
    """One detector candidate: fit on a reference matrix, score rows (higher = odder)."""

    name = "candidate"
    missing_policy = ""

    def fit(self, X: np.ndarray) -> Candidate:
        raise NotImplementedError

    def score(self, X: np.ndarray) -> np.ndarray:
        raise NotImplementedError


class KnnDistance(Candidate):
    name = "kNN-10"
    missing_policy = ("median (training neutral) + missing indicator column, standard scaling; "
                      "absence moves a row to the population centre, i.e. reads as NORMAL")

    def __init__(self, k: int = 10, *, robust: bool = False, mask_missing: bool = False,
                 indicators: bool = False) -> None:
        self.k = k
        self.robust = robust
        self.mask_missing = mask_missing
        self.prep = StandardPrep(robust=robust, indicators=indicators)
        self.nn: NearestNeighbors | None = None
        self.Xfit: np.ndarray | None = None

    def fit(self, X: np.ndarray) -> KnnDistance:
        self.prep.fit(X)
        Xs = self.prep.transform(X)
        self.Xfit = Xs
        self.nn = NearestNeighbors(n_neighbors=self.k).fit(Xs)
        return self

    def score(self, X: np.ndarray) -> np.ndarray:
        Xs = self.prep.transform(X)
        if not self.mask_missing:
            dist, _ = self.nn.kneighbors(Xs, n_neighbors=self.k)
            return np.asarray(dist[:, -1], dtype=float)
        if self.Xfit is None:
            raise RuntimeError("not fitted")
        out = np.empty(len(Xs), dtype=float)
        for i, row in enumerate(Xs):
            observed = np.isfinite(X[i])
            d = np.linalg.norm(self.Xfit[:, observed] - row[observed], axis=1)
            kth = np.partition(d, self.k - 1)[self.k - 1]
            out[i] = float(kth) * math.sqrt(X.shape[1] / max(int(observed.sum()), 1))
        return out


class Lof(Candidate):
    name = "LOF-20"
    missing_policy = ("median (training neutral) + standard scaling; LOF's local density is "
                      "then computed in a space where absent columns sit at the median")

    def __init__(self, k: int = 20, *, dedup: bool = False, indicators: bool = False) -> None:
        self.k = k
        # WHY DEDUP EXISTS. sklearn's LOF divides by a local reachability density that is
        # infinite when a point's k-neighbourhood is a set of exact duplicates (reachability
        # 0 -> lrd inf), so a point NEXT to such a cluster scores inf. This dataset contains
        # thousands of identical quiet host-windows, and in one fold that pushed the 99th
        # percentile of the calibration scores to 8.5e8 -- a threshold above every score the
        # detector can produce, i.e. a detector that is silently off. Collapsing exact
        # duplicates in the REFERENCE removes the zero-distance neighbourhoods without
        # changing what the detector asks.
        self.dedup = dedup
        self.prep = StandardPrep(indicators=indicators)
        self.model: LocalOutlierFactor | None = None

    def fit(self, X: np.ndarray) -> Lof:
        self.prep.fit(X)
        Xs = self.prep.transform(X)
        if self.dedup:
            Xs = np.unique(Xs, axis=0)
        self.model = LocalOutlierFactor(n_neighbors=self.k, novelty=True).fit(Xs)
        return self

    def score(self, X: np.ndarray) -> np.ndarray:
        if self.model is None:
            raise RuntimeError("not fitted")
        # With novelty=True, score_samples is the OPPOSITE of the LOF: negate so higher = odder.
        return np.asarray(-self.model.score_samples(self.prep.transform(X)), dtype=float)


class Gmm(Candidate):
    name = "GMM-BIC"
    missing_policy = ("median (training neutral) + standard scaling; an imputed row is scored "
                      "under the fitted density like any other point")

    def __init__(self, max_components: int = 12, *, indicators: bool = False) -> None:
        self.max_components = max_components
        self.prep = StandardPrep(indicators=indicators)
        self.model: GaussianMixture | None = None
        self.bic: dict[int, float] = {}

    def fit(self, X: np.ndarray) -> Gmm:
        self.prep.fit(X)
        Xs = self.prep.transform(X)
        best = None
        for k in range(1, min(self.max_components, max(1, len(Xs) // 100)) + 1):
            gm = GaussianMixture(n_components=k, covariance_type="diag",
                                 random_state=42, reg_covar=1e-6, n_init=2).fit(Xs)
            self.bic[k] = float(gm.bic(Xs))
            if best is None or self.bic[k] < best[0]:
                best = (self.bic[k], gm)
        if best is None:
            raise RuntimeError("no GMM component count fitted")
        self.model = best[1]
        return self

    def score(self, X: np.ndarray) -> np.ndarray:
        if self.model is None:
            raise RuntimeError("not fitted")
        return np.asarray(-self.model.score_samples(self.prep.transform(X)), dtype=float)


class Envelope(Candidate):
    name = "EllipticEnvelope"
    missing_policy = ("median (training neutral) + standard scaling before the robust "
                      "covariance fit; Mahalanobis distance over all 19 dimensions")

    def __init__(self, *, indicators: bool = False) -> None:
        self.prep = StandardPrep(indicators=indicators)
        self.model: EllipticEnvelope | None = None

    def fit(self, X: np.ndarray) -> Envelope:
        self.prep.fit(X)
        self.model = EllipticEnvelope(contamination=0.06, support_fraction=0.75,
                                      random_state=42).fit(self.prep.transform(X))
        return self

    def score(self, X: np.ndarray) -> np.ndarray:
        if self.model is None:
            raise RuntimeError("not fitted")
        return np.asarray(self.model.mahalanobis(self.prep.transform(X)), dtype=float)


class Forest19(Candidate):
    name = "IForest-19"
    missing_policy = ("median (training neutral) + standard scaling; the control that isolates "
                      "the FEATURE SET from the METHOD")

    def __init__(self, *, indicators: bool = False) -> None:
        self.prep = StandardPrep(indicators=indicators)
        self.model: IsolationForest | None = None

    def fit(self, X: np.ndarray) -> Forest19:
        self.prep.fit(X)
        self.model = IsolationForest(contamination=0.06, random_state=42).fit(self.prep.transform(X))
        return self

    def score(self, X: np.ndarray) -> np.ndarray:
        if self.model is None:
            raise RuntimeError("not fitted")
        return np.asarray(-self.model.score_samples(self.prep.transform(X)), dtype=float)


def candidate_factories() -> dict[str, Any]:
    """The six required candidates, plus the sensitivity variants reported in the appendix."""
    return {
        "kNN-10": KnnDistance,
        "LOF-20": Lof,
        "GMM-BIC": Gmm,
        "EllipticEnvelope": Envelope,
        "IForest-19": Forest19,
        "kNN-10-robust": lambda: KnnDistance(robust=True),
        "kNN-10-masked": lambda: KnnDistance(mask_missing=True),
        "LOF-20-dedup": lambda: Lof(dedup=True),
        "kNN-10+ind": lambda: KnnDistance(indicators=True),
        "LOF-20-dedup+ind": lambda: Lof(dedup=True, indicators=True),
        "EllipticEnvelope+ind": lambda: Envelope(indicators=True),
    }


# ── measurement ─────────────────────────────────────────────────────────────────────────────
def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """Wilson interval for a proportion -- 0/0 is (0, 0), never a silent 0.0 claim."""
    if n <= 0:
        return (0.0, 0.0)
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def spearman(a: np.ndarray, b: np.ndarray) -> tuple[float, int]:
    """Rank correlation with pairwise-complete rows; NaN when there is nothing to correlate."""
    from scipy.stats import spearmanr  # noqa: PLC0415

    m = np.isfinite(a) & np.isfinite(b)
    if int(m.sum()) < 10:
        return (float("nan"), int(m.sum()))
    rho, _ = spearmanr(a[m], b[m])
    return (float(rho), int(m.sum()))


def distinct_stats(scores: np.ndarray, host: np.ndarray) -> dict[str, Any]:
    """Is the score degenerate? Overall and per-host distinct-value counts, modal share."""
    values, counts = np.unique(scores, return_counts=True)
    per_host = []
    for h in np.unique(host):
        s = scores[host == h]
        per_host.append(int(np.unique(s).size))
    return {
        "distinct": int(values.size),
        "rows": int(scores.size),
        "distinct_ratio": float(values.size / max(scores.size, 1)),
        "modal_share": float(counts.max() / max(scores.size, 1)),
        "per_host_median": float(np.median(per_host)) if per_host else 0.0,
        "per_host_min": int(min(per_host)) if per_host else 0,
        "per_host_max": int(max(per_host)) if per_host else 0,
        "std": float(np.std(scores)),
    }


def coverage_stats(scores: np.ndarray, X: np.ndarray) -> dict[str, Any]:
    """Does a missing column look like an anomaly? Score vs measured-coverage, per candidate."""
    cov = np.isfinite(X).mean(axis=1)
    rho, n = spearman(scores, cov)
    full = cov >= 1.0
    out: dict[str, Any] = {
        "spearman_score_vs_coverage": rho, "n": n,
        "coverage_mean": float(cov.mean()),
        "coverage_p05": float(np.percentile(cov, 5)),
        "rows_full_coverage": int(full.sum()),
    }
    if full.any() and (~full).any():
        out["score_p50_full"] = float(np.median(scores[full]))
        out["score_p50_partial"] = float(np.median(scores[~full]))
    return out


def per_host_report(scores: np.ndarray, host: np.ndarray, threshold: float) -> dict[str, Any]:
    """Which hosts the alert budget lands on -- one host owning every alert is a defect."""
    flagged = scores >= threshold
    hosts = np.unique(host)
    per_host = []
    for h in hosts:
        m = host == h
        per_host.append({"host": str(h), "windows": int(m.sum()),
                         "alerts": int(flagged[m].sum()),
                         "far": float(flagged[m].mean())})
    total = int(flagged.sum())
    worst = max((r["alerts"] for r in per_host), default=0)
    return {
        "hosts": len(hosts),
        "windows_per_host_min": int(min(r["windows"] for r in per_host)) if per_host else 0,
        "windows_per_host_median": float(np.median([r["windows"] for r in per_host])) if per_host else 0.0,
        "max_alerts_from_one_host": int(worst),
        "max_alert_share": float(worst / total) if total else 0.0,
        "hosts_with_alerts": int(sum(1 for r in per_host if r["alerts"] > 0)),
        "per_host": per_host,
    }


def alert_persistence(scores: np.ndarray, host: np.ndarray, t: np.ndarray,
                      threshold: float) -> dict[str, Any]:
    """Does an alert predict the SAME host alerting in the next 5-minute window?

    A label-free structure test. If alerts were i.i.d. noise the conditional probability would
    equal the false-alarm rate; a score that tracks a sustained state (a host that is genuinely
    odd for minutes or hours) shows a much higher one. It cannot prove a detection is real --
    one permanently anomalous host also scores high -- so it is read next to the host spread.
    """
    alerted = scores >= threshold
    order = np.lexsort((t, host))
    h, tt, aa = host[order], t[order], alerted[order]
    prev_alert, next_alert = 0, 0
    runs = 0
    run_len = 0
    for i in range(1, len(h)):
        consecutive = h[i] == h[i - 1] and (tt[i] - tt[i - 1]) == np.timedelta64(5, "m")
        if not consecutive:
            if run_len >= 2:
                runs += run_len
            run_len = 0
            continue
        if aa[i - 1]:
            prev_alert += 1
            if aa[i]:
                next_alert += 1
        run_len = run_len + 1 if aa[i] else 0
    if run_len >= 2:
        runs += run_len
    total_alerts = int(alerted.sum())
    far = total_alerts / max(len(alerted), 1)
    return {
        "p_alert_next_given_alert": float(next_alert / prev_alert) if prev_alert else float("nan"),
        "chance": float(far),
        "lift": float((next_alert / prev_alert) / far) if prev_alert and far else float("nan"),
        "alert_run_share": float(runs / total_alerts) if total_alerts else 0.0,
    }


def evaluate_candidate(cand: Candidate, fit: Dataset, cal: Dataset, test: Dataset) -> dict[str, Any]:
    """Fit, calibrate, score, and measure one candidate on one fold."""
    t0 = time.perf_counter()
    cand.fit(fit.X)
    fit_seconds = time.perf_counter() - t0

    t0 = time.perf_counter()
    s_fit = cand.score(fit.X)
    score_seconds = time.perf_counter() - t0
    s_cal = cand.score(cal.X)
    t0 = time.perf_counter()
    s_test = cand.score(test.X)
    test_seconds = time.perf_counter() - t0

    thr = conformal_threshold(s_cal, TARGET_FAR)
    thr_naive = conformal_threshold(s_fit, TARGET_FAR)
    far_cal = float((s_cal >= thr).mean()) if s_cal.size else float("nan")
    far_fit = float((s_fit >= thr).mean()) if s_fit.size else float("nan")
    alerts = int((s_test >= thr).sum())
    alerts_naive = int((s_test >= thr_naive).sum())
    lo, hi = wilson(alerts, len(s_test))
    clean = ~test.flagged
    alerts_clean = int((s_test[clean] >= thr).sum())
    coverage = np.isfinite(test.X).mean(axis=1)
    partial = coverage < 1.0
    partial_alert_share = (float((s_test[partial] >= thr).mean()) if partial.any() else 0.0)
    out: dict[str, Any] = {
        "candidate": cand.name,
        "missing_policy": cand.missing_policy,
        "fit_seconds": round(fit_seconds, 3),
        "score_seconds": round(score_seconds, 3),
        "test_seconds": round(test_seconds, 3),
        "us_per_window": round(1e6 * test_seconds / max(len(s_test), 1), 3),
        "n_fit": len(fit), "n_cal": len(cal), "n_test": len(s_test),
        "threshold": float(thr), "threshold_naive": float(thr_naive),
        # Saturation, the shape Calibration.saturated names: a threshold at or above every
        # reference score cannot be exceeded by anything, so the detector is silently off.
        "threshold_ceiling": float(np.max(s_cal)) if s_cal.size else float("nan"),
        "threshold_saturated": bool(np.isfinite(thr) and thr >= float(np.max(s_cal))),
        "far_train_calibrated": far_cal,
        "far_train_in_sample": far_fit,
        "far_test": alerts / max(len(s_test), 1),
        "far_test_wilson": [lo, hi],
        "alerts": alerts,
        "far_test_clean": alerts_clean / max(int(clean.sum()), 1),
        "alerts_clean": alerts_clean,
        "far_test_naive_threshold": alerts_naive / max(len(s_test), 1),
        "degeneracy": distinct_stats(s_test, test.host),
        "coverage": coverage_stats(s_test, test.X),
        # The missing-data question in one number: if the alert rate on partially observed
        # rows equals the rate on fully observed ones, absence is not acting as an anomaly.
        "far_partial_coverage_rows": partial_alert_share,
        "partial_coverage_share": float(partial.mean()),
        "per_host": per_host_report(s_test, test.host, thr),
        "persistence": alert_persistence(s_test, test.host, test.t, thr),
        "correlation": {},
        "score_p50": float(np.median(s_test)) if s_test.size else float("nan"),
        "score_p99": float(np.percentile(s_test, 99)) if s_test.size else float("nan"),
        "score_max": float(np.max(s_test)) if s_test.size else float("nan"),
        "score_p50_cal": float(np.median(s_cal)) if s_cal.size else float("nan"),
        "score_p99_cal": float(np.percentile(s_cal, 99)) if s_cal.size else float("nan"),
    }
    for model in ("Isolation Forest", "Gradient Boosting"):
        rho, n = spearman(s_test, test.prod.get(model, np.full(len(s_test), np.nan)))
        out["correlation"][model] = {"rho": rho, "n": n}
    out["per_host"].pop("per_host")
    return out


def parse_fold_spec(spec: str) -> Fold:
    """`name,train_start,train_end,test_start,test_end` -- the CLI form of a fold.

    Comma-separated because a timestamp contains colons; the first attempt at this used them
    as the separator and every spec failed to parse.
    """
    parts = [p.strip() for p in spec.split(",")]
    if len(parts) != 5:
        raise SystemExit(f"bad --fold-spec {spec!r}; want name,train_start,train_end,test_start,test_end")
    return Fold(*parts)


def cmd_run(args: argparse.Namespace) -> int:
    data = load_dataset(args.data)
    folds = ([parse_fold_spec(s) for s in args.fold_spec] if args.fold_spec
             else [f for f in FOLDS if args.fold is None or f.name in args.fold])
    results: dict[str, Any] = {"target_far": TARGET_FAR, "folds": {}, "pooled": {},
                               "data": {"path": args.data, "rows": len(data),
                                        "hosts": int(np.unique(data.host).size),
                                        "start": str(data.t.min()), "end": str(data.t.max()),
                                        "flagged_rows": int(data.flagged.sum())}}
    pooled: dict[str, dict[str, Any]] = {}
    for fold in folds:
        train = data.between(fold.train_start, fold.train_end)
        test = data.between(fold.test_start, fold.test_end)
        if args.coverage_level is not None:
            # PER-STRATUM CALIBRATION. This deployment observes exactly three coverage
            # levels (8/19 NetFlow only, 16/19 with no DNS rows, 19/19 complete). A single
            # threshold across them is not a threshold on behaviour: the lower strata sit at
            # the imputed median on the absent columns and score as the most normal points in
            # the space. Filtering to one level here lets the caller calibrate and measure
            # each stratum on its own terms; the pooled number is the window-weighted sum.
            keep = np.isclose(np.isfinite(train.X).mean(axis=1), args.coverage_level, atol=0.01)
            train = train.take(np.flatnonzero(keep))
            keep_t = np.isclose(np.isfinite(test.X).mean(axis=1), args.coverage_level, atol=0.01)
            test = test.take(np.flatnonzero(keep_t))
        if args.complete_case:
            # THE HONEST GATE. Half of this deployment's host-windows are missing a whole
            # telemetry family, and every candidate measured here spends its alert budget on
            # the fully observed ones. Restricting reference and evaluation to complete cases
            # makes the FAR denominator the population the model can actually speak about;
            # everything else is an explicit abstention, not a silent "normal".
            train = train.take(np.flatnonzero(np.isfinite(train.X).all(axis=1)))
            test = test.take(np.flatnonzero(np.isfinite(test.X).all(axis=1)))
        normal = train.take(np.flatnonzero(~train.flagged))
        order = stable_order(normal.host, normal.t)
        if args.train_limit and order.size > args.train_limit:
            order = order[: args.train_limit]
        sample = normal.take(order)
        fit_idx, cal_idx = split_fit_calibration(np.arange(len(sample)))
        fit, cal = sample.take(fit_idx), sample.take(cal_idx)
        fold_out: dict[str, Any] = {
            "train": [fold.train_start, fold.train_end],
            "test": [fold.test_start, fold.test_end],
            "n_train_available": len(train), "n_train_normal": len(normal),
            "n_train_used": len(sample), "n_fit": len(fit), "n_cal": len(cal),
            "n_test": len(test), "n_test_clean": int((~test.flagged).sum()),
            "complete_case": bool(args.complete_case),
            "coverage_level": args.coverage_level,
            "hosts_test": int(np.unique(test.host).size),
            "candidates": {},
        }
        for name, factory in candidate_factories().items():
            if name not in args.candidates:
                continue
            fold_out["candidates"][name] = evaluate_candidate(factory(), fit, cal, test)
            r = fold_out["candidates"][name]
            p = pooled.setdefault(name, {"alerts": 0, "n": 0, "alerts_clean": 0, "n_clean": 0,
                                         "fit_s": 0.0, "us_per_window": [], "rho_if": [],
                                         "rho_gb": [], "folds_worse_than_2x": 0})
            p["alerts"] += r["alerts"]
            p["n"] += r["n_test"]
            p["alerts_clean"] += r["alerts_clean"]
            p["n_clean"] += int((~test.flagged).sum())
            p["fit_s"] += r["fit_seconds"]
            p["us_per_window"].append(r["us_per_window"])
            p["rho_if"].append(r["correlation"]["Isolation Forest"]["rho"])
            p["rho_gb"].append(r["correlation"]["Gradient Boosting"]["rho"])
            if r["far_test"] > 2 * TARGET_FAR:
                p["folds_worse_than_2x"] += 1
        results["folds"][fold.name] = fold_out
        print(f"  {fold.name}: train {len(sample)} (fit {len(fit)}/cal {len(cal)}), "
              f"test {len(test)}", file=sys.stderr)

    for name, p in pooled.items():
        lo, hi = wilson(p["alerts"], p["n"])
        results["pooled"][name] = {
            "far_test": p["alerts"] / max(p["n"], 1),
            "far_test_wilson": [lo, hi],
            "alerts": p["alerts"], "windows": p["n"],
            "far_test_clean": p["alerts_clean"] / max(p["n_clean"], 1),
            "fit_seconds_total": round(p["fit_s"], 2),
            "us_per_window_median": float(np.median(p["us_per_window"])) if p["us_per_window"] else 0.0,
            "rho_isolation_forest": float(np.nanmedian(p["rho_if"])) if p["rho_if"] else float("nan"),
            "rho_gradient_boosting": float(np.nanmedian(p["rho_gb"])) if p["rho_gb"] else float("nan"),
            "folds_worse_than_2x": p["folds_worse_than_2x"],
        }
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(results, indent=2, sort_keys=True))
    print(json.dumps(results["pooled"], indent=2, sort_keys=True))
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    ex = sub.add_parser("extract", help="pull the 19-feature matrix from ClickHouse")
    ex.add_argument("--start", required=True)
    ex.add_argument("--end", required=True)
    ex.add_argument("--scope", action="append", required=True,
                    help="monitored CIDR; repeat for each declared scope")
    ex.add_argument("--out", required=True)
    ex.add_argument("--sql-out", default=None, help="also write the exact SQL that was run")
    ex.set_defaults(func=cmd_extract)

    rn = sub.add_parser("run", help="run the walk-forward bake-off on an extracted matrix")
    rn.add_argument("--data", required=True)
    rn.add_argument("--out", required=True)
    rn.add_argument("--fold", action="append", default=None, help="restrict to fold name(s)")
    rn.add_argument("--fold-spec", action="append", default=None,
                    help="name,train_start,train_end,test_start,test_end (repeatable; overrides FOLDS)")
    rn.add_argument("--coverage-level", type=float, default=None,
                    help="keep only windows whose measured-column share equals this value "
                         "(0.4211, 0.8421, 1.0 on this deployment)")
    rn.add_argument("--complete-case", action="store_true",
                    help="score only rows with all 19 columns measured (reference and test)")
    rn.add_argument("--train-limit", type=int, default=5000,
                    help="the production row cap on the reference; 0 keeps every normal window")
    rn.add_argument("--candidates", nargs="*", default=list(candidate_factories()),
                    help="candidate names to run (default: all)")
    rn.set_defaults(func=cmd_run)
    args = ap.parse_args()
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
