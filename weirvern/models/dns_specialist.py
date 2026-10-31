"""The DNS specialist: query shape, not just resolver volume.

A tunnel or DGA is not defined by how many bytes it moves. It is defined by long, high-entropy
labels, repeated unique names, unusual qtypes and failures. The production ensemble has DNS
features, but they are one block among seventy; this specialist isolates the shape into the
shadow candidate store so the fixed-budget review can compare it on its own.

It writes only `weirvern.ml_candidate_scores`. It never writes the alert table and never pages.
"""
from __future__ import annotations

import math
import statistics
from collections.abc import Iterable, Sequence
from time import perf_counter

from clickhouse_connect.driver.client import Client

from weirvern import __version__, networks
from weirvern.clock import utcnow

MODEL_NAME = "DNSSpecialist"


def shannon_entropy(text: str) -> float:
    """Shannon entropy in bits per character; empty text has zero entropy."""
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for char in text:
        counts[char] = counts.get(char, 0) + 1
    total = len(text)
    return -sum((n / total) * math.log2(n / total) for n in counts.values())


def registrable_domain(name: str) -> str:
    """A small, deterministic approximation of the registrable domain.

    No public-suffix dependency: the last two labels are the comparison unit. That is enough
    for a fixture and for a first-pass novelty ratio; a real suffix list can replace it without
    changing the feature names.
    """
    labels = [part for part in str(name or "").strip(".").lower().split(".") if part]
    return ".".join(labels[-2:]) if len(labels) >= 2 else ".".join(labels)


def _ratio(num: float, den: float) -> float:
    return float(num) / float(den) if den else 0.0


def features_from_queries(queries: Sequence[dict], *, seen_domains: set[str] | None = None
                          ) -> dict[str, float | bool]:
    """Pure query-shape features; a host with no queries is explicitly absent."""
    if not queries:
        return {"present": False, "query_count": 0.0}
    count = len(queries)
    lengths = [float(q.get("query_len") or len(str(q.get("query", ""))))
               for q in queries]
    entropies = [float(q.get("query_entropy", shannon_entropy(str(q.get("query", "")))))
                 for q in queries]
    domains = [registrable_domain(str(q.get("query", ""))) for q in queries]
    unique_queries = len({str(q.get("query", "")) for q in queries})
    unique_domains = len(set(domains))
    txt = sum(1 for q in queries if int(q.get("qtype", 0)) == 16)
    null = sum(1 for q in queries if int(q.get("qtype", 0)) == 10)
    srv = sum(1 for q in queries if int(q.get("qtype", 0)) == 33)
    any_q = sum(1 for q in queries if int(q.get("qtype", 0)) == 255)
    nxdomain = sum(1 for q in queries if int(q.get("rcode", 0)) == 3)
    errors = sum(1 for q in queries if int(q.get("rcode", 0)) != 0)
    new_ratio = 0.0
    if seen_domains is not None:
        new_ratio = _ratio(sum(1 for d in set(domains) if d not in seen_domains),
                           unique_domains)
    return {
        "present": True,
        "query_count": float(count),
        "unique_query_ratio": _ratio(unique_queries, count),
        "unique_domain_ratio": _ratio(unique_domains, count),
        "mean_entropy": statistics.fmean(entropies),
        "max_entropy": max(entropies),
        "mean_len": statistics.fmean(lengths),
        "std_len": statistics.pstdev(lengths),
        "txt_ratio": _ratio(txt, count),
        "null_ratio": _ratio(null, count),
        "srv_ratio": _ratio(srv, count),
        "any_ratio": _ratio(any_q, count),
        "nxdomain_ratio": _ratio(nxdomain, count),
        "error_ratio": _ratio(errors, count),
        "new_domain_ratio": new_ratio,
        "new_domain_known": seen_domains is not None,
    }


def score(features: dict, *, use_dns_shape: bool = True) -> tuple[float, str]:
    """Bounded 0..1 score and readable evidence.

    `use_dns_shape=False` is the source ablation: only query count remains, which a busy
    resolver and a tunnel share. Absence scores 0 and says it is absent.
    """
    if not features.get("present"):
        return 0.0, "no DNS queries in this window (host absent)"
    count = float(features.get("query_count", 0.0))
    if not use_dns_shape:
        return (round(min(1.0, count / 100.0) * 0.25, 4),
                f"count-only: queries={int(count)} (DNS shape ablated)")
    entropy = min(1.0, float(features.get("mean_entropy", 0.0)) / 4.0)
    length = min(1.0, max(0.0, float(features.get("mean_len", 0.0)) - 20.0) / 80.0)
    unique = max(float(features.get("unique_query_ratio", 0.0)),
                 float(features.get("unique_domain_ratio", 0.0)))
    weird_qtype = min(1.0, float(features.get("txt_ratio", 0.0))
                     + float(features.get("null_ratio", 0.0))
                     + float(features.get("srv_ratio", 0.0))
                     + float(features.get("any_ratio", 0.0)))
    nxdomain = min(1.0, float(features.get("nxdomain_ratio", 0.0)))
    new_domain = float(features.get("new_domain_ratio", 0.0))
    value = (0.40 * entropy + 0.20 * length + 0.20 * unique
             + 0.10 * weird_qtype + 0.05 * nxdomain + 0.05 * new_domain)
    value = round(min(1.0, value), 4)
    evidence = (
        f"queries={int(count)}; mean_entropy={float(features.get('mean_entropy', 0.0)):.3f}; "
        f"mean_len={float(features.get('mean_len', 0.0)):.1f}; "
        f"unique_queries={float(features.get('unique_query_ratio', 0.0)):.2f}; "
        f"unique_domains={float(features.get('unique_domain_ratio', 0.0)):.2f}; "
        f"txt={float(features.get('txt_ratio', 0.0)):.2f}; "
        f"nxdomain={nxdomain:.2f}; new_domain="
        f"{new_domain:.2f}{'' if features.get('new_domain_known') else ' (unknown)'}"
    )
    return value, evidence


def query_sql(minutes: int = 15, scope_filter: str = "") -> str:
    """Aggregate `zeek_dns` per host-window; a host with no queries is absent."""
    minutes = max(1, min(int(minutes), 7 * 24 * 60))
    return (
        "SELECT toStartOfFiveMinute(d.ts) AS window_start, d.src_addr, "
        "count() AS query_count, uniqExact(d.query) AS unique_queries, "
        "avg(d.query_entropy) AS mean_entropy, max(d.query_entropy) AS max_entropy, "
        "avg(d.query_len) AS mean_len, stddevPop(d.query_len) AS std_len, "
        "countIf(d.qtype = 16) AS txt_queries, countIf(d.qtype = 10) AS null_queries, "
        "countIf(d.qtype = 33) AS srv_queries, countIf(d.qtype = 255) AS any_queries, "
        "countIf(d.rcode != 0) AS error_queries, countIf(d.rcode = 3) AS nxdomain, "
        "countIf(length(d.answers) > 0) AS answered "
        "FROM weirvern.zeek_dns AS d "
        f"WHERE d.ts >= now() - INTERVAL {minutes} MINUTE "
        f"{scope_filter} "
        "GROUP BY window_start, d.src_addr"
    )


def score_rows(rows: Iterable[tuple], *, use_dns_shape: bool = True) -> list[dict]:
    """Pure scoring over query rows; also the test seam for the ablation."""
    out: list[dict] = []
    for source_row in rows:
        (window_start, src_addr, count, unique_queries, mean_entropy, max_entropy,
         mean_len, std_len, txt, null, srv, any_q, errors, nxdomain, answered) = source_row
        count_i = int(count)
        features = features_from_queries([]) if count_i == 0 else {
            "present": True,
            "query_count": float(count_i),
            "unique_query_ratio": _ratio(float(unique_queries), count_i),
            "unique_domain_ratio": _ratio(float(unique_queries), count_i),
            "mean_entropy": float(mean_entropy),
            "max_entropy": float(max_entropy),
            "mean_len": float(mean_len),
            "std_len": float(std_len),
            "txt_ratio": _ratio(float(txt), count_i),
            "null_ratio": _ratio(float(null), count_i),
            "srv_ratio": _ratio(float(srv), count_i),
            "any_ratio": _ratio(float(any_q), count_i),
            "nxdomain_ratio": _ratio(float(nxdomain), count_i),
            "error_ratio": _ratio(float(errors), count_i),
            "new_domain_ratio": 0.0,
            "new_domain_known": False,
            "answered_ratio": _ratio(float(answered), count_i),
        }
        value, evidence = score(features, use_dns_shape=use_dns_shape)
        out.append({"window_start": window_start, "src_addr": str(src_addr),
                    "score": value, "evidence": evidence, "features": features})
    out.sort(key=lambda r: (str(r["window_start"]), -r["score"], r["src_addr"]))
    rank_by_window: dict[str, int] = {}
    for candidate in out:
        key = str(candidate["window_start"])
        rank_by_window[key] = rank_by_window.get(key, 0) + 1
        candidate["rank"] = rank_by_window[key]
    return out


def run(client: Client, *, minutes: int = 15, scope_filter: str | None = None) -> dict:
    """Score the last window into `ml_candidate_scores`; never touch the alert path."""
    if scope_filter is None:
        scope_filter = networks.training_filter(client, alias="d")
    sql = query_sql(minutes, scope_filter)
    started = perf_counter()
    try:
        rows = client.query(sql).result_rows
    except Exception as exc:  # noqa: BLE001
        return {"available": False, "reason": f"DNS query failed: {type(exc).__name__}",
                "rows": 0, "elapsed_ms": round((perf_counter() - started) * 1000, 1)}
    if not rows:
        return {"available": False, "reason": "no DNS queries in the window",
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
        "available": True, "reason": "", "rows": len(scored),
        "windows": len({str(row["window_start"]) for row in scored}),
        "score_p50": round(float(sorted(scores)[len(scores) // 2]), 4),
        "score_max": round(float(max(scores)), 4),
        "elapsed_ms": round((perf_counter() - started) * 1000, 1),
        "model_version": __version__,
        "source": "weirvern.zeek_dns (query shape)",
    }


__all__ = ["MODEL_NAME", "features_from_queries", "query_sql", "registrable_domain",
           "run", "score", "score_rows", "shannon_entropy"]
