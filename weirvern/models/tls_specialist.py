"""The TLS/JA4 specialist: novelty and rarity, not just session volume.

A new client fingerprint on one host is a lead; the same browser fingerprint on every host is
not. This specialist isolates JA4 novelty, fleet rarity, old TLS versions and SNI/JA4
inconsistency into the shadow candidate store. It never writes the alert table and never pages.

The pure feature functions are the contract. The SQL path supplies session counts and version
mix; novelty and fleet rarity need a history/reference set, which the caller can supply and
which is reported as unknown rather than silently zero when absent.
"""
from __future__ import annotations

from collections.abc import Iterable, Sequence
from time import perf_counter
from typing import Any

from clickhouse_connect.driver.client import Client

from weirvern import __version__, networks
from weirvern.clock import utcnow

MODEL_NAME = "TLSSpecialist"


def _ratio(num: float, den: float) -> float:
    return float(num) / float(den) if den else 0.0


def features_from_sessions(
    sessions: Sequence[dict],
    *,
    seen_ja4: set[str] | None = None,
    fleet_host_counts: dict[str, int] | None = None,
    expected_sni: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Pure JA4/TLS features. No sessions means the host is absent, not a zero vector."""
    if not sessions:
        return {"present": False, "session_count": 0.0}
    count = len(sessions)
    ja4_list = [str(s.get("ja4") or "") for s in sessions]
    unique_ja4 = {j for j in ja4_list if j}
    versions = [str(s.get("version") or "") for s in sessions]
    sni = [str(s.get("server_name") or "") for s in sessions]
    new_ja4 = 0.0 if seen_ja4 is None else _ratio(
        sum(1 for j in unique_ja4 if j not in seen_ja4), len(unique_ja4) or 1)
    # Fleet rarity: 1 - the largest fleet host count share for any fingerprint this host used.
    rarity = 0.0
    if fleet_host_counts is not None and unique_ja4:
        total = max(1, sum(fleet_host_counts.values()))
        rarity = 1.0 - max((fleet_host_counts.get(j, 0) / total for j in unique_ja4),
                           default=0.0)
    mismatch = 0.0
    if expected_sni:
        mismatch = _ratio(sum(1 for s in sessions
                              if expected_sni.get(str(s.get("ja4") or ""))
                              and expected_sni[str(s.get("ja4"))] != str(s.get("server_name") or "")),
                          count)
    return {
        "present": True,
        "session_count": float(count),
        "unique_ja4_ratio": _ratio(len(unique_ja4), count),
        "new_ja4_ratio": new_ja4,
        "new_ja4_known": seen_ja4 is not None,
        "fleet_rarity": rarity,
        "fleet_rarity_known": fleet_host_counts is not None,
        "tls13_ratio": _ratio(sum(1 for v in versions if v in ("TLSv1.3", "TLS1.3")), count),
        "old_tls_ratio": _ratio(sum(1 for v in versions
                                    if v in ("TLSv1", "TLSv1.0", "TLSv1.1", "SSLv3", "SSLv2",
                                             "TLS1.0", "TLS1.1")), count),
        "sni_mismatch_ratio": mismatch,
        "sni_mismatch_known": bool(expected_sni),
        "unique_sni_ratio": _ratio(len({s for s in sni if s}), count),
    }


def score(features: dict, *, use_ja4_shape: bool = True) -> tuple[float, str]:
    """Bounded 0..1 score and readable evidence; absent scores 0 and says so."""
    if not features.get("present"):
        return 0.0, "no TLS sessions in this window (host absent)"
    count = float(features.get("session_count", 0.0))
    if not use_ja4_shape:
        return (round(min(1.0, count / 100.0) * 0.25, 4),
                f"count-only: sessions={int(count)} (JA4 shape ablated)")
    new_ja4 = float(features.get("new_ja4_ratio", 0.0))
    rarity = float(features.get("fleet_rarity", 0.0))
    unique = float(features.get("unique_ja4_ratio", 0.0))
    old = float(features.get("old_tls_ratio", 0.0))
    mismatch = float(features.get("sni_mismatch_ratio", 0.0))
    value = (0.35 * new_ja4 + 0.25 * rarity + 0.15 * unique
             + 0.15 * old + 0.10 * mismatch)
    value = round(min(1.0, value), 4)
    evidence = (
        f"sessions={int(count)}; new_ja4={new_ja4:.2f}"
        f"{'' if features.get('new_ja4_known') else ' (unknown)'}; "
        f"fleet_rarity={rarity:.2f}"
        f"{'' if features.get('fleet_rarity_known') else ' (unknown)'}; "
        f"unique_ja4={unique:.2f}; old_tls={old:.2f}; "
        f"sni_mismatch={mismatch:.2f}"
        f"{'' if features.get('sni_mismatch_known') else ' (unknown)'}"
    )
    return value, evidence


def query_sql(minutes: int = 15, scope_filter: str = "") -> str:
    """Aggregate `zeek_ssl` per host-window; a host with no TLS is absent."""
    minutes = max(1, min(int(minutes), 7 * 24 * 60))
    return (
        "SELECT toStartOfFiveMinute(s.ts) AS window_start, s.src_addr, "
        "count() AS session_count, uniqExact(s.ja4) AS unique_ja4, "
        "countIf(s.version IN ('TLSv1.3', 'TLS1.3')) AS tls13_sessions, "
        "countIf(s.version IN ('TLSv1', 'TLSv1.0', 'TLSv1.1', 'SSLv3', 'SSLv2', "
        "'TLS1.0', 'TLS1.1')) AS old_sessions, "
        "uniqExact(s.server_name) AS unique_sni, "
        "groupUniqArray(s.ja4) AS ja4_list "
        "FROM weirvern.zeek_ssl AS s "
        f"WHERE s.ts >= now() - INTERVAL {minutes} MINUTE "
        f"{scope_filter} "
        "GROUP BY window_start, s.src_addr"
    )


def score_rows(rows: Iterable[tuple], *, use_ja4_shape: bool = True,
               seen_by_host: dict[str, set[str]] | None = None,
               fleet_host_counts: dict[str, int] | None = None) -> list[dict]:
    """Pure scoring over SQL rows; history is optional and named when absent."""
    out: list[dict] = []
    for source_row in rows:
        (window_start, src_addr, count, unique_ja4, tls13, old, unique_sni,
         ja4_list) = source_row
        count_i = int(count)
        seen = None if seen_by_host is None else set(seen_by_host.get(str(src_addr), set()))
        current = {str(j) for j in (ja4_list or []) if j}
        new_ratio = 0.0
        if seen is not None:
            new_ratio = _ratio(sum(1 for j in current if j not in seen), len(current) or 1)
        rarity = 0.0
        if fleet_host_counts is not None and current:
            total = max(1, sum(fleet_host_counts.values()))
            rarity = 1.0 - max((fleet_host_counts.get(j, 0) / total for j in current),
                               default=0.0)
        features = {
            "present": count_i > 0,
            "session_count": float(count_i),
            "unique_ja4_ratio": _ratio(float(unique_ja4), count_i),
            "new_ja4_ratio": new_ratio,
            "new_ja4_known": seen is not None,
            "fleet_rarity": rarity,
            "fleet_rarity_known": fleet_host_counts is not None,
            "tls13_ratio": _ratio(float(tls13), count_i),
            "old_tls_ratio": _ratio(float(old), count_i),
            "sni_mismatch_ratio": 0.0,
            "sni_mismatch_known": False,
            "unique_sni_ratio": _ratio(float(unique_sni), count_i),
        }
        value, evidence = score(features, use_ja4_shape=use_ja4_shape)
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
        scope_filter = networks.training_filter(client, alias="s")
    started = perf_counter()
    try:
        rows = client.query(query_sql(minutes, scope_filter)).result_rows
    except Exception as exc:  # noqa: BLE001
        return {"available": False, "reason": f"TLS query failed: {type(exc).__name__}",
                "rows": 0, "elapsed_ms": round((perf_counter() - started) * 1000, 1)}
    if not rows:
        return {"available": False, "reason": "no TLS sessions in the window",
                "rows": 0, "elapsed_ms": round((perf_counter() - started) * 1000, 1)}
    history_sql = (
        "SELECT s.src_addr, groupUniqArray(s.ja4) AS ja4_list "
        "FROM weirvern.zeek_ssl AS s "
        f"WHERE s.ts < now() - INTERVAL {minutes} MINUTE {scope_filter} "
        "GROUP BY s.src_addr"
    )
    fleet_sql = (
        "SELECT s.ja4, uniqExact(s.src_addr) AS hosts "
        "FROM weirvern.zeek_ssl AS s "
        f"WHERE s.ts < now() - INTERVAL {minutes} MINUTE {scope_filter} "
        "GROUP BY s.ja4"
    )
    seen_by_host: dict[str, set[str]] | None = None
    fleet_host_counts: dict[str, int] | None = None
    try:
        seen_by_host = {str(host): {str(j) for j in (ja4_list or []) if j}
                        for host, ja4_list in client.query(history_sql).result_rows}
        fleet_host_counts = {str(ja4): int(hosts) for ja4, hosts in
                             client.query(fleet_sql).result_rows if ja4}
    except Exception:
        # History is an enhancement. If it is unavailable the score still runs and the
        # evidence says the novelty/rarity fields are unknown.
        seen_by_host = None
        fleet_host_counts = None
    scored = score_rows(rows, seen_by_host=seen_by_host,
                        fleet_host_counts=fleet_host_counts)
    out = []
    now = utcnow()
    for row in scored:
        out.append([row["window_start"], row["src_addr"], MODEL_NAME, float(row["score"]),
                    int(row["rank"]), row["evidence"], __version__, now])
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
        "source": "weirvern.zeek_ssl (JA4/TLS shape)",
    }


__all__ = ["MODEL_NAME", "features_from_sessions", "query_sql", "run", "score", "score_rows"]
