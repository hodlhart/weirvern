"""Fuse the shadow channels into one honest ripple answer per host (RIP-5).

WHY THIS EXISTS. `ripple.fuse()` and `evidence_from_shadow()` were built and tested but nothing
called them: the specialists wrote their tables, the ensemble kept max-fusing four scores, and
the new layer was invisible to the worker and the console. This module is the missing call site.
It reads the three shadow stores, calibrates every model against its OWN recent population,
fuses per host, and records the answer in `ml_ripple`.

WHAT IT DELIBERATELY DOES NOT DO: it never writes `netflow_anomalies`, never pages and never
promotes a model. `pageable` is always 0 here -- the page decision is the alert budget's, not a
shadow pass's. A failure is caught by the worker's shadow block and detection continues.

HONEST LIMITS, measured against the live deployment on 2026-11-11:
  * every channel except the change point reports at the 5-minute scale, so a ripple can only
    clear the two-scale bar when a change point supplies the second scale;
  * the reference population is the most recent REFERENCE_SAMPLE scores per model (a week of
    the HDBSCAN candidate alone is ~900k rows; the whole population does not fit in one pass);
  * a change point's scale comes from `run_length`, the length of the regime that ENDED -- the
    only duration the change-point table records. It is not the duration of the new regime,
    which is unknown until the next change point.
"""
from __future__ import annotations

import json
from collections import Counter
from datetime import UTC, datetime
from typing import Any

from clickhouse_connect.driver.client import Client

from weirvern.clock import utcnow
from weirvern.models import generic_channels, operating_point
from weirvern.models.ripple import ChannelEvidence, evidence_from_shadow, fuse

MODEL_VERSION = "ripple-1"

# A week is long enough to contain a host's ordinary week and short enough that a retrain
# does not leave the reference straddling two different models. The sample is per model and
# bounded because the candidate table grows by ~128k rows a day on the live deployment.
REFERENCE_DAYS = 7
REFERENCE_SAMPLE = 2000

# Must not exceed ripple.DEFAULT_MAX_FRESHNESS_S (900): rows older than that are "stale" by
# definition, and reading them would only produce a longer unknown list.
EVIDENCE_LOOKBACK_S = 900

# A cap on hosts per pass. The live deployment scores ~22 hosts per sweep; the cap exists so a
# scope mistake or a flood cannot turn one shadow pass into an unbounded write.
MAX_HOSTS = 200

# The candidate tables score one 5-minute window. A change point's run_length is counted in
# those windows, so 12 samples is an hour and 288 is a day.
WINDOW_S = 300
SCALE_1H_SAMPLES = 3600 // WINDOW_S
SCALE_24H_SAMPLES = 86400 // WINDOW_S

# Model name -> (family, scale). A family is "a kind of evidence", so two models of the same
# kind (two DNS shapers, say) must not make a ripple on their own. Unknown models keep their own
# slug as the family: silently folding a new detector into an existing family would let it vote
# twice for the same kind of evidence.
CANDIDATE_FAMILIES: dict[str, tuple[str, str]] = {
    "FlowSpecialist": ("flow", "5m"),
    "DNSSpecialist": ("dns", "5m"),
    "TLSSpecialist": ("tls", "5m"),
    "BeaconSpecialist": ("beacon", "5m"),
    "GraphSpecialist": ("graph", "5m"),
    "HDBSCAN": ("candidate", "5m"),
    "External exposure": ("exposure", "5m"),
}

_REFERENCE_SQL = """
SELECT {key} AS model, {score} AS score
FROM {table}
WHERE computed_at >= now() - INTERVAL {days} DAY
ORDER BY model, computed_at DESC
LIMIT {sample} BY model
"""

_RECENT_CANDIDATES = """
SELECT src_addr, model_name, score, model_version, computed_at
FROM weirvern.ml_candidate_scores
WHERE computed_at >= now() - INTERVAL {lookback} SECOND
"""

_RECENT_TEMPORAL = """
SELECT src_addr, concat('temporal:', metric) AS model, discord_score AS score,
       matrix_profile_version AS model_version, computed_at
FROM weirvern.ml_temporal_scores
WHERE computed_at >= now() - INTERVAL {lookback} SECOND
"""

_RECENT_CHANGEPOINTS = """
SELECT src_addr, concat('changepoint:', metric, ':', direction) AS model,
       probability AS score, model_version, computed_at, run_length
FROM weirvern.ml_changepoints
WHERE computed_at >= now() - INTERVAL {lookback} SECOND
"""


def _aware(value: datetime) -> datetime:
    """ClickHouse returns naive UTC; the rest of the package compares aware UTC."""
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value


def _age_seconds(computed_at: datetime | None, now: datetime) -> float:
    if computed_at is None:
        return float("inf")
    return max(0.0, (now - _aware(computed_at)).total_seconds())


def changepoint_scale(run_length: int) -> str:
    """The scale of a change point, from the length of the regime that ended.

    A step after a day of stability is a day-scale change; one after twenty minutes is not.
    `run_length` is the distance to the PREVIOUS change point, so this describes the ending
    regime and never claims anything about how long the new one will last.
    """
    if run_length >= SCALE_24H_SAMPLES:
        return "24h"
    if run_length >= SCALE_1H_SAMPLES:
        return "1h"
    return "5m"


def family_scale_for(model: str) -> tuple[str, str]:
    """(family, scale) for a channel id, including channels with no fresh row this pass."""
    if model in CANDIDATE_FAMILIES:
        return CANDIDATE_FAMILIES[model]
    if model.startswith("temporal:"):
        return "temporal", "5m"
    if model.startswith("changepoint:"):
        # No row means no run_length: name it at the base scale rather than inventing one.
        return "changepoint", "5m"
    slug = model.strip().lower().replace(" ", "_") or "unknown"
    return slug, "5m"


def _query(client: Client, sql: str) -> list[Any]:
    return list(client.query(sql).result_rows)


def reference_population(client: Client) -> dict[str, list[float]]:
    """model -> its recent scores. This is the population each p-value is measured against."""
    out: dict[str, list[float]] = {}
    sources = (
        ("model_name", "score", "weirvern.ml_candidate_scores"),
        ("concat('temporal:', metric)", "discord_score", "weirvern.ml_temporal_scores"),
        ("concat('changepoint:', metric, ':', direction)", "probability",
         "weirvern.ml_changepoints"),
    )
    for key, score, table in sources:
        sql = _REFERENCE_SQL.format(key=key, score=score, table=table,
                                    days=REFERENCE_DAYS, sample=REFERENCE_SAMPLE)
        for model, value in _query(client, sql):
            if model is None or value is None:
                continue
            out.setdefault(str(model), []).append(float(value))
    return out


def _row(host: str, channel: str, score: float, version: str, computed_at: datetime,
         *, family: str, scale: str, now: datetime) -> dict[str, Any]:
    return {
        "src_addr": host,
        "channel": channel,
        "model_name": channel,
        "family": family,
        "scale": scale,
        "score": float(score),
        "model_version": str(version or "unknown"),
        "freshness_s": _age_seconds(computed_at, now),
        "present": True,
    }


def recent_rows(client: Client, now: datetime,
                *, lookback_s: int = EVIDENCE_LOOKBACK_S) -> dict[str, list[dict[str, Any]]]:
    """Recent shadow rows per host, each carrying the family and scale it belongs to."""
    by_host: dict[str, list[dict[str, Any]]] = {}
    for src, model, score, version, computed_at in _query(
            client, _RECENT_CANDIDATES.format(lookback=lookback_s)):
        if not src or score is None:
            continue
        family, scale = family_scale_for(str(model))
        by_host.setdefault(str(src), []).append(
            _row(str(src), str(model), float(score), str(version), computed_at,
                 family=family, scale=scale, now=now))

    for src, model, score, version, computed_at in _query(
            client, _RECENT_TEMPORAL.format(lookback=lookback_s)):
        if not src or score is None:
            continue
        channel = str(model)
        by_host.setdefault(str(src), []).append(
            _row(str(src), channel, float(score), str(version), computed_at,
                 family="temporal", scale="5m", now=now))

    for src, model, score, version, computed_at, run_length in _query(
            client, _RECENT_CHANGEPOINTS.format(lookback=lookback_s)):
        if not src or score is None:
            continue
        channel = str(model)
        by_host.setdefault(str(src), []).append(
            _row(str(src), channel, float(score), str(version), computed_at,
                 family="changepoint", scale=changepoint_scale(int(run_length or 0)), now=now))
    return by_host


def missing_channels(references: dict[str, list[float]],
                     present: set[str] | None = None) -> list[ChannelEvidence]:
    """Named evidence for every known channel this host did not report this pass.

    The fusion treats these as `unknown`, never as zero. A channel that is dark is a fact the
    operator needs to see; an absent channel that silently contributes nothing is how a dead
    feed turns into a quiet network.
    """
    have = present or set()
    out: list[ChannelEvidence] = []
    for model in sorted(references):
        if model in have:
            continue
        family, scale = family_scale_for(model)
        out.append(ChannelEvidence(
            channel=model, family=family, scale=scale, model_id=model, model_version="unknown",
            score=0.0, pvalue=float("nan"), freshness_s=float("inf"), present=False))
    return out


def strongest_per_channel(evidence: list[ChannelEvidence]) -> list[ChannelEvidence]:
    """One piece of evidence per (channel, family, scale), keeping the most significant.

    WHY: Fisher's method assumes independent tests. HDBSCAN writes a score for every candidate
    in a bucket -- measured live on 2026-11-12, hundreds per host -- and every one of them is
    correlated with the others. Feeding all of them into one combination makes the combined
    p-value spuriously tiny: the first live pass reported 3 of 22 hosts as ripples and returned
    a 187 KB payload for 22 hosts. Collapsing to the strongest per channel and scale keeps the
    independence assumption defensible and the payload readable.
    """
    best: dict[tuple[str, str, str], ChannelEvidence] = {}
    for item in evidence:
        key = (item.channel, item.family, item.scale)
        held = best.get(key)
        if held is None or (item.pvalue, -item.score) < (held.pvalue, -held.score):
            best[key] = item
    return list(best.values())


FUSED_HISTORY_SQL = """
SELECT combined_p, src_addr
FROM weirvern.ml_ripple
WHERE combined_p > 0 AND combined_p <= 1
ORDER BY evaluated_at DESC
LIMIT 20000
"""


def fused_history(client: Client) -> tuple[list[float], int]:
    """(every fused p-value this deployment has produced, how many hosts produced them).

    The deployment's own history is the only calibration source that exists: no labels, no
    operator, no second system to compare against.
    """
    values: list[float] = []
    hosts: set[str] = set()
    for row in _query(client, FUSED_HISTORY_SQL):
        value, host = row[0], str(row[1] or "")
        if value is None:
            continue
        values.append(float(value))
        if host:
            hosts.add(host)
    return values, len(hosts)


def evaluate(client: Client, *, now: datetime | None = None,
             lookback_s: int = EVIDENCE_LOOKBACK_S, max_p: float | None = None,
             abstain_reason: str | None = None) -> list[dict[str, Any]]:
    """One fused result per host with fresh evidence, or one segment-level unknown."""
    moment = _aware(now or utcnow()).replace(microsecond=0)
    references = reference_population(client)
    by_host = recent_rows(client, moment, lookback_s=lookback_s)

    if not by_host:
        result = fuse(missing_channels(references))
        return [_record("", result, moment)]

    # Sources with no specialist of their own still carry signal (http, files, ssh, weird,
    # quic, dhcp). They are scored the same way and enter the same fusion; a source that is
    # quiet produces nothing rather than a zero.
    from_source = generic_channels.evidence(client, sorted(by_host)[:MAX_HOSTS], now=moment)

    out: list[dict[str, Any]] = []
    for host in sorted(by_host)[:MAX_HOSTS]:
        evidence = strongest_per_channel(
            evidence_from_shadow(by_host[host], reference_by_model=references))
        evidence.extend(missing_channels(references, {ch.channel for ch in evidence}))
        evidence.extend(from_source.get(host, []))
        verdict = fuse(evidence) if max_p is None else fuse(evidence, max_p=max_p)
        record = _record(host, verdict, moment)
        if abstain_reason:
            # Cold start is not a failure to detect: it is the only honest answer before the
            # deployment knows what its own normal looks like.
            record["status"] = "unknown"
            record["reason"] = abstain_reason
        out.append(record)
    return out


def _record(host: str, result, evaluated_at: datetime) -> dict[str, Any]:
    return {
        "evaluated_at": evaluated_at,
        "src_addr": host,
        "status": result.status,
        "reason": result.reason,
        "confidence": float(result.confidence),
        "combined_p": float(result.combined_p),
        "families": list(result.families),
        "scales": list(result.scales),
        "contributors": result.contributors,
        "unknown_channels": result.unknown,
        "channel_count": len(result.contributors),
        # Always 0: fuse() is called without a page policy, and this pass never pages.
        "pageable": 0,
        "model_version": MODEL_VERSION,
    }


_COLUMNS = ["evaluated_at", "src_addr", "status", "reason", "confidence", "combined_p",
            "families", "scales", "contributors", "unknown_channels", "channel_count",
            "pageable", "model_version"]


def run(client: Client, *, now: datetime | None = None,
        lookback_s: int = EVIDENCE_LOOKBACK_S) -> dict[str, Any]:
    """Evaluate, persist one row per host, and return the counts the worker logs.

    Persisting an `unknown` row matters: the API and the Models card must be able to say
    "nothing was fused, and here is why", rather than showing the last good answer forever.
    """
    history, host_count = fused_history(client)
    point = operating_point.derive(history, hosts=host_count)
    results = evaluate(client, now=now, lookback_s=lookback_s,
                       max_p=point.max_p,
                       abstain_reason=point.reason if point.cold_start else None)
    if results:
        client.insert(
            "weirvern.ml_ripple",
            [[r["evaluated_at"], r["src_addr"], r["status"], r["reason"], r["confidence"],
              r["combined_p"], r["families"], r["scales"],
              json.dumps(r["contributors"], separators=(",", ":")),
              json.dumps(r["unknown_channels"], separators=(",", ":")),
              r["channel_count"], r["pageable"], r["model_version"]] for r in results],
            column_names=_COLUMNS,
        )
    counts = Counter(r["status"] for r in results)
    return {
        "evaluated_at": results[0]["evaluated_at"].isoformat() if results else "",
        "hosts": len(results),
        "ripple": counts.get("ripple", 0),
        "observation": counts.get("observation", 0),
        "unknown": counts.get("unknown", 0),
        "rows": len(results),
        "operating_point": point.as_dict(),
    }


__all__ = ["CANDIDATE_FAMILIES", "EVIDENCE_LOOKBACK_S", "FUSED_HISTORY_SQL", "MAX_HOSTS",
           "MODEL_VERSION", "fused_history",
           "REFERENCE_DAYS", "REFERENCE_SAMPLE", "changepoint_scale", "evaluate",
           "family_scale_for", "missing_channels", "recent_rows", "reference_population", "run"]
