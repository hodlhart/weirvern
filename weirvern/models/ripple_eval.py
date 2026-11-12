"""Measure the ripple stack against the generated corpus (RIP-1 -> RIP-2/3/4).

WHY THIS EXISTS. The three detector cards end in the same requirement: measured, not asserted.
This module is the measurement. It runs the SAME pure feature functions the live specialists use,
calibrates every channel against clean host-days, fuses with the production `fuse()`, and scores
the result against the corpus labels.

WHAT IS MEASURED, and what each number means:

  * detection rate by amplitude and duration -- can it see a change that is small at 5m?
  * latency -- how long after the labelled start does it fire?
  * false alarms per clean host-day -- the denominator that makes "quiet" a number
  * bursts and benign new services that fired -- a fire here is a false alarm by construction
  * the scale that carried each detection -- proof the multi-scale requirement is doing work

CHANNELS. flow at 5m and 1h (the SAME signal at two scales: this is what separates a persistent
change from a burst), graph, DNS, TLS and beacon at 5m, and the matrix-profile discord at 5m and
1h. All of them are calibrated against clean host-days, never against the day being examined.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any

from weirvern.models import beacon_specialist, dns_specialist, graph_specialist, tls_specialist
from weirvern.models.ripple import ChannelEvidence, empirical_pvalue, fuse
from weirvern.models.ripple_corpus import BUCKET_MINUTES, HostDay
from weirvern.models.temporal import matrix_profile

ROLLING_1H = 60 // BUCKET_MINUTES          # 12 buckets
DISCORD_WINDOW = 12                        # 1 hour of 5-minute buckets


def _relative_volume(day: HostDay) -> list[float]:
    """Volume as a multiple of this host's own day median -- the only comparable scale."""
    values = [float(v) for v in day.bytes_out]
    ordered = sorted(values)
    median = ordered[len(ordered) // 2] or 1.0
    return [v / median for v in values]


def _rolling(values: list[float], window: int) -> list[float]:
    out: list[float] = []
    for i in range(len(values)):
        start = max(0, i - window + 1)
        chunk = values[start:i + 1]
        out.append(sum(chunk) / len(chunk))
    return out


def _rolling_present(values: list[float | None], window: int) -> list[float | None]:
    """Trailing mean over the buckets that actually reported; None when none did.

    A missing channel must stay missing at the coarser scale too: averaging it in as zero is how
    a dark feed turns into a quiet one.
    """
    out: list[float | None] = []
    for i in range(len(values)):
        chunk = [v for v in values[max(0, i - window + 1):i + 1] if v is not None]
        out.append(sum(chunk) / len(chunk) if chunk else None)
    return out


def _discord(values: list[float]) -> list[float]:
    """Matrix-profile discord per bucket; the leading edge is filled with its first value.

    The live temporal channel already uses the same matrix profile, so this is not a second
    algorithm -- it is the same one applied to a series the corpus controls.
    """
    profile, _m, _peak, _idx = matrix_profile(values, m=DISCORD_WINDOW)
    scores = [float(x) for x in profile]
    if not scores:
        return [0.0] * len(values)
    pad = len(values) - len(scores)
    return [scores[0]] * pad + scores


def channel_series(day: HostDay, *, baseline_hours: int = 4
                   ) -> dict[tuple[str, str], list[float | None]]:
    """Every channel's score per bucket. None means the channel had no evidence in that bucket.

    A missing channel is None, not zero: the fusion must be able to tell a quiet channel from a
    channel that never reported, and the corpus deliberately contains buckets with no DNS, no TLS
    and no new edges.
    """
    volume = _relative_volume(day)
    one_hour = _rolling(volume, ROLLING_1H)
    out: dict[tuple[str, str], list[float | None]] = {}
    out[("flow", "5m")] = list(volume)
    out[("flow", "1h")] = list(one_hour)
    out[("temporal", "5m")] = list(_discord(volume))
    out[("temporal", "1h")] = list(_discord(one_hour))

    graph_scores: list[float | None] = []
    dns_scores: list[float | None] = []
    tls_scores: list[float | None] = []
    beacon_scores: list[float | None] = []

    # THE NOVELTY BASELINE IS THE HORIZON, NOT THE PREVIOUS BUCKET. With a running union a
    # sustained new edge looks new for exactly one bucket, so a lateral movement that persists
    # for hours scores like a one-off blip (measured: 1 of 8 lateral/tunnel days detected).
    # The live equivalent is a 24-hour lookback; on a one-day corpus the pre-scenario hours are
    # the only baseline that exists, so the harness fixes it at the first N hours and says so.
    baseline_buckets = baseline_hours * 60 // BUCKET_MINUTES
    seen_edges: set[tuple[str, str]] = {
        edge for bucket in day.edges[:baseline_buckets] for edge in bucket}
    seen_domains: set[str] = {
        dns_specialist.registrable_domain(str(q.get("query", "")))
        for bucket in day.queries[:baseline_buckets] for q in bucket}
    seen_ja4: set[str] = set()
    fleet: dict[str, int] = {}
    for bucket in day.sessions:
        for session in bucket:
            ja4 = str(session.get("ja4") or "")
            if ja4:
                fleet[ja4] = fleet.get(ja4, 0) + 1

    for index in range(len(day.bytes_out)):
        edges = list(day.edges[index]) if index < len(day.edges) else []
        features = graph_specialist.features_from_edges(
            edges, day.host, seen_edges=seen_edges, peer_counts=dict(fleet_peers(day, index)))
        graph_scores.append(graph_specialist.score(features)[0] if features.get("present") else None)
        # DELIBERATELY NOT updated per bucket: novelty is measured against the fixed baseline
        # horizon above. A running union made a sustained new edge look new for exactly one
        # bucket, which is why a 3-hour lateral movement scored like a one-off blip.

        queries = day.queries[index] if index < len(day.queries) else []
        dns = dns_specialist.features_from_queries(list(queries), seen_domains=seen_domains)
        dns_scores.append(dns_specialist.score(dns)[0] if dns.get("present") else None)

        sessions = day.sessions[index] if index < len(day.sessions) else []
        tls = tls_specialist.features_from_sessions(
            list(sessions), seen_ja4=seen_ja4, fleet_host_counts=fleet)
        tls_scores.append(tls_specialist.score(tls)[0] if tls.get("present") else None)
        seen_ja4 |= {str(s.get("ja4") or "") for s in sessions if s.get("ja4")}

        window_start = max(0, index - ROLLING_1H + 1)
        times: list[float] = []
        for earlier in range(window_start, index + 1):
            times.extend(day.flow_times[earlier] if earlier < len(day.flow_times) else [])
        beacon = beacon_specialist.features_from_times(times)
        beacon_scores.append(beacon_specialist.score(beacon)[0] if beacon.get("present") else None)

    out[("graph", "5m")] = graph_scores
    out[("dns", "5m")] = dns_scores
    out[("tls", "5m")] = tls_scores
    out[("beacon", "5m")] = beacon_scores
    # THE SAME EVIDENCE AT A COARSER SCALE. Without this a graph-only or DNS-only change can
    # never be a ripple: the fusion requires two scales, and a channel that reports only at 5m
    # supplies one. Measured on the corpus: lateral and DNS-tunnel scenarios were 0/8 for
    # exactly this reason, not because the specialists failed to see them.
    out[("graph", "1h")] = _rolling_present(graph_scores, ROLLING_1H)
    out[("dns", "1h")] = _rolling_present(dns_scores, ROLLING_1H)
    out[("tls", "1h")] = _rolling_present(tls_scores, ROLLING_1H)
    out[("beacon", "1h")] = _rolling_present(beacon_scores, ROLLING_1H)
    return out


def fleet_peers(day: HostDay, index: int) -> dict[str, int]:
    """How many hosts talk to each peer up to this bucket -- the rarity reference."""
    counts: dict[str, int] = {}
    for bucket in day.edges[: index + 1]:
        for peer in {dst for _, dst in bucket}:
            counts[peer] = counts.get(peer, 0) + 1
    return counts


FAMILY_OF = {"flow": "flow", "graph": "graph", "dns": "dns", "tls": "tls",
             "beacon": "beacon", "temporal": "temporal"}


@dataclass
class DayResult:
    host: str
    scenario: str
    expected: str
    fires: list[int]                 # bucket indices that reached "ripple"
    detections: list[dict[str, Any]]  # one per labelled window


def _reference(clean: list[dict[tuple[str, str], list[float | None]]]
               ) -> dict[tuple[str, str], tuple[list[list[float]], list[float]]]:
    """Per-bucket-index reference values, plus a pooled fallback.

    Keyed by the bucket's position in the day, so "normal at 09:00" is compared with 09:00 and
    not with 03:00. The pooled list is only a fallback for indices with too few samples; using it
    as the primary reference is what let the diurnal curve masquerade as cross-channel agreement
    (measured 2026-11-12: 4.4 false alarms per host-day, three of four clean days firing).
    """
    by_index: dict[tuple[str, str], list[list[float]]] = {}
    pooled: dict[tuple[str, str], list[float]] = {}
    for series in clean:
        for key, values in series.items():
            index_lists = by_index.setdefault(key, [])
            for index, value in enumerate(values):
                if value is None:
                    continue
                while len(index_lists) <= index:
                    index_lists.append([])
                index_lists[index].append(float(value))
                pooled.setdefault(key, []).append(float(value))
    return {key: (by_index.get(key, []), pooled.get(key, [])) for key in pooled}


def _pvalue_at(reference: dict[tuple[str, str], tuple[list[list[float]], list[float]]],
               key: tuple[str, str], index: int, score: float) -> float:
    """Empirical p against the same time of day, falling back to the pooled hour only if thin."""
    per_index, pooled = reference.get(key, ([], []))
    bucket = per_index[index] if index < len(per_index) else []
    values = bucket if len(bucket) >= 8 else pooled
    return empirical_pvalue(score, values)


def _persistent(fires: list[int], minimum: int) -> list[int]:
    """Keep only runs of at least `minimum` consecutive firing buckets.

    WHY: the project's own definition says a ripple is persistent or repeated. A single window
    that clears the bar is a burst, and the first corpus run proved the point -- one clean day,
    one burst and one benign new service all produced isolated fires. Persistence is not a
    post-hoc filter invented to make the numbers look good; it is the definition applied.
    """
    if minimum <= 1:
        return fires
    kept: list[int] = []
    run: list[int] = []
    for bucket in fires:
        if run and bucket == run[-1] + 1:
            run.append(bucket)
        else:
            if len(run) >= minimum:
                kept.extend(run)
            run = [bucket]
    if len(run) >= minimum:
        kept.extend(run)
    return kept


def evaluate_days(days: list[HostDay],
                  reference: dict[tuple[str, str], tuple[list[list[float]], list[float]]],
                  *, max_p: float = 0.05, min_consecutive: int = 3,
                  grace_minutes: int = 60, min_families: int = 2,
                  min_scales: int = 2) -> list[DayResult]:
    results: list[DayResult] = []
    for day in days:
        series = channel_series(day)
        fires: list[int] = []
        firing_scales: dict[int, list[str]] = {}
        firing_families: dict[int, list[str]] = {}
        for bucket in range(len(day.bytes_out)):
            evidence = []
            for (channel, scale), values in series.items():
                score = values[bucket] if bucket < len(values) else None
                if score is None or not math.isfinite(float(score)):
                    continue
                p = _pvalue_at(reference, (channel, scale), bucket, float(score))
                if not math.isfinite(p):
                    continue
                evidence.append(ChannelEvidence(
                    channel=channel, family=FAMILY_OF[channel], scale=scale,
                    model_id=channel, model_version="corpus", score=float(score),
                    pvalue=float(p), freshness_s=0.0, present=True))
            if not evidence:
                continue
            verdict = fuse(evidence, max_p=max_p, min_families=min_families,
                           min_scales=min_scales)
            if verdict.status == "ripple":
                fires.append(bucket)
                firing_scales[bucket] = list(verdict.scales)
                firing_families[bucket] = list(verdict.families)
        fires = _persistent(fires, min_consecutive)

        detections: list[dict[str, Any]] = []
        if day.label:
            start = day.label.start_minute // BUCKET_MINUTES
            end = day.label.end_minute // BUCKET_MINUTES
            inside = [b for b in fires if start <= b < end]
            grace_end = end + grace_minutes // BUCKET_MINUTES
            within_grace = [b for b in fires if start <= b < grace_end]
            carried = within_grace or inside
            detections.append({
                "scenario": day.label.scenario,
                "amplitude": day.label.amplitude,
                "duration_min": day.label.end_minute - day.label.start_minute,
                "expected": day.label.expected,
                "detected": bool(inside),
                "detected_with_grace": bool(within_grace),
                "latency_min": (min(inside) - start) * BUCKET_MINUTES if inside else None,
                "scales": sorted({s for b in carried for s in firing_scales.get(b, [])}),
                "families": sorted({f for b in carried for f in firing_families.get(b, [])}),
            })
        results.append(DayResult(host=day.host, scenario=day.scenario,
                                 expected=(day.label.expected if day.label else "clean"),
                                 fires=fires, detections=detections))
    return results


def _wilson(successes: int, total: int, z: float = 1.96) -> tuple[float, float]:
    """Wilson interval: a rate on 18 samples deserves an interval, not a bare percentage."""
    if total == 0:
        return (0.0, 1.0)
    phat = successes / total
    denom = 1 + z * z / total
    centre = (phat + z * z / (2 * total)) / denom
    half = z * math.sqrt(phat * (1 - phat) / total + z * z / (4 * total * total)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def summarise(results: list[DayResult], *, min_consecutive: int = 3) -> dict[str, Any]:
    positive_days = [r for r in results if r.expected == "ripple"]
    negative_days = [r for r in results if r.expected != "ripple"]
    detected = [r for r in positive_days if any(d["detected"] for d in r.detections)]
    detected_grace = [r for r in positive_days
                      if any(d.get("detected_with_grace") for d in r.detections)]
    scale_usage: dict[str, int] = {}
    family_usage: dict[str, int] = {}
    for result in positive_days:
        for detection in result.detections:
            if not detection.get("detected_with_grace"):
                continue
            for scale in detection.get("scales", []):
                scale_usage[scale] = scale_usage.get(scale, 0) + 1
            for family in detection.get("families", []):
                family_usage[family] = family_usage.get(family, 0) + 1
    latencies = [d["latency_min"] for r in positive_days for d in r.detections
                 if d["detected"] and d["latency_min"] is not None]

    cells: dict[str, dict[str, Any]] = {}
    for result in positive_days:
        for detection in result.detections:
            key = f"amp={detection['amplitude']:.2f}|dur={detection['duration_min']}m"
            cell = cells.setdefault(key, {"detected": 0, "total": 0, "latencies": []})
            cell["total"] += 1
            if detection["detected"]:
                cell["detected"] += 1
                if detection["latency_min"] is not None:
                    cell["latencies"].append(detection["latency_min"])

    for cell in cells.values():
        low, high = _wilson(cell["detected"], cell["total"])
        cell["rate"] = round(cell["detected"] / cell["total"], 3) if cell["total"] else 0.0
        cell["ci95"] = [round(low, 3), round(high, 3)]
        cell["median_latency_min"] = (
            sorted(cell["latencies"])[len(cell["latencies"]) // 2] if cell["latencies"] else None)

    false_alarms = sum(len(r.fires) for r in negative_days)
    return {
        "min_consecutive_buckets": min_consecutive,
        "positive_host_days": len(positive_days),
        "detected_host_days": len(detected),
        "detection_rate": round(len(detected) / len(positive_days), 3) if positive_days else 0.0,
        "detection_ci95": [round(x, 3) for x in _wilson(len(detected), len(positive_days))],
        "detected_with_grace": len(detected_grace),
        "detection_rate_with_grace": (round(len(detected_grace) / len(positive_days), 3)
                                      if positive_days else 0.0),
        "detection_ci95_with_grace": [
            round(x, 3) for x in _wilson(len(detected_grace), len(positive_days))],
        "scale_usage": dict(sorted(scale_usage.items())),
        "family_usage": dict(sorted(family_usage.items())),
        "median_latency_min": sorted(latencies)[len(latencies) // 2] if latencies else None,
        "negative_host_days": len(negative_days),
        "false_alarm_windows": false_alarms,
        "false_alarms_per_host_day": (round(false_alarms / len(negative_days), 3)
                                      if negative_days else None),
        "by_scenario": {
            scenario: {
                "days": sum(1 for r in negative_days if r.scenario == scenario),
                "fired": sum(1 for r in negative_days if r.scenario == scenario and r.fires),
            }
            for scenario in sorted({r.scenario for r in negative_days})
        },
        "cells": dict(sorted(cells.items())),
    }


__all__ = ["DISCORD_WINDOW", "ROLLING_1H", "DayResult", "channel_series", "evaluate_days",
           "summarise"]
