"""Cluster/database status collection for the CLI and TUI.

Every probe is individually fault-tolerant and reports *why* it failed rather
than raising: a control plane that crashes when the thing it monitors is down is
worse than useless (you cannot use it to find out that the thing is down).

Latency is always reported from the database's own point of view where possible
(`system.query_log`, `now() - max(ts)`), because wall-clock comparisons between
the admin host and the database are a classic source of bogus "stale data"
alarms.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class Probe:
    """One checked thing, with an explicit outcome."""

    name: str
    ok: bool
    detail: str = ""
    value: Any = None
    latency_ms: float = 0.0


@dataclass
class HealthReport:
    probes: list[Probe] = field(default_factory=list)
    fetched_at: float = field(default_factory=time.time)

    @property
    def ok(self) -> bool:
        return all(p.ok for p in self.probes) if self.probes else False

    def by_name(self, name: str) -> Probe | None:
        return next((p for p in self.probes if p.name == name), None)

    def add(self, probe: Probe) -> None:
        self.probes.append(probe)


# Table -> human label. Ordered by operational relevance, not alphabetically.
KEY_TABLES = [
    ("flows", "NetFlow rows"),
    ("flows_aggregated", "aggregate windows"),
    ("zeek_conn", "Zeek connections"),
    ("zeek_dns", "Zeek DNS queries"),
    ("zeek_notice", "Zeek notices"),
    ("netflow_anomalies", "anomalies"),
    ("alert_events", "alert events"),
    ("ml_models", "model runs"),
    ("baseline_history", "baselines"),
]


def _timed(fn):
    t0 = time.perf_counter()
    try:
        return fn(), (time.perf_counter() - t0) * 1000, None
    except Exception as exc:  # noqa: BLE001 - probe must never raise
        return None, (time.perf_counter() - t0) * 1000, exc


def collect_health(client, settings) -> HealthReport:
    """Probe ClickHouse and the pipeline. Never raises."""
    report = HealthReport()

    # 1. Connectivity + server version.
    def ping():
        return client.query("SELECT version()").result_rows[0][0]

    ver, ms, err = _timed(ping)
    report.add(Probe(
        "clickhouse", ok=err is None,
        detail=f"server {ver}" if ver else f"unreachable: {err}",
        value=ver, latency_ms=ms,
    ))
    if err is not None:
        # Nothing else can be probed; report that plainly.
        report.add(Probe("pipeline", ok=False, detail="not probed: no database connection"))
        return report

    # 2. Row counts per key table (missing table => not an error at boot).
    def counts():
        out: dict[str, int | None] = {}
        for table, _label in KEY_TABLES:
            try:
                out[table] = client.query(
                    f"SELECT count() FROM weirvern.{table}"  # noqa: S608 - fixed table list
                ).result_rows[0][0]
            except Exception:  # noqa: BLE001
                out[table] = None
        return out

    counts_val, ms, err = _timed(counts)
    if err is None and counts_val is not None:
        missing = [t for t, n in counts_val.items() if n is None]
        report.add(Probe(
            "tables", ok=not missing,
            detail=(f"{len(counts_val) - len(missing)}/{len(counts_val)} present"
                    + (f"; missing: {', '.join(missing)}" if missing else "")),
            value=counts_val, latency_ms=ms,
        ))

    # 3. Ingestion freshness — how long since the newest flow arrived.
    def freshness():
        rows = client.query(
            "SELECT dateDiff('second', max(timestamp), now()) FROM weirvern.flows"
        ).result_rows
        return rows[0][0] if rows and rows[0][0] is not None else None

    age_s, ms, err = _timed(freshness)
    if err is None:
        if age_s is None:
            report.add(Probe(
                "ingest_freshness", ok=False, latency_ms=ms,
                detail=(
                    "no flow data yet. The most common cause is an exporter "
                    "pointing at the CONTAINER port instead of the NodePort: send "
                    "NetFlow to <node-ip>:32055 and sFlow to :32063, NOT 2055/6343 "
                    "(those are cluster-internal). Check with: "
                    "tcpdump -i <iface> -nn 'udp and port 2055'"
                ),
            ))
        else:
            age_s = float(age_s)
            report.add(Probe(
                "ingest_freshness", ok=age_s < 900,  # 15 min => ingest is alive
                detail=f"newest flow {_human_age(age_s)} ago",
                value=age_s, latency_ms=ms,
            ))

    # 4. Zeek freshness (only meaningful if the sensor is enabled).
    def zeek_freshness():
        rows = client.query(
            "SELECT dateDiff('second', max(ts), now()) FROM weirvern.zeek_conn"
        ).result_rows
        return rows[0][0] if rows and rows[0][0] is not None else None

    z_age, ms, err = _timed(zeek_freshness)
    if err is None and z_age is not None:
        z_age = float(z_age)
        report.add(Probe(
            "zeek_freshness", ok=z_age < 900,
            detail=f"newest Zeek record {_human_age(z_age)} ago",
            value=z_age, latency_ms=ms,
        ))

    # 5. Model freshness — when did each detector last train?
    def models():
        return client.query(
            "SELECT model_type, max(trained_at) AS last_trained, "
            "argMax(metrics, trained_at) AS metrics, count() AS runs "
            "FROM weirvern.ml_models GROUP BY model_type ORDER BY model_type"
        ).result_rows

    mrows, ms, err = _timed(models)
    if err is None and mrows:
        report.add(Probe(
            "models", ok=True,
            detail=f"{len(mrows)} detector(s) with training history",
            value=mrows, latency_ms=ms,
        ))
    elif err is None:
        report.add(Probe("models", ok=False, detail="no training runs recorded", value=[], latency_ms=ms))

    # 6. Alert activity in the last 24h, split by outcome.
    def alerts():
        return client.query(
            "SELECT reason, count() FROM weirvern.alert_events "
            "WHERE sent_at >= now() - INTERVAL 24 HOUR GROUP BY reason ORDER BY count() DESC"
        ).result_rows

    arows, ms, err = _timed(alerts)
    if err is None:
        report.add(Probe(
            "alerts_24h", ok=True,
            detail="; ".join(f"{r[0]}: {r[1]}" for r in arows) or "none in 24h",
            value=arows, latency_ms=ms,
        ))

    return report


def recent_anomalies(client, limit: int = 25, min_score: float = 0.5) -> list[tuple]:
    """Most recent anomalies for the UI. Returns [] on any failure."""
    try:
        return client.query(
            "SELECT detected_at, src_addr, anomaly_score, severity, detected_by_models "
            "FROM weirvern.netflow_anomalies WHERE anomaly_score >= %(s)s "
            "ORDER BY detected_at DESC LIMIT %(n)s",
            parameters={"s": min_score, "n": limit},
        ).result_rows
    except Exception as exc:  # noqa: BLE001
        logger.debug("recent_anomalies failed: %s", exc)
        return []


def top_talkers(client, hours: int = 24, limit: int = 10) -> list[tuple]:
    """Highest-volume talkers recently (works from aggregates)."""
    try:
        return client.query(
            "SELECT src_addr, sum(total_bytes) AS bytes, sum(flow_count) AS flows, "
            "uniqExact(dst_addr) AS dsts FROM weirvern.flows "
            "WHERE timestamp >= now() - INTERVAL %(h)s HOUR "
            "GROUP BY src_addr ORDER BY bytes DESC LIMIT %(n)s",
            parameters={"h": hours, "n": limit},
        ).result_rows
    except Exception as exc:  # noqa: BLE001
        logger.debug("top_talkers failed: %s", exc)
        return []


def _human_age(seconds: float) -> str:
    s = int(seconds)
    if s < 60:
        return f"{s}s"
    if s < 3600:
        return f"{s // 60}m{s % 60}s"
    if s < 86400:
        return f"{s // 3600}h{(s % 3600) // 60}m"
    return f"{s // 86400}d{(s % 86400) // 3600}h"


human_age = _human_age
