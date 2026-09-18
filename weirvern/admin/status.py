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

import datetime
import logging
import time
from collections.abc import Callable
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
    """Highest-volume talkers recently.

    QUERIES flows_aggregated, NOT flows. THE BUG: this used to read
    `sum(total_bytes), sum(flow_count)` from `weirvern.flows`, but those columns
    only exist on the AGGREGATED table. ClickHouse raised

        Code: 47. Unknown expression or identifier `total_bytes`

    and because this helper catches every exception and returns [] (deliberately,
    so a UI never crashes on a query error), the effect was an ALWAYS-EMPTY Top
    Talkers panel in both the TUI and the web GUI, with nothing logged at a level
    anyone would see. It never surfaced earlier because no test asserted the panel
    had content, and an empty table looks like a quiet network.
    """
    try:
        return client.query(
            "SELECT src_addr, sum(total_bytes) AS bytes, sum(flow_count) AS flows, "
            # max(), not uniqExact(): the aggregate table already stores the count
            # of distinct destinations PER WINDOW in unique_dst_ips, so summing
            # across windows would double-count a host that talks to the same
            # destination in every window. max() is the honest "how wide did this
            # host's fan-out get", which is the question the column answers.
            "max(unique_dst_ips) AS dsts FROM weirvern.flows_aggregated "
            "WHERE window_start >= now() - INTERVAL %(h)s HOUR "
            "GROUP BY src_addr ORDER BY bytes DESC LIMIT %(n)s",
            parameters={"h": hours, "n": limit},
        ).result_rows
    except Exception as exc:  # noqa: BLE001
        # WARNING rather than debug: an empty talkers panel is indistinguishable
        # from a silent network, so this failure needs to be visible.
        logger.warning("top_talkers failed: %s", exc)
        return []


def anomalies_detailed(client, limit: int = 100, min_score: float = 0.0) -> list[dict]:
    """Anomalies WITH the explainability columns, as dicts.

    `recent_anomalies` returns five columns as tuples, which is enough for a
    one-line TUI row. The GUI needs the WHY: which feature deviated, by how much,
    and per-feature contributions. Those live in columns the TUI never reads, and
    re-querying them per row would be N+1 queries from the browser.

    Dicts rather than tuples because the web layer serialises them directly and a
    positional tuple would silently misalign if a column is ever added.
    """
    try:
        res = client.query(
            "SELECT detected_at, window_start, src_addr, anomaly_score, confidence, "
            "severity, detected_by_models, model_agreement, "
            "isolation_forest_score, gradient_boosting_score, dbscan_score, baseline_score, "
            "primary_deviation_feature, primary_deviation_zscore, deviation_magnitude, "
            "feature_contributions, baseline_comparison "
            "FROM weirvern.netflow_anomalies WHERE anomaly_score >= %(s)s "
            "ORDER BY detected_at DESC LIMIT %(n)s",
            parameters={"s": min_score, "n": limit},
        )
        cols = list(res.column_names)
        return [dict(zip(cols, row, strict=False)) for row in res.result_rows]
    except Exception as exc:  # noqa: BLE001
        logger.debug("anomalies_detailed failed: %s", exc)
        return []


def host_detail(client, src_addr: str, hours: int = 24) -> dict:
    """Everything the host drill-down shows for ONE address.

    Deliberately one function returning one dict rather than several endpoints:
    the browser renders the whole page from a single response, so a partial failure
    yields a page with an explicit null section instead of a half-loaded view.

    Every sub-query is individually guarded. A missing Zeek table (the sensor may
    not be enabled on a given deployment) must degrade that SECTION, not fail the
    whole drill-down.
    """
    out: dict = {
        "src_addr": src_addr, "hours": hours,
        "totals": None, "top_destinations": [], "top_ports": [],
        "timeline": [], "anomalies": [], "zeek_services": [],
    }

    def _q(sql: str, params: dict, key: str, cast: Callable = list) -> None:
        try:
            res = client.query(sql, parameters=params)
            out[key] = cast(res.result_rows)
        except Exception as exc:  # noqa: BLE001
            # WARNING and recorded in the payload, not debug. Two real bugs lived
            # behind this handler (a wrong table and a wrong column name), and in
            # both cases the only symptom was an empty panel in the UI -- which is
            # indistinguishable from a host with no activity. An operator needs to
            # be able to tell "nothing here" from "the query is broken".
            logger.warning("host_detail %s failed: %s", key, exc)
            out.setdefault("_errors", {})[key] = str(exc)[:200]

    base = {"a": src_addr, "h": hours}

    _q(
        "SELECT sum(bytes), sum(packets), count(), uniqExact(dst_addr), "
        "uniqExact(dst_port), min(time_flow_start), max(time_flow_start) "
        "FROM weirvern.flows WHERE src_addr = %(a)s "
        "AND time_flow_start >= now() - INTERVAL %(h)s HOUR",
        base, "totals", lambda rows: rows[0] if rows else None,
    )
    _q(
        "SELECT dst_addr, sum(bytes) AS bytes, count() AS flows, uniqExact(dst_port) AS ports "
        "FROM weirvern.flows WHERE src_addr = %(a)s "
        "AND time_flow_start >= now() - INTERVAL %(h)s HOUR "
        "GROUP BY dst_addr ORDER BY bytes DESC LIMIT 15",
        base, "top_destinations",
    )
    _q(
        "SELECT dst_port, proto, sum(bytes) AS bytes, count() AS flows "
        "FROM weirvern.flows WHERE src_addr = %(a)s "
        "AND time_flow_start >= now() - INTERVAL %(h)s HOUR "
        "GROUP BY dst_port, proto ORDER BY flows DESC LIMIT 15",
        base, "top_ports",
    )
    # Hourly buckets, so the sparkline has a shape even for a quiet host. Empty
    # buckets are filled in Python rather than with ClickHouse's WITH FILL, which
    # is easier to reason about and keeps the query portable.
    _q(
        "SELECT toStartOfHour(time_flow_start) AS hr, sum(bytes) AS bytes, count() AS flows "
        "FROM weirvern.flows WHERE src_addr = %(a)s "
        "AND time_flow_start >= now() - INTERVAL %(h)s HOUR GROUP BY hr ORDER BY hr",
        base, "timeline",
    )
    _q(
        "SELECT detected_at, window_start, anomaly_score, severity, detected_by_models, "
        "primary_deviation_feature, baseline_comparison "
        "FROM weirvern.netflow_anomalies WHERE src_addr = %(a)s "
        "AND detected_at >= now() - INTERVAL %(h)s HOUR "
        "ORDER BY detected_at DESC LIMIT 50",
        base, "anomalies",
    )
    # Zeek enrichment, if that sensor is running. Absence is normal, not an error.
    _q(
        "SELECT service, count() AS conns, sum(orig_bytes + resp_bytes) AS bytes "
        # src_addr, NOT id_orig_h. THE BUG: the schema normalizes Zeek's
        # `id_orig_h` to `src_addr` at ingest so the Zeek and NetFlow tables share a
        # join column, but this query kept the raw Zeek field name. ClickHouse
        # raised `Code: 47. Unknown expression or identifier id_orig_h` and the
        # surrounding try/except returned [] -- so the drill-down's Zeek Services
        # panel was empty for every host, including hosts with hundreds of logged
        # connections. Verified against the live database: src_addr returns 483
        # rows for one host where id_orig_h raises.
        "FROM weirvern.zeek_conn WHERE src_addr = %(a)s "
        "AND ts >= now() - INTERVAL %(h)s HOUR AND service IS NOT NULL AND service != '' "
        "GROUP BY service ORDER BY conns DESC LIMIT 12",
        base, "zeek_services",
    )
    return out



def alert_evidence(client, src_addr: str, window_start: str,
                   window_end: str | None = None) -> dict:
    """The RAW records behind one alert -- the actual pivot.

    WHY THIS EXISTS SEPARATELY FROM host_detail: host_detail answers "what has this
    host done in the last N hours", which is an AGGREGATE. An analyst who sees a
    detection needs the opposite: the specific flows and Zeek sessions inside the
    detection's own window that produced that verdict. The anomaly row already
    carries window_start/window_end; nothing read them before, so the one question
    worth asking -- "show me the evidence" -- was unanswerable.

    Bounds are [window_start, window_end] inclusive on both ends. The end defaults to
    the start plus a small epsilon rather than now(), because a detection window is a
    fixed bucket (5 minutes by default) and widening it to now() would drag in
    unrelated later traffic and misrepresent what the model actually saw.
    """
    out: dict = {
        "src_addr": src_addr,
        "window_start": None, "window_end": None,
        "flows": [], "zeek_conn": [], "zeek_dns": [], "notice": [],
        "flow_summary": None,
    }

    def _q(sql: str, params: dict, key: str, cast: Callable = list) -> None:
        try:
            res = client.query(sql, parameters=params)
            out[key] = cast(res.result_rows)
        except Exception as exc:  # noqa: BLE001
            logger.warning("alert_evidence %s failed: %s", key, exc)
            out.setdefault("_errors", {})[key] = str(exc)[:200]

    # Resolve the window. Accept an ISO string from the browser; fall back to the
    # stored window if the caller only supplies an address.
    try:
        res = client.query(
            "SELECT window_start, window_end, anomaly_score, severity, "
            "detected_by_models, baseline_comparison, primary_deviation_feature, "
            "primary_deviation_zscore, feature_contributions "
            "FROM weirvern.netflow_anomalies WHERE src_addr = %(a)s "
            "AND window_start = parseDateTime64BestEffort(%(w)s) LIMIT 1",
            parameters={"a": src_addr, "w": window_start},
        )
        if res.result_rows:
            row = res.result_rows[0]
            out["window_start"] = row[0]
            out["window_end"] = row[1]
            out["anomaly"] = {
                "anomaly_score": row[2], "severity": row[3],
                "detected_by_models": row[4], "baseline_comparison": row[5],
                "primary_deviation_feature": row[6],
                "primary_deviation_zscore": row[7],
                "feature_contributions": row[8],
            }
    except Exception as exc:  # noqa: BLE001
        logger.warning("alert_evidence window lookup failed: %s", exc)
        out.setdefault("_errors", {})["anomaly"] = str(exc)[:200]

    ws = out["window_start"]
    we = out["window_end"]
    if ws is None:
        # No stored window (bad address, or the alert aged out of the TTL). Derive
        # one from the caller's timestamp so the pivot still returns something
        # useful rather than an empty page.
        ws, we = window_start, window_end or window_start

    params = {"a": src_addr, "ws": ws, "we": we}

    # THE EVIDENCE. Raw flows, not aggregates -- these are the records the model
    # scored. Duration is computed from the start/end timestamps because `flows` has
    # no duration column (the real columns are time_flow_start and time_flow_end).
    _q(
        "SELECT time_flow_start, dst_addr, dst_port, proto, bytes, packets, "
        "round(dateDiff('millisecond', time_flow_start, time_flow_end), 1) AS duration_ms "
        "FROM weirvern.flows WHERE src_addr = %(a)s "
        "AND time_flow_start >= %(ws)s AND time_flow_start <= %(we)s "
        "ORDER BY bytes DESC LIMIT 200",
        params, "flows",
    )
    _q(
        "SELECT sum(bytes), sum(packets), count(), uniqExact(dst_addr), "
        "uniqExact(dst_port), min(time_flow_start), max(time_flow_start) "
        "FROM weirvern.flows WHERE src_addr = %(a)s "
        "AND time_flow_start >= %(ws)s AND time_flow_start <= %(we)s",
        params, "flow_summary", lambda rows: rows[0] if rows else None,
    )
    # Zeek sessions in the same window -- the L7 view of the same traffic.
    _q(
        "SELECT ts, dst_addr, dst_port, proto, service, duration, orig_bytes, "
        "resp_bytes, conn_state FROM weirvern.zeek_conn WHERE src_addr = %(a)s "
        "AND ts >= %(ws)s AND ts <= %(we)s ORDER BY ts LIMIT 200",
        params, "zeek_conn",
    )
    # DNS is the highest-signal evidence for exfil and C2, so it is included here
    # rather than left in a table nothing reads.
    _q(
        "SELECT ts, query, qtype, rcode, answers, query_entropy "
        "FROM weirvern.zeek_dns WHERE src_addr = %(a)s "
        "AND ts >= %(ws)s AND ts <= %(we)s ORDER BY ts LIMIT 200",
        params, "zeek_dns",
    )
    _q(
        "SELECT ts, note, msg, actions FROM weirvern.zeek_notice "
        "WHERE src_addr = %(a)s AND ts >= %(ws)s AND ts <= %(we)s "
        "ORDER BY ts LIMIT 50",
        params, "notice",
    )
    return out


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


# ---------------------------------------------------------------------------
# sensor status: what the sensor is ACTUALLY doing
# ---------------------------------------------------------------------------

# How long a heartbeat is trusted. The sensor writes every HEARTBEAT_S; three intervals
# means a single missed write (a slow query, a brief stall) does not flap the display,
# while a dead process is reported within ~45s rather than never.
HEARTBEAT_S = 15
HEARTBEAT_STALE_S = HEARTBEAT_S * 3



def _aware(dt: datetime.datetime) -> datetime.datetime:
    """Make a datetime comparable to ClickHouse's, without inventing an offset.

    ClickHouse returns timezone-AWARE values (in the server's timezone), while
    `datetime.now()` returns a NAIVE one. Mixing them raises TypeError, so one side must be
    labelled -- and the label must be LOCAL, not UTC:

        datetime.now()          -> naive, meaning LOCAL time
        .replace(tzinfo=UTC)    -> WRONG: relabels local time as if it were UTC

    That mistake shifted every age by the container's offset. This deployment runs
    TZ=America/Chicago, so a heartbeat 29 seconds old computed as -17998s -- and because
    `stale` is `age > threshold`, a NEGATIVE age is never stale. A sensor dead for five
    minutes therefore reported `running: True`, which is precisely the failure this feature
    exists to prevent.

    `.astimezone()` on a naive value attaches the system's local timezone, which is what
    the naive value genuinely means. Aware values pass through untouched, and Python then
    compares across timezones correctly -- so this is correct regardless of TZ.
    """
    if dt.tzinfo is None:
        return dt.astimezone()
    return dt


def sensor_status(client, now: datetime.datetime | None = None) -> dict:
    """The sensor's own report of what it is doing, or an honest "unknown".

    WHY THIS EXISTS, AND WHY IT IS NOT JUST THE CONFIG VALUE: the GUI runs in its own pod
    and cannot see the sensor's filesystem, so the configured `SENSOR_MODE` was the only
    thing available to it -- and that is a statement of INTENT, not of reality. The two
    differ exactly when it matters: a weir process that died, or was never started, still
    has SENSOR_MODE=weir in the ConfigMap. Reporting the configured mode as though it were
    the running mode would show "intercepting 2 hosts" for a sensor that is not running.

    THE RULE THIS ENFORCES: a stale heartbeat is reported as NOT RUNNING, never as the
    last known state. That is the same class of bug as the always-empty Top Talkers and
    Zeek Services panels -- a display that looks healthy while being wrong.

    Returns a dict with `running`, `stale`, `age_s`, and the last reported details. Every
    field is present even when nothing was ever reported, so the caller never has to
    distinguish "key missing" from "null value".
    """
    now = _aware(now or datetime.datetime.now())
    out: dict = {
        "reported": False,
        "running": False,
        "stale": False,
        "age_s": None,
        "mode": "",
        "iface": "",
        "segment": "",
        "hosts": 0,
        "mappings": 0,
        "uptime_s": 0.0,
        "restores": 0,
        "refreshes": 0,
        "failures": [],
        "stale_after_s": HEARTBEAT_STALE_S,
        # Always present so a consumer never has to distinguish a missing key from a
        # null value -- the frontend checks `if (s.error)` and an absent key is a
        # different shape.
        "error": None,
    }
    try:
        rows = list(client.query(
            "SELECT mode, iface, segment, hosts, mappings, running, uptime_s, "
            "restores, refreshes, failures, ts "
            "FROM weirvern.sensor_status "
            "ORDER BY ts DESC LIMIT 1"
        ).named_results())
    except Exception as exc:  # noqa: BLE001
        # A missing table is the normal state before the schema Job runs, and it must not
        # be reported as "not running" -- those are different facts and conflating them
        # sends an operator looking for a dead sensor that was never started.
        logger.debug("sensor_status unavailable: %s", exc)
        out["error"] = "sensor status is unavailable"
        return out

    if not rows:
        out["error"] = (
            "no sensor has reported yet. The sensor writes a heartbeat every "
            f"{HEARTBEAT_S}s while it runs, so this means it has not started or cannot "
            "reach ClickHouse."
        )
        return out

    r = rows[0]
    out.update({
        "reported": True,
        "mode": str(r.get("mode") or ""),
        "iface": str(r.get("iface") or ""),
        "segment": str(r.get("segment") or ""),
        "hosts": int(r.get("hosts") or 0),
        "mappings": int(r.get("mappings") or 0),
        "uptime_s": float(r.get("uptime_s") or 0.0),
        "restores": int(r.get("restores") or 0),
        "refreshes": int(r.get("refreshes") or 0),
        "failures": list(r.get("failures") or []),
    })

    ts = r.get("ts")
    reported_running = bool(r.get("running"))
    if isinstance(ts, datetime.datetime):
        # Both sides normalised: see _aware for why this is not just a cast.
        age = (now - _aware(ts)).total_seconds()
        out["age_s"] = round(age, 1)
        out["stale"] = age > HEARTBEAT_STALE_S
        # A stale heartbeat overrides `running`: the process is gone regardless of what its
        # last write claimed, because nothing has written since.
        out["running"] = reported_running and not out["stale"]
        if out["stale"]:
            out["error"] = (
                f"the sensor last reported {_human_age(age)} ago "
                f"(heartbeats are every {HEARTBEAT_S}s), so it is no longer running. "
                f"The most recent mode it reported was '{out['mode']}'."
            )
    else:
        out["error"] = "the sensor heartbeat has an unreadable timestamp"
    return out


def heartbeat(client, *, sensor_id: str, mode: str, iface: str = "", segment: str = "",
              hosts: int = 0, mappings: int = 0, running: bool = False,
              uptime_s: float = 0.0, restores: int = 0, refreshes: int = 0,
              failures: list[str] | None = None) -> bool:
    """Write one heartbeat row. Returns whether it landed.

    Never raises: a sensor that cannot report its status must still capture traffic. The
    failure mode of a missing heartbeat is a dashboard that says "unknown", which is
    recoverable; the failure mode of an exception here is a dead sensor.
    """
    try:
        client.insert(
            "weirvern.sensor_status",
            [[sensor_id, mode, iface, segment, int(hosts), int(mappings),
              1 if running else 0, float(uptime_s), int(restores), int(refreshes),
              list(failures or []), datetime.datetime.now()]],
            column_names=["sensor_id", "mode", "iface", "segment", "hosts", "mappings",
                          "running", "uptime_s", "restores", "refreshes", "failures",
                          "ts"],
        )
        return True
    except Exception as exc:  # noqa: BLE001
        logger.debug("heartbeat write failed: %s", exc)
        return False
