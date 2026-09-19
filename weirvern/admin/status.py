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
from weirvern.admin.mode import MODE_WEIR  # noqa: E402


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


# Setting names that must NEVER be sent to a browser. The GUI has no authentication, so anything
# it returns is readable by anyone who can reach the port -- and this list is a DENY-list applied
# by name, so a new secret added to Settings later is caught by the pattern rather than by someone
# remembering to add it here.
_SECRET_HINTS = ("password", "token", "secret", "key", "credential", "passwd")

# Names that carry a credential but do NOT read like one. The pattern above catches the obvious
# cases and anything named consistently in future; these are the exceptions whose names would
# otherwise sail through -- `pushover_user` is the Pushover USER KEY, an account identifier that
# is only useful together with the API token, so it is a secret with an innocuous name.
# Pattern first, then explicit: a name that does not announce itself still has to be listed.
_SECRET_NAMES = frozenset({"pushover_user_key", "pushover_api_token"})


def _is_secret(name: str) -> bool:
    """Whether a setting's VALUE must be withheld from an unauthenticated page."""
    low = name.lower()
    return low in _SECRET_NAMES or any(hint in low for hint in _SECRET_HINTS)


def _redact(name: str, value):
    """A setting's display value: the value, or the fact that it is set.

    A secret is reported as SET or NOT SET rather than blanked, because "unset" and "hidden" are
    different facts and an operator debugging an authentication failure needs to know which one
    they have. The value itself never leaves the process.
    """
    # A BOOLEAN IS NEVER A SECRET. `capture_password` name-matches the pattern but its value is
    # a switch, not a credential -- and hiding it as "(not set)" would take away exactly the fact
    # an operator needs ("are we capturing passwords?"). Redaction applies to the value a secret
    # would carry, so a bool is reported as the state it is.
    if isinstance(value, bool):
        return "enabled" if value else "disabled"
    if _is_secret(name):
        if value in (None, ""):
            return "(not set)"
        return f"(set, {len(str(value))} chars)"
    if value in (None, ""):
        return "(not set)"
    return value


# The settings worth showing, grouped as the Settings tab displays them. Listed EXPLICITLY rather
# than introspected: a settings object is not a data model, and dumping every attribute would
# expose internals (paths, credentials) through an unauthenticated port by accident.
_SETTINGS_GROUPS: list[tuple[str, str, list[tuple[str, str]]]] = [
    ("detect", "Detection", [
        ("retrain_every_h", "retrain every (h)"),
        ("retrain_window_h", "retrain window (h)"),
        ("detect_interval_s", "detect interval (s)"),
        ("base_threshold", "alert threshold"),
        ("min_agreement", "minimum agreement"),
    ]),
    ("sensor", "Sensor", [
        ("sensor_mode", "mode"),
        ("zeek_iface", "Zeek interface"),
        ("mgmt_iface", "management interface"),
        ("zeek_log_dir", "Zeek log dir"),
        ("tail_file", "NetFlow tail file"),
        ("intercept_targets", "intercept targets"),
        # These three are NOT Settings attributes -- the CLI reads them from the environment
        # directly (`weirvern intercept` falls back to them) and they are ConfigMap keys. They
        # are still worth showing, because enabling weir mode depends on them. `_SOURCE` records
        # that they come from the environment rather than from the settings object, so the row
        # does not pretend to be a preference it is not.
        ("intercept_segment", "intercept segment"),
        ("intercept_addr", "intercept address"),
        ("intercept_gateway", "intercept gateway"),
        ("reverse_dns", "reverse DNS"),
    ]),
    ("runtime", "Storage and runtime", [
        ("clickhouse_host", "ClickHouse host"),
        ("clickhouse_port", "ClickHouse port"),
        ("clickhouse_db", "ClickHouse database"),
        ("clickhouse_user", "ClickHouse user"),
        ("clickhouse_password", "ClickHouse password"),
        ("model_dir", "model directory"),
        ("pushover_enabled", "Pushover"),
        ("pushover_user_key", "Pushover user key"),
        ("pushover_api_token", "Pushover API token"),
        ("pushover_cooldown_s", "Pushover cooldown (s)"),
        ("pushover_max_per_hour", "Pushover max/hour"),
        ("namespace", "namespace"),
        ("version", "version"),
    ]),
]


def _running_version(backend) -> str:
    """The image tag the pod is actually running.

    Asked of the cluster because the in-package `__version__` literal DRIFTS: it read 0.4.0
    while the deployment ran 0.5.6, which would misreport the version of every other setting
    shown beside it. Returns "(unknown)" rather than falling back to the literal -- an operator
    who sees "unknown" will look; one who sees a plausible wrong number will not.
    """
    if backend is None:
        return "(unknown)"
    try:
        ps = backend.ps()
    except Exception:  # noqa: BLE001
        return "(unknown)"
    best = ""
    for svc in ps or []:
        name = (getattr(svc, "name", "") or "").lower()
        image = getattr(svc, "image", "") or ""
        if not image:
            continue
        tag = image.rsplit(":", 1)[-1] if ":" in image else image
        # Prefer the GUI's own image (this page IS the GUI), then the worker: both are built from
        # the same Containerfile, so either answers "what version is deployed".
        if "gui" in name:
            return tag
        if "worker" in name and not best:
            best = tag
    return best or "(unknown)"


def settings_overview(settings=None, namespace: str = "", backend=None) -> dict:
    """The EFFECTIVE configuration, for the Settings tab. Read-only by design.

    WHY READ-ONLY. The GUI is served on a LAN port with no authentication. Anything an HTTP
    request can write is therefore a way to reconfigure a sensor from the network -- and the
    About tab carried the same reasoning before it was removed. So this reports what is running
    and where to change it, rather than offering knobs it cannot safely accept.

    SECRETS ARE REPORTED AS SET OR NOT SET, never in value. The redaction is by NAME pattern, so
    a new credential added later is caught by the pattern rather than by memory.
    """
    import os

    rows: dict[str, list[dict]] = {}
    for key, _title, fields in _SETTINGS_GROUPS:
        out: list[dict] = []
        for attr, label in fields:
            value = getattr(settings, attr, None) if settings is not None else None
            # WHERE the value came from. Without this, "the field does not exist", "the field is
            # set but empty" and "the field is unset" all render identically as "(not set)" --
            # which is how three rows for non-existent fields survived review.
            source = ("setting" if (settings is not None and hasattr(settings, attr))
                      else "env")
            if attr in ("reverse_dns", "namespace", "version"):
                source = "derived"
            if attr == "reverse_dns":
                # Not a Settings field: the resolver reads it from the environment directly.
                value = os.environ.get("WEIRVERN_REVERSE_DNS") or "private (default)"
            elif attr == "namespace":
                # runtime.NAMESPACE is the single definition the backends use; asking it rather
                # than threading a parameter means this row cannot disagree with the cluster the
                # rest of the page is describing.
                if not namespace:
                    try:
                        from weirvern.admin.runtime import NAMESPACE as _NS  # noqa: PLC0415

                        namespace = _NS
                    except Exception:  # noqa: BLE001
                        namespace = "(unknown)"
                value = namespace or "(unknown)"
            elif attr == "version":
                # NOT `weirvern.__version__`: that literal reads 0.4.0 while the image tag is
                # 0.5.6, so it would tell an operator they are running a version they are not.
                # A wrong version is worse than no version -- it makes every other row suspect.
                # The running image is authoritative, and it is only knowable from the cluster.
                value = _running_version(backend)
            elif value is None:
                # Fall back to the environment: these keys are env-driven and the process may be
                # reading them from the ConfigMap rather than a literal default. The name is
                # uppercased, which is the convention every key in this project follows.
                value = os.environ.get(attr.upper())
            out.append({
                "key": attr,
                "label": label,
                "value": _redact(attr, value),
                # A secret is flagged so the UI can say WHY it shows no value, instead of leaving
                # the reader to wonder whether the field is broken.
                "secret": _is_secret(attr),
                # setting | env | derived -- so the UI can show that a blank is an env-only key
                # rather than a broken preference.
                "source": source,
            })
        rows[key] = out
    return {"available": True, "reason": "", "groups": rows,
            "titles": {key: title for key, title, _ in _SETTINGS_GROUPS}}


def _staleness(newest: dict[str, str], interval_h: float) -> list[dict]:
    """Per-detector age of the last retrain, and whether it exceeds the interval.

    Returns a list rather than a dict so the ORDER is stable for a chart legend, sorted stalest
    first -- the thing needing attention is at the top rather than wherever a dict happened to
    order it.

    A DETECTOR THAT HAS NEVER TRAINED IS STALE, with age None. Reporting it as fresh because
    there is no timestamp would be the same class of mistake as counting a never-trained
    detector as scheduled (see worker._oldest_trained_at): a missing measurement must not read
    as a healthy one.
    """
    from datetime import datetime

    known = ["Isolation Forest", "Gradient Boosting", "DBSCAN", "Adaptive Baseline"]
    rows: list[dict] = []
    for name in known:
        stamp = newest.get(name)
        age_h: float | None = None
        if stamp:
            try:
                when = datetime.fromisoformat(stamp)
                now = datetime.now(when.tzinfo) if when.tzinfo else datetime.now()
                age_h = (now - when).total_seconds() / 3600
            except (ValueError, TypeError):
                age_h = None
        rows.append({
            "model": name,
            "last_trained": stamp or "",
            "age_h": round(age_h, 2) if age_h is not None else None,
            # Never trained, or older than the configured interval.
            "stale": age_h is None or age_h > interval_h,
            "never_trained": age_h is None,
        })
    # SORT: never-trained first (the most urgent state -- there is no model at all, not an old
    # one), then by age descending. The key is an explicit tuple rather than arithmetic on a
    # value that can be None, which is what made an earlier version raise TypeError.
    rows.sort(key=lambda r: (0 if r["never_trained"] else 1, -(r["age_h"] or 0.0)))
    return rows


def model_overview(client, hours: int = 72, settings=None) -> dict:
    """Everything the Models view needs, in one round trip per panel.

    WHY THIS IS NOT A SCATTER PLOT OF EVERY ANOMALY: a young deployment has very few
    anomalies (three, at the time of writing). A scatter of three points looks like a
    rendering failure, and padding it with synthetic rows would be worse -- an analyst
    cannot tell invented data from real. So each panel is built from data that is
    genuinely deep at any volume:

      * training history   -- one row per retrain (96 in the first 7 hours)
      * score distribution -- every score the models have produced, including the ones
                              below the alert threshold, which is what shows whether the
                              threshold sits in a sensible place
      * ensemble agreement -- which models fire together, from detected_by_models
      * feature deviations -- per-feature actual vs baseline, from feature_contributions

    Returns {"available": False, "reason": ...} rather than raising or returning empty
    structures, so the frontend can say WHY a panel is blank instead of showing nothing.
    """
    import json

    out: dict = {"available": True, "hours": hours}

    # 1. Training history: the models maturing. Sample counts grow as the window fills.
    try:
        rows = client.query(
            "SELECT model_type, trained_at, training_sample_count, current_weight, "
            "metrics FROM weirvern.ml_models "
            "WHERE trained_at >= now() - INTERVAL %(h)s HOUR "
            "ORDER BY trained_at",
            parameters={"h": hours},
        ).result_rows
    except Exception as exc:  # noqa: BLE001 - a panel must not break the page
        return {"available": False, "reason": f"training history query failed: {exc}"}

    hist: dict[str, list] = {}
    for mtype, trained_at, n, weight, metrics in rows:
        try:
            m = json.loads(metrics) if metrics else {}
        except (ValueError, TypeError):
            m = {}
        hist.setdefault(mtype, []).append({
            "t": _iso(trained_at),
            "n": int(n or 0),
            "w": float(weight or 1.0),
            "metrics": m,
        })
    out["training_history"] = hist
    out["run_count"] = sum(len(v) for v in hist.values())

    # 1b. PER-DETECTOR STALENESS, because the training history alone could not show it.
    #
    # WHY THIS EXISTS. Isolation Forest, Gradient Boosting and DBSCAN went 16 hours without a
    # retrain against a 6-hour interval, and this view rendered that as three tidy lines with
    # plenty of points -- because it plotted run COUNT, not RECENCY. A model whose last retrain
    # was 16 hours ago looks identical to one retrained a minute ago if you only count runs.
    #
    # So each detector now carries when it last trained, how long ago that was in hours, and
    # whether that exceeds the configured interval. `stale` is computed HERE rather than in the
    # browser so the TUI and the GUI cannot disagree about whether a model is overdue.
    # The interval comes from settings when the caller passes them, so the panel compares
    # against the SAME number the worker schedules on. Falling back to the documented default
    # keeps this callable from a test that has no settings rather than failing on it.
    try:
        interval_h = float(getattr(settings, "retrain_every_h", 6) or 6)
    except (TypeError, ValueError):
        interval_h = 6.0
    newest: dict[str, str] = {}
    for mtype, runs in hist.items():
        # `_iso` returns None for a NULL timestamp, and `max()` over a list containing None
        # raises TypeError against a str. A row with no trained_at is not evidence of a run at
        # all, so it is excluded rather than sorted -- measured: this crashed the whole Models
        # view with "'>' not supported between instances of 'NoneType' and 'NoneType'".
        stamps = [run["t"] for run in (runs or []) if run["t"]]
        if stamps:
            newest[mtype] = max(stamps)
    out["retrain_interval_h"] = interval_h
    out["staleness"] = _staleness(newest, interval_h)

    # 2. Score distribution across EVERY anomaly, including sub-threshold ones, so the
    #    threshold can be judged rather than assumed.
    try:
        rows = client.query(
            "SELECT anomaly_score, isolation_forest_score, gradient_boosting_score, "
            "dbscan_score, baseline_score, model_agreement, detected_by_models, "
            "severity, primary_deviation_feature, deviation_magnitude, "
            "window_start, src_addr, feature_contributions "
            "FROM weirvern.netflow_anomalies "
            "WHERE detected_at >= now() - INTERVAL %(h)s HOUR "
            "ORDER BY detected_at DESC LIMIT 500",
            parameters={"h": hours},
        ).result_rows
    except Exception as exc:  # noqa: BLE001
        out["available"] = False
        out["reason"] = f"anomaly query failed: {exc}"
        return out

    MODELS = [
        ("isolation_forest_score", "Isolation Forest"),
        ("gradient_boosting_score", "Gradient Boosting"),
        ("dbscan_score", "DBSCAN"),
        ("baseline_score", "Adaptive Baseline"),
    ]
    scores: dict[str, list[float]] = {label: [] for _col, label in MODELS}
    scores["Ensemble"] = []
    points: list[dict] = []
    features: dict[str, dict[str, float]] = {}
    agreement: dict[str, int] = {}

    for r in rows:
        (score, ifs, gb, db, bl, agree, by_models, severity, primary,
         devmag, window, src, contrib) = r
        scores["Isolation Forest"].append(float(ifs or 0))
        scores["Gradient Boosting"].append(float(gb or 0))
        scores["DBSCAN"].append(float(db or 0))
        scores["Adaptive Baseline"].append(float(bl or 0))
        scores["Ensemble"].append(float(score or 0))
        points.append({
            "score": float(score or 0),
            "agreement": float(agree or 0),
            "severity": severity,
            "models": [m for m in (by_models or "").split(",") if m.strip()],
            "primary": primary or None,
            "magnitude": float(devmag or 0),
            "src_addr": src,
        })
        for name in points[-1]["models"]:
            agreement[name.strip()] = agreement.get(name.strip(), 0) + 1
        # Feature deviations, accumulated per feature so the heatmap shows which feature
        # the models keep flagging -- a per-host view would be empty at low volume.
        if contrib:
            try:
                parsed = json.loads(contrib)
            except (ValueError, TypeError):
                parsed = None
            if isinstance(parsed, dict):
                for fname, fv in parsed.items():
                    if not isinstance(fv, dict):
                        continue
                    z = fv.get("z")
                    if z is None:
                        continue
                    agg = features.setdefault(fname, {"z_sum": 0.0, "n": 0, "max_z": 0.0})
                    agg["z_sum"] += abs(float(z))
                    agg["n"] += 1
                    agg["max_z"] = max(agg["max_z"], abs(float(z)))

    out["scores"] = scores
    out["points"] = points
    out["model_counts"] = agreement
    out["feature_deviations"] = [
        {"feature": k, "mean_abs_z": (v["z_sum"] / v["n"]) if v["n"] else 0.0,
         "max_abs_z": v["max_z"], "n": v["n"]}
        for k, v in sorted(features.items())
    ]
    return out


def _iso(value) -> str | None:
    """ISO timestamp for JSON, or None. Kept local so this module needs no new import."""
    if value is None:
        return None
    try:
        return value.isoformat()
    except AttributeError:
        return str(value)


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
        # Other modes reporting from the same sensor, e.g. a passive capture alongside a live
        # intercept. Always a list, never absent, for the reason given below.
        "others": [],
        # True when a `weir` row exists but has gone stale: an intercept ran and stopped, and
        # whether the node was restored cannot be determined from here. Present always, so a
        # consumer never has to distinguish a missing key from a false value.
        "intercept_stopped": False,
        "stale_after_s": HEARTBEAT_STALE_S,
        # Always present so a consumer never has to distinguish a missing key from a
        # null value -- the frontend checks `if (s.error)` and an absent key is a
        # different shape.
        "error": None,
    }
    try:
        # EVERY row, then choose deterministically in Python. `ORDER BY ts DESC LIMIT 1` was the
        # bug: the table is keyed (sensor_id, mode), so a sensor that is intercepting has TWO live
        # rows -- the worker publishes the configured mode (`loch`) and the intercept publishes its
        # own (`weir`) -- and both beat on the same interval. Whichever wrote last won, so the GUI
        # alternated between them on every refresh. The data was never wrong; the reader was
        # picking by wall-clock instead of by meaning.
        #
        # The table is tiny (one row per sensor per mode), so reading all of it is cheaper than
        # being clever in SQL and much easier to reason about.
        rows = list(client.query(
            "SELECT sensor_id, mode, iface, segment, hosts, mappings, running, uptime_s, "
            "restores, refreshes, failures, ts "
            "FROM weirvern.sensor_status FINAL "
            "ORDER BY ts DESC"
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

    # WHICH ROW IS THE SENSOR. Two rules, in order:
    #
    #   1. An INTERCEPTING row (`weir`) wins over a passive one. It describes the same physical
    #      sensor in a strictly more informative state -- it names the segment, the host count and
    #      a live watchdog -- and it exists only while an intercept process is actually running.
    #   2. Otherwise the FRESHEST row wins, but staleness is computed per row and a stale row is
    #      never chosen over a live one.
    #
    # This is deterministic: the same data always produces the same answer, which is what makes
    # the panel stop changing under a refresh.
    def _rank(row: dict):
        ts_value = row.get("ts")
        age = (
            (now - _aware(ts_value)).total_seconds()
            if isinstance(ts_value, datetime.datetime)
            else float("inf")
        )
        fresh = age <= HEARTBEAT_STALE_S
        active = str(row.get("mode") or "") == MODE_WEIR
        return (fresh, active, -age)

    best = max(rows, key=_rank)
    r = best

    # AN INTERCEPT THAT STOPPED IS NOT THE SAME AS NO INTERCEPT.
    #
    # Measured on the live box: an intercept publishes `weir` while the worker publishes the
    # configured `loch`, both under one sensor_id. When the intercept process ENDS, its row goes
    # stale and `_rank` demotes it -- correctly, a stale row must never beat a live one -- so the
    # reader falls back to the live `loch` row and reports "passive capture, not in the path".
    #
    # That is a safe statement only if the restore actually happened. If the intercept was killed
    # before its watchdog could restore (`kill -9` is uncatchable), the forged ARP mappings are
    # STILL in the node's neighbours' caches: the box is in the path, and the panel says it is not.
    # An operator reading that would conclude their traffic is untouched when it is being relayed.
    #
    # So: report that an intercept RAN and stopped, and that the node may need checking. Not a
    # blocker and not a claim of danger -- a claim of uncertainty, which is the honest state, since
    # this reader cannot see the node's ARP caches from inside the GUI pod.
    stopped_intercept = False
    for row in rows:
        if str(row.get("mode") or "") != MODE_WEIR:
            continue
        if row.get("sensor_id") != best.get("sensor_id"):
            continue
        row_ts = row.get("ts")
        if not isinstance(row_ts, datetime.datetime):
            continue
        if (now - _aware(row_ts)).total_seconds() > HEARTBEAT_STALE_S:
            stopped_intercept = True
    out["intercept_stopped"] = stopped_intercept

    # The OTHER row is reported, not discarded. A sensor running both a passive capture and an
    # intercept is a real and useful state, and hiding the second row is how "the panel is
    # silently showing half the truth" bugs start.
    others: list[dict] = []
    for row in rows:
        # Same SENSOR, different mode. Filtering on sensor_id matters: several worker replicas
        # report under their own pod names, and without it a different replica's heartbeat would
        # be listed as another mode of this sensor.
        if row.get("sensor_id") != best.get("sensor_id"):
            continue
        if row.get("mode") == best.get("mode"):
            continue
        row_ts = row.get("ts")
        if not isinstance(row_ts, datetime.datetime):
            continue
        row_age = (now - _aware(row_ts)).total_seconds()
        if row_age > HEARTBEAT_STALE_S:
            continue
        others.append({
            "mode": str(row.get("mode") or ""),
            "iface": str(row.get("iface") or ""),
            "hosts": int(row.get("hosts") or 0),
            "age_s": round(row_age, 1),
        })
    out["others"] = others
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
