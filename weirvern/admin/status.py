"""Cluster/database status collection for the CLI.

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
import ipaddress
import json
import logging
import re
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from weirvern import addressing
from weirvern.admin import timewindow

from ..clock import age_seconds, as_aware, utcnow

logger = logging.getLogger(__name__)
from weirvern.admin.mode import MODE_SIPHON  # noqa: E402


@dataclass
class Probe:
    """One checked thing, with an explicit outcome.

    ── `ok` IS TRI-STATE, AND THE THIRD VALUE EXISTS FOR A REASON (audit F081) ─────────────────

    `True` is healthy, `False` is a fault, and `None` is NOT APPLICABLE -- the check ran and could
    not measure anything because the thing it measures is not deployed here. A NetFlow-only cluster
    has no capture sensor, so Zeek freshness is neither healthy nor broken there, and collapsing
    that into either value is a lie in one direction or the other:

      * `ok=True` would claim a measurement nothing made, which is the failure this campaign keeps
        finding.
      * `ok=False` would make every NetFlow-only deployment report a fault it does not have, and a
        report that is always failing is one an operator stops reading.

    AN OMITTED PROBE IS NOT AN OPTION, which is what the probe this was added for got wrong: it was
    absent from the report entirely, so a consumer could not distinguish "not applicable" from "the
    check did not run" -- and the missing row read as healthy.

    `HealthReport.ok` treats `None` as neither healthy nor broken, so a not-applicable row cannot
    mask a real failure elsewhere. The row is still PRESENT, which is the whole point: a missing row
    now always means the check did not run.
    """

    name: str
    ok: bool | None
    detail: str = ""
    value: Any = None
    latency_ms: float = 0.0


@dataclass
class HealthReport:
    probes: list[Probe] = field(default_factory=list)
    fetched_at: float = field(default_factory=time.time)

    @property
    def ok(self) -> bool:
        """True when nothing is BROKEN. A not-applicable probe (`ok is None`) is neither.

        `all(p.ok for p in ...)` would have treated None as falsy, so every NetFlow-only deployment
        would report an overall failure for a Zeek probe that has nothing to measure -- the
        always-failing report an operator stops reading. Filtering the Nones keeps a
        not-applicable row from masking a real failure while also not inventing one.
        """
        measured = [p.ok for p in self.probes if p.ok is not None]
        return all(measured) if measured else False

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


def _model_staleness(mrows, settings) -> list[str]:
    """Detector names whose last training is past the retrain cadence (audit F024).

    A THIN ADAPTER, NOT A SECOND STALENESS RULE. `_staleness` already decides what "stale" means
    for this project -- including that a detector which has NEVER trained is stale with age None,
    because a missing measurement must not read as a healthy one. Re-deriving that here is how two
    surfaces end up disagreeing about one dataset, which this project has paid for repeatedly, so
    this converts `ml_models` rows into the shape `_staleness` wants and returns the stale NAMES.

    `mrows` is the probe's own query result: rows of (model_type, last_trained, metrics, runs).
    """
    newest: dict[str, str] = {}
    for row in mrows or []:
        try:
            name, stamp = row[0], row[1]
        except (TypeError, IndexError):
            continue
        if not name:
            continue
        # `str()` because ClickHouse returns a datetime here and `_staleness` parses ISO strings.
        # "" means PRESENT BUT UNTIMESTAMPED, which `_staleness` correctly treats as never-trained.
        newest[str(name)] = "" if stamp is None else str(stamp)

    # ONLY THE DETECTORS THE QUERY ACTUALLY RETURNED. `_staleness` iterates a FIXED list of four
    # known detectors and treats any model absent from its map as never-trained -- correct for
    # `model_overview`, which reads a full history, and WRONG here: this probe's query returns one
    # row per detector that HAS history, so a detector missing from `mrows` was never configured
    # rather than never trained. Measured while writing this: an empty `mrows` made `_staleness`
    # report ALL FOUR detectors as stale, which would have turned "no models yet" into a hard
    # failure on every fresh deployment, and a 1-hour-old single-detector set reported the other
    # three as stale.
    if not newest:
        return []

    interval_h = float(getattr(settings, "retrain_every_h", 6) or 6)
    # `stale` here is a COMPUTED key on the dicts `_staleness` builds, not a table column -- the
    # schema auditor cannot tell the difference and flagged the `.get("stale")` form as a phantom
    # column read, which is a fair complaint about the shape rather than the behaviour. Indexing
    # and naming it keeps the same logic and removes the ambiguity.
    names: list[str] = []
    for entry in _staleness(newest, interval_h):
        model = str(entry["model"])
        if entry["stale"] and model in newest:
            names.append(model)
    return names


def _probe_failed(report, name: str, err: Exception, ms: float) -> None:
    """Record that a probe COULD NOT RUN, instead of omitting its row.

    ── AN ABSENT PROBE IS NOT A PASSING ONE (audit F047) ───────────────────────────────────────

    Six probes in `collect_health` were wrapped in `if err is None:` with NO else branch, so a
    sub-query that raised removed that probe's row from the report entirely. MEASURED by driving the
    real `collect_health` with a stub that fails exactly one query:

        tables raising      -> 5 probes, missing: ['ingest_freshness', 'alerts_24h', 'fingerprint_feed']
        detect_loop raising -> 6 probes, missing: ['detect_loop']

    A consumer reading the report -- the GUI pill, `overall ok`, or a human -- cannot tell "this check
    passed" from "this check never ran", and the failure is attributed nowhere: every row that IS
    present reads normally, so the view looks healthy minus a line nobody counts.

    Same class as F081 (a probe absent because a table was empty) and F024 (row existence read as
    freshness), and it is why `zeek_freshness` reports `ok=None` rather than omitting itself: THE ROW
    IS THE EVIDENCE THAT THE CHECK RAN.

    `ok=False`, not `None`: a probe that cannot run is not a pass, whereas the tri-state `None` means
    "measured, and not applicable here". Collapsing those would make this indistinguishable from the
    case it exists to distinguish.
    """
    report.add(Probe(
        name, ok=False, latency_ms=ms,
        detail=f"this check could not run: {type(err).__name__}: {err}",
    ))


def collect_health(client, settings, user_store=None) -> HealthReport:
    """Probe ClickHouse and the pipeline. Never raises.

    `user_store` (optional) adds the ACCOUNT STORE probe. It is optional rather than required because
    the CLI's `status` path has no store to hand and must not be forced to build one; when it is
    absent the probe reports `ok=None` ("not applicable here") rather than staying silent, per the F047
    rule that a missing row is indistinguishable from a passing one.
    """
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
    else:
        _probe_failed(report, "ingest_freshness", err, ms)

    # 4. Zeek freshness (only meaningful if the sensor is enabled).
    #
    # ── "ONLY MEANINGFUL IF THE SENSOR IS ENABLED" WAS A COMMENT, NEVER A CHECK (F081) ─────────
    #
    # `collect_health` has no way to know whether a capture sensor is deployed for this cluster, so
    # the probe was conditional on DATA EXISTING instead -- which conflates two different facts:
    #
    #   * a cluster with no sensor at all (the NetFlow-only deployment). No rows, correctly.
    #   * a cluster WITH a sensor that has captured nothing. No rows, and that is a fault.
    #
    # Reporting the second as a failure and the first as nothing is the right outcome, but the old
    # code got there by accident and reported BOTH as nothing -- so the fault was invisible. The
    # distinction is now made on evidence rather than on the absence being interpreted: a row must
    # have been written by SOME sensor for the probe to be meaningful, and the heartbeat table is
    # what says a sensor exists.
    def zeek_sensor_deployed() -> bool:
        rows = client.query(
            "SELECT count() FROM weirvern.sensor_status "
            "WHERE ts > now() - INTERVAL 1 DAY"
        ).result_rows
        return bool(rows and rows[0] and int(rows[0][0] or 0) > 0)

    def zeek_freshness():
        rows = client.query(
            "SELECT count(), dateDiff('second', max(ts), now()) FROM weirvern.zeek_conn"
        ).result_rows
        if not rows or not rows[0]:
            return None, None
        n = int(rows[0][0] or 0)
        if n == 0:
            return 0, None
        age = rows[0][1]
        return n, (None if age is None else float(age))

    z_rows, ms, err = _timed(zeek_freshness)
    if err is None:
        n_records, z_age = z_rows if z_rows else (None, None)
        if n_records == 0 and z_age is None:
            # ── AN ABSENT PROBE IS NOT A PASSING ONE (audit F081, CONFIRMED BY RUNNING IT) ──────
            #
            # This used to add the probe ONLY when an age came back, so an empty `zeek_conn` left
            # NO zeek_freshness row in the report at all. Measured with an empty table:
            #
            #     probes: ['clickhouse', 'tables', 'ingest_freshness', 'models', 'detect_loop', ...]
            #     zeek_freshness present? False
            #
            # A consumer reading `overall ok` could not tell "the sensor is healthy" from "the
            # sensor has never produced a single record" -- the same green-reading-over-work-that-
            # did-not-happen shape as F022 and F024 in this campaign. `ingest_freshness` two probes
            # above already reports its empty case as a FAILURE with a remedy, so the two sibling
            # probes disagreed about how to treat emptiness.
            deployed, _ms2, dep_err = _timed(zeek_sensor_deployed)
            if dep_err is not None or not deployed:
                # NO SENSOR IS DEPLOYED, so an empty zeek_conn is the expected state and this probe
                # has nothing to say. Reported as `ok=None` rather than omitted: the row IS present
                # so a consumer can see the check ran, but it does not claim health it cannot
                # measure. `None` is the same "not applicable" signal the rest of this report uses
                # for a measurement that does not exist.
                report.add(Probe(
                    "zeek_freshness", ok=None, latency_ms=ms,
                    detail=(
                        "no capturing weirling is deployed in this cluster (no heartbeat in the last "
                        "24h), so there is no Zeek freshness to measure. This row is present so "
                        "that a MISSING row always means a fault rather than 'not applicable'."
                    ),
                    value=None,
                ))
            else:
                report.add(Probe(
                    "zeek_freshness", ok=False, latency_ms=ms,
                    detail=(
                        "a capturing weirling IS deployed but no Zeek records have EVER been written -- "
                        "zeek_conn is empty, so it has captured nothing. Check that the capture "
                        "DaemonSet is running, that ZEEK_IFACE names a real interface on the node, "
                        "and that the weirling holds NET_RAW."
                    ),
                    value=None,
                ))
        elif z_age is not None:
            report.add(Probe(
                "zeek_freshness", ok=z_age < 900,
                detail=f"newest Zeek record {_human_age(z_age)} ago"
                       + (f" ({n_records} total)" if n_records else ""),
                value=z_age, latency_ms=ms,
            ))
        else:
            # ── THE LAST GAP IN THIS PROBE (audit F047) ─────────────────────────────────────────
            #
            # The branches above cover "no records" and "records with an age". This one covers
            # "records EXIST but the age is NULL", which fell through and added NO row at all -- the
            # same absence F081 fixed one branch up and the same absence F047 fixed across the file.
            # MEASURED by driving collect_health with a stub whose zeek_conn reports count=7 and a
            # NULL age: `zeek_freshness` was simply missing from the report.
            #
            # Records with no measurable age is a real state (`max(ts)` is NULL while rows exist is
            # only possible with a nullable column, but the probe must not CRASH or vanish if the
            # query shape changes to allow it). Reported as a failure of the CHECK rather than as a
            # verdict about the sensor.
            report.add(Probe(
                "zeek_freshness", ok=False, latency_ms=ms,
                detail=(
                    f"zeek_conn holds {n_records} record(s) but the newest timestamp is NULL, so "
                    f"freshness cannot be measured. This is a check failure, not a verdict about the "
                    f"sensor: inspect the ts column for NULLs."
                ),
            ))
    else:
        _probe_failed(report, "zeek_freshness", err, ms)

    # 5. Model freshness — when did each detector last train?
    def models():
        return client.query(
            "SELECT model_type, max(trained_at) AS last_trained, "
            "argMax(metrics, trained_at) AS metrics, count() AS runs "
            "FROM weirvern.ml_models GROUP BY model_type ORDER BY model_type"
        ).result_rows

    mrows, ms, err = _timed(models)
    if err is None and mrows:
        # ── ROW EXISTENCE IS NOT FRESHNESS ────────────────────────────────────────────────
        #
        # CONFIRMED DEFECT (audit F024). This reported `ok=True` on the mere presence of rows
        # in `ml_models`, while the query above it had already SELECTED `max(trained_at)` and
        # then never compared it to anything. MEASURED on the live cluster: every detector's
        # last training was 27.2 HOURS old against RETRAIN_EVERY_H=6 -- 4.5x the interval --
        # and the probe still said `ok=True, "4 detector(s) with training history"`.
        #
        # Combined with F023 (a row was written for a detector that never trained) this made a
        # pipeline that had stopped training indistinguishable from a healthy one. The
        # staleness arithmetic already existed in this module (`_staleness`) but was used only
        # by `model_overview`, not here -- which is why the number was fetched and discarded.
        #
        # A STALE PIPELINE IS NOT "ok, BUT". It is the failure the probe exists to catch: a
        # detector whose artifacts are older than its retrain cadence is scoring from a model
        # fitted on data from another era, and no other probe can see that. So the verdict
        # FOLLOWS the staleness rather than mentioning it beside a green tick.
        try:
            stale = _model_staleness(mrows, settings)
        except Exception as exc:  # noqa: BLE001
            logger.debug("model staleness could not be computed: %s", exc)
            stale = []
        if stale:
            report.add(Probe(
                "models", ok=False,
                detail=(f"{len(stale)} detector(s) STALE (past the "
                        f"{settings.retrain_every_h}h retrain cadence): "
                        + ", ".join(stale[:4])),
                value=mrows, latency_ms=ms,
            ))
        else:
            report.add(Probe(
                "models", ok=True,
                detail=f"{len(mrows)} detector(s) with training history, all within the "
                       f"{settings.retrain_every_h}h cadence",
                value=mrows, latency_ms=ms,
            ))
    elif err is None:
        # WHAT IS MISSING, AND WHY -- MEASURED ON THE LIVE BOX: this read "no training runs recorded",
        # which is true and useless next to a green `ingest_freshness` ("newest flow 2m ago"). The two
        # together look like a broken trainer; the operator's actual question is "will it ever train
        # here?", and answering it needs the input VOLUME, not the absence of an output.
        volume = ""
        try:
            # THE REAL COLUMN NAME (issue #29): `flows` keys its time on `timestamp` -- the
            # aggregate tables use `window_start`, and only the zeek_* tables use `ts` (the
            # codebase says so in soc.py's ingestion series). The old query threw on EVERY
            # call, and the throw was swallowed below, so this probe silently lost its
            # input-volume evidence for good.
            rows = client.query(
                f"SELECT count(), uniqExact(src_addr) FROM weirvern.flows "
                f"WHERE timestamp >= now() - INTERVAL "
                f"{int(getattr(settings, 'detect_window_h', 24))} HOUR"
            ).result_rows
            if rows and rows[0]:
                vol_rows, vol_hosts = int(rows[0][0] or 0), int(rows[0][1] or 0)
                volume = (f" the last {int(getattr(settings, 'detect_window_h', 24))}h hold "
                          f"{vol_rows} flow row(s) from {vol_hosts} host(s); training needs "
                          f"more than that before a detector is stored")
        except Exception as exc:  # noqa: BLE001
            # HONEST, NOT SWALLOWED (issue #29): this used to leave `volume` empty and log
            # only at DEBUG, so a probe that could not READ its evidence read identically to
            # one with nothing to say. The reason now rides in the detail string -- the
            # surface the operator actually reads.
            volume = f" the input volume could not be read: {exc}"
            logger.debug("model input volume could not be read: %s", exc)
        report.add(Probe("models", ok=False,
                         detail="no training runs recorded;" + volume if volume
                         else "no training runs recorded", value=[], latency_ms=ms))
    else:
        _probe_failed(report, "models", err, ms)

    # 6. THE DETECTION LOOP'S OWN HEARTBEAT.
    #
    # ── WHY THIS PROBE EXISTS (audit F015 + F022, which are two views of one gap) ──────────────
    #
    # NOTHING PROBED THE DETECTION LOOP. Measured on the live cluster, while the sweep was
    # analysing ZERO rows: every probe above and below reported ok -- clickhouse, tables,
    # ingest_freshness, zeek_freshness, models, alerts. The container was healthy, data was
    # flowing, models were loaded, and detection was doing nothing.
    #
    # The worker's liveness probe cannot catch this either: it imports `weirvern.config` and
    # proves only that the interpreter and the package on disk work, and the loop swallows every
    # exception and sleeps 30s, so a permanently-failing detection path keeps restarting nothing.
    #
    # THE EVIDENCE IS ALREADY WRITTEN. `AdaptiveBaselineDetector.persist_history` inserts into
    # `baseline_history` with `computed_at = now()` on the path that runs every cycle, and
    # `detection_sweep`'s own writes follow it. So a fresh `computed_at` IS the loop having run --
    # measured: distinct timestamps 300s and 301s apart, matching DETECT_INTERVAL_S exactly.
    #
    # THE THRESHOLD IS DERIVED FROM THE CADENCE, not a literal. A hardcoded 900s would call a
    # deployment with DETECT_INTERVAL_S=1800 dead, and a hardcoded 60s would call a 300s cadence
    # dead on every cycle -- both are the "probe that lies" failure. Three intervals is a margin
    # that tolerates one slow cycle and a ClickHouse hiccup without hiding a stopped loop.
    #
    # AN EMPTY TABLE IS NOT A STALE LOOP, and the two must not be collapsed: no rows at all means
    # detection has never run (or the schema is missing), which is a different fact from rows that
    # stopped arriving. Both are failures here, but the detail says which.
    # ── TWO INDEPENDENT SIGNALS, NOT ONE ───────────────────────────────────────────────────────
    #
    # `baseline_history.computed_at` is written by the baseline detector's train(), and
    # `near_misses.replaced_at` is written by the sweep when a host-window scores. They are
    # different code paths that both run inside a cycle, so a single signal going quiet for a
    # benign reason (nothing scored this window; the baseline had too few samples) must not be
    # read as a stopped loop. THE LOOP RAN IF EITHER IS FRESH -- and `detect_loop` reports both
    # ages so an operator can see which one carried the evidence rather than trusting a verdict
    # with no visible basis.
    def detect_loop():
        # ── THE AGE IS COMPUTED IN SQL, DELIBERATELY ──────────────────────────────────────────
        #
        # Computing it in Python mixes two clocks and two timezones (`datetime.now()` is naive
        # local; ClickHouse returns aware values) -- the trap `_aware()` exists for, and a helper
        # defined far below this probe. Letting the database subtract its own timestamps from its
        # own `now()` avoids the whole class of problem and needs no conversion at all.
        #
        # MEASURED, because the first version of this got it wrong: `dateDiff` against an EMPTY
        # subquery does NOT return 0 or NULL -- it returns the difference from ClickHouse's
        # default datetime, 1790165466 seconds, about 56 years. A guard for `age == 0` was dead
        # code, and a fresh deployment would have been reported as "last cycle 56 years ago"
        # rather than "has never run". So the COUNT decides, and the age is read only when there
        # is something to measure. Verified against the live server:
        #
        #     dateDiff('second', (SELECT max(computed_at) FROM ... WHERE 0), now())  ->  1790165466
        #     dateDiff('second', (SELECT null), now())                              ->  \N
        def one(sql: str) -> float | None:
            rows = client.query(sql).result_rows
            if not rows or not rows[0] or rows[0][0] is None:
                return None
            n = int(rows[0][0])
            if n == 0:
                return None
            age = rows[0][1]
            return None if age is None else float(age)

        base_age = one(
            "SELECT count(), dateDiff('second', max(computed_at), now()) "
            "FROM weirvern.baseline_history"
        )
        near_age = one(
            "SELECT count(), dateDiff('second', max(replaced_at), now()) "
            "FROM weirvern.near_misses"
        )
        return base_age, near_age

    d_ages, ms, err = _timed(detect_loop)
    if err is None:
        cadence = int(getattr(settings, "detect_interval_s", 300) or 300)
        limit_s = max(cadence * 3, 60)
        base_age, near_age = d_ages if d_ages else (None, None)
        fresh = [a for a in (base_age, near_age) if a is not None]
        parts = []
        if base_age is not None:
            parts.append(f"baseline {_human_age(base_age)}")
        if near_age is not None:
            parts.append(f"scores {_human_age(near_age)}")
        evidence = ", ".join(parts) if parts else "no signal at all"
        if not fresh:
            report.add(Probe(
                "detect_loop", ok=False, latency_ms=ms,
                detail=(
                    "the detection loop has NEVER run: no baseline row exists and no host-window "
                    "has been scored, so nothing is being analysed. On a fresh deployment this "
                    "clears once flows arrive; if flows are arriving and this stays, the loop is "
                    "failing before its first write -- check the worker log for "
                    "'Worker loop error'"
                ),
            ))
        else:
            best = min(fresh)
            report.add(Probe(
                "detect_loop", ok=best <= limit_s,
                detail=(
                    f"last cycle {_human_age(best)} ago ({evidence})"
                    + ("" if best <= limit_s else
                       f" -- PAST {_human_age(float(limit_s))}, which is 3x the {cadence}s "
                       f"cadence, so the loop has stopped. Data may still be arriving and every "
                       f"other probe can still read green, because nothing else measures detection")
                ),
                value=best, latency_ms=ms,
            ))
    else:
        _probe_failed(report, "detect_loop", err, ms)

    # 7. Alert activity in the last 24h, split by outcome.
    def alerts():
        return client.query(
            "SELECT reason, count() FROM weirvern.alert_events "
            "WHERE sent_at >= now() - INTERVAL 24 HOUR GROUP BY reason ORDER BY count() DESC"
        ).result_rows

    arows, ms, err = _timed(alerts)
    if err is None:
        # ── A RETURNED ROW IS NOT A WELL-FORMED ROW (audit F047) ─────────────────────────────────
        #
        # This read `r[0]` and `r[1]` for every row, so a row with fewer than two elements raised
        # IndexError straight out of `collect_health` -- taking out the ENTIRE health view, and
        # pointing the traceback at this probe rather than at whatever produced the narrow row.
        # MEASURED by driving the real function with a stub returning `[["log-only"]]`.
        #
        # Row shapes are not a contract the caller can enforce, so a malformed row is REPORTED as a
        # malformed row instead of crashing the report or being silently skipped.
        bad_rows = [r for r in (arows or []) if not hasattr(r, "__len__") or len(r) < 2]
        if bad_rows:
            report.add(Probe(
                "alerts_24h", ok=False, latency_ms=ms,
                detail=(
                    f"the alert-activity query returned {len(bad_rows)} row(s) without the (reason, "
                    f"count) pair, so it could not be summarised: first row {bad_rows[0]!r}. This is "
                    f"a check failure, not a verdict about alerting."
                ),
            ))
        else:
            report.add(Probe(
                "alerts_24h", ok=True,
                detail="; ".join(f"{r[0]}: {r[1]}" for r in (arows or [])) or "none in 24h",
                value=arows, latency_ms=ms,
            ))
    else:
        _probe_failed(report, "alerts_24h", err, ms)

    # 8. The identity feed: is evidence still ARRIVING?
    #
    # ── NOTHING WATCHED THIS, AND IT WENT QUIET FOR TWENTY HOURS (audit F094) ───────────────────
    #
    # `host_fingerprints` is the input to host identification: the raw observations (MAC vendor,
    # DHCP hostname, JA4, software) that `build_identity` classifies. MEASURED on the live sensor
    # while looking for something else: the newest observation was 72,837 seconds old -- 20.2 hours
    # -- while every probe on this page read green. The `identity` probe reports COVERAGE from the
    # VERDICT table, which shrinks slowly as hosts age out of a 7-day window, so a dead feed looks
    # like a stable deployment for most of a week. Nothing in the admin surface reads
    # `host_fingerprints` at all: `grep -c host_fingerprints weirvern/admin/*.py` returns nothing.
    #
    # WHY IT IS A PROBE AND NOT A WARNING ON THE WRITE PATH. The write path already swallows its
    # failures by design -- `_record_observations` logs at DEBUG so a dropped row cannot stop ingest
    # (identification is enrichment; losing flow data would be trading the important thing for the
    # useful one). That design is correct and this probe is the other half of it: if failures are
    # deliberately quiet, something has to measure the RESULT instead, or a total outage and a quiet
    # segment are indistinguishable. The DEBUG-level drop was the reported symptom; the missing
    # measurement is the defect.
    #
    # TRI-STATE, like `zeek_freshness` (F081): a deployment with no Zeek sensor at all writes no
    # observations, correctly, and must not be reported as failing. The distinction is made on
    # EVIDENCE -- a fingerprint row written at any point in the retention -- rather than on absence
    # being interpreted either way. An empty table is `ok=None` and says so.
    def fingerprint_feed():
        return client.query(
            "SELECT dateDiff('second', max(ts), now()), count() "
            "FROM weirvern.host_fingerprints "
            "WHERE ts > now() - INTERVAL 7 DAY"
        ).result_rows

    frows, ms, err = _timed(fingerprint_feed)
    if err is None:
        # ── A RETURNED ROW IS NOT A WELL-FORMED ROW, AND I GOT THIS WRONG FIRST ─────────────────
        #
        # The first version read `frows[0][1]` directly. A one-element row raised IndexError out of
        # `collect_health`, taking out the ENTIRE health view -- and the traceback points at THIS
        # probe, so a malformed result from anywhere would be reported as this check failing. It
        # survived the live deployment only because ClickHouse always returns both columns; a stub
        # with a narrower row exposed it immediately, which is the argument for testing a probe
        # against SHAPES rather than only against a live server.
        row = frows[0] if frows else None
        if row is None or len(row) < 2:
            report.add(Probe(
                "fingerprint_feed", ok=False, latency_ms=ms,
                detail=(
                    "the host-fingerprint query returned no usable row, so the identity feed could "
                    "not be measured. This is a probe failure, not an empty feed: check the query "
                    "against the schema for weirvern.host_fingerprints."
                ),
            ))
        elif not row[1]:
            # No observations in the whole retention window. Either no Zeek sensor is deployed (the
            # NetFlow-only case, where this is correct) or the feed has been dead for a week -- and
            # those are not the same fact, so this reports neither as a pass.
            report.add(Probe(
                "fingerprint_feed", ok=None, latency_ms=ms,
                detail=(
                    "no host-fingerprint observations in the last 7 days, so host identification "
                    "has no input. Correct on a NetFlow-only deployment (no Zeek sensor); a FAULT "
                    "if this cluster has one -- check that the sensor's dhcp/ssl/software logs are "
                    "being written, since a log that stops produces no rows and no error."
                ),
            ))
        else:
            age_s = float(row[0] or 0)
            count = int(row[1])
            # ── THE THRESHOLD COMES FROM THE FEED'S OWN HEALTHY GAPS, MEASURED ─────────────────
            #
            # My first version used 24 hours, on the reasoning that a quiet segment legitimately
            # produces nothing for hours. Then I measured the actual gaps between observations on the
            # live sensor and that reasoning was wrong:
            #
            #     observations: 73   median gap: 73s   p90: 212s   p99: 2,277s
            #
            # A healthy feed produces observations MINUTES apart, not hours -- so a 24h bound would
            # not have flagged the very stall this probe exists for until a full day had passed, and
            # it reported `ok` at 20h17m while the feed was in fact dead. A threshold that only fires
            # after the failure has already run most of a day is barely a probe.
            #
            # Four hours sits an order of magnitude above p99 and well below the measured stall. It
            # is still generous enough for a genuinely idle segment overnight, which is the false
            # positive to avoid: a probe that cries wolf gets ignored, and an ignored probe is how
            # this went unseen in the first place.
            threshold_s = 4 * 3600
            report.add(Probe(
                "fingerprint_feed", ok=age_s < threshold_s,
                detail=(
                    f"newest observation {_human_age(age_s)} ago ({count} in 7d)"
                    + ("" if age_s < threshold_s else
                       ". Host identification has had no input for hours: check the sensor's "
                       "dhcp/ssl/software logs. A log that stops produces no rows and no error, and "
                       "the identity view keeps reporting coverage from stale verdicts for days.")
                ),
                value=age_s, latency_ms=ms,
            ))
    else:
        _probe_failed(report, "fingerprint_feed", err, ms)

    # ── THE ACCOUNT STORE (audit F090) ───────────────────────────────────────────────────────────
    #
    # THE HEALTH VIEW WAS BLIND TO THE LOGIN GATE. Nothing in this module read `user_store`,
    # `has_users` or `USERS_CONFIGMAP`, so a store that could not be read produced no probe, no
    # failure, and an overall report that read green -- while every API read was served WITHOUT AN
    # ACCOUNT. The only signal anywhere was `accounts_note` on `/api/session`, and an operator who is
    # not signed in may never fetch that.
    #
    # The open-read behaviour itself is DELIBERATE and is not changed (see `_accounts_on`: a store
    # that cannot answer is treated as unprovisioned so a broken store cannot lock everyone out of
    # the dashboard). What was missing is that the condition is invisible. This probe makes it a red
    # row instead of a silent posture change.
    #
    # THREE STATES, because "no accounts yet" and "cannot read the accounts" are different facts:
    #
    #   ok=None  the store could not be read, so the gate is off FOR NOW and will be retried. Not a
    #            failure of the pipeline, and not a pass either -- `None` is exactly "measured, and
    #            not applicable".
    #   ok=False the gate is armed but the store is EMPTY, which cannot happen after a successful
    #            bootstrap and means the accounts were lost.
    #   ok=True  accounts exist and reads are gated.
    #
    # No store was handed in (the CLI path) -> `None` with a reason, rather than omitting the row.
    if user_store is None:
        report.add(Probe(
            "account_store", ok=None,
            detail="not probed: no account store available in this process (the worker has none; "
                   "the GUI reports it)",
        ))
    else:
        def _store_state():
            # Deliberately re-reads rather than trusting the cache: F090 was that a FAILED read used
            # to be cached permanently, so a cached "no accounts" is the exact condition this probe
            # must not report as healthy. `load()` now only caches an answered read, so this is the
            # live state.
            records = user_store.snapshot()
            return len(records), getattr(user_store, "exists", None)

        try:
            n_users, exists = _store_state()
            if exists is None:
                report.add(Probe(
                    "account_store", ok=None,
                    detail=(
                        "the account store could not be read, so the login gate is OFF and the "
                        "dashboard is serving reads WITHOUT an account. It is retried on the next "
                        "request, so a transient API failure heals on its own; a persistent one is "
                        "an open dashboard. Check the GUI pod's RBAC and the Kubernetes API."
                    ),
                    value={"users": n_users, "exists": None},
                ))
            elif n_users == 0:
                report.add(Probe(
                    "account_store", ok=False,
                    detail=(
                        "the account store exists but holds NO accounts, so the login gate is OFF. "
                        "Bootstrap creates the admin on first startup, so this should not persist -- "
                        "the accounts may have been lost."
                    ),
                    value={"users": 0, "exists": True},
                ))
            else:
                report.add(Probe(
                    "account_store", ok=True,
                    detail=f"{n_users} account(s); reads are gated",
                    value={"users": n_users, "exists": True},
                ))
        except Exception as exc:  # noqa: BLE001
            _probe_failed(report, "account_store", exc, 0.0)

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
#
# EVERY row also carries a plain-language explanation (see `_SETTINGS_HELP` below), rendered as
# the "?" help on the Settings tab. Written for an operator setting this up for the first time:
# what the setting does, what the default is, and what happens when it changes. A settings page
# that shows a value without explaining it forces the reader into the source, which is the
# opposite of "setup should be easy".
_SETTINGS_GROUPS: list[tuple[str, str, list[tuple[str, str]]]] = [
    ("detect", "Detection", [
        ("retrain_every_h", "retrain every (h)"),
        ("retrain_window_h", "retrain window (h)"),
        ("detect_interval_s", "detect interval (s)"),
        ("base_threshold", "alert threshold"),
        ("min_agreement", "minimum agreement"),
        # The corroboration bar for high/critical escalation. Now a real Settings field:
        # it was previously a detector constant that the GUI advertised as editable, so an
        # edit validated and changed nothing. A row exists only while a field exists behind it.
        ("strong_signal", "strong signal bar"),
    ]),
    ("sensor", "Weirling", [
        ("sensor_mode", "mode"),
        ("zeek_iface", "Zeek interface"),
        ("mgmt_iface", "management interface"),
        ("zeek_log_dir", "Zeek log dir"),
        ("tail_file", "NetFlow tail file"),
        ("intercept_targets", "intercept targets"),
        # These three are NOT Settings attributes -- the CLI reads them from the environment
        # directly (`weirvern intercept` falls back to them) and they are ConfigMap keys. They
        # are still worth showing, because enabling siphon mode depends on them. `_SOURCE` records
        # that they come from the environment rather than from the settings object, so the row
        # does not pretend to be a preference it is not.
        ("intercept_segment", "intercept segment"),
        ("intercept_addr", "intercept address"),
        ("intercept_gateway", "intercept gateway"),
        # The IN-LINE channel: two ports, one bridge, enforcement without siphon.
        ("channel_upstream", "channel upstream port"),
                ("channel_downstream", "channel downstream port"),
        # Whether the in-line channel's crossing traffic becomes flow records.
        ("channel_netflow", "channel flow capture"),
        # The other in-line source: a live siphon intercept relays through this box too, and its
        # traffic can be metered the same way. One tap per box -- see the tooltip.
        ("siphon_netflow", "intercept flow capture"),
        # Traffic exclusion. Editable, because a scanner appearing on the network is exactly the
        # thing an operator needs to respond to without a redeploy.
        ("exclude_cidrs", "exclude from learning"),
        ("capture_exclude_cidrs", "exclude at capture"),
    ]),
    # DNS-VIEW BEHAVIOUR, NOT A SENSOR'S (WSM-1, 2026-10-18). reverse_dns used to sit in the
    # Weirling group, which made "weirling settings" mean the capture AND the DNS view. It is
    # read by the resolver, not by a capture process, so it owns a group the weirling sheet
    # never renders.
    ("dns", "Reverse DNS", [
        ("reverse_dns", "reverse DNS"),
    ]),
    ("sluice", "Sluice Gate", [
        ("sluice_block_domains", "domain blocking"),
        # THE GATE, WHERE ITS SWITCHES LIVE. These five were ConfigMap-only until now: operating
        # the gate meant a patch and a worker restart. Read by the worker, verified from the
        # kernel, and bounded by the same rules the validator enforces (see SETTING_CONTROLS).
        ("sluice_enabled", "enforcement"),
        ("sluice_iface", "enforcement interface"),
        ("sluice_criticality", "block on detections"),
        ("sluice_auto_score", "auto-block threshold"),
        ("sluice_max_block_s", "longest block (s)"),
        ("sluice_interval_s", "re-check interval (s)"),
    ]),
    ("blocklists", "Blocklists", [
        ("blocklist_sync_hours", "sync every (h)"),
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


# PLAIN-LANGUAGE EXPLANATIONS, one per settings row, rendered as the "?" help on the Settings
# tab. Written for an operator who has just deployed Weirvern and is reading the panel top to
# bottom: what this value DOES, what the default is, and what happens when it changes. Kept
# beside the row list so a new row cannot ship without someone having to write one -- a test
# asserts every rendered row has help text.
_SETTINGS_HELP: dict[str, str] = {
    # -- the gate's domain switch and the lists' cadence (2026-10-16)
    "sluice_block_domains": (
        "Whether block-mode DOMAIN rules reach the kernel. On (default), a domain rule in block "
        "mode compiles into the gate's sets and drops what its name resolves to. Off, those "
        "rules keep recording and alerting while address rules keep enforcing -- the switch for "
        "'watch the names first, arm later'. Applying it restarts the worker."),
    "blocklist_sync_hours": (
        "How often imported DNS lists are re-fetched, in hours. Default 24. Lists change between "
        "fetches; a shorter cadence brings new names in sooner at the cost of more downloads. "
        "Disabled lists are skipped either way; custom names are never fetched -- they are yours."),
    # -- detection
    "retrain_every_h": (
        "How often the detectors are retrained on the last training window. Default 6 hours. "
        "Shorter means the models track a changing network faster but use more CPU; longer "
        "means training happens less often and a shift in traffic takes longer to be learned. "
        "The worker restarts are not needed for this one -- it is read on the next sweep."),
    "retrain_window_h": (
        "How much history is used to train the detectors, in hours. Default 72 (3 days). This "
        "window should cover at least one full work-week-ish cycle of your network so 'normal' "
        "includes both busy and quiet periods. Longer is better for stability but slows training "
        "and uses more memory."),
    "detect_interval_s": (
        "How often the detection sweep runs, in seconds. Default 300 (5 minutes). Every sweep "
        "scores the newest flow windows and can raise an alert, so this is also the maximum "
        "delay between suspicious traffic happening and an alert firing."),
    "base_threshold": (
        "The score a host-window must reach (0-1) before it is considered an anomaly at all. "
        "Default 0.35. Lower means more alerts and more false positives; higher means fewer "
        "alerts but a real attack may pass unnoticed. The Models tab's near-miss panel shows "
        "what almost crossed this line, which is the honest way to move it."),
    "min_agreement": (
        "The fraction of detectors that must agree (0-1) before a score is taken seriously. "
        "Default 0.33. At 0.33 with four detectors, two of them agreeing is enough. Raising it "
        "toward 1.0 demands consensus and cuts false positives, at the cost of missing attacks "
        "only one detector's method can see."),
    "strong_signal": (
        "The score (0-1) at which a single detector counts as a STRONG signal for escalation to "
        "high/critical severity. Default 0.85. A single strong detector escalates only when "
        "corroborated by a second detector or by a structural signature (like a zero-byte scan)."),
    # -- sensor
    "sensor_mode": (
        "'loch' (default) watches traffic passively from a mirrored/SPAN port or TAP -- it "
        "cannot affect your network. 'siphon' puts this host in the traffic path by ARP-forging "
        "the gateway mapping, so it can see traffic a mirror cannot AND must never fail closed. "
        "Switching to siphon requires the siphon overlay to be applied first (it grants the "
        "weirling and the worker their capabilities; the mode gate checks it) and it starts the "
        "supervised intercept. Changing this restarts the capture sensor and the worker."),
    "zeek_iface": (
        "The network interface the weirling CAPTURES from -- the dedicated NIC connected to a "
        "switch mirror/SPAN port or a passive TAP. It must not be the same interface as the "
        "management port, and should not be a bridge member: a weirling pointed at the wrong NIC "
        "captures mostly broadcast noise and looks healthy while seeing almost nothing."),
    "mgmt_iface": (
        "The interface carrying the default route, SSH and the cluster API. The weirling never "
        "captures from it; it is used to DETECT when the capture interface is pointed at the "
        "wrong NIC. Changing it restarts the weirling briefly."),
    "channel_upstream": (
        "The port of an IN-LINE weirling that faces the NETWORK (toward the router/switch), for "
        "when this box sits physically between a device and the network instead of on a mirror "
        "port. With CHANNEL_DOWNSTREAM it forms one bridge, and the Sluice Gate's blocks then "
        "drop real traffic while the weirling stays in passive 'loch' mode -- nothing is forged. "
        "Leave both empty for a normal passive sensor."),
    "channel_downstream": (
        "The port that faces the PROTECTED DEVICE or segment. Both channel ports must be "
        "different interfaces, wired in line and joined into one bridge. The gate verifies "
        "that from the kernel -- ports on one forwarding bridge, link up, bridge-nf enabled -- "
        "before it will claim the channel is active, and names exactly what is missing when "
        "it is not."),
    "siphon_netflow": (
        "While a siphon intercept is live, the sensor's own interface is metered the way the "
        "channel's ports are: bounded capture segments, summarised into IPFIX, into the same "
        "`flows` table the channel and any exporter feed. Never on a configured-but-dead intercept "
        "(that would be records of nothing), and it yields to the channel selection when both are "
        "set, because two taps would count each conversation twice."),
    "channel_netflow": (
        "Whether the traffic crossing the IN-LINE channel is summarised into NetFlow records. "
        "'off' (the default) collects nothing from the channel; 'upstream' or 'downstream' names "
        "which port the probe samples -- either port sees every frame crossing the box, so one "
        "is enough. The records go to this deployment's own collector, so they land in the same "
        "Netflow tab and the same model features as the router's export. The probe runs only "
        "while the channel is verified active."),
    "sluice_enabled": (
        "Whether the Sluice Gate enforces block rules at all. Default off, on purpose: "
        "installing Weirvern must not start blocking traffic before anyone has looked at what "
        "it sees. While off, the gate is disarmed and any table left behind by a previous run "
        "is removed; while on, live rules are compiled into the kernel and every block is "
        "TTL-bounded. Turning it off is the one-click way to stop all blocking."),
    "sluice_iface": (
        "The interface the gate enforces on. Empty (the default) resolves automatically: the "
        "channel's bridge when one is verified active, otherwise the capture interface -- "
        "which is what you want on a normal deployment. The management interface is refused: "
        "blocking on the management path would cut off SSH and the cluster API."),
    "sluice_criticality": (
        "'off' (default) means the ensemble's detections alert but never block. 'high' blocks "
        "only high-severity detections with strong agreement, for 30 minutes; 'medium' also "
        "blocks medium severity, for 15 minutes; 'strict' is the widest net. The policy's own "
        "severity and confidence floors still apply, every block lapses on its own, and the "
        "policy only acts while the gate is enabled."),
    "sluice_auto_score": (
        "The operator's own auto-block line, on the fused 0-1 score the ensemble produces. "
        "0 (the default) is off. Set it to 0.9 and any detection scoring 0.9 or above is "
        "blocked on the gate's next pass, for up to the longest-block ceiling; lower it and "
        "more is blocked. It works independently of the severity policy above -- a detection "
        "that clears either one is blocked -- and it only acts while the gate is enabled and "
        "a verified enforcement path is live, so watch the rules the gate files before "
        "lowering it."),
    "sluice_max_block_s": (
        "The ceiling on how long a single block may last, in seconds. Default 3600 (one "
        "hour), maximum 604800 (a week -- the same ceiling the Sluice tab's rule form "
        "offers). The criticality policy's own TTL (15-30 minutes) is usually shorter; this "
        "bound exists so no rule can outlive the operator's intent."),
    "sluice_interval_s": (
        "How often the gate re-evaluates its rules, in seconds. Default 60. This is the "
        "maximum delay between filing a block and it being enforced, and between a rule "
        "lapsing and it being lifted -- the worker sleeps in slices no longer than this so "
        "the promise holds. Lower is fresher at the cost of more frequent rule-store reads."),
    "zeek_log_dir": (
        "Where the worker reads Zeek's logs from inside the pod. Default /zeek/logs, shared "
        "between the Zeek capture and the worker via a host directory. Change only if you moved "
        "that mount in the manifests."),
    "tail_file": (
        "The file goflow2 writes NetFlow/sFlow records to as JSONL, which the worker tails. "
        "Default /data/flows.jsonl. Both processes are pinned to the same node because this is "
        "a file, not a network stream."),
    "intercept_targets": (
        "Which hosts the siphon intercept targets, when SENSOR_MODE is 'siphon'. "
        "Comma-separated addresses or CIDRs (CIDRs expand to their hosts), or '*' "
        "for every host on the segment. EMPTY MEANS "
        "NOTHING IS INTERCEPTED: switching the mode does not divert any traffic by "
        "itself. The worker supervises the intercept, so this list (with segment, "
        "address and gateway below) is what it uses."),
    "intercept_segment": (
        "The network segment (CIDR) the siphon intercept operates on, e.g. "
        "198.51.100.0/24. This IS the blast radius: every host in it would have its ARP "
        "cache forged, so name it explicitly. Must match a segment you are authorised "
        "to monitor."),
    "intercept_addr": (
        "The address the intercept assumes on the capture interface while it relays "
        "traffic (the 'one-armed router' address). It must be an address nothing else "
        "uses; the CLI can suggest free ones (`weirvern intercept --dry-run`). Siphon "
        "refuses to start without it."),
    "intercept_gateway": (
        "The gateway address whose identity is forged for the targeted hosts during a "
        "siphon intercept. The watchdog restores these mappings on every exit path, "
        "including crashes. Never name the sensor's own management gateway address."),
    "reverse_dns": (
        "'private' (default) resolves only private addresses, so lookups stay on your network. "
        "'all' also resolves public addresses, which sends every external destination in your "
        "flow data to a DNS resolver -- that leaks what you talk to, so it is explicit. 'off' "
        "disables lookups entirely; addresses display without names."),
    "exclude_cidrs": (
        "Networks excluded from LEARNING, comma-separated (e.g. 192.0.2.0/24). Traffic from "
        "these networks still reaches the weirling and is counted, but the models are not trained "
        "on it, so known-busy scanners do not become each host's 'normal'. Use this for hosts "
        "whose traffic would drown out real anomalies."),
    "capture_exclude_cidrs": (
        "Networks dropped AT CAPTURE, comma-separated. Zeek never records this traffic at all, "
        "so it cannot be reviewed later -- prefer the learning-exclusion list above if you may "
        "want the evidence. Use this only for traffic that must never be stored."),
    # -- runtime
    "clickhouse_host": (
        "Hostname of the ClickHouse service. Default 'clickhouse', the in-cluster Service name. "
        "Change only for an external database."),
    "clickhouse_port": (
        "ClickHouse's HTTP interface port. Default 8123. Change only for an external database "
        "on a non-standard port."),
    "clickhouse_db": (
        "The database holding Weirvern's tables. Default 'weirvern'. The schema Job creates it "
        "if missing."),
    "clickhouse_user": (
        "The ClickHouse user the worker connects as. Default 'weirvern', created by the schema "
        "Job alongside the password below."),
    "clickhouse_password": (
        "The ClickHouse password for the user above. Reported as set/not-set only, never in "
        "value, and never editable from this page: it is a credential, read from the "
        "'weirvern-secrets' Secret at startup."),
    "model_dir": (
        "Where trained model artifacts are saved. Default /models, on a PersistentVolume, so "
        "retrained baselines survive pod restarts. Point this at a volume or you will retrain "
        "from scratch after every restart."),
    "pushover_enabled": (
        "Whether real push notifications are sent. 'off' (default) logs only: every alert is "
        "formatted, recorded to alert_events with reason 'log-only', and nothing is sent. Turn "
        "it ON only after setting both Pushover keys below; enabling without keys fails "
        "visibly, not silently."),
    "pushover_user_key": (
        "Your Pushover user key (from your Pushover account dashboard). Set/not-set only, "
        "never in value. Required before push notifications can be enabled."),
    "pushover_api_token": (
        "The Pushover application API token (created under 'Create an Application' on "
        "pushover.net). Set/not-set only, never in value. Together with the user key above, "
        "this is what delivers alerts to your phone."),
    "pushover_cooldown_s": (
        "Per-source alert cooldown in seconds. Default 1800 (30 minutes): after an alert for a "
        "host, further alerts for the SAME host are suppressed for this long, so one noisy host "
        "cannot flood your phone."),
    "pushover_max_per_hour": (
        "Global cap on alerts per hour. Default 20. Once reached, additional alerts are "
        "suppressed (and counted as suppressed in the Health tab's alert audit) until the hour "
        "rolls over."),
    "namespace": (
        "The Kubernetes namespace the deployment runs in. Default 'weirvern'. Shown for "
        "reference; changing it requires re-applying the manifests, not this page."),
    "version": (
        "The image tag the deployment is actually running, read from the cluster. A version "
        "that differs from what you deployed means a rollout did not finish."),
}


def _running_version(backend) -> str:
    """The version of the code serving this page.

    TWO SOURCES, AND THE ORDER MATTERS. The running image tag is a MEASUREMENT of what is
    deployed; the in-package `__version__` is a statement about the code itself. Prefer the
    measurement when the cluster is reachable.

    The literal alone was the original bug: it read 0.4.0 while the deployment ran 0.5.6, because
    nothing tied the two together. That is now tied by a test
    (test_the_package_version_matches_the_image_tag_declared_in_the_transformer), so the fallback
    is checked rather than trusted.

    The fallback EXISTS because this pod often cannot reach the cluster at all -- the GUI image
    ships no `kubectl` and the Deployment sets automountServiceAccountToken: false. Requiring a
    cluster read would mean reporting "(unknown)" on the normal deployment, which tells an
    operator nothing when they are trying to confirm what they are running.
    """
    if backend is not None:
        try:
            tag = _version_from_backend(backend)
            if tag:
                return tag
        except Exception:  # noqa: BLE001
            pass
    try:
        from weirvern import __version__  # noqa: PLC0415

        return __version__
    except Exception:  # noqa: BLE001
        return "(unknown)"


def _version_from_backend(backend) -> str:
    """The running image tag, or "" when the cluster cannot answer."""
    try:
        ps = backend.ps()
    except Exception:  # noqa: BLE001
        return ""
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
    return best


def settings_overview(settings=None, namespace: str = "", backend=None,
                      configmap: dict | None = None) -> dict:
    """The EFFECTIVE configuration, for the Settings tab. Read-only by design.

    WHY READ-ONLY. The GUI is served on a LAN port with no authentication. Anything an HTTP
    request can write is therefore a way to reconfigure a sensor from the network -- and the
    About tab carried the same reasoning before it was removed. So this reports what is running
    and where to change it, rather than offering knobs it cannot safely accept.

    SECRETS ARE REPORTED AS SET OR NOT SET, never in value. The redaction is by NAME pattern, so
    a new credential added later is caught by the pattern rather than by memory.

    `configmap` IS THE LIVE CLUSTER CONFIGURATION, when the caller has it. THIS PROCESS'S OWN
    ENVIRONMENT IS NOT THE TRUTH: a deployed GUI pod read its ConfigurationMap once at startup,
    and a settings change restarts the WORKER (which reads the new mode) -- not the GUI. So
    after an operator applied `SENSOR_MODE=siphon` and the intercept was demonstrably running,
    the tab still rendered `loch` from the pod's frozen startup env, and the operator
    reasonably concluded the apply had failed. Measured on the first live test, 2026-09-22.
    With the live map passed in, every non-secret row whose ConfigMap key exists is rendered
    from the CLUSTER's value, so the tab shows what is actually running regardless of when
    this process started. None keeps the old behaviour for callers without cluster access
    (workstation runs, tests).
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
            # THE LIVE CLUSTER VALUE WINS OVER THIS PROCESS'S FROZEN VIEW, for every
            # non-derived row whose ConfigMap key actually exists. The pod's env was read
            # once at startup and a settings change restarts the WORKER, not the GUI -- so
            # without this the tab showed `loch` through a demonstrably running intercept
            # (measured, first live test). Secrets are exempt: their value is never carried
            # here either way, and a ConfigMap row for one does not exist.
            from weirvern.admin import cluster_config as _cc  # noqa: PLC0415

            if configmap is not None and source != "derived":
                cm_value = configmap.get(_cc.to_configmap_key(attr))
                if cm_value is not None and not _is_secret(attr):
                    value = cm_value
                    source = "cluster"
            out.append({
                "key": attr,
                "label": label,
                # HOW THIS ROW APPLIES (BF-5): the badge rides the payload, derived from the
                # writer's own restart table -- the UI renders the server's answer instead of
                # restating it (a restated rule is a rule that drifts).
                "applies": _cc.apply_semantics(attr),
                "value": _redact(attr, value),
                # A secret is flagged so the UI can say WHY it shows no value, instead of leaving
                # the reader to wonder whether the field is broken.
                "secret": _is_secret(attr),
                # setting | env | derived | cluster -- so the UI can show that a blank is an
                # env-only key rather than a broken preference, and that a value is what the
                # CLUSTER is running (not what this process read at startup).
                "source": source,
                # The plain-language explanation, rendered as the row's "?" help. "" only when a
                # row was added without one, which a test fails on -- the explanation is part of
                # the row's contract, not a nice-to-have.
                "help": _SETTINGS_HELP.get(attr, ""),
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
                age_h = (utcnow() - as_aware(when)).total_seconds() / 3600
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


def baselines_overview(client) -> dict:
    """The adaptive baseline, made visible.

    WHY THIS EXISTS: the per-host baselines train every cycle and persist to
    `baseline_history`, but nothing in the console showed them -- an operator could watch
    every other detector's training history and staleness while the one detector whose
    whole job is "what is normal for THIS host" had no surface at all, so "I have not
    seen it work" was exactly true: it worked and was invisible.

    Each panel is honest about its own failure: a store that cannot be read says why,
    rather than rendering as "no baselines", which on this surface would be
    indistinguishable from a trainer that died.
    """
    import json as _json

    out: dict = {"available": True}
    try:
        rows = client.query(
            "SELECT src_addr, avg_bytes, stddev_bytes, avg_packets, avg_unique_dsts, "
            "p95_bytes, p99_bytes, p999_bytes, window_hours, computed_at "
            "FROM weirvern.baseline_history "
            "ORDER BY computed_at DESC LIMIT 1 BY src_addr"
        ).result_rows
    except Exception as exc:  # noqa: BLE001 - a panel must not break the page
        return {"available": False, "reason": f"baseline history query failed: {exc}"}

    hosts: list[dict[str, Any]] = [{
        "src_addr": str(r[0]),
        "avg_bytes": float(r[1] or 0),
        "stddev_bytes": float(r[2] or 0),
        "avg_packets": float(r[3] or 0),
        "avg_unique_dsts": float(r[4] or 0),
        "p95_bytes": float(r[5] or 0),
        "p99_bytes": float(r[6] or 0),
        "p999_bytes": float(r[7] or 0),
        "window_hours": int(r[8] or 0),
        "computed_at": _iso(r[9]),
    } for r in rows]
    hosts.sort(key=lambda h: float(h["avg_bytes"]), reverse=True)
    out["hosts"] = hosts
    out["host_count"] = len(hosts)
    out["refreshed_at"] = hosts[0]["computed_at"] if hosts else None
    out["refreshed_age_s"] = _age_seconds(rows[0][9]) if rows else None

    # The BEHAVIOURAL baselines (Zeek) live in the in-memory artifact; their durable record
    # is the training metadata this detector writes after every refresh.
    out["behavioural_hosts"] = None
    out["fingerprint_hosts"] = None
    out["last_trained"] = None
    try:
        mrows = client.query(
            "SELECT argMax(metrics, trained_at) AS m, max(trained_at) AS t "
            "FROM weirvern.ml_models WHERE model_type = 'Adaptive Baseline'"
        ).result_rows
        if mrows and mrows[0][0]:
            m = _json.loads(mrows[0][0])
            out["behavioural_hosts"] = int(m.get("zeek_baselined_hosts") or 0)
            out["fingerprint_hosts"] = int(m.get("hosts_with_fp_history") or 0)
            out["last_trained"] = _iso(mrows[0][1])
    except Exception as exc:  # noqa: BLE001 - the card says so rather than guessing zero
        out["errors"] = {"training": str(exc)}

    # What it has actually FLAGGED -- "is it doing anything" answered with a count, not a
    # hope. Zero is reported as zero; a failed read says it failed.
    try:
        frows = client.query(
            "SELECT count() AS n, max(detected_at) AS last FROM weirvern.netflow_anomalies "
            "WHERE detected_at >= %(since)s AND detected_at <= %(until)s AND baseline_score > 0",
            parameters={**timewindow.w(24)},
        ).result_rows
        out["fired_24h"] = int(frows[0][0] or 0) if frows else 0
        out["last_fired"] = _iso(frows[0][1]) if frows and frows[0][1] else None
    except Exception as exc:  # noqa: BLE001
        out.setdefault("errors", {})["fired"] = str(exc)
        out["fired_24h"] = None
        out["last_fired"] = None
    return out


def _age_seconds(when) -> int | None:
    """Seconds since a datetimes.datetime, naive or aware -- None when it cannot be read."""
    try:
        return max(0, int(age_seconds(when)))
    except Exception:  # noqa: BLE001
        return None


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
            "WHERE trained_at >= %(since)s AND trained_at <= %(until)s "
            "ORDER BY trained_at",
            parameters={**timewindow.w(hours)},
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
    # browser so every consumer cannot disagree about whether a model is overdue.
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
            "WHERE detected_at >= %(since)s AND detected_at <= %(until)s "
            "ORDER BY detected_at DESC LIMIT 500",
            parameters={**timewindow.w(hours)},
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

    # 5. NEAR MISSES (soc-2): windows that came close to the bar, or cleared it and were
    #    dropped by the agreement gate. These are the false-negative surface -- the evidence
    #    a tuning loop needs that the Anomalies view structurally cannot show (it lists only
    #    what was flagged). Degrades to an empty list with a reason rather than failing the
    #    whole view: on a deployment that has not re-run its schema job since this feature
    #    shipped, the table does not exist yet, and "the panel is blank because the table is
    #    new" is a different statement from "nothing nearly alerted".
    try:
        nm_rows = client.query(
            "SELECT window_start, window_end, src_addr, anomaly_score, threshold_used, "
            "reason, model_agreement, isolation_forest_score, gradient_boosting_score, "
            "dbscan_score, baseline_score, detected_by_models "
            "FROM weirvern.near_misses FINAL "
            "WHERE window_start >= %(since)s AND window_start <= %(until)s "
            "ORDER BY anomaly_score DESC LIMIT 100",
            parameters={**timewindow.w(hours)},
        ).result_rows
        out["near_misses"] = [
            {"window_start": _iso(r[0]), "window_end": _iso(r[1]), "src_addr": r[2],
             "score": float(r[3] or 0), "threshold": float(r[4] or 0),
             "reason": r[5], "agreement": float(r[6] or 0),
             "models": [m for m in (r[11] or "").split(",") if m.strip()]}
            for r in nm_rows
        ]
        out["near_misses_available"] = True
    except Exception as exc:  # noqa: BLE001
        logger.debug("near_misses unavailable: %s", exc)
        out["near_misses"] = []
        out["near_misses_available"] = False
        out["near_misses_reason"] = (
            "the near-miss table has not been created on this deployment yet "
            "(it arrives with the schema job on the version that added it)"
        )
    return out


def _iso(value) -> str | None:
    """ISO timestamp for JSON, or None. Kept local so this module needs no new import."""
    if value is None:
        return None
    try:
        return value.isoformat()
    except AttributeError:
        return str(value)


def host_identity_view(client) -> dict:
    """Every host's identity verdict, with its evidence and the honest denominator.

    THE COVERAGE FIGURE IS NOT OPTIONAL, and it is why this returns a dict rather than a list.
    A list of 14 identified hosts says nothing about the 231 that were not identified, and a
    count on its own is a reassuring number that answers a different question than the one an
    analyst is asking. So the total seen travels beside the total classified.

    A read failure is reported as `available: False` with a reason, never as an empty list: an
    empty list is a legitimate answer meaning "no host has been identified yet", and the two must
    not look alike.
    """
    from weirvern.host_identity import IDENTITY_WINDOW_DAYS, coverage  # noqa: PLC0415

    try:
        rows = client.query(
            """
            SELECT host, mac, os, os_label, confidence, score, agreeing_sources,
                   signals, disagreement, ja4_structure, software_seen,
                   hostnames_seen, ja4_seen, updated_at
            FROM weirvern.host_identity FINAL
            ORDER BY (confidence = 'high') DESC, score DESC
            LIMIT 500
            """
        ).result_rows
    except Exception as exc:  # noqa: BLE001
        return {
            "available": False,
            "reason": f"cannot read host identity: {type(exc).__name__}: {str(exc)[:200]}",
            "hosts": [], "count": 0, "coverage": None,
        }

    hosts = []
    for (host, mac, os_name, os_label, conf, score, n_src, signals, disagree,
         ja4_values, software, hostnames, ja4_seen, updated) in rows:
        hosts.append({
            "host": str(host), "mac": str(mac or ""), "os": str(os_name),
            "os_label": str(os_label), "confidence": str(conf),
            "score": round(float(score or 0), 3),
            "agreeing_sources": int(n_src or 0),
            "signals": _parse_json(signals),
            "disagreement": _parse_json(disagree),
            "ja4_structure": _parse_json(ja4_values),
            "software_seen": _parse_json(software) or [],
            "hostnames_seen": _parse_json(hostnames) or [],
            "ja4_seen": _parse_json(ja4_seen) or [],
            "updated_at": _iso(updated),
            # VIA `_aware`, because ClickHouse returns timezone-AWARE datetimes and
            # `datetime.now()` is naive -- subtracting them raises TypeError inside the handler,
            # where the route's except converts it into `available: False`. The panel would have
            # reported "cannot read host identity" indefinitely while the data was perfectly
            # readable, and the cause would look like a database problem.
            #
            # `_aware` is used rather than a local fix because it already encodes the harder
            # lesson: the label must be LOCAL, not UTC. Relabelling local time as UTC produced
            # NEGATIVE ages, and `stale = age > threshold` means a negative age is never stale --
            # so a sensor dead for five minutes reported running. One helper, already tested.
            "age_s": ((datetime.datetime.now(datetime.UTC) - _aware(updated)).total_seconds()
                      if updated else None),
        })

    hosts, merged = collapse_identity_rows(hosts)

    try:
        cov = coverage(client)
    except Exception as exc:  # noqa: BLE001
        # Coverage unknown is NOT coverage zero. The panel must be able to say which.
        cov = {"available": False, "reason": str(exc)[:200]}
    return {
        "available": True,
        "window_days": IDENTITY_WINDOW_DAYS,
        "hosts": hosts,
        "count": len(hosts),
        # HOW MANY KEYS WERE FOLDED, named rather than silently deduped: the operator saw two
        # rows, and the surface should be able to say why there is now one.
        "merged": merged,
        "coverage": cov,
    }


def collapse_identity_rows(hosts: list[dict]) -> tuple[list[dict], int]:
    """Fold identity rows whose HOST differs only by case (QA-1-D2).

    MEASURED DEFECT: the store keyed one box twice -- `weirvern` and `Weirvern` -- because the
    hostname arrives from two sources with different capitalisation, and every row then offered
    its own Adopt. Two identities for one box is a truth lie: the operator cannot tell which name
    is real, and adopting either creates the fossil the other just left.

    The row with the stronger evidence wins (higher score, then more agreeing sources, then the
    newer observation). The losers' hostnames/software/JA4 are unioned into the winner so nothing
    observed is lost, their spellings are recorded as `aliases`, and the count of folded rows
    travels back so the caller can say so.
    """
    groups: dict[str, list[dict]] = {}
    for row in hosts:
        key = str(row.get("host") or "").strip().lower()
        groups.setdefault(key, []).append(row)

    out: list[dict] = []
    merged = 0
    for group in groups.values():
        if len(group) == 1:
            out.append(group[0])
            continue
        group.sort(key=lambda r: (float(r.get("score") or 0),
                                  int(r.get("agreeing_sources") or 0),
                                  str(r.get("updated_at") or "")), reverse=True)
        winner = dict(group[0])
        aliases = sorted({str(r.get("host")) for r in group if r.get("host")
                          and str(r.get("host")) != str(winner.get("host"))})
        for fname in ("hostnames_seen", "software_seen", "ja4_seen"):
            union: list = []
            for r in group:
                for v in (r.get(fname) or []):
                    if v not in union:
                        union.append(v)
            if union:
                winner[fname] = union
        winner["aliases"] = aliases
        winner["merged_from"] = len(group)
        merged += len(group) - 1
        out.append(winner)

    out.sort(key=lambda r: (str(r.get("confidence") or "") == "high",
                            float(r.get("score") or 0)), reverse=True)
    return out, merged


def _parse_json(value):
    """Parse a JSON-text column, returning None rather than raising on one bad row."""
    if not value:
        return None
    try:
        return json.loads(value)
    except (ValueError, TypeError):
        return None


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


def top_talkers(client, hours: int = 24, limit: int = 10, *,
                filters: dict | None = None) -> dict:
    """Highest-volume talkers recently.

    QUERIES flows_aggregated, NOT flows. THE BUG: this used to read
    `sum(total_bytes), sum(flow_count)` from `weirvern.flows`, but those columns
    only exist on the AGGREGATED table. ClickHouse raised

        Code: 47. Unknown expression or identifier `total_bytes`

    and because this helper catches every exception and returns [] (deliberately,
    so a UI never crashes on a query error), the effect was an ALWAYS-EMPTY Top
    Talkers panel in the web GUI, with nothing logged at a level
    anyone would see. It never surfaced earlier because no test asserted the panel
    had content,    and an empty table looks like a quiet network.

    AN EMPTY LIST IS NOT A STATE (issue #13, 2026-10-16). The same defect the paragraph above
    describes once is what the `return []` failure paths kept alive: a failed talkers query
    rendered as "No talkers in this window." -- a broken read shown as a quiet network, with the
    failure only in the logs. This now returns the standard `{available, reason, points}` shape
    every sibling helper in soc.py uses, so the panel can say "Cannot draw this: <reason>."
    """
    from weirvern.admin.soc import flow_filter, flow_filter_is_raw  # noqa: PLC0415 -- one definition

    filt, fparams = flow_filter(filters)
    if flow_filter_is_raw(filters):
        # The aggregate has no proto/dst_port columns; with those filters active this panel
        # computes the same answer from the raw flows table (see soc.flow_filter). NOTE: no
        # local import of addressing here -- a function-local import makes the name local for
        # the WHOLE function and broke the aggregate path below it ("cannot access local
        # variable"), measured the same hour it was written.
        try:
            rows = client.query(
                "SELECT src_addr, sum(bytes) AS bytes, count() AS flows, "
                "uniqExact(dst_addr) AS dsts FROM weirvern.flows "
                "WHERE timestamp >= %(since)s AND timestamp <= %(until)s "
                "  AND " + addressing.sql_host("src_addr") + " " + filt +
                "GROUP BY src_addr ORDER BY bytes DESC LIMIT %(n)s",
                parameters={**timewindow.w(hours), "n": limit, **fparams},
            ).result_rows
            return {"available": True, "reason": "", "points": rows}
        except Exception as exc:  # noqa: BLE001
            logger.warning("top_talkers (filtered) failed: %s", exc)
            return {"available": False, "reason": f"the talkers query failed: {type(exc).__name__}",
                    "points": []}
    try:
        rows = client.query(
            "SELECT src_addr, sum(total_bytes) AS bytes, sum(flow_count) AS flows, "
            # max(), not uniqExact(): the aggregate table already stores the count
            # of distinct destinations PER WINDOW in unique_dst_ips, so summing
            # across windows would double-count a host that talks to the same
            # destination in every window. max() is the honest "how wide did this
            # host's fan-out get", which is the question the column answers.
            "max(unique_dst_ips) AS dsts FROM weirvern.flows_aggregated "
            "WHERE window_start >= %(since)s AND window_start <= %(until)s " + filt +
            # NOT EVERY ADDRESS THAT APPEARS IS A HOST (weirvern/addressing.py has the
            # measurement): ranking fe80::/ff02::/224.0.0.251 as talkers made the panel read
            # as broken on the first live segment. The count of what was left out is
            # reported separately by `noise_flows`, so the filter is stated, not silent.
            "  AND " + addressing.sql_host("src_addr") + " "
            "GROUP BY src_addr ORDER BY bytes DESC LIMIT %(n)s",
            parameters={**timewindow.w(hours), "n": limit, **fparams},
        ).result_rows
        return {"available": True, "reason": "", "points": rows}
    except Exception as exc:  # noqa: BLE001
        # WARNING rather than debug: an empty talkers panel is indistinguishable
        # from a silent network, so this failure needs to be visible.
        logger.warning("top_talkers failed: %s", exc)
        return {"available": False, "reason": f"the talkers query failed: {type(exc).__name__}",
                "points": []}


def noise_flows(client, hours: int = 24) -> dict:
    """How much recent traffic the host-only panels leave OUT, counted so it can be stated.

    Every panel that ranks hosts now filters non-host addresses (weirvern/addressing.py).
    A filter nobody can see is indistinguishable from data that was never there -- this
    project's named failure mode -- so the count rides in the payload beside the list.
    """
    try:
        rows = client.query(
            "SELECT count(), sum(total_bytes) FROM weirvern.flows_aggregated "
            "WHERE window_start >= %(since)s AND window_start <= %(until)s AND "
            + addressing.noise_sql("src_addr"),
            parameters={**timewindow.w(hours)},
        ).result_rows
        n, b = (rows[0] if rows else (0, 0))
        return {"available": True, "reason": "", "flows": int(n or 0), "bytes": int(b or 0)}
    except Exception as exc:  # noqa: BLE001
        logger.warning("noise_flows failed: %s", exc)
        return {"available": False,
                "reason": f"noise count query failed: {type(exc).__name__}",
                "flows": 0, "bytes": 0}


def anomalies_detailed(client, limit: int = 100, min_score: float = 0.0, *,
                       host: str = "", severity: str = "", model: str = "") -> list[dict]:
    """Anomalies WITH the explainability columns, as dicts.

    The GUI needs the WHY: which feature deviated, by how much,
    and per-feature contributions. Re-querying them per row would be N+1 queries
    from the browser.

    Dicts rather than tuples because the web layer serialises them directly and a
    positional tuple would silently misalign if a column is ever added.

    ── WHY A FAILURE NOW RAISES INSTEAD OF RETURNING [] ───────────────────────────────────────
    MEASURED DEFECT (found by triaging an independent audit finding, 2026-09-23). This function
    used to catch every exception, log it at DEBUG, and return an empty list. The web handler
    above it has a proper failure path -- `except Exception: return self._error(503, ...)` -- but
    it could never run, because this function never raised. So a database that was unreachable or
    a query that had been broken by a schema change produced HTTP 200 with an empty array, and the
    Anomalies view rendered its normal empty state.

    That is this project's named failure mode in its most consequential place: an operator looking
    at an empty triage queue on a deployment whose detection query is broken sees "nothing to
    review", which is a statement about the network rather than about the query. The log line
    exists, at DEBUG, which no deployment runs.

    The caller distinguishes the cases and says which one it is. `recent_anomalies` (the summary
    counter) keeps its lenient behaviour deliberately -- it is a badge on an overview page, and a
    badge that says "unavailable" is honest where an empty list is not; see its own docstring.
    """
    res = client.query(
        "SELECT detected_at, window_start, src_addr, anomaly_score, confidence, "
        "severity, detected_by_models, model_agreement, "
        "isolation_forest_score, gradient_boosting_score, dbscan_score, baseline_score, "
        "primary_deviation_feature, primary_deviation_zscore, deviation_magnitude, "
        "feature_contributions, baseline_comparison "
        "FROM weirvern.netflow_anomalies WHERE anomaly_score >= %(s)s "
        # THE DASHBOARD-WIDE FILTER (the operator, 2026-10-16): a clicked host or severity is
        # answered BY THIS QUERY -- never by hiding rows the browser already received, which
        # would silently mis-report the total.
        + ("AND src_addr = %(host)s " if host else "")
        + ("AND severity = %(sev)s " if severity else "")
        # THE DETECTOR FILTER (US-5, the quiet-a-noisy-detector job): exact per-name match
        # against the comma-joined list -- `involved()`'s own semantics, so "DBSCAN" can
        # never be shadowed by a longer name that contains it.
        + ("AND arrayExists(m -> trimBoth(m) = %(model)s, "
           "splitByChar(',', detected_by_models)) " if model else "")
        + "ORDER BY detected_at DESC LIMIT %(n)s",
        parameters={"s": min_score, "n": limit, **({"host": host} if host else {}),
                    **({"sev": severity} if severity else {}),
                    **({"model": model} if model else {})},
    )
    cols = list(res.column_names)
    return [dict(zip(cols, row, strict=False)) for row in res.result_rows]


def reason_code(detected_by_models: str, feature: str = "") -> str:
    """A STABLE code for one verdict: the detectors' initials plus the measurement that moved.

    "IF+DBSCAN:bytes_z" -- stable for identical inputs, short enough for a table row, and
    greppable in a ticket. Detector names become initials (an all-caps name like DBSCAN stays
    whole); an unnamed feature reads "score". Deduped, order preserved (the ensemble's order).
    """
    parts: list[str] = []
    for name in str(detected_by_models or "").split(","):
        clean = name.strip()
        if not clean:
            continue
        abbrev = clean if clean.isupper() else "".join(
            word[0].upper() for word in re.split(r"[^A-Za-z0-9]+", clean) if word)
        if abbrev and abbrev not in parts:
            parts.append(abbrev)
    det = "+".join(parts) or "?"
    feat = str(feature or "").strip() or "score"
    return f"{det}:{feat}"


def anomalies_total_count(client, min_score: float = 0.0) -> int:
    """The UNFILTERED count under the same min-score -- the Y in "showing X of Y".

    Deliberately carries NONE of the page's filters (host/severity/model): its whole job is to
    say how many alerts exist before them, so a filtered list can state what it is a subset of.
    Raises like its neighbours: a failed read is the caller's to render, never a zero -- a "0"
    here would read as a quiet network rather than a broken query.
    """
    res = client.query(
        "SELECT count() FROM weirvern.netflow_anomalies WHERE anomaly_score >= %(s)s",
        parameters={"s": float(min_score)},
    )
    return int(res.result_rows[0][0]) if res.result_rows else 0


def anomalies_grouped(client, limit: int = 100, min_score: float = 0.0, *,
                      host: str = "", severity: str = "", model: str = "") -> list[dict]:
    """One row per DISTINCT anomaly, with its occurrence count and its windows.

    The operator, 2026-10-16: "These are identical in anomalies. Add a count column instead of
    showing both. then when you click it it shows each time it happened." WHAT IDENTICAL MEANS,
    exactly: the same detection pass, host, score, severity, models and why. The WINDOW is what
    separates occurrences -- which is why the duplicated rows differed only there -- so the
    windows ride along, CAPPED at 50 per row while the count keeps the true total. Raises on
    failure, like anomalies_detailed: an empty list must mean "nothing", never "the query broke".
    """
    where = ["anomaly_score >= %(s)s"]
    params: dict = {"s": float(min_score), "n": int(limit)}
    if host:
        where.append("src_addr = %(host)s")
        params["host"] = str(host)
    if severity:
        where.append("severity = %(sev)s")
        params["sev"] = str(severity)
    if model:
        # Same exact-name semantics as anomalies_detailed (see its note).
        where.append("arrayExists(m -> trimBoth(m) = %(model)s, "
                     "splitByChar(',', detected_by_models))")
        params["model"] = str(model)
    result = client.query(
        "SELECT detected_at, src_addr, anomaly_score, confidence, severity, "
        "detected_by_models, model_agreement, isolation_forest_score, gradient_boosting_score, "
        "dbscan_score, baseline_score, primary_deviation_feature, primary_deviation_zscore, "
        "deviation_magnitude, feature_contributions, baseline_comparison, "
        "count() AS n, arraySlice(arraySort(groupArray(window_start)), 1, 50) AS windows "
        "FROM weirvern.netflow_anomalies WHERE " + " AND ".join(where) + " "
        "GROUP BY detected_at, src_addr, anomaly_score, confidence, severity, "
        "detected_by_models, model_agreement, isolation_forest_score, "
        "gradient_boosting_score, dbscan_score, baseline_score, primary_deviation_feature, "
        "primary_deviation_zscore, deviation_magnitude, feature_contributions, "
        "baseline_comparison "
        "ORDER BY detected_at DESC LIMIT %(n)s",
        parameters=params,
    )
    names = list(result.column_names)
    rows: list[dict] = []
    for r in result.result_rows:
        row = dict(zip(names, r, strict=False))
        row["windows"] = [w.isoformat() if hasattr(w, "isoformat") else str(w)
                          for w in (row.get("windows") or [])]
        # The newest window headlines the row; the rest live in the expansion.
        row["window_start"] = row["windows"][-1] if row["windows"] else None
        row["n"] = int(row.get("n") or 1)
        # US-9: every alert carries a STABLE reason code -- derived from fields in the GROUP BY,
        # so identical verdicts always read identically.
        row["reason_code"] = reason_code(str(row.get("detected_by_models") or ""),
                                         str(row.get("primary_deviation_feature") or ""))
        rows.append(row)
    return rows


def attach_group_reviews(rows: list[dict], idx: dict[tuple, dict], error: str | None,
                         covered_since=None) -> list[dict]:
    """Per-window review state for grouped anomalies, plus the group's own summary.

    The review index is keyed (window_start, host) -- per OCCURRENCE -- so a group is reviewed
    when every window in it is, and `unreviewed_n` counts the ones that are not. The same
    window-coverage rule as attach_reviews: a window older than the index is UNKNOWABLE, not
    unreviewed. On a read failure every window is marked REVIEW_UNAVAILABLE -- a state we could
    not read must not masquerade as work not done.
    """
    for row in rows:
        wins: list[dict] = []
        unreviewed = 0
        for stamp in row.get("windows") or []:
            when = _parse_stamp(stamp)
            entry = None if error else (idx.get((when, row.get("src_addr"))) if when else None)
            state, note = "", ""
            if error:
                state = REVIEW_UNAVAILABLE
                note = "review state is unavailable (has the schema job run since this feature deployed?)"
            elif entry:
                state = str(entry.get("state") or "")
                note = str(entry.get("note") or "")
            else:
                bound = covered_since
                if bound is not None and bound.tzinfo is not None:
                    bound = bound.replace(tzinfo=None)   # naive-to-naive; see attach_reviews
                if bound is not None and when is not None and when < bound:
                    # Unknowable, not unreviewed -- the same sentence attach_reviews uses.
                    state = REVIEW_UNAVAILABLE
                    note = ("older than the review history this view reads, so a review may "
                            "exist without being shown here")
            if state == "":
                unreviewed += 1
            # reviewed_at rides along so the per-occurrence chip can say WHEN, the same
            # sentence the row-level chip shows; without it every restored occurrence
            # would read "not reviewed yet" while it plainly was (issue #20).
            wins.append({"window": stamp, "review_state": state, "review_note": note,
                         "reviewed_at": (entry.get("reviewed_at") if entry else None)})
        row["windows"] = wins
        row["unreviewed_n"] = int(unreviewed)
        newest = wins[-1] if wins else {}
        row["review_state"] = str(newest.get("review_state") or "")
        row["review_note"] = str(newest.get("review_note") or "")
        _attach_ownership(row)
    return rows


def anomaly_severity_counts(client, *, min_score: float = 0.0, host: str = "") -> dict:
    """How many anomalies carry each severity, under the page's current filters.

    THE SEVERITY FILTER IS DELIBERATELY NOT APPLIED. These counts are the tiles an operator
    clicks to SET that filter; a counts query that consumed its own output would collapse to a
    single tile the moment one is on, and switching severity would become a two-click dance with
    the answer hidden. Min-score and host ARE applied -- they are the questions the tiles answer
    ("of what this page is showing, how much is high"). A failed read is a state, not a zero.
    """
    where = ["anomaly_score >= %(s)s"]
    params: dict = {"s": float(min_score)}
    if host:
        where.append("src_addr = %(host)s")
        params["host"] = str(host)
    try:
        rows = client.query(
            "SELECT severity, count() AS n FROM weirvern.netflow_anomalies WHERE "
            + " AND ".join(where) + " GROUP BY severity ORDER BY n DESC",
            parameters=params,
        ).result_rows
    except Exception as exc:  # noqa: BLE001
        logger.warning("severity counts failed: %s", exc)
        return {"available": False, "reason": f"severity counts failed: {type(exc).__name__}",
                "counts": []}
    return {"available": True, "reason": "", "counts": [
        {"severity": str(r[0] or "unknown"), "count": int(r[1] or 0)} for r in rows]}


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

    base = {"a": src_addr, **timewindow.w(hours)}

    _q(
        "SELECT sum(bytes), sum(packets), count(), uniqExact(dst_addr), "
        "uniqExact(dst_port), min(time_flow_start), max(time_flow_start) "
        "FROM weirvern.flows WHERE src_addr = %(a)s "
        "AND time_flow_start >= %(since)s AND time_flow_start <= %(until)s",
        base, "totals", lambda rows: rows[0] if rows else None,
    )
    _q(
        "SELECT dst_addr, sum(bytes) AS bytes, count() AS flows, uniqExact(dst_port) AS ports "
        "FROM weirvern.flows WHERE src_addr = %(a)s "
        "AND time_flow_start >= %(since)s AND time_flow_start <= %(until)s "
        "GROUP BY dst_addr ORDER BY bytes DESC LIMIT 15",
        base, "top_destinations",
    )
    _q(
        "SELECT dst_port, proto, sum(bytes) AS bytes, count() AS flows "
        "FROM weirvern.flows WHERE src_addr = %(a)s "
        "AND time_flow_start >= %(since)s AND time_flow_start <= %(until)s "
        "GROUP BY dst_port, proto ORDER BY flows DESC LIMIT 15",
        base, "top_ports",
    )
    # Hourly buckets, so the sparkline has a shape even for a quiet host. Empty
    # buckets are filled in Python rather than with ClickHouse's WITH FILL, which
    # is easier to reason about and keeps the query portable.
    _q(
        "SELECT toStartOfHour(time_flow_start) AS hr, sum(bytes) AS bytes, count() AS flows "
        "FROM weirvern.flows WHERE src_addr = %(a)s "
        "AND time_flow_start >= %(since)s AND time_flow_start <= %(until)s GROUP BY hr ORDER BY hr",
        base, "timeline",
    )
    _q(
        "SELECT detected_at, window_start, anomaly_score, severity, detected_by_models, "
        "primary_deviation_feature, baseline_comparison "
        "FROM weirvern.netflow_anomalies WHERE src_addr = %(a)s "
        "AND detected_at >= %(since)s AND detected_at <= %(until)s "
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
        "AND ts >= %(since)s AND ts <= %(until)s AND service IS NOT NULL AND service != '' "
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
        "flows": [], "zeek_conn": [], "zeek_dns": [], "notice": [], "zeek_ssl": [],
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
            "primary_deviation_zscore, feature_contributions, "
            # The worker writes these on every anomaly and the Pushover alert prints them, but
            # the evidence query never selected them -- so the ONE page an analyst opens to read
            # the measurement behind an alert could never show a technique. The front end asks
            # for parseTechniques(d.anomaly.attack_techniques) and got undefined every time.
            "attack_techniques, attack_label "
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
                "attack_techniques": row[9], "attack_label": row[10],
            }
    except Exception as exc:  # noqa: BLE001
        logger.warning("alert_evidence window lookup failed: %s", exc)
        out.setdefault("_errors", {})["anomaly"] = str(exc)[:200]

    # ── THE DECISION TRAIL BELONGS ON THE EVIDENCE PAGE (US-D1) ────────────────────────────────
    # The chain reads observed -> detected -> explained -> ruled -> done, and the last two stages
    # are the review store's. Without this merge the page could show the measurement behind an
    # alert but never whether anyone had ruled on it -- so "nobody has looked" and "this was
    # accepted three days ago" rendered identically.
    if out.get("anomaly") is not None:
        try:
            idx, rev_err, covered_since = review_index(client)
            probe = dict(out["anomaly"])
            probe["window_start"] = out.get("window_start")
            probe["src_addr"] = src_addr
            attach_reviews([probe], idx, rev_err, covered_since=covered_since)
            out["anomaly"]["review_state"] = probe.get("review_state", "")
            out["anomaly"]["review_note"] = probe.get("review_note", "")
        except Exception as exc:  # noqa: BLE001
            # A failed review read is "unavailable", never "unreviewed": the chain must not
            # claim nobody has ruled when the ruling simply could not be read.
            logger.warning("alert_evidence review lookup failed: %s", exc)
            out["anomaly"]["review_state"] = REVIEW_UNAVAILABLE
            out["anomaly"]["review_note"] = ""
            out.setdefault("_errors", {})["review"] = str(exc)[:200]

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
    # TLS sessions WITH THEIR FINGERPRINTS -- the records a JA4-driven detection is ABOUT.
    # The models score `zeek_ja4_novelty` and the page used to show only flows, conn, DNS and
    # notices, so an alert that fired on a brand-new TLS stack had no pivot to the sessions
    # that carried it. `ja4_orig` rides along for the rare comparison against a pre-sort value.
    _q(
        "SELECT ts, dst_addr, dst_port, version, server_name, ja4, ja4_orig, "
        "validation_status FROM weirvern.zeek_ssl WHERE src_addr = %(a)s "
        "AND ts >= %(ws)s AND ts <= %(we)s ORDER BY ts LIMIT 100",
        params, "zeek_ssl",
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


def fingerprint_hosts(client, ja4: str, days: int = 7) -> dict:
    """Which hosts have presented this JA4 fingerprint, and when.

    THE HUNTING QUESTION THE IDENTITY CARD CANNOT ANSWER. The card shows ONE host's
    fingerprints; the question an analyst arrives with points the other way -- "who else uses
    this stack?" -- and it is the pivot from a fingerprint seen in one alert to every other host
    that presents it. Reads the RAW ssl records, not the identity verdicts, because a fleet
    still being identified must still be searchable, and a fingerprint seen twice on one host
    and once on another counts as two and one here.
    """
    token = (ja4 or "").strip()
    if not token:
        return {"ja4": "", "hosts": [], "count": 0, "reason": "no fingerprint given"}
    try:
        rows = client.query(
            """
            SELECT src_addr, count() AS sessions, min(ts) AS first_seen,
                   max(ts) AS last_seen, uniqExact(dst_addr) AS peers
            FROM weirvern.zeek_ssl
            WHERE ja4 = %(f)s AND ts >= now() - INTERVAL %(d)s DAY
            GROUP BY src_addr ORDER BY sessions DESC LIMIT 200
            """,
            parameters={"f": token, "d": int(days)},
        ).result_rows
    except Exception as exc:  # noqa: BLE001
        logger.warning("fingerprint lookup failed: %s", exc)
        return {"ja4": token, "hosts": [], "count": 0,
                "reason": f"could not read the ssl records: {type(exc).__name__}"}
    if not rows:
        # "COUNT 0" ALONE READS AS "NOTHING TO SEE" -- and a valid fingerprint whose hosts aged
        # out of the window is a different fact from one never seen (found 2026-10-16, in the
        # operator's "identity... it's not working"). The all-time probe turns the blank into a
        # sentence, and it is cheap: one indexed count.
        reason = f"no host presented this fingerprint in the last {int(days)} days"
        try:
            seen = client.query(
                "SELECT count(), max(ts) FROM weirvern.zeek_ssl WHERE ja4 = %(f)s",
                parameters={"f": token},
            ).result_rows
            total = int(seen[0][0]) if seen else 0
            if total:
                reason += (f"; it WAS seen {total} time(s) before that, most recently "
                           f"{seen[0][1]}")
        except Exception as exc:  # noqa: BLE001 -- the window answer already stands
            logger.debug("fingerprint all-time probe failed: %s", exc)
        return {"ja4": token, "hosts": [], "count": 0, "reason": reason}
    return {
        "ja4": token, "count": len(rows),
        "hosts": [
            {"src_addr": str(r[0]), "sessions": int(r[1] or 0),
             "first_seen": _iso(r[2]), "last_seen": _iso(r[3]), "peers": int(r[4] or 0)}
            for r in rows
        ],
    }


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


def rank_sensor_row(row: dict, now: datetime.datetime | None = None) -> tuple:
    """The ONE rule for choosing which `sensor_status` row describes a sensor.

    Extracted so the fleet view and `sensor_status` cannot disagree about one dataset. A second
    ranking would be the same defect as a second staleness threshold: two readers of one table
    answering differently, with no way for an operator to tell which is lying.

    Rules, in order:
      1. A FRESH row beats a stale one. A stale row must never win.
      2. An INTERCEPTING row (`siphon`) beats a passive one. It describes the same physical
         sensor in a strictly more informative state, and it exists only while an intercept is
         genuinely running.
      3. Otherwise the newest wins.

    Returns a sort key, not the row, so callers take the rule without also taking this
    module's opinion about what the row means.
    """
    ts_value = row.get("ts")
    if isinstance(ts_value, datetime.datetime):
        # `_aware` on BOTH sides. ClickHouse returns aware datetimes while `now()` is naive, so
        # subtracting them raises -- the exact defect `_aware` exists to prevent, and which the
        # first version of this helper reintroduced by calling `now()` directly.
        age_s = (_aware(now or datetime.datetime.now(datetime.UTC)) - _aware(ts_value)).total_seconds()
    else:
        age_s = float("inf")
    fresh = age_s <= HEARTBEAT_STALE_S
    active = str(row.get("mode") or "") == MODE_SIPHON
    return (fresh, active, -age_s)


def best_sensor_row(rows: list[dict], now: datetime.datetime | None = None) -> dict | None:
    """The row that describes the sensor, by `rank_sensor_row`. None when there are no rows."""
    live = [r for r in rows if isinstance(r, dict)]
    if not live:
        return None
    return max(live, key=lambda r: rank_sensor_row(r, now))



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
    differ exactly when it matters: a siphon process that died, or was never started, still
    has SENSOR_MODE=siphon in the ConfigMap. Reporting the configured mode as though it were
    the running mode would show "intercepting 2 hosts" for a sensor that is not running.

    THE RULE THIS ENFORCES: a stale heartbeat is reported as NOT RUNNING, never as the
    last known state. That is the same class of bug as the always-empty Top Talkers and
    Zeek Services panels -- a display that looks healthy while being wrong.

    Returns a dict with `running`, `stale`, `age_s`, and the last reported details. Every
    field is present even when nothing was ever reported, so the caller never has to
    distinguish "key missing" from "null value".
    """
    now = _aware(now or datetime.datetime.now(datetime.UTC))
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
        # True when a `siphon` row exists but has gone stale: an intercept ran and stopped, and
        # whether the node was restored cannot be determined from here. Present always, so a
        # consumer never has to distinguish a missing key from a false value.
        "intercept_stopped": False,
        "stale_after_s": HEARTBEAT_STALE_S,
        # Always present so a consumer never has to distinguish a missing key from a
        # null value -- the frontend checks `if (s.error)` and an absent key is a
        # different shape.
        "error": None,
    }
    # EVERY row, then choose deterministically in Python. `ORDER BY ts DESC LIMIT 1` was the
    # bug: the table is keyed (sensor_id, mode), so a sensor that is intercepting has TWO live
    # rows -- the worker publishes the configured mode (`loch`) and the intercept publishes its
    # own (`siphon`) -- and both beat on the same interval. Whichever wrote last won, so the GUI
    # alternated between them on every refresh. The data was never wrong; the reader was
    # picking by wall-clock instead of by meaning.
    #
    # The table is tiny (one row per sensor per mode), so reading all of it is cheaper than
    # being clever in SQL and much easier to reason about. The read is shared with
    # siphon_liveness via _sensor_rows so the two answers cannot disagree about one dataset.
    rows, err = _sensor_rows(client)
    if err is not None:
        # A missing table is the normal state before the schema Job runs, and it must not
        # be reported as "not running" -- those are different facts and conflating them
        # sends an operator looking for a dead sensor that was never started.
        out["error"] = err
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
    #   1. An INTERCEPTING row (`siphon`) wins over a passive one. It describes the same physical
    #      sensor in a strictly more informative state -- it names the segment, the host count and
    #      a live watchdog -- and it exists only while an intercept process is actually running.
    #   2. Otherwise the FRESHEST row wins, but staleness is computed per row and a stale row is
    #      never chosen over a live one.
    #
    # This is deterministic: the same data always produces the same answer, which is what makes
    # the panel stop changing under a refresh.
    # Uses the SHARED rule (best_sensor_row / rank_sensor_row) rather than a local copy, so the
    # fleet view and this panel cannot pick different rows out of one dataset.
    best = best_sensor_row(rows, now)
    if best is None:
        # Unreachable: `rows` is non-empty by the guard above, and best_sensor_row returns None
        # only for an empty list. Stated rather than asserted away so the type narrows and so a
        # future edit to that guard cannot turn this into a None-dereference further down.
        out["error"] = "no sensor rows were readable"
        return out
    r = best

    # AN INTERCEPT THAT STOPPED IS NOT THE SAME AS NO INTERCEPT.
    #
    # Measured on the live box: an intercept publishes `siphon` while the worker publishes the
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
        if str(row.get("mode") or "") != MODE_SIPHON:
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
              # Per-mode, so a comparison of two modes on one sensor can show WHICH is
              # dropping packets -- the reason to show both rows at all.
              "capture_loss_pct": (None if row.get("capture_loss_pct") is None
                                   else float(row["capture_loss_pct"])),
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
          # None (not 0.0) when unmeasured. That distinction is the point of the column:
          # 0.0 is "measured, nothing lost", and a sensor with no capture_loss.log must
          # not be able to masquerade as one.
          "capture_loss_pct": (None if r.get("capture_loss_pct") is None
                               else float(r["capture_loss_pct"])),
          # None preserved, for the same reason as the percentage: an unmeasured count must not
          # read as a measured zero.
          "packets_recv": (None if r.get("packets_recv") is None else int(r["packets_recv"])),
          "packets_dropped": (None if r.get("packets_dropped") is None
                              else int(r["packets_dropped"])),
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


def _sensor_rows(client) -> tuple[list[dict], str | None]:
    """Every sensor_status row, or an error string. Never raises.

    Split out of sensor_status so siphon_liveness can apply its own rule over the same
    rows: sensor_status answers "which mode is this sensor in", while the liveness
    question is "does ANY row carry intercept evidence". Reading them with one query
    keeps the two answers from disagreeing about the same data.
    """
    try:
        rows = list(client.query(
            "SELECT sensor_id, mode, iface, segment, hosts, mappings, running, uptime_s, "
              "restores, refreshes, failures, ts, "
              "capture_loss_pct, packets_recv, packets_dropped, interfaces "
            "FROM weirvern.sensor_status FINAL "
            "ORDER BY ts DESC"
        ).named_results())
        return rows, None
    except Exception as exc:  # noqa: BLE001
        logger.debug("sensor_status unavailable: %s", exc)
        return [], "sensor status is unavailable"


def siphon_liveness(configured_mode: str, client, now: datetime.datetime | None = None) -> dict:
    """Whether a siphon-CONFIGURED sensor has intercept evidence RIGHT NOW.

    SENSOR_MODE=siphon is a statement of INTENT -- a fact about a ConfigMap, which outlives
    every process that read it. An intercept is a RUNNING process that publishes its own
    heartbeat. The two agree exactly when nothing is wrong, and disagree in the worst way
    when something is.

    WHY THIS CHECK EXISTS (siphon-1): an in-cluster deployment with SENSOR_MODE=siphon could
    set the sysctls, print "mode siphon -- IN-PATH intercept" in the Zeek container, and
    redirect ZERO hosts, because the intercept was operator-triggered and nothing in the
    cluster ran it. Every surface that only reads the config reported a healthy in-path
    sensor. The defect class is the one the changelog keeps naming: a failure that renders
    identically to a successful measurement of zero.

    WHAT CHANGED IN 0.8.0: the WORKER now supervises the intercept when this mode is
    configured (admin/siphon_supervisor), so "configured but nothing running" is no longer
    the expected steady state -- it is a fault to investigate (an incomplete plan, an empty
    target list, missing privileges, or a crashing child). This check stays the loud one.

    WHAT COUNTS AS EVIDENCE, and why the naive answers are wrong:
      * mode=='siphon' alone is not enough -- the WORKER's own row also carries the
        configured mode, with zero mappings, so a config-read would pass while nothing
        intercepts.
      * `running` alone is not enough -- the worker's `running` means "Zeek logs are
        fresh", which is true on a healthy passive sensor too.
      * A fresh row is required -- a stale intercept row is a PAST intercept, reported
        separately as `stopped` (an intercept ran; whether it restored is unknowable
        from here).
      * So: intercept evidence is a FRESH row with mode 'siphon' AND mappings > 0.
        `mappings` is written only by an intercept (the worker always writes 0) and an
        intercept only starts after forging at least one mapping -- which is exactly the
        question being asked. A worker row with mode 'siphon', mappings 0, running 1 is
        NOT evidence and must not pass this check.

    Returns a dict; never raises. `error` is the loud explanation when a siphon-configured
    sensor has no live intercept, and None otherwise.
    """
    out: dict = {
        "applicable": str(configured_mode or "") == MODE_SIPHON,
        "configured_mode": str(configured_mode or ""),
        "live": False,
        "stopped": False,
        "verified": False,
        "hosts": 0,
        "mappings": 0,
        "age_s": None,
        "error": None,
    }
    if not out["applicable"]:
        # Passive mode has no intercept to expect. Returning before the query keeps this
        # check free for every loch deployment, which is most of them.
        return out

    rows, err = _sensor_rows(client)
    if err is not None:
        # "Cannot tell" is its own answer -- it must not be reported as "no intercept"
        # (a claim we cannot support) nor as live (a claim in the unsafe direction).
        out["error"] = (
            "SENSOR_MODE=siphon is configured but whether an intercept is running cannot "
            f"be determined: {err}."
        )
        return out
    if not rows:
        out["error"] = (
            "SENSOR_MODE=siphon is configured but no sensor has ever reported a heartbeat, "
            "so no intercept can be confirmed. The worker writes one every few seconds "
            "while it runs, so this means it has not started or cannot reach ClickHouse. "
            "Check: kubectl -n weirvern get pods"
        )
        return out

    now_aware = _aware(now or datetime.datetime.now(datetime.UTC))
    out["verified"] = True

    def _age_s(row: dict) -> float | None:
        ts_value = row.get("ts")
        if not isinstance(ts_value, datetime.datetime):
            return None
        return (now_aware - _aware(ts_value)).total_seconds()

    stopped = False
    fresh_evidence: dict | None = None
    for row in rows:
        if str(row.get("mode") or "") != MODE_SIPHON:
            continue
        age = _age_s(row)
        fresh = age is not None and age <= HEARTBEAT_STALE_S
        if fresh and int(row.get("mappings") or 0) > 0:
            fresh_evidence = row
            break
        if not fresh:
            # An intercept that RAN and went stale. Whether it restored its mappings is
            # unknowable from here; report the uncertainty rather than either answer.
            stopped = True

    out["stopped"] = stopped
    if fresh_evidence is not None:
        out["live"] = True
        out["hosts"] = int(fresh_evidence.get("hosts") or 0)
        out["mappings"] = int(fresh_evidence.get("mappings") or 0)
        out["age_s"] = round(_age_s(fresh_evidence) or 0.0, 1)
        return out

    # --- applicable, verified, and NOT live. This is the loud case. ---
    if stopped:
        out["error"] = (
            "SENSOR_MODE=siphon is configured and an intercept RAN on this sensor but is no "
            "longer running. Whether its forged ARP entries were restored cannot be "
            "determined from here: if the process was killed uncatchably (kill -9, or a "
            "SIGKILLed kubectl-exec client that outran the self-destruct deadline), hosts "
            "on the intercepted segment may still be routing through a sensor that is no "
            "longer relaying. Check the node's neighbour tables, or re-run an intercept "
            "to overwrite the mappings with the truth."
        )
    else:
        out["error"] = (
            "SENSOR_MODE=siphon is configured but NO intercept is running right now and "
            "the newest heartbeat reports zero mappings. Since 0.8.0 the WORKER supervises "
            "the intercept, so this is a fault, not the expected state -- the supervisor "
            "refused to run it (an incomplete plan, an empty target list, or missing "
            "privileges; its reason is on the sensor panel and in the worker log), or it "
            "is still waiting for the sensor's capabilities. Check: kubectl -n weirvern "
            "logs deploy/weirvern-worker | grep siphon. If you intended interception, "
            "also make sure INTERCEPT_TARGETS names hosts; if this sensor should be "
            "passive, set SENSOR_MODE=loch (it also drops the extra privileges siphon "
            "mode requires). The intercept can still be run by hand, operator-triggered "
            "with `weirvern intercept --iface ... --segment ...`, which is what the "
            "supervisor runs for you."
        )
    return out


def _opt_count(value) -> int | None:
    """A packet count, or None when it was not measured.

    `max(0, int(value or 0))` looked defensive and was wrong: it converts an UNMEASURED count into
    a measured zero, so a sensor whose log carries no counter field reports "0 packets received"
    while it is receiving millions. The column is Nullable so this can stay honest.
    """
    if value is None:
        return None
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return None


# ---------------------------------------------------------------------------
# alert review state (soc-1)
# ---------------------------------------------------------------------------

# The dispositions an analyst can set. Empty string is a REAL state, not absence: it means
# "cleared" -- the row goes back to unreviewed. Kept in one tuple so the API, the schema
# comment, and the tests cannot drift.
VALID_REVIEW_STATES = ("ack", "resolved", "false_positive", "")

# The wire value for "the reviews table could not be read". Distinct from both the empty
# string ("not reviewed") and any real state, because reporting a read failure as
# "unreviewed" would tell the analyst nothing has been reviewed when the truth is that we
# cannot see whether anything has.
REVIEW_UNAVAILABLE = "unavailable"


def _audit_humanize(sec: float) -> str:
    """Seconds to the shortest honest span ("45s", "3h", "9d"). Display only."""
    sec = max(0.0, float(sec))
    if sec < 90:
        return f"{int(sec)}s"
    if sec < 5400:
        return f"{int(sec / 60)}m"
    if sec < 129600:
        return f"{int(sec / 3600)}h"
    return f"{int(sec / 86400)}d"


# WL-2: THE PER-SENSOR PROBLEMS AS ISSUE FINDINGS.
#
# These used to be prose in the weirling drill-down: "capture loss is 62.5%", "registered for
# segment 'fifth floor' but reporting 'sixth floor'". The operator's 2026-10-18 direction makes
# the sheet change-only, so the problems move to the surface that already owns issues (Logs) --
# extracted here as a PURE function over one fleet row, so the classes are unit-testable without
# a database and the audit cannot quietly stop emitting them.
CAPTURE_LOSS_WARN_PCT = 5.0


def sensor_issues(row: dict) -> list[dict]:
    """Findings for one sensor row: measured capture loss, and a contradicted segment."""
    out: list[dict] = []
    sid = str(row.get("sensor_id") or "")
    fix = {"view": "weirlings", "sensor": sid, "label": "open the sensor"}
    loss = row.get("capture_loss_pct")
    if loss is not None:
        try:
            pct = float(loss)
        except (TypeError, ValueError):
            pct = None
        # MEASURED ONLY. An unmeasured loss (NULL) is not an issue and must never be reported
        # as 0%: "not measured" and "measured, nothing lost" are different facts.
        if pct is not None and pct >= CAPTURE_LOSS_WARN_PCT:
            out.append({
                "class": "capture_loss", "severity": "warn", "subject": sid,
                "detail": (f"dropping {pct:g}% of packets "
                           f"({int(row.get('packets_recv') or 0)} received, "
                           f"{int(row.get('packets_dropped') or 0)} dropped): this sensor is "
                           f"blind to most of what is on the wire"),
                "fix": fix,
            })
    declared = str(row.get("segment") or "").strip()
    reported = str(row.get("reported_segment") or "").strip()
    if declared and reported and declared != reported:
        out.append({
            "class": "segment_mismatch", "severity": "info", "subject": sid,
            "detail": f"registered for segment '{declared}' but reporting '{reported}'",
            "fix": fix,
        })
    return out


def pipeline_audit(client, *, now=None) -> dict:
    """The pipeline auditing itself (BF-13; Datadog's monitor-quality, Splunk's content
    management, Hurricane Labs' hygiene lists). Four classes, each read INDEPENDENTLY: a
    class that cannot be read is an entry in `errors`, never a silently absent finding --
    "nothing found" and "the check did not run" must never look alike here, because this
    page's whole job is telling the operator which of the two they are looking at. Every
    finding carries the fix, and the fix names the surface that owns it.
    """
    import datetime as _dt  # noqa: PLC0415

    from weirvern import fleet_store  # noqa: PLC0415

    now = now or _dt.datetime.now(_dt.UTC)
    findings: list[dict] = []
    errors: dict[str, str] = {}

    # ── silent sensors: declared and enabled, but the hub cannot hear them
    try:
        f = fleet_store.build_fleet(client, now=now)
        if not f.get("available"):
            errors["silent_sensors"] = str(f.get("reason") or "the registry did not answer")
        else:
            if f.get("heartbeats_available") is False:
                errors["heartbeats"] = str(f.get("heartbeat_reason") or "heartbeats unreadable")
            for r in f.get("sensors") or []:
                if (r.get("registered") and r.get("enabled")
                        and r.get("state") in ("stale", "never_seen")):
                    age = r.get("age_s")
                    in_path = str(r.get("expected_mode") or "").lower() == "siphon"
                    detail = ("declared and enabled but never heard from"
                              + (" — in-path, so its segment may be waiting for it"
                                 if in_path else "")
                              if r.get("state") == "never_seen" or age is None
                              else f"silent for {_audit_humanize(age)}"
                                   f" (stale after {r.get('stale_after_s', '?')}s)")
                    findings.append({
                        "class": "silent_sensor", "severity": "warn",
                        "subject": str(r.get("sensor_id") or ""),
                        "detail": detail, "elapsed_s": int(age) if age is not None else None,
                        "fix": {"view": "weirlings", "sensor": str(r.get("sensor_id") or ""),
                                "label": "open the sensor"},
                    })
                # WL-2: the per-sensor problems (loss, segment) ride the same fleet pass.
                findings.extend(sensor_issues(r))
    except Exception as exc:  # noqa: BLE001
        logger.warning("audit: silent sensors failed: %s", exc)
        errors["silent_sensors"] = type(exc).__name__

    # ── expired rules: a block whose expiry has elapsed -- enforcement already stopped, the
    #    row is waiting to be cleaned up or extended. The elapsed column is the "muted how
    #    long" fact (BF-13 acceptance), so an operator can tell a stale housekeeping item
    #    from a fresh one.
    try:
        rows = client.query(
            "SELECT rule_id, domain, dst_cidr, expires_at FROM weirvern.sluice_rules FINAL "
            "WHERE revoked_at IS NULL AND disabled_at IS NULL "
            "AND expires_at IS NOT NULL AND expires_at <= %(now)s "
            "ORDER BY expires_at LIMIT 200",
            parameters={"now": now.replace(tzinfo=None)},
        ).result_rows
        for rid, domain, dst, exp in rows:
            elapsed = None
            if exp is not None:
                base = now.replace(tzinfo=None)
                elapsed = max(0.0, (base - exp).total_seconds())
            findings.append({
                "class": "expired_rule", "severity": "info", "subject": str(rid),
                "detail": ("domain rule for " + str(domain)) if domain
                          else ("block of " + str(dst)),
                "elapsed_s": int(elapsed) if elapsed is not None else None,
                # US-3: the fix carries the rule id, so the landing is the RULE (its row on
                # Sluice), not the top of a page the operator then has to search.
                "fix": {"view": "sluice", "rule_id": str(rid),
                        "label": "adjust or revoke on Sluice"},
            })
    except Exception as exc:  # noqa: BLE001
        logger.warning("audit: expired rules failed: %s", exc)
        errors["expired_rules"] = type(exc).__name__

    # ── stuck rules: firing without a quiet week. A rule that has hit SOMETHING every few
    #    minutes for a week is either doing exactly its job or hiding a problem nobody read;
    #    either way a person should say so on purpose (the alert-budget rule, one layer up).
    try:
        old = (now - _dt.timedelta(days=7)).replace(tzinfo=None)
        recent = (now - _dt.timedelta(hours=1)).replace(tzinfo=None)
        rows = client.query(
            "SELECT rule_id, count(), min(ts), max(ts) FROM weirvern.sluice_events "
            "WHERE ts >= %(since)s AND ts <= %(until)s GROUP BY rule_id "
            "HAVING min(ts) <= %(old)s AND max(ts) >= %(recent)s LIMIT 100",
            parameters={"since": (now - _dt.timedelta(days=30)).replace(tzinfo=None),
                        "until": now.replace(tzinfo=None),
                        "old": old, "recent": recent},
        ).result_rows
        for rid, n, first, _last in rows:
            span = ""
            if first is not None:
                span = f" since {_audit_humanize((now.replace(tzinfo=None) - first).total_seconds())}"
            findings.append({
                "class": "stuck_rule", "severity": "warn", "subject": str(rid),
                "detail": f"firing without a quiet week{span} ({int(n or 0)} hits in 30d) "
                          f"— still wanted?",
                "elapsed_s": int((now.replace(tzinfo=None) - first).total_seconds())
                             if first is not None else None,
                "fix": {"view": "blocked", "rule_id": str(rid),
                        "label": "read the hits on Blocked"},
            })
    except Exception as exc:  # noqa: BLE001
        logger.warning("audit: stuck rules failed: %s", exc)
        errors["stuck_rules"] = type(exc).__name__

    # ── unowned detectors: the BF-12 registry, audited. An unregistered or ownerless
    #    detector cannot page -- which is correct -- but somebody should decide whether that
    #    is deliberate, so it is listed until it is.
    try:
        ov = detectors_overview(client)
        if not ov.get("available"):
            errors["detectors"] = str(ov.get("reason") or "the registry did not answer")
        else:
            for d in ov["detectors"]:
                if not d["known"]:
                    findings.append({
                        "class": "unowned_detector", "severity": "warn", "subject": d["name"],
                        "detail": "unregistered — no owner, no runbook: it cannot page",
                        "elapsed_s": None,
                        "fix": {"view": "anomalies", "detector": d["name"],
                                "label": "register it (registry strip)"},
                    })
                elif not d["loud"] or not d["owner"]:
                    findings.append({
                        "class": "unowned_detector", "severity": "warn", "subject": d["name"],
                        "detail": "console-only: no owner or loud permission yet",
                        "elapsed_s": None,
                        "fix": {"view": "anomalies", "detector": d["name"],
                                "label": "register it (registry strip)"},
                    })
    except Exception as exc:  # noqa: BLE001
        logger.warning("audit: detectors failed: %s", exc)
        errors["detectors"] = type(exc).__name__

    counts: dict[str, int] = {}
    for fnd in findings:
        counts[fnd["class"]] = counts.get(fnd["class"], 0) + 1
    return {"available": True, "reason": "", "now": now.isoformat(),
            "findings": findings, "counts": counts, "errors": errors}


def detectors_overview(client) -> dict:
    """The registry joined to what it actually caught: fired and acted-on per detector.

    Rows are the registry UNION the detectors seen in the data -- an unregistered detector
    shows up as exactly that, which is the signal to register it (or leave it quiet on
    purpose). Counts failure is a state with its reason, never an empty registry.
    """
    from weirvern import detector_registry as dr  # noqa: PLC0415

    seen: dict[str, int] = {}
    acted: dict[str, int] = {}
    try:
        for name_str, n in client.query(
            "SELECT detected_by_models, count() FROM weirvern.netflow_anomalies "
            "GROUP BY detected_by_models"
        ).result_rows:
            for nm in dr.involved(str(name_str or "")):
                seen[nm] = seen.get(nm, 0) + int(n or 0)
        for name_str, n in client.query(
            "SELECT a.detected_by_models, count() FROM weirvern.netflow_anomalies AS a "
            "INNER JOIN (SELECT window_start, src_addr FROM weirvern.alert_reviews FINAL "
            "WHERE state != '') AS r "
            "ON a.window_start = r.window_start AND a.src_addr = r.src_addr "
            "GROUP BY a.detected_by_models"
        ).result_rows:
            for nm in dr.involved(str(name_str or "")):
                acted[nm] = acted.get(nm, 0) + int(n or 0)
    except Exception as exc:  # noqa: BLE001
        logger.warning("detector counts failed: %s", exc)
        return {"available": False, "reason": f"detector counts failed: {type(exc).__name__}",
                "detectors": []}
    out = []
    for nm in sorted(set(dr.DETECTORS) | set(seen)):
        st = dr.detector_status(nm)
        out.append({"name": nm, "owner": st["owner"], "runbook": st["runbook"],
                    "rule": st["rule"], "loud": st["loud"], "known": st["known"],
                    "fired": seen.get(nm, 0), "acted": acted.get(nm, 0)})
    return {"available": True, "reason": "", "detectors": out}


def anomaly_discipline_counts(client, *, min_score: float = 0.0, host: str = "") -> dict:
    """Fired vs acted-on, the alert-budget line (BF-12; SRE workbook [S58]).

    `fired` counts the anomaly rows under the same min-score/host filters the severity tiles
    use. `acted` counts disposed occurrences from the review history -- the reviews table
    carries no score, so the score floor cannot apply to it; host can, and does. A failed
    read is a state with its reason, never zeros that would read as a calm queue.
    """
    where = ["anomaly_score >= %(s)s"]
    params: dict = {"s": float(min_score)}
    if host:
        where.append("src_addr = %(host)s")
        params["host"] = str(host)
    try:
        fired = int(client.query(
            "SELECT count() FROM weirvern.netflow_anomalies WHERE " + " AND ".join(where),
            parameters=params,
        ).result_rows[0][0] or 0)
        rwhere = ["state != ''"]
        rparams: dict = {}
        if host:
            rwhere.append("src_addr = %(host)s")
            rparams["host"] = str(host)
        rows = client.query(
            "SELECT state, count() FROM weirvern.alert_reviews FINAL WHERE "
            + " AND ".join(rwhere) + " GROUP BY state",
            parameters=rparams,
        ).result_rows
        by_state = {str(r[0]): int(r[1] or 0) for r in rows}
    except Exception as exc:  # noqa: BLE001
        logger.warning("discipline counts failed: %s", exc)
        return {"available": False, "reason": f"discipline counts failed: {type(exc).__name__}"}
    return {"available": True, "reason": "", "fired": fired,
            "acted": sum(by_state.values()), "by_state": by_state}


def write_review(client, *, window_start: str, src_addr: str, state: str,
                 note: str = "") -> bool:
    """Record an analyst's disposition of one anomaly. Returns whether it landed.

    The review is keyed (window_start, src_addr) -- the same key as the anomaly it reviews
    -- so no id is minted or passed around. ReplacingMergeTree(reviewed_at): a later write
    replaces the earlier one, which is what "current disposition" means.

    Raises ValueError for a state outside VALID_REVIEW_STATES. That is a programming/API
    error (the route validates first), not a runtime failure, and both layers refusing it
    is deliberate: the route gives the caller a 400 with a reason, and this guard means a
    future caller that skips the route still cannot write a state the UI cannot render.
    """
    if state not in VALID_REVIEW_STATES:
        raise ValueError(
            f"unknown review state {state!r}; expected one of {VALID_REVIEW_STATES}"
        )
    stamp = _parse_stamp(window_start)
    if stamp is None:
        raise ValueError(f"unreadable window_start {window_start!r}")
    client.insert(
        "weirvern.alert_reviews",
        [[stamp, src_addr, state, note, datetime.datetime.now(datetime.UTC)]],
        column_names=["window_start", "src_addr", "state", "note", "reviewed_at"],
    )
    return True


def _parse_stamp(value) -> datetime.datetime | None:
    """A window_start from either a datetime (ClickHouse result) or an ISO string (JSON body).

    The browser round-trips the exact value the server sent it, so both forms must parse.
    Naive and aware inputs are both kept as wall-clock: ClickHouse's DateTime64 carries no
    zone, and re-deriving one here would shift the key and orphan the review from its row.
    """
    if isinstance(value, datetime.datetime):
        return value.replace(tzinfo=None) if value.tzinfo else value
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed.replace(tzinfo=None) if parsed.tzinfo else parsed


def write_watch(client, *, src_addr: str, watching: bool) -> bool:
    """Record the operator's watch state for one host (the alert action cell's Watch toggle).

    A WRITE like write_review: validated here even though the route validates too, so a
    future caller that skips the route still cannot store what the fleet cannot render.
    """
    addr = (src_addr or "").strip()
    if not addr or len(addr) > 64:
        raise ValueError(f"implausible src_addr {src_addr!r}")
    try:
        ipaddress.ip_address(addr)
    except ValueError as exc:
        raise ValueError(f"unreadable src_addr {addr!r}") from exc
    client.insert(
        "weirvern.host_watches",
        [[addr, 1 if watching else 0, datetime.datetime.now(datetime.UTC)]],
        column_names=["src_addr", "watching", "watched_at"],
    )
    return True


def watch_index(client) -> tuple[set[str], str | None]:
    """The set of watched hosts, for merging into anomaly rows and the watched filter.

    Returns (addresses, error). The error string is the honest "cannot tell": a missing
    host_watches table (schema job not re-run on this deployment) must not read as
    "nothing is watched" -- that would silently empty the list the operator built.
    """
    try:
        res = client.query(
            "SELECT src_addr FROM weirvern.host_watches FINAL WHERE watching = 1"
        )
        return {row[0] for row in res.result_rows}, None
    except Exception as exc:  # noqa: BLE001
        return set(), str(exc)


def review_index(client, hours: int = 72) -> tuple[dict[tuple, dict], str | None, datetime.datetime | None]:
    """Reviews keyed by (window_start, src_addr), for merging into anomaly rows.

    Returns (index, error, covered_since). The error string is the honest "cannot tell": a missing
    alert_reviews table (schema job has not run yet on an older deployment) must not read as
    "nothing has been reviewed", so the caller distinguishes the two and the UI renders a distinct
    chip for each.

    `covered_since` is the index's OWN lower bound, returned rather than recomputed by the caller.
    Measured defect: the anomalies query has no time bound while this one reads a 72h window, so an
    older row found no match and was labelled "unreviewed" -- a false claim about the operator's
    work. The caller cannot fix that by guessing the window; the window has to come from here, or
    the two drift apart the next time either changes.
    """
    covered_since = datetime.datetime.now(datetime.UTC) - datetime.timedelta(hours=hours)
    try:
        res = client.query(
            "SELECT window_start, src_addr, state, note, reviewed_at "
            "FROM weirvern.alert_reviews FINAL "
            "WHERE window_start >= %(since)s AND window_start <= %(until)s",
            parameters={**timewindow.w(hours)},
        )
        idx: dict[tuple, dict] = {}
        for row in res.result_rows:
            # NORMALISED THROUGH _parse_stamp, the same function attach_reviews uses for
            # the lookup. Measured on the live box: ClickHouse returns window_start as a
            # TZ-AWARE datetime (the server's timezone), and building the index with the
            # raw value while looking it up with a naive one made key equality FAIL for
            # every row -- the review was stored and read back correctly, and then silently
            # not merged, so a false-positive marking looked like it never saved.
            key = (_parse_stamp(row[0]), row[1])
            idx[key] = {"state": row[2], "note": row[3], "reviewed_at": row[4]}
        return idx, None, covered_since
    except Exception as exc:  # noqa: BLE001
        logger.debug("alert_reviews unavailable: %s", exc)
        return {}, "review state is unavailable (has the schema job run since this feature deployed?)", covered_since


def attach_reviews(rows: list[dict], idx: dict[tuple, dict], error: str | None,
                   covered_since=None) -> list[dict]:
    """Merge review state onto anomaly dicts, in place. Returns the rows.

    Every row gains `review_state` and `review_note` so a consumer never has to
    distinguish a missing key from a null value -- the rule the sensor payload already
    follows. On a read failure every row is marked REVIEW_UNAVAILABLE rather than left
    looking unreviewed.

    ── A ROW OLDER THAN THE REVIEW WINDOW IS NOT "UNREVIEWED" ─────────────────────────────────
    MEASURED DEFECT (triaged from an independent finding, 2026-09-23). `review_index` reads a
    BOUNDED window (72h by default) while `anomalies_detailed` has NO time bound -- it returns the
    newest N rows whatever their age. A row older than the window therefore finds no match in the
    index and was labelled `review_state: ""`, which reads as "nobody has looked at this".

    That label is a claim about the operator's work, and it can be false: the review may exist and
    simply fall outside the window. The consequence is an analyst re-triaging an alert that was
    already dispositioned, and losing trust in the queue when they find the notes elsewhere.

    So a row whose window_start predates the index is marked REVIEW_STATE_UNKNOWN instead. The
    caller passes `covered_since` -- the index's own lower bound -- so this function never has to
    guess the window, which is what would let the two drift apart again.
    """
    for row in rows:
        stamp = _parse_stamp(row.get("window_start"))
        key = (stamp, row.get("src_addr"))
        # ── THE COMPARISON MUST BE NAIVE-TO-NAIVE ─────────────────────────────────────────────
        #
        # `_parse_stamp` returns a NAIVE datetime (that is what makes the index keys match, see
        # its own note), while the bound this function is handed is timezone-AWARE. Comparing them
        # raises TypeError -- and this is the THIRD time this project has hit the same naive/aware
        # mismatch, so it is handled by normalising rather than by hoping.
        #
        # The failure mode if it is not: the exception propagates out of attach_reviews into the
        # route's handler, which reports "cannot read the anomalies", so a WORKING view looks
        # broken and the real cause is a comparison in the merge step.
        bound = covered_since
        if bound is not None and bound.tzinfo is not None:
            bound = bound.replace(tzinfo=None)
        if bound is not None and stamp is not None and stamp < bound:
            # Older than what the index could possibly contain: unknowable, not unreviewed.
            row["review_state"] = REVIEW_UNAVAILABLE
            row["review_note"] = (
                "older than the review history this view reads, so a review may exist without "
                "being shown here"
            )
            row["reviewed_at"] = None
            _attach_ownership(row)
            continue
        found = idx.get(key)
        if found is not None:
            row["review_state"] = found["state"]
            row["review_note"] = found["note"]
            row["reviewed_at"] = _json_safe_stamp(found.get("reviewed_at"))
        else:
            row["review_state"] = "" if error is None else REVIEW_UNAVAILABLE
            row["review_note"] = ""
            row["reviewed_at"] = None
        _attach_ownership(row)
    return rows


def _attach_ownership(row: dict) -> None:
    """The triage contract's owner + matched-rule fields (BF-12), DERIVED from the detector
    registry the same way the alert gate reads it -- one table, so a row can never claim an
    owner the pager does not honour."""
    from weirvern import detector_registry  # noqa: PLC0415

    owner, rule = detector_registry.row_ownership(str(row.get("detected_by_models") or ""))
    row["owner"] = owner
    row["matched_rule"] = rule


def _json_safe_stamp(value):
    if isinstance(value, datetime.datetime):
        return value.isoformat()
    return value


_INTERFACES_CACHE: list[str] | None = None
# Software interfaces are not "a sensor's NICs" to any operator: veth pairs, cni/flannel/docker
# plumbing and bridges are noise on every box that runs containers. Everything else is kept as
# reported -- the sensor's own network namespace is what it can actually see.
_SOFTWARE_IFACE_PREFIXES = ("veth", "cni", "flannel", "docker", "br-", "cali", "tunl", "virbr")


def sensor_interfaces() -> list[str]:
    """The interfaces this process can see, cached. Every heartbeat writer calls this (the
    hub's worker, the weirling agents, the final beats) so no writer can silently blank a
    sensor's NICs. Never raises: a sensor that cannot report its NICs must still capture."""
    global _INTERFACES_CACHE
    if _INTERFACES_CACHE is None:
        try:
            import socket as _socket
            names = {name for _, name in _socket.if_nameindex()}
            _INTERFACES_CACHE = sorted(n for n in names
                                       if n != "lo" and not n.startswith(_SOFTWARE_IFACE_PREFIXES))
        except Exception:  # noqa: BLE001
            _INTERFACES_CACHE = []
    return _INTERFACES_CACHE


def heartbeat(client, *, sensor_id: str, mode: str, iface: str = "", segment: str = "",
              hosts: int = 0, mappings: int = 0, running: bool = False,
              uptime_s: float = 0.0, restores: int = 0, refreshes: int = 0,
              failures: list[str] | None = None,
              capture_loss_pct: float | None = None,
              packets_recv: int | None = None,
              packets_dropped: int | None = None,
              interfaces: list[str] | None = None) -> bool:
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
              list(failures or []), datetime.datetime.now(datetime.UTC),
              # None stores as NULL and means NOT MEASURED. It must not become 0.0: 0.0
              # means "measured, nothing lost", so a sensor with no capture_loss.log would
              # read as a perfect one.
              None if capture_loss_pct is None else float(capture_loss_pct),
              _opt_count(packets_recv), _opt_count(packets_dropped),
              [str(n) for n in (interfaces or [])]]],
            column_names=["sensor_id", "mode", "iface", "segment", "hosts", "mappings",
                          "running", "uptime_s", "restores", "refreshes", "failures",
                          "ts",
                          # NEW COLUMNS GO LAST, so the positional list above cannot
                          # misalign against a reader or table that predates them.
                          "capture_loss_pct", "packets_recv", "packets_dropped", "interfaces"],
        )
        return True
    except Exception as exc:  # noqa: BLE001
        logger.debug("heartbeat write failed: %s", exc)
        return False
