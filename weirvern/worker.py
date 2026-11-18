"""Weirvern worker — the single long-running process.

Owns the loop that the legacy `anomaly_detection.py` main() had, restructured:
  * threads: ingest (tail goflow2 JSONL → ClickHouse) + detect (retrain/sweep)
  * schema applied idempotently at boot (was: configmap-embedded SQL)
  * models persisted to MODEL_DIR (was: lost on every restart)
  * graceful shutdown on SIGTERM (was: KeyboardInterrupt only)

Run as:  python -m weirvern.worker
"""
from __future__ import annotations

import json
import logging
import os
import signal
import sys
import threading
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

from clickhouse_connect.driver.client import Client

from weirvern import __version__, addressing, db, ensemble, episodes, networks
from weirvern.alerts import AlertState, push_alert
from weirvern.config import ModelConfig, get_settings
from weirvern.explain import explain, has_novelty
from weirvern.ingester import tail_forever
from weirvern.models import readiness as readiness_mod
from weirvern.models.detectors import (
    AdaptiveBaselineDetector,
    DBSCANDetector,
    GradientBoostingDetector,
    IsolationForestDetector,
)
from weirvern.zeek_features import zeek_window_sql

from .clock import as_aware, utcnow

logger = logging.getLogger(__name__)

# ── THE AGGREGATION BUCKET SIZE, AND WHY IT IS A NAMED CONSTANT ───────────────────────────────
#
# The materialised views in `weirvern/schema/001_weirvern.sql` bucket flows with
# `toStartOfFiveMinute(time_flow_start)`, so every aggregate row's `window_start` is a 5-minute
# boundary. The detection sweep must look back STRICTLY MORE than this, or a bucket falls out of
# the window before the next one has any rows in it -- MEASURED on the live cluster: the sweep's
# own query matched ZERO rows while raw flows kept arriving, and every health probe read green.
#
# It is a constant here because the schema cannot export one, and it is READ rather than repeated:
# the sweep's lookback is computed from it, so changing the view's bucketing means changing ONE
# number that both sides consult. A second copy of "300" in the sweep's arithmetic is exactly the
# drift that produced the defect -- the two durations were equal and looked independent.
AGG_BUCKET_S = 300  # toStartOfFiveMinute in weirvern/schema/001_weirvern.sql

# THE MOST BUCKETS ONE SWEEP MAY EXAMINE while draining a backlog. Measured 2026-11-12: the ingest
# pipeline died, the cursor correctly refused to advance on an empty read, and by the next day
# `since` sat 17 hours back -- roughly 37,000 host-windows in a single pass. The worker was
# OOMKilled at a 6 Gi limit before it could reach `_save_detect_cursor`, so the cursor could not
# advance, so the next cycle did exactly the same thing. A stalled cursor became a crash loop.
# 12 buckets is one hour of aggregates, about 2,200 host-windows at fleet scale, and drains an
# 18-hour backlog in 18 cycles: 90 minutes at the shipped 300s cadence.
MAX_CATCHUP_BUCKETS = 12

# HOW OLD AN EMPTY CHUNK MUST BE BEFORE THE CURSOR IS ALLOWED TO STEP OVER IT (measured 2026-11-17).
#
# The rule above -- never advance a cursor over an empty read -- is correct for rows that are still
# arriving, and WRONG forever when the emptiness is permanent. A sensor outage longer than one
# catch-up chunk creates a leading chunk that can never fill: on 2026-11-16 flows died at 19:12Z, the
# cursor stopped at 19:17:59Z, and the chunk 19:17 -> 20:17 stayed empty. Every cycle re-read it,
# logged "examined NOTHING", and returned without saving -- so when flows came back four hours later
# the cursor was still in the dead hour and detection stayed dark for twenty hours with the pod
# green. A second cursor from the same failure (detect_cursor.json.stuck-20261112) was already on the
# box: it had happened before.
#
# Fifteen minutes is chosen against the producer, not by feel: a window's rows are written by the
# inserting flows, and the tap emits each segment within TICK_S (15s) while flow expiries are 60-600s,
# so a bucket is complete well inside 5 minutes. Waiting 15 puts three full bucket cycles between the
# last possible row and the decision to step over the window.
CURSOR_GAP_GRACE_S = 900


# The gate's supervisor lives at module scope so its `last_ok` SURVIVES BETWEEN PASSES. Rebuilding
# it each time would reset the age that `healthy()` uses to distinguish "holding" from "held the
# last time anyone asked" -- so a supervisor that had stopped would look fresh forever.
_SLUICE: dict = {"supervisor": None, "last_pass": 0.0, "armed": False, "swept": False}


def _is_gate_only(settings) -> bool:
    """Whether this process is a WEIRLING GATE rather than the hub.

    A weirling gate runs the SAME pass with the SAME requirements; what it does not do is DERIVE
    rules from detections (see _sluice_maybe). Read through getattr so a settings object from an
    older ConfigMap -- which has no `role` -- is the hub, which is what it was.
    """
    return str(getattr(settings, "role", "full") or "full") == "gate"


# The DNS-hit pass's own cursor and interval. In-process by design: a restart re-reads the last
# minute of DNS (bounded duplicate events, noted in the module's spirit) rather than persisting a
# cursor for a path whose whole job is watching, not enforcing.
_SLUICE_DNS: dict = {"cursor": None, "last": 0.0}

# The blocklist sync's own interval. The real cadence is per SOURCE (fetched_at older than
# SYNC_EVERY_H), so this pass runs every 30 minutes and usually finds nothing due -- cheap.
_BLOCKLIST: dict = {"last": 0.0}


def _blocklist_maybe(settings, client) -> None:
    """Seed the default sources and sync whatever is stale. Failures are recorded states on
    the source rows; this pass never raises into the cycle."""
    import time as _time  # noqa: PLC0415

    from weirvern import blocklists  # noqa: PLC0415

    now = _time.monotonic()
    if now - float(_BLOCKLIST["last"]) < 1800:
        return
    _BLOCKLIST["last"] = now
    try:
        added = blocklists.ensure_default_sources(client)
        if added:
            logger.info("blocklists: seeded %d default source(s)", added)
        due = blocklists.sync_due(client, every_h=settings.blocklist_sync_hours)
        if due:
            logger.info("blocklists: %d source(s) due for sync", len(due))
        for src in due:
            blocklists.sync_source(client, src)
    except Exception as exc:  # noqa: BLE001
        logger.warning("blocklist pass failed (detection continues): %s", exc)


def _sluice_dns_maybe(settings, client) -> None:
    """Record DNS queries that hit an ACTIVE domain rule -- the alert-first half.

    WHY THIS RUNS EVEN WHEN THE GATE IS DISABLED (SLUICE_ENABLED=0): alert mode's entire promise
    is "see what a rule would catch before it blocks". The pass writes sluice_events rows and
    touches no kernel, so it is visibility, not enforcement -- the thing a monitoring appliance
    is FOR. Only rules whose domain is set are consulted; a deployment without domain rules pays
    one cheap query per interval at most.
    """
    import time as _time  # noqa: PLC0415

    from weirvern import sluice_store  # noqa: PLC0415

    now = _time.monotonic()
    if now - float(_SLUICE_DNS["last"]) < max(15, int(settings.sluice_interval_s)):
        return
    _SLUICE_DNS["last"] = now
    try:
        rules = [r for r in sluice_store.load_live_rules(client) if r.domain]
    except Exception as exc:  # noqa: BLE001
        logger.warning("sluice dns: could not read rules: %s", exc)
        return
    if not rules:
        return
    # THE LIST IS THE SECOND MATCHER: rule hits first (specific), then the blocklist set -- the
    # "small cache" in the operator's ask, held in-process and refreshed on its own clock. A
    # list hit names the MATCHED list entry in `domain` and carries no rule_id; it records the
    # same way a rule hit does, because alert-first does not care which table said the name.
    try:
        from weirvern import blocklists  # noqa: PLC0415

        listed = blocklists.load_domains(client)
    except Exception as exc:  # noqa: BLE001
        logger.warning("sluice dns: could not load the blocklist: %s", exc)
        listed = {}

    cursor = _SLUICE_DNS["cursor"]
    if cursor is None:
        # Naive local time, like every other clock read in this file: the rows zeek writes are
        # stamped in the box's local time, and comparing aware to naive would skip every row.
        cursor = utcnow() - timedelta(seconds=60)
    try:
        rows = client.query(
            "SELECT ts, src_addr, query FROM weirvern.zeek_dns "
            "WHERE ts > %(after)s ORDER BY ts LIMIT 500",
            parameters={"after": cursor},
        ).result_rows
    except Exception as exc:  # noqa: BLE001
        logger.warning("sluice dns: could not read zeek_dns: %s", exc)
        return
    if not rows:
        return
    # THE CLOCK TYPES DO NOT MATCH BY DEFAULT, and the pass DIED on it (measured live
    # 2026-10-16): ClickHouse hands back tz-AWARE datetimes for DateTime columns (the reverse
    # read shows -05:00), while the cursor is naive local -- so `ts > newest` raised "can't
    # compare offset-naive and offset-aware datetimes" and the whole pass wrote nothing while
    # looking scheduled. Normalize to the naive local wall clock (the DB's own convention):
    # strip the zone rather than converting, because the stored values ARE local wall time.
    def _naive(dt):
        return dt.replace(tzinfo=None) if getattr(dt, "tzinfo", None) is not None else dt

    events: list[dict] = []
    newest = cursor
    for ts, src_addr, query in rows:
        tsn = _naive(ts) if ts else None
        if tsn and tsn > newest:
            newest = tsn
        q = str(query or "").lower().rstrip(".")
        hit = False
        for rule in rules:
            # The `*.` marker is for humans (validate_domain stores it as typed, 2026-10-16);
            # the suffix test below already means "this name and its subdomains".
            d = rule.domain.lower().rstrip(".").removeprefix("*.")
            if q == d or q.endswith("." + d):
                events.append({
                    "ts": ts, "rule_id": rule.rule_id, "kind": "dns", "domain": rule.domain,
                    "query": str(query), "src_addr": str(src_addr), "dst_addr": "",
                    "protocol": "dns", "rule_snapshot": rule.snapshot(), "direction": "forward",
                })
                hit = True
                break
        if hit or not listed:
            continue
        matched = blocklists.domain_in_set(q, listed)
        if matched:
            events.append({
                "ts": ts, "rule_id": "", "kind": "dns", "domain": matched,
                "query": str(query), "src_addr": str(src_addr), "dst_addr": "",
                "protocol": "dns", "rule_snapshot": "", "direction": "forward",
            })
    _SLUICE_DNS["cursor"] = newest
    if events:
        try:
            sluice_store.write_events(client, events)
        except Exception as exc:  # noqa: BLE001
            logger.warning("sluice dns: could not record hits: %s", exc)


def _sluice_maybe(settings, client, *, derive: bool = True, store=None) -> None:
    """Run one Sluice Gate pass if it is enabled and its interval has elapsed.

    `derive` is False on a weirling gate: it enforces the rule set the hub wrote, and does not
    mint rules of its own. The check is here rather than at the call site because the pass is the
    only thing that reads detections, and a caller that forgot would silently become a second
    writer.

    DISABLED BY DEFAULT, which is a decision about what kind of tool this is. Weirvern is a
    monitoring appliance first: installing it must not start blocking traffic before anyone has
    looked at what it sees. `SLUICE_ENABLED=1` is an operator opening the gate deliberately.

    When it is disabled the gate is DISARMED -- explicitly, once -- rather than left at whatever the
    kernel last had. An operator who turns blocking off must have it actually stop, not keep
    enforcing the rules from before the switch was flipped.
    """
    import time as _time  # noqa: PLC0415

    from weirvern import sluice_store  # noqa: PLC0415
    from weirvern.admin import channel as _channel  # noqa: PLC0415
    store = store or sluice_store
    from weirvern.nic_plans import NicPlanSet  # noqa: PLC0415
    from weirvern.sluice import (  # noqa: PLC0415
        GATE_STATE_DISARMED,
        SluiceGateGroup,
        SluiceSupervisor,
        choose_backend,
        enforcement_pass,
        gate_tables_of,
        sweep_gate_tables,
    )

    plans = NicPlanSet.from_json(getattr(settings, "intercept_plans", ""))
    plan_group = bool(plans.sluice_ifaces())

    # ── THE ENFORCEMENT TARGET, RESOLVED FROM THE VERIFIED TOPOLOGY ──────────────────────────
    #
    # Priority: an explicit SLUICE_IFACE; then the CHANNEL's bridge when the channel is actually
    # up (that is the interface traffic traverses -- read from the kernel, see admin/channel.py);
    # then the capture interface. The supervisor is REBUILT when the resolved interface MOVES: its
    # module-scope caching exists so `last_ok` age survives passes on the SAME interface, and a
    # different interface is a different gate -- carrying the old age over would let a gate that
    # never installed anywhere read as recently confirmed.
    channel_state = _channel.detect(settings.channel_upstream, settings.channel_downstream)
    _iface = (
        settings.sluice_iface
        or settings.capture_iface
        or (channel_state.bridge if channel_state.active else "")
        or settings.zeek_iface
        or ""
    )
    sup = _SLUICE["supervisor"]
    if plan_group:
        # ONE GATE PER BLOCKING NIC. The group owns a table per interface; the single
        # `sup.iface` cache key below would collide, so the key is the whole interface list.
        want = ",".join(plans.sluice_ifaces())
        if sup is None or getattr(sup, "iface", "") != want:
            sup = SluiceGateGroup(
                plans,
                mgmt_iface=settings.mgmt_iface,
            )
            _SLUICE["supervisor"] = sup
    elif sup is None or getattr(sup, "iface", "") != _iface or isinstance(sup, SluiceGateGroup):
        sup = SluiceSupervisor(
            iface=_iface,
            mgmt_iface=settings.mgmt_iface,
            backend=choose_backend("nft"),
        )
        _SLUICE["supervisor"] = sup

    # ── RECONCILE THE KERNEL WITH THE CURRENT PLAN, EVERY TIME THE TARGET SET MOVES ──────────
    #
    # A gate group owns one table per blocking NIC. When a plan drops a sluice NIC -- or the
    # operator clears the plan and disables blocking -- the group that owned that table is gone,
    # so nothing in memory knows to delete it. The old table kept its drop rule and outlived both
    # the rule and the plan. The kernel is the only source that can enumerate what the previous
    # process left, so sweep every `weirvern_sluice*` table not in the CURRENT target set. This
    # includes the disabled case, where the target set is empty.
    first_sweep = not _SLUICE.get("swept")
    if first_sweep:
        _SLUICE["swept"] = True
    desired_tables = gate_tables_of(sup) if settings.sluice_enabled else set()
    prior_tables = set(_SLUICE.get("tables") or ())
    if settings.sluice_enabled:
        if first_sweep or desired_tables != prior_tables:
            ok, detail = sweep_gate_tables(desired_tables)
            if not ok:
                logger.warning("sluice: could not reconcile gate tables: %s", detail)
        _SLUICE["tables"] = desired_tables
    else:
        ok, detail = True, ""
        # ── ONCE PER PROCESS, NOT ONCE PER PASS (measured 2026-11-17) ─────────────────────────────
        #
        # The worker runs as uid 10001 with every capability dropped, so `nft list tables` fails
        # with "Operation not permitted (you must be root)" on EVERY pass. The intent here is
        # right -- a disabled gate must mean the rules are gone, and a table a previous process
        # armed outlives it -- but the failure is PERMANENT for this process, and a warning every
        # 60 seconds is how the next real warning gets ignored. Measured: this single line was
        # ~1,440 entries a day, and it is the loudest thing in a log that also has to carry the
        # detection sweep's verdicts.
        #
        # So: try once, and if the answer is "this process may not touch nft", say so ONCE at INFO,
        # name the remedy, and stop asking. A different error is still a warning, every time.
        if not _SLUICE.get("nft_blocked"):
            ok, detail = sweep_gate_tables(set())
            if not ok:
                if "Operation not permitted" in detail or "you must be root" in detail:
                    _SLUICE["nft_blocked"] = True
                    logger.info(
                        "sluice: this process cannot manage nft (%s), so the disabled gate's "
                        "leftover tables cannot be swept from here. Nothing is armed and nothing "
                        "is being blocked; a table left by an earlier run needs a privileged "
                        "operator (or the gate container) to remove it. Reported once, not every "
                        "pass.", detail,
                    )
                else:
                    logger.warning("sluice: could not remove gate tables while disabled: %s", detail)
        _SLUICE["tables"] = set()

    if not settings.sluice_enabled:
        # DISARM ONCE, not every pass: re-disarming 1440 times a day would shell out to nft for
        # nothing. But it MUST happen, because `SLUICE_ENABLED=0` has to mean the rules are gone.
        #
        # AND THE KERNEL IS SWEPT, ONCE PER PROCESS. A worker that STARTS with SLUICE_ENABLED=0
        # has `armed=False` and a fresh DISARMED state, so the in-memory check alone would leave a
        # table a PREVIOUS process armed sitting in the kernel -- inert (its sets empty once the
        # rules lapsed) but present, and "disabled" must mean gone. The kernel is the only source
        # that can tell. Measured on the test box: a disabled restart left `table inet
        # weirvern_sluice` behind, and nothing in the cluster would ever have removed it.
        leftover = bool(first_sweep and sup.backend.installed())
        changed = bool(_SLUICE["armed"] or sup.state.state != GATE_STATE_DISARMED or leftover)
        if changed:
            sup.disarm()
            _SLUICE["armed"] = False
            logger.info("sluice gate is DISABLED (SLUICE_ENABLED=0); rules are not enforced%s",
                        ": removed a table a previous run left behind" if leftover else "")
        # A DISABLED RESTART MUST NOT LEAVE A STALE "DEGRADED" ROW BEHIND. The fresh supervisor is
        # already disarmed, so the guard above skips the write -- which is right for an EMPTY
        # table (nothing has run) and wrong for a row a previous process wrote. Measured live:
        # the old process recorded "degraded" while shutting down, the new one skipped its write,
        # and the panel kept showing a fault on a box with no nft table at all.
        if first_sweep:
            try:
                prior = store.load_gate_state(client, _sensor_name(settings))
                stale = (prior.get("state") != GATE_STATE_DISARMED
                         or not prior.get("iface")
                         or not prior.get("backend"))
                if changed or stale:
                    # A stale row still needs a state that names this gate's interface and backend.
                    # The default GateState has neither, and writing it made the panel say
                    # "interface —" and warn about a '' backend on a gate that uses nft on eth1.
                    if not changed:
                        sup.disarm()
                    store.write_gate_state(client, _sensor_name(settings), sup.state)
            except Exception as exc:  # noqa: BLE001
                logger.warning("sluice: could not record the disarmed state: %s", exc)
        return

    now = _time.monotonic()
    if now - float(_SLUICE["last_pass"]) < max(5, int(settings.sluice_interval_s)):
        return
    _SLUICE["last_pass"] = now

    # Detections are read only when SOMETHING may block on them -- a policy above Off, or the
    # operator's numeric auto-block threshold -- so a deployment that blocks nothing pays no
    # query for it.
    detections: list[dict] = []
    auto_score = float(getattr(settings, "sluice_auto_score", 0.0) or 0.0)
    if derive and (settings.sluice_criticality != "off" or auto_score > 0.0):
        detections = current_detections_for_blocking(client)

    # WHETHER A CONFIGURED SIPHON IS ACTUALLY INTERCEPTING, checked only when it matters. A
    # configured siphon with no live intercept is a sensor that is NOT in the path -- the gate must
    # not read ARMED on the strength of a ConfigMap. `None` = the evidence could not be read, which
    # the pass treats as "not verified", never as "fine".
    siphon_live: bool | None = None
    _mode = "siphon" if plans.siphon_ifaces() else settings.sensor_mode
    if _mode == "siphon":
        try:
            from weirvern.admin import status as _status  # noqa: PLC0415
            siphon_live = bool(_status.siphon_liveness(_mode, client).get("live"))
        except Exception as exc:  # noqa: BLE001
            logger.warning("sluice: could not read siphon intercept evidence: %s", exc)
            siphon_live = None

    state = enforcement_pass(
        store, sup, client=client, sensor=_sensor_name(settings),
        policy=settings.sluice_criticality, max_block_s=settings.sluice_max_block_s,
        auto_score=auto_score,
        detections=detections,
        # So the pass can say plainly WHICH enforcement path is live -- channel, siphon, or none.
        sensor_mode=_mode,
        channel=channel_state,
        siphon_live=siphon_live,
        block_domains=settings.sluice_block_domains,
    )
    _SLUICE["armed"] = state.holding
    logger.info("sluice gate: %s -- %s", state.state, state.detail)


# HOW OFTEN the Health tab's table-size history gets a sample. Five minutes is enough to see a
# table building over a day and cheap enough to be invisible; the Health query buckets hourly.
_TABLE_SIZE_SAMPLE_S = 300.0
_TABLE_SIZE_LAST = {"at": 0.0}


def _table_size_maybe(client: Client, *, now: float | None = None) -> None:
    """Append one snapshot of every table's size for the Health trend lines.

    A READ-SIDE TREND CANNOT BE RECONSTRUCTED. system.parts answers what a table weighs now; the
    operator asked which tables are BUILDING, which needs history. This writer is deliberately
    in the worker (the one always-running process) and throttled: one query per five minutes,
    not one per page load, so opening Health never writes and a forgotten tab cannot skew data.
    """
    import time as _time  # noqa: PLC0415

    current = float(now) if now is not None else _time.monotonic()
    if current - float(_TABLE_SIZE_LAST["at"]) < _TABLE_SIZE_SAMPLE_S:
        return
    try:
        rows = client.query(
            "SELECT table, sum(rows) AS n, sum(bytes_on_disk) AS b "
            "FROM system.parts WHERE database = 'weirvern' AND active "
            "GROUP BY table"
        ).result_rows
        if rows:
            client.insert(
                "weirvern.table_size_history",
                [[str(r[0]), int(r[1] or 0), int(r[2] or 0)] for r in rows],
                column_names=["table_name", "rows", "bytes"],
            )
            _TABLE_SIZE_LAST["at"] = current
    except Exception as exc:  # noqa: BLE001
        # Never break detection because a size snapshot failed (the schema may not have run yet).
        logger.debug("table size sample failed: %s", exc)


# ── FLOWS COME FROM THE TAP, NOT FROM THIS PROCESS ─────────────────────────────────────────
#
# The capture children (tcpdump segments -> softflowd -> IPFIX) used to live here. They do
# not any more, and the reason is a MEASURED one: this container runs as uid 10001, and
# Kubernetes DROPS an added capability for a non-root container. The pod spec carried
# `add: ["NET_RAW"]` and CapEff inside it read 0000000000000000, so the tap could not open
# the capture socket and flows stopped while every surface still looked configured. The
# capture grant now belongs to the process that actually reads the wire -- `weirvern.tap`,
# run by the Zeek DaemonSet's sidecar on the hub and by the agent container on a weirling
# (see `weirvern/tap.py`). The worker READS the collector's output like any other flow
# source and needs no capture capability at all.

_PROCESS_STARTED = utcnow()


def _sensor_name(settings) -> str:
    """What this sensor calls itself in the gate's state row, and in every sensor-keyed table.

    ── WHY THIS IS NOT socket.gethostname(), MEASURED IN CLUSTER ───────────────────────────────
    Inside Kubernetes `socket.gethostname()` returns the POD NAME, not the node. Measured on the
    live deployment: the worker wrote rows under `weirvern-worker-84899c6f55-9z7g2` while the GUI
    computed `weirvern-gui-79c77d8667-b7c7q` for itself. Two consequences, both real:

      * the GUI can never match the worker's rows, so a panel filtering to its own sensor finds
        nothing and reports "the gate has not run yet" on a gate that is running fine; and
      * the name CHANGES ON EVERY RESTART, because a pod name carries its ReplicaSet hash. Rows
        accumulate under a new identity each time, so no query can follow one gate across a
        restart -- which is exactly when an operator looks.

    THE ORDER OF PREFERENCE, and what each source is for:

      settings.sensor_name   an explicit name, for a deployment that wants to call itself something
                             (and the field the weirlings case will use to tell sensors apart)
      NODE_NAME              the node, supplied by the DOWNWARD API. Stable across pod restarts and
                             identical in every pod scheduled to that node -- so the worker's rows
                             and the GUI's reads agree, and they keep agreeing after a rollout.
      hostname               last resort for a non-cluster run (a bare python invocation, the CLI,
                             a test), where the hostname IS the box and is stable.

    Falls back rather than to a literal, because a state row with an empty sensor name cannot be
    attributed to a box -- and once there is more than one sensor an unattributable row is worse
    than no row.
    """
    import os  # noqa: PLC0415
    import socket  # noqa: PLC0415

    explicit = getattr(settings, "sensor_name", "") or ""
    if explicit:
        return str(explicit)
    # The downward API is wired in both deployments. When it is absent (a non-cluster run) the
    # hostname is the correct answer, not a failure.
    return os.environ.get("NODE_NAME") or socket.gethostname() or "sensor"


def current_detections_for_blocking(client, window_minutes: int = 60) -> list[dict]:
    """Recent detections, in the shape the criticality policy reads.

    Deliberately the SAME rows the GUI's Anomalies view shows: an operator who sees a host flagged
    there and then sees it blocked must be looking at one source of truth, not two that can disagree
    about what the ensemble said.

    Returns [] on a read failure rather than raising, and logs it. The caller is deciding whether to
    BLOCK; a failed query must not become an implicit "block nothing new" that no one can see, so it
    is logged and the existing rules are still armed.
    """
    try:
        rows = client.query(
            """
            SELECT src_addr, severity, anomaly_score, identity
            FROM weirvern.netflow_anomalies
            WHERE detected_at >= now() - INTERVAL %(m)s MINUTE
            ORDER BY detected_at DESC
            LIMIT 200
            """,
            parameters={"m": int(window_minutes)},
        ).result_rows
    except Exception as exc:  # noqa: BLE001
        logger.warning("sluice: could not read recent detections: %s", exc)
        return []
    return [
        {"src_addr": str(src or ""), "severity": str(sev or ""),
         "anomaly_score": float(score or 0.0), "identity": str(ident or "")}
        for src, sev, score, ident in rows
    ]

_stop = threading.Event()

# How long shutdown waits for the ingest thread to finish its current pass and checkpoint (F079).
# A pass reads only what is new since the last cursor, so this is normally milliseconds; the bound
# exists so a stalled client cannot hold the pod open until the kubelet SIGKILLs it, which would
# cost the checkpoint this wait is protecting.
_INGEST_JOIN_TIMEOUT_S = 10

# The last (thin_window_floor, base_threshold) pair already reported as unalertable, so the
# sweep logs it once per configuration rather than every cycle (audit F186).
_thin_floor_warned: tuple[float, float] | None = None


def check_thin_floor_reachable(cfg: ModelConfig, settings) -> bool:
    """Verify the threshold relationship, LOGGING rather than raising on a violation (audit F186).

    EXTRACTED SO IT CAN BE TESTED BY DRIVING IT. While this logic sat inline in `detection_sweep`,
    the only way to test the once-per-configuration latch was to re-implement it in the test -- and a
    test that re-implements the product proves nothing about the product. A mutation removing the
    product's latch changed no test result at all, which is exactly how that shows up.

    Returns True when the configuration can alert on thin windows. `main()` uses the RAISING form
    (`ensemble.assert_thin_floor_is_reachable`) so a deployment that could never have alerted refuses
    to start; this one exists for the live path, where `BASE_THRESHOLD` can be edited while the
    worker runs and where stopping detection would be worse than the blind band. See the note in
    `detection_sweep`.
    """
    global _thin_floor_warned
    try:
        ensemble.assert_thin_floor_is_reachable(cfg, settings.base_threshold)
        _thin_floor_warned = None
        return True
    except ValueError as exc:
        key = (cfg.thin_window_floor, settings.base_threshold)
        if _thin_floor_warned != key:
            _thin_floor_warned = key
            logger.error("DETECTION CANNOT ALERT ON THIN WINDOWS: %s", exc)
            logger.error(
                "Every window below %s flows is unalertable regardless of how strong its signal is. "
                "Raise thin_window_floor or lower BASE_THRESHOLD; windows at or above that flow "
                "count are unaffected and detection continues.", cfg.min_flows_for_full_confidence,
            )
        return False


def _handle_sigterm(signum, frame):  # noqa: ARG001
    logger.info("SIGTERM received — shutting down gracefully")
    _stop.set()


def build_detectors(settings, cfg: ModelConfig, model_dir: str | None = None):
    """The four detectors, aimed at `model_dir` (the live artifact directory by default).

    The override exists for the FORCED RETRAIN: the candidate must train through these same
    classes with these same arguments, or the rehearsal proves nothing about the scheduled path
    -- but it must write its artifacts somewhere that is not scoring traffic.
    """
    model_dir = model_dir or settings.model_dir
    return [
        IsolationForestDetector(model_dir, cfg),
        GradientBoostingDetector(model_dir, cfg),
        DBSCANDetector(model_dir, cfg),
        AdaptiveBaselineDetector(model_dir, cfg),
    ]


def load_or_train(client: Client, detectors, settings,
                  cfg: ModelConfig) -> tuple[bool, datetime | None]:
    """Warm start from persisted artifacts; otherwise train cold (lesson:
    v14 deployed while v19 sat on disk — the persisted artifact is the
    source of truth, and each training run records metadata to ml_models).

    RETURNS (usable, trained_at). The second element is when the FULL detectors were actually
    trained, read from their own on-disk metadata; it is None when nothing was trained.

    WHY IT RETURNS A TIMESTAMP AND NOT JUST A BOOL. The caller used to stamp
    `last_full_train = utcnow()` whenever the detectors were usable, and a WARM START is
    usable with no training having happened at all. So every restart reset the retrain clock to
    now for models whose artifacts could be hours old, and `train_if_due` then correctly
    declined to retrain for another `retrain_every_h`.

    MEASURED on the deployment: Isolation Forest, Gradient Boosting and DBSCAN were loaded from
    disk on each restart and had not retrained in 16 hours despite a 6-hour interval, while the
    Adaptive Baseline -- which has its own fast-refresh path -- trained every few minutes. The
    stale models raised nothing, looked healthy on the status page, and kept scoring against a
    baseline trained on an older traffic mix.

    The age now comes from the ARTIFACT rather than from the process's uptime, so a warm start
    resumes the previous schedule instead of restarting it.
    """
    if_model, gb_model, db_model, bl_model = detectors
    any_loaded = 0
    for d in detectors:
        if d.load():
            any_loaded += 1
    if any_loaded == len(detectors):
        logger.info("All detectors loaded from disk — warm start")
        oldest = _oldest_trained_at(detectors)
        if oldest is not None:
            age_h = (utcnow() - as_aware(oldest)).total_seconds() / 3600
            logger.info("Artifacts are %.1fh old (retrain due at %dh)",
                        age_h, settings.retrain_every_h)
        return True, oldest

    end_dt, start_dt = utcnow(), utcnow() - timedelta(hours=settings.retrain_window_h)
    trained_any = False
    # WHICH detectors actually trained, tracked as we go. `_record_model_metadata` writes a
    # TRAINING-HISTORY row, and the health probe counts those rows -- so writing one for a detector
    # that did not train is a false claim about the pipeline (audit F023, confirmed live). The list
    # is built from the real return values rather than inferred later from `trained_at`, because
    # that inference is the same guess that produced the defect.
    trained: list = []
    if if_model.train(start_dt, end_dt, client) and if_model.X_train_unscaled is not None:
        trained.append(if_model)
        trained_any = True
        # The GB teacher is fitted from IF's own labels, but a GB train can still return
        # False (no anomalies in the teacher, no teacher). A False result must not earn a
        # training-history row (GitHub #60); the detector still has the previous artifact.
        if gb_model.train(if_model, if_model.X_train_unscaled, start_dt, end_dt, client):
            trained.append(gb_model)
    if db_model.train(start_dt, end_dt, client):
        trained.append(db_model)
        trained_any = True
    if bl_model.train(start_dt, end_dt, client):
        trained.append(bl_model)
        trained_any = True
        bl_model.persist_history(client, settings.retrain_window_h)
    if trained:
        _record_model_metadata(client, trained)

    if not trained_any:
        logger.warning(
            "Cold start found no data to train on — detection stays idle until "
            "the next cycle. This is expected on a fresh deployment and clears "
            "once flows arrive."
        )
        return False, None
    return True, _oldest_trained_at(detectors)


def _oldest_trained_at(detectors) -> datetime | None:
    """When the OLDEST full detector was trained, taken from the artifacts themselves.

    THE OLDEST, not the newest: the retrain clock must fire when the stalest model is due, so one
    freshly-trained detector cannot hold a retrain back for the others.

    THE ADAPTIVE BASELINE IS EXCLUDED. It refreshes on its own faster cadence, so including it
    would pin the clock to a timestamp from minutes ago on every cycle and the full retrain would
    never become due -- which is exactly the bug being fixed here.

    None when no detector reports a timestamp, which the caller reads as "due". An unknown age
    must not silently suppress a retrain.
    """
    from weirvern.models.detectors import AdaptiveBaselineDetector

    # `trained_at` lives on the detector's METADATA, not on the detector: base.py records it as
    # a ModelMetadata field at persist time and the load path logs it ("Loaded Isolation Forest
    # from disk (trained ...)"). Reading `d.trained_at` would have been None for every detector
    # and the retrain clock would have silently treated everything as due -- the opposite
    # failure, and a busy one.
    stamps = []
    for d in detectors:
        if isinstance(d, AdaptiveBaselineDetector):
            continue
        # ONLY READY DETECTORS COUNT. `ModelMetadata.trained_at` has
        # `default_factory=datetime.now`, so a detector that has NEVER been trained still reports
        # a timestamp -- the moment it was constructed. Including it would pin the clock to
        # "just now" and suppress the retrain this helper exists to schedule: the same
        # never-retrain failure, arrived at from the other direction. A detector that is not
        # ready contributes nothing, and if none are ready the answer is None ("due").
        if not d.is_ready():
            continue
        meta = getattr(d, "metadata", None)
        stamps.append(getattr(meta, "trained_at", None))
    valid = [s for s in stamps if isinstance(s, datetime)]
    return min(valid) if valid else None


def train_if_due(
    client: Client,
    detectors,
    settings,
    cfg: ModelConfig,
    last_full_train: datetime | None,
) -> datetime | None:
    """Retrain on cadence (legacy: full retrain every 6h, fast baseline
    refresh every cycle). v20 fix: the first rebuild had no retraining at all
    after a warm start — models went stale forever.

    The returned timestamp only advances when a full retrain actually happened
    (at least one detector trained). Otherwise the next cycle retries a full
    retrain rather than deferring it a whole cadence while models stay stale.
    """
    now = utcnow()
    if last_full_train is None or (now - as_aware(last_full_train)) > timedelta(hours=settings.retrain_every_h):
        end_dt = now
        start_dt = now - timedelta(hours=settings.retrain_window_h)
        logger.info("🔄 Full retrain (window %dh)", settings.retrain_window_h)
        if_model, gb_model, db_model, bl_model = detectors
        trained_any = False
        # Same rule as the cold start: record history ONLY for what trained (audit F023).
        trained: list = []
        if if_model.train(start_dt, end_dt, client):
            trained_any = True
            trained.append(if_model)
            if if_model.X_train_unscaled is not None and gb_model.train(
                    if_model, if_model.X_train_unscaled, start_dt, end_dt, client):
                trained.append(gb_model)
        if db_model.train(start_dt, end_dt, client):
            trained_any = True
            trained.append(db_model)
        if bl_model.train(start_dt, end_dt, client):
            trained_any = True
            trained.append(bl_model)
            bl_model.persist_history(client, settings.retrain_window_h)
        if not trained_any:
            logger.warning("Full retrain produced nothing (insufficient data) — will retry next cycle")
            return last_full_train
        _record_model_metadata(client, trained)
        return now

    # Fast baseline refresh (legacy: every 5-min cycle, 1-day window).
    bl_model = next((d for d in detectors if isinstance(d, AdaptiveBaselineDetector)), None)
    if bl_model is not None and bl_model.train(now - timedelta(hours=24), now, client):
        # Keep the DB mirrors in step with the on-disk artifact we just saved.
        bl_model.persist_history(client, 24)
        _record_model_metadata(client, [bl_model])
    return last_full_train


def process_model_actions(client: Client, detectors, settings, cfg: ModelConfig) -> None:
    """Carry out whatever the operator asked for on the Models page.

    Cheap when idle: two indexed lookups against a table with a handful of rows. The WORKER does
    this because it is the only process that owns MODEL_DIR; the GUI files rows and reads them
    (weirvern/models/actions.py explains why the channel between the two pods is ClickHouse).

      * `retrain` -> train a candidate and report it. Nothing live is touched.
      * `keep`    -> install the candidate over the live artifacts (archiving what they replace)
                     and record the training history at the moment it becomes live.
      * `trash`   -> delete the candidate. The live models were never touched.

    A request that cannot be carried out is moved to `failed` WITH ITS REASON, never left in
    `requested`: a request that sits there forever looks like a worker that is busy.
    """
    from weirvern.models import actions, retrain  # noqa: PLC0415

    for req in actions.pending(client, actions.RETRAIN):
        action_id = req["action_id"]
        actions.finish(client, action_id, actions.RUNNING)
        try:
            report = retrain.run_candidate(client, settings, cfg)
        except Exception as exc:  # noqa: BLE001
            logger.exception("forced retrain %s failed", action_id)
            actions.finish(client, action_id, actions.FAILED,
                           report={"error": f"{type(exc).__name__}: {exc}"})
            continue
        actions.finish(client, action_id, actions.DONE, report=report,
                       note=retrain.report_summary(report))

    for req in actions.pending(client, actions.KEEP):
        action_id = req["action_id"]
        target = req["target_id"] or str((actions.latest(client, actions.RETRAIN) or {}).get(
            "action_id", ""))
        done = actions.latest(client, actions.RETRAIN) or {}
        if done.get("state") != actions.DONE or done.get("action_id") != target:
            actions.finish(client, action_id, actions.FAILED,
                           note="no finished candidate to keep")
            continue
        try:
            outcome = retrain.apply_candidate(client, settings, detectors)
        except Exception as exc:  # noqa: BLE001
            logger.exception("keeping candidate %s failed", target)
            actions.finish(client, action_id, actions.FAILED,
                           report={"error": f"{type(exc).__name__}: {exc}"})
            continue
        if not outcome["installed"]:
            failed = outcome.get("failed") or []
            why = ("; ".join(f"{f['name']}: {f['reason']}" for f in failed)
                   or "the candidate had no artifacts left to install")
            actions.finish(client, action_id, actions.FAILED, note=why)
            continue
        # The artifacts are live; their training IS the newest entry in the model history, and
        # the metadata inside them carries the candidate's real training time (not now).
        try:
            _record_model_metadata(client, detectors)
        except Exception as exc:  # noqa: BLE001
            logger.warning("could not record model metadata after keep: %s", exc)
        refused = outcome.get("failed") or []
        note = f"{len(outcome['installed'])} artifact(s) installed"
        if refused:
            note += f"; {len(refused)} refused: " + "; ".join(
                f"{f['name']}: {f['reason']}" for f in refused)
        actions.finish(client, action_id, actions.APPLIED, report=outcome, note=note)

    for req in actions.pending(client, actions.TRASH):
        action_id = req["action_id"]
        # MEASURED LIVE: a trash filed while the retrain was still RUNNING discarded an empty
        # candidate directory and reported success -- and the retrain then wrote its artifacts into
        # a directory nobody had judged. A decision needs something to decide about, so a trash (or
        # a keep, above) only acts on a FINISHED candidate; anything else is failed with the reason.
        done = actions.latest(client, actions.RETRAIN) or {}
        if done.get("state") != actions.DONE:
            actions.finish(client, action_id, actions.FAILED,
                           note="no finished candidate to discard: the retrain is not done")
            continue
        try:
            outcome = retrain.discard_candidate(settings)
        except Exception as exc:  # noqa: BLE001
            logger.exception("discarding candidate failed")
            actions.finish(client, action_id, actions.FAILED,
                           report={"error": f"{type(exc).__name__}: {exc}"})
            continue
        actions.finish(client, action_id, actions.DISCARDED, report=outcome,
                       note=f"{len(outcome['removed'])} artifact(s) removed")


def _record_model_metadata(client: Client, detectors) -> None:
    """Record training history for the detectors that ACTUALLY TRAINED.

    ── A ROW FOR A DETECTOR THAT DID NOT TRAIN IS A FALSE CLAIM ──────────────────────────────
    #
    # CONFIRMED DEFECT (audit F023). This wrote a metadata row for every detector it was handed,
    # and both call sites hand it the whole list. So a detector whose `train()` returned False
    # still got a `ml_models` row -- and that row is what the health probe counts:
    #
    #     models  ok=True  "4 detector(s) with training history"
    #
    # MEASURED on the live cluster: every detector's last training was 27.2 HOURS old against
    # RETRAIN_EVERY_H=6, and the probe still reported ok because it only counts rows (see F024).
    # Together those two make a pipeline that is not training look healthy, so the honest fix
    # starts here: do not write the row in the first place.
    #
    # `trained_at` is set by each detector's own `train()`, so a detector that did not train
    # carries a STALE or absent one. Rather than trust that, the call site passes only the
    # detectors that returned True -- this function cannot know otherwise, and guessing from
    # `trained_at` would reintroduce the same defect one level down.
    """
    for d in detectors:
        try:
            client.insert(
                "weirvern.ml_models",
                [list(d.metadata.to_row().values())],
                column_names=list(d.metadata.to_row().keys()),
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("Could not record metadata for %s: %s", d.name, exc)


# The anomaly row's column names, defined ONCE. The row literal in detection_sweep and this tuple
# must agree in length AND order; separating the two definitions is what let them drift by two
# columns (the legacy pair was added here and not to the row).
_ANOMALY_COLUMNS: tuple[str, ...] = (
    "detected_at", "window_start", "window_end", "src_addr", "anomaly_score",
    "confidence", "isolation_forest_score", "gradient_boosting_score",
    "dbscan_score", "baseline_score", "model_agreement",
    "primary_deviation_feature", "primary_deviation_zscore", "deviation_magnitude",
    "feature_contributions", "baseline_comparison", "detected_by_models", "severity",
    "attack_techniques", "attack_label", "strong_families", "severity_basis",
    "network_scope",
)


def _may_step_over_empty_chunk(new_cursor: datetime, *, now: datetime | None = None,
                               grace_s: float = CURSOR_GAP_GRACE_S) -> bool:
    """Whether an empty chunk is old enough to be stepped over instead of re-read forever.

    Split out of the sweep so the decision is a pure function of two clocks: the whole point of the
    grace period is that it is testable at the boundary, and a test that has to build a ClickHouse
    client to ask "does this wedge?" would never have been written.

    `now` is injectable for the same reason. The comparison uses `<` rather than `<=`: a chunk that
    ended exactly at the horizon is still inside it.
    """
    return new_cursor < (now or utcnow()) - timedelta(seconds=grace_s)


def _covered_through(settings, last_covered: datetime | None) -> tuple[datetime, datetime]:
    """The lower bound for this sweep's window, and the new cursor to carry forward.

    The cursor is returned as a plain `datetime`, NOT `datetime | None`: this function always knows
    the time the sweep started, so "there was no cursor to resume from" is a fact about the INPUT and
    is never a reason to return no cursor. An earlier version typed the return as optional and mypy
    caught the consequence -- two call sites passed a possibly-None cursor to the writer, which would
    have silently recorded nothing (or raised) on the very first cycle after a restart, the case the
    checkpoint exists for.

    ── A SLOW CYCLE LEFT WINDOWS UNEXAMINED, WITH NOTHING LOGGED (audit F045) ──────────────────

    The lookback is `AGG_BUCKET_S + detect_interval_s` = 600s at the shipped settings, and it used to
    be applied to `now()` EVERY cycle. That is correct for a cycle that starts on time, and it
    silently assumes the previous one ran 300s ago. When a cycle takes longer than the lookback, the
    window has MOVED PAST windows that were never examined, and the only trace is a gap in a
    heartbeat.

    MEASURED ON THE LIVE CLUSTER, from `baseline_history.computed_at` gaps over 48 hours:

        cycles: 292   median gap: 300s   p99: 966s   MAX: 1183s
        ten separate gaps over 600s: 1183, 1170, 1138, 949, 897, 893, 847, 835, 818, 778
        gap 1183s  ->  2 whole 5-minute buckets never examined

    The cause is in this module's own loop: `train_if_due` runs BEFORE the sweep and blocks, so the
    6-hourly full retrain (and any ClickHouse slowness) pushes the next sweep's `now()` forward while
    `since` moves with it. The loop compensates the SLEEP at the end of the cycle -- so the cadence
    looks healthy afterwards -- but nothing recovers the window that was skipped. Those buckets are
    still in `flows_aggregated`: they age out of the lookback, not out of the table, so the data is
    THERE and simply stops being examined.

    THE FIX: carry the time this sweep STARTED, and back off one bucket from it. Concretely,

        since = min(now - lookback, cursor - AGG_BUCKET_S)

    WHY `min` AND WHY THE BACK-OFF, exactly:

      * `now - lookback` is the healthy-case window. Keeping it as one arm of the `min` means this
        function returns EXACTLY the previous window whenever cycles run on time -- the fix changes
        nothing in the healthy case, which is the property to want in a recovery mechanism.
      * `cursor - AGG_BUCKET_S` is the recovery arm: it re-covers the bucket that was IN FLIGHT when
        the previous sweep started. That bucket was only partially written at the time (its flows
        keep arriving for the rest of its 300s), so the previous sweep saw a partial row. Re-reading
        it is safe -- the (window_start, src_addr) dedupe below skips what was already recorded --
        and NOT re-reading it would be the gap this function exists to close.
      * The two arms coincide in the healthy case: cursor = now - detect_interval_s, so
        `cursor - AGG_BUCKET_S = now - detect_interval_s - AGG_BUCKET_S`, which is precisely
        `now - lookback`. Verified by test rather than by arithmetic alone.

    CLAMPED TO THE RETENTION THAT EXISTS. Widening the window across a long outage (a worker scaled
    to zero for a day, say) would try to score 24 hours of aggregates in one pass: a burst that costs
    far more than it finds, and the models are trained on `retrain_window_h` in any case. So the
    window is never older than that retention, and a gap exceeding it is LOGGED as unrecoverable
    rather than silently re-windowed.

    RETURNED, NOT STORED. The caller owns the cursor, so this stays a pure function of its inputs and
    is testable with no filesystem and no loop.
    """
    now = utcnow()
    lookback_s = max(AGG_BUCKET_S + settings.detect_interval_s, settings.detect_interval_s)
    default_since = now - timedelta(seconds=lookback_s)

    since = default_since
    if last_covered is not None:
        if last_covered > now:
            # A clock that went BACKWARDS (an NTP step, a restarted node) must not be trusted: the
            # cursor would sit in the future and every later sweep would examine nothing. The
            # default window is self-correcting, so fall back to it.
            logger.warning(
                "Detection cursor %s is in the FUTURE (clock stepped?); falling back to the "
                "default %ds window", last_covered, lookback_s,
            )
        else:
            recovery_since = last_covered - timedelta(seconds=AGG_BUCKET_S)
            since = min(default_since, recovery_since)

    # Never older than the retention the models were trained against -- see the docstring.
    floor = now - timedelta(hours=max(1, settings.retrain_window_h))
    if since < floor:
        logger.warning(
            "Detection covered nothing for %.1fh before %s (retention %dh): those aggregates have "
            "aged past the window the models know and CANNOT be scored now. Sweeping %.1fh instead. "
            "A gap this large means detection was not running at all -- that is what the "
            "detect_loop probe is for.",
            (now - since).total_seconds() / 3600, last_covered, settings.retrain_window_h,
            settings.retrain_window_h,
        )
        since = floor

    # ── ONE CYCLE MUST NOT TRY TO COVER THE WHOLE BACKLOG (measured 2026-11-12) ────────────────
    #
    # The two clamps above bound HOW FAR BACK the window reaches. Neither bounds HOW MUCH one
    # cycle examines, and those are different numbers. MEASURED: `since` reached 17 hours back,
    # roughly 37,000 host-windows in one pass, the worker was OOMKilled before it could save the
    # cursor, so the cursor never advanced and the next cycle repeated it exactly.
    #
    # A CHUNK, NOT A NARROWER WINDOW. `since` is left where it is, so nothing is dropped and the
    # backlog is still covered in full; only the CURSOR is held to one chunk, so successive sweeps
    # walk forward and each one is bounded. Returning a cursor of `now` while reading only a chunk
    # would mark the unread remainder as covered, which is the silent-skip defect this file has
    # already fixed twice.
    #
    # THE CALLER MUST APPLY THE SAME UPPER BOUND TO ITS READS, or this changes nothing.
    cap = timedelta(seconds=MAX_CATCHUP_BUCKETS * AGG_BUCKET_S)
    if now - since > cap:
        chunk_end = since + cap
        logger.warning(
            "Detection is %.1fh behind and is draining in bounded chunks of %.1fh, so no single "
            "cycle can OOM. About %d cycle(s) to reach the present. Nothing is skipped: each "
            "cycle resumes at the chunk boundary. THIS CHUNK: %s -> %s",
            (now - since).total_seconds() / 3600,
            cap.total_seconds() / 3600,
            int((now - since).total_seconds() / cap.total_seconds() + 0.999),
            since, chunk_end,
        )
        return since, chunk_end

    return since, now


def _load_detect_cursor(settings) -> datetime | None:
    """The boundary the previous sweep covered, or None if there is no usable checkpoint.

    ── WHY THIS IS ON DISK AND NOT IN MEMORY ───────────────────────────────────────────────────

    A worker restart is one of the ways this gap occurs: the loop exits and the next process starts
    a fresh `now() - lookback` window, stepping over everything the previous process had not reached.
    An in-memory cursor would be reset by exactly the event it needs to survive, so it lives beside
    the model artifacts -- the same `MODEL_DIR` that already persists across restarts for this
    reason.

    A MISSING OR UNREADABLE FILE IS NOT AN ERROR. On first run there is nothing to resume from, and
    the default window is correct. A corrupt file is discarded rather than raising: refusing to
    sweep because a checkpoint is malformed would trade a small recovery for a total detection
    outage, which is the worse of the two.
    """
    path = Path(settings.model_dir) / "detect_cursor.json"
    try:
        data = json.loads(path.read_text())
        value = data.get("covered_through")
        if not value:
            return None
        parsed = datetime.fromisoformat(value)
        # A CURSOR IS A TIME, AND TIMES ARE AWARE HERE. Older cursors were written without a
        # zone; comparing one to utcnow() raises TypeError and, measured live after a restart,
        # stops the entire detection loop. Normalise the old form instead of refusing it.
        return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)
    except FileNotFoundError:
        return None
    except Exception as exc:  # noqa: BLE001 - see the docstring
        logger.warning("Detection cursor at %s is unusable (%s); starting a fresh window", path, exc)
        return None


def _save_controls(settings, checks) -> None:
    """Record the control verdicts beside the cursor, so the health probe reads the LAST run.

    Written on EVERY sweep, including degraded ones. A file that only appears when things are well
    is indistinguishable from a worker that stopped running the controls at all -- the same
    ambiguity as a health panel with no capture row.

    Failure to write is a warning, not an exception: the sweep has already done its work, and a
    bookkeeping problem must not discard a detection cycle.
    """
    path = Path(settings.model_dir) / "detection_controls.json"
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({
            "checked_at": datetime.now(UTC).isoformat(),
            "ok": not any(c.ok is False for c in checks),
            "checks": [{"name": c.name, "ok": c.ok, "detail": c.detail} for c in checks],
        }))
    except OSError as exc:
        logger.warning("could not record detection controls: %s", exc)


def _save_detect_cursor(settings, covered_through: datetime) -> None:
    """Record the boundary this sweep covered. Failure here is logged, never raised.

    A CHECKPOINT THAT CANNOT BE WRITTEN IS NOT A REASON TO LOSE THE SWEEP'S VERDICTS. The sweep has
    already persisted its anomalies and is about to alert on them; raising here would discard that
    work to report a bookkeeping problem. The consequence of a failed write is one skipped-window
    risk, the same as before this fix, not a lost detection cycle.
    """
    path = Path(settings.model_dir) / "detect_cursor.json"
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"covered_through": covered_through.isoformat()}))
        # ONE LINE PER SAVE, WITH THE VALUE. A cursor that advances less than the chunk it was given
        # is otherwise invisible: the drain loop can only report where it ended up, not which of the
        # call sites wrote it or what it was handed. `aware` is in the line because a naive/aware
        # mismatch here silently changes what the next `since` becomes.
        logger.info("detect cursor -> %s (tzinfo=%s)", covered_through.isoformat(),
                    "aware" if covered_through.tzinfo else "naive")
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "Could not record the detection cursor at %s (%s). A cycle longer than the lookback "
            "may skip a window until this is writable.", path, exc,
        )


def _true_cardinalities(client: Client, since: str) -> dict[tuple, dict]:
    """Exact distinct counts per (window_start, src_addr), read from the RAW flow table.

    ── WHY THIS EXISTS RATHER THAN SUMMING THE PARTIALS (audit F-T1046) ────────────────────────

    The aggregate tables hold one row per INSERT BLOCK, each with `uniq(dst_addr)` / `uniq(dst_port)`
    computed over that block alone. Summing those partial counts is an UPPER BOUND: a destination
    contacted in three blocks is counted three times.

    An upper bound is the wrong direction for these numbers, because they GATE detection. T1046 fires
    on `unique_dst_ports >= DISCOVERY_MIN_PORTS` and T1018 on `unique_dst_ips >= 20`; an inflated
    count manufactures port-scan alerts on hosts that merely contacted the same few destinations
    repeatedly. Trading a detection gap for false positives is not a fix.

    The raw table still holds every flow, so the true distinct counts are one query away. That read
    covers only the windows this sweep examines (one aggregation interval plus a bucket, not the
    whole retention), and it is the only source that is actually correct.

    FAILURE IS SURFACED, NOT SILENT. If the raw read fails, the caller falls back to the summed upper
    bound and LOGS it. An approximation that a threshold reads must never be invisible, because a
    silently approximate count is exactly how this defect went unnoticed.
    """
    out: dict[tuple, dict] = {}
    try:
        cols, rows = db.fetch_rows_named(
            client,
            # THE SAME EXPRESSIONS THE MATERIALIZED VIEW USES, evaluated over the WHOLE window
            # instead of one insert block. `entropy(dst_port)`, `stddevPop` and the quantiles are
            # per-block measurements in the aggregate tables and CANNOT be recovered from those
            # blocks: an entropy computed over 2 ports is bounded by 1.0 no matter how many blocks
            # are added, while T1046 requires 3.0. MEASURED on the live cluster: the fragmented
            # windows hold per-block entropy of 0 to 0.54 and T1046's threshold is 3.0, so the
            # collapse alone left that rule blind -- the value has to be recomputed, not folded.
            #
            # `WHERE dst_port > 0` and the active-minutes expression are copied from the view, so
            # the raw path and the aggregate path describe the same population.
            "SELECT toStartOfFiveMinute(time_flow_start) AS window_start, src_addr, "
            "       uniqExact(dst_addr) AS n_dst_ips, uniqExact(dst_port) AS n_dst_ports, "
            "       uniqExact((dst_addr, dst_port)) AS n_connections, "
            "       entropy(dst_port) AS port_entropy, "
            "       stddevPop(bytes) AS bytes_stddev, "
            "       stddevPop(packets) AS packets_stddev, "
            "       count(DISTINCT toStartOfMinute(time_flow_start)) AS active_minutes "
            "FROM weirvern.flows WHERE time_flow_start >= %(since)s AND dst_port > 0 "
            "GROUP BY window_start, src_addr",
            since=since,
        )
        for r in rows:
            rec = dict(zip(cols, r, strict=False))
            out[(rec["window_start"], rec["src_addr"])] = {
                "unique_dst_ips": rec["n_dst_ips"],
                "unique_dst_ports": rec["n_dst_ports"],
                "unique_dst_addrs": rec["n_dst_ips"],
                "unique_connections": rec["n_connections"],
                # Recomputed over the whole window -- see the query's comment for why folding is
                # impossible. These are the values the RULES read, so they must be per-window.
                "port_entropy": rec["port_entropy"],
                "bytes_stddev": rec["bytes_stddev"],
                "packets_stddev": rec["packets_stddev"],
                "active_minutes": rec["active_minutes"],
            }
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "Could not read exact distinct counts from the raw flow table (%s). Falling back to "
            "SUMMING the partial aggregate rows, which is an UPPER BOUND: a destination seen in "
            "several insert blocks is counted once per block, so discovery thresholds "
            "(unique_dst_ports, unique_dst_ips) may OVERSTATE and raise scan alerts that are not "
            "there. This sweep's cardinalities are approximate.", exc,
        )
    return out


def _collapse_partial_aggregates(flows: list[dict], div_idx: dict, client: Client) -> list[dict]:
    """Fold per-insert-block partial aggregate rows into ONE row per (window_start, src_addr).

    See the call site for the measured fragmentation (93.8% of host-windows, up to 46 rows each) and
    for why each field is folded the way it is. This function performs the fold; the reasoning and
    the numbers live at the call site.

    ROW ORDER STOPS MATTERING HERE, which is the point. Before this, whichever partial row happened
    to arrive last silently decided every threshold -- so the same scan could be detected or missed
    depending on the order ClickHouse returned rows in.
    """
    if not flows:
        return []

    keys = {(f["window_start"], f["src_addr"]) for f in flows}
    if len(keys) == len(flows):
        # Nothing fragmented in this window. Returned UNCHANGED rather than rebuilt, so the common
        # case allocates nothing and every value is bit-identical to before this fix.
        return flows

    first = min(f["window_start"] for f in flows)
    since = first.strftime("%Y-%m-%d %H:%M:%S") if hasattr(first, "strftime") else str(first)
    exact = _true_cardinalities(client, since)

    # Additive: the window's total IS the sum of its blocks.
    ADDITIVE = ("flow_count", "total_bytes", "total_packets")
    # Cardinality: replaced by the exact raw-table read where available. The SUM is the documented
    # upper-bound fallback -- `_true_cardinalities` logs when that fallback is what happened.
    CARDINALITY = ("unique_dst_ips", "unique_dst_ports", "unique_dst_addrs", "unique_connections")
    # Estimates that arithmetic on partials cannot recover: an average of averages weights every
    # block equally regardless of size. The LARGEST block's value is the best available estimate,
    # because the largest block is the closest thing to the window as a whole.
    LARGEST_BLOCK = ("avg_bytes", "avg_packets")
    # NOT RECOVERABLE FROM PARTIALS AT ALL, and the largest block is not a substitute either:
    # entropy over 2 ports cannot exceed 1.0 however many blocks are added, while T1046 requires
    # 3.0. Recomputed from the raw flows by `_true_cardinalities`, which runs the materialized
    # view's own expressions over the whole window.
    NON_FOLDABLE = ("port_entropy", "bytes_stddev", "packets_stddev", "active_minutes")

    merged: dict[tuple, dict] = {}
    for f in flows:
        key = (f["window_start"], f["src_addr"])
        cur = merged.get(key)
        if cur is None:
            merged[key] = dict(f)
            merged[key]["_largest_block_flows"] = f.get("flow_count") or 0
            merged[key]["_largest_block_bytes"] = f.get("total_bytes") or 0
            merged[key]["_largest_block_packets"] = f.get("total_packets") or 0
            continue
        for col in ADDITIVE:
            if col in f:
                cur[col] = (cur.get(col) or 0) + (f.get(col) or 0)
        for col in CARDINALITY:
            if col in f:
                cur[col] = (cur.get(col) or 0) + (f.get(col) or 0)  # upper bound; replaced below
        # ── A TOTAL ORDER, NOT A RACE (measured 2026-10-16) ───────────────────────────────────
        #
        # This compared flow counts alone, so two blocks with the SAME count left the window's
        # avg_bytes/avg_packets to whichever row ClickHouse happened to return first -- and the
        # seeded-attack harness caught what that costs: the same host-window scored 0.6978 in one
        # pass and 0.6001 in the next with byte-identical feature contributions, because the ROW
        # had been assembled differently, not the model. The fold's own docstring promises "row
        # order stops mattering here"; for this tie it did not. (flow_count, total_bytes,
        # total_packets) is a total order over the values the two LARGEST_BLOCK columns are derived
        # from, so ties on all three imply identical averages and the choice cannot matter.
        rank = (f.get("flow_count") or 0, f.get("total_bytes") or 0, f.get("total_packets") or 0)
        cur_rank = (cur.get("_largest_block_flows") or 0, cur.get("_largest_block_bytes") or 0,
                    cur.get("_largest_block_packets") or 0)
        if rank > cur_rank:
            (cur["_largest_block_flows"], cur["_largest_block_bytes"],
             cur["_largest_block_packets"]) = rank
            for col in LARGEST_BLOCK:
                if col in f:
                    cur[col] = f[col]

    for key, cur in merged.items():
        cur.pop("_largest_block_flows", None)
        cur.pop("_largest_block_bytes", None)
        cur.pop("_largest_block_packets", None)
        # The DIVERSITY side-table is fragmented the same way and supplies the port counts T1046
        # reads. Folded here so a rule reading `unique_dst_ports` sees the window's number.
        div = div_idx.get(key) or {}
        if div:
            for col in CARDINALITY:
                if col in div:
                    cur[col] = (cur.get(col) or 0) + (div.get(col) or 0)
            for col in LARGEST_BLOCK:
                if col in div and col not in cur:
                    cur[col] = div[col]
        exact_key = exact.get(key)
        if exact_key:
            # Cardinality AND the non-foldable estimates. Both come from the same raw read, because
            # both are per-window facts that the per-block aggregate rows cannot express.
            for col in CARDINALITY + NON_FOLDABLE:
                if col in exact_key:
                    cur[col] = exact_key[col]

    return list(merged.values())


def detection_sweep(client: Client, detectors, settings, cfg: ModelConfig) -> list[dict]:
    """One detection pass over the last DETECT_INTERVAL_S of aggregates.

    Returns the verdict list (which the caller alerts on) after persisting
    anomaly rows. v20 fix: alerts use these verdicts directly instead of a
    separate re-query — the old re-query's sliding window re-alerted the
    same rows every sweep.

    ── THE CONFIGURATION IS CHECKED BEFORE ANY DETECTOR RUNS (audit F186) ────────────────────────

    `thin_window_floor` and `base_threshold` are different KINDS of number -- a multiplier on a
    capped score, and an absolute score -- and when the product of the first with the score cap
    falls under the second, EVERY window below `min_flows_for_full_confidence` is unalertable
    whatever the detectors report. That shipped: 0.99 * 0.35 = 0.3465 against a bar of 0.35, which
    is why 23 of 23 live near misses scored exactly 0.3465 across six unrelated hosts and 99.8% of
    the windows on the cluster sat in the band.

    THE CHECK RUNS HERE AND ITS FAILURE IS LOGGED ONCE, NOT RAISED. `BASE_THRESHOLD` is
    operator-editable (0.0-1.0), so it can be raised on a RUNNING cluster, and raising from this
    function would make the detection loop error every cycle -- replacing "blind to thin windows"
    with "detection stops entirely", which is strictly worse. `main()` uses the RAISING form, so a
    deployment that could never have alerted refuses to start; a live edit degrades to a loud
    periodic warning. `_thin_floor_warned` keeps it to one line per distinct configuration.
    """
    check_thin_floor_reachable(cfg, settings)

    # ── THE LOOKBACK MUST BE WIDER THAN THE AGGREGATION BUCKET ────────────────────────────────
    #
    # MEASURED DEFECT, on the live cluster. The materialised views bucket flows on
    # `toStartOfFiveMinute(time_flow_start)`, and this sweep used to look back exactly
    # `detect_interval_s` -- 300s -- which is THE SAME DURATION AS THE BUCKET. Measured state:
    # all three aggregation tables held 16,934/16,870 rows, their newest `window_start` was a
    # 5-minute boundary 315 seconds old, raw flows were still arriving, and this function's own
    # query matched ZERO rows when run by hand. Detection was analysing nothing.
    #
    # WHY EQUAL DURATIONS RACE, precisely:
    #
    #   * Bucket B covers [B, B+300) and is only WRITTEN once a flow lands inside it.
    #   * A sweep at wall-clock T computes `since = T - 300` and requires `window_start >= since`.
    #   * So bucket B is visible only while T <= B + 300 -- which is exactly when the bucket's own
    #     flows stop arriving, and the NEXT bucket has only just opened and may be empty.
    #   * With the cadence equal to the bucket size the phase never drifts, so a sweep can sit in
    #     the empty case indefinitely rather than averaging out.
    #
    # At T = 00:21:50 with B = 00:15:00, `since` = 00:16:50 and `00:15:00 >= 00:16:50` is false:
    # zero rows, every cycle, while every health probe reads green -- which is why nothing caught
    # it (see audit F022: nothing probes the detection loop at all).
    #
    # THE FIX: look back the BUCKET plus one full interval. A bucket then stays inside the window
    # for its whole life plus a full interval of slack, so a sweep landing just after a bucket
    # boundary still sees the bucket that just closed.
    #
    # DERIVED FROM THE BUCKET, NOT FROM TWICE THE INTERVAL. `2 * detect_interval_s` happens to work
    # at the shipped value of 300s, and is WRONG the moment an operator raises the cadence -- at
    # DETECT_INTERVAL_S=60 the lookback would be 120s against a 300s bucket and the race would come
    # straight back, silently, on a deployment that had just made detection faster. The bucket size
    # is a property of the schema, so it is named once (AGG_BUCKET_S, next to the views it
    # describes) and this arithmetic reads it.
    #
    # The cost is re-examining up to one extra bucket per sweep, which is cheap and, more
    # importantly, SAFE: the (window_start, src_addr) dedupe below uses this SAME `since`, so rows
    # already recorded are skipped rather than re-alerted. That guard now has to work, where before
    # it was mostly idle because the window held nothing.
    #
    # ── FROM WHERE THE LAST SWEEP FINISHED, NOT FROM now() (audit F045) ─────────────────────────
    #
    # The lookback above is the window for a cycle that STARTS ON TIME, and it lives in
    # `_covered_through` now -- it used to be computed here as an unused local, which is how a second
    # copy of the arithmetic would have started drifting from the function that decides the window.
    # Applied to `now()` on every cycle, it silently assumed the previous one ran `detect_interval_s`
    # ago, so a cycle longer than the lookback moved the window past buckets that were never
    # examined. See `_covered_through` for the measured gaps and `_load_detect_cursor` for why the
    # cursor is on disk.
    _last_covered = _load_detect_cursor(settings)
    _since_dt, _new_cursor = _covered_through(settings, _last_covered)
    # THE DATABASE COLUMN IS NAIVE LOCAL TIME, THE CURSOR IS AWARE UTC. Formatting the aware
    # cursor directly wrote a UTC wall-clock into a comparison against `window_start` (a naive
    # DateTime in the server's America/Chicago zone). The cursor then sat five hours in the
    # future, every sweep matched zero rows, and detection stopped while the pod stayed green --
    # measured live: cursor 23:45Z while aggregates reached 21:30 local. Convert to the worker's
    # local zone, which is the same host zone ClickHouse uses, before formatting.
    since = _since_dt.astimezone().strftime("%Y-%m-%d %H:%M:%S")
    # THE UPPER BOUND IS WHAT MAKES THE CHUNK REAL. `_covered_through` holds the cursor to one
    # chunk of MAX_CATCHUP_BUCKETS; without this the reads below ignore that and pull the whole
    # backlog anyway, which is precisely how a capped cursor still OOMed.
    until = _new_cursor.astimezone().strftime("%Y-%m-%d %H:%M:%S")

    agg_cols, agg_rows = db.fetch_rows_named(
        client,
        # ORDERED, AND IT IS NOT COSMETIC (measured 2026-10-16). These tables can hold one row per
        # INSERT BLOCK for the same (window_start, src_addr); `_collapse_partial_aggregates` folds
        # the MAIN table order-independently, but the side tables below are indexed by key with
        # "last row wins", so WHICH copy a host-window got was ClickHouse's arbitrary choice. The
        # seeded-attack harness caught the cost: two scorings of the same window in one process gave
        # DBSCAN 0.7178 in one and 0.6487 in the other for the same host -- a detection flipped out
        # by a tie. An ORDER BY makes the read reproducible within a run and across runs; the fold
        # below still does the arithmetic.
        "SELECT window_start, window_start + INTERVAL 5 MINUTE AS window_end, src_addr, "
        "countMerge(flow_count) AS flow_count, sumMerge(total_bytes) AS total_bytes, "
        "sumMerge(total_packets) AS total_packets, uniqMerge(unique_dst_ips) AS unique_dst_ips "
        "FROM weirvern.flows_window WHERE window_start >= %(since)s "
        "AND window_start < %(until)s AND "
        # The models learn about HOSTS. A window keyed on ff02::2 would train the baseline on a
        # multicast group's "behaviour" (see weirvern/addressing.py for the measurement).
        + addressing.sql_host("src_addr") + " "
        + "GROUP BY window_start, src_addr "
        "ORDER BY window_start, src_addr",
        since=since, until=until,
    )
    if not agg_rows:
        # A cursor advanced here would be WRONG: an empty aggregate table means the window was not
        # examined because there was nothing in it, and `_covered_through` must re-cover it next
        # cycle in case rows arrive late. Only a sweep that actually ran records coverage.
        #
        # IT MUST SAY SO (measured 2026-11-12). This used to return in complete silence, so a
        # dead NetFlow path looked exactly like a quiet network: the cursor never advanced, the
        # pod stayed green, and detection was dark for sixteen hours with nothing in the log.
        # An empty read is the most important thing this function can report, so it is a
        # warning, not an info, and it carries what to check.
        logger.warning(
            "Detection sweep examined NOTHING: no host-windows in weirvern.flows_window at or "
            "after %s (the cursor would advance to %s). Detection is dark this cycle. Check "
            "whether flows are landing with: SELECT max(time_flow_start) FROM weirvern.flows. "
            "If the tap is not running, nothing reaches IPFIX -- check the zeek pod's tap "
            "sidecar (`kubectl -n weirvern logs ds/zeek -c tap`).",
            since, _new_cursor.isoformat(),
        )
        # ── AN EMPTY CHUNK THAT CAN NEVER FILL MUST NOT WEDGE THE CURSOR (measured 2026-11-17) ─────
        #
        # The refusal to advance above is the right default and stays the default: a bucket whose
        # rows are still arriving must be re-covered. It becomes a permanent stop when the
        # emptiness is a FACT rather than a delay -- an outage longer than one catch-up chunk
        # leaves a leading chunk with no flows in it that no later arrival can fill. See
        # CURSOR_GAP_GRACE_S for the live case (20 hours dark after flows returned) and the second
        # stale cursor already on the box from the same failure.
        #
        # So: re-cover inside the grace window, step over outside it, and say which happened. A
        # skipped window is not silently marked as examined -- the warning carries the boundary
        # that was skipped, and the data it would have covered does not exist.
        if _may_step_over_empty_chunk(_new_cursor):
            _save_detect_cursor(settings, _new_cursor)
            logger.warning(
                "Detection cursor was WEDGED at %s: the chunk %s -> %s is empty and ended more "
                "than %ds ago, so no row can still arrive for it. Advancing the cursor to %s "
                "instead of re-reading the same dead window every cycle.",
                _last_covered, since, until, CURSOR_GAP_GRACE_S, _new_cursor.isoformat(),
            )
        return []

    div_cols, div_rows = db.fetch_rows_named(
        client,
        "SELECT * FROM weirvern.flows_aggregated_diversity WHERE window_start >= %(since)s "
        "AND window_start < %(until)s AND "
        # The models learn about HOSTS. A window keyed on ff02::2 would train the baseline on a
        # multicast group's "behaviour" (see weirvern/addressing.py for the measurement).
        + addressing.sql_host("src_addr") + " "
        "ORDER BY window_start, src_addr",
        since=since, until=until,
    )
    tmp_cols, tmp_rows = db.fetch_rows_named(
        client,
        "SELECT * FROM weirvern.flows_aggregated_temporal WHERE window_start >= %(since)s "
        "AND window_start < %(until)s AND "
        # The models learn about HOSTS. A window keyed on ff02::2 would train the baseline on a
        # multicast group's "behaviour" (see weirvern/addressing.py for the measurement).
        + addressing.sql_host("src_addr") + " "
        "ORDER BY window_start, src_addr",
        since=since, until=until,
    )

    # THE ZEEK SIDE OF SCORING, which is what makes the Zeek features real rather than
    # train-only. Training on a feature that live scoring cannot supply is worse than not
    # having it: the model learns weights for a column that is always zero at inference,
    # so every live score is computed from a different distribution than it was fitted on.
    #
    # One query for the whole sweep, keyed on (5-minute window, host) to match
    # flows_aggregated exactly. Wrapped because a Zeek schema problem must not stop
    # detection entirely -- NetFlow-only detection is a degraded mode, not a stopped system.
    def index(cols: list[str], rows) -> dict[tuple, dict]:
        out = {}
        for r in rows:
            out[(r[0], r[1])] = dict(zip(cols[2:], r[2:], strict=False))
        return out

    zeek_idx: dict[tuple, dict] = {}
    try:
        z_cols, z_rows = db.fetch_rows_named(client, zeek_window_sql(since, until))
        zeek_idx = index(z_cols, z_rows)
        if not zeek_idx:
            logger.warning(
                "Zeek summary is empty for this sweep, so every Zeek feature is imputed. "
                "Check that the Zeek sensor covers the same segment as NetFlow."
            )
    except Exception as exc:  # noqa: BLE001
        logger.warning("Could not load the Zeek window summary (continuing NetFlow-only): %s", exc)

    div_idx = index(div_cols, div_rows)
    tmp_idx = index(tmp_cols, tmp_rows)

    # WHAT THIS CYCLE ACTUALLY READ, stated once per sweep. Without it an operator cannot tell a
    # sweep that examined one window from one that examined forty thousand, and that difference
    # is precisely what turns a stalled cursor into an OOM kill. Every number here is a count
    # that could have been zero, which is the point.
    logger.info(
        "Detection sweep: window from %s, %d host-window(s), diversity %d, temporal %d, zeek %d",
        since, len(agg_rows), len(div_rows), len(tmp_rows), len(zeek_idx),
    )

    # ── THE OTHER TWO SIDE-TABLES NEED THE SAME VOICE THE ZEEK ONE HAS ────────────────────────
    #
    # CONFIRMED DEFECT (audit F005), measured by counting the guards: `if not zeek_idx` exists and
    # WARNS, while `if not div_idx` / `if not tmp_idx` did not exist at all. An unjoined side-table
    # then flows into `extract_features`, where `if diversity:` / `if temporal:` fall through to
    # values that LOOK like measurements:
    #
    #     port_entropy          = 0.0    "no ports seen" reads as a quiet host
    #     connection_density    = 1.0    reads as one connection per flow
    #     activity_regularity   = 1.0    reads as perfectly regular traffic
    #     burstiness            = 1.0    reads as no bursting
    #
    # None of those were measured, and NOTHING SAID SO -- so every score in the sweep is silently
    # degraded and an operator has no signal that the degradation happened. The Zeek warning
    # directly above is the shape this should have had all along, and its absence here is the
    # asymmetry that made the defect hard to see: one sibling warned, so the code looked careful.
    #
    # A warning rather than a refusal: detection continuing on partial features is deliberate (an
    # alert missing a feature still beats no alert), and the point is only that the degradation is
    # STATED. The two cases are logged separately because they have different causes -- an empty
    # diversity table means the aggregation produced nothing for these windows, which is a
    # different fault from a broken Zeek summary.
    if not div_idx:
        logger.warning(
            "Diversity metrics are empty for this sweep, so log_unique_dst_ports, port_entropy, "
            "bytes_stddev_norm and connection_density are all IMPUTED (not measured). Every score "
            "in this sweep is degraded; check the Phase-2 diversity aggregation."
        )
    if not tmp_idx:
        logger.warning(
            "Temporal metrics are empty for this sweep, so activity_regularity and burstiness are "
            "both IMPUTED as 1.0 (not measured). Every score in this sweep is degraded; check the "
            "Phase-2 temporal aggregation."
        )

    # SOC-2: near misses are collected during detection and stored in the same sweep.
    # Owned here so the ensemble stays a pure function of its inputs.
    near_misses: list[dict] = []

    flows: list[dict] = [dict(zip(agg_cols, r, strict=True)) for r in agg_rows]
    # ── THE AGGREGATE TABLES HOLD PARTIAL ROWS, AND EVERY RULE READ ONE OF THEM (audit F-T1046) ─
    #
    # A ClickHouse materialized view fires PER INSERT BLOCK: each insert into `weirvern.flows`
    # produces its OWN aggregate row for the same (window_start, src_addr). The target table is
    # `MergeTree()`, not ReplacingMergeTree, so those partial rows are NEVER merged -- all of them
    # are present, each holding the counts for the block that produced it.
    #
    # MEASURED ON THE LIVE CLUSTER over 24 hours:
    #
    #     flows_aggregated:           592 host-windows, 555 fragmented = 93.8%, worst case 46 rows
    #     flows_aggregated_diversity: 589 host-windows, 552 fragmented = 93.7%, worst case 46 rows
    #
    #     one worst-case host-window, the 46 partial rows' unique_dst_ports:
    #         [1,1,1,2,1,1,1,1,1,1,2,2,2,2, ... 2]     <- 46 values
    #         what the sweep saw (max)     = 2 ports
    #         what the window holds (sum)  = 81
    #
    # WHY THIS SILENTLY DESTROYED DISCOVERY DETECTION. Two things went wrong together and either
    # alone would have been enough:
    #
    #   * `flows` was one dict PER PARTIAL ROW, so one host-window produced up to 46 scorer inputs,
    #     each scored as if it were the whole window.
    #   * `flow_by_key` below maps (window_start, src_addr) -> ONE row, and a plain dict assignment
    #     means the LAST partial wins. For a scan the last block is typically the smallest, so
    #     T1046's `ports >= DISCOVERY_MIN_PORTS` was evaluated against the LEAST informative row of
    #     the window. A 500-port scan spread over 46 insert blocks read as 1-2 ports.
    #
    # Every discovery threshold counts something per window, and every count was a per-BLOCK count:
    # that is why the finding reads "partial per-block aggregates blinding T1046/T1018".
    flows = _collapse_partial_aggregates(flows, div_idx, client)
    for f in flows:
        key = (f["window_start"], f["src_addr"])
        # ── THE THREE SIDE-TABLES ARE MERGED IN, NOT NESTED, AND THAT IS LOAD-BEARING ────────
        #
        # These used to be attached ONLY as `_diversity` / `_temporal` / `_zeek`, and the ATT&CK
        # rules read them as FLAT keys (`row.get("unique_dst_ports")`, `row.get("port_entropy")`).
        # Nothing ever flattened the nesting, so those reads always returned None -> 0.0 and the
        # rules depending on them could NEVER fire.
        #
        # Measured, with a row that satisfies T1046 on every threshold (400 ports, entropy 8.4,
        # 4 KB out, 300 destinations) and differs ONLY in where the values live:
        #
        #     nested under _diversity   -> 1 technique  [T1018]
        #     merged flat               -> 3 techniques [T1046, T1595, T1018]
        #
        # So a textbook port scan produced no discovery technique at all. This is the same class
        # of defect as the four dead-column rules already fixed earlier in this project: a name
        # read in one place that the producing side never provides under that name. The earlier fix
        # NAMES; the values were still unreachable.
        #
        # The nested forms are KEPT as well, because the detectors and explain.py read
        # `_diversity`/`_temporal`/`_zeek` explicitly and must keep working. Merging is additive.
        #
        # Collision order is deliberate: flows_aggregated first, then the side-tables, so a column
        # that exists in both (there is none today) would take the more specific table's value.
        #
        # The three are written EXPLICITLY rather than in a loop, so the attachment is greppable
        # and each lookup's index is visible: `f["_diversity"]`, `f["_temporal"]`, `f["_zeek"]` are
        # the keys the ensemble and explain.py read, and a test asserts each is present.
        f["_diversity"] = div_idx.get(key)
        f["_temporal"] = tmp_idx.get(key)
        f["_zeek"] = zeek_idx.get(key)
        for got in (f["_diversity"], f["_temporal"], f["_zeek"]):
            if not got:
                continue
            for k, v in got.items():
                # Never let a side-table shadow the flow row's own identity columns, and never
                # overwrite a key the flow row already carries -- a silent overwrite here would be
                # invisible and would change what every rule reads.
                if k not in f:
                    f[k] = v

    # ── OPERATOR-DECLARED NETWORK SCOPE ─────────────────────────────────────────────────
    # A per-host baseline is only meaningful for a declared host population. Without this
    # filter every internet peer and scanner becomes a "host"; measured live, 9,620 of 10,973
    # alerts in twelve hours were external source addresses. The table is authoritative and
    # deliberately has no RFC1918 fallback: an address outside every declared scope is
    # unclassified, and the coverage summary says so rather than hiding it.
    #
    # NO ROWS MEANS "NOT CONFIGURED YET", and detection keeps its legacy behaviour so an
    # upgrade cannot silently stop alerting before the operator has declared a network. Once
    # any scope exists, only monitored scopes are scored. A declaration that exists but has no
    # monitored scope is an intentional no-alert state and is logged as such.
    declared = networks.load_scopes(client)
    if declared:
        flows, scope_coverage = networks.filter_monitored(flows, declared)
        logger.info(
            "Network scope: %d/%d host-windows alertable; %d unclassified; labels=%s",
            scope_coverage["kept"], scope_coverage["seen"],
            scope_coverage["unclassified"], scope_coverage["by_label"],
        )
        if not flows:
            logger.warning(
                "Network scopes are declared but none are monitored; no per-host alerts "
                "will be produced this sweep. Set a scope to monitored in Settings → Networks."
            )
            _save_detect_cursor(settings, _new_cursor)
            return []

    eligible = None
    if getattr(settings, "ml_eligibility", False):
        try:
            from weirvern.models import calibration as _cal  # noqa: PLC0415
            eligible = _cal.eligibility(client, settings)
            ineligible = sorted(name for name, ok in eligible.items() if not ok)
            if ineligible:
                logger.warning("ML eligibility: %s barred from fused score: %s",
                               len(ineligible), ", ".join(ineligible))
        except Exception as exc:  # noqa: BLE001
            # A failed eligibility read must not stop detection. It DOES mean the gate did not
            # run this sweep; say so rather than silently behaving as if it passed.
            logger.warning("ML eligibility read failed (detection continues, gate skipped): %s", exc)
    # THE BAR COMES FROM THE CALIBRATION WHEN THERE IS ONE, because a conformal threshold is the
    # only construction here whose value IS the chosen alerts-per-day. A missing or saturated row
    # returns None and the decision keeps its own threshold, so this cannot fail closed into a
    # silent engine without saying so in the log.
    calibrated_bar = None
    if getattr(settings, "ml_calibrated_threshold", False):
        try:
            from weirvern.models import calibration as _cal  # noqa: PLC0415
            calibrated_bar = _cal.calibrated_bar(client, settings)
            logger.info("Alert bar: %s",
                        f"calibrated {calibrated_bar:.4f}" if calibrated_bar is not None
                        else f"uncalibrated, base_threshold {settings.base_threshold}")
        except Exception as exc:  # noqa: BLE001
            logger.warning("calibrated bar read failed (using base_threshold): %s", exc)
    score_population: list[dict] = []
    verdicts = ensemble.detect_flows(flows, detectors, settings, cfg, near_misses=near_misses,
                                      eligible=eligible, score_population=score_population,
                                      calibrated_bar=calibrated_bar)
    logger.info(
        "Detection sweep: scored %d host-window(s), %d near miss(es), %d verdict(s) above "
        "threshold",
        len(flows), len(near_misses), len(verdicts),
    )
    if near_misses:
        # BEST-EFFORT, and deliberately so: a failure to record near misses must not cost a
        # real alert. They are a tuning aid, not the product.
        try:
            client.insert(
                "weirvern.near_misses",
                [[m["window_start"], m["window_end"], m["src_addr"], m["anomaly_score"],
                  m["threshold_used"], m["reason"], m["model_agreement"],
                  m["isolation_forest_score"], m["gradient_boosting_score"],
                  m["dbscan_score"], m["baseline_score"], m["detected_by_models"],
                  utcnow()] for m in near_misses],
                column_names=["window_start", "window_end", "src_addr", "anomaly_score",
                              "threshold_used", "reason", "model_agreement",
                              "isolation_forest_score", "gradient_boosting_score",
                              "dbscan_score", "baseline_score", "detected_by_models",
                              "replaced_at"],
            )
            logger.info("Recorded %d near miss(es)", len(near_misses))
        except Exception as exc:  # noqa: BLE001
            logger.warning("Could not record near misses (continuing): %s", exc)
    if score_population:
        # PRD-2: the population is every scored host-window BEFORE the threshold. A write
        # failure must not stop detection; the calibration pass will name its fallback.
        try:
            from weirvern.models import calibration as _cal_pop  # noqa: PLC0415

            recorded = _cal_pop.record_population(
                client, score_population, model_version=__version__)
            logger.info("ML score population: %d raw score(s) recorded", recorded)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Could not record score population (calibration falls back): %s", exc)
    if not verdicts:
        # The aggregates WERE read and scored here; there was simply nothing above threshold, so
        # coverage is real and must be recorded -- otherwise a quiet network would look like the
        # loop was stuck and every sweep would re-read the same window.
        #
        # SAID OUT LOUD, because "scored 4,000 windows and nothing crossed the bar" and "read
        # nothing at all" are opposite diagnoses that used to produce the same empty result and
        # the same silent return.
        logger.info(
            "Detection sweep: %d host-window(s) scored, none above threshold; cursor advanced "
            "to %s", len(flows), _new_cursor.isoformat(),
        )
        _save_detect_cursor(settings, _new_cursor)
        return []

    flow_by_key = {(f["window_start"], f["src_addr"]): f for f in flows}

    # Skip host-windows already recorded (overlapping sweeps re-see the same
    # 5-minute aggregate rows). The table is ReplacingMergeTree on
    # (window_start, src_addr), so this is a cheap correctness+cleanliness
    # guard, not the only line of defense.
    try:
        existing = {
            (r[0], r[1]) for r in db.fetch_rows(
                client,
                "SELECT window_start, src_addr FROM weirvern.netflow_anomalies "
                "WHERE window_start >= %(since)s",
                since=since,
            )
        }
    except Exception as exc:  # noqa: BLE001
        logger.warning("Could not pre-load existing anomalies (continuing): %s", exc)
        existing = set()

    rows = []
    fresh: list[dict] = []
    # The per-host baseline lives on the AdaptiveBaselineDetector, which already
    # computes mean/stddev/percentiles per host. Reach for it once rather than per
    # anomaly row.
    baseline_det = next(
        (d for d in detectors if getattr(d, "name", "") == "Adaptive Baseline"), None)
    baselines = getattr(baseline_det, "baselines", None) or {}
    for v in verdicts:
        if (v["window_start"], v["src_addr"]) in existing:
            continue
        fresh.append(v)
        f = flow_by_key.get((v["window_start"], v["src_addr"]), {})
        # Real explainability instead of the placeholders this used to write
        # (0.0, 0.0, "{}", "") — see weirvern/explain.py for why the deviation is
        # measured against the host's own baseline.
        exp = explain(f, baselines.get(v["src_addr"]))
        # ── SEVERITY IS DECIDED WHERE THE EVIDENCE IS ───────────────────────────────────────
        #
        # `detect_flows` can see the scores and the structural signature, but not the host's
        # measured deviation -- that needs the baseline and is computed here. Its provisional
        # severity is therefore re-evaluated against the explanation: a 0.99 model score on a
        # gateway whose bytes moved 1.3x must not stay `critical`. Direct signatures (a port
        # scan) and new TLS fingerprints remain material without a volume z-score.
        novelty = has_novelty(f, baselines.get(v["src_addr"]))
        v["severity"] = ensemble.severity_of(
            v["anomaly_score"], v.get("strong_models", 0), bool(v.get("signature")),
            strong_families=v.get("strong_families"),
            deviation_magnitude=float(exp["deviation_magnitude"]),
            novelty=novelty,
        )
        v["severity_basis"] = ensemble.severity_basis(
            v["anomaly_score"], v.get("strong_families", 0), bool(v.get("signature")),
            float(exp["deviation_magnitude"]), novelty,
        )
        # Attach the explanation to the verdict as well as the row. The alert
        # formatter reads baseline_comparison to say WHY, and the DB row must
        # carry the same values: an alert that explains an anomaly differently
        # from the stored row is worse than no explanation at all.
        v.update({
            "primary_deviation_feature": exp["primary_deviation_feature"],
            "primary_deviation_zscore": exp["primary_deviation_zscore"],
            "deviation_magnitude": exp["deviation_magnitude"],
            "feature_contributions": exp["feature_contributions"],
            "baseline_comparison": exp["baseline_comparison"],
        })
        # ATT&CK mapping was removed from this tool. The two legacy columns remain in the
        # table for schema compatibility, but they are always empty from here on: no
        # technique is computed, stored for display, or sent to an alert.
        rows.append([
            utcnow(), v["window_start"], f.get("window_end"), v["src_addr"],
            v["anomaly_score"], v["confidence"], v["isolation_forest_score"],
            v["gradient_boosting_score"], v["dbscan_score"], v["baseline_score"],
            v["model_agreement"], exp["primary_deviation_feature"],
            exp["primary_deviation_zscore"], exp["deviation_magnitude"],
            exp["feature_contributions"], exp["baseline_comparison"],
            v["detected_by_models"], v["severity"],
            # Legacy ATT&CK columns, intentionally empty after the mapping removal.
            "[]", "",
            int(v.get("strong_families") or 0), str(v.get("severity_basis") or ""),
            str(f.get("_network_scope") or ""),
        ])
    # THE GUARD THAT SHOULD HAVE CAUGHT THIS. A positional INSERT is correct only while the row
    # and the column list agree in length AND order, and they used to live 20 lines apart.
    # clickhouse-connect does raise on a mismatch (driver/insert.py:94), but it raises INSIDE the
    # worker loop, where the generic handler turns it into "a quiet network". Fail here instead,
    # where the message can name the cause.
    for _row in rows:
        if len(_row) != len(_ANOMALY_COLUMNS):
            raise ValueError(
                f"anomaly row has {len(_row)} values but {len(_ANOMALY_COLUMNS)} column names; "
                "a positional INSERT must agree in length and order"
            )
    skipped = len(verdicts) - len(fresh)
    if skipped:
        logger.info("⏭️  Skipped %d already-recorded host-windows", skipped)
    if not rows:
        # Nothing new: return nothing so the alert pass does not re-push
        # detections that were already alerted in an earlier sweep.
        #
        # AND RECORD WHAT WAS COVERED (issue #34). This state -- verdicts produced, every one
        # already recorded -- fell between the two older save sites: the sweep READ the
        # aggregates, FOLDED and SCORED them, and accounted for every verdict; the
        # examination happened, so `_new_cursor` is a truth about this sweep exactly as in the
        # no-verdicts branch above. Without this save the cursor stays pinned at the last
        # FRESH write, and every later sweep re-reads, re-folds, re-scores and re-skips the
        # whole span from that pin -- work growing without bound on a quiet network, logged
        # only as "Skipped N already-recorded host-windows".
        _save_detect_cursor(settings, _new_cursor)
        return []

    client.insert("weirvern.netflow_anomalies", rows, column_names=list(_ANOMALY_COLUMNS))
    logger.info("🚨 %d anomalies recorded", len(rows))
    # ── THE SWEEP RAN TO COMPLETION: RECORD WHAT IT COVERED (audit F045) ────────────────────────
    #
    # Placed HERE, at the end, and not at the top: the cursor means "this time was examined", and a
    # sweep that raised on the way would not have examined it. Recording at the start would turn any
    # mid-sweep exception into a permanently skipped window -- the defect this fixes, made worse.
    _save_detect_cursor(settings, _new_cursor)

    # ── CONTROLS: a sweep that cannot demonstrate its own ranking is not a measurement ────────
    #
    # Placed after the cursor is saved, deliberately. The window WAS examined whether or not the
    # controls pass; a control failure must not re-open it and score the same rows again next
    # cycle. What a failure changes is the STATUS of the run, which is what the operator acts on.
    #
    # The two controls and why they are these two: weirvern/models/controls.py.
    from weirvern.models import controls as controls_mod  # noqa: PLC0415 -- keep the sweep's import
    # graph small for callers that only want detection
    try:
        checks = controls_mod.run_controls(client)
    except Exception as exc:  # noqa: BLE001 -- a broken control is a verdict, not a lost sweep
        checks = [controls_mod.Control("controls", None, f"could not run: {exc}")]
    if controls_mod.degraded(checks):
        logger.error("Detection run DEGRADED -- control failed: %s", controls_mod.describe(checks))
    else:
        logger.info("Detection controls: %s", controls_mod.describe(checks))
    _save_controls(settings, checks)

    return fresh


# _explain_primary was REMOVED here, deliberately rather than left unused.
#
# Its docstring said it named "the feature that dominated", and it returned
# `verdict["detected_by_models"].split(",")[0]` — a DETECTOR name. That value was
# written into netflow_anomalies.primary_deviation_feature, so the column held
# "Adaptive Baseline" where a feature belonged, and four sibling columns were
# hardcoded zeros. It is deleted rather than deprecated because a plausible-looking
# helper next to the real one is how the placeholder got reintroduced the first
# time. The replacement is weirvern/explain.py.



def _heartbeat_thread(settings, siphon=None) -> None:
    """Publish the sensor's observed state every `heartbeat_interval_s`, forever.

    Beats IMMEDIATELY on start, so a freshly deployed worker populates the dashboard
    without waiting an interval -- otherwise the panel says "never reported" for the first
    15s of every deploy and looks broken.

    NEVER RAISES: the cost of a missing heartbeat is a dashboard reading "unknown", which
    is recoverable, while an exception here must not be able to kill ingestion.

    `siphon` is the in-process supervisor (worker's own), or None. While it reports that
    the worker should NOT publish (a live intercept child owns the row, or a clean re-arm
    seam that is seconds from the next run), this thread skips its write: the
    `(sensor_id, 'siphon')` row is keyed one-per-sensor-and-mode, and two writers would
    clobber each other and make the liveness check flap. The decision lives on the
    supervisor (worker_should_publish) because the supervisor knows whether a child is
    running, whether one just crashed, and whether a clean re-arm is imminent.
    """
    from weirvern.admin import sensorwatch, status

    # THE SAME IDENTITY THE REST OF THE SYSTEM USES. `_sensor_name` prefers settings.sensor_name,
    # then NODE_NAME from the downward API, then the hostname. This used to read `HOSTNAME`
    # directly, which in a pod IS THE POD NAME: it carries the ReplicaSet hash, so it changes on
    # every restart and leaves a row behind under the old name each time.
    #
    # MEASURED on the live cluster after a rollout: the fleet carried TWENTY-THREE distinct
    # `weirvern-worker-<hash>-<suffix>` identities, and two of them were reporting as fresh
    # undeclared sensors at that moment. So this was not only history: it made a healthy
    # deployment look like it had unknown sensors feeding it, which is the security-relevant
    # case the fleet view raises.
    #
    # The fix is to CALL the existing helper rather than re-derive its rule. A second expression
    # is how the two drifted in the first place -- `_sensor_name` was corrected for the gate's
    # state row and this site was missed.
    #
    # SENSOR_ID still wins when set explicitly: a deployment that names its sensors wants that
    # name everywhere, and the heartbeat is the row an operator reads a sensor's health from.
    sid = (os.environ.get("SENSOR_ID") or "").strip() or _sensor_name(settings)
    from weirvern.nic_plans import NicPlanSet  # noqa: PLC0415

    interval = max(5, int(getattr(settings, "heartbeat_interval_s", 15)))
    logger.info("Sensor heartbeat every %ds, observing %s", interval,
                sensorwatch._log_dir())

    while not _stop.is_set():
        try:
            # ONE WRITER, BY AGREEMENT (see SiphonSupervisor.worker_should_publish). A live
            # intercept child owns the (sensor_id, 'siphon') row with its authoritative
            # numbers; the worker writes it only when the supervisor says so -- on loch, on
            # a refused plan, after a crash, and after a clean exit once the seam would
            # otherwise read as stale.
            if siphon is not None and not siphon.worker_should_publish:
                _stop.wait(interval)
                continue
            # THE PLAN IS THE MODE. A per-NIC siphon entry must report `siphon` even when the
            # legacy sensor-level SENSOR_MODE is loch; otherwise applying a plan and watching
            # the fleet row would look as if nothing happened until a second enable.
            _plans = NicPlanSet.from_json(getattr(settings, "intercept_plans", ""))
            _siphon_nics = _plans.siphon_ifaces()
            fields = sensorwatch.observe(
                mode="siphon" if _siphon_nics else getattr(settings, "sensor_mode", "loch"),
                iface=(_siphon_nics[0] if _siphon_nics else ""),
            )
            # THE SUPERVISOR'S OWN PROBLEMS RIDE ALONG. When siphon mode is
            # configured the worker supervises the intercept (admin/siphon_supervisor);
            # a plan it refused to run, or a child that keeps crashing, is otherwise
            # invisible -- the heartbeat would say "loch"-shaped healthy while nothing
            # is intercepted. The note is set by the supervisor in THIS process.
            try:
                from weirvern.admin import siphon_supervisor as sup_mod

                extra = sup_mod.notes()
                if extra:
                    fields["failures"] = list(fields.get("failures") or []) + extra
            except Exception:  # noqa: BLE001
                logger.debug("siphon supervisor notes unavailable", exc_info=True)
            fields.setdefault("interfaces", status.sensor_interfaces())
            with db.connect(settings, retries=1, delay_s=1) as client:
                status.heartbeat(client, sensor_id=sid, **fields)
        except Exception as exc:  # noqa: BLE001
            logger.debug("sensor heartbeat failed: %s", exc)
        _stop.wait(interval)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    settings = get_settings()
    cfg = ModelConfig()

    signal.signal(signal.SIGTERM, _handle_sigterm)

    # INSTALL THE EXCLUSION FILTER BEFORE ANY ROW IS WRITTEN. Set at startup rather than per
    # batch so the ingest paths cannot disagree, and so a malformed CIDR refuses to start the
    # worker instead of appearing to work while filtering nothing.
    try:
        from weirvern import exclude as exclude_mod
        from weirvern import ingester as ingester_mod

        _filter = exclude_mod.from_env()
        ingester_mod.set_traffic_filter(_filter)
        if _filter.enabled:
            logger.info("Traffic exclusion rules: %s", ", ".join(_filter.rules))
    except ValueError as exc:
        # A malformed list is a CONFIGURATION error, and starting anyway would silently filter
        # the wrong thing (or nothing). Refusing is the honest failure.
        logger.error("WEIRVERN_EXCLUDE_CIDRS is invalid: %s", exc)
        raise SystemExit(2) from exc

    # ── A CONFIGURATION THAT CANNOT ALERT REFUSES TO START (audit F186) ─────────────────────────
    #
    # Same shape as the malformed-CIDR check above, and for the same reason: starting anyway would
    # mean detection runs, reports itself healthy, and is structurally blind to every window below
    # `min_flows_for_full_confidence`. That is the failure this project keeps finding -- a green
    # reading over work that did not happen -- so it is refused at startup rather than warned about.
    #
    # The sweep ALSO checks, because BASE_THRESHOLD is operator-editable on a running cluster; there
    # it logs rather than raises, so a bad live edit degrades the thin band instead of stopping
    # detection altogether.
    try:
        ensemble.assert_thin_floor_is_reachable(cfg, settings.base_threshold)
    except ValueError as exc:
        logger.error("Detection configuration is unalertable: %s", exc)
        raise SystemExit(2) from exc

    # ── A GATEWAY-BACKED REMOTE GATE ─────────────────────────────────────────────────────────────
    # The direct-ClickHouse gate path below still exists for legacy installs, but an mTLS unit
    # has no database credential. The adapter supplies rules and state over the same
    # authenticated gateway the agent uses; the compiler, supervisor and safety checks are the
    # hub's own. This branch must come before db.connect(), or a gateway gate would try to open
    # a database it deliberately does not have.
    if _is_gate_only(settings) and (os.environ.get("WEIRLING_GATEWAY_URL") or "").strip():
        from weirvern.gateway_gate import GatewayGateStore  # noqa: PLC0415
        from weirvern.weirling_client import GatewayClient  # noqa: PLC0415

        gateway = GatewayClient(
            os.environ["WEIRLING_GATEWAY_URL"],
            os.environ.get("WEIRLING_CLIENT_CERT", ""),
            os.environ.get("WEIRLING_CLIENT_KEY", ""),
            os.environ.get("WEIRLING_ROOT_CA", ""),
        )
        store = GatewayGateStore(gateway)
        logger.info(
            "WEIRVERN_ROLE=gate — enforcing the hub's rules over mTLS as %s",
            _sensor_name(settings) or "unnamed",
        )
        while not _stop.is_set():
            try:
                _sluice_maybe(settings, None, derive=False, store=store)
            except Exception:  # noqa: BLE001
                logger.exception("gate pass failed; retrying next interval")
            _stop.wait(max(5, int(settings.sluice_interval_s)))
        logger.info("gate role stopping")
        return

    client = db.connect(settings)
    db.apply_schema(client, settings)
    logger.info("Schema ready — starting Weirvern worker")

    # Any action left mid-flight by a previous process is ORPHANED (this is the only executor), and
    # "running" must not outlive the process that was running it.
    try:
        from weirvern.models import actions as _actions  # noqa: PLC0415

        _actions.reap_running(client)
    except Exception as exc:  # noqa: BLE001
        logger.warning("could not reap orphaned model actions: %s", exc)

    # ── A WEIRLING GATE: enforce here, derive nothing ────────────────────────────────────────────
    #
    # WHAT "ANY WEIRLING THAT HAS THE ABILITY" MEANS IN CODE. A sensor box that sits in the path
    # (its own channel, or a live siphon intercept) and can install rules is a place traffic can be
    # stopped, so it enforces the shared rule set -- with the hub's own checks, because it is the
    # hub's own code: the rules must be READABLE (an unreadable ruleset is not an empty one and the
    # gate is left as it is), the enforcement path must be VERIFIED rather than configured, and the
    # interface is never the management NIC. `SLUICE_ENABLED=0` means disarmed here too, exactly as
    # on the hub.
    #
    # IT DOES NOT DERIVE. The hub reads the detections and writes the rules; a second deriver would
    # create a duplicate rule for the same detection, and the operator who revoked one would keep
    # being blocked by the other -- the worst possible way for two gates to disagree.
    #
    # IT DOES NOT INGEST, DETECT, OR TRAIN either. Those are the hub's, and a sensor running them
    # would double-count a segment's traffic in the hub's own database.
    if _is_gate_only(settings):
        logger.info(
            "WEIRVERN_ROLE=gate — enforcing the shared rule set on this sensor (%s); "
            "rules are derived on the hub", _sensor_name(settings) or "unnamed",
        )
        while not _stop.is_set():
            try:
                _sluice_maybe(settings, client, derive=False)
            except Exception:  # noqa: BLE001
                # One failed pass must not kill the gate: the next interval retries, and the last
                # recorded state stays what the kernel last confirmed. Crashing here would leave
                # rules installed with nothing re-checking them.
                logger.exception("gate pass failed; retrying next interval")
            _stop.wait(max(5, int(settings.sluice_interval_s)))
        logger.info("gate role stopping")
        return

    # Ingest thread: tail goflow2's sink continuously (legacy: inline heredoc pod).
    # v20 fix: tail_forever tracks file offsets so rows are never re-inserted.
    #
    # settings.zeek_log_dir is passed as the 4th argument. It was previously
    # omitted, so tail_forever's `zeek_dir` defaulted to "" and the Zeek branch
    # never ran: zeek_conn/dns/ssl/notice stayed empty forever while
    # ZEEK_LOG_DIR was configured in the ConfigMap and the Zeek DaemonSet burned
    # CPU. The second sensor — most of the value for DNS tunnelling, JA3 C2 and
    # slow beaconing — contributed nothing, and `weirvern status` still looked
    # clean because the zeek_freshness probe only registers when rows exist.
    #
    # ── ITS OWN CLIENT, NOT THE MAIN ONE ────────────────────────────────────────
    #
    # The ingest thread previously received the SAME clickhouse-connect client as
    # the detection loop, and the driver refuses that outright:
    #
    #   Attempt to execute concurrent queries within the same session.
    #   Please use a separate client instance per thread/process.
    #
    # It surfaced as "Ingest pass failed" on the very first pass, and because
    # clickhouse-connect sessions are not thread-safe, the failure is
    # intermittent rather than deterministic: it appears only when the two
    # threads overlap, so a quiet deployment can look perfectly healthy and start
    # losing ingest passes the moment traffic picks up. One client per thread is
    # the driver's documented requirement, not a workaround.
    ingest_client = db.connect(settings)
    ingest_thread = threading.Thread(
        target=tail_forever,
        args=(ingest_client, settings.tail_file, 5.0, settings.zeek_log_dir),
        # ── THE INGEST LOOP FINISHES ITS PASS BEFORE THE PROCESS EXITS (audit F079) ───────────────
        #
        # `tail_forever` has accepted a `stop` event for a while (it is how tests stop it), and the
        # worker NEVER PASSED ONE. On SIGTERM the signal handler set `_stop`, the detect loop broke,
        # and `sys.exit(0)` tore the process down with the ingest thread wherever it happened to be.
        # Because the cursor is checkpointed AFTER each pass, a kill mid-pass leaves the checkpoint at
        # the PREVIOUS offset and the next start re-reads and re-inserts every row since -- into
        # `flows`, which is a plain MergeTree with no deduplication. That is the F018 duplicate-row
        # failure mode re-entering through process teardown rather than through an in-memory cursor.
        #
        # MEASURED, driving the real `tail_and_insert`: completed pass + checkpoint -> restart reads
        # its saved offset and inserts 0 rows; identical pass without the checkpoint -> restart loads
        # offset 0 and inserts all 10 rows again.
        #
        # The event is shared with the detect loop, so the ONE SIGTERM now stops both, and the join at
        # the bottom of main() gives the in-flight pass a bounded moment to finish and checkpoint.
        # tail_files: the per-NIC file map -- one collector per NIC, same port, one file each.
        kwargs={"exporter_allow": settings.flow_exporter_allow, "stop": _stop,
                "tail_files": settings.tail_files},
        daemon=True,
        name="ingest-thread",
    )
    ingest_thread.start()
    if settings.flow_exporter_allow.strip():
        logger.info(
            "Flow ingest will accept ONLY exporters in %s; every other sampler_address is "
            "rejected and counted. (Unset WEIRVERN_FLOW_EXPORTER_ALLOW to accept any sender.)",
            settings.flow_exporter_allow,
        )
    else:
        logger.info(
            "Flow ingest accepts ANY exporter. NetFlow is unauthenticated UDP on hostNetwork, "
            "so any device that can reach this node can add records to the detection data. Set "
            "WEIRVERN_FLOW_EXPORTER_ALLOW once you know your exporters (`weirvern exporters` "
            "lists the addresses seen)."
        )
    if settings.zeek_log_dir:
        logger.info("Ingest thread started: flows=%s zeek=%s",
                    settings.tail_file, settings.zeek_log_dir)
    else:
        logger.info("Ingest thread started on %s (Zeek ingest DISABLED: "
                    "ZEEK_LOG_DIR is empty — set it to enable the packet sensor)",
                    settings.tail_file)

    # Report what the SENSOR is doing, observed from its log files. The sensor container
    # has no python3 (busybox/ash, perl and Zeek only -- verified on the live pod), so it
    # cannot report itself, and the worker is the only component with both Python and a
    # read-only view of the logs.
    #
    # Its own thread because the heartbeat interval (15s) is independent of the detection
    # interval (300s): sharing the detection loop would make the sensor look dead between
    # cycles. Every failure is swallowed, so a monitoring problem never stops detection.
    # IN-PATH INTERCEPT SUPERVISION (siphon mode only).
    #
    # When SENSOR_MODE=siphon is configured WITH a complete plan, the worker keeps
    # the intercept running as a supervised child (see admin/siphon_supervisor.py
    # for why a child rather than an in-process intercept). In loch mode -- or with
    # an incomplete plan, which is the safe state -- start() states the reason and
    # returns; nothing is spawned.
    #
    # STARTED BEFORE THE HEARTBEAT THREAD so a refusal note exists by the first beat:
    # the heartbeat carries the note (see _heartbeat_thread), and starting this after
    # would leave the dashboard's first impression "healthy" for one interval.
    siphon = None
    try:
        from weirvern.admin import siphon_supervisor as siphon_mod

        # ONE GROUP EVEN FOR ONE NIC: the worker then has the same ownership and
        # heartbeat rule for every sensor shape, instead of two code paths that drift.
        siphon = siphon_mod.SiphonSupervisorGroup(siphon_mod.configs_from_env())
        siphon.start()
    except Exception:  # noqa: BLE001
        # Non-fatal BY DESIGN: a supervision problem must not stop ingest, detection
        # or alerting. The failure is visible in the log and, via notes(), on the
        # sensor panel -- and `weirvern status` fails loudly when siphon mode is
        # configured with no live intercept.
        logger.error("siphon supervisor could not start", exc_info=True)
        siphon = None

    # Report what the SENSOR is doing, observed from its log files. The sensor container
    # has no python3 (busybox/ash, perl and Zeek only -- verified on the live pod), so it
    # cannot report itself, and the worker is the only component with both Python and a
    # read-only view of the logs.
    #
    # Its own thread because the heartbeat interval (15s) is independent of the detection
    # interval (300s): sharing the detection loop would make the sensor look dead between
    # cycles. Every failure is swallowed, so a monitoring problem never stops detection.
    threading.Thread(
        target=_heartbeat_thread,
        args=(settings, siphon),
        daemon=True,
        name="sensor-heartbeat",
    ).start()

    detectors = build_detectors(settings, cfg)
    alert_state = AlertState()
    last_full_train: datetime | None = None
    trained_once = False
    shadow_tick = 0
    last_readiness_state: str | None = None

    while not _stop.is_set():
        cycle_start = time.time()
        try:
            # THE OPERATOR'S REQUESTS COME FIRST (measured 2026-10-16: a request filed at 12:23
            # sat "requested" for hours while the box's cold training ran across every worker
            # restart -- this call used to sit AFTER the training branch, so a request was
            # hostage to training that had not finished). process_model_actions is cheap when
            # idle, and the retrain path builds its OWN detectors, so it never needed this
            # cycle's trained ones. The keep/trash paths reload from the installed artifacts.
            process_model_actions(client, detectors, settings, cfg)
            if not trained_once:
                # Only latch `trained_once` when training actually produced
                # usable detectors. On a fresh deployment the worker starts
                # before traffic arrives, so the cold train finds 0 rows and
                # returns False; retrying every cycle then picks it up within
                # detect_interval_s instead of waiting out retrain_every_h.
                #
                # `last_full_train` COMES FROM THE ARTIFACTS, NOT FROM now(). A warm start is
                # usable without anything having been trained, so stamping now() here reset the
                # retrain clock on every restart: measured on the deployment, Isolation Forest,
                # Gradient Boosting and DBSCAN went 16 hours without a retrain against a 6-hour
                # interval, while the Adaptive Baseline refreshed every few minutes because it has
                # its own path. The stale models raised nothing and kept scoring.
                usable, trained_at = load_or_train(client, detectors, settings, cfg)
                if usable:
                    trained_once = True
                    last_full_train = as_aware(trained_at) if trained_at else utcnow()
                else:
                    logger.info("No data to train on yet — will retry next cycle "
                                "(this clears automatically once flows arrive)")
            else:
                last_full_train = train_if_due(client, detectors, settings, cfg, last_full_train)

            # ── THE OPERATOR'S OWN REQUESTS, ON EVERY CYCLE ───────────────────────────────────────
            #
            # HERE, not inside the branch above. It was written inside it first and the deployment
            # proved the mistake within minutes: that branch runs only once the detectors have
            # trained, and a box with no training data never reaches it -- so a forced retrain sat
            # at `requested` forever, which is exactly the state this feature exists to make
            # impossible ("a row that sits there looks like a worker that is busy"). A forced
            # retrain on a box with no data is a legitimate request whose ANSWER is "nothing
            # trained", and it must get that answer.
            # (The requests themselves were carried out at the TOP of this cycle -- see the note
            # there. Only the orphan sweep stays here, with the rest of the model bookkeeping.)
            # ... and the race-free sweep for anything a RESTART left behind: a one-shot reap at
            # startup missed a request filed seconds before the rollout (measured), because the
            # previous pod's write had not landed yet. Anything stamped `running` before THIS
            # process started cannot be running -- this is the only executor.
            try:
                from weirvern.models import actions as _act  # noqa: PLC0415

                _act.reap_running(client, before=_PROCESS_STARTED)
            except Exception as exc:  # noqa: BLE001
                logger.debug("orphan sweep failed (harmless, retried next cycle): %s", exc)

            readiness = readiness_mod.assess(client, settings)
            if readiness.state != last_readiness_state:
                last_readiness_state = readiness.state
                if readiness.ready:
                    logger.info(
                        "ML warm-up complete: %s window(s), %s host(s), %.1fh observed",
                        readiness.windows, readiness.hosts, readiness.observed_hours,
                    )
                else:
                    logger.warning(
                        "ML warm-up (%s): detections are recorded but not paged; %s",
                        readiness.state, "; ".join(readiness.reasons) or "waiting for data",
                    )

            verdicts = detection_sweep(client, detectors, settings, cfg)
            # THE EPISODE VIEW MUST TRACK THE CLOCK, NOT THE VERDICT LIST. It used to refresh
            # only when `verdicts` was non-empty. A quiet cycle therefore left `alert_episodes`
            # stale (measured: the table's last write was 6.5 hours before the worker's latest
            # anomaly), so the page budget and the dashboard were reading an old view. Refresh
            # on every cycle; the refresh itself is read-only unless the builder produces rows.
            episode_summary = None
            try:
                episode_summary = episodes.refresh(client, settings)
                logger.info("Episodes: %s built, %s pageable",
                            episode_summary["episodes"], episode_summary["pageable"])
            except Exception as exc:  # noqa: BLE001
                # The episode view is a review convenience, never a detection prerequisite.
                # A failed read leaves the verdict un-gated; say so rather than silently
                # pretending every window was pageable or that none was.
                logger.warning("Episode refresh failed (page budget skipped): %s", exc)
            for v in verdicts:
                pageable = True
                if episode_summary is not None:
                    try:
                        pageable = episodes.claim(client, v, settings)
                    except Exception as exc:  # noqa: BLE001
                        logger.warning("Episode claim failed for %s/%s (paging): %s",
                                       v.get("src_addr"), v.get("window_start"), exc)
                if not readiness.ready:
                    pageable = False
                    v["_page_reason"] = "warmup"
                v["_pageable"] = pageable
                push_alert(v, settings, alert_state, client)

            # ── SHADOW CALIBRATION ──────────────────────────────────────────────────────────
            # The table is a measurement of the alert tail's false-alarm budget, not a change to
            # the alert path. A failure here must never stop detection, so it is bounded and
            # logged; `ML_SHADOW` is the explicit switch.
            if getattr(settings, "ml_shadow", False):
                try:
                    from weirvern.models import calibration as _cal  # noqa: PLC0415

                    calibrated = _cal.run(client, settings)
                    if calibrated:
                        logger.info("ML calibration shadow: %d model row(s)", len(calibrated))
                    # The slower channels are hourly, not per sweep: they query whole series and
                    # fit candidate models, and a five-minute cadence would spend CPU for no new
                    # answer. The calibration threshold itself stays per-cycle.
                    if shadow_tick % 12 == 0:
                        from weirvern.models import roles as _roles  # noqa: PLC0415

                        proposed = _roles.run(client, settings)
                        if proposed:
                            logger.info("ML role proposals: %d host(s)", len(proposed))
                        from weirvern.models import beacon_specialist as _beacon  # noqa: PLC0415
                        from weirvern.models import candidates as _cand  # noqa: PLC0415
                        from weirvern.models import changepoints as _cp  # noqa: PLC0415
                        from weirvern.models import dns_specialist as _dns  # noqa: PLC0415
                        from weirvern.models import drift as _drift  # noqa: PLC0415
                        from weirvern.models import external as _ext  # noqa: PLC0415
                        from weirvern.models import flow_specialist as _flow  # noqa: PLC0415
                        from weirvern.models import graph_specialist as _graph  # noqa: PLC0415
                        from weirvern.models import temporal as _temp  # noqa: PLC0415
                        from weirvern.models import tls_specialist as _tls  # noqa: PLC0415

                        cand = _cand.run(client)
                        if cand.get("rows"):
                            logger.info("ML HDBSCAN shadow: %s rows, %s clusters",
                                        cand["rows"], cand.get("clusters"))
                        flow = _flow.run(client, minutes=60)
                        if flow.get("rows"):
                            logger.info("ML flow-shape shadow: %s row(s), max=%.2f",
                                        flow["rows"], flow["score_max"])
                        graph = _graph.run(client, minutes=60)
                        if graph.get("rows"):
                            logger.info("ML graph shadow: %s host(s), max=%.2f",
                                        graph["hosts"], graph["score_max"])
                        dns = _dns.run(client, minutes=60)
                        if dns.get("rows"):
                            logger.info("ML DNS-shape shadow: %s row(s), max=%.2f",
                                        dns["rows"], dns["score_max"])
                        tls = _tls.run(client, minutes=60)
                        if tls.get("rows"):
                            logger.info("ML TLS-shape shadow: %s row(s), max=%.2f",
                                        tls["rows"], tls["score_max"])
                        beacon = _beacon.run(client, minutes=60)
                        if beacon.get("rows"):
                            logger.info("ML beacon shadow: %s pair(s), max=%.2f",
                                        beacon["rows"], beacon["score_max"])
                        temp = _temp.run(client)
                        if temp.get("rows"):
                            logger.info("ML temporal shadow: %s row(s)", temp["rows"])
                        chg = _cp.run(client)
                        if chg.get("rows"):
                            logger.info("ML change-point shadow: %s row(s)", chg["rows"])
                        ext = _ext.run(client)
                        if ext.get("rows"):
                            logger.info("ML external exposure shadow: %s row(s), %s host(s), "
                                        "p50=%.2f",
                                        ext["rows"], ext.get("hosts"), ext.get("score_p50", 0.0))
                        drift = _drift.run(client, hours=24)
                        if drift.get("rows"):
                            logger.info("ML drift: %s pair(s), %s notice(s); retrain=%s",
                                        drift["rows"], len(drift.get("notices", [])),
                                        drift["retrain"]["trigger"])
                        # THE HOST-HOUR, IN SHADOW. It writes its own two tables and logs a
                        # line; nothing in the alert path reads them, so this cannot page.
                        # It runs now because the reference cannot be back-filled later: the
                        # flow log is trimmed long before the thirty days a per-host baseline
                        # needs, so the hour has to be accumulated while the flows still exist.
                        from weirvern.models import host_hour as _hh  # noqa: PLC0415

                        try:
                            hh = _hh.run(client, alerts_per_day=float(
                                getattr(settings, "host_hour_alerts_per_day", 20)))
                            logger.info(
                                "ML host-hour shadow: %s hour(s), %s host(s), %s anomalous, "
                                "%s episode(s); alpha %.4f for a budget of %s/day",
                                hh["hours_scored"], hh["hosts"], hh["anomalous"],
                                hh["episodes"], hh["alpha"], hh["budget_per_day"])
                        except Exception as exc:  # noqa: BLE001
                            # Its own guard: a broken host-hour build must name itself rather
                            # than be reported as a failure of the specialists beside it.
                            logger.warning("ML host-hour shadow failed: %s", exc)
                        # RIP-5: the fusion pass runs where the evidence was just written, not
                        # on a separate timer. The specialists above are hourly, so a fusion on
                        # the 5-minute detection cycle would almost always find every channel
                        # stale and persist an unknown -- an honest answer, but not a useful
                        # one. Its own try/except: a fusion failure must name itself, not be
                        # reported as a generic shadow-pass failure that blames the detectors.
                        try:
                            from weirvern.models import ripple_shadow as _ripple  # noqa: PLC0415

                            fused = _ripple.run(client)
                            point = fused["operating_point"]
                            logger.info(
                                "ML ripple: %s host(s) — %s ripple, %s observation, %s unknown "
                                "(max_p %s, %s samples, %s)",
                                fused["hosts"], fused["ripple"], fused["observation"],
                                fused["unknown"], point["max_p"], point["samples"],
                                "COLD START — abstaining" if point["cold_start"] else "warm")
                        except Exception as exc:  # noqa: BLE001
                            logger.warning("ML ripple pass failed (detection continues): %s", exc)
                    shadow_tick += 1
                except Exception as exc:  # noqa: BLE001
                    logger.warning("ML shadow pass failed (detection continues): %s", exc)

            # HOST IDENTITY runs on the same cycle as detection, AFTER it.
            #
            # Order matters and is deliberate: the identity pass classifies from observations the
            # INGESTER wrote, so running it after detection means a sweep always sees the latest
            # fingerprints rather than racing the ingest. It is also cheap -- one aggregation over
            # `host_fingerprints` for the whole segment, not one query per host -- so it does not
            # need a slower cadence.
            #
            # A failure here MUST NOT stop detection. Identification is enrichment; losing alerts
            # because a fingerprint pass raised would trade the important thing for the useful one.
            try:
                from weirvern.host_identity import build_identity
                build_identity(client)
            except Exception as exc:  # noqa: BLE001
                logger.warning("host identity pass failed (detection continues): %s", exc)

            # ── the Sluice Gate, on its own cadence ────────────────────────────────────────
            #
            # WHY IT RUNS ON A TIMER OF ITS OWN rather than every detection pass. Rules EXPIRE, so
            # something must re-evaluate the bound regularly or a lapsed rule keeps being enforced
            # -- the failure being a network that silently stops working weeks later. This is that
            # something. It also means a worker restart re-establishes the kernel rules within a
            # minute rather than leaving a live block missing for a whole detection interval.
            #
            # Guarded exactly like the identity pass: a failure here must not stop detection.
            # Detection is the product; blocking is a capability on top of it.
            try:
                _sluice_maybe(settings, client)
            except Exception as exc:  # noqa: BLE001
                logger.warning("sluice gate pass failed (detection continues): %s", exc)
            try:
                _sluice_dns_maybe(settings, client)
            except Exception as exc:  # noqa: BLE001
                logger.warning("sluice dns pass failed (detection continues): %s", exc)
            try:
                _blocklist_maybe(settings, client)
            except Exception as exc:  # noqa: BLE001
                logger.warning("blocklist pass failed (detection continues): %s", exc)

            # The in-line flow probe used to be ticked from here. It is now its own process at
            # the capture boundary (weirvern.tap), because the capture grant cannot survive in
            # this container (see the block above `_PROCESS_STARTED`). Nothing here supervises it.
            try:
                _table_size_maybe(client)
            except Exception as exc:  # noqa: BLE001
                logger.debug("table size pass failed (detection continues): %s", exc)

            # The sensor heartbeat runs in its OWN thread, not here.
            #
            # Publishing inside this loop would make the heartbeat's interval equal to
            # detect_interval_s -- five minutes by default -- while sensor_status treats a
            # heartbeat older than 45s as dead. A perfectly healthy sensor would therefore
            # be reported as stopped almost all the time: the panel would be permanently
            # WRONG rather than permanently empty. See _heartbeat_thread.
        except KeyboardInterrupt:
            break
        except Exception as exc:  # noqa: BLE001
            logger.error("Worker loop error: %s", exc, exc_info=True)
            time.sleep(30)
        # Sleep the remainder of the detection interval -- IN SLICES, because the Sluice Gate
        # has its own cadence (see its section above): it must re-evaluate rules within
        # `sluice_interval_s`, so a filed block ENFORCES and a lapsed one LIFTS on that timescale.
        # One long sleep made the REAL cadence the detection interval (300s default) while the
        # panel promised "within 60s" -- measured live at 301s between passes. A slice never
        # exceeds the gate's own interval, so the promise holds by construction; each slice costs
        # one cheap gated check that returns immediately until the interval elapses.
        elapsed = time.time() - cycle_start
        remaining = max(1, settings.detect_interval_s - int(elapsed))
        slice_s = max(5, min(60, int(settings.sluice_interval_s)))
        while remaining > 0 and not _stop.is_set():
            step = min(remaining, slice_s)
            _stop.wait(step)
            remaining -= step
            try:
                _sluice_maybe(settings, client)
            except Exception as exc:  # noqa: BLE001
                logger.warning("sluice gate pass failed (detection continues): %s", exc)
            try:
                _sluice_dns_maybe(settings, client)
            except Exception as exc:  # noqa: BLE001
                logger.warning("sluice dns pass failed (detection continues): %s", exc)
            try:
                _blocklist_maybe(settings, client)
            except Exception as exc:  # noqa: BLE001
                logger.warning("blocklist pass failed (detection continues): %s", exc)
            try:
                _table_size_maybe(client)
            except Exception as exc:  # noqa: BLE001
                logger.debug("table size pass failed (detection continues): %s", exc)

    # ── LET THE INGEST LOOP FINISH ITS PASS (audit F079) ──────────────────────────────────────────
    #
    # `_stop` is already set (that is why the loop above broke), so the ingest thread has been asked
    # to stop at its next loop boundary. Joining here gives the in-flight pass its chance to insert
    # AND checkpoint, which is the difference between a clean restart and a re-ingested slice.
    #
    # BOUNDED ON PURPOSE, and SHORT. The checkpoint is saved per PASS, and a pass reads only what is
    # new since the last one, so the wait is normally milliseconds. A hard cap keeps a pathological
    # pass (an enormous backlog, or a client that has stopped responding) from holding the pod open
    # until the kubelet's grace period SIGKILLs it -- which would lose the very checkpoint this is
    # here to protect, and delay the SIGKILL of the supervised child below.
    #
    # `join` on a thread that never started raising would be a poor trade for a shutdown path, so a
    # failed join is logged and the shutdown continues: an unclean stop still stops.
    try:
        ingest_thread.join(timeout=_INGEST_JOIN_TIMEOUT_S)
        if ingest_thread.is_alive():
            logger.warning(
                "Ingest thread did not finish its pass within %ss; exiting anyway (the next start "
                "will re-ingest the rows since its last checkpoint)", _INGEST_JOIN_TIMEOUT_S,
            )
        else:
            logger.info("Ingest thread stopped cleanly — its cursor is checkpointed")
    except Exception:  # noqa: BLE001
        logger.error("Could not join the ingest thread during shutdown", exc_info=True)

    # ORDERLY SIPHON SHUTDOWN. SIGTERM the supervised intercept BEFORE we exit so it
    # restores every forged ARP mapping while this container still has a network stack
    # to send the restore frames from. If this were skipped, the pod's stop would
    # SIGKILL the child at the end of the grace period and the mappings would wait on
    # ARP expiry instead -- correct but slower, and not the path to leave as the
    # common case.
    if siphon is not None:
        try:
            siphon.stop()
        except Exception:  # noqa: BLE001
            logger.error("siphon supervisor shutdown failed", exc_info=True)

    # The capture children are NOT this process's to stop any more: the tap is supervised where
    # it runs (the Zeek sidecar / the weirling agent) and shuts its own tcpdump down on SIGTERM.

    logger.info("Worker exited cleanly")
    sys.exit(0)


if __name__ == "__main__":
    main()

