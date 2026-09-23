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
from datetime import datetime, timedelta

from clickhouse_connect.driver.client import Client

from weirvern import attack, db, ensemble
from weirvern.alerts import AlertState, push_alert
from weirvern.config import ModelConfig, get_settings
from weirvern.explain import explain
from weirvern.ingester import tail_forever
from weirvern.models.detectors import (
    AdaptiveBaselineDetector,
    DBSCANDetector,
    GradientBoostingDetector,
    IsolationForestDetector,
)
from weirvern.zeek_features import (
    index_protocol_records,
    zeek_protocol_records_sql,
    zeek_window_sql,
)

logger = logging.getLogger("weirvern.worker")


# The gate's supervisor lives at module scope so its `last_ok` SURVIVES BETWEEN PASSES. Rebuilding
# it each time would reset the age that `healthy()` uses to distinguish "holding" from "held the
# last time anyone asked" -- so a supervisor that had stopped would look fresh forever.
_SLUICE: dict = {"supervisor": None, "last_pass": 0.0, "armed": False}


def _sluice_maybe(settings, client) -> None:
    """Run one Sluice Gate pass if it is enabled and its interval has elapsed.

    DISABLED BY DEFAULT, which is a decision about what kind of tool this is. Weirvern is a
    monitoring appliance first: installing it must not start blocking traffic before anyone has
    looked at what it sees. `SLUICE_ENABLED=1` is an operator opening the gate deliberately.

    When it is disabled the gate is DISARMED -- explicitly, once -- rather than left at whatever the
    kernel last had. An operator who turns blocking off must have it actually stop, not keep
    enforcing the rules from before the switch was flipped.
    """
    import time as _time  # noqa: PLC0415

    from weirvern import sluice_store  # noqa: PLC0415
    from weirvern.sluice import (  # noqa: PLC0415
        GATE_STATE_DISARMED,
        SluiceSupervisor,
        choose_backend,
        enforcement_pass,
    )

    sup = _SLUICE["supervisor"]
    if sup is None:
        sup = SluiceSupervisor(
            iface=(settings.sluice_iface or settings.zeek_iface or ""),
            mgmt_iface=settings.mgmt_iface,
            backend=choose_backend("nft"),
        )
        _SLUICE["supervisor"] = sup

    if not settings.sluice_enabled:
        # DISARM ONCE, not every pass: re-disarming 1440 times a day would shell out to nft for
        # nothing. But it MUST happen, because `SLUICE_ENABLED=0` has to mean the rules are gone.
        if _SLUICE["armed"] or sup.state.state != GATE_STATE_DISARMED:
            sup.disarm()
            _SLUICE["armed"] = False
            try:
                sluice_store.write_gate_state(client, _sensor_name(settings), sup.state)
            except Exception as exc:  # noqa: BLE001
                logger.warning("sluice: could not record the disarmed state: %s", exc)
            logger.info("sluice gate is DISABLED (SLUICE_ENABLED=0); rules are not enforced")
        return

    now = _time.monotonic()
    if now - float(_SLUICE["last_pass"]) < max(5, int(settings.sluice_interval_s)):
        return
    _SLUICE["last_pass"] = now

    # Detections are read only when the policy is not Off, so an operator who has not enabled
    # auto-blocking pays no query for it.
    detections: list[dict] = []
    if settings.sluice_criticality != "off":
        detections = current_detections_for_blocking(client)

    state = enforcement_pass(
        sluice_store, sup, client=client, sensor=_sensor_name(settings),
        policy=settings.sluice_criticality, max_block_s=settings.sluice_max_block_s,
        detections=detections,
        # So the pass can say plainly that a passive sensor installs rules without enforcing them.
        sensor_mode=settings.sensor_mode,
    )
    _SLUICE["armed"] = state.holding
    logger.info("sluice gate: %s -- %s", state.state, state.detail)


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


def _handle_sigterm(signum, frame):  # noqa: ARG001
    logger.info("SIGTERM received — shutting down gracefully")
    _stop.set()


def build_detectors(settings, cfg: ModelConfig):
    model_dir = settings.model_dir
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
    `last_full_train = datetime.now()` whenever the detectors were usable, and a WARM START is
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
            age_h = (datetime.now() - oldest).total_seconds() / 3600
            logger.info("Artifacts are %.1fh old (retrain due at %dh)",
                        age_h, settings.retrain_every_h)
        return True, oldest

    end_dt, start_dt = datetime.now(), datetime.now() - timedelta(hours=settings.retrain_window_h)
    trained_any = False
    if if_model.train(start_dt, end_dt, client) and if_model.X_train_unscaled is not None:
        gb_model.train(if_model, if_model.X_train_unscaled, start_dt, end_dt, client)
        trained_any = True
    if db_model.train(start_dt, end_dt, client):
        trained_any = True
    if bl_model.train(start_dt, end_dt, client):
        trained_any = True
        bl_model.persist_history(client, settings.retrain_window_h)
    _record_model_metadata(client, detectors)

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
    now = datetime.now()
    if last_full_train is None or (now - last_full_train) > timedelta(hours=settings.retrain_every_h):
        end_dt = now
        start_dt = now - timedelta(hours=settings.retrain_window_h)
        logger.info("🔄 Full retrain (window %dh)", settings.retrain_window_h)
        if_model, gb_model, db_model, bl_model = detectors
        trained_any = False
        if if_model.train(start_dt, end_dt, client):
            trained_any = True
            if if_model.X_train_unscaled is not None:
                gb_model.train(if_model, if_model.X_train_unscaled, start_dt, end_dt, client)
        if db_model.train(start_dt, end_dt, client):
            trained_any = True
        if bl_model.train(start_dt, end_dt, client):
            trained_any = True
            bl_model.persist_history(client, settings.retrain_window_h)
        if not trained_any:
            logger.warning("Full retrain produced nothing (insufficient data) — will retry next cycle")
            return last_full_train
        _record_model_metadata(client, detectors)
        return now

    # Fast baseline refresh (legacy: every 5-min cycle, 1-day window).
    bl_model = next((d for d in detectors if isinstance(d, AdaptiveBaselineDetector)), None)
    if bl_model is not None and bl_model.train(now - timedelta(hours=24), now, client):
        # Keep the DB mirrors in step with the on-disk artifact we just saved.
        bl_model.persist_history(client, 24)
        _record_model_metadata(client, [bl_model])
    return last_full_train


def _record_model_metadata(client: Client, detectors) -> None:
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
# columns (the ATT&CK pair was added here and not to the row).
_ANOMALY_COLUMNS: tuple[str, ...] = (
    "detected_at", "window_start", "window_end", "src_addr", "anomaly_score",
    "confidence", "isolation_forest_score", "gradient_boosting_score",
    "dbscan_score", "baseline_score", "model_agreement",
    "primary_deviation_feature", "primary_deviation_zscore", "deviation_magnitude",
    "feature_contributions", "baseline_comparison", "detected_by_models", "severity",
    "attack_techniques", "attack_label",
)


def detection_sweep(client: Client, detectors, settings, cfg: ModelConfig) -> list[dict]:
    """One detection pass over the last DETECT_INTERVAL_S of aggregates.

    Returns the verdict list (which the caller alerts on) after persisting
    anomaly rows. v20 fix: alerts use these verdicts directly instead of a
    separate re-query — the old re-query's sliding window re-alerted the
    same rows every sweep.
    """
    since = (datetime.now() - timedelta(seconds=settings.detect_interval_s)).strftime("%Y-%m-%d %H:%M:%S")

    agg_cols, agg_rows = db.fetch_rows_named(
        client,
        "SELECT * FROM weirvern.flows_aggregated WHERE window_start >= %(since)s",
        since=since,
    )
    if not agg_rows:
        return []

    div_cols, div_rows = db.fetch_rows_named(
        client,
        "SELECT * FROM weirvern.flows_aggregated_diversity WHERE window_start >= %(since)s",
        since=since,
    )
    tmp_cols, tmp_rows = db.fetch_rows_named(
        client,
        "SELECT * FROM weirvern.flows_aggregated_temporal WHERE window_start >= %(since)s",
        since=since,
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
    protocol_by_host: dict[str, list[dict]] = {}
    try:
        z_cols, z_rows = db.fetch_rows_named(client, zeek_window_sql(since))
        zeek_idx = index(z_cols, z_rows)
        # The Tier-2 PROTOCOL records, for the ATT&CK mapping. Fetched separately from the
        # aggregated features because the mapping needs individual facts (a share path, an RPC
        # operation) rather than counts -- aggregating first would discard the evidence. A
        # failure here must not stop detection: an alert without a technique is still an alert.
        try:
            p_cols, p_rows = db.fetch_rows_named(client, zeek_protocol_records_sql(since))
            protocol_by_host = index_protocol_records(p_rows, p_cols)
            logger.info("ATT&CK mapping: %d hosts with protocol records",
                        len(protocol_by_host))
        except Exception as exc:  # noqa: BLE001
            logger.warning("Could not load protocol records for ATT&CK mapping "
                           "(mapping will use volumetric evidence only): %s", exc)
            protocol_by_host = {}
        if not zeek_idx:
            logger.warning(
                "Zeek summary is empty for this sweep, so every Zeek feature is imputed. "
                "Check that the Zeek sensor covers the same segment as NetFlow."
            )
    except Exception as exc:  # noqa: BLE001
        logger.warning("Could not load the Zeek window summary (continuing NetFlow-only): %s", exc)

    div_idx = index(div_cols, div_rows)
    tmp_idx = index(tmp_cols, tmp_rows)

    # SOC-2: near misses are collected during detection and stored in the same sweep.
    # Owned here so the ensemble stays a pure function of its inputs.
    near_misses: list[dict] = []

    flows: list[dict] = [dict(zip(agg_cols, r, strict=True)) for r in agg_rows]
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
        # of defect as the four dead rules already fixed in attack.py: a name read in one place
        # that the producing side never provides under that name. The earlier fix corrected the
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

    verdicts = ensemble.detect_flows(flows, detectors, settings, cfg, near_misses=near_misses)
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
                  datetime.now()] for m in near_misses],
                column_names=["window_start", "window_end", "src_addr", "anomaly_score",
                              "threshold_used", "reason", "model_agreement",
                              "isolation_forest_score", "gradient_boosting_score",
                              "dbscan_score", "baseline_score", "detected_by_models",
                              "replaced_at"],
            )
            logger.info("Recorded %d near miss(es)", len(near_misses))
        except Exception as exc:  # noqa: BLE001
            logger.warning("Could not record near misses (continuing): %s", exc)
    if not verdicts:
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
        # ── ATT&CK techniques supported by this window's measurements ──────────
        #
        # Mapped from the SAME feature row the explanation used, so the technique and the
        # numbers cannot disagree -- an alert claiming T1046 while the row shows 400 ports
        # and 5 MB would mean two different rows had been read.
        #
        # Two sources, and they are genuinely different evidence:
        #   * the volumetric row (`f`)          -> discovery, exfiltration, DNS tunnelling
        #   * the Zeek records for this host    -> admin shares, DCE/RPC, Kerberos, NTLM, TLS
        # The Zeek half is frequently empty because the join is sparse; that yields fewer
        # techniques, which is correct. It must never be rendered as "no lateral movement".
        techniques = attack.map_techniques(f)
        zeek_rows = protocol_by_host.get(v["src_addr"]) or []
        techniques += attack.map_zeek_techniques(zeek_rows)
        # BOTH SHAPES, deliberately. The DB column needs JSON-serialisable dicts; the alert
        # formatter needs the Match objects, because attack.summarise() reads `.confidence` and
        # `.technique.id`. Storing only dicts made the ATT&CK line raise AttributeError inside
        # push_alert -- which is swallowed by the worker loop, so every detection that DID carry a
        # technique attribution was silently lost: the alert most worth having was the one that
        # never arrived. Keep the objects under a private key the row writer does not read.
        v["attack_techniques"] = [m.as_dict() for m in techniques]
        v["_attack_matches"] = techniques
        v["attack_label"] = attack.label(techniques)
        rows.append([
            datetime.now(), v["window_start"], f.get("window_end"), v["src_addr"],
            v["anomaly_score"], v["confidence"], v["isolation_forest_score"],
            v["gradient_boosting_score"], v["dbscan_score"], v["baseline_score"],
            v["model_agreement"], exp["primary_deviation_feature"],
            exp["primary_deviation_zscore"], exp["deviation_magnitude"],
            exp["feature_contributions"], exp["baseline_comparison"],
            v["detected_by_models"], v["severity"],
            # ATT&CK LAST, matching _ANOMALY_COLUMNS. json.dumps because the column is a String
            # holding a list of objects: a raw list would be stringified by the driver into Python
            # repr, which is not JSON and cannot be parsed back.
            json.dumps(v["attack_techniques"]), v["attack_label"],
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
        return []

    client.insert("weirvern.netflow_anomalies", rows, column_names=list(_ANOMALY_COLUMNS))
    logger.info("🚨 %d anomalies recorded", len(rows))
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

    sid = os.environ.get("SENSOR_ID") or os.environ.get("HOSTNAME", "worker")
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
            fields = sensorwatch.observe()
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

    client = db.connect(settings)
    db.apply_schema(client, settings)
    logger.info("Schema ready — starting Weirvern worker")

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
        kwargs={"exporter_allow": settings.flow_exporter_allow},
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

        siphon = siphon_mod.SiphonSupervisor(siphon_mod.config_from_env())
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

    while not _stop.is_set():
        cycle_start = time.time()
        try:
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
                    last_full_train = trained_at or datetime.now()
                else:
                    logger.info("No data to train on yet — will retry next cycle "
                                "(this clears automatically once flows arrive)")
            else:
                last_full_train = train_if_due(client, detectors, settings, cfg, last_full_train)

            verdicts = detection_sweep(client, detectors, settings, cfg)
            for v in verdicts:
                push_alert(v, settings, alert_state, client)

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
        # Sleep the remainder of the detection interval
        elapsed = time.time() - cycle_start
        _stop.wait(max(1, settings.detect_interval_s - int(elapsed)))

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

    logger.info("Worker exited cleanly")
    sys.exit(0)


if __name__ == "__main__":
    main()

