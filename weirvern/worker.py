"""Weirvern worker — the single long-running process.

Owns the loop that the legacy `anomaly_detection.py` main() had, restructured:
  * threads: ingest (tail goflow2 JSONL → ClickHouse) + detect (retrain/sweep)
  * schema applied idempotently at boot (was: configmap-embedded SQL)
  * models persisted to MODEL_DIR (was: lost on every restart)
  * graceful shutdown on SIGTERM (was: KeyboardInterrupt only)

Run as:  python -m weirvern.worker
"""
from __future__ import annotations

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

    verdicts = ensemble.detect_flows(flows, detectors, settings, cfg)
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
        v["attack_techniques"] = [m.as_dict() for m in techniques]
        v["attack_label"] = attack.label(techniques)
        rows.append([
            datetime.now(), v["window_start"], f.get("window_end"), v["src_addr"],
            v["anomaly_score"], v["confidence"], v["isolation_forest_score"],
            v["gradient_boosting_score"], v["dbscan_score"], v["baseline_score"],
            v["model_agreement"], exp["primary_deviation_feature"],
            exp["primary_deviation_zscore"], exp["deviation_magnitude"],
            exp["feature_contributions"], exp["baseline_comparison"],
            v["detected_by_models"], v["severity"],
        ])
    skipped = len(verdicts) - len(fresh)
    if skipped:
        logger.info("⏭️  Skipped %d already-recorded host-windows", skipped)
    if not rows:
        # Nothing new: return nothing so the alert pass does not re-push
        # detections that were already alerted in an earlier sweep.
        return []

    client.insert("weirvern.netflow_anomalies", rows, column_names=[
        "detected_at", "window_start", "window_end", "src_addr", "anomaly_score",
        "confidence", "isolation_forest_score", "gradient_boosting_score",
        "dbscan_score", "baseline_score", "model_agreement",
        "primary_deviation_feature", "primary_deviation_zscore", "deviation_magnitude",
        "feature_contributions", "baseline_comparison", "detected_by_models", "severity",
        # The ATT&CK columns. Positional insert: these must stay LAST and in the same order as
        # the values appended above, or every value after them lands in the wrong column.
        "attack_techniques", "attack_label",
    ])
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



def _heartbeat_thread(settings) -> None:
    """Publish the sensor's observed state every `heartbeat_interval_s`, forever.

    Beats IMMEDIATELY on start, so a freshly deployed worker populates the dashboard
    without waiting an interval -- otherwise the panel says "never reported" for the first
    15s of every deploy and looks broken.

    Never raises: the cost of a missing heartbeat is a dashboard reading "unknown", which
    is recoverable, while an exception here must not be able to kill ingestion.
    """
    from weirvern.admin import sensorwatch, status

    sid = os.environ.get("SENSOR_ID") or os.environ.get("HOSTNAME", "worker")
    interval = max(5, int(getattr(settings, "heartbeat_interval_s", 15)))
    logger.info("Sensor heartbeat every %ds, observing %s", interval,
                sensorwatch._log_dir())

    while not _stop.is_set():
        try:
            with db.connect(settings, retries=1, delay_s=1) as client:
                status.heartbeat(client, sensor_id=sid, **sensorwatch.observe())
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
        daemon=True,
        name="ingest-thread",
    )
    ingest_thread.start()
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
    threading.Thread(
        target=_heartbeat_thread,
        args=(settings,),
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

    logger.info("Worker exited cleanly")
    sys.exit(0)


if __name__ == "__main__":
    main()

