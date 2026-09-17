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
import signal
import sys
import threading
import time
from datetime import datetime, timedelta

from clickhouse_connect.driver.client import Client

from weirvern import db, ensemble
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


def load_or_train(client: Client, detectors, settings, cfg: ModelConfig) -> bool:
    """Warm start from persisted artifacts; otherwise train cold (lesson:
    v14 deployed while v19 sat on disk — the persisted artifact is the
    source of truth, and each training run records metadata to ml_models).

    Returns True when the detectors are usable afterwards, False when they are
    not (no data yet). THE BUG THIS FIXES: this used to return None in both
    cases, so the caller could not distinguish "warm" from "we had nothing to
    train on". On a fresh deployment the worker starts before any traffic has
    arrived, training fails with "Not enough data for Isolation Forest (0 rows)",
    and the caller then stamped last_full_train = now() as though it had
    succeeded. The next full retrain was therefore deferred by the ENTIRE
    retrain_every_h window, so a deployment that boots to an empty database
    detects nothing for up to 6 hours while every pod reports healthy.
    """
    if_model, gb_model, db_model, bl_model = detectors
    any_loaded = 0
    for d in detectors:
        if d.load():
            any_loaded += 1
    if any_loaded == len(detectors):
        logger.info("All detectors loaded from disk — warm start")
        return True

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
    return trained_any


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

    def index(cols: list[str], rows) -> dict[tuple, dict]:
        out = {}
        for r in rows:
            out[(r[0], r[1])] = dict(zip(cols[2:], r[2:], strict=False))
        return out

    div_idx = index(div_cols, div_rows)
    tmp_idx = index(tmp_cols, tmp_rows)

    flows: list[dict] = [dict(zip(agg_cols, r, strict=True)) for r in agg_rows]
    for f in flows:
        key = (f["window_start"], f["src_addr"])
        f["_diversity"] = div_idx.get(key)
        f["_temporal"] = tmp_idx.get(key)

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


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    settings = get_settings()
    cfg = ModelConfig()

    signal.signal(signal.SIGTERM, _handle_sigterm)
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
                if load_or_train(client, detectors, settings, cfg):
                    trained_once = True
                    last_full_train = datetime.now()
                else:
                    logger.info("No data to train on yet — will retry next cycle "
                                "(this clears automatically once flows arrive)")
            else:
                last_full_train = train_if_due(client, detectors, settings, cfg, last_full_train)

            verdicts = detection_sweep(client, detectors, settings, cfg)
            for v in verdicts:
                push_alert(v, settings, alert_state, client)
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
