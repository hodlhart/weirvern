-- ── THE POPULATION THE CALIBRATION ACTUALLY NEEDS ───────────────────────────────────────────
--
-- `netflow_anomalies` stores only the windows that crossed the alert bar. Calibrating a detector
-- on that tail measures "how often an already-alerting score was high", not the false-alarm rate
-- over the traffic the detector scored. This table records EVERY scored host-window and every
-- model's raw score, before the threshold, agreement gate, severity or episode budget.
--
-- It is a measurement store, not a verdict store. It never changes alerting. ReplacingMergeTree
-- removes the duplicate host-windows produced by overlapping detection sweeps; the raw
-- `netflow_anomalies` table remains untouched.
CREATE TABLE IF NOT EXISTS weirvern.ml_window_scores
(
    window_start  DateTime,
    src_addr      String,
    model_name    LowCardinality(String),
    score         Float64,
    model_version String,
    computed_at   DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree(computed_at)
ORDER BY (model_name, window_start, src_addr)
TTL computed_at + INTERVAL 30 DAY;
