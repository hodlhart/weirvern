-- ── DRIFT IS A NOTICE, NOT A PAGE ────────────────────────────────────────────────────────────
--
-- A score distribution can move while every single threshold still looks healthy. This table
-- records a time-split comparison per model/host: current window against the preceding window.
-- It is additive and read-only for the alert path; a drift row is a notice for the operator,
-- never an alert, and it never triggers a retrain by itself.
CREATE TABLE IF NOT EXISTS weirvern.ml_drift
(
    computed_at     DateTime DEFAULT now(),
    window_start    DateTime,
    model_name      LowCardinality(String),
    src_addr        String,
    role            LowCardinality(String) DEFAULT '',
    metric          LowCardinality(String) DEFAULT 'score',
    baseline_value  Float64,
    current_value   Float64,
    drift_score     Float64,
    status          LowCardinality(String),
    evidence        String
)
ENGINE = ReplacingMergeTree(computed_at)
ORDER BY (model_name, window_start, src_addr)
TTL computed_at + INTERVAL 90 DAY;
