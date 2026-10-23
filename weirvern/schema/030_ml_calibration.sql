-- 030_ml_calibration.sql
--
-- WHY THIS EXISTS: a detector score is a ranking, not a false-alarm rate. The live console had a
-- global threshold and no way to ask "will this keep to N alerts/day?" These tables store the
-- conformal calibration the worker computes, plus an append-only history so a threshold can be
-- audited or rolled back.
--
-- SHADOW ONLY. The rows here do not change netflow_anomalies.severity or alert_events until an
-- operator promotes the calibration. `reference_source` states the limitation: the reference is
-- the stored detection tail, not every host-window the models scored.

CREATE TABLE IF NOT EXISTS weirvern.ml_calibration
(
    model_name        String,
    scope             LowCardinality(String),
    subject           String,
    statistic         LowCardinality(String),
    target_far        Float64,
    threshold         Float64,
    p50               Float64,
    p95               Float64,
    p99               Float64,
    sample_count      UInt32,
    validation_count  UInt32,
    observed_far      Float64,
    reference_source  String,
    model_version     String,
    computed_at       DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree(computed_at)
ORDER BY (model_name, scope, subject, statistic);

CREATE TABLE IF NOT EXISTS weirvern.ml_calibration_history
(
    computed_at       DateTime,
    model_name        String,
    scope             LowCardinality(String),
    subject           String,
    statistic         LowCardinality(String),
    target_far        Float64,
    threshold         Float64,
    p50               Float64,
    p95               Float64,
    p99               Float64,
    sample_count      UInt32,
    validation_count  UInt32,
    observed_far      Float64,
    reference_source  String,
    model_version     String
)
ENGINE = MergeTree()
ORDER BY (computed_at, model_name, scope, subject, statistic);
