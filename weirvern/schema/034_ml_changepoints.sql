-- 034_ml_changepoints.sql
--
-- WHY THIS EXISTS: a sustained regime change (a new device, a moved service, a misconfiguration)
-- is not a single-window outlier. Recording it separately lets the console say "normal changed
-- here" without turning every window after it into a new critical alert. Shadow-only.
CREATE TABLE IF NOT EXISTS weirvern.ml_changepoints
(
    detected_at     DateTime,
    src_addr        String,
    metric          LowCardinality(String),
    direction       LowCardinality(String),
    changepoint_at  DateTime,
    probability     Float64,
    run_length      UInt32,
    magnitude       Float64,
    algorithm       LowCardinality(String),
    model_version   String,
    computed_at     DateTime DEFAULT now()
)
ENGINE = MergeTree()
ORDER BY (detected_at, src_addr, metric)
TTL computed_at + INTERVAL 90 DAY;
