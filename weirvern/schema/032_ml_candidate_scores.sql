-- 032_ml_candidate_scores.sql
--
-- WHY THIS EXISTS: a challenger detector must be judged on the same windows as the live ensemble
-- without ever writing an alert. This append-only table is the shadow score store. A row here is a
-- candidate's opinion, not a verdict; the live `netflow_anomalies` table is untouched.
CREATE TABLE IF NOT EXISTS weirvern.ml_candidate_scores
(
    window_start     DateTime,
    src_addr         String,
    model_name       LowCardinality(String),
    score            Float64,
    rank             UInt16,
    evidence         String,
    model_version    String,
    computed_at      DateTime DEFAULT now()
)
ENGINE = MergeTree()
ORDER BY (model_name, window_start, src_addr)
TTL computed_at + INTERVAL 30 DAY;
