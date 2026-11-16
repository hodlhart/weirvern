-- 033_ml_temporal_scores.sql
--
-- WHY THIS EXISTS: the tabular detectors see a 5-minute magnitude, not the SHAPE of the host's
-- day. A matrix-profile discord says "this window has no close match in the host's own series";
-- that is a different question from "these bytes are high". Shadow-only, evidence attached.
CREATE TABLE IF NOT EXISTS weirvern.ml_temporal_scores
(
    window_start          DateTime,
    src_addr              String,
    metric                LowCardinality(String),
    discord_score         Float64,
    matched_window_start  DateTime,
    matrix_profile_version String,
    -- UInt32, NOT UInt16. MEASURED 2026-11-16 on the live box: a three-day series at five-minute
    -- buckets is 150,107 points, which overflows UInt16 (65,535). clickhouse_connect reports that as
    -- "Unable to create Python array ... usually caused by trying to insert None values", so the
    -- symptom named a NULL and the cause was an overflow -- the temporal shadow pass had never
    -- written a row while its log line blamed nothing in particular.
    series_points         UInt32,
    computed_at           DateTime DEFAULT now()
)
ENGINE = MergeTree()
ORDER BY (metric, window_start, src_addr)
TTL computed_at + INTERVAL 30 DAY;
