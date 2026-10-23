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
    series_points         UInt16,
    computed_at           DateTime DEFAULT now()
)
ENGINE = MergeTree()
ORDER BY (metric, window_start, src_addr)
TTL computed_at + INTERVAL 30 DAY;
