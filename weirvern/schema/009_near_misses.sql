-- Near misses: windows that scored close to the alert threshold, or that cleared it and
-- were dropped by the agreement gate.
--
-- WHY THIS TABLE EXISTS (SOC-2). The Anomalies view shows what was FLAGGED. Nothing showed
-- what almost was: a window at 0.66 against a 0.7 threshold, or one where a single strong
-- detector fired and the agreement gate suppressed it. Those are exactly what a tuning loop
-- needs -- an alerting system with no false-negative surface can only be tuned by guessing.
--
-- THE AUDIT SAID THIS DATA "EXISTS, IT JUST IS NOT QUERIED". IT DID NOT EXIST. Measured
-- against ensemble.detect_flows: both drop paths `continue` before anything is recorded, so
-- the scores were computed and thrown away. This table is where they land now, and the
-- comment says so because "query it" would have been the wrong instruction to follow.
--
-- KEYED (window_start, src_addr, reason): one row per host-window per drop reason. A window
-- can appear twice -- once as below-threshold only if it never cleared the bar, once as
-- agreement-gate -- and the reasons are genuinely different evidence, so both are kept.
-- ReplacingMergeTree(replaced_at): a re-scored window replaces its older row.
--
-- TTL 7 DAYS, SHORTER THAN netflow_anomalies' 30, deliberately: a near miss is a tuning
-- observation, not an incident record. It matters for days, not a month, and the shorter
-- TTL is what keeps a permissive band's volume bounded.
CREATE TABLE IF NOT EXISTS weirvern.near_misses
(
    window_start            DateTime64(3),
    window_end              DateTime64(3),
    src_addr                String,

    -- The ensemble score and the bar it failed to clear (or cleared, then died at the gate).
    -- threshold_used is the ADAPTIVE threshold for this host at this window, not the global
    -- setting, so the displayed gap is the real one.
    anomaly_score           Float64,
    threshold_used          Float64,

    -- 'below-threshold' | 'agreement-gate'. LowCardinality: two values.
    reason                  LowCardinality(String),

    -- Same per-detector shape as netflow_anomalies, so a tuning view can compare a near miss
    -- against the anomaly it almost became without two different vocabularies.
    model_agreement         Float64,
    isolation_forest_score  Float64,
    gradient_boosting_score Float64,
    dbscan_score            Float64,
    baseline_score          Float64,
    detected_by_models      String DEFAULT '',

    replaced_at             DateTime64(3) DEFAULT now64(3)
)
ENGINE = ReplacingMergeTree(replaced_at)
PARTITION BY toYYYYMM(window_start)
ORDER BY (window_start, src_addr, reason)
TTL window_start + INTERVAL 7 DAY;
