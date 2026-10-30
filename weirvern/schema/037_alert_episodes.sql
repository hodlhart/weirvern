-- ── EPISODES: ONE HOST INCIDENT, MANY WINDOWS ─────────────────────────────────────────────
--
-- The anomaly table records every five-minute window. An operator does not review windows; they
-- review an incident. This table groups consecutive windows for the same host when the gap
-- between them is <= episode_gap_minutes (default 30), carries the highest severity and score,
-- and marks ONE pageable window per episode. Raw `netflow_anomalies` rows are never changed.
--
-- `pageable` is the budget decision, not a detection decision: a high/critical episode may be
-- pageable, medium/low are observations. `paged_at` is written by the claim path so a later
-- refresh cannot page the same episode twice. `page_window` is the one window that earned the
-- page (the highest-scoring window); every other occurrence remains visible but is log-only.
CREATE TABLE IF NOT EXISTS weirvern.alert_episodes
(
    src_addr       String,
    episode_start  DateTime64(3),
    episode_end    DateTime64(3),
    first_detected DateTime64(3),
    last_detected  DateTime64(3),
    occurrences    UInt32,
    window_count   UInt32,
    max_score      Float64,
    severity       LowCardinality(String),
    severity_rank  UInt8,
    role           LowCardinality(String) DEFAULT '',
    page_window    DateTime64(3),
    pageable       UInt8 DEFAULT 0,
    page_reason    LowCardinality(String) DEFAULT '',
    paged_at       Nullable(DateTime64(3)),
    updated_at     DateTime64(3)
)
ENGINE = ReplacingMergeTree(updated_at)
PARTITION BY toYYYYMM(episode_start)
ORDER BY (src_addr, episode_start)
TTL toDateTime(updated_at) + INTERVAL 30 DAY;
