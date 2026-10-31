-- ── REVIEW FEEDBACK IS AN ADJUSTMENT, NOT TRAINING DATA ──────────────────────────────────────
--
-- A disposition can tune one host/role budget or threshold for a bounded period. It is not a
-- training label: this table carries before/after, reason, reviewer, review key and expiry, so
-- the adjustment can be replayed, reverted or expired without silently changing a model.
CREATE TABLE IF NOT EXISTS weirvern.ml_review_adjustments
(
    adjustment_id       String,
    created_at          DateTime64(3),
    reviewer            LowCardinality(String) DEFAULT 'operator',
    scope               LowCardinality(String),
    subject             String,
    metric              LowCardinality(String),
    before_value        Float64,
    after_value         Float64,
    reason              String,
    review_window_start DateTime64(3),
    review_src_addr     String,
    expiry              DateTime64(3),
    reverted_at         Nullable(DateTime64(3)),
    revert_reason       String DEFAULT '',
    active              UInt8 DEFAULT 1
)
ENGINE = ReplacingMergeTree(created_at)
ORDER BY adjustment_id
TTL expiry + INTERVAL 90 DAY;
