-- Host watches: the operator's "track this entity" list.
--
-- WHY THIS TABLE EXISTS (the alert action cell). An anomaly row's third one-click action is
-- Watch -- a persistent, server-side "keep an eye on this host" mark, so the operator can
-- pull the queue up filtered to what they are tracking instead of re-finding the host by
-- hand every morning. It is deliberately NOT an anomaly-level state: that is alert_reviews'
-- job. The watch follows the HOST across windows and survives until it is switched off.
--
-- KEYED BY src_addr ALONE, REPLACING on every toggle: the current watching flag IS the
-- fact. A row per toggle event would make "what am I watching" a question about history
-- instead of intent. The off state is written as watching=0 rather than a delete so the
-- ReplacingMergeTree has a version to replace and FINAL reads one answer either way.
--
-- NO TTL, UNLIKE alert_reviews: a watch is operator intent, not a derivative of any one
-- anomaly, so it must not age out with them. The table stays tiny -- one row per host.
CREATE TABLE IF NOT EXISTS weirvern.host_watches
(
    src_addr   String,
    -- 1 = watching, 0 = switched off.
    watching   UInt8,
    -- When the watch was last written. The ReplacingMergeTree version column; DateTime64(3)
    -- so a rapid off->on within one second cannot tie and leave FINAL picking at random.
    watched_at DateTime64(3) DEFAULT now64(3),
    -- Actor class, like alert_reviews.reviewed_by: 'operator' for a token-authenticated
    -- write. Present now so a real identity slots in later without a schema change.
    watched_by LowCardinality(String) DEFAULT 'operator'
)
ENGINE = ReplacingMergeTree(watched_at)
ORDER BY src_addr;
