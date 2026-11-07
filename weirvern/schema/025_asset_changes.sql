-- 025_asset_changes.sql
--
-- THE CHANGE LEDGER BETWEEN NMAP AND ML. `asset_services` is a current-state table: its
-- ReplacingMergeTree overwrites the old observation, so there is nothing to compare against.
-- These two tables make the comparison durable.
--
-- asset_service_history is append-only: one row per open service per successful scan. It is the
-- evidence behind a change and the history a future AssetPostureModel trains on.
--
-- asset_changes is the reviewed record. A change is not automatically "the new baseline": an
-- operator marks it expected or suspicious. review_state is deliberately separate from confidence.
CREATE TABLE IF NOT EXISTS weirvern.asset_service_history
(
    asset_key       String,
    ip              String,
    scan_id         String,
    port            UInt16,
    protocol        LowCardinality(String) DEFAULT 'tcp',
    service         String DEFAULT '',
    product         String DEFAULT '',
    version         String DEFAULT '',
    cpe             String DEFAULT '',
    observed_at     DateTime64(3) DEFAULT now64(3)
)
ENGINE = MergeTree
ORDER BY (asset_key, observed_at, port, protocol);

CREATE TABLE IF NOT EXISTS weirvern.asset_changes
(
    asset_key       String,
    ip              String,
    change_key      String,
    kind            LowCardinality(String),
    port            UInt16 DEFAULT 0,
    protocol        LowCardinality(String) DEFAULT 'tcp',
    old_value       String DEFAULT '',
    new_value       String DEFAULT '',
    confidence      LowCardinality(String) DEFAULT 'medium',
    evidence        String DEFAULT '',
    scan_id         String DEFAULT '',
    first_seen      DateTime64(3) DEFAULT now64(3),
    last_seen       DateTime64(3) DEFAULT now64(3),
    review_state    LowCardinality(String) DEFAULT 'new'
)
ENGINE = ReplacingMergeTree(last_seen)
ORDER BY (asset_key, change_key);
