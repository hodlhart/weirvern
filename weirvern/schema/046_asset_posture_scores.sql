-- 026_asset_posture_scores.sql
--
-- THE SHADOW CHANNEL FOR ASSET-POSTURE. A score is produced for every Nmap change, but nothing
-- reads it for enforcement yet. Keeping the score separate from asset_changes means a later
-- model version can rescan the same change without rewriting what was observed.
CREATE TABLE IF NOT EXISTS weirvern.asset_posture_scores
(
    asset_key       String,
    change_key      String,
    score           Float32 DEFAULT 0,
    band            LowCardinality(String) DEFAULT 'expected',
    reasons         Array(String) DEFAULT [],
    features        String DEFAULT '{}',
    model_version   LowCardinality(String) DEFAULT '',
    scored_at       DateTime64(3) DEFAULT now64(3),
    review_state    LowCardinality(String) DEFAULT 'new'
)
ENGINE = ReplacingMergeTree(scored_at)
ORDER BY (asset_key, change_key);
