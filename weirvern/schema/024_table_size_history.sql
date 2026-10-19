-- 024_table_size_history: a table that only reports its size now cannot say which way it is going.
--
-- The Health tab's Table sizes card reads system.parts, which is a CURRENT measurement. The
-- operator asked for a trend per table to tell building tables from quiet ones, and a trend
-- cannot be reconstructed from one sample. The worker appends a snapshot on its normal cycle
-- (throttled), and this table keeps enough history to draw a day of movement.
--
-- A plain MergeTree, not Replacing: every sample is a fact about that moment. Duplicate samples
-- inside a slow cycle are harmless (the query buckets by hour and takes the max), and keeping
-- them makes the history honest rather than silently deduplicated.
CREATE TABLE IF NOT EXISTS weirvern.table_size_history
(
    at         DateTime64(3, 'UTC') DEFAULT now64(3),
    table_name String,
    rows       UInt64,
    bytes      UInt64
)
ENGINE = MergeTree
ORDER BY (table_name, at)
TTL toDateTime(at) + INTERVAL 30 DAY;
