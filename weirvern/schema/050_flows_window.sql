-- 050_flows_window.sql
--
-- ONE ROW PER (window, host). This replaces the flow aggregation as the unit the whole
-- detection stack reads, and it fixes the defect that invalidated every model score.
--
-- WHY THE OLD SHAPE WAS WRONG
--
-- `flows_aggregated` is a plain MergeTree behind `flows_aggregated_mv`. A ClickHouse
-- materialized view fires ONCE PER INSERTED BLOCK, so its `GROUP BY window_start,
-- src_addr` groups within a block, not across the window. One host-window therefore
-- lands as many rows, one per insert. Measured live on 2026-11-12: 99.6% of
-- host-windows fragmented in 24h, worst case 601 rows; over a week the worst case was
-- 5,548. Training read those rows raw and the sweep folded them client-side, so the
-- model was fitted on one unit and scored on another. Measured cost: the shipped
-- detector's score ranked 0.8922 against the insert-block count, which is pipeline
-- timing and never a model input.
--
-- WHY AGGREGATINGMERGETREE FIXES IT
--
-- The target engine holds PARTIAL aggregate STATES and ClickHouse merges rows sharing
-- the sorting key in the background. Readers use `-Merge` combinators and get the true
-- per-window value no matter how many blocks contributed. There is no client-side fold
-- to get wrong and no window can be scored against a fragment.
--
-- `uniqState` / `uniqMerge` also gives the TRUE distinct destination count across
-- blocks. The old `uniq(dst_addr)` per block, summed by the reader, double-counted any
-- destination seen in two insert blocks, which is why `_true_cardinalities` had to
-- re-query raw `flows` to get an honest number.
--
-- MEANS ARE NOT STORED. An average of averages is wrong, and the old table stored
-- `avg_bytes` / `avg_packets` per block so that a reader averaging them again produced
-- a quantity corresponding to nothing. This table stores sums and counts and computes
-- the mean at read time.
--
-- FRAGMENTATION CANNOT HIDE. There is deliberately no `block_rows` column: after
-- merge it would always read 1, which is true but uninformative. To measure
-- fragmentation, count rows in the raw target before merge, or count rows in `flows`
-- per window. `scripts/audit_flow_fragmentation.py` does the latter.

CREATE TABLE IF NOT EXISTS weirvern.flows_window
(
    window_start    DateTime,
    src_addr        String,

    -- Additive across insert blocks.
    flow_count      AggregateFunction(count, UInt8),
    total_bytes     AggregateFunction(sum, UInt64),
    total_packets   AggregateFunction(sum, UInt64),

    -- True cardinality across blocks, not a sum of per-block cardinalities.
    unique_dst_ips  AggregateFunction(uniq, String),

    -- Most recent insert that touched this window, for staleness checks.
    updated_at      SimpleAggregateFunction(max, DateTime)
)
ENGINE = AggregatingMergeTree()
PARTITION BY toYYYYMM(window_start)
ORDER BY (window_start, src_addr)
TTL window_start + INTERVAL 7 DAY;

-- Drop and recreate the view. `CREATE ... IF NOT EXISTS` does not rebuild an existing
-- materialized view, so a migration that only added the table would leave the old view
-- writing to the old table and the new one empty.
DROP VIEW IF EXISTS weirvern.flows_window_mv;

CREATE MATERIALIZED VIEW weirvern.flows_window_mv
TO weirvern.flows_window
AS
SELECT
    toStartOfFiveMinute(time_flow_start) AS window_start,
    src_addr,
    countState()                          AS flow_count,
    sumState(toUInt64(bytes))             AS total_bytes,
    sumState(toUInt64(packets))           AS total_packets,
    uniqState(dst_addr)                   AS unique_dst_ips,
    now()                                 AS updated_at
FROM weirvern.flows
GROUP BY window_start, src_addr;

-- NO READ VIEW. This was tried and was the bug.
--
-- A view containing `GROUP BY` forces ClickHouse to materialise the entire grouped
-- table before an outer `WHERE` can filter. On 2026-11-12 a five-minute sweep through
-- such a view asked for the whole retained history and the worker was OOMKilled three
-- times at a 4 GiB limit.
--
-- Readers instead splice the merge in with the time predicate beside it, through
-- `weirvern/flow_windows.py:folded()`, so part pruning still applies. That module is
-- the single definition of a folded host-window.
--
-- The two rules for anyone touching this table:
--   1. Use `-Merge` combinators. The columns are states, not values.
--   2. Put the window predicate in the SAME select as the merge, never outside a view.
