-- 061_flows_window_endpoint.sql
--
-- THE MISSING HALF OF THE NETWORK: A HOST THAT ONLY RECEIVES TRAFFIC IS INVISIBLE.
--
-- `flows_window` has ONE key: `src_addr`. Every flows-based channel in the ripple layer therefore
-- describes only the SOURCE endpoint of a flow. An inbound flow -- external scanner to an internal
-- server, a client to a NAS, anything where our host is the destination -- contributes nothing to
-- the host that received it, and roughly half the addresses on this network never appear as a
-- source at all. Measured live before this migration: `flows` over 3.4 days held 4,800 distinct
-- sources against 5,666 distinct destinations. The 866+ addresses that only receive traffic had no
-- flow evidence of any kind.
--
-- WHY A PARALLEL TABLE AND NOT A `dst_addr` COLUMN.
--
-- `flows_window` is ONE ROW PER (window_start, src_addr) holding AggregateFunction states. Adding
-- `dst_addr` would make the sorting key (window, src, dst), i.e. one row per HOST PAIR, and every
-- aggregate that reads the table would silently change meaning: `flow_count` would become "flows
-- with this exact source/destination pair" and a reader that summed it per host would still get the
-- right total only by accident, while `uniqMerge(unique_dst_ips)` would become a per-pair count of
-- one. The grain is the contract. A second table keeps both contracts intact and lets the outbound
-- side be checked against the old table row for row.
--
-- WHAT A ROW HERE IS. One monitored ENDPOINT, one direction, one five-minute window:
--
--   direction = 'out'  host_addr is the SOURCE of the flow. This is exactly the population
--                      `flows_window` holds -- every flow's source, including a remote source of
--                      an inbound flow -- which is what makes the parity check exact and why the
--                      backfill can be validated against the old table.
--   direction = 'in'   host_addr is the DESTINATION of the flow, and `unique_peer_ips` counts the
--                      distinct senders. This is the half that did not exist before.
--
-- A flow between two monitored hosts produces one 'out' row for its source and one 'in' row for
-- its destination. That is NOT double counting a flow: it is the same event seen from each end, and
-- each row describes a different host's behaviour. A reader that wants the network total must pick
-- ONE direction; a reader that wants a host's traffic must read BOTH and label them. The ripple
-- layer keeps the directions as separate channels for exactly this reason.
--
-- A SELF-FLOW (src_addr = dst_addr, which broadcast and multicast produce constantly) therefore
-- contributes two states to the same (window, host) -- one 'out', one 'in' -- that merge into
-- flow_count = 2. That is the honest reading: the host both sent and received it. Excluding those
-- rows would break the outbound parity with `flows_window`, which is the check that proves the
-- roll-up is faithful.
--
-- THE SAME AGGREGATE COLUMN SHAPES AS `flows_window`, so the same `-Merge` combinators and the same
-- `weirvern/flow_windows.py` rules apply. See 050 for why means are not stored and why uniqState is
-- the only honest distinct count across insert blocks.

CREATE TABLE IF NOT EXISTS weirvern.flows_window_endpoint
(
    window_start      DateTime,
    host_addr         String,
    -- 'out' = the source endpoint, 'in' = the destination endpoint. LowCardinality because the
    -- column is a two-value label repeated on every row and is part of the sorting key.
    direction         LowCardinality(String),

    -- Additive across insert blocks, exactly as in flows_window.
    flow_count        AggregateFunction(count, UInt8),
    total_bytes       AggregateFunction(sum, UInt64),
    total_packets     AggregateFunction(sum, UInt64),

    -- True cardinality of the OTHER endpoint across blocks: destinations for 'out', sources
    -- for 'in'. A sum of per-block cardinalities would double-count a peer seen in two blocks.
    unique_peer_ips   AggregateFunction(uniq, String),

    -- Most recent insert that touched this row, for staleness checks.
    updated_at        SimpleAggregateFunction(max, DateTime)
)
ENGINE = AggregatingMergeTree()
PARTITION BY toYYYYMM(window_start)
ORDER BY (window_start, host_addr, direction)
-- The 7-day bootstrap floor, like every other managed table. `retention.ensure()` runs from
-- `db.apply_schema` on every start and converges this to the derived window.
TTL window_start + INTERVAL 7 DAY;

-- Drop and recreate the view. `CREATE ... IF NOT EXISTS` does not rebuild an existing materialized
-- view, so a migration that only added the table would leave an older view writing to the old
-- target (or, on a fresh database, nothing) while the new table stayed empty. 050 does the same and
-- for the same reason. The DROP is safe to repeat: the CREATE immediately after recreates it.
DROP VIEW IF EXISTS weirvern.flows_window_endpoint_mv;

CREATE MATERIALIZED VIEW IF NOT EXISTS weirvern.flows_window_endpoint_mv
TO weirvern.flows_window_endpoint
AS
SELECT
    window_start,
    host_addr,
    direction,
    countState()                      AS flow_count,
    sumState(toUInt64(bytes))         AS total_bytes,
    sumState(toUInt64(packets))       AS total_packets,
    uniqState(peer_addr)              AS unique_peer_ips,
    now()                             AS updated_at
FROM
(
    -- ONE ROW PER FLOW PER ENDPOINT. Each branch reads the same inserted block exactly once, so a
    -- flow can only reach the aggregate through 'out' (its source) and through 'in' (its
    -- destination). There is no third path and no join that could duplicate it.
    SELECT
        toStartOfFiveMinute(time_flow_start) AS window_start,
        src_addr                             AS host_addr,
        'out'                                AS direction,
        dst_addr                             AS peer_addr,
        bytes,
        packets
    FROM weirvern.flows
    UNION ALL
    SELECT
        toStartOfFiveMinute(time_flow_start) AS window_start,
        dst_addr                             AS host_addr,
        'in'                                 AS direction,
        src_addr                             AS peer_addr,
        bytes,
        packets
    FROM weirvern.flows
)
GROUP BY window_start, host_addr, direction;

-- NO READ VIEW, for the reason 050 measured: a view containing GROUP BY materialises the whole
-- grouped table before an outer WHERE can filter, and a five-minute sweep then reads the entire
-- retained history. On 2026-11-12 that OOMKilled the worker three times at a 4 GiB limit. Readers
-- use `weirvern/flow_windows.py:folded_endpoint()`, which keeps the time predicate beside the
-- merge so part pruning applies.
--
-- THE TWO RULES FOR THIS TABLE, unchanged from 050:
--   1. Use `-Merge` combinators; the columns are states, not values.
--   2. Put the window predicate in the SAME select as the merge.
