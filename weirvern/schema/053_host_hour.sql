-- 053_host_hour.sql
--
-- THE DECISION UNIT MOVES FROM THE FIVE-MINUTE WINDOW TO THE HOST-HOUR.
--
-- At 22 monitored hosts this network produces about 87,000 host-windows a day and 528
-- host-hours. A detector that decides per window gets 165 times more chances to raise a
-- false alarm for the same evidence, and the measured consequence is the current alert
-- volume: 176 episodes a day against a target of ten to twenty. Scoring the hour does not
-- make the detector smarter; it makes the arithmetic possible.
--
-- The five-minute window stays the ATOM. `host_hour_features` is built from it, and nothing
-- here replaces `flows_window` or the sweep that reads it.
--
-- WHY THESE FEATURES, AND NOT THE RAW COLUMNS
--
-- A host-hour is compared against the same host's own past hours, so the vector has to be
-- comparable across hours of very different size. Logs for the counts (a busy hour is not
-- ten thousand times more anomalous than a quiet one, it is a few sigma), and a ratio for
-- bytes per flow so a host that does the same work in fewer, larger connections is visible.
--
-- `dst_hosts` is the EXACT distinct destination count for the hour, which is why the
-- builder reads raw `flows` rather than summing `flows_window.unique_dst_ips`: a uniq state
-- cannot be merged across window boundaries, and summing per-window counts over-counts any
-- destination seen in two windows. At this scale an hour is about 38,000 flow rows, so the
-- exact query is cheap; on a larger network the right fix is a second materialized view
-- keyed on the hour, not a sum of per-window uniques.

CREATE TABLE IF NOT EXISTS weirvern.host_hour_features
(
    hour            DateTime,
    src_addr        String,

    -- Measured, not derived: the merge of the hour's five-minute windows.
    flow_count      UInt64,
    total_bytes     UInt64,
    total_packets   UInt64,
    dst_hosts       UInt32,

    -- What the channels read. Stored rather than computed at read time so a reference
    -- rebuild and a live score see exactly the same numbers.
    log_bytes       Float64,
    log_packets     Float64,
    log_flows       Float64,
    bytes_per_flow  Float64,

    computed_at     DateTime
)
ENGINE = ReplacingMergeTree(computed_at)
PARTITION BY toYYYYMM(hour)
ORDER BY (hour, src_addr)
TTL hour + INTERVAL 30 DAY;

-- ONE ROW PER (host, hour of day, feature): what "normal" means for this host at this time.
--
-- `phase_hours` records how far the phase was pooled to reach a sample count worth using.
-- Fourteen days gives fourteen examples for a given hour of day, which is too few for a
-- stable median/MAD; pooling the adjacent hours until there are at least fifty is the rule
-- the design specifies, and recording the width makes a thin phase visible instead of
-- silently noisy.
CREATE TABLE IF NOT EXISTS weirvern.host_reference_stats
(
    src_addr        String,
    hour_of_day     UInt8,
    feature         LowCardinality(String),

    median          Float64,
    mad             Float64,
    p01             Float64,
    p99             Float64,
    n               UInt32,
    phase_hours     UInt8,
    window_days     UInt16,
    computed_at     DateTime
)
ENGINE = ReplacingMergeTree(computed_at)
ORDER BY (src_addr, hour_of_day, feature);

-- THE REFERENCE'S OWN CHANNEL SCORES, kept as samples so a live p-value is conformal
-- rather than normal-approximated: p = (1 + #{reference >= score}) / (n + 1).
--
-- A feature-level median/MAD cannot produce this. The channel statistic is a MAX over
-- several features, and the distribution of a maximum is not the distribution of its parts.
-- Keeping the per-hour channel scores (about 24 x 30 rows per host per channel) is small and
-- makes the p-value exactly the empirical tail the design asks for.
CREATE TABLE IF NOT EXISTS weirvern.host_reference_samples
(
    src_addr    String,
    hour_of_day UInt8,
    channel     LowCardinality(String),
    score       Float64,
    observed_at DateTime,
    computed_at DateTime
)
ENGINE = ReplacingMergeTree(computed_at)
ORDER BY (src_addr, hour_of_day, channel, observed_at)
TTL computed_at + INTERVAL 2 DAY;

-- EVERY CHANNEL'S VERDICT FOR EVERY HOUR, INCLUDING THE ONES THAT ABSTAINED.
--
-- The design's rule: silence has a reason. A channel with no reference or no data writes a
-- state, not a zero, so a broken input cannot look like a quiet network.
CREATE TABLE IF NOT EXISTS weirvern.host_hour_scores
(
    hour        DateTime,
    src_addr    String,
    channel     LowCardinality(String),
    score       Float64,
    p_value     Float64,
    state       LowCardinality(String),   -- scored | no-reference | no-data | error
    evidence    String,
    computed_at DateTime
)
ENGINE = ReplacingMergeTree(computed_at)
ORDER BY (hour, src_addr, channel)
TTL hour + INTERVAL 30 DAY;
