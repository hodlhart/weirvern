-- 062_normal_ripple_signatures.sql
--
-- A PERMANENT CHANGE SHOULD NOT RIPPLE EVERY HOUR UNTIL THE BASELINE CATCHES UP.
--
-- `normal_traffic` (055) taught the FLOW/DNS baseline what an operator considers normal, but the
-- ripple channels never read it: their question is not "how much traffic" but "is this VALUE new
-- for this host", and the two cannot be answered by the same row shape. This table is that answer
-- for the ripple layer.
--
-- WHAT A ROW IS: ONE exact value, on ONE channel, for ONE host, expected until a review date.
-- It is a statement about the host's own normal, not a filter on the alert path: the raw traffic
-- is untouched, every row still exists in `flows`/`zeek_*`, and only the "is this value new for
-- this host" computation changes. The evidence returns by itself when `review_after` passes.
--
-- SCOPE IS THE SAFETY PROPERTY. There is deliberately no column that could name a family, a
-- channel-wide rule, or a host-wide rule:
--   * `channel` is a validated channel name, never a family (`tls` is not a channel);
--   * `value` is one exact string compared with equality, never a prefix, regex or mask;
--   * `host_addr` is one address literal, never a CIDR;
--   * `review_after` is a DATE with a 90-day default and a 365-day ceiling, so no row is forever.
-- The API (`weirvern/ripple_signatures.py`) refuses every wider shape; the tests prove it.
--
-- WHY REPLACING, AND WHY THE VERSION COLUMN IS NOT `created_at`.
-- Removal must supersede a row, never delete it: the audit survives. `created_at` records when
-- the operator made the claim and is carried unchanged through a removal, so the history still
-- says who claimed it and when; `updated_at` is the write clock ReplacingMergeTree compares.
-- The sorting key puts the lookup index first: every read is "for this host and channel".
--
-- ADDITIVE AND SAFE: CREATE TABLE IF NOT EXISTS, no ALTER, no backfill. A deployment that never
-- normalizes a signature simply keeps an empty table.
CREATE TABLE IF NOT EXISTS weirvern.normal_ripple_signatures
(
    id             String,
    -- One address literal. A CIDR is refused by the API because it would widen the claim.
    host_addr      String,
    -- The ripple channel whose value is being taught, e.g. `tls_fingerprint_diversity`.
    channel        LowCardinality(String),
    -- Derived from the channel by the server, stored for the reader; never supplied by a caller.
    family         LowCardinality(String),
    -- The exact value the channel compares: `server_name|ja4`, a user-agent, a banner pair, ...
    value          String,
    created_at     DateTime64(3),
    created_by     LowCardinality(String) DEFAULT 'operator',
    -- Why this value is normal for this host. Required; the record is the review.
    reason         String,
    -- The evidence returns on its own when this date passes. 90 days by default, 365 at most.
    review_after   Date,
    -- Removal supersedes the row (ReplacingMergeTree) and records who and why.
    removed_at     Nullable(DateTime64(3)),
    removed_by     LowCardinality(String) DEFAULT '',
    removed_reason String DEFAULT '',
    -- The ReplacingMergeTree version. NOT `created_at`: a removal must not rewrite the moment the
    -- claim was made, or the audit would say the operator removed what they had just created.
    updated_at     DateTime64(3)
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY (host_addr, channel, id);
