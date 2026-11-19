-- ── NORMALIZED TRAFFIC IS OPERATOR KNOWLEDGE, NOT A SILENCED ALERT ────────────────────────────
--
-- The Normalize tab lets an operator mark traffic that is normal FOR THEM. That judgement is
-- folded into the host's adaptive baseline, so the models learn it as normal and stop scoring it
-- as anomalous. Nothing in the alert path consults this table: if the traffic stops paging, it is
-- because the baseline widened, not because a page was suppressed (operator, 2026-11-19).
--
-- PERMANENT UNTIL REMOVED. There is no TTL. Removal writes a new row with status='removed' and
-- the remover's name; the old row stays for the history. ReplacingMergeTree(created_at) keeps the
-- newest row per entry_id, so `FINAL` reads the current state of each entry.
CREATE TABLE IF NOT EXISTS weirvern.normal_traffic
(
    entry_id      String,
    created_at    DateTime64(3),
    created_by    LowCardinality(String) DEFAULT 'operator',
    source        LowCardinality(String),            -- 'flow' | 'dns'
    status        LowCardinality(String) DEFAULT 'active',
    removed_at    Nullable(DateTime64(3)),
    removed_by    LowCardinality(String) DEFAULT '',
    src_addr      String,                            -- the host the pattern belongs to
    dst_prefix    String DEFAULT '',                 -- flow rows: destination /24
    dst_port      UInt16 DEFAULT 0,
    proto         UInt8 DEFAULT 0,
    dns_name      String DEFAULT '',                 -- dns rows
    dns_qtype     UInt16 DEFAULT 0,
    flows         UInt64 DEFAULT 0,
    bytes         UInt64 DEFAULT 0,
    packets       UInt64 DEFAULT 0,
    samples       UInt64 DEFAULT 0,                  -- windows the distribution was measured over
    avg_bytes     Float64 DEFAULT 0,
    var_bytes     Float64 DEFAULT 0,
    avg_packets   Float64 DEFAULT 0,
    var_packets   Float64 DEFAULT 0,
    first_seen    DateTime64(3),
    last_seen     DateTime64(3),
    note          String DEFAULT ''
)
ENGINE = ReplacingMergeTree(created_at)
ORDER BY entry_id;
