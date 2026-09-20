-- Alert review state: the analyst's disposition of an anomaly.
--
-- WHY THIS TABLE EXISTS (SOC-1). Before this, the GUI could show an anomaly and explain
-- it, and then the workflow ended: no acknowledge, no resolve, no false-positive marking,
-- no note. The same recurring benign anomaly (a nightly backup, a scanner you own)
-- re-appeared forever with no way to clear it, and there was no record of what was
-- reviewed -- so "what did I look at last night" had no answer and the wall of identical
-- rows never shrank.
--
-- KEYED LIKE netflow_anomalies, DELIBERATELY. A review is about ONE (window_start,
-- src_addr) anomaly. The same pair is the ReplacingMergeTree key of netflow_anomalies,
-- so a review joins to its anomaly with no id column to mint, pass around, and
-- eventually get wrong. A review for a window that has aged out of netflow_anomalies
-- (30-day TTL) is harmless and also expires under the same TTL below.
--
-- STATE, NOT A BOOLEAN. "Reviewed" collapses three different dispositions with three
-- different follow-ups: ack (seen, still watching), resolved (handled), false_positive
-- (the model was wrong -- which is also the label ML's feedback loop will read later).
-- An empty string means REVIEW CLEARED (back to unreviewed), which is the honest
-- representation of undo; absence of a row would be indistinguishable from "never
-- reviewed" only by accident, and with ReplacingMergeTree the cleared row still carries
-- its note when one was left.
--
-- REPLACING, not append: the current disposition is the fact, and every write replaces
-- it. A full audit trail would need an append log; that is explicitly deferred, and this
-- table's shape does not pretend to be one.
CREATE TABLE IF NOT EXISTS weirvern.alert_reviews
(
    -- The anomaly this reviews: same pair as netflow_anomalies' ORDER BY.
    window_start   DateTime64(3),
    src_addr       String,

    -- 'ack' | 'resolved' | 'false_positive' | '' (cleared). LowCardinality: three values.
    state          LowCardinality(String),

    -- The analyst's words. Free text, capped, empty when none was given. Kept on a
    -- cleared review on purpose: "cleared, but the note said ack'd for the vendor demo"
    -- is more useful than a blank row.
    note           String,

    -- When the review was last written. DateTime64(3) rather than DateTime: this is the
    -- ReplacingMergeTree version column, and two decisions a second apart (ack, then
    -- immediately false-positive) must not tie -- a tie leaves FINAL picking arbitrarily
    -- between them.
    reviewed_at    DateTime64(3) DEFAULT now64(3),

    -- Phase 1 has no per-user identity on the GUI (writes are gated by the single
    -- operator token), so this records the ACTOR CLASS, not a person: 'operator' for a
    -- token-authenticated write. It exists now so a later real identity slots in
    -- without a schema change.
    reviewed_by    LowCardinality(String) DEFAULT 'operator'
)
ENGINE = ReplacingMergeTree(reviewed_at)
ORDER BY (window_start, src_addr)
TTL toDateTime(window_start) + INTERVAL 30 DAY;

-- Same TTL as netflow_anomalies: a review cannot outlive its anomaly, and both vanish
-- together so the GUI never joins a review to nothing.
