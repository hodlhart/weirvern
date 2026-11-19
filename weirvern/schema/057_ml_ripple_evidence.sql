-- 057_ml_ripple_evidence.sql
--
-- WHY THIS EXISTS: a ripple is made of evidence, and until now the evidence existed only
-- inside a scoring pass. `ml_ripple` stores the FUSED answer per host, so the console could
-- say "a ripple fired" but not "which measurements moved, by how much, against what". The
-- operator's direction was to show the pieces before the answer: "show all the ml and the
-- peices of ripples". This is that store.
--
-- WHAT A ROW IS. One host, one channel, one scale, one measurement: the statistic for the
-- trailing window, the median of that host's OWN trailing baseline, the empirical p-value, the
-- number of baseline windows behind it, and how much of the expected baseline actually
-- existed. A channel with too little history writes NO row -- absence is the statement "not
-- measured", which is different from p = 1.0 ("measured and quiet").
--
-- WHY REPLACING AND NOT MERGE. The pass runs hourly and measures the SAME (window, host,
-- channel, scale) more than once while the hour is open. The newest computed_at wins, so a
-- reader never sees two rows for one measurement. `scale` is part of the sorting key because a
-- 1h and a 24h measurement of the same channel are different pieces of evidence, not a
-- correction of each other.
--
-- THE RIPPLES ARE NOT STORED. They are a deterministic grouping of these rows
-- (weirvern/models/ripple_evidence.py), so a second table would be a copy that can drift from
-- the evidence it claims to summarise -- after a TTL, a re-run, or a change to the grouping
-- window. The read path groups these rows instead, which keeps the sentence and the numbers
-- in the same place.
--
-- ADDITIVE AND SAFE: CREATE TABLE IF NOT EXISTS, no ALTER of an existing table, no backfill.
-- A deployment that never runs the pass simply has an empty table, and the read path says so.
CREATE TABLE IF NOT EXISTS weirvern.ml_ripple_evidence
(
    -- The grouping window the ripple is read in (hour-aligned), and its end. `observed_at` is
    -- when the measurement actually ran; the two differ because a pass at 14:37 measures the
    -- trailing window ending at 14:37 but belongs to the 14:00 ripple window.
    window_start     DateTime,
    window_end       DateTime,

    src_addr         String,
    channel          LowCardinality(String),
    family           LowCardinality(String),
    -- 1h | 6h | 24h | 7d. The length of the window that was measured, not the bucket size.
    scale            LowCardinality(String),

    -- The measurement and the history it was ranked against.
    value            Float64,
    baseline_median  Float64,
    p_value          Float64,
    sample_count     UInt32,
    coverage         Float64,
    -- "rose" | "fell" | "unchanged": both tails are tested, because a host going quiet is a
    -- change and a one-sided test would miss half of what an operator needs to see.
    direction        LowCardinality(String),

    model_version    LowCardinality(String),
    observed_at      DateTime,
    computed_at      DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree(computed_at)
PARTITION BY toYYYYMM(window_start)
ORDER BY (window_start, src_addr, channel, scale)
-- Thirty days of hourly windows is enough to compare a ripple against the recent past and
-- small enough that the table stays a measurement store rather than another flow log.
TTL window_start + INTERVAL 30 DAY;
