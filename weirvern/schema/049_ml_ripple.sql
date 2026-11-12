-- 049_ml_ripple.sql
--
-- WHY THIS EXISTS: RIP-5 fuses the shadow channels into one answer per host, and that answer must
-- be readable after the pass that produced it. A fused result that only exists in a log line
-- cannot be explained to an operator, compared across cycles, or probed by the API -- and the
-- Models card would have to recompute it, which would make the console disagree with what the
-- worker actually decided.
--
-- One row per host per evaluation; `src_addr = ''` is the segment-level row written when no
-- channel had fresh evidence (the honest "unknown", never an empty success). `pageable` is
-- recorded but is always 0 from this pass: the page decision belongs to the alert budget.
--
-- The JSON columns hold `ripple.fuse()`'s own lists verbatim. They are Strings, not Nested,
-- because the reader must reproduce exactly what was decided, including the reasons, rather than
-- re-deriving them from a flattened form.
CREATE TABLE IF NOT EXISTS weirvern.ml_ripple
(
    evaluated_at     DateTime,
    src_addr         String,
    status           LowCardinality(String),
    reason           String,
    confidence       Float64,
    combined_p       Float64,
    families         Array(String),
    scales           Array(String),
    contributors     String,
    unknown_channels String,
    channel_count    UInt16,
    pageable         UInt8,
    model_version    String,
    computed_at      DateTime DEFAULT now()
)
ENGINE = MergeTree()
ORDER BY (evaluated_at, src_addr)
TTL computed_at + INTERVAL 90 DAY;
