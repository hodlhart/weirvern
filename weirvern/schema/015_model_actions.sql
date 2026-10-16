CREATE TABLE IF NOT EXISTS weirvern.model_actions
(
    -- WHY A TABLE AND NOT A FLAG IN MEMORY. The training runs in the WORKER pod, which owns
    -- MODEL_DIR; the operator is looking at the GUI pod, which does not mount it. The two pods
    -- share exactly one thing, and it is not a filesystem: it is ClickHouse. So a request is a
    -- row, the worker acts on it, and the result is a row back -- the same shape as the gate's
    -- rule store, for the same reason: a decision made in one process and read in another must
    -- be visible in both, and must survive a restart of either.
    ts           DateTime,
    action_id    String,
    -- retrain: the operator asked for a candidate. keep / trash: they judged it.
    action       LowCardinality(String),
    -- requested -> running -> done | failed, and for a decision: requested -> applied | discarded.
    -- A state that never changes is a request nobody picked up, and the GUI shows it as such
    -- rather than as "working".
    state        LowCardinality(String),
    -- For keep / trash: the action_id of the retrain they are judging.
    target_id    String,
    requested_by String,
    note         String,
    -- The JSON report the worker produced (per-detector rows, the training window, and how many
    -- detections were already recorded inside that window). Kept on the row rather than in a
    -- file, because the operator reads it from the OTHER pod.
    report       String
)
ENGINE = ReplacingMergeTree(ts)
ORDER BY (action_id);
