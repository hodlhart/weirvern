-- Sensor heartbeat.
--
-- WHY THIS TABLE EXISTS: the web GUI runs in its own pod and has NO access to the sensor
-- pod's filesystem, so it cannot see whether an intercept is actually running. Before
-- this, it could only report the CONFIGURED mode from the ConfigMap -- which is a claim
-- about intent, not about reality. Those differ exactly when it matters most: a siphon
-- process that died, or was never started, still has SENSOR_MODE=siphon in the ConfigMap.
--
-- ClickHouse is the right rendezvous because both components already talk to it, it works
-- across pods and nodes, and it means the TUI and the GUI show the same fact from the same
-- source rather than each inferring it separately.
--
-- WHY A HEARTBEAT AND NOT A FLAG: a boolean "running" column cannot distinguish "the
-- intercept is up" from "the intercept was up when it last wrote and has since died".
-- Staleness is the signal. A row whose `ts` is older than a few heartbeat intervals means
-- the process is gone, and the reader must say so rather than displaying the last known
-- state as if it were current -- which is the same silent-empty failure this project has
-- hit repeatedly (an always-empty Top Talkers panel, an always-empty Zeek Services panel).

CREATE TABLE IF NOT EXISTS weirvern.sensor_status
(
    -- Identity of the reporting process. One sensor per deployment today; a replica would
    -- write its own node name so the reader can show both rather than one overwriting.
    sensor_id     LowCardinality(String),

    -- Mode the process is ACTUALLY running in, written by the process itself. This is the
    -- field that makes the table worth having: it is observed, not configured.
    mode          LowCardinality(String),

    -- For siphon: what is being intercepted. Empty in loch mode, where there is nothing to
    -- intercept -- an empty value here means "not applicable", not "unknown".
    iface         LowCardinality(String),
    segment       String,
    hosts         UInt32,
    mappings      UInt32,

    -- liveness and the watchdog's own counters. `restores` climbing while `running` is
    -- true means the watchdog fired and re-armed, which an operator needs to see: it
    -- means the segment was briefly un-poisoned, or that forwarding stalled.
    running       UInt8,
    uptime_s      Float64,
    restores      UInt32,
    refreshes     UInt32,

    -- Reasons the watchdog failed open, newest last. Kept alongside the counters so
    -- "why did it drop" is answerable from the same row that shows it dropped.
    failures      Array(String),

    -- When the heartbeat was written. STALENESS IS THE LIVENESS SIGNAL: readers compute
    -- age from this and must report "not running" past a threshold, never the last state.
    ts            DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree(ts)
ORDER BY (sensor_id, mode)
TTL ts + INTERVAL 7 DAY;

-- One row per (sensor_id, mode): a heartbeat UPDATES its own row rather than appending, so
-- this stays tiny no matter how long the sensor runs. ReplacingMergeTree(ts) keeps the
-- newest version once parts merge; the reader orders by ts to be correct before then.
