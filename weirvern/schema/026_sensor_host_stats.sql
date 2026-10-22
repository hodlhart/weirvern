-- Host counters reported by a sensor, including remote weirlings.
--
-- WHY THIS IS A HEARTBEAT COLUMN AND NOT A SECOND METRICS TABLE: the fleet view already has one
-- row per sensor per mode, and the CPU/memory reading is a property of that reporter at that
-- moment. A JSON string keeps this additive across the existing (sensor_id, mode) key and lets
-- an older reader ignore it without a schema migration dance. Empty means NOT REPORTED -- the
-- UI must render a dash, never a measured zero.
ALTER TABLE weirvern.sensor_status
    ADD COLUMN IF NOT EXISTS host_stats String DEFAULT '' AFTER interfaces;
