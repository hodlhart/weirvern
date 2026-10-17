-- 019_sensor_interfaces.sql
--
-- Each sensor's own NICs, as the sensor itself sees them: its heartbeat's network namespace,
-- filtered of software interfaces by the heartbeat. The operator asked for "each sensor its
-- nics" beside its status on the fleet panel (2026-10-17); the hub cannot enumerate a remote
-- box's interfaces itself, so the sensor reports them the way it reports everything else.
--
-- Array(String) rather than a comma string: no delimiter games, and an empty array means
-- "not reported", which the reader renders as a dash -- never as a made-up list.

ALTER TABLE weirvern.sensor_status
    ADD COLUMN IF NOT EXISTS interfaces Array(String) AFTER packets_dropped;
