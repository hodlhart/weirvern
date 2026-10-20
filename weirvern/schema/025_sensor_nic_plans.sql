-- 025_sensor_nic_plans.sql
--
-- THE PER-NIC PLAN SET FOR EVERY SENSOR, hub or remote.
--
-- 020 gave one weirling one plan: one mode, one capture interface, one segment. That is the
-- same single-valued mistake the hub ConfigMap had, one level down. A sensor with eth1 and eth2
-- could describe only one of them; writing the second overwrote the first.
--
-- The plan set is JSON keyed by interface, carried beside the legacy plan rather than replacing
-- it. An old row reads as `plan_nics = ''` and behaves exactly as before, while a new row can
-- carry eth1=siphon + eth2=sluice. The document is validated by `weirvern/nic_plans.py` on write
-- and again by the agent before it arms anything.
--
-- WHY A STRING AND NOT COLUMNS PER ROLE. The set has a variable number of interfaces; a row per
-- NIC would be a second table with its own lifecycle, and the registry's one-row-per-sensor
-- shape is what the fleet view reads. The JSON is the document; the legacy columns stay for the
-- one-plan fallback and for every pre-upgrade reader.

ALTER TABLE weirvern.weirlings
    ADD COLUMN IF NOT EXISTS plan_nics String DEFAULT '' AFTER plan_targets;
