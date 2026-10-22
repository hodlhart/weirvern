-- 028_weirling_topology.sql
--
-- EXPLICIT REMOTE TOPOLOGY: capture (default) or inline.
--
-- A SPAN/TAP unit is a passive capture sensor. An inline unit is a different deployment: two
-- dedicated NICs in a transparent bridge, and no management address on either. Making that a
-- declared field keeps the fleet view from guessing and prevents a test from being offered on a
-- topology that cannot perform it.
--
-- Appended last, like the plan columns, so a pre-upgrade positional reader stays aligned. Old
-- rows read the default `capture`; nothing silently becomes inline.
ALTER TABLE weirvern.weirlings
    ADD COLUMN IF NOT EXISTS topology LowCardinality(String) DEFAULT 'capture' AFTER plan_nics;
