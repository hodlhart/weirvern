-- 022_weirling_networks.sql
--
-- WHAT A WEIRLING MONITORS, IN ITS OWN REGISTRATION.
--
-- `segment` is where the sensor SITS and the schema deliberately allows free text ("third floor
-- IDF"). It is not a reliable scan scope. `networks` is the explicit list of CIDRs the sensor
-- monitors; the scanner reads it, so registering or changing a weirling changes the scope without
-- a second hand-maintained list. Empty means "not declared", never "covers nothing".
--
-- Array(String), not a comma-separated string: each entry can be validated as a CIDR at the API
-- boundary, and the GUI can show one fact per network.
ALTER TABLE weirvern.weirlings
    ADD COLUMN IF NOT EXISTS networks Array(String) DEFAULT [] AFTER plan_targets;
