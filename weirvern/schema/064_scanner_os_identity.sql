-- 064_scanner_os_identity.sql
--
-- THE DISTRO AND THE PACKAGE FAMILY ARE DIFFERENT FACTS (operator, 2026-11-20).
--
-- Measured defect: a host whose /etc/os-release says NAME="Ubuntu", VERSION_ID="26.04",
-- ID=ubuntu, ID_LIKE=debian was reported as "debian 13" -- the family (ID_LIKE) had been used
-- as the distribution name, with a version from the wrong line. The console must show what a
-- person recognises ("Ubuntu 26.04 LTS"), while the install command is chosen from the family.
--
-- os_id stays the machine identifier from ID ("ubuntu"); os_label is the display string the
-- console renders, including the family/manager note when they differ; os_family is what picks
-- the package manager (apt here). Appended columns; existing readers keep their positions.
ALTER TABLE weirvern.scanner_status
    ADD COLUMN IF NOT EXISTS os_label String DEFAULT '',
    ADD COLUMN IF NOT EXISTS os_family LowCardinality(String) DEFAULT '';
