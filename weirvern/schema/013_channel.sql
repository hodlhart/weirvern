-- 013_channel.sql
--
-- WHY THE GATE'S STATE ROW GAINS A COLUMN. The Sluice Gate can now enforce by two VERIFIED
-- paths, and the honest answer to "is this gate doing anything" depends on which one is live:
--
--   * 'channel' -- a weirling wired IN LINE (upstream port <-> downstream port on one bridge,
--     bridge-nf enabled). Enforces while the mode stays `loch`: nothing is forged.
--   * 'siphon'  -- in path by ARP redirect, verified by LIVE intercept evidence (a fresh
--     sensor_status row with mappings > 0), not by the configuring of the mode.
--   * 'none'    -- rules are installed but no verified path carries traffic through this host;
--     the state column reads 'degraded' with the reason in `detail`.
--   * ''        -- no verdict was taken (an older pass, or a caller that did not supply a mode).
--
-- `detail` alone would make an operator parse English to answer "by what?", and this project
-- keeps deciding that a machine-readable fact belongs in a column exactly once. The state row is
-- what the panel and the alarm paths read; the enforcement path is not decoration there, it is
-- the difference between a block that drops real packets and a counter over traffic that never
-- passed through.

ALTER TABLE weirvern.sluice_state
    ADD COLUMN IF NOT EXISTS enforcement String DEFAULT '' AFTER backend_expected;
