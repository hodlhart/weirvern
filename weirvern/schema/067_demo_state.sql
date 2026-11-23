-- 067_demo_state.sql
--
-- THIS DEPLOYMENT IS SHOWING SEEDED DATA, AND THE CONSOLE SAYS SO.
--
-- A test drive that looks like a working sensor is the most dangerous demo there is: the Health
-- panel would report a stalled feed (there is no capture), the Models tab would hold detectors
-- that never saw a packet, and a reader could mistake any of it for a live deployment. The seeder
-- already tells the operator in the terminal; this table makes the same fact readable BY THE GUI,
-- so the banner and the health checks agree with the seeder.
--
-- A TABLE RATHER THAN AN ENVIRONMENT VARIABLE. The console reads ClickHouse; a flag that lives
-- only in a pod's environment is invisible to the API that renders the page, and a demo seeded on
-- a box whose env was not changed would look live. The seeder writes this row as part of seeding.
--
-- `enabled = 0` is how demo mode is retired without dropping the evidence that it happened: the
-- seed and the timestamp stay, and the live-feed checks come back.
CREATE TABLE IF NOT EXISTS weirvern.demo_state
(
    id         UInt8,
    enabled    UInt8,
    seeded_at  DateTime64(3, 'UTC'),
    seed       UInt32,
    hosts      UInt16,
    note       String DEFAULT ''
)
ENGINE = ReplacingMergeTree(seeded_at)
ORDER BY id;
