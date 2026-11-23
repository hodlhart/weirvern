-- The weirling registry: which sensors this hub EXPECTS to hear from.
--
-- WHY THIS TABLE EXISTS, GIVEN `sensor_status` ALREADY DOES. That table is what sensors
-- REPORT, so it can only describe a sensor that has checked in. An operator rolling out a
-- sensor on the third floor needs the opposite comparison: "I registered it, and it has never
-- said anything." Three genuinely different situations render identically as a missing row:
--
--   1. no sensors are configured at all,
--   2. a sensor is expected and has never come up, and
--   3. something is feeding this hub that nobody declared.
--
-- The registry makes the EXPECTATION explicit, which is the only way the comparison can be
-- made. Without it, (2) is invisible and (3) is invisible; both are states an operator must be
-- told about, and one of them is security-relevant.
--
-- REVOKED, NOT DELETED. `revoked_at` marks a registration retired while the row survives.
-- Deleting it would erase the only record that a sensor was ever expected, so a sensor that
-- broke and was pulled would be indistinguishable from one that never existed. The heartbeat
-- rows are never deleted, so a removed sensor's history stays as evidence.
--
-- WHY THERE ARE TWO TIMESTAMPS, WHICH IS NOT REDUNDANT:
--   `added_at`   when the sensor was FIRST registered. A fact about the fleet, shown to the
--                operator, and never rewritten.
--   `updated_at` the write time, and the ReplacingMergeTree VERSION.
-- The first draft used `added_at` as the version column and immediately had a problem worth
-- naming: revoking a sensor must supersede its registration, so the revocation row has to carry
-- a NEWER version -- which would have meant writing a fresh "added_at" for a sensor that was not
-- added, silently changing a fact the operator reads. Separating the version from the fact keeps
-- "when did we add this" honest while still letting an edit or a revocation win.

CREATE TABLE IF NOT EXISTS weirvern.weirlings
(
    -- The name this sensor is known by everywhere: heartbeat rows, the GUI, URLs. Constrained
    -- at the API boundary to characters needing no escaping, so a registration cannot produce a
    -- broken drill-down later.
    sensor_id   LowCardinality(String),

    -- Where it will report from. EMPTY IS MEANINGFUL: it means "not known yet", which is the
    -- normal case at registration time (an address may come from DHCP, or be the address the
    -- sensor NATs from). Storing a placeholder would be inventing a fact.
    address     String,

    -- Where it sits, in the operator's own words ("third floor IDF"). Free text on purpose:
    -- topology is site-specific, and a taxonomy imposed here would be wrong somewhere.
    segment     String,

    -- `loch` (passive: SPAN port or tap) or `siphon` (in-path). Recorded because it changes how
    -- urgent a never-reporting sensor is -- an in-path sensor that never came up may be blocking
    -- traffic on the segment it was meant to cover, while a passive one simply is not there yet.
    expected_mode LowCardinality(String),

    -- Deliberately switched off. NOT REPORTING IS THE EXPECTED OUTCOME for a disabled sensor, so
    -- the fleet view must not raise an alarm for it. Kept separate from revoked: a disabled
    -- sensor is still part of the fleet and still expected back.
    enabled     UInt8 DEFAULT 1,

    note        String,

    added_at    DateTime DEFAULT now(),
    -- Version column: the newest write for a sensor is the truth, so an edit or a revocation
    -- supersedes the row it replaces.
    updated_at  DateTime DEFAULT now(),

    -- NULL while live. Set when retired, and the row is kept.
    revoked_at  Nullable(DateTime),

    -- THE SENSOR'S OWN INTERCEPT PLAN (020_weirling_plan.sql carries the full reasoning).
    -- The deployment-global INTERCEPT_* keys describe exactly one sensor -- the one whose
    -- worker reads that ConfigMap. These fields let EVERY weirling carry its own: the
    -- operator writes them from the fleet view, and the sensor's own agent reads its OWN
    -- row, because ClickHouse is the one rendezvous a hub and a remote sensor share.
    --
    -- Kept in step with `expected_mode` on write (`fleet_store.register`), so the operator
    -- sees ONE mode per sensor: the declaration the fleet view compares against reports.
    --
    -- All '' = no plan declared, which is the pre-existing behaviour for a sensor that was
    -- registered before this existed.
    plan_mode    LowCardinality(String) DEFAULT '',
    plan_iface   LowCardinality(String) DEFAULT '',
    plan_segment String DEFAULT '',
    plan_addr    String DEFAULT '',
    plan_gateway String DEFAULT '',
    plan_targets String DEFAULT '',

    -- THE PER-WEIRLING IN-LINE CHANNEL (068_weirling_channel.sql carries the reasoning).
    -- A channel is a bridge between two NICs, not a sensor mode: the sensor stays in `loch`
    -- and the pair is what traffic crosses. Stored here so EVERY weirling can carry one, not
    -- just the hub whose ConfigMap happens to name the two ports.
    plan_channel_upstream   LowCardinality(String) DEFAULT '',
    plan_channel_downstream LowCardinality(String) DEFAULT ''
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY (sensor_id);

-- ONE ROW PER SENSOR, enforced by the ORDER BY key and collapsed by the engine. `FINAL` on the
-- read resolves versions that have not merged yet; the table is tiny, so reading it with FINAL
-- is cheap and much easier to reason about than a hand-written argMax.
