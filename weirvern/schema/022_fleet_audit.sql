-- 022_fleet_audit: the write trail for destructive actions (BF-9).
--
-- WHY THIS TABLE. The studied consoles' containment flows end the same way: the operator
-- confirms with a reason, and months later someone asks WHO took the segment in-path and WHY.
-- The reason is not a formality -- it is the difference between an incident review and a
-- guessing session. One row per accepted write: what, on what, by whom, why, and when. The
-- table is append-only by convention: nothing in the product updates or deletes these rows.

CREATE TABLE IF NOT EXISTS weirvern.fleet_audit (
    at       DateTime64(3, 'UTC') DEFAULT now64(3),
    scope    LowCardinality(String),   -- fleet | sluice
    action   LowCardinality(String),   -- plan | revoke | enable | disable ...
    target   String,                   -- the exact target, verbatim
    reason   String,
    actor    String
) ENGINE = MergeTree()
ORDER BY (at, scope, action, target)
TTL at + INTERVAL 365 DAY;
