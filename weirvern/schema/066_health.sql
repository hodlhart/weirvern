-- 066_health.sql
--
-- THE WATCHDOG'S DURABLE HEALTH LEDGER.
--
-- WHY A TABLE AND NOT A LOG LINE. On 2026-11-21 an eighteen-hour dual-sink outage was visible
-- only as `logger.error` lines, and the alert channel that should have carried it had
-- PUSHOVER_ENABLED=0 with both keys empty: 32,897 `alert_events` rows, zero sent. A verdict that
-- exists only in the log of a pod that has since been replaced cannot be read back, cannot be
-- rate-limited across five-minute CronJob invocations, and cannot be shown on the Health panel.
--
-- ONE ROW PER CHECK, upserted by a ReplacingMergeTree. `status` is the closed state set from the
-- watchdog (`ok`, `stalled`, `no_data`, `unreadable`, `restart`, `oomkilled`, `pressure`,
-- `failed`, `expiring`, `error`, `unconfigured`). `last_notified_at` is what makes repeats
-- rate-limited without a filesystem: the next run reads it through FINAL and suppresses a
-- duplicate page inside the cooldown while still sending a recovery edge.
--
-- `watchdog_delivery=unconfigured` is written on every run where Pushover is disabled or either
-- key is empty. That row is the point of the table: the watchdog must not report success for a
-- page it could not send.
CREATE TABLE IF NOT EXISTS weirvern.health
(
    check_name       LowCardinality(String),
    status           LowCardinality(String),
    detail           String DEFAULT '',
    -- The check's structured measurement as JSON (age, bytes, pod restart counts). String rather
    -- than a typed column because every check measures a different shape, and a shared envelope
    -- beats a sparse table with a dozen nullable columns.
    value            String DEFAULT '',
    -- How many consecutive runs have reported the same firing status. A climbing number beside a
    -- flat `last_notified_at` is the difference between "still down" and "just went down".
    consecutive      UInt32 DEFAULT 0,
    last_notified_at Nullable(DateTime64(3, 'UTC')),
    updated_at       DateTime64(3, 'UTC') DEFAULT now64(3)
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY check_name
TTL toDateTime(updated_at) + INTERVAL 90 DAY;
