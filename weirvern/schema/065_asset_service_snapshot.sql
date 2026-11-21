-- 065_asset_service_snapshot.sql
--
-- `asset_services` IS A SNAPSHOT, NOT A LEDGER (operator, 2026-11-21).
--
-- Measured defect: a host last scanned when only one port answered still listed the twelve
-- services an older scan had found. `ReplacingMergeTree` only replaces a row with the SAME
-- (asset_key, port, protocol): a port that disappears is never overwritten, so the current table
-- accumulated every port the host had ever exposed. The history was correct all along
-- (`asset_service_history` is append-only, one row per service per scan); the "current" table
-- was the one that lied.
--
-- The writer now replaces the host's set on every COMPLETE scan: it inserts the new set and
-- deletes that host's rows which this scan did not produce. `last_seen_scan_id` is what makes
-- that one statement safe -- the delete predicate is "not from this scan", so it can never
-- remove a row the same scan just inserted, regardless of insert/delete ordering or merges.
--
-- It is also the answer to "which scan produced this row?" for an operator reading the host
-- sheet; the previous schema had only `observed_at`, which cannot be joined to asset_scans
-- because a scan id is not a timestamp.
--
-- `asset_scans.scan_complete` records what Nmap itself said about the run. Without it a partial
-- port list and a host that really closed ports are indistinguishable, and the ripple channel
-- that compares one scan with the previous one would report a broken scan as a set of closures.
-- The default is 0 ("not known to be complete"), so every historical row -- including the
-- interrupted scans that have no result -- is excluded by the channel rather than trusted.
--
-- ADDITIVE AND IDEMPOTENT: ADD COLUMN IF NOT EXISTS, constant defaults, no rewrite of existing
-- parts. Rows in asset_services written before this migration carry '' and are removed by the
-- first complete scan of their host -- which is exactly the repair this migration exists to
-- allow.
ALTER TABLE weirvern.asset_services
    ADD COLUMN IF NOT EXISTS last_seen_scan_id String DEFAULT '';

ALTER TABLE weirvern.asset_scans
    ADD COLUMN IF NOT EXISTS scan_complete UInt8 DEFAULT 0;
