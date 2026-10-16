-- UNTIL REVOKED: the operator can set a block's duration to 0.

-- 011 made `expires_at` NOT NULL and refused unbounded blocks, on the reasoning that a rule with
-- no end outlives the person who wrote it and the only safe direction was to refuse it. The
-- operator has since asked for exactly that capability, explicitly (2026-10-16): "users should be
-- able to set time to 0 to block indefinitely". It is their network and their call, so the
-- column becomes Nullable and NULL means UNTIL REVOKED -- deliberately not a far-future
-- timestamp, which would render as a plausible date in every view that formats one and be a lie
-- in the store.
--
-- Every reader that filtered `expires_at > now()` treats NULL as LIVE (see LIVE_RULE_SQL in
-- sluice_store.py); `Rule.is_live()` in Python follows the same rule, the rules list shows
-- "until revoked" instead of a date, and revocation is the only way such a rule stops.

-- IDEMPOTENT ON PURPOSE: apply_schema re-runs every file on every start (tests/test_schema_migrations.py
-- enforces it), so the statement carries IF EXISTS and re-applying it is a no-op.
ALTER TABLE weirvern.sluice_rules MODIFY COLUMN IF EXISTS expires_at Nullable(DateTime);
