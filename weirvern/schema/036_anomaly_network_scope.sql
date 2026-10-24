-- ── THE SCOPE THAT PRODUCED AN ANOMALY ────────────────────────────────────────────────
--
-- Operator-declared network scopes decide whether a host is eligible for per-host alerts.
-- Carrying the winning scope on the anomaly row makes that decision auditable after the fact:
-- a row can be filtered by scope, and a row with an empty scope means "unscoped legacy" rather
-- than an implicit internal/external guess.
--
-- The base CREATE in 001 carries the same column for fresh installs; this ALTER is what makes
-- an existing deployment get it, because CREATE TABLE IF NOT EXISTS is a no-op once the table
-- exists (the ATT&CK-columns lesson in tests/test_schema_migrations.py).
ALTER TABLE weirvern.netflow_anomalies
    ADD COLUMN IF NOT EXISTS network_scope LowCardinality(String) DEFAULT '' AFTER severity_basis;
