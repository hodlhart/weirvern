-- Migration: add the ATT&CK technique columns to netflow_anomalies.
--
-- WHY THIS FILE EXISTS AS A SEPARATE MIGRATION RATHER THAN AN EDIT TO 001_weirvern.sql.
--
-- The columns were first added to the CREATE TABLE in 001_weirvern.sql, which is where they
-- belong -- and on the deployed system nothing happened. `apply_schema` runs every *.sql file
-- on every start, but a CREATE TABLE IF NOT EXISTS is a no-op once the table exists, so an
-- edited column list is never applied to a database that already has the table. Measured on
-- the test box:
--
--     ClickHouse exception, code: 47
--     Unknown expression identifier `attack_techniques` in
--     SELECT attack_techniques FROM weirvern.netflow_anomalies
--
-- The table was there, the schema file listed the column, and the column did not exist. That
-- gap is invisible on a fresh deployment and permanent on an existing one, which is the worst
-- combination: it works for whoever built it and fails for whoever upgrades.
--
-- So schema changes to an EXISTING table go in a numbered migration that ALTERs. The DDL in
-- the original file is kept in step so a fresh install gets the right column list in one
-- statement, and this file is what reconciles a database that predates the change.
--
-- `ADD COLUMN IF NOT EXISTS` is idempotent in ClickHouse, so this is safe to run on every
-- worker start and on every schema Job -- which is exactly how apply_schema calls it.

ALTER TABLE weirvern.netflow_anomalies
    ADD COLUMN IF NOT EXISTS attack_techniques String DEFAULT '[]';

ALTER TABLE weirvern.netflow_anomalies
    ADD COLUMN IF NOT EXISTS attack_label String DEFAULT '';

-- Record the migration so an operator can see which schema state a deployment is in. The
-- version string is deliberately the file's own name: a later reader can match the row to the
-- file without guessing at an ordering scheme.
INSERT INTO weirvern.schema_versions (version) VALUES ('005_attack_techniques');
