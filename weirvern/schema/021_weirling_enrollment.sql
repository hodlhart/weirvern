-- 021_weirling_enrollment.sql
--
-- ONE-TIME ENROLLMENT TOKENS FOR mTLS WEIRLINGS.
--
-- The operator creates a token for a sensor id; the sensor presents it once with a
-- CSR and receives a certificate. Only the SHA-256 hash is stored, so a database
-- reader cannot replay the token. The row is kept after use as the audit record of
-- which sensor was enrolled and when; a token is never reused.
--
-- The registry itself remains `weirvern.weirlings`. This table only authorizes the
-- enrollment; the `used_at` version is written after the CSR has been signed and the
-- sensor has been registered, so a failed enrollment does not burn the token.

CREATE TABLE IF NOT EXISTS weirvern.weirling_enrollments
(
    token_hash      String,
    sensor_id       LowCardinality(String),
    address         String DEFAULT '',
    segment         String DEFAULT '',
    expected_mode   LowCardinality(String) DEFAULT 'loch',
    expires_at      DateTime,
    used_at         Nullable(DateTime),
    updated_at      DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY (token_hash);
