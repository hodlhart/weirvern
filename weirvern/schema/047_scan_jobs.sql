-- MANUAL SCAN JOBS + LEASES.
--
-- A job is a request, not a second scanning loop. The scanner claims one row at a time under a
-- lease, so two scanner pods cannot execute the same request and a pod restart does not lose it.
-- ReplacingMergeTree keeps the latest state per job_id; the history of state transitions lives in
-- asset_scans, which is where every invocation is already recorded.
CREATE TABLE IF NOT EXISTS weirvern.scan_jobs
(
    job_id       UUID,
    asset_key    String,
    ip           String,
    requested_by LowCardinality(String) DEFAULT 'operator',
    requested_at DateTime64(3) DEFAULT now64(3),
    state        LowCardinality(String) DEFAULT 'queued',
    lease_owner  String DEFAULT '',
    lease_until  Nullable(DateTime64(3)),
    started_at   Nullable(DateTime64(3)),
    finished_at  Nullable(DateTime64(3)),
    result       String DEFAULT '',
    error        String DEFAULT ''
)
ENGINE = ReplacingMergeTree(requested_at)
ORDER BY job_id;
