-- 022_weirling_sonar.sql
--
-- REMOTE SONAR REQUESTS.
--
-- The hub cannot create a Job on a weirling outside its cluster. Instead the hub
-- queues one survey request per sensor here; the sensor's authenticated agent claims
-- it on its next poll, runs sonar.survey() on its own capture interface, and posts the
-- measured result back. The row is the durable handoff, so a GUI restart or a brief
-- gateway outage does not lose the request.
--
-- `result` is the same JSON object the local survey returns. `error` carries a
-- refusal from the sensor (missing capability, unknown interface) separately from a
-- timeout, which is reported by the hub without inventing a result.
--
-- TTL keeps abandoned requests from being claimed hours later; a survey is an
-- operator-actionable measurement, not a background job.

CREATE TABLE IF NOT EXISTS weirvern.weirling_sonar_requests
(
    request_id    String,
    sensor_id     LowCardinality(String),
    iface         String,
    mgmt_iface    String DEFAULT '',
    status        LowCardinality(String) DEFAULT 'pending',
    result        String DEFAULT '',
    error         String DEFAULT '',
    requested_at  DateTime DEFAULT now(),
    updated_at    DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY (request_id)
TTL requested_at + INTERVAL 1 DAY;
