-- 027_weirling_probe.sql
--
-- REMOTE CAPTURE-LIVENESS PROBE REQUESTS.
--
-- A remote unit is not in the hub's cluster, so the hub cannot exec into it. The hub queues a
-- bounded, read-only capture probe here; the sensor's authenticated agent claims it on its next
-- poll, measures its own NIC and Zeek log growth for the requested window, and posts the result.
-- The row is the durable handoff, so a GUI restart or a brief gateway outage does not lose it.
--
-- WHAT THIS IS NOT: an in-path test. No ARP is forged, no mode changes, no configuration is
-- written. A capture probe proves the port is alive and producing records; it cannot prove
-- forwarding or dropping, and the result must not claim those.
--
-- `observed = false` is a valid, successful measurement (a silent mirror/segment). `error` is
-- only for a probe that could not run (missing interface, unreadable counter, timeout).

CREATE TABLE IF NOT EXISTS weirvern.weirling_probe_requests
(
    request_id    String,
    sensor_id     LowCardinality(String),
    iface         String,
    seconds       UInt16 DEFAULT 30,
    status        LowCardinality(String) DEFAULT 'pending',
    result        String DEFAULT '',
    error         String DEFAULT '',
    requested_at  DateTime DEFAULT now(),
    updated_at    DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY (request_id)
TTL requested_at + INTERVAL 1 DAY;
