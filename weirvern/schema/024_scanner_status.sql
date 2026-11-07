-- 024_scanner_status.sql
--
-- SCANNER READINESS, REPORTED BY THE SCANNER ITSELF. A node can inventory passively without
-- Nmap, but it cannot do the deeper service/NSE identity. The UI must be able to tell the
-- difference instead of rendering a basic node as a fully capable one.
--
-- profile is 'nmap' or 'basic'. nmap_version is the measured `nmap --version` line, never a
-- configured expectation. os_id/os_version let the setup sheet show the right package command
-- for this node; the hub never executes it.
CREATE TABLE IF NOT EXISTS weirvern.scanner_status
(
    sensor_id       LowCardinality(String),
    profile         LowCardinality(String) DEFAULT 'basic',
    nmap_available  UInt8 DEFAULT 0,
    nmap_version    String DEFAULT '',
    nmap_path       String DEFAULT '',
    nse_available   UInt8 DEFAULT 0,
    os_id           LowCardinality(String) DEFAULT '',
    os_version      String DEFAULT '',
    detail          String DEFAULT '',
    last_check      DateTime64(3) DEFAULT now64(3)
)
ENGINE = ReplacingMergeTree(last_check)
ORDER BY sensor_id;
