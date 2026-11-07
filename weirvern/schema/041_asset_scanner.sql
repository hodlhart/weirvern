-- 041_asset_scanner.sql
--
-- THE ACTIVE INVENTORY LAYER. The Assets view has always been built from traffic Weirvern
-- already saw; that is excellent for discovery but it cannot say whether a host is patched,
-- which service version is exposed, or what a new device is. Nmap and Nuclei fill only that
-- gap: Nmap names the services, Nuclei checks the specific templates that match them.
--
-- THE REGISTRY IS KEYED BY A STABLE-AS-POSSIBLE IDENTITY, NOT JUST AN ADDRESS. A DHCP lease
-- moves; a finding attached to "198.51.100.50" then points at a different machine. The scanner
-- prefers a MAC-derived key when Nmap or DHCP gives one and falls back to ip:<address> only
-- when no hardware identity is available. The address is still stored because every passive
-- source in this repository speaks in addresses.
--
-- SCAN STATE IS A SMALL CLOSED SET: pending -> scanning -> done | error. 'known' means the
-- scanner has seen the host but has not been asked to scan it (the safe first-run baseline).
-- A pending row is the durable queue: a scanner restart picks it up instead of forgetting it.
CREATE TABLE IF NOT EXISTS weirvern.asset_registry
(
    asset_key       String,
    ip              String,
    mac             String DEFAULT '',
    hostname        String DEFAULT '',
    first_seen      DateTime64(3) DEFAULT now64(3),
    last_seen       DateTime64(3) DEFAULT now64(3),
    scan_state      LowCardinality(String) DEFAULT 'pending',
    last_scan_at    DateTime64(3) DEFAULT toDateTime64(0, 3),
    scan_error      String DEFAULT '',
    source          LowCardinality(String) DEFAULT 'scanner'
)
ENGINE = ReplacingMergeTree(last_seen)
ORDER BY asset_key;

-- One row per open service observed by Nmap. ReplacingMergeTree keeps the newest observation
-- for a (asset, port, protocol); a service that disappears is not deleted, because absence of
-- evidence is not evidence of absence and the scanner may simply have been unable to reach it.
CREATE TABLE IF NOT EXISTS weirvern.asset_services
(
    asset_key       String,
    ip              String,
    port            UInt16,
    protocol        LowCardinality(String) DEFAULT 'tcp',
    service         String DEFAULT '',
    product         String DEFAULT '',
    version         String DEFAULT '',
    cpe             String DEFAULT '',
    observed_at     DateTime64(3) DEFAULT now64(3)
)
ENGINE = ReplacingMergeTree(observed_at)
ORDER BY (asset_key, port, protocol);

-- One row per Nuclei match. finding_key is a hash of template + matched URL + matcher name:
-- the same template re-firing on the same endpoint updates last_seen rather than duplicating.
-- The CVE column is deliberately a string, not an array: one finding normally maps to one CVE,
-- and keeping the raw template id and matched-at makes the evidence readable when it is not.
CREATE TABLE IF NOT EXISTS weirvern.asset_findings
(
    asset_key       String,
    ip              String,
    scanner         LowCardinality(String) DEFAULT 'nuclei',
    finding_key     String,
    template_id     String DEFAULT '',
    name            String DEFAULT '',
    severity        LowCardinality(String) DEFAULT 'unknown',
    cve             String DEFAULT '',
    matched_at      String DEFAULT '',
    description     String DEFAULT '',
    remediation     String DEFAULT '',
    first_seen      DateTime64(3) DEFAULT now64(3),
    last_seen       DateTime64(3) DEFAULT now64(3)
)
ENGINE = ReplacingMergeTree(last_seen)
ORDER BY (asset_key, scanner, finding_key);

-- An append-only audit of every invocation, including the command line and the failure. A
-- scanner that silently stops scanning is indistinguishable from a network with no findings;
-- this table is how the UI and the operator can tell the difference.
CREATE TABLE IF NOT EXISTS weirvern.asset_scans
(
    scan_id         String,
    asset_key       String,
    ip              String,
    kind            LowCardinality(String),
    started_at      DateTime64(3) DEFAULT now64(3),
    finished_at     Nullable(DateTime64(3)),
    status          LowCardinality(String) DEFAULT 'running',
    error           String DEFAULT '',
    command         String DEFAULT ''
)
ENGINE = MergeTree
ORDER BY (started_at, scan_id);
