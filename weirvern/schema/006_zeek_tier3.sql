-- Tier 3 Zeek logs: identity attributes, encapsulation, and the TLS blind spot.
--
-- WHY THESE FIVE, AND WHY NOT THE OTHER SIXTY-ODD.
--
-- Two independent research passes (Scripts/zeek-log-research-threat-hunting.md and
-- zeek-log-research-ml.md) ranked every log Zeek 9.0.0 ships, from the v9.0.0 source tree rather
-- than from documentation. Both place these five in their top eight. Each answers a question no
-- log we already ingest can, which is the bar -- the same bar set in 004_zeek_identity.sql.
--
--   dhcp          THE ONLY LOG WITH L2 IDENTITY. It converts an IP in conn.log into a MAC and a
--                 hostname: the pivot that makes every other log attributable after a DHCP lease
--                 expires. It is also what lets a per-host baseline key on something stable --
--                 a MAC persists across leases, an IP does not, so a baseline keyed on IP loses
--                 its subject whenever the lease turns over. A rogue DHCP server is visible as a
--                 server_addr that is not yours.
--
--   x509          ALREADY WRITTEN BY THIS SENSOR AND PREVIOUSLY UNREAD. ssl.log carries
--                 fingerprints only -- cert_chain_fps is a vector of fingerprint strings -- so it
--                 structurally cannot say whether the certificate behind one is self-signed, a CA,
--                 expired, short-key, or carries a SAN that contradicts the SNI. Those properties
--                 exist nowhere else. Volume is bounded three times over: x509 deduplicates its own
--                 rows, the site policy logs host certificates only (suppressing CA chains), and
--                 log_x509_in_files_log is off.
--
--   tunnel        THE EXISTENCE OF A ROW IS THE FINDING. Zeek's own documentation says so: an
--                 unexpected tunnel.log entry is worth investigating in itself. conn.log carries
--                 `tunnel_parents`, which is a set of UIDs -- an identifier, not a fact about what
--                 the tunnel IS. The encapsulation type is only here. Near-zero volume, and both
--                 fields are bounded enums.
--
--   quic          CLOSES A TLS BLIND SPOT. QUIC is encrypted at the transport layer and never
--                 appears in ssl.log, so a host that moves its C2 to QUIC is simply invisible to
--                 the current corpus. This recovers the SNI (server_name) and the ALPN protocol,
--                 which is the categorical signal that makes it useful rather than merely present.
--
--   ldap_search   AD ENUMERATION IS DEFINED BY FILTER CONTENT, and nothing else exposes directory
--                 queries at all. result_count is a clean numeric outlier feature; the filter is a
--                 bounded structured string whose NOVELTY is the BloodHound-style enumeration
--                 signal. Zeek's default_capture_password is false, so bind arguments are redacted
--                 and no credential reaches this table.
--
-- DELIBERATELY NOT ADDED, with the reason recorded rather than left to be rediscovered:
--
--   signatures        Its sig_count/host_count are Zeek's own scan thresholds -- and we already
--                     derive the equivalent from raw flows in flows_aggregated_diversity. Adding
--                     it would store a second copy of a signal we compute.
--   pe                Ten clean booleans and genuinely dense, but only populated when an executable
--                     crosses the wire, which this deployment's files.log shows does not happen.
--                     A table that stays empty is the exact defect this project keeps finding.
--   unknown_protocols The purest unsupervised novelty signal available, and GATED behind an @load.
--                     Its first_bytes field is RAW PAYLOAD, which would break the standing
--                     invariant that no payload bytes are stored. Revisit with that field dropped.
--   smb_cmd           Ranked last by the hunting research despite rich fields: Zeek's own script
--                     header calls it "primarily useful for debugging", and it is high volume.
--   smtp, ftp, radius, rfb, ntp, snmp, irc   Protocol not present on this segment.
--
-- FIELD NAMES ARE FROM THE ZEEK 9.0.0 SOURCE TREE, not from docs.zeek.org: the current docs serve
-- the 9.1.0-dev branch, whose ssl.log and x509.log examples show OLDER names than 9.0.0 declares
-- (the examples use cert_chain_fuids and an `id` field, while 9.0.0 declares cert_chain_fps and
-- fingerprint). The research reports state this explicitly, and it is why every column below was
-- read from the record definitions rather than from a documentation example.
--
-- RETENTION follows the rule established in 004_zeek_identity.sql: every table BOUNDED, shortest
-- where the exposure is greatest. None of these take the detection tables' unified window, which
-- is a baseline requirement stated in weirvern/retention.py, and none are unbounded.

-- ── dhcp: L2 identity, the pivot for everything else ───────────────────────────
CREATE TABLE IF NOT EXISTS weirvern.zeek_dhcp
(
    ts              DateTime,
    -- Zeek logs `uids` as a SET: one DHCP transaction can span several connections, so this is
    -- a vector rather than a scalar. Kept as a joined string because ClickHouse makes set
    -- membership awkward to query and nothing needs the per-element identity.
    uids            String,
    -- The client. `client_addr` is 0.0.0.0 in a DISCOVER, which is expected and why it is not
    -- used as the row's key.
    client_addr     IPv4,
    -- A server_addr that is not your own is a rogue DHCP server. That is the whole detection.
    server_addr     IPv4,
    -- THE STABLE IDENTIFIER. A baseline keyed on IP loses its subject whenever the lease turns
    -- over; a MAC does not. This is the single most valuable column in the Tier 3 set.
    mac             String,
    host_name       String,
    client_fqdn     String,
    domain          String,
    requested_addr  IPv4,
    assigned_addr   IPv4,
    -- Seconds. Continuous, so usable as a feature directly.
    lease_time      Float64,
    -- DISCOVER/OFFER/REQUEST/ACK/NAK/RELEASE -- bounded enum.
    msg_types       String,
    duration        Float64
)
ENGINE = MergeTree
PRIMARY KEY (ts, mac)
ORDER BY (ts, mac)
-- 90 days. MAC and hostname are device-identifying rather than person-identifying, and the pivot
-- value decays: a lease record matters while the IP in conn.log could still belong to that
-- device. Longer than that and it is an inventory, not a lookup table.
TTL ts + INTERVAL 90 DAY;

-- ── x509: certificate properties ssl.log cannot express ────────────────────────
CREATE TABLE IF NOT EXISTS weirvern.zeek_x509
(
    ts              DateTime,
    -- THE JOIN KEY to ssl.log's cert_chain_fps. An identifier, never a feature.
    fingerprint     String,
    -- Flattened from the nested X509::Certificate record. The nesting is preserved in the log as
    -- certificate.subject etc.; flattening here keeps queries simple and the columns are all
    -- scalar.
    subject         String,
    issuer          String,
    -- `subject == issuer` is a self-signed certificate, which is the single highest-value derived
    -- feature here -- and it is a comparison between two columns, so both must be stored verbatim.
    common_name     String,
    not_valid_before DateTime,
    not_valid_after DateTime,
    -- key_length and sig_alg are what make "weak crypto" a MEASUREMENT rather than a guess.
    key_alg         LowCardinality(String),
    key_length      UInt32,
    sig_alg         LowCardinality(String),
    -- basic_constraints.ca: is this a CA certificate? A rogue CA in the corpus is a finding.
    is_ca           UInt8,
    -- The SAN list, joined. `server_name NOT IN san_dns` is the SNI/SAN mismatch check, and it
    -- needs the full list to be meaningful.
    san_dns         String,
    -- host_cert/client_cert from the record: whose certificate is this?
    host_cert       UInt8,
    client_cert     UInt8
)
ENGINE = MergeTree
PRIMARY KEY (ts, fingerprint)
ORDER BY (ts, fingerprint)
-- 60 days. Certificate subjects name organisations and internal hostnames, so this is more
-- identifiable than dhcp; but the inventory is genuinely useful across a quarter, and Zeek
-- deduplicates rows so volume is small.
TTL ts + INTERVAL 60 DAY;

-- ── tunnel: the presence of a row is the signal ────────────────────────────────
CREATE TABLE IF NOT EXISTS weirvern.zeek_tunnel
(
    ts              DateTime,
    uid             String,
    src_addr        IPv4,
    dst_addr        IPv4,
    -- Tunnel::IP, GRE, TEREDO, AYIYA, SOCKS, GTPv1, HTTP, VXLAN, GENEVE. A bounded enum, and
    -- the whole reason this log exists: conn.log has tunnel_parents (UIDs) and never the type.
    tunnel_type     LowCardinality(String),
    -- DISCOVER / CLOSE / EXPIRE.
    action          LowCardinality(String)
)
ENGINE = MergeTree
PRIMARY KEY (ts, src_addr)
ORDER BY (ts, src_addr, tunnel_type)
-- 90 days. No identifier and no payload -- only the fact that encapsulation occurred and its
-- kind -- so this can live as long as the identity tables without a privacy cost.
TTL ts + INTERVAL 90 DAY;

-- ── quic: the TLS blind spot ───────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS weirvern.zeek_quic
(
    ts              DateTime,
    uid             String,
    src_addr        IPv4,
    dst_addr        IPv4,
    dst_port        UInt16,
    -- The SNI. This is the feature that matters: QUIC never reaches ssl.log, so without this a
    -- host's QUIC destinations are unnamed.
    server_name     String,
    -- The ALPN protocol, e.g. h3. Categorical and bounded.
    client_protocol LowCardinality(String),
    version         LowCardinality(String)
)
ENGINE = MergeTree
PRIMARY KEY (ts, src_addr)
ORDER BY (ts, src_addr)
-- 30 days. server_name is a hostname and dst_addr is an address; together they are browsing
-- history. Bounded shorter than the certificate inventory for that reason.
TTL ts + INTERVAL 30 DAY;

-- ── ldap_search: directory enumeration ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS weirvern.zeek_ldap_search
(
    ts              DateTime,
    uid             String,
    src_addr        IPv4,
    dst_addr        IPv4,
    dst_port        UInt16,
    -- The search filter. A bounded, grammar-constrained string, and the enumeration signal is its
    -- NOVELTY -- a filter shape this host has never issued before.
    --
    -- NOTE: Zeek's default_capture_password is false, so bind arguments are redacted and no
    -- credential reaches this table. That is the default, not a configuration choice we made.
    ldap_filter     String,
    base_object     String,
    -- scope is base/one/sub; deref_aliases is never/search/find/always. Both bounded.
    scope           LowCardinality(String),
    deref_aliases   LowCardinality(String),
    -- A clean numeric outlier feature: a search returning 10,000 objects is enumeration.
    result_count    UInt32,
    result          LowCardinality(String)
)
ENGINE = MergeTree
PRIMARY KEY (ts, src_addr)
ORDER BY (ts, src_addr)
-- 30 days, the shortest in this file. `base_object` and `ldap_filter` name directory paths and
-- often usernames or groups -- the most directly identifying content in the Tier 3 set.
TTL ts + INTERVAL 30 DAY;
