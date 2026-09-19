-- Tier 2 Zeek logs: the identity and lateral-movement set.
--
-- WHY THESE, AND WHY NOT MORE. Each table below exists because it answers a question no
-- log we already ingest can answer. That is the bar -- not "this protocol is interesting".
-- The current 8 logs (conn/dns/ssl/notice/http/files/ssh/weird) are flow and protocol
-- metadata; they can say a host talked to another host, and in most cases what port and
-- how much. They cannot say WHO authenticated, to WHAT share, or with WHICH directory
-- identity. That is the gap these fill:
--
--   kerberos    client -> service (SPN) with request_type. The ONLY source for
--               Kerberoasting / AS-REP roasting: an unusual SPN requested by an unusual
--               principal is invisible to conn.log.
--   dce_rpc     endpoint + operation + named_pipe. PsExec/WMI/service execution: the
--               canonical lateral-movement path, and it looks like ordinary SMB traffic
--               in conn.log.
--   smb_mapping the SHARE PATH (\\HOST\ADMIN$). conn.log reports service=smb and nothing
--               else, so admin-share access is currently invisible.
--   smb_files   file ACTION (READ/WRITE/DELETE/RENAME) with the path. Tool transfer, and
--               ransomware bursts, are action-level facts.
--   ntlm        username <-> hostname <-> domainname. A bipartite identity graph, which is
--               what pass-the-hash detection is built from.
--
-- FIELD NAMES ARE TAKEN FROM THE INSTALLED ZEEK SOURCE, not from documentation. Every
-- column below was read from the `&log` declarations in the Zeek 9.0.0 scripts on the live
-- sensor, because documentation and prose summaries disagree with each other and with the
-- shipped code. One concrete example, which would have been a silent bug: kerberos.log's
-- `error_code` is declared `&optional` WITHOUT `&log`, so it is NOT in the log at all --
-- only `error_msg` is. A schema built from a field list would have had a column that could
-- never populate, which is exactly the defect already found in zeek_ssl.ja3/ja3s.
--
-- PRIVACY: this set is a deliberate step change. `ntlm.username`, `kerberos.client` and
-- `smb_files.path` convert this corpus from "traffic telemetry" into "identifiable persons
-- and their files". That is the cost of the asset-identity analytics, and it is paid on
-- purpose.
--
-- RETENTION POLICY, stated accurately. An earlier version of this comment claimed these
-- tables "carry SHORTER retention than the flow tables", and that claim was FALSE: the flow
-- tables are 7 days (zeek_conn/dns/ssl) while these run 30-90, because the flow tables are
-- short for a VOLUME reason -- they are enormous -- and not for a privacy one. Comparing
-- against them would have justified 7 days here, which is shorter than a lateral-movement
-- campaign and would delete the evidence before the investigation that needs it.
--
-- The rule actually applied is a bound justified by the PII surface and the analytic window,
-- per table, shortest where the exposure is greatest:
--
--   zeek_smb_files    30d  verbatim paths AND filenames -- the highest exposure here, and
--                          the only one of the five that records WHAT was touched
--   zeek_smb_mapping  60d  share paths, which name hosts and departments
--   zeek_ntlm         60d  username <-> host <-> domain, the identity graph itself
--   zeek_kerberos     90d  principals and SPNs; campaigns are measured in weeks, so this is
--                          the shortest window that still answers the question it exists for
--   zeek_dce_rpc      90d  RPC metadata only: no username, no path, no payload. Nothing in
--                          this table identifies a person on its own.
--
-- Every table here is BOUNDED. An unbounded PII table is the failure mode that matters, and
-- tests/test_zeek_tier2.py asserts both the bound and the ordering above.

-- ── kerberos ───────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS weirvern.zeek_kerberos
(
    ts              DateTime,
    uid             String,
    src_addr        IPv4,
    dst_addr        IPv4,
    dst_port        UInt16,
    -- AS / TGS / AP. AS-REP roasting is a burst of AS requests for principals that do not
    -- require preauth; Kerberoasting is TGS requests naming many SPNs.
    request_type    LowCardinality(String),
    -- The directory identity. PII: a real username, not an IP.
    client          String,
    -- The ticket's service principal (e.g. HTTP/host, cifs/host).
    service         String,
    success         UInt8,
    -- NOTE: error_code is deliberately ABSENT. It is declared &optional but NOT &log in
    -- Zeek 9.0.0, so it never appears in kerberos.log. error_msg carries the same signal
    -- as text ("NEEDED_PREAUTH" etc.) and does appear.
    error_msg       String,
    ticket_from     DateTime,
    ticket_till     DateTime,
    cipher          LowCardinality(String),
    forwardable     UInt8,
    renewable       UInt8
)
ENGINE = MergeTree
PRIMARY KEY (ts, src_addr)
ORDER BY (ts, src_addr, client)
-- 90 days. Directory identities are the most useful correlation key we have for lateral
-- movement, and attack campaigns are measured in weeks; but this is PII, so it is bounded
-- well below the flow tables.
TTL ts + INTERVAL 90 DAY;

-- ── dce_rpc ────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS weirvern.zeek_dce_rpc
(
    ts              DateTime,
    uid             String,
    src_addr        IPv4,
    dst_addr        IPv4,
    dst_port        UInt16,
    rtt             Float64,
    -- No payload and no credentials: RPC metadata only, which is why this table can carry
    -- longer retention than the identity ones.
    named_pipe      String,
    -- The interface UUID, e.g. for SVCCTL (service control) or ATSVC (scheduler).
    endpoint        LowCardinality(String),
    -- The call, e.g. `CreateServiceW`, `NetShareEnum`.
    operation       LowCardinality(String)
)
ENGINE = MergeTree
PRIMARY KEY (ts, src_addr)
ORDER BY (ts, src_addr, endpoint, operation)
TTL ts + INTERVAL 90 DAY;

-- ── smb_mapping: the share path ────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS weirvern.zeek_smb_mapping
(
    ts              DateTime,
    uid             String,
    src_addr        IPv4,
    dst_addr        IPv4,
    -- The tree connect path, e.g. \\HOST\ADMIN$ or \\HOST\C$. Contains hostnames and
    -- sometimes usernames or departments, hence the shorter TTL.
    path            String,
    service         LowCardinality(String),
    native_file_system LowCardinality(String),
    share_type      LowCardinality(String)
)
ENGINE = MergeTree
PRIMARY KEY (ts, src_addr)
ORDER BY (ts, src_addr, path)
TTL ts + INTERVAL 60 DAY;

-- ── smb_files: action-level file semantics ─────────────────────────────────────
CREATE TABLE IF NOT EXISTS weirvern.zeek_smb_files
(
    ts              DateTime,
    uid             String,
    src_addr        IPv4,
    dst_addr        IPv4,
    fuid            String,
    -- FILE_READ/WRITE/OPEN/CLOSE/DELETE/RENAME/... Ransomware is a burst of RENAME and
    -- DELETE; tool transfer is a WRITE followed by a remote service start (dce_rpc).
    action          LowCardinality(String),
    -- Full path and basename logged VERBATIM by Zeek. The highest PII surface in this set,
    -- and the reason retention here is the shortest of the four.
    path            String,
    filename        String,
    size            UInt64,
    prev_name       String
)
ENGINE = MergeTree
PRIMARY KEY (ts, src_addr)
ORDER BY (ts, src_addr, action)
TTL ts + INTERVAL 30 DAY;

-- ── ntlm: the identity graph ───────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS weirvern.zeek_ntlm
(
    ts              DateTime,
    uid             String,
    src_addr        IPv4,
    dst_addr        IPv4,
    -- username + hostname + domainname together are what makes pass-the-hash detectable:
    -- one credential appearing against many hosts is the signature, and no single field
    -- shows it.
    username        String,
    hostname        String,
    domainname      String,
    success         UInt8
)
ENGINE = MergeTree
PRIMARY KEY (ts, src_addr)
ORDER BY (ts, src_addr, username, hostname)
TTL ts + INTERVAL 60 DAY;

-- ── the aggregation that makes these usable ────────────────────────────────────
--
-- One row per (day, principal, host): "who authenticated where, and how often". Hunting
-- pass-the-hash means scanning this for a username appearing on many distinct hosts inside
-- a short window, which over raw rows means a full scan of the table on every query.
CREATE TABLE IF NOT EXISTS weirvern.ntlm_identity_daily
(
    day             Date,
    username        String,
    hostname        String,
    domainname      String,
    auth_count      UInt64,
    distinct_src    UInt32
)
ENGINE = SummingMergeTree((auth_count))
ORDER BY (day, username, hostname)
TTL day + INTERVAL 180 DAY;

CREATE MATERIALIZED VIEW IF NOT EXISTS weirvern.ntlm_identity_daily_mv
TO weirvern.ntlm_identity_daily
AS SELECT
    toDate(ts)  AS day,
    username    AS username,
    hostname    AS hostname,
    domainname  AS domainname,
    count()     AS auth_count,
    uniqExact(src_addr) AS distinct_src
FROM weirvern.zeek_ntlm
WHERE success = 1
GROUP BY day, username, hostname, domainname;
