
-- ── Tier 1 Zeek logs ─────────────────────────────────────────────────────────
--
-- WHY THESE FOUR AND NOT OTHERS. Zeek can write ~164 log types. Weirvern kept four
-- (conn, dns, ssl, notice) while Zeek was ALREADY writing http, files, ssh and weird
-- on every deployment -- the site policy loads known-hosts and known-services, so
-- those logs were produced and then silently discarded. Measured on the test cluster
-- over a few hours: 359 http, 324 files, 155 ssh, 78 weird records dropped.
--
-- Those four are not marginal. The detection side is a 4-model ensemble over NetFlow
-- AGGREGATES, which sees volume, fan-out and timing, and cannot see a URL, a filename,
-- an SSH auth result or a protocol anomaly. Without them "what did that host actually
-- request?" and "what files moved?" are unanswerable, and those are the first two
-- questions an analyst asks after an alert.
--
-- RETENTION IS ONE WINDOW, DELIBERATELY -- and it is DERIVED, not written here.
--
-- These tables used to keep 30 (http/files) and 90 (ssh/weird) days, per table, on the
-- argument that exposure and analytic value differ. They do differ, but the ripple layer
-- compares a host against its OWN trailing history at 1h/6h/24h/7d scales with a 30-window
-- minimum, so a table that keeps less than 35 days cannot answer the 24h scale no matter
-- what it contains. One window for every source is what makes a multi-scale baseline
-- possible at all -- and how long that window can be is decided by the disk.
--
-- SO THE TTL BELOW IS A BOOTSTRAP, NOT A POLICY. It is the 7-day floor: a brand-new database
-- has no ingest history to measure, and the floor is the safe direction. weirvern/retention.py
-- derives the real value from free disk and the observed ingest at startup and on every apply
-- (DATA_RETENTION_DAYS, default "auto"), and converges every table here with ALTER MODIFY TTL.
--
-- The privacy consequence is stated rather than hidden: a deployment that derives 35 days
-- keeps `zeek_http` five days LONGER than its old 30, and `zeek_ssh`/`zeek_weird` 55 days
-- SHORTER than their old 90. `zeek_files` is NOT governed by this control (it is not a
-- ripple source) and stays at its 30-day budget; so does every other Zeek log in 004/006.
--
-- LOWERING THE WINDOW IS DESTRUCTIVE: ClickHouse expires the older rows on the next merge.
-- See docs/runbooks/data-retention.md for the per-table contract.

CREATE TABLE IF NOT EXISTS zeek_http
(
    ts           DateTime,
    uid          String,
    src_addr     String,
    src_port     UInt16,
    dst_addr     String,
    dst_port     UInt16,
    method       LowCardinality(String),
    host         String,
    uri          String,
    referrer     String,
    user_agent   String,
    status_code  UInt16,
    resp_mime    LowCardinality(String),
    resp_bytes   UInt64,
    -- Derived at ingest, not by Zeek. A long URI or a high-entropy query string is the
    -- signature of data-in-URL exfiltration, and computing it here keeps that signal
    -- queryable without re-parsing URIs in every hunt.
    uri_len      UInt16,
    uri_entropy  Float32
)
ENGINE = ReplacingMergeTree()
PARTITION BY toYYYYMM(ts)
ORDER BY (ts, uid)
TTL ts + INTERVAL 7 DAY;

CREATE TABLE IF NOT EXISTS zeek_files
(
    ts          DateTime,
    uid         String,
    fuid        String,
    src_addr    String,
    dst_addr    String,
    -- Zeek's `source` is the protocol that carried the file (HTTP, SMTP, ...). Called
    -- `f_source` because a bare `source` column is ambiguous in queries.
    f_source    LowCardinality(String),
    filename    String,
    mime_type   LowCardinality(String),
    -- sha256 is kept because it is the only field here that can be matched against a
    -- threat-intel feed WITHOUT exposing the filename: the hash is safe to share and
    -- compare, the filename is not.
    sha256      String,
    md5         String,
    seen_bytes  UInt64,
    total_bytes UInt64,
    missing     UInt64
)
ENGINE = ReplacingMergeTree()
PARTITION BY toYYYYMM(ts)
ORDER BY (ts, uid)
TTL ts + INTERVAL 30 DAY;

CREATE TABLE IF NOT EXISTS zeek_ssh
(
    ts            DateTime,
    uid           String,
    src_addr      String,
    src_port      UInt16,
    dst_addr      String,
    dst_port      UInt16,
    -- The SSH PROTOCOL number (2 in practice, for every row measured). NOT a software banner:
    -- Zeek puts those in `client`/`server` below. Kept as UInt8 because that is what Zeek
    -- declares; a feature must not compare it to a string, which is a type error at query time.
    version       UInt8,
    auth_success  UInt8,
    auth_attempts UInt64,
    -- NOTE: `direction` is declared by Zeek in ssh.log's #fields list and is left UNSET in
    -- practice -- measured: 188 of 188 rows empty on the live sensor. The column is kept
    -- because it costs nothing and a future Zeek version may populate it, but NO FEATURE may
    -- depend on it; the SSH features use auth_attempts/auth_success and the protocol version.
    --
    -- `direction` was intended to distinguish an inbound attempt (someone attacking us) from an
    -- outbound one (a host of ours trying to log in elsewhere), which is the
    -- difference between a perimeter problem and a compromised internal host.
    direction     LowCardinality(String),
    client        String,
    server        String
)
ENGINE = ReplacingMergeTree()
PARTITION BY toYYYYMM(ts)
ORDER BY (ts, uid)
TTL ts + INTERVAL 7 DAY;

CREATE TABLE IF NOT EXISTS zeek_weird
(
    ts        DateTime,
    uid       String,
    src_addr  String,
    src_port  UInt16,
    dst_addr  String,
    dst_port  UInt16,
    name      LowCardinality(String),
    -- Zeek's own `notice` flag: whether this weird also raised a Notice. Splitting the
    -- two lets a hunt separate "the protocol did something odd" from "Zeek considered
    -- it worth alerting on", which are very different volumes.
    noticed   UInt8,
    peer      LowCardinality(String)
)
ENGINE = ReplacingMergeTree()
PARTITION BY toYYYYMM(ts)
ORDER BY (ts, uid)
TTL ts + INTERVAL 7 DAY;
