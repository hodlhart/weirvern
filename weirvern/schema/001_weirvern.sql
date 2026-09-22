-- Weirvern schema (v0.1) — idempotent, named DB, TTLs retained.
-- Design notes vs legacy experiment:
--   * all tables live in the `weirvern` database (was: default)
--   * every object is CREATE ... IF NOT EXISTS
--   * raw flow TTL 3 days, aggregates 7 days, alert_events 30 days
--   * alert_events is new: every Pushover send is recorded (audit + tests)

CREATE TABLE IF NOT EXISTS flows
(
    timestamp        DateTime64(3),
    sampler_address  String,
    time_flow_start  DateTime64(3),
    time_flow_end    DateTime64(3),
    src_addr         String,
    dst_addr         String,
    src_port         UInt16,
    dst_port         UInt16,
    proto            UInt8,
    etype            UInt16,
    bytes            UInt64,
    packets          UInt64,
    tcp_flags        UInt8,
    sampling_rate    UInt32,
    src_as           UInt32,
    dst_as           UInt32,
    src_vlan         UInt16,
    dst_vlan         UInt16,
    in_if            UInt32,
    out_if           UInt32,
    next_hop         String,
    ip_tos           UInt8,
    ip_ttl           UInt8,
    frag_offset      UInt16
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, src_addr)
TTL toDateTime(timestamp) + INTERVAL 3 DAY;

-- Host-level 5-minute aggregates for ML (src_addr only — per-connection
-- rows carry no direction in this schema, matching the legacy design).
CREATE TABLE IF NOT EXISTS flows_aggregated
(
    window_start     DateTime,
    window_end       DateTime,
    src_addr         String,
    flow_count       UInt64,
    total_bytes      UInt64,
    total_packets    UInt64,
    avg_bytes        Float64,
    avg_packets      Float64,
    unique_dst_ips   UInt64
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(window_start)
ORDER BY (window_start, src_addr)
TTL window_start + INTERVAL 7 DAY;

CREATE MATERIALIZED VIEW IF NOT EXISTS flows_aggregated_mv
TO weirvern.flows_aggregated
AS
SELECT
    toStartOfFiveMinute(time_flow_start) AS window_start,
    window_start + INTERVAL 5 MINUTE AS window_end,
    src_addr,
    count() AS flow_count,
    sum(bytes) AS total_bytes,
    sum(packets) AS total_packets,
    avg(bytes) AS avg_bytes,
    avg(packets) AS avg_packets,
    uniq(dst_addr) AS unique_dst_ips
FROM weirvern.flows
GROUP BY window_start, window_end, src_addr;

-- Connection-diversity metrics (port scans, lateral movement)
CREATE TABLE IF NOT EXISTS flows_aggregated_diversity
(
    window_start       DateTime,
    src_addr           String,
    unique_dst_ports   UInt64,
    unique_dst_addrs   UInt64,
    unique_connections UInt64,
    port_entropy       Float64,
    bytes_stddev       Float64,
    packets_stddev     Float64,
    min_bytes          UInt64,
    max_bytes          UInt64,
    p50_bytes          Float64,
    p95_bytes          Float64,
    active_minutes     UInt8
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(window_start)
ORDER BY (window_start, src_addr)
TTL window_start + INTERVAL 7 DAY;

CREATE MATERIALIZED VIEW IF NOT EXISTS flows_aggregated_diversity_mv
TO weirvern.flows_aggregated_diversity
AS
SELECT
    toStartOfFiveMinute(time_flow_start) AS window_start,
    src_addr,
    uniq(dst_port) AS unique_dst_ports,
    uniq(dst_addr) AS unique_dst_addrs,
    uniqExact(dst_addr, dst_port) AS unique_connections,
    entropy(dst_port) AS port_entropy,
    stddevPop(bytes) AS bytes_stddev,
    stddevPop(packets) AS packets_stddev,
    min(bytes) AS min_bytes,
    max(bytes) AS max_bytes,
    quantile(0.5)(bytes) AS p50_bytes,
    quantile(0.95)(bytes) AS p95_bytes,
    count(DISTINCT toStartOfMinute(time_flow_start)) AS active_minutes
FROM weirvern.flows
WHERE dst_port > 0
GROUP BY window_start, src_addr;

-- Temporal pattern metrics (C2 beaconing: low activity_regularity)
CREATE TABLE IF NOT EXISTS flows_aggregated_temporal
(
    window_start        DateTime,
    src_addr            String,
    minute_activity     Array(UInt32),
    activity_regularity Float64,
    burstiness          Float64,
    inter_flow_avg      Float64,
    inter_flow_stddev   Float64
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(window_start)
ORDER BY (window_start, src_addr)
TTL window_start + INTERVAL 7 DAY;

CREATE MATERIALIZED VIEW IF NOT EXISTS flows_aggregated_temporal_mv
TO weirvern.flows_aggregated_temporal
AS
SELECT
    window_start,
    src_addr,
    groupArray(cnt) AS minute_activity,
    if(avg(cnt) > 0, stddevPop(cnt) / avg(cnt), 0) AS activity_regularity,
    if(avg(cnt) > 0, max(cnt) / avg(cnt), 1) AS burstiness,
    0 AS inter_flow_avg,
    0 AS inter_flow_stddev
FROM (
    SELECT
        toStartOfFiveMinute(time_flow_start) AS window_start,
        src_addr,
        toStartOfMinute(time_flow_start) AS minute,
        count() AS cnt
    FROM weirvern.flows
    GROUP BY window_start, src_addr, minute
)
GROUP BY window_start, src_addr;

-- Detection results (explainable ensemble output).
-- ReplacingMergeTree keyed on (window_start, src_addr) so overlapping sweeps
-- re-inserting the same host-window collapse instead of accumulating duplicate
-- rows (measured: consecutive sweeps over an overlapping window produced
-- duplicate (window_start, src_addr) groups, inflating counts/dashboards even
-- though the per-source alert cooldown suppressed the duplicate push).
CREATE TABLE IF NOT EXISTS netflow_anomalies
(
    detected_at               DateTime64(3),
    window_start              DateTime64(3),
    window_end                DateTime64(3),
    src_addr                  String,
    anomaly_score             Float64,
    confidence                Float64,
    isolation_forest_score    Float64,
    gradient_boosting_score   Float64,
    dbscan_score              Float64,
    baseline_score            Float64,
    model_agreement           Float64,
    primary_deviation_feature String,
    primary_deviation_zscore  Float64,
    deviation_magnitude       Float64,
    feature_contributions     String,
    baseline_comparison       String,
    detected_by_models        String,
    severity                  LowCardinality(String),
    -- ATT&CK techniques supported by this window's measurements, as JSON: a list of
    -- {id, name, tactic, confidence, evidence, network_visibility}. Empty array when nothing
    -- matched, which is the common case.
    --
    -- STORED, NOT COMPUTED AT READ TIME, and that is a deliberate choice. The mapping is a
    -- judgement about a window of traffic; recomputing it in the GUI would let a display
    -- change history, and an analyst comparing an alert from last week against today's screen
    -- needs the two to agree. It also means a later change to the thresholds does not rewrite
    -- what the system said at the time -- the alert that was sent stays the alert that was
    -- sent.
    attack_techniques         String DEFAULT '[]',
    -- The compact label for list views: "T1046 (high), T1018 (medium)". Denormalised on
    -- purpose: the list renders 100 rows, and parsing 100 JSON blobs to build a table cell
    -- would be work the database can do once at write time.
    attack_label              String DEFAULT ''
)
ENGINE = ReplacingMergeTree(detected_at)
PARTITION BY toYYYYMM(detected_at)
ORDER BY (window_start, src_addr)
TTL toDateTime(detected_at) + INTERVAL 30 DAY;

-- Model registry: every training run writes its metadata here
CREATE TABLE IF NOT EXISTS ml_models
(
    model_id                  String,
    model_type                String,
    trained_at                DateTime DEFAULT now(),
    training_duration_seconds UInt32,
    feature_columns           Array(String),
    model_params              String,
    metrics                   String,
    training_window_start     DateTime,
    training_window_end       DateTime,
    training_sample_count     UInt32,
    current_weight            Float64 DEFAULT 1.0
)
ENGINE = MergeTree()
ORDER BY (trained_at, model_id);

-- Per-host baselines (percentile-driven scoring)
CREATE TABLE IF NOT EXISTS baseline_history
(
    computed_at       DateTime DEFAULT now(),
    src_addr          String,
    avg_bytes         Float64,
    stddev_bytes      Float64,
    avg_packets       Float64,
    stddev_packets    Float64,
    avg_unique_dsts   Float64,
    stddev_unique_dsts Float64,
    sample_count      UInt64,
    window_hours      UInt32 DEFAULT 72,
    p95_bytes         Float64,
    p99_bytes         Float64,
    p999_bytes        Float64,
    p95_packets       Float64,
    p99_packets       Float64,
    p999_packets      Float64
)
ENGINE = ReplacingMergeTree(computed_at)
PARTITION BY toYYYYMM(computed_at)
ORDER BY (src_addr, computed_at)
TTL computed_at + INTERVAL 30 DAY;

-- Alert audit trail (Pushover sends + suppressed sends)
CREATE TABLE IF NOT EXISTS alert_events
(
    sent_at      DateTime64(3),
    src_addr     String,
    window_start DateTime,
    severity     LowCardinality(String),
    score        Float64,
    message      String,
    sent         UInt8,          -- 1 = delivered to Pushover, 0 = suppressed/log-only
    reason       LowCardinality(String)  -- "cooldown" | "cap" | "log-only" | "sent"
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(sent_at)
ORDER BY (sent_at, src_addr)
TTL toDateTime(sent_at) + INTERVAL 30 DAY;

-- Schema version stamp
CREATE TABLE IF NOT EXISTS schema_versions
(
    applied_at DateTime DEFAULT now(),
    version    String
)
ENGINE = MergeTree()
ORDER BY applied_at;

-- =============================================================================
-- Zeek packet-level logs (second sensor).
-- NetFlow/sFlow describes volume and topology; Zeek describes protocol
-- behaviour. A DNS tunnel, a JA3-tagged C2 channel, or a slow scan that moves
-- almost no bytes are invisible in flow records but explicit in these tables.
-- ReplacingMergeTree keyed on (ts, uid) so re-ingesting a rotated log line
-- (tailer restart) collapses instead of duplicating.
-- =============================================================================

CREATE TABLE IF NOT EXISTS zeek_conn
(
    ts         DateTime,
    uid        String,
    src_addr   String,
    src_port   UInt16,
    dst_addr   String,
    dst_port   UInt16,
    proto      LowCardinality(String),
    service    LowCardinality(String),
    duration   Float64,
    orig_bytes UInt64,
    resp_bytes UInt64,
    orig_pkts  UInt64,
    resp_pkts  UInt64,
    conn_state LowCardinality(String),
    history    String
)
ENGINE = ReplacingMergeTree()
PARTITION BY toYYYYMM(ts)
ORDER BY (ts, uid)
TTL ts + INTERVAL 7 DAY;

CREATE TABLE IF NOT EXISTS zeek_dns
(
    ts            DateTime,
    uid           String,
    src_addr      String,
    dst_addr      String,
    proto         LowCardinality(String),
    trans_id      UInt32,
    query         String,
    qtype         UInt16,
    rcode         UInt8,
    answers       String,
    query_len     UInt16,
    query_entropy Float64
)
ENGINE = ReplacingMergeTree()
PARTITION BY toYYYYMM(ts)
ORDER BY (ts, uid)
TTL ts + INTERVAL 7 DAY;

CREATE TABLE IF NOT EXISTS zeek_ssl
(
    ts                DateTime,
    uid               String,
    src_addr          String,
    dst_addr          String,
    dst_port          UInt16,
    version           LowCardinality(String),
    cipher            String,
    server_name       String,
    -- JA4: TLS ClientHello fingerprint, emitted by the module vendored at
    -- zeek/vendor/ja4-zeek-scripts and COPYed into the sensor image at build time.
    --
    -- These replace ja3/ja3s, which were DEAD COLUMNS: Zeek 9.x core ships no ja3
    -- policy at all (verified by grepping the entire installed script tree), so the
    -- fields never appeared in ssl.log and the columns could never populate. JA3 was
    -- removed from core Zeek and now lives only in a third-party package; JA4 is the
    -- successor and is what the vendored module emits.
    --
    -- ja4 covers the TLS ClientHello, so it identifies the CLIENT software even when
    -- the payload is encrypted -- which is the whole point of fingerprinting TLS.
    ja4               String,
    -- ja4_orig is the same fingerprint computed with the client-offered ordering kept.
    ja4_orig          String,
    validation_status LowCardinality(String),
    established       UInt8
)
ENGINE = ReplacingMergeTree()
PARTITION BY toYYYYMM(ts)
ORDER BY (ts, uid)
TTL ts + INTERVAL 7 DAY;

-- Zeek's own curated detections (scan detection etc.) as an independent
-- signal that corroborates the ML ensemble. Not an alert source by itself.
CREATE TABLE IF NOT EXISTS zeek_notice
(
    ts           DateTime,
    uid          String,
    src_addr     String,
    dst_addr     String,
    note         LowCardinality(String),
    msg          String,
    sub          String,
    peer_descr   String,
    actions      String,
    suppress_for Float64
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(ts)
ORDER BY (ts, src_addr)
TTL ts + INTERVAL 30 DAY;

-- Packet-level corroboration for the anomaly record: per-host, per-5-minute
-- view across the Zeek logs. A VIEW (not a materialized table) because it joins
-- three independently-arriving log types; a materialized view would need three
-- feeds writing into one row and would be wrong whenever one lags.
CREATE VIEW IF NOT EXISTS zeek_host_activity AS
WITH
    c AS (
        SELECT toStartOfFiveMinute(ts) AS window_start, src_addr,
               count() AS conns,
               uniqExact(dst_addr) AS dst_hosts,
               uniqExact(dst_port) AS dst_ports,
               sum(orig_bytes + resp_bytes) AS total_bytes
        FROM weirvern.zeek_conn
        GROUP BY window_start, src_addr
    ),
    d AS (
        SELECT toStartOfFiveMinute(ts) AS window_start, src_addr,
               count() AS dns_queries,
               max(query_entropy) AS max_query_entropy,
               avg(query_len) AS mean_query_len,
               uniqExact(query) AS distinct_queries
        FROM weirvern.zeek_dns
        GROUP BY window_start, src_addr
    ),
    s AS (
        SELECT toStartOfFiveMinute(ts) AS window_start, src_addr,
               count() AS tls_sessions,
               uniqExact(ja4) AS distinct_ja4,
               uniqExact(server_name) AS distinct_sni
        FROM weirvern.zeek_ssl
        GROUP BY window_start, src_addr
    ),
    n AS (
        SELECT toStartOfFiveMinute(ts) AS window_start, src_addr,
               count() AS notices,
               arrayStringConcat(groupUniqArray(note), ',') AS notice_types
        FROM weirvern.zeek_notice
        GROUP BY window_start, src_addr
    )
SELECT
    w.window_start AS window_start,
    w.src_addr AS src_addr,
    ifNull(c.conns, 0) AS conns,
    ifNull(c.dst_hosts, 0) AS dst_hosts,
    ifNull(c.dst_ports, 0) AS dst_ports,
    ifNull(c.total_bytes, 0) AS total_bytes,
    ifNull(d.dns_queries, 0) AS dns_queries,
    ifNull(d.max_query_entropy, 0.0) AS max_query_entropy,
    ifNull(d.mean_query_len, 0.0) AS mean_query_len,
    ifNull(d.distinct_queries, 0) AS distinct_queries,
    ifNull(s.tls_sessions, 0) AS tls_sessions,
    ifNull(s.distinct_ja4, 0) AS distinct_ja4,
    ifNull(s.distinct_sni, 0) AS distinct_sni,
    ifNull(n.notices, 0) AS notices,
    ifNull(n.notice_types, '') AS notice_types
FROM (
    SELECT window_start, src_addr FROM c
    UNION DISTINCT
    SELECT window_start, src_addr FROM d
    UNION DISTINCT
    SELECT window_start, src_addr FROM s
    UNION DISTINCT
    SELECT window_start, src_addr FROM n
) AS w
LEFT JOIN c ON w.window_start = c.window_start AND w.src_addr = c.src_addr
LEFT JOIN d ON w.window_start = d.window_start AND w.src_addr = d.src_addr
LEFT JOIN s ON w.window_start = s.window_start AND w.src_addr = s.src_addr
LEFT JOIN n ON w.window_start = n.window_start AND w.src_addr = n.src_addr;
