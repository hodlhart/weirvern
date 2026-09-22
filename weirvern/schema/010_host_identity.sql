-- Passive host identification: what each host IS, and the evidence for it.
--
-- WHY THESE ARE TWO TABLES AND NOT ONE.
--
-- `host_fingerprints` holds OBSERVATIONS: one row per source per host per window, exactly as
-- the sensor saw it, with no interpretation. `host_identity` holds the VERDICT: one current row
-- per host, the combined answer and the confidence in it.
--
-- The split exists because fingerprints CHANGE and a verdict must be re-derivable. A laptop that
-- reconnects over a VPN presents a different TLS stack; a host that upgrades from Windows 10 to
-- 11 changes its User-Agent; a DHCP lease hands the same address to a different machine entirely.
-- If only the verdict were stored, none of that would be visible after the fact -- and the
-- question an analyst actually asks during an incident ("what did this host look like YESTERDAY?")
-- would be unanswerable.
--
-- Storing observations also makes the classifier CORRECTABLE. When an operator confirms a host's
-- real OS, the confirmation is added as a signal and the verdict recomputed from evidence that is
-- still on disk. A table that stored only conclusions could never be re-scored.

CREATE TABLE IF NOT EXISTS weirvern.host_fingerprints
(
    ts               DateTime,
    -- The host this observation is about. Kept as the address the traffic carried; the MAC is a
    -- separate column because a lease can move and an address can be reassigned.
    src_addr         String,
    -- The stable identifier where one is known. A baseline keyed on IP loses its subject the
    -- moment a lease turns over -- the same reasoning as zeek_dhcp.mac.
    mac              String,
    -- WHAT KIND OF EVIDENCE, and it is not decoration: it is the key the classifier weights by.
    --   software       an application banner (strongest: it names the distribution)
    --   dhcp_fqdn      the host's own statement of its FQDN
    --   dhcp_hostname  a bare hostname, which is whatever a person typed
    --   oui            the NIC vendor, which is the hypervisor on a VM
    --   ja4            a TLS ClientHello fingerprint, which identifies the stack
    --   ja4_structure  a decoded JA4 header (transport/version/cipher counts), not an OS claim
    --   operator       a human confirmation; outranks every inference
    source           LowCardinality(String),
    -- The raw observation, UNPARSED. This is the column that makes the table re-scorable: a
    -- better reference table can be run against these strings without re-ingesting anything.
    raw              String,
    -- What the reference tables made of it, if anything.
    os_guess         LowCardinality(String),
    os_label         String,
    confidence       LowCardinality(String),
    -- Human-readable reasoning. Not optional: a verdict whose evidence cannot be read is a
    -- verdict nobody can check, and an unchecked fingerprint is how a wrong one survives.
    detail           String,
    weight           Float32,
    -- Provenance for anything non-obvious, so a later reader can tell an inferred row from a
    -- confirmed one without reading the source.
    note             String
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(ts)
ORDER BY (ts, src_addr, source)
-- Fingerprint history is the point of this table, so it is kept far longer than raw flows.
-- 90 days is long enough to answer "what did this host look like during last month's incident".
TTL toDateTime(ts) + INTERVAL 90 DAY;


CREATE TABLE IF NOT EXISTS weirvern.host_identity
(
    -- ReplacingMergeTree: the verdict is CURRENT STATE, one row per host, and a re-score
    -- replaces its own row. `updated_at` is the version column so the newest wins.
    updated_at       DateTime,
    host             String,
    mac              String,
    os               LowCardinality(String),
    os_label         String,
    confidence       LowCardinality(String),
    score            Float32,
    -- How many independent SOURCES agreed, which is what confidence is actually derived from.
    -- Stored because "high" means nothing without it: two agreeing sources is a different claim
    -- from one source repeated three times.
    agreeing_sources UInt8,
    -- Everything that produced the verdict, as JSON: [{source, os_label, detail, weight}, ...].
    -- Denormalised on purpose, so reading the verdict never requires a join or a second query.
    signals          String,
    -- Signals that point somewhere OTHER than the verdict. Kept rather than discarded: a host
    -- whose banner says Ubuntu and whose hostname says DESKTOP- is either renamed or dual-boot,
    -- and that is a finding, not noise to be averaged away.
    disagreement     String,
    -- The decoded JA4 header, when the host made a TLS connection. Structural facts only.
    ja4_structure    String,
    -- The distinct raw values seen, for a GUI that wants to show the evidence behind a label.
    software_seen    String,
    hostnames_seen   String,
    ja4_seen         String
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY host
-- An identity that has not been re-derived in 90 days is stale rather than wrong, but it should
-- not be presented as current. The GUI reads freshness from updated_at; the TTL bounds the table.
TTL toDateTime(updated_at) + INTERVAL 90 DAY;
