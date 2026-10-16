-- 018: blocklist sources and their domains (2026-10-16)
--
-- WHAT THIS IS FOR. The operator: "can we use https://github.com/hagezi/dns-blocklists or
-- custom lists or custom domains?" A source is a URL plus a format; its domains land in one
-- table that three readers share: the DNS-hit pass (record when a client asks for a listed
-- name -- alert-first, nothing is blocked by importing a list), the future block path (a
-- listed name's resolved addresses, through the same reverse cache domain rules use), and the
-- GUI (what was imported, when, and whether the last fetch failed).
--
-- WHY SOURCES ARE ROWS AND NOT CONFIG: a fetch can fail, a list can go stale, and the
-- difference between "no domains" and "the last sync failed" must be visible rather than a
-- quiet empty list. `last_error` and `fetched_at` are the two fields that carry that.
--
-- Idempotent: CREATE TABLE IF NOT EXISTS.

CREATE TABLE IF NOT EXISTS weirvern.blocklist_sources
(
    source_id    String,
    name         String,
    url          String,
    -- hosts | domains | dnsmasq | wildcard | custom. Parsing is format-specific; a wrong format
    -- imports nothing and says so, rather than importing garbage.
    format       LowCardinality(String),
    enabled      UInt8 DEFAULT 1,
    added_at     DateTime,
    fetched_at   Nullable(DateTime),
    domain_count UInt64 DEFAULT 0,
    last_error   String DEFAULT ''
)
ENGINE = ReplacingMergeTree(fetched_at)
ORDER BY source_id;

CREATE TABLE IF NOT EXISTS weirvern.blocklist_domains
(
    domain    String,
    source_id String,
    added_at  DateTime
)
ENGINE = ReplacingMergeTree(added_at)
ORDER BY (domain, source_id);
