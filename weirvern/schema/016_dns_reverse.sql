-- 016: the reverse map -- which names have pointed at which addresses (2026-10-16)
--
-- WHY A TABLE AND NOT A QUERY. The operator's ask: "can we reverse lookup ips with a small
-- cache to also block traffic". The cache has to serve three readers at once -- the DNS view's
-- per-IP reveal, the worker's domain-rule checks, and (later) the gate's domain->IP expansion --
-- and each of them wants a cheap point lookup rather than an arrayJoin over the whole DNS table.
--
-- SMALL BY CONSTRUCTION: a materialized view off zeek_dns, so it only ever holds what DNS
-- actually answered -- no scan, no import, no list to keep fresh. ReplacingMergeTree keyed on
-- (ip, domain) keeps the LAST sighting per pair, and readers bound it by `last_seen` (the
-- cache window), so "small" is enforced at read time rather than by a cleanup job.
--
-- ANSWERS ARE MESSY AND THAT IS HANDLED HERE, ONCE: zeek writes a comma-joined list that mixes
-- addresses with NSEC/TXT mDNS chatter, so the view keeps only tokens that PARSE as an address
-- (isIPv4String/isIPv6String) and only for the qtypes whose answers are address-bearing.
-- Idempotent: CREATE ... IF NOT EXISTS.

CREATE TABLE IF NOT EXISTS weirvern.dns_reverse_map
(
    ip        String,
    domain    String,
    last_seen DateTime64(3)
)
ENGINE = ReplacingMergeTree(last_seen)
ORDER BY (ip, domain);

CREATE MATERIALIZED VIEW IF NOT EXISTS weirvern.dns_reverse_mv TO weirvern.dns_reverse_map AS
SELECT
    trim(BOTH ' ' FROM token) AS ip,
    lower(query)              AS domain,
    ts                        AS last_seen
FROM weirvern.zeek_dns
ARRAY JOIN splitByChar(',', answers) AS token
WHERE (isIPv4String(trim(BOTH ' ' FROM token)) OR isIPv6String(trim(BOTH ' ' FROM token)))
  AND query != ''
  AND qtype IN (1, 28, 12, 255, 5, 2, 15, 65)
