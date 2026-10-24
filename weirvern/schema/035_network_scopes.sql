-- ── OPERATOR-DECLARED NETWORK SCOPES ────────────────────────────────────────────────
--
-- A per-host anomaly baseline needs a stable host population. NetFlow's src_addr is not
-- automatically such a host: it can be an internet peer, a scanner, or a VPN client that
-- spoke once. This table is the operator's declaration of what a network IS and whether its
-- hosts are eligible for per-host alerts.
--
-- THE LABEL IS NOT A PRIVATE-ADDRESS TEST. `internal`, `vpn`, `dmz` and `external` are
-- operator choices; an address outside every row is `unclassified`, which is a visible
-- configuration gap rather than an implicit answer. This is deliberate: an enterprise does
-- not have to teach the software its address plan, and a home deployment is not special-cased.
--
-- MONITORED AND POLICY ARE SEPARATE. `monitored` controls whether a host in the scope is
-- eligible for per-host baselines and alerting. `policy` describes how traffic is handled:
--   full      -- per-host features and alerts
--   aggregate -- observed in aggregate; not a per-host alert source
--   observe   -- recorded and visible, never alertable
--   off       -- ignored
-- A row with monitored=0 is never alertable regardless of policy.
--
-- OVERLAPS ARE ALLOWED. Resolution is longest-prefix-match; the most specific declaration wins
-- and ties are broken deterministically by id. The application validates CIDRs before writing;
-- an invalid stored row is skipped rather than turned into a silent "unclassified" claim.
CREATE TABLE IF NOT EXISTS weirvern.network_scopes
(
    id          String,
    cidr        String,
    label       LowCardinality(String),
    monitored   UInt8 DEFAULT 0,
    policy      LowCardinality(String) DEFAULT 'observe',
    description String DEFAULT '',
    source      LowCardinality(String) DEFAULT 'operator',
    -- Tombstone instead of an asynchronous DELETE mutation: one current row per id, and the
    -- prior declaration remains available until the merge/audit window is over.
    deleted     UInt8 DEFAULT 0,
    updated_at  DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY id;
