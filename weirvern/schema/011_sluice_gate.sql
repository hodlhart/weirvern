-- SLUICE GATE: operator-controlled traffic blocking, and the record of what was blocked.
--
-- A WEIR HOLDS WATER BACK; A SLUICE GATE DECIDES WHAT PASSES. That is the whole idea: Weirvern
-- already SEES everything, and this is the part that can stop it. The name is deliberate -- the
-- gate is a decision point an operator opens and closes, not a wall, and every decision it makes
-- is recorded here.
--
-- WHY THREE TABLES AND NOT ONE.
--
--   sluice_rules      the DECISIONS. What the operator (or a rule derived from a detection) asked
--                     to block, why, and until when. This is the intent, and it is authored.
--   sluice_events     what actually HAPPENED on the wire, one row per blocked flow or per counter
--                     flush. This is the effect, and it is measured.
--   sluice_state      the GATE ITSELF: is enforcement armed, on which interface, with which policy.
--
-- The split between intent and effect is the same reasoning as observations vs verdicts in
-- 010_host_identity.sql, and it matters more here: a rule that is in force but never matched
-- anything is a rule that is not working, and a blocked flow with no rule behind it is an
-- enforcement bug. One table could not show either.
--
-- THE THING THIS SCHEMA REFUSES TO DO: a block is always BOUNDED. `expires_at` is NOT NULL. There
-- is no such thing as a permanent rule created by this system, because the failure mode of an
-- unattended blocklist is a network that quietly stops working months later with nobody able to
-- say why. An operator who wants permanence must renew it, and the renewal is a decision they can
-- see. (`expires_at` in the far future is still a bound, and still shows up in the expiry view --
-- that is the point.)
--
-- NOTHING HERE IS A FIREWALL. This is not iptables-as-configuration-management: the gate lives in
-- kernel packet handling on the sensor, it is applied and removed by the sensor's own supervisor,
-- and if the supervisor stops the gate OPENS rather than staying shut. A security control that
-- fails closed on a monitoring appliance takes the network down with it; the operator asked for a
-- gate, not a wall. See weirvern/sluice.py for why, and for the count that proves the gate opened.

CREATE TABLE IF NOT EXISTS weirvern.sluice_rules
(
    -- Identity of the rule. A ULID-like sortable id so the GUI can page without an offset, and so
    -- two rules created in the same second still order stably.
    rule_id          String,
    created_at       DateTime,
    -- WHO asked. An operator's account name, or "detection" when a rule was derived from an ML
    -- verdict, or "installer" for a rule seeded at bring-up. Kept as text rather than a foreign
    -- key because the account store is a separate concern and a rule must survive an account
    -- being removed -- an unattributed block is worse than an unattributed comment.
    created_by       String,
    -- WHY, in the operator's own words. Required in practice: the GUI will not submit without it,
    -- because the question asked three weeks later is always "why is this blocked".
    reason           String,
    -- WHAT to match. A match is a set of optional, ANDed predicates. Empty string means "this
    -- predicate does not apply", which is why they are not Nullable: an empty string sorts and
    -- compares simply, and `coalesce`-style branching in the hot path is what makes a filter
    -- slow. See sluice.match_rule for the exact semantics.
    --
    -- Addresses may be a single address or a CIDR. Kept as String rather than IPv4/IPv6 typed
    -- columns because a rule can be either family and ClickHouse types are per-column; the
    -- enforcement layer parses once at load, not per packet.
    src_cidr         String,
    dst_cidr         String,
    -- Protocol and port. 0 means "any". A port rule requires a protocol; the GUI enforces that
    -- pairing rather than the database, so a half-specified rule fails with a sentence instead of
    -- silently matching everything.
    protocol         String,
    dst_port         UInt16,
    -- The direction, from the SENSOR's point of view: 'forward' is traffic it relays between two
    -- hosts (the siphon case), 'in' is traffic destined for the sensor itself. Kept explicit so a
    -- rule that was meant for relayed traffic cannot silently block the operator's own SSH.
    direction        String,
    -- THE BOUND. Never null; see the header. A rule whose expiry has passed is inert at
    -- enforcement time even before the reaper tidies it up, so a failed cleanup can never leave a
    -- live rule behind.
    expires_at       DateTime,
    -- Manual rules are enforced as written. Derived rules (from detections) carry their confidence
    -- and can be auto-revoked when the detection that justified them ages out.
    origin           String,
    -- For a derived rule: the detection that created it, so the GUI can show the evidence beside
    -- the block and an analyst can disagree with it.
    origin_ref       String,
    -- Severity of the underlying detection at creation time. Used by the criticality policy: a
    -- rule derived from a high-severity verdict is enforced more aggressively than one derived
    -- from a medium.
    severity         String,
    -- Soft delete. A revoked rule stays readable so the record of what was blocked and why is not
    -- destroyed by the act of unblocking it -- the audit trail an incident review needs.
    revoked_at       Nullable(DateTime),
    revoked_by       String,
    -- The operator who owns the decision, for the "who do I ask about this" question.
    note             String
)
ENGINE = ReplacingMergeTree(created_at)
ORDER BY (rule_id)
TTL toDateTime(created_at) + INTERVAL 400 DAY;


CREATE TABLE IF NOT EXISTS weirvern.sluice_events
(
    -- When the sensor observed the block. Second granularity: a per-packet row would be a denial
    -- of service on the database, and a counter flush is what the enforcement layer actually has.
    ts               DateTime,
    rule_id          String,
    -- The 5-tuple, as the sensor saw it. Kept per flow rather than pre-aggregated so an analyst
    -- can answer "was MY host blocked" without a second query.
    src_addr         String,
    dst_addr         String,
    src_port         UInt16,
    dst_port         UInt16,
    protocol         String,
    -- How many packets and bytes this rule stopped in the window. A block that fires once and
    -- never again is usually a scanner that moved on, not a success.
    packets          UInt64,
    bytes            UInt64,
    -- WHAT the rule was, copied at enforcement time. A rule can be edited or revoked, and the
    -- event must still say what was actually in force when it fired -- otherwise the history is
    -- rewritten by every later edit.
    rule_snapshot    String,
    direction        String
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(ts)
ORDER BY (ts, rule_id)
TTL toDateTime(ts) + INTERVAL 90 DAY;


-- The gate's own state: one row per sensor, so the GUI can answer "is blocking ARMED, and where"
-- without inferring it from the absence of events. A gate whose state must be inferred is a gate
-- nobody can trust.
CREATE TABLE IF NOT EXISTS weirvern.sluice_state
(
    sensor           String,
    updated_at       DateTime,
    -- 'armed' | 'disarmed' | 'degraded'. DEGRADED is the interesting one: the gate could not
    -- install its rules and has therefore OPENED, with the reason recorded. An operator must be
    -- able to see that the gate is not holding rather than assuming it is.
    state            String,
    -- The interface enforcement is attached to, and the interface that carries management. These
    -- are stored together and shown together because a gate armed on the management interface is
    -- the mistake that locks the operator out of their own appliance.
    iface            String,
    mgmt_iface       String,
    -- Counts, so the GUI can show throughput and refusals rather than only a state word.
    rules_active     UInt32,
    rules_total      UInt32,
    packets_blocked  UInt64,
    bytes_blocked    UInt64,
    -- Why the gate is degraded, or empty. The sentence the operator needs.
    detail           String,
    -- The enforcement backend that is actually in use, and whether it is the one that was asked
    -- for. A mismatch is the silent-failure case this column exists to expose.
    backend          String,
    backend_expected String
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY (sensor)
TTL toDateTime(updated_at) + INTERVAL 30 DAY;
