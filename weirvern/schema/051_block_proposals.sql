-- Proposed blocks: what an agent or a person asked to block, and what a person decided.
--
-- WHY THIS TABLE EXISTS. Blocking is the one action in this product that can take a network away.
-- An automated detector must be able to say "this host should be blocked, here is why" without being
-- able to make it so, and a person must be able to see the evidence and then click. Without a place
-- to put the PROPOSAL, the only options are an agent that blocks directly (unacceptable) or an agent
-- that cannot block at all (also unacceptable, and where the MCP server started: read-only).
--
-- THE SPLIT IS THE SAFETY PROPERTY, so it is enforced by the data model rather than by convention:
-- writing a row here changes nothing about enforcement. `status = 'applied'` means a person applied
-- it, and `rule_id` names the rule that resulted, so the trail from proposal to rule exists in one
-- row.
--
-- KEYED ON proposal_id WITH REPLACING, not an append log. The current status of a proposal is the
-- fact, and a decision replaces the row. An append-only decision history would be a different table
-- and is deliberately not pretended here; the fleet audit already records the block itself.
--
-- NOTHING IS BLOCKED BY A ROW IN THIS TABLE. That sentence is the whole reason it exists.
CREATE TABLE IF NOT EXISTS weirvern.block_proposals
(
    -- Minted at creation (proposals.new_proposal_id), never derived from the host: the same host may
    -- be proposed more than once, and a derived id would collapse two separate decisions.
    proposal_id    String,

    -- Who proposed it, as an actor class plus a name: 'agent:fathom' for the MCP server, the
    -- account username for a person using the rendered form. LowCardinality is wrong here -- the set
    -- grows with accounts -- so it is a plain String.
    proposed_by    String,

    -- WHAT would be blocked: a bare address or a domain, exactly as the operator would type it.
    -- Validated at write time by sluice.validate_domain / sluice.parse_cidr, because a proposal that
    -- cannot become a rule is worse than no proposal: it looks actionable and is not.
    host           String,

    -- Why. Required, free text, capped by the caller. An unexplained block proposal is not reviewable.
    reason         String,

    -- The evidence that prompted it: an anomaly window, a rule id, a URL, or the words "manual".
    -- Empty is allowed and distinct from missing, so a person who typed nothing reads as having
    -- cited nothing.
    evidence       String DEFAULT '',

    -- How long the resulting block should last, in minutes. 0 means indefinite, matching the rule
    -- schema's own convention (014_sluice_indefinite.sql).
    ttl_minutes    UInt32 DEFAULT 0,

    -- 'proposed' | 'applied' | 'dismissed'. LowCardinality: three values, and a fourth would be a
    -- deliberate schema change rather than something that appears at runtime.
    status         LowCardinality(String) DEFAULT 'proposed',

    -- The version column. DateTime64(3), not DateTime: a proposal and its decision can land inside
    -- the same second, and a tie leaves FINAL picking arbitrarily between them.
    proposed_at    DateTime64(3) DEFAULT now64(3),

    -- When and by whom it was decided. Nullable rather than a sentinel timestamp, because "not
    -- decided yet" and "decided at the epoch" must not be able to look alike.
    decided_at     Nullable(DateTime64(3)),
    decided_by     String DEFAULT '',

    -- Set when status becomes 'applied': the rule this proposal created. Empty otherwise. This is
    -- the join between "someone asked" and "something is now enforced".
    rule_id        String DEFAULT ''
)
ENGINE = ReplacingMergeTree(proposed_at)
ORDER BY proposal_id;

-- NO TTL, DELIBERATELY. Every other workflow table here expires, because a review of an anomaly has
-- no meaning once the anomaly is gone. A block proposal is the opposite: it is the record of a
-- decision to change what a network enforces, and the question "who asked for this, why, and did a
-- person agree" must still have an answer a year later. Deletion would be a retention policy
-- decision, not a default.
