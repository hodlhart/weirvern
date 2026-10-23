-- 031_host_roles.sql
--
-- WHY THIS EXISTS: the detector scores an address, but "normal" depends on what the address IS.
-- The live window showed the gateway and the media services producing most local high/critical
-- rows on small changes; an internet peer has no baseline at all. Role and scope make that
-- context explicit and operator-correctable instead of leaving every host equal.
--
-- AUTO IS A PROPOSAL, NOT A CLAIM. `source='operator'` wins on read; an absent row is unknown,
-- never silently defaulted to workstation. `evidence` says which observation produced the role.

CREATE TABLE IF NOT EXISTS weirvern.host_roles
(
    host        String,
    role        LowCardinality(String),
    scope       LowCardinality(String),
    source      LowCardinality(String),
    confidence  Float64,
    evidence    String,
    updated_at  DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY host;
