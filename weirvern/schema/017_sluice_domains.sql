-- 017: domain rules, and the events they record (2026-10-16)
--
-- WHY A DOMAIN NEEDS ITS OWN PREDICATE. The kernel matches addresses, not names -- so a domain
-- rule is resolved through the reverse map (schema/016: which names have pointed at which
-- addresses, from what DNS actually answered) into the addresses the name currently owns, and
-- THOSE are what the gate enforces. The cache is what keeps this bounded and honest: it holds
-- only recent answers, so a domain rule blocks what the name resolves to NOW, not what it
-- resolved to last week.
--
-- MODE, because alert-first is the ask: `alert` records hits (kind='dns' events, below) and
-- blocks nothing; `block` additionally installs the resolved addresses at the gate. The default
-- is `block` -- a rule is a decision, and the form asks which -- while the LIST-driven future
-- path can choose alert for everything it imports without touching this schema.
--
-- Idempotent: ADD COLUMN IF NOT EXISTS.

ALTER TABLE weirvern.sluice_rules
    ADD COLUMN IF NOT EXISTS domain String DEFAULT '' AFTER dst_cidr;

ALTER TABLE weirvern.sluice_rules
    ADD COLUMN IF NOT EXISTS mode LowCardinality(String) DEFAULT 'block' AFTER domain;

-- The DNS hits: which rule, which name was asked for, by whom. `kind` separates these from the
-- flow-shaped block events the gate writes today ('flow'), so old readers keep working.
ALTER TABLE weirvern.sluice_events
    ADD COLUMN IF NOT EXISTS kind LowCardinality(String) DEFAULT '' AFTER ts;

ALTER TABLE weirvern.sluice_events
    ADD COLUMN IF NOT EXISTS domain String DEFAULT '' AFTER kind;

ALTER TABLE weirvern.sluice_events
    ADD COLUMN IF NOT EXISTS query String DEFAULT '' AFTER domain;
