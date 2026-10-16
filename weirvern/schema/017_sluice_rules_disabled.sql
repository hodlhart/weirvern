-- 017: DISABLED RULES (the operator, 2026-10-16: "rules needs a trashcan and a disable icon next
-- to each rule ... it also needs a bulk select with check boxes along the side for mass delete
-- or disable").
--
-- A THIRD STATE BESIDE LIVE AND REVOKED. Revoked is gone (the audit trail keeps the record);
-- expired is lapsed by the clock. DISABLED is deliberate and REVERSIBLE: the rule stays in the
-- list, stops being enforced immediately, records nothing, and can be switched back on. The
-- column defaults to NULL, so every existing rule is untouched and "NULL = not disabled" is the
-- one reading the store, the views and the enforcement query all share.
ALTER TABLE weirvern.sluice_rules
    ADD COLUMN IF NOT EXISTS disabled_at Nullable(DateTime64(3));
