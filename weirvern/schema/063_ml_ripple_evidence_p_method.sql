-- 063_ml_ripple_evidence_p_method.sql
--
-- WHY THIS EXISTS: the ripple evidence layer used to have exactly one test -- the empirical
-- two-sided rank p -- whose floor is 1/(n+1). Only a baseline of 100+ windows can express a p
-- below the 0.01 family bar, so the 6h scale at 94 windows and the coarser scales were measured
-- and then refused. `ripple_tail.py` adds a fitted negative binomial for count channels; the
-- evidence row must say WHICH test produced its number, or a reader cannot tell a rank from a
-- model and the provenance the design promises is missing.
--
-- p_method is one of:
--   'empirical'    rank-based, n >= 100, no distributional assumption
--   'negbin'       fitted negative binomial tail, n < 100, over-dispersed baseline
--   'poisson'      fitted Poisson tail, n < 100, variance indistinguishable from the mean
--   'insufficient' no p-value exists (p_value is NaN): the baseline was degenerate or too short
--
-- p_detail carries the fit's parameters as text (mean, variance, dispersion index, size) or the
-- reason the fit was refused. It is empty for an empirical row.
--
-- DEFAULTS ARE HONEST FOR EXISTING ROWS. Every row written before this migration was produced by
-- the empirical test, so DEFAULT 'empirical' labels history correctly rather than leaving it
-- ambiguous. ADD COLUMN IF NOT EXISTS makes the migration idempotent, and ClickHouse does not
-- rewrite existing parts for a column with a constant default.
ALTER TABLE weirvern.ml_ripple_evidence
    ADD COLUMN IF NOT EXISTS p_method LowCardinality(String) DEFAULT 'empirical' AFTER p_value,
    ADD COLUMN IF NOT EXISTS p_detail String DEFAULT '' AFTER p_method;
