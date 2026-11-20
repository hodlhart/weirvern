-- 060_ml_calibration_far_interval.sql
--
-- WHY THIS EXISTS: a calibration row stored a false-alarm RATE but not the sample it was measured
-- on, so the Detectors table could print "FAR 0.045 above the 0.030 tolerance" without saying that
-- 0.045 was five exceedances in 110 validation windows -- an interval of roughly 2%-10%. On
-- 2026-11-20 that reading benched three detectors, and the same detector had read 0.000 seven
-- minutes earlier. The rate is a binomial proportion; it is not a scalar.
--
-- `validation_count` already exists (schema 030) and is now read as the denominator. These two
-- columns store the Wilson 95% bounds computed from it, so every row carries the interval that
-- was judged. The eligibility rule also recomputes them from (observed_far, validation_count) when
-- a row predates this migration, so nothing is forced into `calibrating` for a missing column.
--
-- Additive and idempotent. Rows written before it keep NULL and are recomputed on read; no
-- backfill is attempted, because the stored FAR alone cannot recover the exceedance count any more
-- precisely than `round(rate * n)`.
ALTER TABLE weirvern.ml_calibration
    ADD COLUMN IF NOT EXISTS far_lower Nullable(Float64);

ALTER TABLE weirvern.ml_calibration
    ADD COLUMN IF NOT EXISTS far_upper Nullable(Float64);

ALTER TABLE weirvern.ml_calibration_history
    ADD COLUMN IF NOT EXISTS far_lower Nullable(Float64);

ALTER TABLE weirvern.ml_calibration_history
    ADD COLUMN IF NOT EXISTS far_upper Nullable(Float64);
