-- 058_ml_calibration_coverage.sql
--
-- WHY THIS EXISTS: schema 056 added `coverage` to ml_calibration and its history, but nothing ever
-- wrote it, so every row read NULL and a false-alarm rate was stored with no record of what the
-- model was fed. Measured live after ML_MISSING_FEATURES was switched on: Isolation Forest's
-- observed FAR fell from a fused 0.25 to 0.0097 against a 0.01 target, and the row could not say
-- whether that rate was measured on 10 of 77 columns or on all of them. A FAR measured on a mostly
-- imputed vector is not comparable to one measured on the full vector.
--
-- `coverage` alone is a ratio, and a ratio cannot be audited once the feature set moves. These
-- columns keep the counts it came from, the operator-readable form, and the missing-data mode that
-- produced the row, so two false-alarm rates are never compared across incompatible vectors:
--
--   coverage_observed / coverage_expected   measured and expected column counts summed over the
--                                           reference windows. NULL means coverage was not
--                                           measured: the flag was off, or the reference was the
--                                           stored anomaly tail, which carries no feature vector.
--   coverage_detail                         the same counts as an operator reads them, '10/77'.
--                                           Empty string -- never '77/77' -- when unrecorded.
--   missing_mode                            'on' or 'off': whether ML_MISSING_FEATURES produced the
--                                           reference scores. '' on rows written before this
--                                           migration, which are comparable to neither.
--
-- The counts are measured once, by `models.missing.coverage_counts`, in the same feature assembly
-- the detectors consume, and written beside the score in `ml_window_scores`. Nothing downstream
-- re-derives a feature list.
--
-- Additive and idempotent. Rows written before it keep NULL / '' and read as unrecorded; no
-- backfill is attempted, because inventing a coverage figure for history would be worse than
-- admitting it was never measured.
ALTER TABLE weirvern.ml_window_scores
    ADD COLUMN IF NOT EXISTS coverage_observed Nullable(UInt32);

ALTER TABLE weirvern.ml_window_scores
    ADD COLUMN IF NOT EXISTS coverage_expected Nullable(UInt32);

ALTER TABLE weirvern.ml_calibration
    ADD COLUMN IF NOT EXISTS coverage_observed Nullable(UInt32);

ALTER TABLE weirvern.ml_calibration
    ADD COLUMN IF NOT EXISTS coverage_expected Nullable(UInt32);

ALTER TABLE weirvern.ml_calibration
    ADD COLUMN IF NOT EXISTS coverage_detail String DEFAULT '';

ALTER TABLE weirvern.ml_calibration
    ADD COLUMN IF NOT EXISTS missing_mode LowCardinality(String) DEFAULT '';

ALTER TABLE weirvern.ml_calibration_history
    ADD COLUMN IF NOT EXISTS coverage_observed Nullable(UInt32);

ALTER TABLE weirvern.ml_calibration_history
    ADD COLUMN IF NOT EXISTS coverage_expected Nullable(UInt32);

ALTER TABLE weirvern.ml_calibration_history
    ADD COLUMN IF NOT EXISTS coverage_detail String DEFAULT '';

ALTER TABLE weirvern.ml_calibration_history
    ADD COLUMN IF NOT EXISTS missing_mode LowCardinality(String) DEFAULT '';
