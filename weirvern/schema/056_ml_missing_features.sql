-- 056_ml_missing_features.sql
--
-- WHY THIS EXISTS: the ML path used to turn every source it could not read into 0. Measured on
-- the live deployment, Isolation Forest carries 77 features of which 63 are Zeek, but Zeek is
-- visible on ~14 hosts against ~3,730 NetFlow hosts -- so nearly every host's vector was a wall
-- of zeroes that reads as "perfectly quiet" on every ratio and "no traffic at all" on every
-- count. The measured false-alarm rates were 0.33 (IF), 0.33 (GB), 1.00 (DBSCAN) against a 0.01
-- target.
--
-- The fix keeps "not measured" as NULL rather than 0 and imputes it at scoring time, behind the
-- default-OFF `ml_missing_features` flag. These columns are what make that auditable:
--
--   coverage          how much of the detector's vector was actually measured for this window.
--                     NULLABLE ON PURPOSE: NULL means "coverage was not measured" (the flag was
--                     off when the row was written), which is a different fact from 0.0
--                     ("nothing was measured") and must never be rendered as one.
--   excluded          1 when the window was below the coverage floor and therefore kept out of
--                     both the calibration reference fit and the FAR measurement.
--   excluded_windows  how many windows the calibration row above removed.
--
-- Every column is additive and every statement is idempotent: with the flag off the worker
-- writes NULL/0 and reads exactly the population it read before.
ALTER TABLE weirvern.ml_window_scores
    ADD COLUMN IF NOT EXISTS coverage Nullable(Float64);

ALTER TABLE weirvern.ml_window_scores
    ADD COLUMN IF NOT EXISTS excluded UInt8 DEFAULT 0;

ALTER TABLE weirvern.ml_calibration
    ADD COLUMN IF NOT EXISTS coverage Nullable(Float64);

ALTER TABLE weirvern.ml_calibration
    ADD COLUMN IF NOT EXISTS excluded_windows UInt32 DEFAULT 0;

ALTER TABLE weirvern.ml_calibration_history
    ADD COLUMN IF NOT EXISTS coverage Nullable(Float64);

ALTER TABLE weirvern.ml_calibration_history
    ADD COLUMN IF NOT EXISTS excluded_windows UInt32 DEFAULT 0;
