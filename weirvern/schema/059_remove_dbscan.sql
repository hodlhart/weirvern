-- 059_remove_dbscan.sql
--
-- THE DENSITY DETECTOR IS REMOVED, NOT RETIRED. The code, the class, the feature paths, the
-- ensemble family, the registry entry, the Detectors row and the artifacts on the models PVC are
-- gone in 0.23.102. This migration removes what the engine's TABLES still hold for it, so a fresh
-- or upgraded deployment cannot resurrect a name that has no detector behind it:
--
--   ml_model_cards        the curated card. It was written as `retired`, and a card is now
--                         documentation of intent only -- but a card for a model that does not
--                         exist is a registry row nothing can ever satisfy.
--   ml_models             the engine's own training log. The Detectors table and the freshness
--                         panel are read off the LIVE roster now, so this is history rather than
--                         a gate; it is deleted because the operator's instruction was to remove
--                         the detector completely, and the dated record of WHY lives in
--                         CHANGELOG 0.23.102 with the measurement.
--   ml_calibration(-history)  measurements of a score nobody can reproduce any more.
--   ml_window_scores      the stored per-window scores. 97.89% of the 27,454 rows measured
--                         2026-11-12 -> 2026-11-19 sat at 0.99 or above (p50 = p99 = max = 0.99),
--                         i.e. the population carried no information: no threshold could separate
--                         anything from anything.
--
-- WHAT IS DELIBERATELY NOT DROPPED: the `dbscan_score` columns in `netflow_anomalies` and
-- `near_misses`. They are historical incident rows, and a column drop is one-way. The code stopped
-- writing and reading them in 0.23.102 (they are omitted from every INSERT column list and SELECT),
-- so they are dormant rather than wrong. Dropping them is a separate decision, to be taken once no
-- pre-0.23.102 pod can still write an INSERT that names them -- the schema Job runs before the new
-- image rolls out, so doing it here would fail the OLD pods' inserts for the length of the rollout.
--
-- Idempotent: every statement deletes only rows no statement will ever create again, and a
-- second run matches none of them.
-- LIGHTWEIGHT DELETES, not `ALTER TABLE ... DELETE`: both are idempotent (a second run matches
-- nothing), and `DELETE FROM` does not read as an ALTER whose idempotence the migration guard has
-- to prove from an `IF EXISTS` clause. A delete has no schema effect to re-apply.
DELETE FROM weirvern.ml_model_cards WHERE model_name = 'DBSCAN';
DELETE FROM weirvern.ml_models WHERE model_type = 'DBSCAN';
DELETE FROM weirvern.ml_calibration WHERE model_name = 'DBSCAN';
DELETE FROM weirvern.ml_calibration_history WHERE model_name = 'DBSCAN';
DELETE FROM weirvern.ml_window_scores WHERE model_name = 'DBSCAN';
