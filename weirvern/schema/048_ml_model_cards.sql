-- 048_ml_model_cards.sql
--
-- WHY A CARD, NOT ANOTHER COLUMN ON ml_models: `ml_models` is a training log -- one row per
-- run, forever. A promotion needs a durable identity that survives a retrain, names the exact
-- artifact and feature/calibration versions that were evaluated, and carries the rollback
-- reference an operator needs at 03:00. Keeping that on the training row would make the
-- latest run look like the current model.
--
-- ADDITIVE ONLY. No row is deleted. A retired model keeps its card so the history of what
-- influenced alerts remains readable.
CREATE TABLE IF NOT EXISTS weirvern.ml_model_cards
(
    model_id              String,
    model_name            String,
    version               String,
    artifact_hash         String,
    training_window_start DateTime,
    training_window_end   DateTime,
    feature_version       String,
    calibration_version   String,
    eval_report_id        String,
    status                LowCardinality(String),  -- shadow | canary | production | retired
    owner                 String,
    approved_by           String,
    approved_at           DateTime,
    rollback_ref          String,
    intended_use          String,
    out_of_scope          String,
    known_limitations     String,
    updated_at            DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY model_id;

-- Seed the cards for the four detectors currently on disk. Values are the measured artifact
-- hashes and training/calibration timestamps on the deployment at 2026-11-11 08:32 UTC.
-- `eval_report_id = not_measured` is deliberate: no fixed-budget report was attached to these
-- artifacts when the registry was introduced. The card says so instead of inventing an id.
INSERT INTO weirvern.ml_model_cards
    (model_id, model_name, version, artifact_hash, training_window_start, training_window_end,
     feature_version, calibration_version, eval_report_id, status, owner, approved_by, approved_at,
     rollback_ref, intended_use, out_of_scope, known_limitations)
SELECT * FROM
(
    SELECT
        'adaptive-baseline' AS model_id,
        'Adaptive Baseline' AS model_name,
        'v4' AS version,
        'c736c6b397f5e522c3fdd99585fbee5f87d90644ed39eb4996b8d227c4faa1b6' AS artifact_hash,
        toDateTime('2026-11-10 08:32:23', 'UTC') AS training_window_start,
        toDateTime('2026-11-11 08:32:23', 'UTC') AS training_window_end,
        '4' AS feature_version,
        '2026-11-11T08:32:27Z' AS calibration_version,
        'not_measured' AS eval_report_id,
        'production' AS status,
        'operator' AS owner,
        'operator' AS approved_by,
        toDateTime('2026-11-11 08:32:27', 'UTC') AS approved_at,
        'models/Adaptive Baseline_v3.pkl + weirvern-worker:0.23.17' AS rollback_ref,
        'Per-host volumetric baseline for anomaly scoring and context.' AS intended_use,
        'Not a classifier, and not evidence of an attack on its own.' AS out_of_scope,
        'Baseline drifts with the host population, so retrain after a topology change.' AS known_limitations
    UNION ALL
    SELECT
        'isolation-forest', 'Isolation Forest', 'v4',
        '9ad91fb954d7af5b2899749d72a4fa69db9a1c104de699d16466f52208e7243a',
        toDateTime('2026-11-08 06:47:02', 'UTC'), toDateTime('2026-11-11 06:47:02', 'UTC'),
        '4', '2026-11-11T08:32:27Z', 'not_measured', 'production', 'operator', 'operator',
        toDateTime('2026-11-11 08:32:27', 'UTC'),
        'models/Isolation Forest_v3.pkl + weirvern-worker:0.23.17',
        'Unsupervised flow-shape detector in the fused anomaly score.',
        'Not a malware classifier, with no payload or process visibility.',
        'Scores drift with traffic mix, and the fixed-budget report is not attached to this artifact.'
    UNION ALL
    SELECT
        'gradient-boosting', 'Gradient Boosting', 'v4',
        '3c8ffb252f3d59869af296d6d9b505f3d86134838441ef42661753637eb1b9f6',
        toDateTime('2026-11-08 06:47:02', 'UTC'), toDateTime('2026-11-11 06:47:02', 'UTC'),
        '4', '2026-11-11T08:32:27Z', 'not_measured', 'production', 'operator', 'operator',
        toDateTime('2026-11-11 08:32:27', 'UTC'),
        'models/Gradient Boosting_v3.pkl + weirvern-worker:0.23.17',
        'Supervised student of the Isolation Forest family in the fused score.',
        'Inherits its training labels, so it is not a standalone ground truth.',
        'Label quality is the limit, and the fixed-budget report is not attached to this artifact.'
    UNION ALL
    SELECT
        'dbscan', 'DBSCAN', 'v4',
        '9c528d3a400e620ecf6e2cfe1ab0fde5f1e346961d14ed4fa2ca165c0de1092d',
        toDateTime('2026-11-08 06:47:02', 'UTC'), toDateTime('2026-11-11 06:47:02', 'UTC'),
        '4', '2026-11-11T08:32:27Z', 'not_measured', 'retired', 'operator', 'operator',
        toDateTime('2026-11-11 08:32:27', 'UTC'),
        'models/DBSCAN_v3.pkl + weirvern-worker:0.23.17',
        'Historical density detector, retained for comparison only.',
        'Must not contribute to the fused production score.',
        'Measured observed FAR 0.9735 against target 0.01, so it is ineligible.'
) AS seed
WHERE (SELECT count() FROM weirvern.ml_model_cards) = 0;

INSERT INTO weirvern.schema_versions (version) VALUES ('048_ml_model_cards');
