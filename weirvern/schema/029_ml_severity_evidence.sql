-- 029_ml_severity_evidence.sql
--
-- WHY THIS EXISTS: the severity label was a model-score claim with no stored basis. A row could
-- say `critical` while its measured deviation was 1.3x and no independent model family agreed;
-- the operator could not tell an incident from a lead. These columns make the basis part of the
-- row instead of a sentence only in the alert body.
--
-- APPENDED, never inserted: the anomaly INSERT is positional by column name, and older readers
-- must keep working. Both have defaults so pre-upgrade rows stay readable.
ALTER TABLE weirvern.netflow_anomalies
    ADD COLUMN IF NOT EXISTS strong_families UInt8 DEFAULT 0 AFTER attack_label,
    ADD COLUMN IF NOT EXISTS severity_basis LowCardinality(String) DEFAULT '' AFTER strong_families;
