-- 052_ml_temporal_points_widen.sql
--
-- THE COLUMN WAS TOO NARROW FOR THE SERIES IT DESCRIBES. `series_points` counted the points in the
-- host's whole window (three days at five-minute buckets = 150,107) into a UInt16, so the INSERT
-- raised clickhouse_connect's DataError with the sentence about None values, and the temporal shadow
-- pass silently wrote nothing. Widening is not cosmetic: a series longer than 65,535 points is the
-- NORMAL case for the default `days=3`, so the pass failed on every host every cycle.
--
-- MODIFY COLUMN keeps the existing rows (they are all within the old range by definition).
ALTER TABLE weirvern.ml_temporal_scores
    MODIFY COLUMN IF EXISTS series_points UInt32;
