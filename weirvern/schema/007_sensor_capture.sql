-- 007_sensor_capture.sql
--
-- WHY THIS EXISTS. `sensorwatch.capture_loss()` already reads Zeek's capture_loss.log, but the
-- value only ever became a prose sentence inside `sensor_status.failures` and was never stored as
-- a number. So no surface could show it as a measurement, and the GUI could not answer "is this
-- sensor dropping packets?" except by pattern-matching an English string.
--
-- A sensor that is dropping 60% of packets looks HEALTHY everywhere else: logs are being written,
-- rows are being ingested, every panel renders. Capture loss is the only field that says the
-- sensor is blind to most of what is on the wire, which makes it worth a column rather than a
-- sentence.
--
-- Nullable on purpose. NULL means "not measured" (no capture_loss.log, or a log with no usable
-- row), and that is a different fact from 0.0 which means "measured, nothing lost". Collapsing
-- them would let an unmeasured sensor read as a perfect one -- the silent-empty pattern.

ALTER TABLE weirvern.sensor_status
    ADD COLUMN IF NOT EXISTS capture_loss_pct Nullable(Float32) AFTER refreshes;

-- ALSO NULLABLE, FOR THE SAME REASON AS THE PERCENTAGE. Measured on the live sensor, this Zeek
-- build's capture_loss.log declares `ts ts_delta peer gaps acks percent_lost` -- there is no
-- pkts_recv/pkts_drop column. A NOT NULL count would force a missing field to store 0, reporting
-- "zero packets" for a sensor receiving millions. NULL keeps not-measured distinct from zero.
ALTER TABLE weirvern.sensor_status
    ADD COLUMN IF NOT EXISTS packets_recv Nullable(UInt64) AFTER capture_loss_pct;

ALTER TABLE weirvern.sensor_status
    ADD COLUMN IF NOT EXISTS packets_dropped Nullable(UInt64) AFTER packets_recv;

-- WHAT IS DELIBERATELY NOT HERE: an interface *byte counter*. Zeek's capture_loss.log carries
-- packets received/dropped, which is the quantity that answers "are packets arriving at the
-- capture interface" -- and it is the analyzer's own measurement of its own socket. Reading
-- /proc/net/dev from the worker would report the WORKER's netns, which is not the capture
-- interface at all (only the Zeek DaemonSet has hostNetwork). A counter from the wrong namespace
-- would look like a measurement and be a fiction, which is worse than an absent column.
