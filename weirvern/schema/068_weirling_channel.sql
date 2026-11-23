-- 068_weirling_channel.sql
--
-- A CHANNEL IS NOT A SENSOR MODE. `mode` answers how this sensor gets traffic (loch = passive
-- mirror/SPAN/TAP, siphon = ARP in-path). A CHANNEL is the inline bridge between two NICs,
-- implemented by `admin/channel.py`: both ports present and up with carrier, enslaved to one
-- bridge, bridge-nf on, and the node's FORWARD path admitting the bridge. Until now the pair
-- lived only in the deployment ConfigMap (`CHANNEL_UPSTREAM` / `CHANNEL_DOWNSTREAM`), which
-- describes exactly one sensor -- the one whose worker reads that ConfigMap -- so every remote
-- weirling was refused a channel it might genuinely need.
--
-- WHY THE PAIR LIVES IN THE REGISTRY. The hub cannot patch a remote unit's environment (the GUI
-- ServiceAccount deliberately cannot patch Deployments), and `kubectl` on a sensor is the manual
-- step the fleet view exists to remove. The plan row is the rendezvous both sides already use,
-- the same argument 020_weirling_plan.sql carried for the intercept fields.
--
-- WHY TWO COLUMNS RATHER THAN A JSON BLOB. Each side is one control in the sheet, and the write
-- path validates both against `plan_nics` and the management port. A blob would move that
-- contract into every reader and make a typo discoverable only when the bridge failed.
--
-- WHY THE SENSOR REPORTS ITS OWN PAIR. The console must never infer "active" from a plan that
-- says somebody intended one. `sensor_status` gains the pair the sensor actually uses plus
-- `channel_active` read from its kernel, so a staged pair reads as staged until the sensor's own
-- report agrees. NULL `channel_active` means the agent did not report one (an older build),
-- which is why the column is Nullable: 0 is a measurement, NULL is not-measured.
--
-- Both ALTERs are idempotent because `apply_schema` re-runs every file on every start.

ALTER TABLE weirvern.weirlings
    ADD COLUMN IF NOT EXISTS plan_channel_upstream   LowCardinality(String) DEFAULT '' AFTER plan_targets,
    ADD COLUMN IF NOT EXISTS plan_channel_downstream LowCardinality(String) DEFAULT '' AFTER plan_channel_upstream;

ALTER TABLE weirvern.sensor_status
    ADD COLUMN IF NOT EXISTS channel_active     Nullable(UInt8) AFTER host_stats,
    ADD COLUMN IF NOT EXISTS channel_upstream   LowCardinality(String) DEFAULT '' AFTER channel_active,
    ADD COLUMN IF NOT EXISTS channel_downstream LowCardinality(String) DEFAULT '' AFTER channel_upstream,
    ADD COLUMN IF NOT EXISTS channel_bridge     LowCardinality(String) DEFAULT '' AFTER channel_downstream;
