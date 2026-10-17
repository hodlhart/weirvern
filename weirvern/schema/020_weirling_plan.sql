-- 020_weirling_plan.sql
--
-- THE PER-WEIRLING INTERCEPT PLAN, stored beside the registration.
--
-- WHY IT LIVES IN THE REGISTRY. Until now the intercept plan was DEPLOYMENT-GLOBAL: the
-- `INTERCEPT_*` keys in `weirvern-env` describe exactly one sensor -- the one whose worker
-- reads that ConfigMap. A second sensor (a weirling unit on another segment, or on another
-- box) has no way to say "my segment is this, my gateway is that", and the hub has no way to
-- tell it: the hub can read a remote box's heartbeat, and can write to its own database --
-- and nothing else. ClickHouse is the one rendezvous both sides already have (the same
-- argument the `sensor_status` table carries in 003), so the plan travels the way the
-- heartbeat does: the operator writes it here, the sensor's own agent reads its OWN row.
--
-- WHY NOT PER-DEPLOYMENT CONFIG (the unit's own env). Because the hub could not set it:
-- the GUI's ServiceAccount deliberately cannot patch Deployments (see 60-rbac.yaml), and
-- `kubectl` on a remote sensor is exactly the manual step the fleet view exists to remove.
-- A plan an operator cannot reach is not a plan.
--
-- WHY THE COLUMNS ARE STRINGS, NOT A JSON BLOB. Each field is validated on write by the
-- same code the intercept itself uses (`intercept.parse_cidr`, the supervisor's target
-- expansion), and the GUI shows one control per field. A blob would move the field contract
-- into every reader and make a typo discoverable only at arm time.
--
-- WHY `plan_mode` IS SEPARATE FROM `expected_mode`: `expected_mode` is the DECLARATION the
-- fleet view compares against the sensor's reports; `plan_mode` is what the sensor's agent
-- should RUN. They are kept in step on write (see `fleet_store.register`) so an operator
-- sees one mode, never two that disagree.
--
-- `plan_*` all default to '' -- "no plan declared", not "a plan of empty values" -- so an
-- upgraded deployment keeps working untouched: a sensor with no plan behaves exactly as
-- before, and the local sensor's runtime stays where it has always been (the ConfigMap its
-- own worker reads).

ALTER TABLE weirvern.weirlings
    ADD COLUMN IF NOT EXISTS plan_mode    LowCardinality(String) DEFAULT '' AFTER revoked_at,
    ADD COLUMN IF NOT EXISTS plan_iface   LowCardinality(String) DEFAULT '' AFTER plan_mode,
    ADD COLUMN IF NOT EXISTS plan_segment String DEFAULT '' AFTER plan_iface,
    ADD COLUMN IF NOT EXISTS plan_addr    String DEFAULT '' AFTER plan_segment,
    ADD COLUMN IF NOT EXISTS plan_gateway String DEFAULT '' AFTER plan_addr,
    ADD COLUMN IF NOT EXISTS plan_targets String DEFAULT '' AFTER plan_gateway;
