"""The per-weirling intercept plan: where it lives, what it refuses, and how it reaches a sensor.

WHY THIS FILE EXISTS. `INTERCEPT_*` in the cluster ConfigMap describes exactly one sensor -- the
one whose worker reads that ConfigMap. A fleet of weirlings needs one plan PER SENSOR, stored
where the hub and a remote box already meet (the hub's database, the same rendezvous the
heartbeat uses), because the hub cannot patch a remote deployment's environment: the GUI's
ServiceAccount deliberately cannot, and `kubectl` on the sensor is the manual step the fleet
view exists to remove (see 020_weirling_plan.sql).

THE PROPERTIES PINNED HERE, EACH ONE A DEFECT IF IT BREAKS:

  * a plan's VALUES are validated by the intercept's OWN rules (parse_cidr's v4-only cap, the
    supervisor's target expansion), so a plan the hub accepts is a plan the intercept honours;
  * an ORDINARY registration edit cannot silently blank a sensor's plan (the row-existence
    failure this store has already been bitten by once, on `segment`/`note`);
  * `expected_mode` and the plan's mode are ONE fact -- kept in step on write -- or the fleet
    view shows an operator two modes that disagree;
  * a plan that is merely INCOMPLETE is stored and reported, never silently dropped: the
    sensor refuses to arm, and the fleet row says why before anyone goes looking;
  * the payload carries the plan for every sensor, because the drill-down renders one control
    per field from it.
"""
from __future__ import annotations

import datetime

import pytest

from weirvern import fleet as fleet_mod
from weirvern import fleet_store as store
from weirvern.fleet import FleetError, Registration, SensorPlan

NOW = datetime.datetime(2026, 10, 17, 12, 0, 0, tzinfo=datetime.UTC)

GOOD = dict(mode="siphon", iface="eth2", segment="198.51.100.0/24",
            addr="198.51.100.250", gateway="198.51.100.1", targets="*")


class _StubResult:
    def __init__(self, rows, cols):
        self.result_rows = rows
        self._cols = cols

    def named_results(self):
        for r in self.result_rows:
            yield dict(zip(self._cols, r, strict=False))


class _StubClient:
    """Holds registry rows as COLUMNS-ordered lists, and supersedes on insert."""

    def __init__(self, rows=None):
        self.rows = list(rows or [])
        self.inserted = []

    def query(self, sql, **_kw):
        if "FROM weirvern.weirlings" in sql:
            return _StubResult(self.rows, store.COLUMNS)
        return _StubResult([], store.COLUMNS)

    def insert(self, table, rows, column_names=None):  # noqa: ANN001
        for r in rows:
            self.inserted.append(dict(zip(column_names, r, strict=False)))
            self.rows = [x for x in self.rows if x[0] != r[0]]
            self.rows.append(list(r))


def _row(sensor_id="s1", address="", segment="", mode="loch", enabled=1, note="",
         added_at=None, updated_at=None, revoked_at=None, plan=None):
    """A registry row in COLUMNS order (the plan columns appended, as they are stored)."""
    plan = plan or {}
    return [sensor_id, address, segment, mode, enabled, note,
            added_at or NOW, updated_at or NOW, revoked_at,
            *[plan.get(f, "") for f in fleet_mod.PLAN_FIELDS]]


# ── the values the plan accepts, and the ones it refuses ─────────────────────────────────────

def test_a_complete_plan_is_accepted_and_round_trips():
    p = fleet_mod.make_plan(**GOOD)
    assert p.as_dict() == GOOD
    assert p.configured and p.armed_mode == "siphon"
    assert p.problems() == [], "a complete siphon plan must have nothing outstanding"


def test_an_empty_plan_is_a_state_not_an_error():
    """A registration that predates the plan columns has one, and it must behave as before."""
    p = fleet_mod.make_plan()
    assert p.as_dict() == {f: "" for f in fleet_mod.PLAN_FIELDS}
    assert not p.configured
    assert p.armed_mode == "", "no mode declared is not a mode"
    assert p.problems() == []


@pytest.mark.parametrize("bad, needle", [
    (dict(mode="wat"), "not one this hub knows"),
    (dict(iface="eth0; rm -rf /"), "not usable"),
    (dict(segment="not-a-cidr"), "cannot be intercepted"),
    (dict(addr="banana"), "is not an IP address"),
    (dict(addr="2001:db8::1"), "IPv6"),
    (dict(gateway="2001:db8::1"), "IPv6"),
    (dict(targets="banana"), "neither an address, a CIDR, nor '*'"),
    (dict(targets="*,198.51.100.5"), "contradictory"),
])
def test_a_malformed_plan_is_refused_NAMING_the_field(bad, needle):
    """A refusal an operator cannot act on sends them to the logs; every one of these names
    the field and says what a usable value looks like."""
    values = {**GOOD, **bad}
    with pytest.raises(FleetError) as e:
        fleet_mod.make_plan(**values)
    assert needle in str(e.value), str(e.value)


def test_the_segment_is_validated_by_the_intercepts_OWN_rules():
    """The v4-only rule and the address cap come from `intercept.parse_cidr`, not from a second
    opinion here -- so a plan this module accepts cannot be one the intercept refuses to run."""
    with pytest.raises(FleetError) as e:
        fleet_mod.make_plan(**{**GOOD, "segment": "2001:db8::/64"})
    assert "IPv4-only" in str(e.value), str(e.value)
    with pytest.raises(FleetError) as e:
        fleet_mod.make_plan(**{**GOOD, "segment": "198.51.100.0/16"})
    assert "1024" in str(e.value), str(e.value)


def test_targets_are_validated_by_the_SUPERVISORS_own_rules():
    with pytest.raises(FleetError) as e:
        fleet_mod.make_plan(**{**GOOD, "targets": "2001:db8::5"})
    assert "IPv6" in str(e.value) and "never match" in str(e.value)


def test_an_incomplete_siphon_plan_is_STORED_and_reported_not_dropped():
    """Shapes are validated on write; completeness is a run-time state the sensor reports. The
    refusals come from the supervisor's own `missing()`/`target_problems()` so the fleet view and
    the sensor's arm-time refusal cannot disagree about what is outstanding."""
    p = fleet_mod.make_plan(mode="siphon")
    assert p.problems(), "an empty siphon plan has to say what it is missing"
    joined = "; ".join(p.problems())
    assert "INTERCEPT_SEGMENT" in joined and "INTERCEPT_ADDR" in joined
    assert "INTERCEPT_GATEWAY" in joined
    p2 = fleet_mod.make_plan(mode="siphon", segment="198.51.100.0/24",
                             addr="198.51.100.250", gateway="198.51.100.1")
    assert any("targets" in prob.lower() for prob in p2.problems()), p2.problems()


def test_the_adapter_hands_the_supervisor_the_same_fields():
    """The sensor's agent runs the SAME supervisor the hub worker runs; this is the seam that
    makes that true, so a renamed field would otherwise arm an intercept on the wrong segment."""
    cfg = fleet_mod.make_plan(**GOOD).to_intercept_config()
    assert (cfg.mode, cfg.iface, cfg.segment, cfg.our_ip, cfg.gateway, cfg.targets) == (
        "siphon", "eth2", "198.51.100.0/24", "198.51.100.250", "198.51.100.1", "*")
    assert cfg.enabled is True


# ── the store: the plan is declared data, and an edit must not erase it ──────────────────────

def test_the_plan_is_written_in_COLUMNS_order():
    """A positional insert against a grown column list is how every value after the insertion
    point shifts silently -- the plan is appended LAST so a pre-plan reader stays aligned."""
    client = _StubClient()
    store.register(client, "s1", plan=fleet_mod.make_plan(**GOOD), now=NOW)
    written = client.inserted[-1]
    assert written["plan_mode"] == "siphon"
    assert written["plan_iface"] == "eth2"
    assert written["plan_segment"] == "198.51.100.0/24"
    assert written["plan_addr"] == "198.51.100.250"
    assert written["plan_gateway"] == "198.51.100.1"
    assert written["plan_targets"] == "*"
    assert list(written) == store.COLUMNS, "the insert's keys must be the declared columns"


def test_an_ordinary_edit_CANNOT_blank_a_sensors_plan():
    """THE DEFECT THIS GUARDS, one level down from the segment/note case this store already
    fixed: `register(client, "s1", address=...)` -- adding an address -- must not discard the
    intercept plan somebody declared, or the sensor silently stops being in-path."""
    client = _StubClient([_row("s1", segment="third floor", plan={"mode": "siphon"})])
    store.register(client, "s1", address="198.51.100.20", now=NOW)
    written = client.inserted[-1]
    assert written["plan_mode"] == "siphon", (
        "an edit that never mentioned the plan wiped it")
    assert written["address"] == "198.51.100.20"


def test_a_plan_handed_in_REPLACES_the_previous_one_as_a_group():
    """Half-merging a group of interdependent fields would leave a plan that cannot arm while
    looking edited -- the new plan is authoritative in full."""
    client = _StubClient([_row("s1", plan={"mode": "siphon", "segment": "198.51.100.0/24",
                                           "addr": "198.51.100.250",
                                           "gateway": "198.51.100.1", "targets": "*"})])
    store.register(client, "s1", plan=fleet_mod.make_plan(mode="loch"), now=NOW)
    written = client.inserted[-1]
    assert written["plan_mode"] == "loch"
    assert written["plan_segment"] == "" and written["plan_targets"] == ""


def test_expected_mode_and_the_plans_mode_are_ONE_fact():
    """The fleet view compares `expected_mode` against what the sensor reports; the sensor runs
    the plan's mode. Two writers for one value is how an operator ends up reading two modes that
    disagree about one sensor."""
    client = _StubClient()
    reg = store.register(client, "s1", plan=fleet_mod.make_plan(**GOOD), now=NOW)
    assert reg.expected_mode == "siphon"
    assert client.inserted[-1]["expected_mode"] == "siphon"

    # ...and a plan that sets no mode leaves the caller's declaration alone.
    client2 = _StubClient()
    reg2 = store.register(client2, "s2", expected_mode="siphon",
                          plan=fleet_mod.make_plan(segment="198.51.100.0/24"), now=NOW)
    assert reg2.expected_mode == "siphon"


def test_a_registration_from_before_the_plan_columns_reads_as_NO_plan():
    """An upgrade must not take the fleet view down: the row predates the columns, and the read
    is defensive for exactly that reason."""
    client = _StubClient([_row("s1", segment="third floor")])
    (reg,) = store.read_registrations(client)
    assert reg.plan == SensorPlan()
    assert not reg.plan.configured


def test_the_payload_carries_the_plan_for_the_renderer():
    """The drill-down renders one control per field FROM the payload; a missing key is how a
    per-sensor control ends up editing nothing at all."""
    h = fleet_mod.classify(
        Registration(sensor_id="edge-1", plan=fleet_mod.make_plan(**GOOD)),
        [], now=NOW)
    row = store._health_to_json(h)  # noqa: SLF001 -- the shipping serialiser, on purpose
    assert set(row["plan"]) == set(fleet_mod.PLAN_FIELDS)
    assert row["plan"]["mode"] == "siphon"


# ── the fleet view's reading of a plan ───────────────────────────────────────────────────────

def test_an_incomplete_siphon_plan_is_STATED_on_the_sensors_row():
    """Before the operator goes looking: a plan that cannot arm says so where the sensor is."""
    reg = Registration(sensor_id="edge-1", expected_mode="siphon",
                       plan=fleet_mod.make_plan(mode="siphon", segment="198.51.100.0/24"))
    h = fleet_mod.classify(reg, [], now=NOW)
    joined = " ".join(h.findings)
    assert "cannot arm as declared" in joined
    assert "INTERCEPT_ADDR" in joined


def test_a_complete_siphon_plan_adds_no_scolding():
    reg = Registration(sensor_id="edge-1", expected_mode="siphon",
                       plan=fleet_mod.make_plan(**GOOD))
    h = fleet_mod.classify(reg, [], now=NOW)
    assert not any("cannot arm" in f for f in h.findings), h.findings


# ── the merge used by the API's staged-then-applied writes ───────────────────────────────────

def test_plan_from_changes_merges_over_the_current_plan():
    current = fleet_mod.make_plan(mode="siphon", segment="198.51.100.0/24")
    merged = fleet_mod.plan_from_changes(current, {"addr": "198.51.100.250",
                                                   "targets": "198.51.100.5"})
    assert merged.segment == "198.51.100.0/24", "a change must not drop the field it did not name"
    assert merged.addr == "198.51.100.250"
    assert merged.targets == "198.51.100.5"


def test_plan_from_changes_REFUSES_an_unknown_field_rather_than_dropping_it():
    """A silently ignored field is a control that does nothing while looking applied."""
    with pytest.raises(FleetError) as e:
        fleet_mod.plan_from_changes(SensorPlan(), {"intercept_segment": "198.51.100.0/24"})
    assert "unknown plan field" in str(e.value)


def test_plan_from_changes_can_CLEAR_a_field_with_an_empty_value():
    current = fleet_mod.make_plan(**GOOD)
    cleared = fleet_mod.plan_from_changes(current, {"targets": ""})
    assert cleared.targets == "" and cleared.segment == "198.51.100.0/24"
