"""The weirlings registry STORE: the write path, which had no test file.

WHY THIS FILE EXISTS (glm-5.3 review): `tests/test_fleet.py` covers `fleet.py` -- the view that
compares registrations against heartbeats -- and never touches `fleet_store.py`'s write functions.
Every defect the review found on the write path was therefore unpinned: a toggle that un-revoked a
retired sensor, an "edit" that silently discarded declared facts, an insert failure escaping the
documented error type, and a version column written in the wrong timezone. Four mutations survived
until these tests existed.
"""
from __future__ import annotations

import datetime

import pytest

from weirvern import fleet as fleet_mod
from weirvern import fleet_store as store
from weirvern.fleet import Registration


class _StubResult:
    def __init__(self, rows):
        self.result_rows = rows

    def named_results(self):
        cols = getattr(self, "_cols", None) or store.COLUMNS
        for r in self.result_rows:
            yield dict(zip(cols, r, strict=False))


class _StubClient:
    """Holds the registry rows and answers the two queries the store makes."""

    def __init__(self, rows=None):
        self.rows = list(rows or [])
        self.inserted = []
        self.fail_insert: Exception | None = None

    def query(self, sql, **_kw):
        if "FROM weirvern.weirlings" in sql:
            return _StubResult(self.rows)
        return _StubResult([])

    def insert(self, table, rows, column_names=None):  # noqa: ANN001
        if self.fail_insert is not None:
            raise self.fail_insert
        for r in rows:
            self.inserted.append(dict(zip(column_names, r, strict=False)))
            # Supersede by sensor_id, as the ReplacingMergeTree would.
            self.rows = [x for x in self.rows if x[0] != r[0]]
            self.rows.append(r)


def _row(sensor_id="s1", address="", segment="", mode="loch", enabled=1, note="",
         added_at=None, updated_at=None, revoked_at=None):
    """A registry row in COLUMNS order."""
    now = datetime.datetime.now(datetime.UTC)
    return [sensor_id, address, segment, mode, enabled, note,
            added_at or now, updated_at or now, revoked_at]


# ── A TOGGLE MUST NOT UN-REVOKE A RETIRED SENSOR ────────────────────────────────────────────────


def test_switching_a_REVOKED_sensor_on_is_refused():
    """THE DEFECT. `set_enabled(sid, True)` wrote revoked_at=None, silently resurrecting a sensor the
    operator had retired -- and `_find` includes revoked rows, so the toggle could reach exactly it.
    """
    revoked_at = datetime.datetime.now(datetime.UTC)
    client = _StubClient([_row(sensor_id="s1", revoked_at=revoked_at)])

    with pytest.raises(store.FleetError) as e:
        store.set_enabled(client, "s1", True)
    assert "revoked" in str(e.value), str(e.value)

    # And the stored row must still be revoked.
    assert client.rows, "the row vanished"
    assert client.rows[-1][store.COLUMNS.index("revoked_at")] is not None, (
        "the revocation was erased by a toggle, so a retired sensor silently reappeared in the fleet"
    )


def test_switching_a_revoked_sensor_off_is_a_no_op_not_a_rewrite():
    """Already revoked and being disabled: nothing to change, so nothing is written."""
    revoked_at = datetime.datetime.now(datetime.UTC)
    client = _StubClient([_row(sensor_id="s1", enabled=0, revoked_at=revoked_at)])
    before = len(client.inserted)
    store.set_enabled(client, "s1", False)
    assert len(client.inserted) == before, (
        "disabling an already-revoked sensor rewrote the row, moving its version for no reason"
    )


def test_a_live_sensor_can_still_be_toggled():
    """The other direction, so the fix cannot be 'refuse everything'."""
    client = _StubClient([_row(sensor_id="s1", enabled=1)])
    out = store.set_enabled(client, "s1", False)
    assert out.enabled is False
    assert client.rows[-1][store.COLUMNS.index("enabled")] == 0


# ── AN EDIT MUST NOT DISCARD WHAT THE CALLER DID NOT MENTION ─────────────────────────────────────


def test_register_as_an_EDIT_keeps_the_fields_the_caller_did_not_name():
    """THE DEFECT. The docstring's own example -- `register(client, "s1", address=...)` to ADD an
    address -- silently blanked segment and note, because both default to "".
    """
    client = _StubClient()
    store.register(client, "s1", segment="198.51.100.0/24", note="third floor")
    stored = client.rows[-1]
    assert stored[store.COLUMNS.index("segment")] == "198.51.100.0/24"

    # NOW THE DOCSTRING'S EXAMPLE: add an address, name nothing else.
    store.register(client, "s1", address="198.51.100.20")
    stored = client.rows[-1]
    assert stored[store.COLUMNS.index("address")] == "198.51.100.20", "the address was not set"
    assert stored[store.COLUMNS.index("segment")] == "198.51.100.0/24", (
        "adding an address wiped the segment the operator had already declared"
    )
    assert stored[store.COLUMNS.index("note")] == "third floor", (
        "adding an address wiped the note"
    )


def test_an_edit_still_preserves_added_at():
    """The older guarantee, kept pinned so the merge does not regress it."""
    client = _StubClient()
    first = store.register(client, "s1", segment="198.51.100.0/24")
    added = client.rows[-1][store.COLUMNS.index("added_at")]
    store.register(client, "s1", address="198.51.100.20")
    assert client.rows[-1][store.COLUMNS.index("added_at")] == added, (
        "re-registering stamped a new added_at, so every edited sensor reads as newly added"
    )
    assert first.sensor_id == "s1"


def test_clearing_a_field_is_still_possible_when_asked_for():
    """A destructive change must be requestable, or the merge would make blanking impossible."""
    client = _StubClient()
    store.register(client, "s1", note="third floor")
    store.register(client, "s1", clear={"note"})
    assert client.rows[-1][store.COLUMNS.index("note")] == "", (
        "clear={'note'} did not blank the note, so a declared fact can never be removed"
    )


# ── THE VERSION COLUMN MUST CARRY AN INSTANT, NOT A WALL-CLOCK READING ──────────────────────────


def test_timestamps_are_written_AWARE_so_the_version_column_is_an_instant():
    """THE DEFECT (measured live).

    Every timestamp was sent NAIVE, and clickhouse-connect sends a naive datetime as wall-clock text
    with no offset, which the SERVER interprets in its own timezone. MEASURED: server timezone was
    America/Chicago (UTC-5), so a row written at the real 14:56 UTC was stored as 14:56 -- five hours
    earlier than the instant. For a `ReplacingMergeTree(updated_at)` version column that means an edit
    can compute a version EARLIER than the row it replaces, so FINAL keeps the old registration and the
    operator watches their change silently not apply.
    """
    client = _StubClient()
    store.register(client, "s1", segment="198.51.100.0/24")

    for col in ("added_at", "updated_at"):
        v = client.rows[-1][store.COLUMNS.index(col)]
        assert v is not None, f"{col} was not written"
        assert getattr(v, "tzinfo", None) is not None, (
            f"{col} was written NAIVE ({v!r}). A naive datetime is sent as wall-clock text and "
            f"interpreted in the SERVER's timezone, so the stored value is not the instant it was "
            f"written -- which breaks the version ordering the ReplacingMergeTree depends on"
        )


# ── THE DOCUMENTED ERROR TYPE MUST COVER THE WRITE ──────────────────────────────────────────────


def test_an_insert_failure_raises_FleetStoreError():
    """THE DEFECT. `register`'s docstring promises FleetStoreError on a storage failure and the READ
    path honours it, but the insert was unwrapped -- so a caller catching FleetStoreError, as the
    contract tells them to, would not catch a write failure.
    """
    client = _StubClient()
    client.fail_insert = RuntimeError("Code: 60. Table weirvern.weirlings does not exist")

    with pytest.raises(store.FleetStoreError) as e:
        store.register(client, "s1", segment="198.51.100.0/24")
    msg = str(e.value)
    assert "could not be written" in msg, msg
    assert "s1" in msg, msg


# ── A DISABLED REGISTRATION THAT IS STILL FEEDING IS NOT AN ALL-CLEAR ───────────────────────────


def test_a_DISABLED_sensor_that_is_still_reporting_says_so():
    """THE DEFECT. The disabled branch returned before consulting the heartbeat, so a registration
    switched off while the sensor was ACTIVELY feeding rendered state=disabled, "not expected to
    report", and is_problem=False. The flag is registry-only -- it does not stop the sensor.
    """
    now = datetime.datetime.now(datetime.UTC)
    reg = Registration(sensor_id="s1", address="", segment="", expected_mode="loch",
                       enabled=False, note="", added_at=now, revoked_at=None)
    fresh = [{"sensor_id": "s1", "ts": now - datetime.timedelta(seconds=5), "mode": "loch"}]

    h = fleet_mod.classify(reg, fresh, now=now)
    assert h.state == fleet_mod.STATE_DISABLED, f"state is {h.state}"
    joined = " ".join(h.findings)
    assert "switched off" in joined, joined
    assert "reported" in joined and "despite being" in joined, (
        f"a sensor feeding the hub RIGHT NOW while switched off is reported as a clean all-clear. "
        f"findings: {h.findings}"
    )


def test_a_disabled_and_SILENT_sensor_stays_alarm_free():
    """The other direction: the disabled state exists so a maintenance window is quiet."""
    now = datetime.datetime.now(datetime.UTC)
    reg = Registration(sensor_id="s1", address="", segment="", expected_mode="loch",
                       enabled=False, note="", added_at=now, revoked_at=None)
    h = fleet_mod.classify(reg, [], now=now)
    assert h.state == fleet_mod.STATE_DISABLED
    joined = " ".join(h.findings)
    assert "despite being" not in joined, (
        f"a switched-off sensor with no heartbeat got the 'still reporting' note: {h.findings}"
    )


# ── THE DECLARED ADDRESS VS THE REPORTED ONE ───────────────────────────────────────────────────


def test_a_DECLARED_address_that_disagrees_with_the_report_is_flagged():
    """THE DEFECT. Segment and mode each had a declared-vs-reported check; address did not, even
    though it was collected on both sides -- so the one field that could catch an identity mix-up was
    the one field exempt from the comparison the registry exists to make.
    """
    now = datetime.datetime.now(datetime.UTC)
    reg = Registration(sensor_id="s1", address="198.51.100.20", segment="", expected_mode="loch",
                       enabled=True, note="", added_at=now, revoked_at=None)
    hb = [{"sensor_id": "s1", "ts": now - datetime.timedelta(seconds=5), "mode": "loch",
           "address": "198.51.100.99"}]

    h = fleet_mod.classify(reg, hb, now=now)
    joined = " ".join(h.findings)
    assert "198.51.100.20" in joined and "198.51.100.99" in joined, (
        f"a sensor registered at one address but reporting from another was not flagged. "
        f"findings: {h.findings}"
    )


def test_an_EMPTY_declared_address_is_not_a_disagreement():
    """An empty registration address means "not known yet", which is the normal case."""
    now = datetime.datetime.now(datetime.UTC)
    reg = Registration(sensor_id="s1", address="", segment="", expected_mode="loch",
                       enabled=True, note="", added_at=now, revoked_at=None)
    hb = [{"sensor_id": "s1", "ts": now - datetime.timedelta(seconds=5), "mode": "loch",
           "address": "198.51.100.99"}]
    h = fleet_mod.classify(reg, hb, now=now)
    joined = " ".join(h.findings)
    assert "registered at" not in joined, (
        f"an unset declared address was treated as a disagreement: {h.findings}"
    )


# ── GLM 5.3 REVIEW: "NO ROW NOW" IS NOT "NEVER REPORTED" ────────────────────────────────────────


def test_the_retention_constant_matches_the_schema_it_mirrors():
    """A constant that disagrees with the TTL would be a second source of truth for one fact.

    `HEARTBEAT_STALE_S` is IMPORTED rather than redefined for exactly this reason, so the retention
    window has to be held to the same standard. This reads the schema file rather than restating the
    number.
    """
    import pathlib
    import re as _re

    from weirvern import fleet as F

    schema = (pathlib.Path(__file__).resolve().parent.parent) / F.HEARTBEAT_RETENTION_SCHEMA
    text = schema.read_text()
    m = _re.search(r"TTL\s+ts\s*\+\s*INTERVAL\s+([0-9]+)\s+DAY", text)
    assert m, (
        f"could not find a `TTL ts + INTERVAL n DAY` in {F.HEARTBEAT_RETENTION_SCHEMA}. Either the "
        f"schema changed shape or the file moved, and either way this test is no longer measuring "
        f"what it claims"
    )
    assert float(m.group(1)) == F.HEARTBEAT_RETENTION_DAYS, (
        f"the schema keeps heartbeats for {m.group(1)} days but the module says "
        f"{F.HEARTBEAT_RETENTION_DAYS}. classify() decides 'never reported' versus 'the evidence was "
        f"deleted' on this number, so the two must agree"
    )


def test_a_long_silent_sensor_is_NOT_reported_as_a_fresh_install():
    """THE DEFECT (confirmed against the live cluster).

    `sensor_status` carries `TTL ts + INTERVAL 7 DAY`, verified live as
    `ReplacingMergeTree(ts) ... TTL ts + toIntervalDay(7)`. EVERY row a silent sensor wrote is
    deleted after seven days, so a sensor that reported for months and then went silent for eight
    flips to never_seen -- and this module's own docstring says the two states "differ in the one
    fact that matters: whether the sensor ever worked. An operator chasing a never-seen sensor into
    its logs will find no logs." That operator would be sent hunting through logs that exist.
    """
    now = datetime.datetime.now(datetime.UTC)
    reg = Registration(
        sensor_id="s1", address="", segment="", expected_mode="loch", enabled=True, note="",
        added_at=now - datetime.timedelta(days=40), revoked_at=None,
    )

    h = fleet_mod.classify(reg, [], now=now)

    assert h.state == fleet_mod.STATE_NEVER_SEEN, (
        f"the state changed; it is what the remaining data supports. state={h.state}"
    )
    joined = " ".join(h.findings)
    assert "DELETED" in joined or "deleted" in joined, (
        f"a sensor registered 40 days ago with no heartbeat rows was reported as 'registered but has "
        f"never reported' with no caveat. The registry keeps `added_at` forever while heartbeats age "
        f"out at 7 days, so this reading cannot distinguish a fresh install from a sensor whose "
        f"history was erased. findings: {h.findings}"
    )
    assert "7" in joined and "40" in joined, (
        f"the caveat must carry both numbers so the operator can see the overlap. findings: {h.findings}"
    )


def test_a_genuinely_new_registration_gets_no_retention_caveat():
    """The other direction, so the caveat cannot become noise on every never-seen sensor.

    A sensor registered an hour ago genuinely has no history to have lost, and telling the operator
    its heartbeats "would have been deleted" would be false.
    """
    now = datetime.datetime.now(datetime.UTC)
    reg = Registration(
        sensor_id="s1", address="", segment="", expected_mode="loch", enabled=True, note="",
        added_at=now - datetime.timedelta(hours=1), revoked_at=None,
    )

    h = fleet_mod.classify(reg, [], now=now)

    assert h.state == fleet_mod.STATE_NEVER_SEEN
    joined = " ".join(h.findings)
    assert "DELETED" not in joined, (
        f"a registration one hour old was told its earlier heartbeats would have been deleted, which "
        f"cannot be true. findings: {h.findings}"
    )


def test_a_registration_with_no_added_at_does_not_crash_the_caveat():
    """`added_at` is optional on the dataclass, and a row could have been written without one."""
    now = datetime.datetime.now(datetime.UTC)
    reg = Registration(sensor_id="s1", address="", segment="", expected_mode="loch", enabled=True,
                       note="", added_at=None, revoked_at=None)
    h = fleet_mod.classify(reg, [], now=now)
    assert h.state == fleet_mod.STATE_NEVER_SEEN


def test_a_NAIVE_added_at_is_read_as_UTC_rather_than_raising():
    """`added_at` is a plain `datetime | None` on the dataclass, so a caller can hand this a naive
    value -- and subtracting an aware `now` from a naive datetime RAISES TypeError, which would abort
    the whole fleet view for one row. Read as UTC instead, the same rule `_age_s` and the sluice
    staleness check already apply to a naive timestamp.

    Found by mutation: removing the awareness guard left every other test green, so nothing pinned it.
    """
    now = datetime.datetime.now(datetime.UTC)
    naive = (now - datetime.timedelta(days=40)).replace(tzinfo=None)
    reg = Registration(sensor_id="s1", address="", segment="", expected_mode="loch", enabled=True,
                       note="", added_at=naive, revoked_at=None)

    h = fleet_mod.classify(reg, [], now=now)   # must not raise
    assert h.state == fleet_mod.STATE_NEVER_SEEN
    assert any("DELETED" in f for f in h.findings), (
        f"a naive added_at 40 days old did not produce the retention caveat, so it was not read as "
        f"UTC. findings: {h.findings}"
    )
