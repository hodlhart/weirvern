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
