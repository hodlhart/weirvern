"""The weirling registry: the database side. Registrations in, the fleet out.

Kept apart from `weirvern/fleet.py` on purpose, the same split `sluice_store.py` uses. That
module is the DECISION layer -- what a registration means, whether a sensor is healthy -- and
it is testable with no database. This one is the STORE. Mixing them would make the semantics
require ClickHouse to be importable, which is how a unit test becomes an integration test
without anybody deciding that.

THE READ PATH RAISES RATHER THAN RETURNING AN EMPTY LIST. An empty list means "no sensors are
registered", and the fleet view would then render a calm, empty, HEALTHY-LOOKING fleet --
while the registry it was supposed to read is unreachable. That is this project's most-named
failure: a missing measurement rendered as a measured zero. A failure must be distinguishable
from a genuinely empty fleet, because those two need opposite actions from the operator.

THE ONE THING THIS STORE MUST NOT DO: infer a registration from a heartbeat. A sensor that
reports is not the same as a sensor that was declared -- the whole reason the registry exists
is to tell those apart, and auto-registering on first sight would make the fleet view
incapable of ever reporting `unregistered`.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime

from clickhouse_connect.driver.client import Client

from weirvern.fleet import (
    HEARTBEAT_STALE_S,
    FleetError,
    Registration,
    SensorHealth,
    classify,
    fleet,
    make_registration,
    revoke,
    summarise,
    validate_address,
    validate_mode,
    validate_sensor_id,
)

logger = logging.getLogger(__name__)

TABLE = "weirvern.weirlings"

# Every column, in one place, so the insert order cannot drift from the select order. A
# positional list is the classic way these diverge: a column added to the table and to the
# SELECT but not to the positional insert shifts every value by one, silently.
COLUMNS = ["sensor_id", "address", "segment", "expected_mode", "enabled", "note",
           "added_at", "updated_at", "revoked_at"]


class FleetStoreError(RuntimeError):
    """The registry could not be read or written. Distinct from a rejected registration."""


def _row_to_registration(row: dict) -> Registration:
    """One stored row as a Registration.

    Defensive about the NULLs because two of these columns are nullable in the table and one
    of them (`revoked_at`) decides whether a sensor appears in the fleet at all. A `revoked_at`
    read as a string rather than None would make a revoked sensor look live forever.
    """
    revoked = row.get("revoked_at")
    if not isinstance(revoked, datetime):
        revoked = None
    added = row.get("added_at")
    if not isinstance(added, datetime):
        added = None
    return Registration(
        sensor_id=str(row.get("sensor_id") or ""),
        address=str(row.get("address") or ""),
        segment=str(row.get("segment") or ""),
        expected_mode=str(row.get("expected_mode") or ""),
        enabled=bool(row.get("enabled")),
        note=str(row.get("note") or ""),
        added_at=added,
        revoked_at=revoked,
    )


def read_registrations(client: Client, *, include_revoked: bool = False) -> list[Registration]:
    """Every registration. Raises `FleetStoreError` when the table cannot be read.

    `include_revoked` exists for an audit question ("was this ever covered?"), not for the
    fleet view: a revoked sensor reappearing on every refresh would be a row nobody can clear.
    """
    where = "" if include_revoked else " WHERE revoked_at IS NULL"
    try:
        rows = list(client.query(
            f"SELECT {', '.join(COLUMNS)} FROM {TABLE} FINAL{where} ORDER BY sensor_id"
        ).named_results())
    except Exception as exc:  # noqa: BLE001 -- the caller needs one error type, not the
        # driver's taxonomy. A missing table (schema not applied yet) and an unreachable
        # database are the same problem from the operator's side: the fleet cannot be read,
        # so nothing may be claimed about it.
        logger.debug("weirlings registry unavailable: %s", exc)
        raise FleetStoreError(
            "the weirling registry could not be read, so the fleet state is UNKNOWN rather "
            "than empty. Check that ClickHouse is reachable and the schema job has run."
        ) from exc
    return [_row_to_registration(r) for r in rows if str(r.get("sensor_id") or "")]


def write_registration(client: Client, reg: Registration) -> None:
    """Insert (or supersede) one registration.

    `updated_at` is written as NOW rather than taken from the object: it is the version column,
    so it must order strictly after whatever row it is replacing. Copying a timestamp from the
    caller would let an edit lose to the row it was meant to replace, and the operator would see
    their change silently not apply.
    """
    now = datetime.now(UTC).replace(tzinfo=None)
    client.insert(
        TABLE,
        [[reg.sensor_id, reg.address, reg.segment, reg.expected_mode,
          1 if reg.enabled else 0, reg.note,
          # added_at is the FIRST registration time and is preserved across edits. The store
          # is the only place that knows the difference between "created" and "rewritten", so
          # the caller passing a fresh `make_registration` (which stamps added_at=now) would
          # reset it on every edit. Taking the earliest of the two keeps the fact honest.
          reg.added_at or now,
          now,
          reg.revoked_at.replace(tzinfo=None) if reg.revoked_at else None]],
        column_names=COLUMNS,
    )


def register(client: Client, sensor_id: str, *, address: str = "", segment: str = "",
             expected_mode: str = "loch", note: str = "",
             now: datetime | None = None) -> Registration:
    """Create or update a registration. Raises FleetError on bad input, FleetStoreError on a
    storage failure.

    AN EDIT PRESERVES `added_at`. Re-registering an existing sensor is an ordinary thing to do
    (fixing a typo in the segment, adding its address once known), and stamping a new added_at
    each time would make the fleet view report every edited sensor as newly added.
    """
    reg = make_registration(sensor_id, address=address, segment=segment,
                           expected_mode=expected_mode, note=note, now=now)
    existing = None
    try:
        for r in read_registrations(client, include_revoked=True):
            if r.sensor_id == reg.sensor_id:
                existing = r
                break
    except FleetStoreError:
        # A read failure must not become a silent overwrite: without the existing row we cannot
        # preserve `added_at`, and inventing it would change a fact the operator reads.
        raise
    if existing is not None:
        reg = Registration(**{**reg.__dict__, "added_at": existing.added_at})
    write_registration(client, reg)
    return reg


def set_enabled(client: Client, sensor_id: str, enabled: bool,
                now: datetime | None = None) -> Registration:
    """Switch a sensor on or off WITHOUT revoking it.

    Deliberately distinct from `revoke_registration`: a sensor taken out of service for a
    maintenance window is still part of the fleet and still expected back, and reporting it as
    an alarm every refresh would train the reader to ignore the column. Raises FleetError when
    the sensor is not registered -- creating one from a toggle would register a sensor at an
    address and segment nobody specified.
    """
    sid = validate_sensor_id(sensor_id)
    reg = _find(client, sid)
    if reg is None:
        raise FleetError(
            f"{sid!r} is not registered, so it cannot be switched on or off. Register it "
            "first: a toggle carries no address, segment or mode, so creating one from it "
            "would invent those facts."
        )
    out = Registration(**{**reg.__dict__, "enabled": bool(enabled),
                          "revoked_at": None if enabled else reg.revoked_at})
    write_registration(client, out)
    return out


def revoke_registration(client: Client, sensor_id: str,
                        now: datetime | None = None) -> Registration:
    """Retire a registration, keeping the row. Raises FleetError when it is not registered."""
    sid = validate_sensor_id(sensor_id)
    reg = _find(client, sid)
    if reg is None:
        raise FleetError(f"{sid!r} is not registered, so there is nothing to revoke.")
    out = revoke(reg, now=now)
    write_registration(client, out)
    return out


def _find(client: Client, sensor_id: str) -> Registration | None:
    """One registration by id, revoked included. Raises FleetStoreError on a read failure."""
    for r in read_registrations(client, include_revoked=True):
        if r.sensor_id == sensor_id:
            return r
    return None


def read_heartbeats(client: Client) -> tuple[list[dict], str | None]:
    """Every `sensor_status` row, or (empty, reason). Never raises.

    BORROWED DELIBERATELY FROM `status._sensor_rows` rather than re-queried: that helper
    already carries the rule about which columns exist and returns the same shape
    `sensor_status` reads. Querying separately here would be a second reader of one table,
    which is how two panels start disagreeing about one sensor.

    Never raises for the same reason it does not there: a heartbeat read failure degrades the
    fleet view to "registrations only", which is still useful, while raising would blank the
    whole tab.
    """
    from weirvern.admin import status as status_mod

    try:
        return status_mod._sensor_rows(client)  # noqa: SLF001 -- the shared reader, on purpose
    except Exception as exc:  # noqa: BLE001
        logger.debug("heartbeat read failed: %s", exc)
        return [], "sensor heartbeats are unavailable, so this shows registrations only"


def build_fleet(client: Client, *, now: datetime | None = None) -> dict:
    """The fleet view's payload: availability, the rows, and the counts.

    THE ENVELOPE IS RETURNED, NOT A BARE LIST. `available: false` with a `reason` is how the
    view renders "cannot read the registry" differently from "you have no sensors", which are
    opposite facts: one is an outage, the other is a fresh install. A bare `[]` cannot carry
    that distinction to the DOM, and by the time the renderer sees it the reason is gone.

    REGISTRATION FAILURE IS FATAL TO THE PAYLOAD; HEARTBEAT FAILURE IS NOT. Without the
    registry there is no fleet to describe -- everything the view shows is a comparison against
    a declared expectation. Without heartbeats the fleet is still describable (every registered
    sensor reads as never-seen), so the tab degrades instead of erroring, and the reason is
    stated so a healthy-looking panel cannot be mistaken for a complete one.
    """
    now = now or datetime.now(UTC)
    heartbeats, hb_error = read_heartbeats(client)
    try:
        regs = read_registrations(client)
    except FleetStoreError as exc:
        return {
            "available": False,
            "reason": str(exc),
            "sensors": [],
            "summary": None,
            "heartbeats_available": False,
            "heartbeat_reason": hb_error,
        }

    health = fleet(regs, heartbeats, now=now)
    return {
        "available": True,
        "reason": None,
        "sensors": [_health_to_json(h) for h in health],
        "summary": summarise(health),
        "heartbeats_available": hb_error is None,
        "heartbeat_reason": hb_error,
    }


def _health_to_json(h: SensorHealth) -> dict:
    """A SensorHealth as JSON. Timestamps become ISO strings or null, never a placeholder."""
    last_seen = h.last_seen
    return {
        "sensor_id": h.sensor_id,
        "state": h.state,
        "is_problem": h.is_problem,
        "address": h.address,
        "segment": h.segment,
        "reported_segment": h.reported_segment,
        "expected_mode": h.expected_mode,
        "reported_mode": h.reported_mode,
        "enabled": h.enabled,
        "registered": h.registered,
        "age_s": h.age_s,
        "last_seen": last_seen.isoformat() if isinstance(last_seen, datetime) else None,
        # NULL means NOT MEASURED and is carried through as null. Coercing it to 0.0 here would
        # report a sensor that never measured anything as a perfect one.
        "capture_loss_pct": h.capture_loss_pct,
        "packets_recv": h.packets_recv,
        "packets_dropped": h.packets_dropped,
        "hosts": h.hosts,
        "note": h.note,
        "findings": list(h.findings),
        "stale_after_s": HEARTBEAT_STALE_S,
    }


def classify_one(client: Client, sensor_id: str) -> dict | None:
    """One sensor's row for a drill-down, or None when it is neither registered nor reporting.

    Reads through `build_fleet` rather than querying separately so a drill-down and the fleet
    list can never disagree about the same sensor -- one query, one truth.
    """
    payload = build_fleet(client)
    if not payload.get("available"):
        return None
    for h in payload.get("sensors", []):
        if h.get("sensor_id") == sensor_id:
            return h
    return None


# Re-exported so the API layer does not need to import the semantics module separately.
__all__ = [
    "COLUMNS",
    "TABLE",
    "FleetStoreError",
    "build_fleet",
    "classify",
    "classify_one",
    "read_heartbeats",
    "read_registrations",
    "register",
    "revoke_registration",
    "set_enabled",
    "validate_address",
    "validate_mode",
    "validate_sensor_id",
    "write_registration",
]
