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
from dataclasses import replace
from datetime import UTC, datetime, timedelta

from clickhouse_connect.driver.client import Client

from weirvern.fleet import (
    HEARTBEAT_STALE_S,
    PLAN_FIELDS,
    STATE_UNKNOWN,
    STATE_UNREGISTERED,
    FleetError,
    Registration,
    SensorHealth,
    SensorPlan,
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
#
# THE PLAN COLUMNS GO LAST, as the heartbeat's new columns do (see status.heartbeat): the
# registry row is also read positionally by fixtures and by the stub client's zip, and appending
# is what keeps a pre-plan reader aligned instead of shifted.
COLUMNS = ["sensor_id", "address", "segment", "expected_mode", "enabled", "note",
           "added_at", "updated_at", "revoked_at",
           *[f"plan_{f}" for f in PLAN_FIELDS]]


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
        # Same defensive read as the timestamps: a row from before the plan columns existed
        # (or from a stub fixture that predates them) reads as NO PLAN rather than raising.
        plan=SensorPlan.from_row(row),
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

    ── THE TIMEZONE BUG THAT MADE THE VERSION COLUMN LIE (glm-5.3 review, measured live) ────────

    Every timestamp here was sent as a NAIVE datetime -- `.replace(tzinfo=None)` on local writes,
    and `added_at` from `make_registration` as `datetime.now(UTC)` with its tzinfo dropped by the
    driver. clickhouse-connect sends a naive datetime as wall-clock text with no offset, and the
    SERVER interprets it in the server's timezone. MEASURED on the live cluster:

        server timezone()   = America/Chicago   (UTC-5)
        true UTC now        = 2026-09-24 00:23
        server now()        = 2026-09-23 19:23
        a row written at the real 14:56 UTC    -> updated_at 2026-09-23 14:56:05

    so the stored value named "updated_at" is FIVE HOURS EARLIER than the instant it was written.
    For a `ReplacingMergeTree(updated_at)` version column that is not cosmetic: the version has to
    increase or the replacement loses. An edit written in the same local hour as the row it replaces
    computes a version EARLIER than that row, so `FINAL` keeps the OLD registration and the operator
    watches their change silently not apply -- which is precisely the failure the docstring above
    says this line exists to prevent.

    It also made the live rows mutually incoherent: `added_at` and `updated_at` for one sensor
    differed by 18,894s and 18,014s in two samples, which is the offset showing through rather than
    real elapsed time.

    FIXED BY SENDING AWARE UTC. An aware datetime carries its offset, so the server stores the
    instant rather than a wall-clock reading, and the comparison is correct whatever the server's
    timezone is. `added_at` already arrived aware from `make_registration`; the two `.replace(
    tzinfo=None)` calls were what discarded it.
    """
    now = datetime.now(UTC)
    # THE DOCUMENTED CONTRACT MUST COVER THE WRITE (glm-5.3 review). `register`'s docstring promises
    # "FleetStoreError on a storage failure" and the READ path honours that (see read_registrations),
    # but this insert was unwrapped -- so an INSERT failure (a timeout, or the table dropped between
    # the read and the write) escaped as a raw driver exception. A caller catching FleetStoreError,
    # which is what the contract tells them to do, would not catch it. The error taxonomy is part of
    # the API, and one unwrapped call makes it a lie for exactly the failure class it exists for.
    try:
        _write_registration_row(client, reg, now)
    except FleetStoreError:
        raise
    except Exception as exc:  # noqa: BLE001 -- the caller needs one error type, not the driver's
        logger.debug("weirlings registry write failed for %s: %s", reg.sensor_id, exc)
        raise FleetStoreError(
            f"the registration for {reg.sensor_id!r} could not be written, so it may not be in "
            "effect. Check that ClickHouse is reachable and the schema job has run."
        ) from exc


def _write_registration_row(client: Client, reg: Registration, now: datetime) -> None:
    """The raw insert, separated so the caller can wrap it in the module's error type."""
    plan = reg.plan.as_dict()
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
          reg.revoked_at or None,
          # Positional, in COLUMNS order -- which is why the plan's fields are appended last
          # and enumerated from PLAN_FIELDS rather than typed out here.
          *[plan[f] for f in PLAN_FIELDS]],
        ],
        column_names=COLUMNS,
    )


def write_audit(client: Client, *, scope: str, action: str, target: str,
                reason: str = "", actor: str = "") -> None:
    """Append one row to the write trail. Never raises on its own: the CALLER decides whether a
    failed audit write should fail the action (for the destructive ones it should surface; for
    the informational ones the store's degradation rules apply)."""
    client.insert(
        "weirvern.fleet_audit",
        [[str(scope), str(action), str(target), str(reason or ""), str(actor or "")]],
        column_names=["scope", "action", "target", "reason", "actor"],
    )


def read_audit(client: Client, *, scope: str = "", action: str = "", target: str = "",
               limit: int = 20) -> tuple[list[dict], str]:
    """The trail, newest first, or ([], reason). Never raises -- a store outage must not take
    the surface down with it (the store's own degradation pattern)."""
    try:
        where = []
        params: dict[str, object] = {"lim": int(limit)}
        if scope:
            where.append("scope = %(scope)s")
            params["scope"] = scope
        # US-10: filterable by ACTION too -- "who applied settings" is a different question
        # from "who touched the fleet", and the trail must answer both.
        if action:
            where.append("action = %(act)s")
            params["act"] = action
        if target:
            where.append("target = %(target)s")
            params["target"] = target
        clause = (" WHERE " + " AND ".join(where)) if where else ""
        rows = client.query(
            f"SELECT at, scope, action, target, reason, actor FROM weirvern.fleet_audit"
            f"{clause} ORDER BY at DESC LIMIT %(lim)s",
            parameters=params,
        ).result_rows
        return ([{"at": str(r[0]), "scope": r[1], "action": r[2], "target": r[3],
                  "reason": r[4], "actor": r[5]} for r in rows], "")
    except Exception as exc:  # noqa: BLE001
        return [], str(exc)


def register(client: Client, sensor_id: str, *, address: str = "", segment: str = "",
             expected_mode: str = "loch", note: str = "", now: datetime | None = None,
             clear: set[str] | None = None, plan: SensorPlan | None = None) -> Registration:
    """Create or update a registration. Raises FleetError on bad input, FleetStoreError on a
    storage failure.

    AN EDIT PRESERVES WHAT THE CALLER DID NOT MENTION, INCLUDING `added_at` (audit, glm-5.3 review).

    The docstring used to say re-registering is "an ordinary thing to do (fixing a typo in the
    segment, adding its address once known)" while the code implemented FULL REPLACEMENT, carrying
    over only `added_at`. So the documented example -- `register(client, "s1", address="...")` to add
    an address -- silently blanked the sensor's `segment` and `note`, because both default to `""`.
    An "edit" that discards previously declared facts is the row-existence problem one level up: the
    registry looks updated while the operator's earlier declarations are gone.

    The rule now: A FIELD THE CALLER NAMES IS AUTHORITATIVE, INCLUDING AN EMPTY STRING; a field left
    unset keeps its previous value. Defaults are still `""` rather than `None` so the function
    signature and every existing call site are unchanged -- but `""` must be taken as "unset" for a
    field that already has a value, which is why `clear` exists. Naming a field is still how you
    blank it deliberately: `clear={"note"}` empties the note while leaving everything else alone.
    That way neither behaviour is a surprise, and the destructive one has to be asked for.
    """
    sid = validate_sensor_id(sensor_id)
    reg = make_registration(sid, address=address, segment=segment,
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
        # Merge, rather than replace. `added_at` is always preserved; the three descriptive fields
        # fall back to their existing value when the caller left them empty.
        merged = {**reg.__dict__, "added_at": existing.added_at}
        for field_name in ("address", "segment", "note"):
            given = getattr(reg, field_name, "")
            if field_name in (clear or set()):
                merged[field_name] = ""
            elif not str(given).strip():
                # Not named (or named empty) and the caller did not ask to clear it: keep what the
                # operator already declared rather than blanking it.
                merged[field_name] = getattr(existing, field_name, "")
        # `expected_mode` is not merged: it defaults to a real value ("loch"), so an absent argument
        # is indistinguishable from "loch" and merging it would make the mode unchangeable.
        reg = Registration(**merged)
        # ── THE PLAN FOLLOWS THE SAME RULE, WITH ONE DIFFERENCE: IT ARRIVES AS A GROUP ────────
        #
        # `plan=None` means "the caller said nothing about the plan" -- an ordinary edit keeps
        # whatever was declared. A plan handed in is the whole group and REPLACES it, because
        # its fields are interdependent (a segment without its address arms nothing) and every
        # caller that sets one -- the fleet view's form, the CLI -- sends all six. Field-wise
        # merging here would let a form that only knows some fields blank the rest.
        reg = replace(reg, plan=existing.plan if plan is None else plan)
    elif plan is not None:
        reg = replace(reg, plan=plan)
    # ── ONE OPERATOR-FACING MODE PER SENSOR ──────────────────────────────────────────────────
    #
    # `expected_mode` is the declaration the fleet view compares against the sensor's reports;
    # the plan's `mode` is what the sensor's agent runs. Kept in step ON WRITE, so the two can
    # never present an operator with two modes that disagree -- the failure this project keeps
    # finding one layer up (one fact, two readers). A plan with no mode set leaves the
    # registration's mode as the caller gave it.
    if reg.plan.mode in ("loch", "siphon"):
        reg = replace(reg, expected_mode=reg.plan.mode)
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

    ── A TOGGLE MUST NOT UN-REVOKE A RETIRED SENSOR (audit, glm-5.3 review) ────────────────────

    This wrote `"revoked_at": None if enabled else reg.revoked_at`, so switching ON a sensor that
    had been REVOKED silently erased its revocation -- and `_find` includes revoked rows, so the
    toggle could reach exactly that sensor. The operator retired it, then a one-click toggle
    resurrected it with the audit trail overwritten, which is how a retired sensor quietly
    reappears in a fleet of twenty. Disabling an already-revoked row is now a no-op rather than a
    rewrite, and enabling one is refused with an instruction to re-register: resurrecting is a
    deliberate act and should read like one.
    """
    sid = validate_sensor_id(sensor_id)
    reg = _find(client, sid)
    if reg is None:
        raise FleetError(
            f"{sid!r} is not registered, so it cannot be switched on or off. Register it "
            "first: a toggle carries no address, segment or mode, so creating one from it "
            "would invent those facts."
        )
    if reg.revoked_at is not None:
        if enabled:
            raise FleetError(
                f"{sid!r} was revoked, so it cannot simply be switched back on -- that would erase "
                "the record that it was retired. Register it again if it is coming back into "
                "service."
            )
        # Already revoked and being disabled: nothing to change, and rewriting the row would only
        # move its version.
        return reg

    out = Registration(**{**reg.__dict__, "enabled": bool(enabled)})
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


def plan_subject(client: Client, sensor_id: str) -> tuple[Registration | None, str]:
    """The live registration a per-sensor plan write targets, or a refusal sentence.

    WHY THIS READS THE REGISTRY AND NOT THE FLEET PAYLOAD. The GUI's plan routes need to know
    whether a sensor is declared before they will hold a plan for it. Reading that out of the
    fleet VIEW's rows would mean parsing a presentation payload with string keys -- and the
    schema audit rightly flagged exactly that ("plan" and "registered" are produced by the
    payload builder, not by any table), because a write path that reads its own storage back out
    of a payload breaks silently the first time a field is renamed for the browser. The registry
    is the typed source; this returns it.

    A REVOKED registration is `None` here: `read_registrations` returns live ones only, and a
    retired sensor has to be registered again before it can be given a plan -- the same rule
    `set_enabled` enforces, for the same reason.
    """
    try:
        sid = validate_sensor_id(sensor_id)
    except FleetError as exc:
        return None, str(exc)
    try:
        registrations = read_registrations(client)
    except FleetStoreError as exc:
        return None, f"the sensor could not be read: {exc}"
    for reg in registrations:
        if reg.sensor_id == sid:
            return reg, ""
    return None, (
        f"no sensor named {sid!r} is registered, so there is nothing to hold a plan. Adopt it "
        f"in the fleet view first -- one click in its row."
    )


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


# ── WL-1: PER-SENSOR FLOW EVIDENCE, FROM THE FLOWS THEMSELVES ────────────────────────────────
#
# The Weirlings list shows a weirling's flow trend and two tap indicators. The honest source is
# the `flows` table's own `sampler_address` -- the exporter's address, which is the sensor's
# reported address -- so no agent change is needed to know whether a sensor's flows are being
# observed. Absence is a fact too: zero flows from an address in the window is "not observed"
# and must never render as a flat zero line that reads as measured idle traffic.


def flow_evidence(client: Client, addresses: list[str], *, hours: int = 24,
                  now: datetime | None = None) -> tuple[dict[str, dict], str]:
    """Per exporter address: how many flows in the window and when the last one landed."""
    addrs = sorted({str(a).strip() for a in (addresses or []) if str(a or "").strip()})
    if not addrs:
        return {}, ""
    # NOW() IS THE DATABASE'S OWN CLOCK. Measured live: flows are stored in the server's
    # local time (America/Chicago) while a Python UTC-naive `since` is five hours ahead of it,
    # so a 60-minute window matched nothing beside 7,100 stored flows. Comparing in the DB's
    # timezone removes the skew without guessing anyone's offset.
    try:
        rows = client.query(
            "SELECT sampler_address, count(), max(timestamp) FROM weirvern.flows "
            f"WHERE timestamp > now() - INTERVAL {int(hours)} HOUR "
            "AND sampler_address IN %(addrs)s "
            "GROUP BY sampler_address",
            parameters={"addrs": addrs},
        ).result_rows
        out = {str(addr): {"flows": int(n or 0), "last_at": str(last) if last else ""}
               for addr, n, last in rows}
        return out, ""
    except Exception as exc:  # noqa: BLE001
        return {}, str(exc)


def flow_series(client: Client, addresses: list[str], *, minutes: int = 60, buckets: int = 12,
                now: datetime | None = None) -> tuple[dict[str, list[int]], str]:
    """Flows per bucket per exporter, for a sparkline. Zero-filled only when the exporter has
    at least one flow in the window; no flows at all returns NO series (the caller says
    "not observed"), so an empty trend and an idle one never look alike."""
    addrs = sorted({str(a).strip() for a in (addresses or []) if str(a or "").strip()})
    if not addrs:
        return {}, ""
    minutes, buckets = max(1, int(minutes)), max(1, int(buckets))
    # Same clock rule as flow_evidence: the window is the database's, and the buckets are
    # aligned to the DATA's own newest minute -- so a timezone difference cannot push every
    # flow into bucket zero, and a series that stopped three hours ago still draws its shape.
    try:
        rows = client.query(
            "SELECT sampler_address, toStartOfMinute(timestamp) AS m, count() "
            "FROM weirvern.flows "
            f"WHERE timestamp > now() - INTERVAL {int(minutes)} MINUTE "
            "AND sampler_address IN %(addrs)s "
            "GROUP BY sampler_address, m ORDER BY m",
            parameters={"addrs": addrs},
        ).result_rows
    except Exception as exc:  # noqa: BLE001
        return {}, str(exc)
    span = minutes * 60.0
    bucket_s = span / buckets
    by_addr: dict[str, list[tuple]] = {}
    last_minute = None
    for addr, minute, n in rows:
        a = str(addr)
        by_addr.setdefault(a, []).append((minute, n))
        if last_minute is None or minute > last_minute:
            last_minute = minute
    if last_minute is None:
        return {}, ""
    out: dict[str, list[int]] = {}
    for a, points in by_addr.items():
        series = out[a] = [0] * buckets
        for minute, n in points:
            try:
                back = (last_minute - minute).total_seconds()
            except Exception:  # noqa: BLE001
                continue
            if back < 0 or back >= span:
                continue      # older than the window (or clock skew): not this sparkline
            idx = min(buckets - 1, buckets - 1 - int(back / bucket_s))
            series[idx] += int(n or 0)
    return out, ""


def zeek_evidence(client: Client, *, hours: int = 24,
                  now: datetime | None = None) -> tuple[dict, str]:
    """Whether this DEPLOYMENT's Zeek is writing. Only the hub runs Zeek -- a remote weirling
    does not report one, and the caller says so rather than inventing a dark indicator."""
    now = now or datetime.now(UTC)
    since = now.replace(tzinfo=None) - timedelta(hours=int(hours))
    try:
        rows = client.query(
            "SELECT count(), max(ts) FROM weirvern.zeek_conn WHERE ts > %(since)s",
            parameters={"since": since},
        ).result_rows
        n, last = (rows[0] if rows else (0, None))
        return ({"observed": bool(n), "rows": int(n or 0), "last_at": str(last) if last else "",
                 "why": "" if n else "the hub's Zeek has written nothing in the last 24h"}, "")
    except Exception as exc:  # noqa: BLE001
        return {"observed": False, "rows": 0, "last_at": "", "why": str(exc)}, str(exc)


def build_fleet(client: Client, *, now: datetime | None = None,
                problems_only: bool = False) -> dict:
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

    if hb_error:
        # ── AN UNREADABLE HEARTBEAT READ IS NOT AN EMPTY FLEET (glm-5.3 review) ──────────────────
        #
        # This fell through to `fleet(regs, [], now=now)`, so with the registry readable and the
        # heartbeat read FAILED (they carry separate column-existence rules, so one can fail alone),
        # every registered sensor classified as never_seen with the finding "registered but has never
        # reported. Check that it can reach this hub and that its flow exporter points at the hub's
        # collector". A PROBLEM state, counted in the summary.
        #
        # So a hub-side fault was reported as a problem with every remote sensor's INSTALL, and the
        # operator's next action is to go and check sensors that are working fine. That is the exact
        # class this module's own docstring warns about, one layer up: `read_heartbeats` was careful
        # to return a REASON rather than an empty list -- "the fleet view degrades to registrations
        # only, which is still useful" -- and then the caller discarded the distinction by iterating
        # an empty list as if it were the truth.
        #
        # The registrations are still shown, because "what did I declare" is readable and useful. What
        # changes is that the ROWS do not claim a state the heartbeat cannot support: a sensor's
        # health is left unclassified and the reason is carried, the same shape `sluice_store` uses
        # for an unreadable timestamp ("cannot say", not "stale").
        health = fleet(regs, [], now=now)
        for h in health:
            h.state = STATE_UNKNOWN
            h.findings.insert(
                0,
                f"this sensor's state cannot be read: {hb_error}. The registration below is what "
                f"was DECLARED; whether it is reporting is unknown until the heartbeat store is "
                f"readable again.",
            )
    else:
        health = fleet(regs, heartbeats, now=now)
    # ── AN UNADOPTED WEIRLING IS SHOWN ONLY WHILE IT IS TALKING ─────────────────────────────────
    #
    # `sensor_status` keeps seven days of heartbeats, so an identity that stopped -- a pod name
    # from an earlier rollout, a decommissioned unit, a host renamed once -- keeps producing
    # `unregistered` rows long after anything is on the wire. Those rows cannot be adopted (the
    # sensor that wrote them is gone), they can never become alive, and every one of them buries
    # the row that IS feeding the hub and needs a decision. The operator's rule (2026-10-18): an
    # undeclared sensor appears in this tab only while it is online and still talking.
    #
    # The test is the SAME freshness window every other panel uses -- `HEARTBEAT_STALE_S`,
    # imported, never re-invented -- and it is applied to the OBJECTS before `summarise`, so the
    # header counts and the rows cannot disagree about how many sensors the view is showing.
    #
    # An unreadable timestamp is NOT evidence of talking, so it is hidden with the ghosts: the
    # claim this filter makes is "this sensor is reporting now", and a row that cannot support
    # that claim has no business in the list. REGISTERED sensors are untouched, whatever their
    # age: `stale` is the state that exists precisely to tell an operator a declared sensor has
    # gone quiet, and hiding it would delete the answer to "where did my sensor go?".
    health = [h for h in health
              if h.state != STATE_UNREGISTERED
              or (h.age_s is not None and h.age_s <= HEARTBEAT_STALE_S)]
    # THE FILTER IS APPLIED TO THE OBJECTS, NOT TO THE SERIALISED ROWS. Filtering on a payload key
    # would read a DERIVED field as though it were a database column -- the schema auditor flagged
    # exactly that, and it was right to: `is_problem` is computed here, not stored anywhere.
    summary = summarise(health)
    if problems_only:
        health = [h for h in health if h.is_problem]
    return {
        "available": True,
        "reason": None,
        "sensors": [_health_to_json(h) for h in health],
        # The SUMMARY IS OF THE WHOLE FLEET, even when the rows are filtered: "showing problems
        # only" with every count reduced to the filtered subset would report a fleet of four
        # problems and no healthy sensors, which is a different and false statement.
        "summary": summary,
        "filtered": problems_only,
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
        # THE DECLARED PLAN, as plain strings, always present. The drill-down renders one
        # control per field from THIS payload, so a missing key would kill the panel at the
        # first formatter call -- and an absent key is exactly how a per-sensor control ends
        # up silently editing nothing.
        "plan": h.plan.as_dict(),
        "interfaces": list(h.interfaces),
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
    "SensorPlan",
    "build_fleet",
    "classify",
    "classify_one",
    "plan_subject",
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
