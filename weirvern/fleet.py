"""Weirlings: the fleet of sensors feeding one hub.

WHAT A WEIRLING IS. The hub (ClickHouse + worker + GUI) is one thing; a weirling is any
additional sensor elsewhere in the network that feeds it. A weirling exports flows to the
hub's collector, and may additionally ship Zeek logs. This module is the DECISION Layer:
what a registration means, whether a sensor is healthy, and what to tell an operator. It
is deliberately importable and testable with no database, the same split `sluice.py` uses.

WHY A REGISTRY AT ALL, WHEN `sensor_status` ALREADY EXISTS. `sensor_status` is what sensors
REPORT. It can only describe a sensor that has checked in, so on its own it cannot express
the fact an operator most needs during a roll-out:

    "I registered a sensor on the third floor and it has NEVER said anything."

That is a completely different situation from "there are no sensors", and from "there is a
sensor I have never heard of reporting to my hub". The heartbeat table renders all three as
an absence of the expected row. A registry makes the expectation explicit so the comparison
becomes possible, and the comparison is the entire value of a fleet view.

THE FIVE STATES, AND WHY COLLAPSING ANY PAIR IS A DEFECT. Each one needs a different action
from the person reading it, so a view that merges them cannot be acted on:

  alive        registered, heartbeat fresh. Nothing to do.
  stale        registered, heartbeat exists but has aged out. The sensor RAN and stopped.
               Action: check the box -- it may be powered off, or its capture may have died.
  never_seen   registered, no heartbeat EVER. The sensor never came up at all.
               Action: check the install -- wrong hub address, firewall, wrong config.
  unregistered heartbeat exists with no registration. Something is feeding this hub that
               nobody declared. Action: identify it, then register or allow-list it. Also a
               security-relevant event, the same class as an unexpected NetFlow exporter.
  disabled     registered and deliberately switched off. Not reporting is EXPECTED here, so
               this state must not raise an alarm. Action: none.

`stale` and `never_seen` are the pair most likely to be collapsed, because both render as
"no fresh heartbeat". They differ in the one fact that matters: whether the sensor ever
worked. An operator chasing a never-seen sensor into its logs will find no logs.

THE STALENESS THRESHOLD IS IMPORTED, NOT INVENTED. `status.HEARTBEAT_STALE_S` is the one
number the rest of the project uses to decide a heartbeat has aged out. A second threshold
here would let the fleet view call a sensor dead while the sensor panel called it alive, and
the two would disagree about one dataset -- the failure this project has hit repeatedly.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime

# Re-exported so callers importing from here get the SAME number the sensor panel uses.
from weirvern.admin.status import HEARTBEAT_STALE_S, best_sensor_row

# The health states. Strings rather than an enum because they cross a JSON boundary and are
# displayed; an enum would need a serialisation rule and a display-name table, and those are
# two more places for the value to drift from the word the operator sees.
STATE_ALIVE = "alive"
STATE_STALE = "stale"
STATE_NEVER_SEEN = "never_seen"
STATE_UNREGISTERED = "unregistered"
STATE_DISABLED = "disabled"

# The states that mean "a human should look at this". Disabled and alive are deliberately
# absent: a disabled sensor not reporting is the intended outcome, and listing it as a problem
# would train the reader to ignore the whole column.
PROBLEM_STATES = (STATE_STALE, STATE_NEVER_SEEN, STATE_UNREGISTERED)

# A sensor id ends up in a ClickHouse LowCardinality column, in URLs, and in the GUI. Kept to
# the set that needs no escaping anywhere: a space or a slash in a sensor name is a bug that
# shows up as a broken drill-down rather than as a validation error.
SENSOR_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$")

# Modes a weirling may be registered in. `loch` is passive (a SPAN port or a tap); `siphon`
# is in-path. There is deliberately no third option: a sensor in neither is not a weirling,
# and `auto` would be an expectation that cannot be checked, which defeats the point of
# recording one.
KNOWN_MODES = ("loch", "siphon")


class FleetError(ValueError):
    """A rejected fleet operation, with a message written for the operator.

    A ValueError subclass so a caller that does not know this type still treats a bad
    registration as a bad argument rather than a crash.
    """


@dataclass(frozen=True)
class Registration:
    """One sensor the hub expects to hear from.

    ADDRESS IS OPTIONAL AND OFTEN UNKNOWN AT REGISTRATION TIME. An operator standing up a
    sensor knows its NAME and where it will sit; its source address is frequently assigned by
    DHCP or is the address it will NAT from, and is learned when it first reports. Storing it
    as "" rather than inventing a placeholder keeps "not known yet" distinct from a real
    address, which matters because the unregistered-state check compares addresses.
    """

    sensor_id: str
    address: str = ""
    segment: str = ""
    expected_mode: str = "loch"
    enabled: bool = True
    note: str = ""
    added_at: datetime | None = None
    revoked_at: datetime | None = None

    @property
    def live(self) -> bool:
        """Whether this registration is in force. Revoked is not deleted: see `revoke`."""
        return self.revoked_at is None

    @property
    def expects_in_path(self) -> bool:
        """Whether this sensor was registered as one that sits in the traffic path.

        Used to qualify a health reading: a `siphon` weirling that is registered but has never
        reported is a segment that may be expecting an intercept, which is a more urgent
        never_seen than a passive sensor's. Reporting them identically would bury the one that
        can black-hole traffic.
        """
        return self.expected_mode == "siphon"


def validate_sensor_id(sensor_id: str) -> str:
    """A sensor id, or raise FleetError explaining what is wrong with it.

    Rejects rather than sanitises. Quietly rewriting an operator's name means the sensor
    registers under a name they did not choose, and then their own lookup for the name they
    typed finds nothing -- which reads as "the sensor never checked in".
    """
    sid = (sensor_id or "").strip()
    if not sid:
        raise FleetError("a sensor id is required (it is the name this sensor is known by)")
    if not SENSOR_ID_RE.match(sid):
        raise FleetError(
            f"sensor id {sid!r} is not usable: use letters, digits, dot, dash or underscore, "
            "start with a letter or digit, 63 characters or fewer. It appears in URLs and in "
            "the GUI, so characters needing escaping are refused rather than silently encoded."
        )
    return sid


def validate_address(address: str) -> str:
    """A sensor address, or "" when not known yet, or raise FleetError.

    Accepts a bare host address only. A CIDR is refused because this field answers "which one
    box is this", and an operator who types a network is telling us their intent was different
    from what this field means -- guessing (taking the network address, dropping the prefix)
    would register a sensor at an address it does not have.
    """
    addr = (address or "").strip()
    if not addr:
        return ""
    try:
        return str(ipaddress.ip_address(addr))
    except ValueError as exc:
        raise FleetError(
            f"sensor address {addr!r} is not a valid IP address. Register the sensor's host "
            "address, not a network: the fleet view matches this against the address a "
            "heartbeat reports."
        ) from exc


def validate_mode(mode: str) -> str:
    """A registration mode, or raise FleetError.

    An unknown mode is refused rather than accepted-and-ignored: the mode is what makes a
    never-seen in-path sensor more urgent than a passive one, so a value nothing understands
    would silently downgrade that sensor to the harmless case.
    """
    m = (mode or "").strip().lower()
    if m not in KNOWN_MODES:
        raise FleetError(
            f"{mode!r} is not a sensor mode this hub knows: expected one of "
            f"{', '.join(KNOWN_MODES)}."
        )
    return m


def make_registration(sensor_id: str, *, address: str = "", segment: str = "",
                      expected_mode: str = "loch", note: str = "",
                      now: datetime | None = None) -> Registration:
    """A validated registration. The single place a new sensor is constructed."""
    return Registration(
        sensor_id=validate_sensor_id(sensor_id),
        address=validate_address(address),
        segment=(segment or "").strip()[:120],
        expected_mode=validate_mode(expected_mode),
        enabled=True,
        note=(note or "").strip()[:500],
        added_at=now or datetime.now(UTC),
        revoked_at=None,
    )


def revoke(reg: Registration, now: datetime | None = None) -> Registration:
    """Retire a registration without deleting it.

    WHY NOT DELETE. Two reasons, and both are the reason this returns a new object rather
    than a flag on the caller:

      * The row is the only record that a sensor was ever expected, so deleting it makes a
        sensor that broke and was pulled indistinguishable from one that never existed. When
        someone asks "was this covered?", the answer has to survive the cleanup.
      * The heartbeat rows keyed by this sensor id are NOT deleted -- a sensor's reported
        history is evidence. Deleting the registration while the heartbeats remain would turn
        every past reading into an `unregistered` alert, which is a fleet view that alarms
        about sensors somebody deliberately removed.
    """
    if reg.revoked_at is not None:
        return reg
    return replace(reg, revoked_at=now or datetime.now(UTC), enabled=False)


@dataclass
class SensorHealth:
    """One row of the fleet view: a registration compared against what the hub has heard."""

    sensor_id: str
    state: str
    address: str = ""
    # DECLARED: the operator's own label for where this sensor sits.
    segment: str = ""
    # OBSERVED: what the sensor itself reported. Carried separately rather than overwriting the
    # declaration, for the same reason `expected_mode` and `reported_mode` are separate -- one is
    # a claim somebody made, the other is a fact the sensor produced, and they disagree exactly
    # when something is misconfigured. My first version let the declaration win and dropped the
    # observation, so a sensor intercepting the wrong segment looked correctly placed.
    reported_segment: str = ""
    expected_mode: str = ""
    reported_mode: str = ""
    enabled: bool = True
    registered: bool = False
    age_s: float | None = None
    last_seen: datetime | None = None
    # NULL means NOT MEASURED and must never be coerced to 0.0, which would report a sensor
    # that has never measured anything as a perfect one.
    capture_loss_pct: float | None = None
    packets_recv: int | None = None
    packets_dropped: int | None = None
    hosts: int = 0
    note: str = ""
    # Short, operator-facing sentences. Never a bare state word: "stale" alone does not say
    # whether that means the box is off or its capture died.
    findings: list[str] = field(default_factory=list)

    @property
    def is_problem(self) -> bool:
        return self.state in PROBLEM_STATES


def _age_s(ts: object, now: datetime) -> float | None:
    """Seconds since `ts`, or None when it cannot be read.

    Returns None rather than 0.0 for an unreadable timestamp: 0.0 means "just now", which
    would report a sensor with a broken timestamp as the freshest in the fleet.
    """
    if not isinstance(ts, datetime):
        return None
    if ts.tzinfo is None:
        # ClickHouse returns aware datetimes, but a fixture or a hand-written row may not be.
        # Assuming UTC is the same rule `status._aware` applies, kept consistent here so the
        # fleet view and the sensor panel cannot disagree about one row's age.
        ts = ts.replace(tzinfo=UTC)
    try:
        return max(0.0, (now - ts).total_seconds())
    except TypeError:
        return None


def classify(reg: Registration | None, heartbeats: list[dict], *,
             now: datetime | None = None) -> SensorHealth:
    """One sensor's health, from its registration and the heartbeats it has written.

    `heartbeats` is every `sensor_status` row for this sensor id, across modes -- a sensor
    genuinely has two rows when it is intercepting, because the worker publishes the
    configured mode and the intercept publishes its own. Picking one by wall-clock is a bug
    this project has already fixed once in `sensor_status`; the same rule applies here, so
    the newest row wins by MEANING (a running process beats a configured one), not by `ts`.
    """
    now = now or datetime.now(UTC)
    if now.tzinfo is None:
        now = now.replace(tzinfo=UTC)

    rows = [r for r in heartbeats if isinstance(r, dict)]
    # THE SHARED RULE, not a local one. `best_sensor_row` is the same function `sensor_status`
    # uses, so the fleet view and the sensor panel cannot pick different rows out of one dataset.
    # My first version here hand-rolled a "newest wins" rule; that would have disagreed with the
    # panel exactly when a sensor has two live rows and the older one is the more informative
    # (`siphon` beats a fresher `loch`), which is a disagreement nobody could have debugged.
    newest = best_sensor_row(rows, now)
    age = _age_s(newest.get("ts"), now) if newest else None

    reported_mode = str(newest.get("mode") or "") if newest else ""

    h = SensorHealth(
        sensor_id=(reg.sensor_id if reg else str((newest or {}).get("sensor_id") or "")),
        state="",
        address=(reg.address if reg else ""),
        segment=(reg.segment if reg else ""),
        reported_segment=str((newest or {}).get("segment") or ""),
        expected_mode=(reg.expected_mode if reg else ""),
        reported_mode=reported_mode,
        enabled=(reg.enabled if reg else False),
        registered=bool(reg is not None),
        age_s=age,
        last_seen=(newest.get("ts") if newest else None),
        capture_loss_pct=(newest.get("capture_loss_pct") if newest else None),
        packets_recv=(newest.get("packets_recv") if newest else None),
        packets_dropped=(newest.get("packets_dropped") if newest else None),
        hosts=int((newest or {}).get("hosts") or 0),
        note=(reg.note if reg else ""),
    )

    # A registration whose address was never recorded learns it from the first heartbeat.
    # Shown, not stored: a heartbeat's address is an observation and may change, while the
    # registration is what the operator declared. Writing it back would make the registry a
    # moving target and lose the original declaration.
    if not h.address and newest:
        h.address = str(newest.get("address") or newest.get("sampler_address") or "")

    # ── Classify, most specific first.
    if reg is None:
        h.state = STATE_UNREGISTERED
        h.findings.append(
            "this sensor is feeding the hub but is not registered, so nobody declared it. "
            "Identify it, then register it or add it to the flow exporter allow-list."
        )
        return h

    if not reg.enabled:
        h.state = STATE_DISABLED
        h.findings.append(
            "this sensor is registered but switched off, so it is not expected to report."
        )
        return h

    if newest is None:
        h.state = STATE_NEVER_SEEN
        h.findings.append(
            f"registered but has never reported. Check that it can reach this hub and that "
            f"its flow exporter points at the hub's collector (heartbeats arrive every "
            f"{HEARTBEAT_STALE_S // 3}s when it runs)."
        )
        if reg.expects_in_path:
            h.findings.append(
                "this sensor was registered as IN-PATH (siphon), so the segment it covers may "
                "be waiting on an intercept that has never run."
            )
        return h

    if age is None:
        # Reported something, timestamp unreadable. NOT `alive`: calling it fresh would be a
        # claim the data does not support, and NOT `stale` either -- we cannot show it ran and
        # stopped. Reported as stale because that is the conservative reading (someone looks),
        # with the real reason stated rather than implied.
        h.state = STATE_STALE
        h.findings.append(
            "reported a heartbeat whose timestamp could not be read, so its age is unknown. "
            "Treated as not-fresh rather than fresh."
        )
        return h

    if age <= HEARTBEAT_STALE_S:
        h.state = STATE_ALIVE
        h.findings.append(f"reporting normally, last heard {int(age)}s ago.")
    else:
        h.state = STATE_STALE
        h.findings.append(
            f"last reported {int(age)}s ago, past the {HEARTBEAT_STALE_S}s freshness window, "
            f"so it has stopped. It ran and then stopped, which is different from never "
            f"starting: look for why it died rather than why it never came up."
        )

    # ── Independent of health: what the sensor reports about itself, against the one fact
    # the hub can see. Each is a real disagreement an operator would otherwise have to spot
    # by eye across two panels.
    if (h.reported_segment and reg.segment
            and h.reported_segment.lower() != reg.segment.lower()):
        h.findings.append(
            f"registered for segment {reg.segment!r} but reporting {h.reported_segment!r}. "
            f"The registration is the DECLARATION; the reported segment is what the sensor "
            f"believes it is covering."
        )
    if reported_mode and reg.expected_mode and reported_mode != reg.expected_mode:
        h.findings.append(
            f"registered as {reg.expected_mode} but reporting {reported_mode}. The "
            f"registration is what was DECLARED; the reported mode is observed."
        )
    if h.capture_loss_pct is not None and h.capture_loss_pct >= 10.0:
        h.findings.append(
            f"capture loss is {h.capture_loss_pct:.1f}%: this sensor is blind to most of "
            f"what is on the wire, which no other field will show."
        )
    if h.capture_loss_pct is None and h.state == STATE_ALIVE:
        h.findings.append(
            "no capture-loss measurement, so packet loss is unknown rather than zero."
        )
    return h


def fleet(registrations: list[Registration], heartbeats: list[dict], *,
          now: datetime | None = None) -> list[SensorHealth]:
    """The whole fleet: every registered sensor, plus any reporting that nobody registered.

    THE UNION IS THE POINT. Iterating only registrations hides an undeclared sensor (the
    security-relevant case); iterating only heartbeats hides a sensor that never came up (the
    case a roll-out actually needs). Neither source alone can answer "what is my fleet doing".

    Revoked registrations are EXCLUDED here, and that is deliberate: they are kept in the
    store so the history survives, but a sensor somebody removed must not reappear as a
    stale row on every refresh. Its live heartbeats, if any remain, surface as unregistered --
    which is the truthful reading, because nobody has declared it any more.
    """
    now = now or datetime.now(UTC)
    if now.tzinfo is None:
        now = now.replace(tzinfo=UTC)

    by_id: dict[str, list[dict]] = {}
    for r in heartbeats:
        if not isinstance(r, dict):
            continue
        sid = str(r.get("sensor_id") or "")
        if sid:
            by_id.setdefault(sid, []).append(r)

    out: list[SensorHealth] = []
    declared: set[str] = set()
    for reg in registrations:
        if not reg.live:
            continue
        declared.add(reg.sensor_id)
        out.append(classify(reg, by_id.get(reg.sensor_id, []), now=now))

    for sid, rows in by_id.items():
        if sid in declared:
            continue
        out.append(classify(None, rows, now=now))

    # Problems first, then by name. The view exists to surface trouble, and a fleet large
    # enough to need one is a fleet whose healthy majority would otherwise push the one broken
    # sensor below the fold on every load.
    out.sort(key=lambda h: (0 if h.is_problem else 1, h.sensor_id.lower()))
    return out


def summarise(health: list[SensorHealth]) -> dict:
    """Counts for the fleet view's header.

    `measured` is carried so a zero count can be told from an unmeasured one. With no sensors
    registered and nothing reporting, every count is genuinely 0 -- but a caller that only saw
    the zeroes could not distinguish that from a query that failed, which is why the read path
    reports availability separately rather than relying on a count of 0 to mean "fine".
    """
    counts = {
        STATE_ALIVE: 0, STATE_STALE: 0, STATE_NEVER_SEEN: 0,
        STATE_UNREGISTERED: 0, STATE_DISABLED: 0,
    }
    for h in health:
        counts[h.state] = counts.get(h.state, 0) + 1
    return {
        "total": len(health),
        "registered": sum(1 for h in health if h.registered),
        "problems": sum(1 for h in health if h.is_problem),
        **counts,
    }
