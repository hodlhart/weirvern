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
from collections.abc import Mapping
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
# ── "CANNOT SAY" IS NOT A PROBLEM VERDICT (glm-5.3 review) ──────────────────────────────────────
#
# This exists because every other state is a CLAIM about the sensor, and there is a case where the
# hub cannot make one: the heartbeat store is unreadable while the registry reads fine. Before this,
# `build_fleet` passed an empty heartbeat list in that situation, so every registered sensor was
# classified `never_seen` -- "registered but has never reported. Check that it can reach this hub" --
# and counted as a problem. A hub-side fault was reported as a fault in every remote sensor's INSTALL.
#
# Deliberately NOT in PROBLEM_STATES: `is_problem` means "a human should look at this", and the
# action for never_seen (go check the sensor's install) is the WRONG action here. The reason is
# carried in the row's findings instead, so the operator is told what is actually unknown. This is
# the same three-state convention `status.py` uses for `ok=None` and `sluice_store` uses for an
# unreadable timestamp ("cannot say", not "stale").
STATE_UNKNOWN = "unknown"

# How long this hub KEEPS a heartbeat. Read from the schema rather than invented here, because the
# number belongs to the table: `sensor_status` is declared `TTL ts + INTERVAL 7 DAY`, and a constant
# in this module that disagreed with it would be a second source of truth for one fact -- the exact
# failure `HEARTBEAT_STALE_S` is imported (not redefined) above to avoid.
#
# It matters to `classify()` because this is the window past which "no heartbeat row" stops meaning
# "never reported": the evidence has been deleted, so the two readings become indistinguishable.
HEARTBEAT_RETENTION_DAYS = 7.0

# The schema file this number mirrors. Pinned so the test that greps the TTL has one place to look.
HEARTBEAT_RETENTION_SCHEMA = "weirvern/schema/003_sensor_status.sql"


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
# A remote deployment's physical role. `capture` is a SPAN/TAP sensor; `inline` is the explicit
# two-NIC bridge. Never inferred from a mode or a heartbeat: the field is a declaration.
TOPOLOGIES = ("capture", "inline")

# The intercept plan's fields, in one place. Every reader (the store's column mapping, the
# API's per-field view, the GUI's controls) iterates THIS tuple, so a field cannot be added
# to one of them and forgotten in another -- the drift this project keeps finding.
PLAN_FIELDS = ("mode", "iface", "segment", "addr", "gateway", "targets")


# ── the per-sensor intercept plan ────────────────────────────────────────────────────────────
#
# WHY THIS TYPE EXISTS, AND WHY IT IS IN THE REGISTRY RATHER THAN IN A DEPLOYMENT'S ENV.
#
# `INTERCEPT_SEGMENT` / `INTERCEPT_ADDR` / `INTERCEPT_GATEWAY` / `INTERCEPT_TARGETS` in
# `weirvern-env` describe ONE sensor: the one whose worker reads that ConfigMap. A fleet of
# weirlings has one plan per sensor, and the hub cannot reach a remote box's manifest (the GUI's
# ServiceAccount deliberately cannot patch Deployments) -- so the plan is stored where the two
# sides already meet: the hub's own database, the same rendezvous the heartbeat uses. The
# operator writes it through the fleet view; the sensor's own agent reads its OWN row and arms
# (or refuses, with a reason) inside its own deployment.
#
# THE VALIDATION IS NOT A SECOND OPINION. Every shape check here is the check the intercept
# itself makes -- `intercept.parse_cidr` for the segment and its address cap, the supervisor's
# target expansion for a targets list -- imported and reused, never retyped. A plan this module
# accepts must be a plan the intercept can honour; when the two could disagree, the refusals
# here would be the lie.
#
# AN INCOMPLETE PLAN IS NOT AN ERROR, IT IS A STATE. An operator may stage a segment now and the
# address tomorrow. `problems()` states what is still missing, and the sensor's supervisor turns
# that into a refused-to-arm NOTE on the heartbeat -- visible, attributed, and never a silent
# no-op. That is why `make_plan` validates SHAPES only.


@dataclass(frozen=True)
class SensorPlan:
    """One weirling's declared intercept plan. All fields default to '' = not set."""

    mode: str = ""
    iface: str = ""
    segment: str = ""
    addr: str = ""
    gateway: str = ""
    targets: str = ""
    # PER-NIC PLANS for a sensor with more than one usable NIC. JSON keyed by interface;
    # empty means the legacy single plan above. This is what lets a remote weirling carry
    # eth1=siphon + eth2=sluice instead of one plan overwriting the other.
    nics: str = ""

    @property
    def configured(self) -> bool:
        """Whether ANY field is set. False is the pre-existing state of a registration."""
        return bool(self.nics.strip()) or any(
            str(getattr(self, f) or "").strip() for f in PLAN_FIELDS)

    @property
    def armed_mode(self) -> str:
        """The mode a sensor's agent should RUN. Empty plan -> `loch`, the safe resting state."""
        if self.nics.strip():
            from weirvern.nic_plans import NicPlanSet  # noqa: PLC0415

            return "siphon" if NicPlanSet.from_json(self.nics).siphon_ifaces() else "loch"
        return self.mode if self.mode in KNOWN_MODES else ""

    def as_dict(self) -> dict[str, str]:
        """The plan as plain strings, for JSON and for the per-field GUI controls."""
        return {f: str(getattr(self, f) or "") for f in PLAN_FIELDS}

    def to_intercept_config(self):
        """The supervisor's own config object, built from this plan.

        THE ADAPTER IS THE POINT: the sensor agent hands this to the SAME `SiphonSupervisor`
        (and thus the same `weirvern intercept` child) the hub worker runs, so the safety
        contract -- watchdog restore, bounded runs, self-destruct deadline -- cannot fork
        between a hub sensor and a weirling.
        """
        from weirvern.admin import siphon_supervisor  # noqa: PLC0415 -- adapter, kept local

        return siphon_supervisor.InterceptConfig(
            mode=self.armed_mode, iface=self.iface, segment=self.segment,
            our_ip=self.addr, gateway=self.gateway, targets=self.targets,
        )

    def to_intercept_configs(self) -> list:
        """Every siphon NIC's config, or the legacy single config when no per-NIC set exists."""
        if not self.nics.strip():
            return [self.to_intercept_config()] if self.armed_mode == "siphon" else []
        from weirvern.admin import (
            siphon_supervisor,  # noqa: PLC0415
            siphonnet,  # noqa: PLC0415
        )
        from weirvern.nic_plans import NicPlanSet  # noqa: PLC0415

        return [
            siphon_supervisor.InterceptConfig(
                mode="siphon", iface=iface, segment=plan.segment,
                our_ip=plan.addr, gateway=plan.gateway, targets=plan.targets,
                policy_table=siphonnet.policy_table_for(iface),
            )
            for iface, plan in NicPlanSet.from_json(self.nics).plans.items() if plan.siphon
        ]

    @classmethod
    def from_row(cls, row: Mapping[str, object]) -> SensorPlan:
        """A plan read back from a stored registry row (`plan_*` columns).

        Missing keys read as "" rather than raising: an upgraded deployment's rows predate
        the columns, and a plan that cannot be read must not take the fleet view down.
        """
        values = {f: str(row.get(f"plan_{f}") or "") for f in PLAN_FIELDS}
        values["nics"] = str(row.get("plan_nics") or "")
        return cls(**values)

    def problems(self) -> list[str]:
        """What stops this plan from arming RIGHT NOW, in the supervisor's own words.

        Empty when the plan is complete (or when the mode is not siphon, where nothing has to
        be complete). Used by the fleet view to warn at staging time and by the sensor agent's
        supervisor at arm time -- one source for one fact.
        """
        configs = self.to_intercept_configs()
        if not configs:
            return []
        out: list[str] = []
        for cfg in configs:
            out.extend(cfg.missing())
            out.extend(cfg.target_problems())
            if not cfg.target_args():
                out.append(
                    f"{cfg.iface}: no intercept targets: an empty target list diverts no "
                    "traffic, so the sensor will refuse to arm until hosts (or '*') are named"
                )
        return out

    def warnings(self) -> list[str]:
        """Cost warnings, phrased for the operator (not refusals)."""
        out: list[str] = []
        if self.armed_mode == "siphon":
            out.append(
                "siphon is IN-PATH: while the sensor intercepts, its hosts depend on the "
                "sensor's forwarding, so a stopped sensor is an outage for exactly the "
                "hosts this plan names (loch cannot see them until it is switched back)"
            )
        return out


def make_plan(*, mode: str = "", iface: str = "", segment: str = "", addr: str = "",
              gateway: str = "", targets: str = "", nics: str = "") -> SensorPlan:
    """A validated plan, or FleetError naming the field that is wrong.

    SHAPES ONLY -- see the block comment above: a half-filled plan is stored, and the sensor
    says what is missing when it tries to arm.
    """
    from weirvern.admin import intercept as ic_mod  # noqa: PLC0415 -- the intercept's own rules
    from weirvern.admin import mode as mode_mod  # noqa: PLC0415
    from weirvern.admin import siphonnet  # noqa: PLC0415

    raw_mode = str(mode or "").strip()
    m = ""
    if raw_mode:
        normalised = mode_mod.normalise(raw_mode)
        if normalised not in KNOWN_MODES:
            raise FleetError(
                f"mode {raw_mode!r} is not one this hub knows: expected "
                f"{', '.join(KNOWN_MODES)}, or empty for 'not set'."
            )
        m = normalised

    iface = str(iface or "").strip()
    if iface:
        why = siphonnet.iface_name_error(iface)
        if why:
            raise FleetError(f"capture interface {iface!r} is not usable: {why}")

    segment = str(segment or "").strip()
    if segment:
        try:
            # The intercept's OWN parser, so the cap and the v4-only rule cannot drift.
            ic_mod.parse_cidr(segment)
        except ValueError as exc:
            raise FleetError(f"segment {segment!r} cannot be intercepted: {exc}") from exc

    for label, value in (("intercept address", addr), ("gateway", gateway)):
        value = str(value or "").strip()
        if not value:
            continue
        try:
            parsed = ipaddress.ip_address(value)
        except ValueError as exc:
            raise FleetError(
                f"{label} {value!r} is not an IP address. The sensor needs a real one: the "
                f"address is assigned to the capture port and the gateway's MAC is needed to "
                f"restore the mappings."
            ) from exc
        if parsed.version != 4:
            raise FleetError(
                f"{label} {value!r} is IPv6; siphon mode is IPv4-only (the ARP frames, the "
                f"forwarding sysctls and the relay are all v4), so it can never match."
            )

    targets = str(targets or "").strip()
    if targets:
        why = _targets_problem(targets)
        if why:
            raise FleetError(why)

    raw_nics = str(nics or "").strip()
    if raw_nics:
        from weirvern.nic_plans import NicPlanError, NicPlanSet  # noqa: PLC0415

        try:
            plan_set = NicPlanSet.from_json(raw_nics)
        except NicPlanError as exc:
            raise FleetError(f"per-NIC plans cannot be stored: {exc}") from exc
        problems = plan_set.validate()
        if problems:
            raise FleetError("per-NIC plans cannot be stored: " + "; ".join(problems))
        if not m:
            m = "siphon" if plan_set.siphon_ifaces() else "loch"

    return SensorPlan(mode=m, iface=iface, segment=segment,
                      addr=str(addr or "").strip(), gateway=str(gateway or "").strip(),
                      targets=targets, nics=raw_nics)


def _targets_problem(targets: str) -> str:
    """Why this target list cannot be honoured, or "" when it can.

    Mirrors the supervisor's expansion rules EXACTLY (it runs the same `target_problems` call
    at arm time) plus the two shapes the supervisor would pass through to the CLI, where they
    would intercept less than asked rather than fail: a mixing of '*' with named hosts, and a
    token that is neither an address, a CIDR, nor '*'.
    """
    from weirvern.admin import siphon_supervisor  # noqa: PLC0415

    tokens = [t.strip() for t in targets.split(",") if t.strip()]
    if not tokens:
        return ""
    stars = [t for t in tokens if t.lower() in ("*", "all")]
    if stars and len(tokens) > 1:
        return (
            f"targets mix {stars[0]!r} with named hosts; '*' already means every host on the "
            f"segment, so the list is contradictory rather than broader."
        )
    if stars:
        return ""
    for token in tokens:
        try:
            ipaddress.ip_network(token, strict=False)
        except ValueError:
            return (
                f"target {token!r} is neither an address, a CIDR, nor '*'. The intercept "
                f"expands named targets itself; a token it cannot parse would be reported as "
                f"a host that did not answer, which reads as a quiet network instead of a typo."
            )
    problems = siphon_supervisor.InterceptConfig(targets=targets).target_problems()
    return "; ".join(problems)


def plan_from_changes(current: SensorPlan, changes: Mapping[str, object]) -> SensorPlan:
    """`changes` (row-keyed, partial) applied over `current`, validated as one plan.

    The merge-then-validate order is deliberate: a change is judged in the context of the plan
    it will produce, so a refusal names the value that is actually wrong rather than a field
    that is merely absent from the request. Unknown keys are REFUSED, never dropped -- a
    silently ignored field is a control that does nothing while looking applied.
    """
    unknown = sorted(set(changes) - set(PLAN_FIELDS))
    if unknown:
        raise FleetError(
            f"unknown plan field(s): {', '.join(unknown)}. Known fields: "
            f"{', '.join(PLAN_FIELDS)}."
        )
    values = current.as_dict()
    for name in PLAN_FIELDS:
        if name in changes:
            values[name] = str(changes[name] if changes[name] is not None else "").strip()
    return make_plan(**values)


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
    # EXPLICIT DEPLOYMENT TOPOLOGY. `capture` is the passive SPAN/TAP unit (default); `inline`
    # is the two-NIC bridge. It is declared, never inferred from a mode or a heartbeat.
    topology: str = "capture"
    # THE SENSOR'S OWN INTERCEPT PLAN (see SensorPlan above). Defaulting to an empty plan is
    # what keeps this additive: a registration made before the field existed behaves exactly
    # as it did, and the plan only exists for a sensor somebody declared one for.
    plan: SensorPlan = field(default_factory=SensorPlan)

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





def validate_topology(topology: str) -> str:
    """A deployment topology, or raise FleetError.

    An unknown value is refused rather than accepted and ignored: the topology decides which
    test is truthful and whether an inline unit is allowed at all.
    """
    t = (topology or "").strip().lower()
    if not t:
        return "capture"
    if t not in TOPOLOGIES:
        raise FleetError(
            f"{topology!r} is not a weirling topology: expected one of {', '.join(TOPOLOGIES)}."
        )
    return t


def make_registration(sensor_id: str, *, address: str = "", segment: str = "",
                      expected_mode: str = "loch", note: str = "", topology: str = "capture",
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
        topology=validate_topology(topology),
    )


def revoke(reg: Registration, now: datetime | None = None) -> Registration:
    """Retire a registration without deleting it.

    WHY NOT DELETE. Two reasons, and both are the reason this returns a new object rather
    than a flag on the caller:

      * The row is the only record that a sensor was ever expected, so deleting it makes a
        sensor that broke and was pulled indistinguishable from one that never existed. When
        someone asks "was this covered?", the answer has to survive the cleanup.
      * The heartbeat rows keyed by this sensor id are NOT deleted -- a sensor's reported
        history is evidence. Its PLAN is cleared, though: settings are not history, and a
        re-added sensor must start from the safe resting state rather than inherit a route.
        Deleting the registration while the heartbeats remain would turn every past reading
        into an `unregistered` alert, which is a fleet view that alarms about sensors somebody
        deliberately removed.
    """
    if reg.revoked_at is not None:
        return reg
    # THE SETTINGS GO WITH THE REGISTRATION. A revoked sensor that keeps a plan in the registry
    # is a sensor that comes back with the old cross-polluted NIC roles the moment somebody
    # re-adds it. Clear the plan fields (including the per-NIC JSON) here, in the decision
    # layer, so every caller gets the same clean slate; the row itself and its heartbeats stay.
    return replace(reg, revoked_at=now or datetime.now(UTC), enabled=False,
                   plan=SensorPlan())


def channel_state(mode: str, mappings: int, running: bool, fresh: bool) -> dict:
    """Whether the in-path channel is forwarding, as a word plus its reason.

    MODE IS INTENT; THE CHANNEL IS EVIDENCE. `siphon` in a ConfigMap says the sensor is
    CONFIGURED to sit in the traffic path; the intercept's own heartbeat (mappings > 0) says
    traffic is actually crossing it. This deployment measured the difference: mode siphon,
    mappings 0, Zeek observed -- and no flows for 24h, because the channel was never up.
    Rendering the configured word alone made the row claim a working path it did not have.
    """
    mode = str(mode or "").lower()
    mappings = int(mappings or 0)
    if mode != "siphon":
        return {"state": "disabled", "mappings": 0,
                "why": "loch is passive: there is no in-path channel"}
    if not fresh:
        return {"state": "disabled", "mappings": mappings,
                "why": "the intercept's heartbeat is stale, so the channel cannot be confirmed"}
    if mappings <= 0:
        return {"state": "disabled", "mappings": 0,
                "why": "siphon is declared but no intercept mappings are live; traffic is not "
                       "crossing the channel, so flow capture cannot produce records"}
    return {"state": "enabled", "mappings": mappings,
            "why": f"the in-path channel is forwarding ({mappings} mappings)"}


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
    # The OBSERVED source address, from the heartbeat. Separate from `address` for the same reason,
    # and because the two being one field is what made the comparison below impossible (glm-5.3
    # review): with `address` holding the declaration, a heartbeat from somewhere else was never
    # recorded and the check could never fire.
    reported_address: str = ""
    expected_mode: str = ""
    reported_mode: str = ""
    # DECLARED DEPLOYMENT TOPOLOGY: capture or inline. Never inferred.
    topology: str = "capture"
    # THE SENSOR'S DECLARED INTERCEPT PLAN, carried on the row so the drill-down can show and
    # edit it without a second read that could disagree with the list it was opened from.
    plan: SensorPlan = field(default_factory=SensorPlan)
    # THE SENSOR'S OWN NICS, from its heartbeat (its netns view, filtered of software
    # interfaces). Empty means not reported; the reader renders a dash, never a guess.
    interfaces: list[str] = field(default_factory=list)
    # WHAT THE HEARTBEAT SAYS ABOUT THE CAPTURE PATH. `iface` is the interface the sensor
    # reports capturing on; `mappings`/`running` are the intercept's own evidence. The fleet
    # row needs them to answer "is the channel forwarding?" without a second read.
    iface: str = ""
    mappings: int = 0
    running: bool = False
    enabled: bool = True
    registered: bool = False
    age_s: float | None = None
    last_seen: datetime | None = None
    # NULL means NOT MEASURED and must never be coerced to 0.0, which would report a sensor
    # that has never measured anything as a perfect one.
    capture_loss_pct: float | None = None
    packets_recv: int | None = None
    packets_dropped: int | None = None
    # Raw JSON reported by the agent. Empty means NOT MEASURED -- never 0%.
    host_stats: str = ""
    hosts: int = 0
    note: str = ""
    # Short, operator-facing sentences. Never a bare state word: "stale" alone does not say
    # whether that means the box is off or its capture died.
    findings: list[str] = field(default_factory=list)

    @property
    def is_problem(self) -> bool:
        """Whether this needs a human to act.

        `unregistered` is a problem ONLY while it is actively reporting; with no fresh heartbeat
        there is nothing an operator can do, and counting ghosts as problems buries the real
        undeclared sensor. The state stays `unregistered` either way, so the row is still visible
        and still says what it is.
        """
        if self.state != STATE_UNREGISTERED:
            return self.state in PROBLEM_STATES
        return self.age_s is not None and self.age_s <= HEARTBEAT_STALE_S


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
        topology=(reg.topology if reg else "capture"),
        plan=(reg.plan if reg else SensorPlan()),
        interfaces=list((newest or {}).get("interfaces") or []),
        iface=str((newest or {}).get("iface") or ""),
        mappings=int((newest or {}).get("mappings") or 0),
        running=bool((newest or {}).get("running") or False),
        enabled=(reg.enabled if reg else False),
        registered=bool(reg is not None),
        age_s=age,
        last_seen=(newest.get("ts") if newest else None),
        capture_loss_pct=(newest.get("capture_loss_pct") if newest else None),
        packets_recv=(newest.get("packets_recv") if newest else None),
        packets_dropped=(newest.get("packets_dropped") if newest else None),
        host_stats=str((newest or {}).get("host_stats") or ""),
        hosts=int((newest or {}).get("hosts") or 0),
        note=(reg.note if reg else ""),
    )

    # A registration whose address was never recorded learns it from the first heartbeat.
    # Shown, not stored: a heartbeat's address is an observation and may change, while the
    # registration is what the operator declared. Writing it back would make the registry a
    # moving target and lose the original declaration.
    # ── THE OBSERVED ADDRESS IS CARRIED SEPARATELY FROM THE DECLARATION (glm-5.3 review) ─────────
    #
    # This used to read `if not h.address and newest:` -- so the heartbeat's address was copied into
    # `h.address` ONLY when the registration had none. Once an operator declared an address, the
    # observed one was never recorded, and the declared-vs-reported comparison added just below could
    # never fire: the two sides were literally the same field. MEASURED: a registration at one address
    # with a heartbeat reporting from another produced no finding at all.
    #
    # `h.address` stays the DECLARATION (the field has always meant "where we expect it") and the
    # observation goes in its own field, the same split `reported_segment` and `reported_mode` already
    # use. That is what makes a disagreement visible instead of unrepresentable.
    if newest:
        h.reported_address = str(newest.get("address") or newest.get("sampler_address") or "")
    if not h.address and newest:
        # A registration whose address was never recorded learns it from the first heartbeat.
        h.address = h.reported_address

    # ── THE PLAN'S OWN COMPLETENESS, ON THE ROW THAT WILL LIVE OR DIE BY IT ──────────────────
    #
    # A siphon plan that is missing its segment, address or gateway does not half-work: the
    # sensor's own supervisor REFUSES to arm (nothing is intercepted, which is the safe
    # direction) and writes the reason on ITS heartbeat. Without this, the only place that
    # reason is visible is the sensor's own findings -- after the sensor has noticed. Stating
    # it here, from the declaration itself, is what lets the fleet view say "this cannot arm
    # yet, here is what is missing" BEFORE the operator goes looking, and it is computed from
    # the same `problems()` the supervisor's refusal comes from.
    #
    # Computed BEFORE the state branches, because it is a fact about the DECLARATION, not about
    # the sensor's health: it is equally true of a sensor that has never reported and one that
    # is reporting happily in loch with an unrunnable plan staged.
    if h.plan.armed_mode == "siphon":
        gaps = h.plan.problems()
        if gaps:
            h.findings.append(
                "this sensor's siphon plan cannot arm as declared, so nothing is being "
                "intercepted: " + "; ".join(gaps) + ". The sensor refuses rather than "
                "intercepting less than declared, and it will arm by itself once the plan is "
                "complete."
            )

    # ── Classify, most specific first.
    if reg is None:
        # AN UNREGISTERED SENSOR IS ONLY A PROBLEM WHILE IT IS ACTUALLY REPORTING.
        #
        # MEASURED on the live cluster: the fleet filled with `unregistered` rows that were
        # STALE GHOSTS -- heartbeat rows written under a sensor identity that no longer exists
        # (before the sensor-name fix, that identity was the POD NAME, so every rollout left one
        # behind). Treating those as problems the same way as an undeclared sensor that is feeding
        # the hub right now makes the two indistinguishable, and the real one -- the
        # security-relevant case, same class as an unexpected NetFlow exporter -- gets buried
        # under historical noise. That is the same defect this module exists to prevent, one level
        # up: a distinction collapsed in the renderer.
        #
        # So the freshness of the heartbeat decides, and the finding says which case it is.
        if age is not None and age > HEARTBEAT_STALE_S:
            h.state = STATE_UNREGISTERED
            # NOT a problem: nothing is feeding the hub now. It is kept visible because
            # "something reported once that nobody declared" is worth being able to see, and
            # kept OUT of the problem count because an operator can do nothing about a ghost.
            h.findings.append(
                f"reported once under this name and stopped {int(age)}s ago, and nobody ever "
                f"declared it. This is a historical row rather than an active sensor: nothing is "
                f"feeding the hub under this name now, so there is nothing to act on. It ages out "
                f"of the window on its own."
            )
            return h
        h.state = STATE_UNREGISTERED
        h.findings.append(
            "this sensor is feeding the hub RIGHT NOW and is not registered, so nobody declared "
            "it. Identify it, then register it or add it to the flow exporter allow-list."
        )
        return h

    if not reg.enabled:
        h.state = STATE_DISABLED
        h.findings.append(
            "this sensor is registered but switched off, so it is not expected to report."
        )
        # ── A DISABLED ROW THAT IS STILL REPORTING IS NOT AN ALL-CLEAR (glm-5.3 review) ──────────
        #
        # This branch returns before consulting the heartbeat, so a registration that is switched off
        # while the sensor is ACTIVELY feeding the hub renders `state=disabled`, "not expected to
        # report", and `is_problem=False`. Nothing in this module tells the sensor to stop -- `enabled`
        # is a registry-only flag -- so switching a row off does NOT stop the feed. The row then
        # asserts "not expected to report" about a sensor reporting right now, which is the exact
        # shape this project keeps finding: a state that means "ignore this row" silently also
        # covering "this row is lying to you".
        #
        # Kept as a finding rather than a state change: the operator's instruction (do not expect it)
        # is still what the state should say, and quietly reclassifying it as alive would undo their
        # decision. The note is what makes the two distinguishable.
        if h.age_s is not None and h.age_s <= HEARTBEAT_STALE_S:
            h.findings.append(
                f"BUT it reported {int(h.age_s)}s ago, so it is feeding this hub despite being "
                f"switched off. The flag is registry-only -- it does not stop the sensor. If it "
                f"should be silent, stop it on the host."
            )
        return h

    if newest is None:
        h.state = STATE_NEVER_SEEN
        h.findings.append(
            f"registered but has never reported. Check that it can reach this hub and that "
            f"its flow exporter points at the hub's collector (heartbeats arrive every "
            f"{HEARTBEAT_STALE_S // 3}s when it runs)."
        )
        # ── BUT "NO ROW NOW" IS NOT THE SAME AS "NEVER REPORTED" (glm-5.3 review, CONFIRMED LIVE) ─
        #
        # This module's own docstring names `stale` and `never_seen` as the pair most likely to be
        # collapsed, and says they "differ in the one fact that matters: whether the sensor ever
        # worked. An operator chasing a never-seen sensor into its logs will find no logs."
        #
        # They WERE collapsible, and the window is not a code path: `sensor_status` carries
        # `TTL ts + INTERVAL 7 DAY` (verified against the live cluster: `ReplacingMergeTree(ts) ...
        # TTL ts + toIntervalDay(7)`). Every row a silent sensor ever wrote is DELETED after seven
        # days, so a sensor that reported for months and then went silent for eight flips to
        # never_seen -- sending the operator to hunt through logs that definitely exist, with the one
        # field that could have said otherwise erased by the database.
        #
        # The registry does NOT age out (no TTL on `weirlings`), so `added_at` is the honest evidence
        # that survives: a registration older than the heartbeat retention, with no rows, is
        # overwhelmingly likely to have reported at some point. Said as a caveat rather than asserted
        # as fact, because a sensor that was registered and genuinely never came up in that time is
        # indistinguishable from here -- and inventing certainty is the failure this project keeps
        # finding. The state stays `never_seen` for the same reason: it is what the data supports.
        retention_days = HEARTBEAT_RETENTION_DAYS
        if reg.added_at is not None:
            reg_age_days = (now - (
                reg.added_at if reg.added_at.tzinfo else reg.added_at.replace(tzinfo=UTC)
            )).total_seconds() / 86400.0
            if reg_age_days > retention_days:
                h.findings.append(
                    f"BUT it was registered {reg_age_days:.0f} days ago and this hub keeps "
                    f"heartbeats for only {retention_days:.0f}, so an earlier heartbeat would have "
                    f"been DELETED and this reading cannot tell 'never reported' from 'stopped "
                    f"reporting a while ago'. Check the sensor's own logs for an earlier run before "
                    f"treating this as a fresh install."
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
    # ── THE ADDRESS, WHICH WAS COLLECTED ON BOTH SIDES AND NEVER COMPARED (glm-5.3 review) ─────
    #
    # Segment and mode each had a declared-vs-reported check here; address did not, even though
    # `reg.address` is the operator's declaration and `h.address` comes from the heartbeat. That made
    # the registry's own stated purpose half-done: the schema's header says the registry exists so the
    # EXPECTATION can be compared against what the hub hears, and one of the three fields an operator
    # declares was silently exempt from that comparison.
    #
    # It is also the one field that would catch an identity mix-up: a sensor reporting from an address
    # nobody registered is either mis-deployed or standing in for one that is. Reported as a
    # disagreement rather than a failure, because a sensor can legitimately NAT or move (DHCP), which
    # is why the registry stores an EMPTY address as "not known yet" and this check requires both
    # sides to be non-empty.
    if h.reported_address and reg.address and h.reported_address != reg.address:
        h.findings.append(
            f"registered at {reg.address} but reporting from {h.reported_address}. The registration is the "
            f"DECLARATION; the reported address is where the hub actually hears it. Expected if the "
            f"sensor NATs or took a new DHCP lease -- worth checking if it does not."
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
        # NAMED, not left to `counts.get`. An unknown state still increments correctly either way,
        # but only a named key reaches the header, and a count that is invisible in the summary is
        # how "we could not read this" would silently look like "nothing to report".
        STATE_UNKNOWN: 0,
    }
    for h in health:
        counts[h.state] = counts.get(h.state, 0) + 1
    return {
        "total": len(health),
        "registered": sum(1 for h in health if h.registered),
        "problems": sum(1 for h in health if h.is_problem),
        # WHAT THE FLEET IS COLLECTING, not how many things are wrong. The summary tile used
        # to count problems; the operator asked for a Networks count instead. A network is a
        # non-empty segment this fleet has a plan or a report for, counted once even when two
        # NICs sit on the same subnet. An empty plan/report contributes nothing -- it is not a
        # network of 0.0.0.0/0.
        "networks": len(_collected_networks(health)),
        **counts,
    }


def _network_key(raw: object) -> str:
    """A stable identity for one segment: canonical CIDR when possible, raw text otherwise."""
    value = str(raw or "").strip()
    if not value:
        return ""
    try:
        import ipaddress  # noqa: PLC0415

        return str(ipaddress.ip_network(value, strict=False))
    except ValueError:
        # A named segment ("third floor") is still an operator-declared network; counting it
        # is more honest than dropping it because it is not CIDR-shaped.
        return value


def _collected_networks(health: list[SensorHealth]) -> set[str]:
    """Distinct network segments across every sensor's plan and reported/declared segment."""
    found: set[str] = set()
    for h in health:
        for raw in (h.segment, h.reported_segment, h.plan.segment):
            key = _network_key(raw)
            if key:
                found.add(key)
        if h.plan.nics.strip():
            try:
                from weirvern.nic_plans import NicPlanSet  # noqa: PLC0415

                for plan in NicPlanSet.from_json(h.plan.nics).plans.values():
                    key = _network_key(plan.segment)
                    if key:
                        found.add(key)
            except Exception:  # noqa: BLE001
                # A malformed plan is a problem for the plan editor, not a reason to make the
                # whole summary unavailable. Its parsed segments are simply not counted.
                continue
    return found
