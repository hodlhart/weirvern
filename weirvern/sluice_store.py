"""Sluice Gate: the database side. Rules in, state out.

Kept apart from `weirvern/sluice.py` on purpose. That module is the DECISION layer -- what a rule
means, whether it is still in force, what the kernel should be told -- and it is testable without a
database. This one is the STORE: reading rules out, writing events and gate state in. Mixing them
would make the decision layer need ClickHouse to be importable, which is how a unit test becomes an
integration test without anyone deciding that.

THE READ PATH IS THE ONE THAT MATTERS HERE, because it is what the enforcement loop calls every
minute. Two things are deliberate:

  * The live-rule filter is applied in SQL (`revoked_at IS NULL AND (expires_at IS NULL OR
    expires_at > now())` -- NULL meaning until revoked) AND again
    in `Rule.is_live()`. That is not redundant defensiveness: the SQL filter is what keeps the read
    cheap, and `is_live` is what guarantees correctness if the two ever disagree -- a rule that
    lapsed between the query and the arming must not be enforced. Belt and braces on the ONE thing
    that must not be wrong, because an expired rule still blocking is a network that stops working
    with nobody able to say why.

  * A read failure RAISES rather than returning an empty list. An empty list means "no rules", and
    the gate would then disarm itself and report ARMED-with-nothing. A database blip would silently
    OPEN the gate, which is exactly the class of failure this project names most often: a missing
    measurement rendered as a measured zero.
"""

from __future__ import annotations

import ipaddress
import logging
import uuid
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from typing import Any

from clickhouse_connect.driver.client import Client

from weirvern.sluice import (
    GATE_STATE_ARMED,
    GATE_STATE_DEGRADED,
    GATE_STATE_DISARMED,
    GateState,
    Rule,
    SluiceError,
    parse_cidr,
)

logger = logging.getLogger(__name__)

LIVE_RULE_SQL = """
SELECT rule_id, src_cidr, dst_cidr, domain, mode, protocol, dst_port, direction, expires_at,
       created_by, reason, origin, origin_ref, severity, revoked_at, disabled_at
FROM weirvern.sluice_rules FINAL
WHERE revoked_at IS NULL
  -- A DISABLED RULE IS NOT ENFORCED (schema/017). One clause here stops BOTH the kernel compile
  -- and the alert pass, because both read live rules through this query -- the operator's
  -- switch must mean the same thing everywhere, or it means nothing.
  AND disabled_at IS NULL
  -- NULL is UNTIL REVOKED (schema/014), not "missing": a bare `expires_at > now()` evaluates to
  -- NULL for these rows and would drop every indefinite rule out of enforcement silently, which
  -- is the exact failure shape this file's comments keep warning about.
  AND (expires_at IS NULL OR expires_at > now())
ORDER BY created_at DESC
LIMIT 10000
"""


def new_rule_id() -> str:
    """A sortable id: timestamp first, so the GUI can page without an offset.

    Deliberately not a UUID alone. Rules are read and shown in creation order, and a random id
    would make "the newest rule" a sort over a string that carries no time.
    """
    return f"{datetime.now(UTC):%Y%m%d%H%M%S}-{uuid.uuid4().hex[:8]}"


def _row_to_rule(row: Sequence[Any]) -> Rule:
    (rule_id, src, dst, domain, mode, proto, port, direction, expires, created_by, reason,
     origin, origin_ref, severity, revoked, disabled) = row
    return Rule(
        rule_id=str(rule_id),
        src_cidr=str(src or ""),
        dst_cidr=str(dst or ""),
        domain=str(domain or ""),
        mode=str(mode or "block"),
        protocol=str(proto or ""),
        dst_port=int(port or 0),
        direction=str(direction or "forward"),
        expires_at=expires,
        created_by=str(created_by or ""),
        reason=str(reason or ""),
        origin=str(origin or "manual"),
        origin_ref=str(origin_ref or ""),
        severity=str(severity or ""),
        revoked_at=revoked,
        disabled_at=disabled,
    )


def load_live_rules(client: Client) -> list[Rule]:
    """Every rule that is in force right now. RAISES on failure -- see the module docstring."""
    result = client.query(LIVE_RULE_SQL)
    rules = [_row_to_rule(r) for r in result.result_rows]
    # A second filter, in Python, against the SAME predicate the kernel will be given. If these two
    # ever disagree the SQL is the bug, but enforcing the stricter of the two is the safe direction.
    return [r for r in rules if r.is_live()]


def load_all_rules(client: Client, limit: int = 500) -> list[Rule]:
    """Every rule, including expired and revoked ones, for the GUI's list.

    The distinction from `load_live_rules` matters to the operator: "this rule exists but is not
    enforced" is a different statement from "this rule does not exist", and a view that showed only
    live rules would make a lapsed block look like it had been deleted.
    """
    result = client.query(
        """
        SELECT rule_id, src_cidr, dst_cidr, domain, mode, protocol, dst_port, direction,
               expires_at, created_by, reason, origin, origin_ref, severity, revoked_at,
               disabled_at
        FROM weirvern.sluice_rules FINAL
        ORDER BY created_at DESC
        LIMIT %(lim)s
        """,
        parameters={"lim": int(limit)},
    )
    return [_row_to_rule(r) for r in result.result_rows]


def validate_domain(raw: str) -> str:
    """Normalize and check a domain-rule name. Returns the normalized form or raises.

    ONE PLACE, like the CIDR refusals: the form, the API and any future list importer all come
    through here, so "what is a blockable name" cannot drift into three opinions. Lowercase, no
    trailing dot, at least one dot, labels of [a-z0-9-] (no leading/trailing hyphen), 253 chars
    max. An IP literal is refused politely: a domain rule is for names; addresses have their own
    rule shape and a name-shaped IP would silently match nothing.
    """
    name = str(raw or "").strip().lower().rstrip(".")
    if not name:
        raise SluiceError("a domain rule needs a name")
    # A LEADING `*.` IS HOW AN OPERATOR SAYS "this name AND its subdomains" (the operator,
    # 2026-10-16: "modify it like adding a *"). It is STORED AS TYPED -- what the operator wrote
    # is what every table shows -- and stripped where matching happens (the worker's DNS pass,
    # resolve_domain_ips), because the matcher already treats a name as covering its subdomains.
    # Validated on the name underneath, so `*.example.com` passes exactly the checks example.com
    # does.
    wildcard = name.startswith("*.")
    if wildcard:
        name = name[2:]
        if not name:
            raise SluiceError("`*.` alone is not a name: write `*.example.com`")
    if len(name) > 253:
        raise SluiceError("that domain is longer than 253 characters; it cannot be a real name")
    try:
        ipaddress.ip_address(name)
    except ValueError:
        pass
    else:
        raise SluiceError(
            "that is an IP address, not a domain: block addresses with the source/destination "
            "fields, which the kernel enforces directly")
    if "." not in name:
        raise SluiceError(f"{name!r} has no dot: a domain rule matches names like example.com")
    for label in name.split("."):
        if not label or len(label) > 63 or label.startswith("-") or label.endswith("-"):
            raise SluiceError(f"{name!r} has a label that cannot be a domain label: {label!r}")
        if not all(c.isalnum() or c == "-" for c in label):
            raise SluiceError(f"{name!r} contains characters a domain cannot have")
    return ("*." + name) if wildcard else name


def create_rule(
    client: Client,
    *,
    src_cidr: str = "",
    dst_cidr: str = "",
    domain: str = "",
    mode: str = "block",
    protocol: str = "",
    dst_port: int = 0,
    direction: str = "forward",
    ttl_minutes: int = 60,
    created_by: str = "",
    reason: str = "",
    origin: str = "manual",
    origin_ref: str = "",
    severity: str = "",
    now: datetime | None = None,
) -> Rule:
    """Record a new rule. Validates the addresses; a ttl of 0 means UNTIL REVOKED.

    This function used to refuse a non-positive ttl outright, and the schema backed it up (011:
    "a block is always BOUNDED"). That was the right default and the wrong ceiling: the operator
    asked for the capability explicitly (2026-10-16), so 0 now records `expires_at = NULL`, which
    every reader treats as live-until-revoked. A NEGATIVE value is still refused -- it is a typo,
    not an intention, and there is nothing it could mean.
    """
    now = now or datetime.now(UTC)
    mode = str(mode or "block").strip().lower()
    if mode not in ("alert", "block"):
        raise SluiceError(f"mode must be alert or block, not {mode!r}")
    dom = validate_domain(domain) if str(domain or "").strip() else ""
    if dom:
        # A DOMAIN RULE NAMES A NAME, NOT ADDRESSES. Same reasoning as the source+destination
        # refusal below: a combined predicate would enforce something wider or narrower than it
        # describes, so it is refused at authoring rather than compiled by guess.
        if str(src_cidr or "").strip() or str(dst_cidr or "").strip():
            raise SluiceError(
                "a domain rule names a domain, not addresses: block the domain, or block the "
                "addresses, not both in one rule")
        if str(direction or "forward").strip().lower() != "forward":
            raise SluiceError("a domain rule is a forward rule; inbound domain rules are not supported yet")
        if int(dst_port or 0):
            raise SluiceError(
                "a port-scoped domain rule is not supported yet: the kernel set matches "
                "addresses, so the port would be silently ignored")
        src = dst = ""
    else:
        src = parse_cidr(src_cidr, "source")
        dst = parse_cidr(dst_cidr, "destination")
    if not src and not dst and not dom:
        raise SluiceError("a rule needs at least one address, or a domain")
    if src and dst:
        # A SOURCE AND A DESTINATION DO NOT COMPILE TOGETHER (review round 2026-10-15). The
        # backend installs a source rule as "everything from that source", so accepting both
        # recorded a rule that blocked strictly more than its own description -- and the GUI
        # offers both fields, so this is the shape an operator reaches for. Refused at
        # authoring AND at compile; see _base_ruleset for the second belt.
        raise SluiceError(
            "a rule names a source OR a destination, not both: a source rule installs as "
            "\"everything from that source\" (scoped to a port if one is set), so a combined "
            "rule would block more than it says. Block the source or the destination; to "
            "scope one service, use the port field."
        )
    if direction == "in" and not src:
        raise SluiceError(
            "an inbound rule blocks traffic FROM a source arriving at this sensor; a "
            "destination-only inbound rule would match nothing while reading as enforced. "
            "Give it a source."
        )
    if dst_port and not protocol:
        raise SluiceError("a port needs a protocol: set protocol to tcp or udp")
    if ttl_minutes < 0:
        raise SluiceError(
            "ttl_minutes cannot be negative: 0 means until revoked, and any positive number is "
            "the number of minutes"
        )

    rule = Rule(
        rule_id=new_rule_id(),
        src_cidr=src,
        dst_cidr=dst,
        domain=dom,
        mode=mode,
        protocol=protocol,
        dst_port=int(dst_port),
        direction=direction,
        # 0 -> NULL -> until revoked (schema/014). Not a far-future date: the rules list and the
        # expiry view format this value, and a date meaning "forever" is a lie in both.
        expires_at=((now + timedelta(minutes=int(ttl_minutes))) if int(ttl_minutes) > 0 else None),
        created_by=created_by,
        reason=reason,
        origin=origin,
        origin_ref=origin_ref,
        severity=severity,
    )
    client.insert(
        "weirvern.sluice_rules",
        [[
            rule.rule_id, now, rule.created_by, rule.reason, rule.src_cidr, rule.dst_cidr,
            rule.domain, rule.mode,
            rule.protocol, rule.dst_port, rule.direction, rule.expires_at, rule.origin,
            rule.origin_ref, rule.severity, None, "", "",
        ]],
        column_names=[
            "rule_id", "created_at", "created_by", "reason", "src_cidr", "dst_cidr",
            "domain", "mode",
            "protocol", "dst_port", "direction", "expires_at", "origin", "origin_ref",
            "severity", "revoked_at", "revoked_by", "note",
        ],
    )
    logger.info(
        "sluice: rule %s created by %s for %s until %s (%s)",
        rule.rule_id, created_by or "unknown", rule.describes(),
        rule.expires_at or "revoked", reason or "no reason given",
    )
    return rule


def update_rule_mode(client: Client, rule_id: str, mode: str, *, by: str = "",
                     now: datetime | None = None) -> Rule:
    """Change only the mode -- a thin wrapper over update_rule, kept because callers and tests
    name this operation."""
    return update_rule(client, rule_id, mode=mode, by=by, now=now)


def update_rule(client: Client, rule_id: str, *, mode: str | None = None,
                domain: str | None = None, by: str = "", now: datetime | None = None) -> Rule:
    """Edit a rule in place: its mode and/or its name.

    THE SAME RULE, EDITED. Re-inserted under the SAME rule_id (the table is read with FINAL), so
    the rule's identity, its creation time and its reason survive; the note column records what
    changed. A delete-and-recreate would make the audit trail read as two unrelated rules.

    A DOMAIN MAY ONLY BE EDITED ON A DOMAIN RULE: an address rule's name field is empty on
    purpose, and giving it a name would silently widen what it matches. Refused with a sentence.
    `validate_domain` accepts the `*.` marker, so "adding a *" is a valid edit.
    """
    rid = str(rule_id or "").strip()
    if not rid:
        raise SluiceError("no rule id given")
    want_mode = None if mode is None else str(mode).strip().lower()
    if want_mode is not None and want_mode not in ("alert", "block"):
        raise SluiceError(f"mode must be alert or block, not {want_mode!r}")
    want_domain = validate_domain(domain) if domain is not None else None
    if want_mode is None and want_domain is None:
        raise SluiceError("an edit needs a mode or a domain")
    when = now or datetime.now(UTC)
    rows = client.query(
        "SELECT rule_id, created_at, created_by, reason, src_cidr, dst_cidr, domain, mode, "
        "protocol, dst_port, direction, expires_at, origin, origin_ref, severity, revoked_at, "
        "disabled_at "
        "FROM weirvern.sluice_rules FINAL WHERE rule_id = %(r)s",
        parameters={"r": rid},
    ).result_rows
    if not rows:
        raise SluiceError(f"no rule with id {rid}")
    (rid, created_at, created_by, reason, src, dst, dom, cur, proto, port, direction,
     expires, origin, origin_ref, severity, revoked, was_disabled) = rows[0]
    if revoked is not None:
        raise SluiceError("this rule was revoked; re-arming a revoked rule is a new rule with a "
                           "new reason, not an edit")
    cur_mode, cur_dom = str(cur or "block"), str(dom or "")
    if want_mode is not None and want_mode == cur_mode and want_domain is None:
        raise SluiceError(f"this rule is already in {want_mode} mode")
    if want_domain is not None and not cur_dom:
        raise SluiceError("this rule matches addresses, not a name; there is no domain to edit")
    new_mode = want_mode if want_mode is not None else cur_mode
    new_dom = want_domain if want_domain is not None else cur_dom
    if new_mode == cur_mode and new_dom == cur_dom:
        raise SluiceError("nothing would change")
    changes = []
    if new_mode != cur_mode:
        changes.append(f"mode {cur_mode}->{new_mode}")
    if new_dom != cur_dom:
        changes.append(f"domain {cur_dom or '(none)'}->{new_dom}")
    client.insert(
        "weirvern.sluice_rules",
        [[rid, created_at, created_by, reason, src, dst, new_dom, new_mode, proto, port,
          direction, expires, origin, origin_ref, severity, None, "",
          ("; ".join(changes) + f" by {by or 'operator'} at {when:%Y-%m-%d %H:%M}"),
          was_disabled]],
        column_names=[
            "rule_id", "created_at", "created_by", "reason", "src_cidr", "dst_cidr",
            "domain", "mode",
            "protocol", "dst_port", "direction", "expires_at", "origin", "origin_ref",
            "severity", "revoked_at", "revoked_by", "note", "disabled_at",
        ],
    )
    logger.info("sluice: rule %s edited: %s by %s", rid, "; ".join(changes), by or "unknown")
    return _row_to_rule((rid, src, dst, new_dom, new_mode, proto, port, direction, expires,
                         created_by, reason, origin, origin_ref, severity, None, was_disabled))


def revoke_rule(client: Client, rule_id: str, *, by: str = "", now: datetime | None = None) -> bool:
    """Soft-delete a rule. The record stays readable, because the audit trail of what was blocked
    and why must not be destroyed by the act of unblocking it."""
    now = now or datetime.now(UTC)
    existing = client.query(
        "SELECT rule_id, created_at, created_by, reason, src_cidr, dst_cidr, protocol, dst_port, "
        "direction, expires_at, origin, origin_ref, severity, disabled_at "
        "FROM weirvern.sluice_rules FINAL WHERE rule_id = %(r)s",
        parameters={"r": rule_id},
    ).result_rows
    if not existing:
        return False
    row = list(existing[0])
    client.insert(
        "weirvern.sluice_rules",
        [[
            row[0], row[1], row[2], row[3], row[4], row[5], row[6], row[7], row[8], row[9],
            row[10], row[11], row[12], row[13], now, by, "revoked",
        ]],
        column_names=[
            "rule_id", "created_at", "created_by", "reason", "src_cidr", "dst_cidr",
            "protocol", "dst_port", "direction", "expires_at", "origin", "origin_ref",
            "severity", "disabled_at", "revoked_at", "revoked_by", "note",
        ],
    )
    logger.info("sluice: rule %s revoked by %s", rule_id, by or "unknown")
    return True


def write_gate_state(client: Client, sensor: str, state: GateState,
                     now: datetime | None = None) -> None:
    """Record what the gate is doing, so the GUI can answer without inferring it.

    Written on EVERY pass, including the degraded ones. A gate whose state must be inferred from the
    absence of events is a gate nobody can trust: the operator needs to see "armed" or "DEGRADED,
    and here is why", not an empty panel.
    """
    now = now or datetime.now(UTC)
    client.insert(
        "weirvern.sluice_state",
        [[
            sensor, now, state.state, state.iface, state.mgmt_iface, state.rules_active,
            state.rules_total, state.packets_blocked, state.bytes_blocked, state.detail,
            state.backend, state.backend_expected, state.enforcement,
        ]],
        column_names=[
            "sensor", "updated_at", "state", "iface", "mgmt_iface", "rules_active",
            "rules_total", "packets_blocked", "bytes_blocked", "detail", "backend",
            "backend_expected", "enforcement",
        ],
    )


def load_gate_states(client: Client, limit: int = 50) -> dict:
    """EVERY sensor's last recorded gate state, newest first -- who is enforcing, and where.

    ONE RULE STORE, MANY GATES. The rules are fleet-wide; enforcement happens on every box that
    sits in the path, which in a distributed deployment is the hub AND whichever weirlings can
    install rules. The operator needs to see that list, because "the rule is live" and "the rule is
    blocking on the segment that saw the traffic" are different statements, and only this view can
    tell them apart.

    Staleness is NOT decided here: the caller compares `updated_at` to now, because only it knows
    the expected cadence.
    """
    try:
        rows = client.query(
            """
            SELECT sensor, updated_at, state, iface, rules_active, rules_total,
                   packets_blocked, bytes_blocked, detail, enforcement
            FROM weirvern.sluice_state FINAL
            ORDER BY updated_at DESC
            LIMIT %(lim)s
            """,
            parameters={"lim": int(limit)},
        ).result_rows
    except Exception as exc:  # noqa: BLE001
        logger.warning("could not read the fleet's gate states: %s", exc)
        return {"available": False, "reason": f"{type(exc).__name__}: {exc}", "gates": []}
    return {
        "available": True, "reason": "",
        "gates": [
            {"sensor": str(r[0]), "updated_at": r[1], "state": str(r[2]), "iface": str(r[3]),
             "rules_active": int(r[4] or 0), "rules_total": int(r[5] or 0),
             "packets_blocked": int(r[6] or 0), "bytes_blocked": int(r[7] or 0),
             "detail": str(r[8]), "enforcement": str(r[9] or "")}
            for r in rows
        ],
    }


def load_gate_state(client: Client, sensor: str = "") -> dict:
    """The gate's last recorded state. `available: False` with a reason when it cannot be read.

    Follows the project's route convention: a failure and an empty result must not look alike. A
    gate that was never armed and a gate whose state could not be read are different situations, and
    the operator acts differently on each.

    ── WHY THE ROW IS CHOSEN BY RECENCY AND THAT IS WRONG ON ITS OWN ──────────────────────────
    MEASURED (live, 2026-09-23). This query took the newest row ACROSS ALL SENSORS. The Sluice Gate
    state table is shared, and anything that runs an enforcement pass writes to it -- the worker,
    the CLI, an ad-hoc script. A single harness run that armed and exited left an `armed` row that
    then outranked the worker's own rows, so the panel showed ARMED while the node had zero sluice
    tables. The operator was reading another process's history and had no way to know.

    So when a caller names a sensor, the state is filtered to it. The project already keys
    `sensor_status` per sensor for the same reason. The staleness check covers the remaining case --
    a row that is current but abandoned -- and the two together mean the panel can only ever show
    the named sensor's own state, and can say when even that has stopped.
    """
    try:
        if sensor:
            rows = client.query(
                """
                SELECT sensor, updated_at, state, iface, mgmt_iface, rules_active, rules_total,
                       packets_blocked, bytes_blocked, detail, backend, backend_expected, enforcement
                FROM weirvern.sluice_state FINAL
                WHERE sensor = {sensor:String}
                ORDER BY updated_at DESC
                LIMIT 1
                """,
                parameters={"sensor": sensor},
            ).result_rows
        else:
            rows = client.query(
                """
                SELECT sensor, updated_at, state, iface, mgmt_iface, rules_active, rules_total,
                       packets_blocked, bytes_blocked, detail, backend, backend_expected, enforcement
                FROM weirvern.sluice_state FINAL
                ORDER BY updated_at DESC
                LIMIT 1
                """,
            ).result_rows
    except Exception as exc:  # noqa: BLE001
        return {"available": False, "reason": f"cannot read the gate state: {type(exc).__name__}"}
    if not rows:
        return {
            "available": True, "state": GATE_STATE_DISARMED, "sensor": sensor,
            "detail": "the gate has not run yet, so nothing is being enforced",
            "rules_active": 0, "rules_total": 0, "packets_blocked": 0, "bytes_blocked": 0,
        }
    (name, updated, state, iface, mgmt, active, total, pkts, byts, detail, backend,
     expected, enforcement) = rows[0]
    out = {
        "available": True, "sensor": str(name), "updated_at": updated, "state": str(state),
        "iface": str(iface or ""), "mgmt_iface": str(mgmt or ""), "rules_active": int(active or 0),
        "rules_total": int(total or 0), "packets_blocked": int(pkts or 0),
        "bytes_blocked": int(byts or 0), "detail": str(detail or ""), "backend": str(backend or ""),
        "backend_expected": str(expected or ""),
        # WHICH verified path is enforcing ('channel'/'siphon'/'none'), machine-readable -- the
        # state row explains itself in `detail` too, but an operator should not have to parse
        # English to answer "by what?". See schema/013_channel.sql.
        "enforcement": str(enforcement or ""),
    }
    # A BACKEND MISMATCH IS ITS OWN FINDING. If the gate wanted nft and got the null backend, it is
    # not enforcing whatever the state column says -- so the mismatch is surfaced rather than left
    # for the reader to notice.
    if out["backend"] != out["backend_expected"]:
        out["warning"] = (
            f"the gate is using the {out['backend']!r} backend but expected "
            f"{out['backend_expected']!r}: rules are NOT being enforced by the backend that was "
            "asked for"
        )
        if out["state"] == GATE_STATE_ARMED:
            out["state"] = GATE_STATE_DEGRADED
    # ── A STALE 'ARMED' MUST NOT READ AS CURRENT ─────────────────────────────────────────────
    #
    # MEASURED (live, 2026-09-23). Two of my own test harnesses wrote an 'armed' row, exited, and
    # left it behind. The GUI then showed ARMED with 1 rule enforced while the node had ZERO
    # sluice tables -- the gate was not blocking anything. Every reading on the panel was a
    # historical fact presented as a current one, including the drop counters.
    #
    # The supervisor already refuses to call itself healthy without a recent confirmation
    # (`SluiceSupervisor.healthy`), because "a supervisor that stopped running leaves state=armed
    # behind". That reasoning applies to the ROW as well: whoever wrote it may have died, and the
    # row cannot know. The row's own timestamp is the evidence, so it is used here rather than
    # trusted blindly.
    #
    # HOW THE THRESHOLD IS CHOSEN: the enforcement pass runs every 60s (SLUICE_INTERVAL_S), so a
    # row older than a few intervals means the process that writes it has stopped. 300s is five
    # missed passes -- long enough that a slow cycle or a brief database stall does not trip it,
    # short enough that an operator looking at the panel after a crash is told.
    if out["state"] in (GATE_STATE_ARMED, GATE_STATE_DEGRADED):
        age_s: float | None = None
        try:
            written = out.get("updated_at")
            if isinstance(written, datetime):
                # ClickHouse returns timezone-AWARE datetimes and `datetime.now()` is naive, so the
                # subtraction raises TypeError inside this function -- which a caller's except would
                # turn into "cannot read the gate state", hiding a working gate behind a bug in the
                # staleness check. The project has hit exactly this before; normalise first.
                stamp = written if written.tzinfo else written.replace(tzinfo=UTC)
                age_s = (datetime.now(UTC) - stamp).total_seconds()
        except Exception:  # noqa: BLE001
            # An unreadable timestamp is not evidence of staleness. Leave age_s None, which the
            # check below treats as "cannot say" rather than "stale" -- the same three-state
            # reasoning the stress harness had to adopt after a false DEAD verdict.
            age_s = None
        if age_s is not None:
            out["age_s"] = int(age_s)
            if age_s > 300:
                stale_note = (
                    f"this state was recorded {int(age_s // 60)} minutes ago and the gate writes "
                    "one every minute, so whatever recorded it has stopped. Treat the state and "
                    "the counters below as HISTORICAL: they are what the gate last reported, not "
                    "what it is doing now."
                )
                out["stale"] = True
                existing = out.get("warning")
                out["warning"] = f"{existing} {stale_note}" if existing else stale_note
    return out


def write_events(client: Client, events: list[dict], now: datetime | None = None) -> int:
    """Record blocked flows. Returns the number written.

    Rows are pre-aggregated by the enforcement layer (a per-packet insert would be a denial of
    service on the database), so this writes what it is given. An empty list is a no-op rather than
    a row of zeros: an event row asserts that a block HAPPENED.
    """
    if not events:
        return 0
    now = now or datetime.now(UTC)
    rows = []
    for e in events:
        rows.append([
            e.get("ts", now), str(e.get("rule_id", "")),
            str(e.get("kind", "flow")), str(e.get("domain", "")), str(e.get("query", "")),
            str(e.get("src_addr", "")),
            str(e.get("dst_addr", "")), int(e.get("src_port", 0)), int(e.get("dst_port", 0)),
            str(e.get("protocol", "")), int(e.get("packets", 0)), int(e.get("bytes", 0)),
            e.get("rule_snapshot", "{}"), str(e.get("direction", "forward")),
        ])
    client.insert(
        "weirvern.sluice_events", rows,
        column_names=[
            "ts", "rule_id", "kind", "domain", "query", "src_addr", "dst_addr", "src_port",
            "dst_port", "protocol", "packets", "bytes", "rule_snapshot", "direction",
        ],
    )
    logger.info("sluice: recorded %d event(s)", len(rows))
    return len(rows)


def resolve_domain_ips(client: Client, domain: str, *, window_h: int = 6,
                       cap: int = 512) -> list[str]:
    """The addresses a name currently owns, from the reverse map (schema/016).

    WHAT "CURRENTLY" MEANS: answers seen inside `window_h`, so a domain rule enforces what DNS
    actually resolved the name to recently -- not what it resolved to last month. A name that has
    more addresses than `cap` (a CDN, usually) contributes its most recently seen ones first;
    the cap keeps a single rule from making the kernel set enormous.
    """
    # The `*.` marker is for humans; the suffix clause below already covers subdomains, so it is
    # stripped here rather than special-cased into the SQL.
    name = str(domain or "").strip().lower().rstrip(".").removeprefix("*.")
    if not name:
        return []
    since = datetime.now(UTC) - timedelta(hours=max(1, int(window_h)))
    rows = client.query(
        """
        SELECT ip, max(last_seen) AS ls
        FROM weirvern.dns_reverse_map
        WHERE (domain = %(d)s OR endsWith(domain, %(suf)s)) AND last_seen >= %(since)s
        GROUP BY ip ORDER BY ls DESC LIMIT %(cap)s
        """,
        parameters={"d": name, "suf": "." + name, "since": since, "cap": int(cap)},
    ).result_rows
    return [str(r[0]) for r in rows]


def attach_resolved_ips(client: Client, rules: list[Rule], *, window_h: int = 6,
                        cap: int = 512) -> tuple[list[Rule], list[str]]:
    """Fill each domain rule's `resolved_ips`. Returns (rules, problems) -- problems are NOTES
    for the gate's detail, not exceptions: one unresolvable name must not disarm the rest."""
    problems: list[str] = []
    for r in rules:
        if not r.domain:
            continue
        try:
            r.resolved_ips = resolve_domain_ips(client, r.domain, window_h=window_h, cap=cap)
        except Exception as exc:  # noqa: BLE001
            problems.append(
                f"domain {r.domain}: resolution failed ({type(exc).__name__}); not armed")
            r.resolved_ips = []
    return rules, problems


def derived_rules_for_detections(
    detections: list[dict],
    *,
    policy: str,
    max_ttl_minutes: int,
    auto_score: float = 0.0,
) -> list[dict]:
    """Turn detections into the rules they justify, under the operator's two instruments.

    TWO WAYS IN, deliberately: the SEVERITY POLICY (`SLUICE_CRITICALITY` -- a class with its own
    confidence floor and TTL) and the SCORE THRESHOLD (`SLUICE_AUTO_SCORE` -- "any detection at
    or above this number is blocked"). A detection qualifies through EITHER; when both are set
    the policy is a finer net and the threshold is a hard floor under it. That is the operator's
    own instruction: "any alert over a certain custom threshold is blocked".

    Pure: no database, no kernel. That makes the POLICY testable, which matters because this is the
    part an operator is trusting when they let a model block traffic on their network.

    Returns dicts of rule FIELDS rather than Rules, so the caller decides whether to persist them;
    a function that wrote as a side effect could not be tested against a real detection set without
    a database.

    Two refusals worth naming:
      * A detection with no SOURCE ADDRESS is skipped. There is nothing to block that is not "the
        whole segment", and blocking that is an outage.
      * The TTL is the policy's when a policy applies, else a fixed 30 minutes for a
        score-triggered block -- ALWAYS capped by the operator's ceiling, so no policy change and
        no threshold change can produce a longer block than the operator allowed.
    """
    from weirvern.sluice import CRITICALITY_POLICIES, policy_allows  # noqa: PLC0415

    spec = CRITICALITY_POLICIES.get(policy)
    policy_on = spec is not None and spec["min_severity"] is not None
    if not policy_on and float(auto_score) <= 0.0:
        return []
    # BOTH ARE MINUTES. Naming the parameter after its unit and then dividing by 60 was a units
    # bug: an operator capping blocks at 5 minutes got a 1-minute block (5 // 60 == 0, then the
    # floor of 1 took over). Nothing raised -- the block was simply five times shorter than asked,
    # which is the kind of wrongness only a test on the VALUE can catch.
    if policy_on and spec is not None:
        ttl = max(1, min(int(spec["ttl_minutes"]), int(max_ttl_minutes)))
    else:
        ttl = max(1, min(30, int(max_ttl_minutes)))

    out = []
    for d in detections:
        src = str(d.get("src_addr") or "").strip()
        if not src:
            logger.debug("sluice: skipping a detection with no source address")
            continue
        severity = str(d.get("severity") or "")
        confidence = float(d.get("anomaly_score") or 0.0)
        allowed, why = (policy_allows(policy, severity=severity, confidence=confidence)
                        if policy_on else (False, ""))
        if not allowed and float(auto_score) > 0.0 and confidence >= float(auto_score):
            allowed = True
            why = (f"score {confidence:.2f} is at or above the operator's auto-block threshold "
                   f"{float(auto_score):.2f}")
        if not allowed:
            logger.debug("sluice: not blocking %s: %s", src, why or "below every policy")
            continue
        out.append({
            "src_cidr": src if "/" in src else f"{src}/32",
            "ttl_minutes": ttl,
            "reason": f"detection: {why}",
            "origin": "detection",
            "origin_ref": str(d.get("identity") or d.get("id") or ""),
            "severity": severity,
            "created_by": "detection",
        })
    return out


def set_rule_disabled(client: Client, rule_id: str, disabled: bool, *, by: str = "",
                      now: datetime | None = None) -> Rule:
    """Park a rule, or put it back (the operator, 2026-10-16: "a trashcan and a disable icon next
    to each rule ... a confirm if selected").

    IN PLACE, like every other edit here: same rule_id, same creation, same reason -- the note
    records the flip. Disabling is not revoking: a revoked rule is gone for good, a disabled one
    is waiting to be switched back on, and the list must tell the operator which of those two
    they are looking at.
    """
    rid = str(rule_id or "").strip()
    if not rid:
        raise SluiceError("no rule id given")
    when = now or datetime.now(UTC)
    rows = client.query(
        "SELECT rule_id, created_at, created_by, reason, src_cidr, dst_cidr, domain, mode, "
        "protocol, dst_port, direction, expires_at, origin, origin_ref, severity, revoked_at, "
        "disabled_at FROM weirvern.sluice_rules FINAL WHERE rule_id = %(r)s",
        parameters={"r": rid},
    ).result_rows
    if not rows:
        raise SluiceError(f"no rule with id {rid}")
    (rid, created_at, created_by, reason, src, dst, dom, mode, proto, port, direction,
     expires, origin, origin_ref, severity, revoked, was_disabled) = rows[0]
    if revoked is not None:
        raise SluiceError("this rule is revoked; a revoked rule is gone -- arm a new one instead")
    if (was_disabled is not None) == bool(disabled):
        raise SluiceError("this rule is already " + ("disabled" if disabled else "enabled"))
    new_disabled = when if disabled else None
    note = (f"{'disabled' if disabled else 're-enabled'} by {by or 'operator'} "
            f"at {when:%Y-%m-%d %H:%M}")
    client.insert(
        "weirvern.sluice_rules",
        [[rid, created_at, created_by, reason, src, dst, dom, mode, proto, port, direction,
          expires, origin, origin_ref, severity, None, "", note, new_disabled]],
        column_names=[
            "rule_id", "created_at", "created_by", "reason", "src_cidr", "dst_cidr", "domain",
            "mode", "protocol", "dst_port", "direction", "expires_at", "origin", "origin_ref",
            "severity", "revoked_at", "revoked_by", "note", "disabled_at",
        ],
    )
    logger.info("sluice: rule %s %s by %s", rid, "disabled" if disabled else "re-enabled",
                by or "unknown")
    return _row_to_rule((rid, src, dst, dom, mode, proto, port, direction, expires, created_by,
                         reason, origin, origin_ref, severity, None, new_disabled))


def revoke_rules(client: Client, rule_ids: Sequence[str], *, by: str = "",
                 limit: int = 200) -> dict:
    """Revoke a SELECTION (the operator: "bulk select ... for mass delete"). Bounded on purpose:
    a mass delete is a deliberate act, and one that silently swallowed ten thousand ids would be
    a worse failure than a refusal. Missing ids are REPORTED, never guessed past."""
    ids = [str(r or "").strip() for r in (rule_ids or []) if str(r or "").strip()]
    if not ids:
        raise SluiceError("no rule ids given")
    if len(ids) > int(limit):
        raise SluiceError(f"refusing to revoke {len(ids)} rules at once; the cap is {int(limit)}")
    done: list[str] = []
    missing: list[str] = []
    for rid in ids:
        (done if revoke_rule(client, rid, by=by) else missing).append(rid)
    return {"revoked": done, "missing": missing}
