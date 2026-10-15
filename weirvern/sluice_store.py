"""Sluice Gate: the database side. Rules in, state out.

Kept apart from `weirvern/sluice.py` on purpose. That module is the DECISION layer -- what a rule
means, whether it is still in force, what the kernel should be told -- and it is testable without a
database. This one is the STORE: reading rules out, writing events and gate state in. Mixing them
would make the decision layer need ClickHouse to be importable, which is how a unit test becomes an
integration test without anyone deciding that.

THE READ PATH IS THE ONE THAT MATTERS HERE, because it is what the enforcement loop calls every
minute. Two things are deliberate:

  * The live-rule filter is applied in SQL (`revoked_at IS NULL AND expires_at > now()`) AND again
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
SELECT rule_id, src_cidr, dst_cidr, protocol, dst_port, direction, expires_at,
       created_by, reason, origin, origin_ref, severity, revoked_at
FROM weirvern.sluice_rules FINAL
WHERE revoked_at IS NULL
  AND expires_at > now()
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
    (rule_id, src, dst, proto, port, direction, expires, created_by, reason,
     origin, origin_ref, severity, revoked) = row
    return Rule(
        rule_id=str(rule_id),
        src_cidr=str(src or ""),
        dst_cidr=str(dst or ""),
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
        SELECT rule_id, src_cidr, dst_cidr, protocol, dst_port, direction, expires_at,
               created_by, reason, origin, origin_ref, severity, revoked_at
        FROM weirvern.sluice_rules FINAL
        ORDER BY created_at DESC
        LIMIT %(lim)s
        """,
        parameters={"lim": int(limit)},
    )
    return [_row_to_rule(r) for r in result.result_rows]


def create_rule(
    client: Client,
    *,
    src_cidr: str = "",
    dst_cidr: str = "",
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
    """Record a new rule. Validates the addresses, and REFUSES to record one with no expiry.

    The expiry is required here as well as in the schema because this is the function a future
    caller is most likely to use to mean "block this forever", and "forever" is exactly what this
    system does not offer. A caller wanting permanence must renew, and the renewal is a decision
    they can see.
    """
    now = now or datetime.now(UTC)
    src = parse_cidr(src_cidr, "source")
    dst = parse_cidr(dst_cidr, "destination")
    if not src and not dst:
        raise SluiceError("a rule needs at least one address: a source or a destination")
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
    if ttl_minutes <= 0:
        raise SluiceError(
            "ttl_minutes must be positive: this system does not create permanent blocks. "
            "Use a long ttl and renew it if that is what you want, so the decision stays visible."
        )

    rule = Rule(
        rule_id=new_rule_id(),
        src_cidr=src,
        dst_cidr=dst,
        protocol=protocol,
        dst_port=int(dst_port),
        direction=direction,
        expires_at=now + timedelta(minutes=int(ttl_minutes)),
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
            rule.protocol, rule.dst_port, rule.direction, rule.expires_at, rule.origin,
            rule.origin_ref, rule.severity, None, "", "",
        ]],
        column_names=[
            "rule_id", "created_at", "created_by", "reason", "src_cidr", "dst_cidr",
            "protocol", "dst_port", "direction", "expires_at", "origin", "origin_ref",
            "severity", "revoked_at", "revoked_by", "note",
        ],
    )
    logger.info(
        "sluice: rule %s created by %s for %s until %s (%s)",
        rule.rule_id, created_by or "unknown", rule.describes(), rule.expires_at, reason or "no reason given",
    )
    return rule


def revoke_rule(client: Client, rule_id: str, *, by: str = "", now: datetime | None = None) -> bool:
    """Soft-delete a rule. The record stays readable, because the audit trail of what was blocked
    and why must not be destroyed by the act of unblocking it."""
    now = now or datetime.now(UTC)
    existing = client.query(
        "SELECT rule_id, created_at, created_by, reason, src_cidr, dst_cidr, protocol, dst_port, "
        "direction, expires_at, origin, origin_ref, severity FROM weirvern.sluice_rules FINAL "
        "WHERE rule_id = %(r)s",
        parameters={"r": rule_id},
    ).result_rows
    if not existing:
        return False
    row = list(existing[0])
    client.insert(
        "weirvern.sluice_rules",
        [[
            row[0], row[1], row[2], row[3], row[4], row[5], row[6], row[7], row[8], row[9],
            row[10], row[11], row[12], now, by, "revoked",
        ]],
        column_names=[
            "rule_id", "created_at", "created_by", "reason", "src_cidr", "dst_cidr",
            "protocol", "dst_port", "direction", "expires_at", "origin", "origin_ref",
            "severity", "revoked_at", "revoked_by", "note",
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
            e.get("ts", now), str(e.get("rule_id", "")), str(e.get("src_addr", "")),
            str(e.get("dst_addr", "")), int(e.get("src_port", 0)), int(e.get("dst_port", 0)),
            str(e.get("protocol", "")), int(e.get("packets", 0)), int(e.get("bytes", 0)),
            e.get("rule_snapshot", "{}"), str(e.get("direction", "forward")),
        ])
    client.insert(
        "weirvern.sluice_events", rows,
        column_names=[
            "ts", "rule_id", "src_addr", "dst_addr", "src_port", "dst_port", "protocol",
            "packets", "bytes", "rule_snapshot", "direction",
        ],
    )
    logger.info("sluice: recorded %d blocked flow(s)", len(rows))
    return len(rows)


def derived_rules_for_detections(
    detections: list[dict],
    *,
    policy: str,
    max_ttl_minutes: int,
) -> list[dict]:
    """Turn detections into the rules they justify, under the operator's criticality policy.

    Pure: no database, no kernel. That makes the POLICY testable, which matters because this is the
    part an operator is trusting when they let a model block traffic on their network.

    Returns dicts of rule FIELDS rather than Rules, so the caller decides whether to persist them;
    a function that wrote as a side effect could not be tested against a real detection set without
    a database.

    Two refusals worth naming:
      * A detection with no SOURCE ADDRESS is skipped. There is nothing to block that is not "the
        whole segment", and blocking that is an outage.
      * The TTL is the policy's, CAPPED by the operator's ceiling. A policy change must never be
        able to produce a longer block than the operator allowed.
    """
    from weirvern.sluice import CRITICALITY_POLICIES, policy_allows  # noqa: PLC0415

    spec = CRITICALITY_POLICIES.get(policy)
    if spec is None or spec["min_severity"] is None:
        return []
    # BOTH ARE MINUTES. Naming the parameter after its unit and then dividing by 60 was a units
    # bug: an operator capping blocks at 5 minutes got a 1-minute block (5 // 60 == 0, then the
    # floor of 1 took over). Nothing raised -- the block was simply five times shorter than asked,
    # which is the kind of wrongness only a test on the VALUE can catch.
    ttl = max(1, min(int(spec["ttl_minutes"]), int(max_ttl_minutes)))

    out = []
    for d in detections:
        src = str(d.get("src_addr") or "").strip()
        if not src:
            logger.debug("sluice: skipping a detection with no source address")
            continue
        severity = str(d.get("severity") or "")
        confidence = float(d.get("anomaly_score") or 0.0)
        allowed, why = policy_allows(policy, severity=severity, confidence=confidence)
        if not allowed:
            logger.debug("sluice: not blocking %s: %s", src, why)
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
