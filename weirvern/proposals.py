"""Block proposals: the store between "an agent thinks this should be blocked" and "a person did".

WHY THIS MODULE IS TRANSPORT-FREE. Both the MCP server (`fathom`) and the rendered Flask form need
to propose a block and list what is pending. If each talked to ClickHouse itself there would be two
readers of one table with two ideas of what `status` means. So the operations live here, take a
ClickHouse client, and return plain values: the MCP tool and the Flask route are both thin callers.

THE SAFETY PROPERTY. Nothing here blocks anything. `create_proposal` writes a row that enforcement
does not read. `apply_proposal` is the ONLY function that turns a proposal into a rule, and it is
called by a route a signed-in person drives, never by the agent path. That boundary is the reason
the MCP server can offer blocking at all.
"""

from __future__ import annotations

import secrets
from datetime import datetime
from typing import Any

from clickhouse_connect.driver.client import Client

from weirvern import sluice, sluice_store
from weirvern.clock import utcnow

# Three states, and a fourth would be a deliberate schema change rather than something that appears
# at runtime. Exported so callers do not retype the strings.
STATUS_PROPOSED = "proposed"
STATUS_APPLIED = "applied"
STATUS_DISMISSED = "dismissed"
STATUSES = (STATUS_PROPOSED, STATUS_APPLIED, STATUS_DISMISSED)

# A reason is what makes a proposal reviewable. An unexplained one is refused at the door rather than
# stored and hoped over.
MIN_REASON = 4
MAX_REASON = 600


class ProposalError(ValueError):
    """A proposal that cannot be stored, with a sentence the caller can show a person."""


def new_proposal_id() -> str:
    """A short, unguessable id. Not derived from the host: the same host may be proposed twice and a
    derived id would collapse two separate decisions into one row."""
    return "bp_" + secrets.token_hex(8)


def _row_to_proposal(row: dict[str, Any]) -> dict[str, Any]:
    """Wire shape. Datetimes become ISO strings so both a JSON response and a template can use it."""
    decided = row.get("decided_at")
    proposed = row.get("proposed_at")
    return {
        "proposal_id": row.get("proposal_id", ""),
        "proposed_by": row.get("proposed_by", ""),
        "host": row.get("host", ""),
        "reason": row.get("reason", ""),
        "evidence": row.get("evidence", "") or "",
        "ttl_minutes": int(row.get("ttl_minutes") or 0),
        "status": row.get("status", STATUS_PROPOSED),
        "proposed_at": proposed.isoformat() if isinstance(proposed, datetime) else str(proposed or ""),
        "decided_at": decided.isoformat() if isinstance(decided, datetime) else "",
        "decided_by": row.get("decided_by", "") or "",
        "rule_id": row.get("rule_id", "") or "",
    }


def _clean(request: dict[str, Any]) -> dict[str, Any]:
    """Validate a proposal before it can be stored.

    VALIDATION HAPPENS HERE, NOT AT APPLY TIME. A proposal whose host cannot become a rule is worse
    than no proposal: it looks actionable, a person clicks it, and the failure surfaces later in a
    place that cannot explain itself. `sluice` already knows what a usable target looks like and what
    it would cost, so this asks it rather than inventing a second opinion.
    """
    host = str(request.get("host") or "").strip()
    reason = str(request.get("reason") or "").strip()
    evidence = str(request.get("evidence") or "").strip()[:400]
    proposed_by = str(request.get("proposed_by") or "").strip() or "unknown"

    if not host:
        raise ProposalError("a host or domain is required")
    if len(reason) < MIN_REASON:
        raise ProposalError(
            f"a reason of at least {MIN_REASON} characters is required: an unexplained block "
            f"proposal cannot be reviewed"
        )
    if len(reason) > MAX_REASON:
        raise ProposalError(f"the reason is longer than {MAX_REASON} characters")

    try:
        ttl = int(request.get("ttl_minutes") or 0)
    except (TypeError, ValueError):
        raise ProposalError("the duration must be a whole number of minutes") from None
    if ttl < 0:
        raise ProposalError("the duration cannot be negative")

    # THE SHAPE IS CHECKED HERE; THE DEPLOYMENT IS CHECKED AT APPLY TIME. `sluice.parse_cidr` and
    # `sluice_store.validate_domain` are the module that decides whether a target is well formed, so
    # this asks them rather than inventing a second opinion. `sluice.refuse_reason` is deliberately
    # NOT called: it is keyword-only and needs the interface and management interface, which are
    # deployment facts this layer does not have. `create_rule` runs it when the proposal is applied,
    # so a host that is well formed but unroutable on this box is refused there, in the place that
    # can also say which interface made it impossible.
    try:
        if _looks_like_ipv4(host):
            sluice.parse_cidr(host, "dst_cidr")
        else:
            sluice_store.validate_domain(host)
    except Exception as exc:  # noqa: BLE001
        raise ProposalError(f"{host} is not a target a rule could block: {exc}") from None

    return {
        "proposal_id": new_proposal_id(),
        "proposed_by": proposed_by,
        "host": host,
        "reason": reason,
        "evidence": evidence,
        "ttl_minutes": ttl,
        "status": STATUS_PROPOSED,
    }


def _looks_like_ipv4(value: str) -> bool:
    parts = value.split(".")
    if len(parts) != 4:
        return False
    return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def create_proposal(client: Client, request: dict[str, Any]) -> dict[str, Any]:
    """Store a proposal. Changes NOTHING about enforcement."""
    clean = _clean(request)
    client.insert(
        "weirvern.block_proposals",
        [[clean["proposal_id"], clean["proposed_by"], clean["host"], clean["reason"],
          clean["evidence"], clean["ttl_minutes"], clean["status"]]],
        column_names=["proposal_id", "proposed_by", "host", "reason", "evidence",
                      "ttl_minutes", "status"],
    )
    return clean


def load_proposals(client: Client, *, status: str | None = None,
                   limit: int = 100) -> list[dict[str, Any]]:
    """The proposals, newest first, optionally filtered to one status.

    FINAL because the table is Replacing: without it a decided proposal also appears once per
    version, so a queue would show the same host twice with two different answers.
    """
    where = ""
    params: dict[str, Any] = {}
    if status:
        if status not in STATUSES:
            raise ProposalError(f"status must be one of {', '.join(STATUSES)}")
        where = "WHERE status = %(status)s"
        params["status"] = status
    rows = client.query(
        f"""
        SELECT proposal_id, proposed_by, host, reason, evidence, ttl_minutes, status,
               proposed_at, decided_at, decided_by, rule_id
        FROM weirvern.block_proposals FINAL
        {where}
        ORDER BY proposed_at DESC
        LIMIT {int(limit)}
        """,  # nosec B608 - the only interpolation is a capped int
        parameters=params,
    ).result_rows
    names = ["proposal_id", "proposed_by", "host", "reason", "evidence", "ttl_minutes", "status",
             "proposed_at", "decided_at", "decided_by", "rule_id"]
    return [_row_to_proposal(dict(zip(names, row, strict=False))) for row in rows]


def apply_proposal(client: Client, proposal_id: str, *, by: str,
                   direction: str = "forward") -> dict[str, Any]:
    """Turn a proposal into a live rule. THE ONLY FUNCTION HERE THAT CHANGES ENFORCEMENT.

    Called by a route a signed-in person drives. The rule is created through `sluice_store.create_rule`
    with the same validation any other rule gets, so applying a proposal cannot bypass a refusal that
    a manual rule would hit. If the rule write fails, the proposal is NOT marked applied: a proposal
    that says "applied" with no rule behind it would be a false record of enforcement.
    """
    if not proposal_id:
        raise ProposalError("a proposal id is required")
    found = [p for p in load_proposals(client, limit=1000) if p["proposal_id"] == proposal_id]
    if not found:
        raise ProposalError(f"no proposal {proposal_id!r}")
    prop = found[0]
    if prop["status"] != STATUS_PROPOSED:
        raise ProposalError(
            f"proposal {proposal_id} is already {prop['status']}; nothing to apply"
        )

    rule = sluice_store.create_rule(
        client,
        mode="block",
        domain=prop["host"] if not _looks_like_ipv4(prop["host"]) else "",
        dst_cidr=prop["host"] if _looks_like_ipv4(prop["host"]) else "",
        direction=direction,
        ttl_minutes=prop["ttl_minutes"],
        reason=prop["reason"],
        created_by=by,
        origin="proposal",
        origin_ref=prop["proposal_id"],
    )
    rule_id = getattr(rule, "rule_id", "") or ""
    decided_at = utcnow()
    client.insert(
        "weirvern.block_proposals",
        [[prop["proposal_id"], prop["proposed_by"], prop["host"], prop["reason"],
          prop["evidence"], prop["ttl_minutes"], STATUS_APPLIED, prop["proposed_at"],
          decided_at, by, rule_id]],
        column_names=["proposal_id", "proposed_by", "host", "reason", "evidence", "ttl_minutes",
                      "status", "proposed_at", "decided_at", "decided_by", "rule_id"],
    )
    return {**prop, "status": STATUS_APPLIED, "decided_by": by, "rule_id": rule_id}


def dismiss_proposal(client: Client, proposal_id: str, *, by: str) -> dict[str, Any]:
    """Record that a person declined it. Keeps the row: "we saw this and said no, because" is the
    fact that stops the same proposal being re-litigated every week."""
    if not proposal_id:
        raise ProposalError("a proposal id is required")
    found = [p for p in load_proposals(client, limit=1000) if p["proposal_id"] == proposal_id]
    if not found:
        raise ProposalError(f"no proposal {proposal_id!r}")
    prop = found[0]
    if prop["status"] != STATUS_PROPOSED:
        raise ProposalError(f"proposal {proposal_id} is already {prop['status']}")
    client.insert(
        "weirvern.block_proposals",
        [[prop["proposal_id"], prop["proposed_by"], prop["host"], prop["reason"],
          prop["evidence"], prop["ttl_minutes"], STATUS_DISMISSED, prop["proposed_at"],
          utcnow(), by, ""]],
        column_names=["proposal_id", "proposed_by", "host", "reason", "evidence", "ttl_minutes",
                      "status", "proposed_at", "decided_at", "decided_by", "rule_id"],
    )
    return {**prop, "status": STATUS_DISMISSED, "decided_by": by}
