"""The operator's model actions: force a retrain, then keep or trash what it produced.

This module is the STORE -- rows in `weirvern.model_actions` -- and nothing else. The worker
executes; the GUI files requests and reads results; both go through here.

TWO STATES THAT MUST NEVER BE CONFLATED, which is most of why this file is explicit:

  * A request in state `requested` that is not moving is a request NOBODY PICKED UP. The worker
    may be down, or between cycles. It is not "working on it", and the GUI says so.
  * A candidate in state `done` is a trained model sitting on disk that is NOT scoring anything.
    Nothing in the running pipeline reads it until a `keep` moves it into place. That is the
    point of the whole exchange: the operator sees what the retrain produced before the model
    that is watching their network is replaced.
"""

from __future__ import annotations

import json
import logging
import random
import string
from datetime import UTC, date, datetime
from typing import Any

from clickhouse_connect.driver.client import Client

logger = logging.getLogger(__name__)

ACTIONS_TABLE = "weirvern.model_actions"
RETRAIN = "retrain"
KEEP = "keep"
TRASH = "trash"

# The states a row can be in, per action. Named here so the GUI and the worker cannot drift.
REQUESTED = "requested"
RUNNING = "running"
DONE = "done"
FAILED = "failed"
APPLIED = "applied"
DISCARDED = "discarded"


def new_action_id(now: datetime | None = None) -> str:
    """`<UTC timestamp>-<4 random chars>`, the same shape the rule store uses."""
    now = now or datetime.now(UTC)
    tail = "".join(random.choices(string.ascii_lowercase + string.digits, k=4))
    return f"{now.strftime('%Y%m%d%H%M%S')}-{tail}"


def request(client: Client, *, action: str, by: str = "", target_id: str = "",
            note: str = "", now: datetime | None = None) -> str:
    """File a request. Returns its action_id.

    No deduplication: two retrains filed a second apart are two requests, and collapsing them
    would hide that the operator asked twice (which usually means the first one failed in a way
    they did not see). The worker takes them oldest first.
    """
    if action not in (RETRAIN, KEEP, TRASH):
        raise ValueError(f"unknown model action {action!r}")
    now = now or datetime.now(UTC)
    action_id = new_action_id(now)
    client.insert(
        ACTIONS_TABLE,
        [[now, action_id, action, REQUESTED, target_id, by, note, ""]],
        column_names=["ts", "action_id", "action", "state", "target_id",
                      "requested_by", "note", "report"],
    )
    logger.info("model action %s (%s) requested by %s", action_id, action, by or "unknown")
    return action_id


def _get(client: Client, action_id: str) -> dict[str, Any] | None:
    rows = client.query(
        f"""
        SELECT ts, action_id, action, state, target_id, requested_by, note, report
        FROM {ACTIONS_TABLE} FINAL
        WHERE action_id = %(a)s
        """,
        parameters={"a": action_id},
    ).result_rows
    if not rows:
        return None
    ts, aid, action, state, target_id, by, note, report = rows[0]
    return {"ts": ts, "action_id": str(aid), "action": str(action), "state": str(state),
            "target_id": str(target_id), "requested_by": str(by), "note": str(note),
            "report": str(report)}


def _json_default(value):
    """The last resort for `json.dumps(report)` at the state-write boundary. A datetime is the
    known case (detector metadata windows, issue #5). ANYTHING ELSE STAYS LOUD: the default
    converts the one type the report is known to carry and re-raises for the rest, because a
    report that cannot be serialized should fail visibly rather than silently become a string
    that no reader expects."""
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    raise TypeError(f"the action report carries {type(value).__name__}, which json cannot hold")


def finish(client: Client, action_id: str, state: str, *, report: dict | None = None,
           note: str = "", now: datetime | None = None) -> bool:
    """Move a row to a new state, keeping every other field.

    A COPY, written as a new version of the same action_id (ReplacingMergeTree keeps the newest),
    so the row stays one row: a state machine whose history is a trail of rows would make "what
    is the state of this action" a query with an opinion in it.
    """
    row = _get(client, action_id)
    if row is None:
        logger.warning("model action %s vanished before it could be moved to %s", action_id, state)
        return False
    now = now or datetime.now(UTC)
    client.insert(
        ACTIONS_TABLE,
        [[now, action_id, row["action"], state, row["target_id"], row["requested_by"],
          note or row["note"],
          json.dumps(report, default=_json_default) if report is not None else row["report"]]],
        column_names=["ts", "action_id", "action", "state", "target_id",
                      "requested_by", "note", "report"],
    )
    logger.info("model action %s -> %s", action_id, state)
    return True


def reap_running(client: Client, *, note: str = "", before=None) -> int:
    """Mark every `running` action as FAILED -- on STARTUP, by the only process that runs them.

    WHY THIS IS SAFE AND NECESSARY. Exactly one process executes these actions (the worker), so a
    row in `running` at worker startup is by definition ORPHANED: the process that was carrying it
    out is gone (a deploy rolled the pod, an OOM kill, a crash) and nothing will ever finish it. Left
    alone it is the worst state this table can hold -- "running" reads as a worker that is busy, the
    operator waits, and the panel never changes. Measured: a deploy during a retrain left exactly
    that row, which is how this function came to exist.

    It is called at startup, BEFORE the cycle can file anything of its own, so it cannot race a
    legitimately running action.
    """
    reaped = 0
    # `before` -- MEASURED ON THE DEPLOYMENT (2026-10-16): a retrain filed from the console seconds
    # before a rollout survived the startup reap and sat in `running` forever, because the old pod's
    # write had not been committed when the new pod ran its one-shot query. A one-shot reap RACES
    # ITS OWN PREDECESSOR. The process start time is the race-free line: exactly one process runs
    # these actions, so any `running` row stamped before THIS process began cannot be live -- no
    # matter when the query happens to run. The startup call passes nothing (everything running is
    # orphaned then); the cycle passes the worker's start time, so a race can only delay the verdict.
    where = "state = %(s)s" if before is None else "state = %(s)s AND ts < %(before)s"
    for state in (RUNNING,):
        # BATCHED IN A LOOP (issue #29): the single LIMIT 50 pass stranded everything past
        # the 50th row until the NEXT call -- at startup, that meant a mass failure above 50
        # rows needed several restarts to clear. Batches of 50 are reaped until one comes
        # back short; the batch bound stays so one query never materialises a giant result.
        # The 200-batch ceiling (10k rows) only guards against a `finish` that silently
        # fails to change state, which would otherwise spin forever.
        for _batch in range(200):
            rows = client.query(
                f"SELECT action_id FROM {ACTIONS_TABLE} FINAL WHERE {where} LIMIT 50",
                parameters={"s": state, "before": before} if before is not None else {"s": state},
            ).result_rows
            for (action_id,) in rows:
                finish(client, str(action_id), FAILED,
                       note=note or "the worker restarted while this was running; file it again")
                reaped += 1
            if len(rows) < 50:
                break
        else:
            logger.warning("model actions: reap hit its 200-batch ceiling; some rows may remain")
    if reaped:
        logger.warning("model actions: %d orphaned row(s) marked failed at startup", reaped)
    return reaped


def pending(client: Client, action: str) -> list[dict[str, Any]]:
    """Requests of one kind that nobody has picked up yet, OLDEST FIRST."""
    rows = client.query(
        f"""
        SELECT ts, action_id, action, state, target_id, requested_by, note, report
        FROM {ACTIONS_TABLE} FINAL
        WHERE action = %(a)s AND state = %(s)s
        ORDER BY ts ASC
        LIMIT 20
        """,
        parameters={"a": action, "s": REQUESTED},
    ).result_rows
    return [{"ts": ts, "action_id": str(aid), "action": str(act), "state": str(state),
             "target_id": str(target), "requested_by": str(by), "note": str(note),
             "report": str(report)}
            for ts, aid, act, state, target, by, note, report in rows]


def latest(client: Client, action: str) -> dict[str, Any] | None:
    """The newest row of one kind, whatever state it is in -- what the GUI shows."""
    rows = client.query(
        f"""
        SELECT ts, action_id, action, state, target_id, requested_by, note, report
        FROM {ACTIONS_TABLE} FINAL
        WHERE action = %(a)s
        ORDER BY ts DESC
        LIMIT 1
        """,
        parameters={"a": action},
    ).result_rows
    if not rows:
        return None
    ts, aid, act, state, target, by, note, report = rows[0]
    return {"ts": ts, "action_id": str(aid), "action": str(act), "state": str(state),
            "target_id": str(target), "requested_by": str(by), "note": str(note),
            "report": str(report)}
