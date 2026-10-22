"""The durable hub<->remote capture-probe handoff.

WHY A TABLE, NOT A GATEWAY-SIDE FUTURE: a remote unit is polled by its own agent; the hub cannot
open a connection to it. The request must survive a GUI restart or a gateway outage, exactly like
the remote Sonar queue. This store is deliberately narrow: create, claim, read, finish. The
probe itself belongs to the sensor's process, which is the only process with its NIC counters.

A PROBE IS READ-ONLY. Nothing here changes a plan, a mode or a sysctl. A silent port is a valid
`observed=false` result, not a failure; `error` is reserved for a probe that could not run.
"""
from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Any

from clickhouse_connect.driver.client import Client

TABLE = "weirvern.weirling_probe_requests"
DEFAULT_SECONDS = 30
MIN_SECONDS = 5
MAX_SECONDS = 120


def new_request_id() -> str:
    return f"probe-{datetime.now(UTC):%Y%m%d%H%M%S}-{uuid.uuid4().hex[:8]}"


def create_request(client: Client, *, sensor_id: str, iface: str,
                   seconds: int = DEFAULT_SECONDS) -> dict[str, Any]:
    """Queue one probe. Returns the request document (which is also the row)."""
    seconds = max(MIN_SECONDS, min(MAX_SECONDS, int(seconds)))
    now = datetime.now(UTC)
    row = {
        "request_id": new_request_id(),
        "sensor_id": str(sensor_id),
        "iface": str(iface or ""),
        "seconds": seconds,
        "status": "pending",
        "result": "",
        "error": "",
        "requested_at": now,
        "updated_at": now,
    }
    client.insert(
        TABLE,
        [[row[k] for k in ("request_id", "sensor_id", "iface", "seconds", "status",
                           "result", "error", "requested_at", "updated_at")]],
        column_names=["request_id", "sensor_id", "iface", "seconds", "status", "result",
                      "error", "requested_at", "updated_at"],
    )
    return row


def get_request(client: Client, request_id: str) -> dict[str, Any] | None:
    rows = list(client.query(
        "SELECT request_id, sensor_id, iface, seconds, status, result, error, "
        "requested_at, updated_at "
        f"FROM {TABLE} FINAL WHERE request_id = %(id)s LIMIT 1",
        parameters={"id": str(request_id)},
    ).named_results())
    return dict(rows[0]) if rows else None


def claim_next(client: Client, sensor_id: str) -> dict[str, Any] | None:
    """Atomically-ish claim the oldest pending probe for this authenticated sensor.

    The gateway authenticates the sensor before calling this; the sensor_id in the WHERE is a
    second fence so a unit cannot claim another unit's request. The status changes to `running`
    before the reply is sent, so a second poll cannot run the same probe twice. ReplacingMergeTree
    needs a newer `updated_at`; the caller's next claim reads FINAL.
    """
    rows = list(client.query(
        "SELECT request_id, sensor_id, iface, seconds, status, result, error, requested_at "
        f"FROM {TABLE} FINAL WHERE sensor_id = %(s)s AND status = 'pending' "
        "ORDER BY requested_at ASC LIMIT 1",
        parameters={"s": str(sensor_id)},
    ).named_results())
    if not rows:
        return None
    row = dict(rows[0])
    finish(client, row, status="running")
    return row


def finish(client: Client, row: dict[str, Any], *, status: str, result: dict | None = None,
           error: str = "") -> None:
    """Write the terminal state with a newer version."""
    now = datetime.now(UTC)
    client.insert(
        TABLE,
        [[row["request_id"], row["sensor_id"], row.get("iface", ""), int(row.get("seconds") or 0),
          status, json.dumps(result or {}, default=str) if result is not None else "",
          str(error or "")[:2000], row.get("requested_at") or now, now]],
        column_names=["request_id", "sensor_id", "iface", "seconds", "status", "result",
                      "error", "requested_at", "updated_at"],
    )
