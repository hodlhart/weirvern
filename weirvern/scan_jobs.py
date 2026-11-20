"""Manual scan jobs: the operator's request and the scanner's lease.

A job is deliberately a row in ClickHouse rather than an HTTP call from the GUI to the scanner.
The GUI and the scanner are separate Deployments; a queue lets the scanner stay offline, lets a
pod restart preserve the request, and gives the Assets view a durable answer to "did my scan
start?". The scanner claims with a lease so a dead pod's work is reclaimable, and every state
change is a replacement row keyed by job_id.
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

JOB_COLUMNS = [
    "job_id", "asset_key", "ip", "requested_by", "requested_at", "state",
    "lease_owner", "lease_until", "started_at", "finished_at", "result", "error",
]
ACTIVE_STATES = ("queued", "claimed")


def _now() -> datetime:
    return datetime.now(UTC)


def _row(job: dict[str, Any]) -> list[Any]:
    return [job.get(column) for column in JOB_COLUMNS]


def _insert(client: Any, job: dict[str, Any]) -> None:
    client.insert("weirvern.scan_jobs", [_row(job)], column_names=JOB_COLUMNS)


def find_asset(client: Any, ip: str) -> dict[str, Any] | None:
    rows = client.query(
        "SELECT asset_key, ip, mac, hostname, first_seen, last_seen, scan_state, "
        "       last_scan_at, scan_error, source FROM weirvern.asset_registry FINAL "
        "WHERE ip = %(ip)s ORDER BY last_seen DESC LIMIT 1",
        parameters={"ip": ip},
    ).result_rows
    if not rows:
        return None
    columns = ["asset_key", "ip", "mac", "hostname", "first_seen", "last_seen",
               "scan_state", "last_scan_at", "scan_error", "source"]
    return dict(zip(columns, rows[0], strict=False))


def active_for_asset(client: Any, asset_key: str) -> dict[str, Any] | None:
    rows = client.query(
        "SELECT job_id, asset_key, ip, requested_by, requested_at, state, lease_owner, "
        "       lease_until, started_at, finished_at, result, error "
        "FROM weirvern.scan_jobs FINAL "
        "WHERE asset_key = %(asset_key)s AND state IN ('queued', 'claimed') "
        "ORDER BY requested_at DESC LIMIT 1",
        parameters={"asset_key": asset_key},
    ).result_rows
    return dict(zip(JOB_COLUMNS, rows[0], strict=False)) if rows else None


def create_job(client: Any, asset: dict[str, Any], requested_by: str = "operator") -> dict[str, Any]:
    """Queue one host scan. The caller checks `active_for_asset` first to avoid a queue of
    identical requests; the scanner still treats the scan itself as idempotent."""
    job = {
        "job_id": str(uuid.uuid4()),
        "asset_key": str(asset["asset_key"]),
        "ip": str(asset["ip"]),
        "requested_by": (requested_by or "operator")[:80],
        "requested_at": _now(),
        "state": "queued",
        "lease_owner": "",
        "lease_until": None,
        "started_at": None,
        "finished_at": None,
        "result": "",
        "error": "",
    }
    _insert(client, job)
    return job


def claim_next_job(client: Any, owner: str, lease_s: int = 900) -> dict[str, Any] | None:
    """Claim the oldest queued job, or one whose lease has expired."""
    now = _now()
    rows = client.query(
        "SELECT job_id, asset_key, ip, requested_by, requested_at, state, lease_owner, "
        "       lease_until, started_at, finished_at, result, error "
        "FROM weirvern.scan_jobs FINAL "
        "WHERE state = 'queued' OR (state = 'claimed' AND lease_until < %(now)s) "
        "ORDER BY requested_at ASC LIMIT 1",
        parameters={"now": now},
    ).result_rows
    if not rows:
        return None
    job = dict(zip(JOB_COLUMNS, rows[0], strict=False))
    job.update({
        "state": "claimed",
        "lease_owner": (owner or "scanner")[:120],
        "lease_until": now + timedelta(seconds=max(30, int(lease_s))),
        "started_at": now,
        "finished_at": None,
        "result": "",
        "error": "",
    })
    _insert(client, job)
    return job


def finish_job(client: Any, job: dict[str, Any], *, ok: bool, result: str = "",
               error: str = "") -> None:
    now = _now()
    job.update({
        "state": "done" if ok else "error",
        "finished_at": now,
        "lease_until": None,
        "result": (result or ("scan completed" if ok else ""))[:500],
        "error": ("" if ok else (error or "scan failed"))[:500],
    })
    _insert(client, job)


def get_job(client: Any, job_id: str) -> dict[str, Any] | None:
    """One job by id, for a URL that addresses a single scan.

    The queue read answers with the most recent 20 jobs, so a bookmarked job id would fall out
    of the list while the job still existed. This lookup keeps the sheet's subject addressable
    for as long as the row exists, and returns None rather than inventing a state when it does
    not.
    """
    rows = client.query(
        "SELECT job_id, asset_key, ip, requested_by, requested_at, state, lease_owner, "
        "       lease_until, started_at, finished_at, result, error "
        "FROM weirvern.scan_jobs FINAL WHERE job_id = %(job_id)s LIMIT 1",
        parameters={"job_id": job_id},
    ).result_rows
    return dict(zip(JOB_COLUMNS, rows[0], strict=False)) if rows else None


def list_jobs(client: Any, ip: str = "", limit: int = 20) -> list[dict[str, Any]]:
    params: dict[str, Any] = {"limit": max(1, min(int(limit), 100))}
    where = ""
    if ip:
        where = "WHERE ip = %(ip)s "
        params["ip"] = ip
    rows = client.query(
        "SELECT job_id, asset_key, ip, requested_by, requested_at, state, lease_owner, "
        "       lease_until, started_at, finished_at, result, error "
        f"FROM weirvern.scan_jobs FINAL {where}"
        "ORDER BY requested_at DESC LIMIT %(limit)s",
        parameters=params,
    ).result_rows
    return [dict(zip(JOB_COLUMNS, row, strict=False)) for row in rows]
