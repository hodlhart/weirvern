"""Manual scan jobs: the operator's request and the scanner's lease.

A job is deliberately a row in ClickHouse rather than an HTTP call from the GUI to the scanner.
The GUI and the scanner are separate Deployments; a queue lets the scanner stay offline, lets a
pod restart preserve the request, and gives the Assets view a durable answer to "did my scan
start?". The scanner claims with a lease so a dead pod's work is reclaimable, and every state
change is a replacement row keyed by job_id.
"""
from __future__ import annotations

import ipaddress
import uuid
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from typing import Any

JOB_COLUMNS = [
    "job_id", "asset_key", "ip", "requested_by", "requested_at", "state",
    "lease_owner", "lease_until", "started_at", "finished_at", "result", "error",
]
ACTIVE_STATES = ("queued", "claimed")
TERMINAL_STATES = ("done", "error", "cancelled")

# THE FALLBACK SENTENCE when no weirling can scan and the caller has no measured reason.
# A named refusal beats a generic one, but it must never replace the measured sentence the
# fleet actually produced.
SCAN_UNAVAILABLE = "no registered weirling reports Nmap, so a queued job would never be claimed"


def _now() -> datetime:
    return datetime.now(UTC)


def _as_utc(value: Any) -> datetime | None:
    """ClickHouse returns naive datetimes; the queue compares them with an aware UTC now.

    WITHOUT THIS the comparison raises TypeError and an unreadable job would be reported as a
    healthy one by a caller that caught the error -- the exact class of lie this module is
    being taught to stop telling.
    """
    if not isinstance(value, datetime):
        return None
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _span(seconds: float) -> str:
    total = max(0, int(seconds))
    h, m, s = total // 3600, (total % 3600) // 60, total % 60
    if h:
        return f"{h}h{m:02d}m"
    if m:
        return f"{m}m{s:02d}s"
    return f"{s}s"


def derive(job: dict[str, Any], *, lease_s: int = 900, scanning_enabled: bool = True,
           unavailable_reason: str = "", now: datetime | None = None) -> dict[str, Any]:
    """Add the queue's DERIVED state: abandoned, stale, or the row's own word.

    DERIVED, NEVER STORED. `state` is what the scanner wrote; abandonment is a conclusion from
    the lease and the absence of a claim, so it is computed at read time and the column is left
    alone. Writing "abandoned" into the table would make a job that a later scanner could still
    claim look permanently dead, and would need a second writer to undo it.

    Three facts, three names:
      * queued past the lease with no claim  -> `abandoned` (nothing is working on it)
      * claimed with an expired lease        -> `stale` (the scanner may be gone; another may
                                                reclaim it, because claim_next_job treats an
                                                expired lease as claimable)
      * anything else                        -> the row's own state, unchanged

    When NO weirling can scan, every queued job is unclaimable now: saying "wait for the lease"
    would be a slower version of the same lie, so the reason names the measured capability.
    """
    out = dict(job)
    state = str(out.get("state") or "")
    reason = ""
    derived = state
    lease = max(30, int(lease_s or 900))
    moment = now or _now()

    if state == "queued":
        if not scanning_enabled:
            derived = "abandoned"
            reason = unavailable_reason or SCAN_UNAVAILABLE
        else:
            requested = _as_utc(out.get("requested_at"))
            waited = (moment - requested).total_seconds() if requested else 0.0
            if requested and waited > lease:
                derived = "abandoned"
                reason = (
                    f"no scanner claimed this job in {_span(waited)}; its {lease}s lease "
                    "ran out with no claim, so nothing is working on it"
                )
    elif state == "claimed":
        until = _as_utc(out.get("lease_until"))
        if until is not None and until < moment:
            derived = "stale"
            reason = (
                f"the scanner's {lease}s lease ran out {_span((moment - until).total_seconds())} "
                "ago with no result; another scanner may reclaim this job"
            )

    out["derived_state"] = derived
    out["abandoned"] = derived == "abandoned"
    out["state_reason"] = reason
    return out


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


def ip_allowed(ip: str, networks: Iterable[str] | None) -> bool:
    """Is `ip` inside ANY declared network? Empty/None proves nothing, so it refuses.

    THE ONE DEFINITION of a weirling's reach, used by the claim here and by the eligibility
    read in `scanner.fleet_capability`. A second implementation would let the console promise
    a scan the claim then refuses.
    """
    try:
        addr = ipaddress.ip_address(str(ip or "").strip())
    except ValueError:
        return False
    for raw in networks or ():
        try:
            if addr in ipaddress.ip_network(str(raw or "").strip(), strict=False):
                return True
        except ValueError:
            continue
    return False


def claim_next_job(client: Any, owner: str, lease_s: int = 900,
                   networks: Iterable[str] | None = None) -> dict[str, Any] | None:
    """Claim the oldest queued job IN THIS WEIRLING'S SCOPE, or one whose lease expired.

    THE SCOPE IS PART OF THE CLAIM, not a UI hint: a weirling may only execute a scan for an
    address inside the networks it declared in its own registration. When `networks` is given,
    out-of-scope rows are skipped (they stay queued for a weirling that can reach them) and a
    weirling cannot claim another segment's work by asking first.
    """
    now = _now()
    rows = client.query(
        "SELECT job_id, asset_key, ip, requested_by, requested_at, state, lease_owner, "
        "       lease_until, started_at, finished_at, result, error "
        "FROM weirvern.scan_jobs FINAL "
        "WHERE state = 'queued' OR (state = 'claimed' AND lease_until < %(now)s) "
        "ORDER BY requested_at ASC LIMIT 50",
        parameters={"now": now},
    ).result_rows
    chosen: dict[str, Any] | None = None
    for row in rows:
        job = dict(zip(JOB_COLUMNS, row, strict=False))
        if networks is not None and not ip_allowed(str(job.get("ip") or ""), networks):
            continue
        chosen = job
        break
    if chosen is None:
        return None
    job = chosen
    job.update({
        "state": "claimed",
        "lease_owner": (owner or "weirling")[:120],
        "lease_until": now + timedelta(seconds=max(30, int(lease_s))),
        "started_at": now,
        "finished_at": None,
        "result": "",
        "error": "",
    })
    _insert(client, job)
    return job


def delete_job(client: Any, job_id: str) -> None:
    """REMOVE a queued job from the record entirely (operator, 2026-11-20).

    A queued scan that never ran is not history worth keeping in the queue: the operator asked
    for it and asked to take it back. The FACT of the request is preserved in `fleet_audit` by
    the caller, so deletion cannot be used to erase that a scan was ever asked for.

    `mutations_sync = 2` waits for the mutation, so the next read cannot see the row and report
    a successful cancel as a no-op.
    """
    client.command(
        "ALTER TABLE weirvern.scan_jobs DELETE WHERE job_id = %(job_id)s "
        "SETTINGS mutations_sync = 2",
        parameters={"job_id": str(job_id)},
    )


def request_cancel(client: Any, job: dict[str, Any], *, actor: str = "operator") -> dict[str, Any]:
    """Ask the weirling running this job to stop. The row STAYS until it confirms.

    DELETING A RUNNING SCAN WOULD BE A LIE: the row would vanish while Nmap still probes the
    network. So the state becomes `cancel_requested`, the agent polls it, kills its child, and
    reports back; only then does the hub delete the row and audit the confirmation.
    """
    job.update({
        "state": "cancel_requested",
        "result": f"cancellation requested by {actor or 'operator'}; the weirling has not "
                  "confirmed",
        "error": "",
        "finished_at": None,
    })
    _insert(client, job)
    return job


def cancel_requested(client: Any, job_id: str, owner: str) -> bool:
    """Has the hub asked THIS weirling to stop this job? Read by the agent during a scan."""
    job = get_job(client, job_id)
    return bool(job and str(job.get("state") or "") == "cancel_requested"
                and str(job.get("lease_owner") or "") == owner)



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
