"""Fleet scanning: who may claim a job, what "cancel" means, and who may ask at all.

THE QUEUE'S HONESTY IS THE FEATURE. A queued row is a promise that some weirling will run it.
Three facts have to hold for that promise to be true, and each has a test here that would fail
if the promise became a lie:

  * the claim is SCOPE-AWARE -- a weirling cannot take work for a network it never declared, so
    a job cannot be "claimed" by a node that cannot reach the target;
  * cancelling a QUEUED job removes it and leaves the audit row that says it was asked for,
    while cancelling a RUNNING one does NOT delete it (a running scan that vanishes from the
    record while Nmap still probes is exactly the class of lie this queue exists to stop);
  * a VIEWER cannot create or cancel, enforced by the real Flask gate rather than by hiding a
    button.

The fake below is ClickHouse-shaped: `insert` replaces by job_id (the code's own
replacement-row model), `command` applies the DELETE mutation, and `query` answers by the SQL
the module actually writes. It is deliberately not a query engine -- the predicates that matter
are asserted to be present in the SQL and then applied here.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from weirvern import scan_jobs
from weirvern.admin import payloads

JOB_COLUMNS = scan_jobs.JOB_COLUMNS
ASSET_COLUMNS = ("asset_key", "ip", "mac", "hostname", "first_seen", "last_seen",
                 "scan_state", "last_scan_at", "scan_error", "source")


class Rows:
    def __init__(self, rows):
        self.result_rows = rows


def _now() -> datetime:
    return datetime.now(UTC)


def _job(*, job_id="job-1", ip="198.51.100.10", state="queued",
         requested_at=None, lease_until=None, lease_owner="", asset_key="asset-1"):
    return {
        "job_id": job_id, "asset_key": asset_key, "ip": ip, "requested_by": "operator",
        "requested_at": requested_at or _now(), "state": state,
        "lease_owner": lease_owner, "lease_until": lease_until, "started_at": None,
        "finished_at": None, "result": "", "error": "",
    }


def _tuple(job: dict[str, Any]) -> tuple:
    return tuple(job.get(column) for column in JOB_COLUMNS)


class ScanStore:
    """The two tables the queue writes, and the one read that proves the deletion."""

    def __init__(self, jobs=(), assets=()):
        self.jobs: dict[str, dict[str, Any]] = {str(j["job_id"]): dict(j) for j in jobs}
        self.assets = [dict(a) for a in assets]
        self.audits: list[dict[str, Any]] = []
        self.commands: list[str] = []

    # ── writes ────────────────────────────────────────────────────────────────────────────────
    def insert(self, table, data, column_names=None):
        cols = list(column_names or [])
        if table == "weirvern.scan_jobs":
            assert cols == JOB_COLUMNS, f"the queue's column list changed: {cols}"
            for row in data:
                item = dict(zip(cols, row, strict=False))
                # REPLACEMENT ROWS: the queue never updates in place, it inserts the next state.
                self.jobs[str(item["job_id"])] = item
            return
        if table == "weirvern.fleet_audit":
            assert cols == ["scope", "action", "target", "reason", "actor"], cols
            for row in data:
                self.audits.append(dict(zip(cols, row, strict=False)))
            return
        raise AssertionError(f"unexpected insert into {table}")

    def command(self, sql, parameters=None):
        self.commands.append(sql)
        params = parameters or {}
        if "ALTER TABLE weirvern.scan_jobs DELETE WHERE job_id" in sql:
            # The mutation must WAIT for itself, or the next read can still see the row and a
            # successful cancel would report a row that is about to disappear.
            assert "mutations_sync = 2" in sql, "the delete does not wait for its own mutation"
            self.jobs.pop(str(params.get("job_id")), None)
            return
        raise AssertionError(f"unexpected command: {sql}")

    # ── reads ─────────────────────────────────────────────────────────────────────────────────
    def query(self, sql, parameters=None):
        params = parameters or {}
        if "weirvern.asset_registry" in sql:
            rows = [[a.get(c) for c in ASSET_COLUMNS]
                    for a in self.assets if a.get("ip") == params.get("ip")]
            return Rows(rows)
        if "weirvern.scan_jobs" in sql:
            return Rows(self._scan_jobs(sql, params))
        raise AssertionError(f"unexpected query: {sql}")

    def _scan_jobs(self, sql: str, params: dict[str, Any]) -> list[tuple]:
        jobs = sorted(self.jobs.values(), key=lambda j: j["requested_at"])
        if "count()" in sql:
            return [[sum(1 for j in jobs if j["state"] == "queued")]]
        if "WHERE job_id = %(job_id)s" in sql:
            job = self.jobs.get(str(params.get("job_id")))
            return [_tuple(job)] if job else []
        if "state = 'queued' OR" in sql:
            now = params["now"]
            return [_tuple(j) for j in jobs
                    if j["state"] == "queued"
                    or (j["state"] == "claimed" and j.get("lease_until") is not None
                        and j["lease_until"] < now)]
        if "state IN ('queued', 'claimed')" in sql:
            return [_tuple(j) for j in jobs
                    if j["state"] in ("queued", "claimed")
                    and j["asset_key"] == params.get("asset_key")]
        return [_tuple(j) for j in jobs]


# ── the claim is scope-aware ──────────────────────────────────────────────────────────────────

def test_a_weirling_cannot_claim_a_target_outside_its_declared_networks():
    """THE SCOPE IS PART OF THE CLAIM. A node that cannot reach the target must not take it."""
    job = _job(ip="203.0.113.5")
    store = ScanStore(jobs=[job])

    assert scan_jobs.claim_next_job(
        store, owner="wl-lan", networks=["198.51.100.0/24"]) is None
    assert store.jobs["job-1"]["state"] == "queued", (
        "an out-of-scope claim changed the row: the job must stay queued for a node that can "
        "actually reach it")

    claimed = scan_jobs.claim_next_job(
        store, owner="wl-dmz", networks=["203.0.113.0/24"])
    assert claimed is not None and claimed["job_id"] == "job-1"
    assert store.jobs["job-1"]["state"] == "claimed"
    assert store.jobs["job-1"]["lease_owner"] == "wl-dmz"


def test_no_declared_networks_proves_nothing_so_the_claim_refuses():
    """EMPTY IS "NOT DECLARED", NEVER "EVERYWHERE". The operator declares scope on the weirling."""
    store = ScanStore(jobs=[_job(ip="198.51.100.10")])
    assert scan_jobs.claim_next_job(store, owner="wl-a", networks=[]) is None
    assert scan_jobs.claim_next_job(store, owner="wl-a", networks=None) is not None


# ── cancel: a queued row goes, a running row stays ───────────────────────────────────────────

def test_cancelling_a_queued_job_removes_it_and_writes_one_audit_row():
    store = ScanStore(jobs=[_job()])
    code, payload = payloads.scan_job_cancel(
        store, job_id="job-1", reason="queued twice by mistake", actor="sam")

    assert code == 200, payload
    assert payload["removed"] is True
    assert "job-1" not in store.jobs, "the queued row survived the cancel"
    assert len(store.audits) == 1, f"expected exactly one audit row, got {store.audits}"
    audit = store.audits[0]
    assert audit["scope"] == "scan"
    assert audit["action"] == "scan_cancel"
    assert audit["reason"] == "queued twice by mistake"
    assert audit["actor"] == "sam"
    assert "198.51.100.10" in audit["target"] and "job-1" in audit["target"], (
        "the audit must name the target and the job: the row it describes is gone")


def test_cancelling_a_running_job_answers_202_and_KEEPS_the_row():
    """A RUNNING SCAN THAT VANISHES FROM THE RECORD IS A LIE: Nmap is still probing."""
    store = ScanStore(jobs=[_job(
        state="claimed", lease_owner="wl-dmz",
        lease_until=_now() + timedelta(minutes=10))])

    code, payload = payloads.scan_job_cancel(
        store, job_id="job-1", reason="wrong host", actor="sam")

    assert code == 202, payload
    assert payload["state"] == "cancel_requested"
    assert payload["confirmed"] is False
    assert "job-1" in store.jobs, "a running job was deleted instead of asked to stop"
    assert store.jobs["job-1"]["state"] == "cancel_requested"
    assert store.jobs["job-1"]["lease_owner"] == "wl-dmz"
    assert [a["action"] for a in store.audits] == ["scan_cancel_requested"]
    assert store.audits[0]["reason"] == "wrong host"


def test_a_cancel_without_a_reason_is_refused_and_changes_nothing():
    store = ScanStore(jobs=[_job()])
    code, payload = payloads.scan_job_cancel(store, job_id="job-1", reason="   ")
    assert code == 400 and payload["refused"] == "reason_required"
    assert "job-1" in store.jobs, "a refused cancel still removed the row"
    assert store.audits == []


def test_bulk_cancel_writes_one_audit_row_per_job():
    """ONE REASON, PER-JOB OUTCOMES, PER-JOB EVIDENCE. A batch must not flatten into one row."""
    store = ScanStore(jobs=[
        _job(job_id="job-1", ip="198.51.100.10"),
        _job(job_id="job-2", ip="198.51.100.11"),
        _job(job_id="job-3", ip="198.51.100.12", state="claimed", lease_owner="wl-a",
             lease_until=_now() + timedelta(minutes=10)),
    ])

    code, payload = payloads.scan_jobs_cancel(
        store, job_ids=["job-1", "job-2", "job-3"], reason="duplicate requests", actor="sam")

    assert code == 200, payload
    assert [entry["job_id"] for entry in payload["removed"]] == ["job-1", "job-2"]
    assert [entry["job_id"] for entry in payload["unconfirmed"]] == ["job-3"]
    assert "job-1" not in store.jobs and "job-2" not in store.jobs
    assert "job-3" in store.jobs and store.jobs["job-3"]["state"] == "cancel_requested"
    assert len(store.audits) == 3, f"one audit row per job, got {store.audits}"
    assert sorted(a["action"] for a in store.audits) == [
        "scan_cancel", "scan_cancel", "scan_cancel_requested"]
    assert {a["reason"] for a in store.audits} == {"duplicate requests"}
    assert {a["actor"] for a in store.audits} == {"sam"}
    assert len({a["target"] for a in store.audits}) == 3, "the audit rows do not name each job"


def test_a_finished_job_is_not_cancellable():
    store = ScanStore(jobs=[_job(state="done")])
    code, payload = payloads.scan_job_cancel(store, job_id="job-1", reason="too late")
    assert code == 409 and payload["refused"] == "already_finished"
    assert "job-1" in store.jobs and store.audits == []


# ── the role gate, through the REAL Flask surface ────────────────────────────────────────────

def _roles_app(role: str):
    """A real app with a real session registry, carrying a session for `role`."""
    import pytest

    flask = pytest.importorskip("flask")  # noqa: F841 - the module must be importable
    from weirvern.admin import flask_app
    from weirvern.admin import users as users_mod

    class _K8s:
        def read(self):
            from weirvern.admin.cluster_config import NotFoundError

            raise NotFoundError("weirvern-users does not exist")

        def create(self, data):  # pragma: no cover - bootstrap only
            self.data = dict(data)

        def patch_data(self, data):  # pragma: no cover
            self.data = dict(data)

    store = users_mod.UserStore(_K8s())
    store.load()
    _sessions = users_mod.SessionRegistry()
    token = _sessions.create(users_mod.Identity(username="sam", role=role))
    _throttle = users_mod.LoginThrottle()

    class _Auth:
        enabled = False
        reason = "write access is disabled: WEIRVERN_GUI_TOKEN is not set"

        def check(self, presented, client=""):
            return False

    def _boom(settings):
        raise RuntimeError("this request must be refused before a table is read")

    _settings = type("S", (), {"scan_job_lease_s": 900, "scan_claim_interval_s": 10})()

    class _Ctx:
        settings = _settings
        backend = None
        config_client = None
        user_store = store
        sessions = _sessions
        throttle = _throttle
        auth = _Auth()
        accounts_note = ""
        capabilities = None
        connect_factory = staticmethod(_boom)

    return flask_app.create_app(_Ctx(), secret_key="scan-roles"), token


def test_a_viewer_cannot_create_or_cancel_a_scan():
    """SERVER-SIDE, not a hidden button: a viewer's POST and DELETE are both refused."""
    app, token = _roles_app("viewer")
    client = app.test_client()
    headers = {"X-Weirvern-Session": token}

    created = client.post("/api/scan-jobs", json={"ip": "198.51.100.10"}, headers=headers)
    assert created.status_code == 403, created.data
    assert "viewer" in created.get_data(as_text=True).lower()

    removed = client.delete("/api/scan-jobs/job-1", json={"reason": "not mine"},
                            headers=headers)
    assert removed.status_code == 403, removed.data

    bulk = client.post("/api/scan-jobs/cancel",
                       json={"job_ids": ["job-1"], "reason": "not mine"}, headers=headers)
    assert bulk.status_code == 403, bulk.data

    # THE INSTALLER IS A WRITE TOO, and it is the one that takes a sudo password. A viewer must
    # be refused before the body is read, so the secret is never even parsed for them.
    install = client.post("/api/weirlings/wl-a/install",
                          json={"reason": "install nmap", "sudo_password": "hunter2"},
                          headers=headers)
    assert install.status_code == 403, install.data


def test_an_admin_gets_past_the_same_gate():
    """THE NEGATIVE CONTROL: the 403s above are the role, not a route that always refuses."""
    app, token = _roles_app("admin")
    client = app.test_client()
    headers = {"X-Weirvern-Session": token}

    # The gate passes and the route reaches its table read, which this context deliberately
    # fails: 503 is the queue's named "not readable" answer. Anything but 403 proves the gate
    # let the admin through.
    got = client.post("/api/scan-jobs", json={"ip": "198.51.100.10"}, headers=headers)
    assert got.status_code == 503, got.data
    assert "not readable" in got.get_data(as_text=True)


# ── the agent-side poll: a cancel must actually stop the probe ───────────────────────────────

def test_the_run_loop_kills_nmap_when_the_check_says_stop(monkeypatch):
    """THE POLL IS REAL: `cancel_check` is what stands between "cancel" and a live Nmap."""
    import subprocess

    from weirvern import scanner

    class _Proc:
        def __init__(self):
            self.killed = False
            self.returncode = None
            self.communicates = 0

        def communicate(self, timeout=None):
            self.communicates += 1
            if not self.killed:
                raise subprocess.TimeoutExpired(cmd="nmap", timeout=timeout)
            self.returncode = -9
            return "", ""

        def kill(self):
            self.killed = True

        def poll(self):
            return self.returncode

    proc = _Proc()
    monkeypatch.setattr(scanner.shutil, "which", lambda name: "/usr/bin/nmap")
    monkeypatch.setattr(scanner.subprocess, "Popen", lambda *a, **k: proc)

    with pytest.raises(scanner.ScanCancelled):
        scanner._run(["nmap", "--version"], 60, cancel_check=lambda: True)
    assert proc.killed, "the operator's cancel did not kill the child"
    assert proc.communicates >= 2, "the loop did not wait for the killed process to be reaped"


def test_the_scan_worker_polls_the_hub_while_a_job_runs(monkeypatch):
    """The wiring, exercised: the worker hands the scan a poll that asks the hub per job."""
    import threading

    from weirvern import scanner
    from weirvern.admin import sensor_agent

    # A stop that the fake scan sets, so the worker's own loop ends after one pass instead of
    # waiting out its claim interval.
    stop = threading.Event()
    polls: list[str] = []
    seen: dict[str, object] = {}

    class _Client:
        is_gateway = True

        def scan_capability(self, capability):
            return True

        def scan_next(self):
            return {"job_id": "job-7", "ip": "198.51.100.10"}, ""

        def scan_cancel(self, job_id):
            polls.append(job_id)
            return True

        def scan_result(self, job_id, result):
            seen["result"] = (job_id, result)
            return True

    client = _Client()
    monkeypatch.setattr(sensor_agent, "connect", lambda settings: client)
    monkeypatch.setattr(scanner, "detect_scanner",
                        lambda settings, sid="": {"nmap_available": True, "nmap_version": "7.95",
                                                  "os_id": "", "os_version": "",
                                                  "scan_mode": "connect", "detail": ""})

    def _fake_scan(settings, ip, *, raw=False, cancel_check=None):
        seen["ip"] = ip
        seen["poll"] = bool(cancel_check()) if cancel_check else None
        stop.set()
        return {"ok": True, "cancelled": True}

    monkeypatch.setattr(scanner, "run_service_scan", _fake_scan)
    settings = type("S", (), {"scan_claim_interval_s": 10, "scan_job_lease_s": 900,
                              "scan_nmap_binary": "nmap", "sensor_name": "wl-a"})()

    sensor_agent._scan_worker(settings, "wl-a", stop)

    assert seen.get("ip") == "198.51.100.10"
    assert seen.get("poll") is True, "the worker ran a scan with no poll for a cancellation"
    assert polls == ["job-7"], f"the poll asked about the wrong job: {polls}"
    assert seen.get("result", ("", {}))[0] == "job-7", "the outcome was not reported for the job"

