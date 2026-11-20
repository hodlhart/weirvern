"""The one-click Nmap installer: memory-only, one command, one scope, no secret on the wire home.

THE PROPERTY THAT MATTERS MOST IS AN ABSENCE: the sudo password must not appear in any payload
the console can read, in any log line, or in the audit row that survives. Those are asserted by
SEARCHING serialised output, not by trusting the shape of a dict. The rest is the allow-list
(only the shipped nmap command can run), the service credential (absent means refuse), host
ownership (an unregistered or revoked weirling is refused) and the prompt's limits (five
minutes, three attempts per ten minutes).
"""
from __future__ import annotations

import json
import logging
from datetime import UTC, datetime, timedelta

import pytest

from weirvern import install_requests
from weirvern.admin import gateway_call, payloads

SECRET = "S3cret-Sudo-Pass-9x"


class _Settings:
    scan_install_token = "service-token"
    gateway_url = "https://gateway.invalid:8443"
    gateway_ca = ""


def _store() -> install_requests.Store:
    return install_requests.Store()


def _request(store: install_requests.Store, *, password: str | None = SECRET):
    return store.create(host_id="wl-a", family="debian", version="13",
                        reason="install nmap to enable scanning", actor="sam",
                        password=password)


# ── the secret must not be findable ─────────────────────────────────────────────────────────

def test_the_password_is_absent_from_every_payload_a_console_can_read():
    store = _store()
    request = _request(store)
    public = json.dumps(request.public(), default=str)
    assert SECRET not in public, "the create payload carries the password"

    claimed = store.claim("wl-a")
    assert claimed is not None and claimed["password"] == SECRET, (
        "the weirling did not receive the password it must pipe to sudo")
    # The ONE delivery is the only place it ever existed outside the caller. Every read after
    # it -- the status the console polls, the public shape -- has nothing to leak.
    assert SECRET not in json.dumps(store.status(request.request_id).public(), default=str)
    assert SECRET not in json.dumps(store.claim("wl-a"), default=str), (
        "a second pickup returned the password again")
    assert request._password is None, "the stored password was not cleared on delivery"


def test_the_password_is_absent_from_the_console_response_and_the_log(caplog):
    class _Client:
        def query(self, sql, parameters=None):
            class R:
                result_rows = [("debian", "13", 0, "password")]
            return R()

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    sent: dict = {}

    def _fake_create(settings, **kwargs):
        sent.update(kwargs)
        return 200, {"ok": True, "request_id": "req-1", "host_id": "wl-a",
                     "command": install_requests.command_for("debian", "13"),
                     "state": "pending", "expires_at": "2026-11-20T00:00:00+00:00"}

    caplog.set_level(logging.DEBUG)
    original = gateway_call.install_create
    import weirvern.admin.gateway_call as module

    module.install_create = _fake_create
    try:
        code, payload = payloads.weirling_install(
            _Client(), _Settings(), sensor_id="wl-a", reason="install nmap",
            actor="sam", sudo_password=SECRET)
    finally:
        module.install_create = original

    assert code == 200 and payload["ok"] is True
    assert SECRET not in json.dumps(payload, default=str), "the console response leaks it"
    assert SECRET not in caplog.text, "a log line leaks it"
    # It WAS forwarded, or the feature cannot work; the gateway is the only holder.
    assert sent.get("sudo_password") == SECRET


def test_the_password_is_absent_from_the_audit_row(monkeypatch):
    from weirvern import weirling_gateway

    inserted: list = []

    class _Client:
        def insert(self, table, data, column_names=None):
            inserted.append((table, data, column_names))

        def close(self):
            pass

    gateway = weirling_gateway.Gateway(_Settings(), ca=None)  # type: ignore[arg-type]
    monkeypatch.setattr(gateway, "client", lambda: _Client())
    monkeypatch.setattr(gateway, "_registered", lambda client, sid: (object(), None))
    store = _store()
    request = store.create(host_id="wl-a", family="debian", version="13",
                           reason="install nmap to enable scanning", actor="sam",
                           password=SECRET)
    monkeypatch.setattr(install_requests, "STORE", store)
    code, payload = gateway.install_result(
        "wl-a", {"request_id": request.request_id, "ok": True, "exit_code": 0,
                 "output": "nmap installed", "nmap_version": "7.95", "scan_mode": "connect"})
    assert code == 200, payload
    rows = [row for table, data, _cols in inserted if table == "weirvern.fleet_audit"
            for row in data]
    assert rows, "the install wrote no audit row"
    serialised = json.dumps(rows, default=str)
    assert SECRET not in serialised, f"the audit row carries the password: {serialised}"
    assert rows[0][1] == "nmap_install", rows[0]
    assert "sudo password used" in rows[0][3]
    assert "wl-a" in rows[0][2]


# ── one command, and only one ───────────────────────────────────────────────────────────────

def test_the_allowlist_is_the_shipped_install_command_only():
    assert install_requests.command_for("debian", "13") == (
        "sudo apt-get update && sudo apt-get install -y nmap")
    assert install_requests.command_for("alpine") == "sudo apk add --no-cache nmap"
    for hostile in ("debian; rm -rf /", "plan9", "", "$(curl evil)"):
        with pytest.raises(install_requests.InstallError):
            install_requests.command_for(hostile)


def test_run_local_refuses_a_tampered_command_without_running_anything(monkeypatch):
    def _explode(*a, **k):  # pragma: no cover - it must not be called
        raise AssertionError("a non-allowlisted command reached subprocess")

    monkeypatch.setattr(install_requests.subprocess, "run", _explode)
    settings = type("S", (), {"scan_nmap_binary": "nmap", "sensor_name": "wl-a"})()
    out = install_requests.run_local(settings, {
        "host_id": "wl-a", "family": "debian", "version": "13",
        "command": "sudo rm -rf /", "password": "",
    })
    assert out["ok"] is False and "not an Nmap install command" in out["output"]


def test_run_local_pipes_the_password_to_sudo_and_redacts_its_echo(monkeypatch):
    seen: dict = {}

    def _fake_run(argv, **kwargs):
        seen["argv"] = argv
        seen["input"] = kwargs.get("input")
        return type("P", (), {"returncode": 0,
                              "stdout": f"installed (echo {SECRET})\n",
                              "stderr": ""})()

    monkeypatch.setattr(install_requests.subprocess, "run", _fake_run)
    monkeypatch.setattr(install_requests.scanner, "detect_scanner",
                        lambda settings, sid="": {"sudo_state": "password",
                                                  "nmap_version": "7.95",
                                                  "scan_mode": "connect"})
    settings = type("S", (), {"scan_nmap_binary": "nmap", "sensor_name": "wl-a"})()
    out = install_requests.run_local(settings, {
        "host_id": "wl-a", "family": "debian", "version": "13",
        "command": install_requests.command_for("debian", "13"), "password": SECRET,
    })
    assert seen["argv"][:4] == ["sudo", "-S", "-p", ""]
    assert seen["input"] == SECRET + "\n"
    assert SECRET not in out["output"] and "***" in out["output"]
    assert out["ok"] is True and out["nmap_version"] == "7.95"


def test_a_host_without_privilege_is_refused_before_a_password_is_asked_for():
    class _Client:
        def query(self, sql, parameters=None):
            class R:
                result_rows = [("debian", "13", 0, "none")]
            return R()

    code, payload = payloads.weirling_install(
        _Client(), _Settings(), sensor_id="wl-a", reason="install nmap")
    assert code == 403 and payload["refused"] == "no_privilege"
    assert "not in sudoers" in payload["error"]


# ── the service credential ──────────────────────────────────────────────────────────────────

def test_the_endpoint_refuses_when_the_service_credential_is_absent():
    settings = _Settings()
    settings.scan_install_token = ""
    ok, code, message = install_requests.service_credential(settings, "anything")
    assert ok is False and code == 503 and "not configured" in message

    ok, code, _ = install_requests.service_credential(_Settings(), "")
    assert ok is False and code == 401

    ok, code, _ = install_requests.service_credential(_Settings(), "wrong")
    assert ok is False and code == 401

    ok, code, _ = install_requests.service_credential(_Settings(), "service-token")
    assert ok is True and code == 200


def test_an_unregistered_host_is_refused_before_a_request_exists(monkeypatch):
    from weirvern import weirling_gateway

    gateway = weirling_gateway.Gateway(_Settings(), ca=None)  # type: ignore[arg-type]
    monkeypatch.setattr(gateway, "client", lambda: type("C", (), {"close": lambda self: None})())
    monkeypatch.setattr(gateway, "_registered",
                        lambda client, sid: (None, (403, {"error": "sensor is not registered"})))
    store = _store()
    monkeypatch.setattr(install_requests, "STORE", store)
    code, payload = gateway.install_create({
        "host_id": "someone-else", "distro_family": "debian", "reason": "install nmap"})
    assert code == 403
    assert store._by_id == {}, "a refused host still created an in-memory request"


# ── the prompt's limits ────────────────────────────────────────────────────────────────────

def test_the_prompt_expires_after_five_minutes():
    store = _store()
    request = _request(store)
    request.expires_at = datetime.now(UTC) - timedelta(seconds=1)
    assert store.claim("wl-a") is None, "an expired prompt was still claimable"
    assert store.status(request.request_id).state == "expired"
    assert request._password is None, "an expired prompt kept its password"


def test_three_attempts_per_host_per_ten_minutes():
    store = _store()
    for _ in range(3):
        _request(store, password=None)
    with pytest.raises(install_requests.InstallError) as caught:
        _request(store, password=None)
    assert caught.value.code == 429
    # A different host is unaffected.
    store.create(host_id="wl-b", family="debian", version="13", reason="install nmap",
                 actor="sam", password=None)


# ── the agent-side worker ──────────────────────────────────────────────────────────────────

def test_the_install_worker_runs_a_delivered_request(monkeypatch):
    import threading

    from weirvern.admin import sensor_agent

    stop = threading.Event()
    seen: dict = {}

    class _Client:
        is_gateway = True

        def install_next(self):
            return {"request_id": "req-9", "host_id": "wl-a", "family": "debian",
                    "version": "13", "command": "sudo apt-get install -y nmap",
                    "password": "pw"}

        def install_result(self, request_id, result):
            seen["result"] = (request_id, result)
            stop.set()
            return True

    monkeypatch.setattr(sensor_agent, "connect", lambda settings: _Client())
    monkeypatch.setattr(install_requests, "run_local",
                        lambda settings, request: {"ok": True, "exit_code": 0,
                                                   "output": "done", "nmap_version": "7.95",
                                                   "scan_mode": "connect"})
    settings = type("S", (), {"scan_install_interval_s": 5})()
    sensor_agent._install_worker(settings, "wl-a", stop)
    assert seen.get("result", ("", {}))[0] == "req-9"
    assert seen["result"][1]["ok"] is True
