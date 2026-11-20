"""The one-click Nmap installer: a request that exists only in memory.

WHY MEMORY, AND WHY THIS SHAPE. The operator asked for a fallback that installs Nmap on a
weirling whose user has a sudo PASSWORD, without ever putting that password anywhere durable.
That rules out ClickHouse (the queue's usual medium), the environment of any workload, every
log line and every audit row. So the request lives in the gateway process for at most five
minutes, is handed to the target weirling ONCE over its existing mutual-TLS channel, and the
password is gone from the hub the moment it is delivered.

THE COMMAND IS NEVER TAKEN FROM THE CALLER. A request carries a distro id and version; the
command is recomputed from `scanner.nmap_install_command`, the same table the console renders,
and the weirling re-checks it before executing. An allow-list of one is what makes "the
endpoint can only install nmap" true rather than aspirational.
"""
from __future__ import annotations

import hmac
import re
import secrets
import subprocess
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from weirvern import scanner
from weirvern.config import Settings

# THE PROMPT EXPIRES. Five minutes is long enough to paste a password and short enough that a
# request left behind cannot be picked up by a weirling that reconnects an hour later.
MAX_AGE_S = 300
# THREE ATTEMPTS PER HOST PER TEN MINUTES. A typo is recoverable; a prompt that can be replayed
# indefinitely is a password oracle.
MAX_PER_HOST = 3
WINDOW_S = 600
INSTALL_TIMEOUT_S = 180
MAX_OUTPUT = 4000

REDACTED = "***"


class InstallError(Exception):
    """A refusal with a sentence the console can show, and a status code to carry it."""

    def __init__(self, message: str, code: int = 400):
        super().__init__(message)
        self.code = code


def _now() -> datetime:
    return datetime.now(UTC)


def command_for(family: str, version: str = "") -> str:
    """The ONE command this endpoint may run for a host, from the shipped table.

    An unknown distro is a refusal, not a guess: the console shows the copy-command line for
    those, exactly as it does when no package manager could be detected.
    """
    table = scanner.nmap_install_command(str(family or ""), str(version or ""))
    command = str(table.get("command") or "").strip()
    if not table.get("known") or not table.get("manager") or not command:
        raise InstallError(
            "no package manager could be detected for this host; copy the install command "
            "instead of asking the weirling to run one")
    return command


def strip_sudo(command: str) -> str:
    """The command without its leading `sudo`, for a caller that is already root."""
    return re.sub(r"^\s*sudo\s+", "", str(command or "")).strip()


def redact(text: str, secret: bytes | bytearray | str | None) -> str:
    """Remove the password from captured output. sudo does not echo stdin, but 'does not' is
    not 'cannot', and this is the one place output leaves the process."""
    out = str(text or "")
    if secret:
        needle = secret.decode("utf-8", "ignore") if isinstance(secret, (bytes, bytearray)) \
            else str(secret)
        if needle:
            out = out.replace(needle, REDACTED)
    # A line that announces a password is not useful evidence even when it does not contain it.
    return out[:MAX_OUTPUT]


@dataclass
class Request:
    request_id: str
    host_id: str
    family: str
    version: str
    command: str
    reason: str
    actor: str
    created_at: datetime
    expires_at: datetime
    state: str = "pending"          # pending -> delivered -> done | failed | expired
    exit_code: int | None = None
    output: str = ""
    nmap_version: str = ""
    scan_mode: str = ""
    password_used: bool = False
    _password: bytearray | None = field(default=None, repr=False)

    # ── the secret never leaves through a serialiser ─────────────────────────────────────────
    def public(self) -> dict[str, Any]:
        """Everything the console (or a test) may see. There is no password field here."""
        return {
            "request_id": self.request_id,
            "host_id": self.host_id,
            "command": self.command,
            "reason": self.reason,
            "actor": self.actor,
            "state": self.state,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "exit_code": self.exit_code,
            "output": self.output,
            "nmap_version": self.nmap_version,
            "scan_mode": self.scan_mode,
            "password_used": self.password_used,
        }

    def clear_password(self) -> None:
        """Overwrite the bytes before dropping the reference. Memory is not a lock, but a
        zeroed buffer is not a copy of the operator's password either."""
        if self._password is not None:
            for index in range(len(self._password)):
                self._password[index] = 0
            self._password = None


class Store:
    """The in-memory requests, keyed by id, plus the one-per-host pickup rule."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._by_id: dict[str, Request] = {}
        self._by_host: dict[str, list[Request]] = {}

    def _purge(self, now: datetime) -> None:
        for request in list(self._by_id.values()):
            if request.state in ("pending", "delivered") and request.expires_at <= now:
                request.state = "expired"
                request.clear_password()
                if request.state == "expired":
                    request.output = request.output or "the request expired before it was claimed"

    def create(self, *, host_id: str, family: str, version: str, reason: str,
               actor: str, password: str | None = None) -> Request:
        why = str(reason or "").strip()
        if not why:
            raise InstallError("a reason is required to install Nmap; it is kept in the audit trail")
        sid = str(host_id or "").strip()
        if not sid:
            raise InstallError("host_id is required")
        command = command_for(family, version)
        now = _now()
        with self._lock:
            self._purge(now)
            recent = [r for r in self._by_host.get(sid, [])
                      if r.created_at > now - timedelta(seconds=WINDOW_S)]
            if len(recent) >= MAX_PER_HOST:
                raise InstallError(
                    f"{MAX_PER_HOST} install attempts were already made on {sid} in the last "
                    f"{WINDOW_S // 60} minutes; wait before trying again with a corrected password",
                    code=429)
            secret = bytearray(str(password).encode("utf-8")) if password else None
            request = Request(
                request_id=secrets.token_urlsafe(18), host_id=sid,
                family=str(family or ""), version=str(version or ""), command=command,
                reason=why[:500], actor=str(actor or "operator")[:80],
                created_at=now, expires_at=now + timedelta(seconds=MAX_AGE_S),
                password_used=secret is not None, _password=secret,
            )
            self._by_id[request.request_id] = request
            self._by_host.setdefault(sid, []).append(request)
            return request

    def status(self, request_id: str) -> Request:
        with self._lock:
            self._purge(_now())
            request = self._by_id.get(str(request_id or ""))
            if request is None:
                raise InstallError("no install request with that id", code=404)
            return request

    def claim(self, host_id: str) -> dict[str, Any] | None:
        """Hand the oldest pending request to its host, ONCE.

        The password is removed from the store here: a second poll, a status read or a test that
        serialises the request cannot see it. The returned dict is the one delivery.
        """
        sid = str(host_id or "").strip()
        now = _now()
        with self._lock:
            self._purge(now)
            for request in sorted(self._by_host.get(sid, []), key=lambda r: r.created_at):
                if request.state != "pending" or request.expires_at <= now:
                    continue
                password = ""
                if request._password is not None:
                    password = bytes(request._password).decode("utf-8", "ignore")
                    request.clear_password()
                request.state = "delivered"
                return {
                    "request_id": request.request_id,
                    "host_id": request.host_id,
                    "family": request.family,
                    "version": request.version,
                    "command": request.command,
                    "reason": request.reason,
                    "expires_at": request.expires_at.isoformat(),
                    "password": password,
                    "password_used": request.password_used,
                }
            return None

    def result(self, request_id: str, host_id: str, *, ok: bool, exit_code: int | None,
               output: str = "", nmap_version: str = "", scan_mode: str = "") -> Request:
        with self._lock:
            request = self._by_id.get(str(request_id or ""))
            if request is None:
                raise InstallError("no install request with that id", code=404)
            if request.host_id != str(host_id or "").strip():
                raise InstallError("this request belongs to a different weirling", code=403)
            if request.state not in ("delivered", "pending"):
                raise InstallError(f"this request is already {request.state}", code=409)
            request.state = "done" if ok else "failed"
            request.exit_code = exit_code
            request.output = str(output or "")[:MAX_OUTPUT]
            request.nmap_version = str(nmap_version or "")[:80]
            request.scan_mode = str(scan_mode or "")[:16]
            request.clear_password()
            return request


STORE = Store()


def service_credential(settings: Settings, presented: str) -> tuple[bool, int, str]:
    """Whether an install request may proceed, and the refusal to send when it may not.

    ONE DEFINITION, used by the gateway route and by the tests. An UNSET credential refuses
    (503) rather than accepting every caller -- the absence of a secret is not permission.
    """
    configured = str(getattr(settings, "scan_install_token", "") or "")
    if not configured:
        return False, 503, "the install service credential is not configured on this gateway"
    if not presented or not hmac.compare_digest(str(presented), configured):
        return False, 401, "the install service credential is required"
    return True, 200, ""


def run_local(settings: Settings, request: dict[str, Any]) -> dict[str, Any]:
    """Execute ONE claimed install on this weirling, with the command it was promised.

    THE ALLOW-LIST IS RE-CHECKED HERE. The hub computed the command; this side recomputes it
    from the same table and refuses a mismatch, so a compromised hub response cannot turn the
    installer into a shell.
    """
    host_id = str(request.get("host_id") or "").strip()
    delivered = str(request.get("command") or "").strip()
    family = str(request.get("family") or "")
    version = str(request.get("version") or "")
    # THE ALLOW-LIST IS RE-CHECKED HERE. The hub computed the command; this side recomputes it
    # from the same table and refuses a mismatch, so a compromised hub response cannot turn the
    # installer into a shell.
    if delivered != command_for(family, version):
        return {"ok": False, "exit_code": None,
                "output": "the delivered command is not an Nmap install command; refusing to run it",
                "nmap_version": "", "scan_mode": ""}

    capability = scanner.detect_scanner(settings, host_id)
    mode = str(capability.get("sudo_state") or "unknown")
    password = str(request.get("password") or "")
    secret = bytearray(password.encode("utf-8")) if password else None
    if mode == "none":
        return {"ok": False, "exit_code": None,
                "output": "this weirling's user is not in sudoers and is not root; run the "
                          "command as root instead", "nmap_version": "",
                "scan_mode": "none"}
    if secret is None and mode == "password":
        return {"ok": False, "exit_code": None,
                "output": "this host needs a sudo password and none arrived with the request",
                "nmap_version": "", "scan_mode": "none"}
    if mode == "root":
        argv = ["sh", "-c", strip_sudo(delivered)]
        stdin = None
    elif mode == "passwordless":
        argv = ["sudo", "-n", "sh", "-c", strip_sudo(delivered)]
        stdin = None
    else:
        argv = ["sudo", "-S", "-p", "", "sh", "-c", strip_sudo(delivered)]
        stdin = password + "\n"
    try:
        proc = subprocess.run(  # noqa: S603 - a fixed argv, no shell interpolation of input
            argv, input=stdin, capture_output=True, text=True, timeout=INSTALL_TIMEOUT_S,
            check=False,
        )
        output = redact((proc.stdout or "") + (proc.stderr or ""), secret)
        ok = proc.returncode == 0
    except (OSError, subprocess.SubprocessError) as exc:
        output = redact(f"the install could not run: {exc}", secret)
        proc = None
        ok = False
    finally:
        if secret is not None:
            for index in range(len(secret)):
                secret[index] = 0
    after = scanner.detect_scanner(settings, host_id) if ok else {}
    return {
        "ok": bool(ok),
        "exit_code": getattr(proc, "returncode", None),
        "output": output,
        "nmap_version": str(after.get("nmap_version") or ""),
        "scan_mode": str(after.get("scan_mode") or ""),
    }
