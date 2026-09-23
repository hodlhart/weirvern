"""Accounts, roles, and sessions for the web GUI.

WHY THIS EXISTS. The GUI was read-only for its whole life because it is served on a LAN port
with no TLS, and the first write surface (settings) was gated on a single shared operator token
rather than a password. A token is not an account: there is no way to give a second person
access without giving them the token, no record of who changed what, and nothing to disable
when someone leaves. This module is the accounts layer: one default admin created during setup,
per-user accounts after that, and two roles.

THE ROLES, EXACTLY TWO AND DELIBERATELY SO.

  * admin  -- may change settings, reviews, and manage accounts.
  * viewer -- may see every view, and may change nothing.

A third role would need a written-down permission model; two roles need one sentence, and the
request was for a person who administers the deployment and people who read it.

STORAGE: A CONFIGMAP (`weirvern-users`), NOT A SECRET -- a trade-off made with eyes open.
Password hashes are credential material, and a Secret is the convention for that. It is a
ConfigMap anyway for two reasons: (1) the GUI's ServiceAccount grant deliberately has NO access
to Secrets -- that absence is what stops a compromised GUI pod from exfiltrating the Pushover
credentials, and it is documented as a property the project chose; widening the grant to store
hashes would trade a proven guard for a smaller one. (2) The alternative, a file on a PVC,
would die with the pod on many clusters. The exposure taken on is bounded: scrypt hashes at
the parameters below are expensive to attack offline, and anyone who can read ConfigMaps in
this namespace can already reconfigure the whole deployment. The trade is stated here rather
than implied.

WHY A CONFIGMAP AND NOT CLICKHOUSE, which already holds alert reviews. A login gate must
work when ClickHouse does not: the first thing an operator wants to do during a database
incident is read the health page. Accounts in the database would make the GUI unreachable
exactly when it is the instrument you need. The settings write path already talks to the
Kubernetes API, so this reuses that credential and needs no new one.

HASHES: `hashlib.scrypt`, stdlib, no new dependency. Per-user 16-byte salt, n=2^14, r=8, p=1.
Format: `scrypt$n=16384$r=8$p=1$<salt hex>$<hash hex>` -- self-describing, so parameters can
be raised later without invalidating stored hashes. Comparison via `hmac.compare_digest`.

SESSIONS ARE IN MEMORY, and that is a real property, not an oversight: a restart signs
everyone out. The alternative (sessions in the ConfigMap) would write on every request and
turn a login token into configuration. Signing in again after a restart is acceptable; a
ConfigMap write per request is not. Sessions carry an absolute TTL -- no sliding renewal, so
a stolen token cannot be kept alive forever by using it.

THE BOOTSTRAP PASSWORD IS SHOWN ONCE. `bootstrap()` creates the `admin` account on first
startup with a random password, returned to the caller to log ONCE. It is not written to the
store, so "show it again" is not a feature that can leak later. `must_change` forces a new
password at first login, enforced server-side -- not just rendered by the UI.
"""

from __future__ import annotations

import datetime
import hashlib
import hmac
import json
import logging
import secrets
import threading
import time
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)

# The store. A separate ConfigMap from weirvern-env so a settings merge can never touch account
# records, and so the RBAC story for each is readable on its own.
USERS_CONFIGMAP = "weirvern-users"
USERS_KEY = "users.json"

ROLE_ADMIN = "admin"
ROLE_VIEWER = "viewer"
ROLES: tuple[str, ...] = (ROLE_ADMIN, ROLE_VIEWER)

# Password floor. Length is the only rule: composition classes ("one number, one symbol")
# measurably push people toward predictable patterns (`Password1!`) without adding entropy.
MIN_PASSWORD_LEN = 8
MAX_PASSWORD_LEN = 256
MIN_USERNAME_LEN = 1
MAX_USERNAME_LEN = 32

# scrypt parameters. n=2^14 with r=8,p=1 is ~16 MiB and tens of milliseconds: expensive
# enough to matter offline, fast enough that a login does not feel broken.
_SCRYPT_N = 16384
_SCRYPT_R = 8
_SCRYPT_P = 1
_SCRYPT_DKLEN = 32
_SCRYPT_MAXMEM = 64 * 1024 * 1024
_SALT_BYTES = 16

# How long a session lives. Absolute, not sliding.
SESSION_TTL_S = 12 * 3600

# The bootstrap account created once, when the store is empty.
BOOTSTRAP_USERNAME = "admin"


class UserError(Exception):
    """A refused account operation, with a reason written for the operator."""


# ── hashing ──────────────────────────────────────────────────────────────────────────────


def hash_password(password: str) -> str:
    """A self-describing scrypt hash. Never returns or embeds the password itself."""
    salt = secrets.token_bytes(_SALT_BYTES)
    digest = hashlib.scrypt(
        password.encode("utf-8"), salt=salt,
        n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=_SCRYPT_DKLEN,
        maxmem=_SCRYPT_MAXMEM,
    )
    return (f"scrypt$n={_SCRYPT_N}$r={_SCRYPT_R}$p={_SCRYPT_P}$"
            f"{salt.hex()}${digest.hex()}")


def verify_password(password: str, encoded: str) -> bool:
    """Whether `password` matches a stored hash. False on any malformed input.

    A malformed stored hash must refuse, not raise: one corrupt record should fail the one
    login it belongs to, not take the whole login route down for everyone.
    """
    try:
        scheme, n_s, r_s, p_s, salt_hex, hash_hex = (encoded or "").split("$")
        if scheme != "scrypt":
            return False
        digest = hashlib.scrypt(
            (password or "").encode("utf-8"), salt=bytes.fromhex(salt_hex),
            n=int(n_s.split("=")[1]), r=int(r_s.split("=")[1]), p=int(p_s.split("=")[1]),
            dklen=len(bytes.fromhex(hash_hex)), maxmem=_SCRYPT_MAXMEM,
        )
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(digest.hex(), hash_hex)


# A fixed salt used only to equalise login timing. See `dummy_verify`.
_DUMMY_SALT = b"\x00" * _SALT_BYTES


def dummy_verify(password: str) -> bool:
    """Burn the same scrypt cost as a real verification, then return False.

    Called when the username does not exist. Without it, a login for an unknown account
    returns in microseconds (no hash to check) while a wrong password takes ~50ms, and the
    difference tells an attacker which usernames exist. Always False -- there is no input
    that makes this succeed.
    """
    import contextlib

    with contextlib.suppress(ValueError, TypeError):
        hashlib.scrypt(
            (password or "").encode("utf-8"), salt=_DUMMY_SALT,
            n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=_SCRYPT_DKLEN,
            maxmem=_SCRYPT_MAXMEM,
        )
    return False


# ── validation ───────────────────────────────────────────────────────────────────────────


def validate_username(username: str) -> str:
    """The canonical username, or raise. Lowercase, narrow charset."""
    name = (username or "").strip().lower()
    if not (MIN_USERNAME_LEN <= len(name) <= MAX_USERNAME_LEN):
        raise UserError(
            f"a username must be {MIN_USERNAME_LEN}-{MAX_USERNAME_LEN} characters"
        )
    if not all(c.isalnum() or c in "._-" for c in name):
        raise UserError("a username may contain letters, digits, dot, dash and underscore only")
    return name


def validate_password(password: str) -> None:
    """Raise unless the password meets the length floor. Length is the whole policy."""
    if not isinstance(password, str) or len(password) < MIN_PASSWORD_LEN:
        raise UserError(f"a password must be at least {MIN_PASSWORD_LEN} characters")
    if len(password) > MAX_PASSWORD_LEN:
        raise UserError(f"a password may be at most {MAX_PASSWORD_LEN} characters")


# ── identities ───────────────────────────────────────────────────────────────────────────


@dataclass
class Identity:
    """Who a request is, and what it may do.

    `via` is "session" for a signed-in account and "token" for the break-glass operator
    token, which has no username and no password to change -- both are reported to the UI so
    the Account panel can say so instead of offering a form that cannot work.
    """

    username: str
    role: str
    must_change: bool = False
    via: str = "session"

    @property
    def is_admin(self) -> bool:
        return self.role == ROLE_ADMIN


# ── the store ────────────────────────────────────────────────────────────────────────────


@dataclass
class UserRecord:
    username: str
    role: str
    hash: str
    must_change: bool = False
    created_at: str = ""
    updated_at: str = ""

    def to_json(self) -> dict[str, Any]:
        return {
            "username": self.username, "role": self.role, "hash": self.hash,
            "must_change": self.must_change, "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_json(cls, entry: dict[str, Any]) -> UserRecord:
        return cls(
            username=str(entry.get("username") or ""),
            role=str(entry.get("role") or ROLE_VIEWER),
            hash=str(entry.get("hash") or ""),
            must_change=bool(entry.get("must_change")),
            created_at=str(entry.get("created_at") or ""),
            updated_at=str(entry.get("updated_at") or ""),
        )

    def public(self) -> dict[str, Any]:
        """The record as the API returns it: NEVER the hash."""
        return {
            "username": self.username, "role": self.role,
            "must_change": self.must_change, "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


def _stamp() -> str:
    return datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


class UserStore:
    """The accounts, read from and written to a ConfigMap through the cluster client.

    The client is duck-typed (read / patch_data / create), which is what the tests drive --
    the real one is `weirvern.admin.cluster_config.ClusterConfig` bound to `weirvern-users`.

    CACHED IN MEMORY, refreshed on every write made through this object. Login validates
    against the cache so the hot path never reads the Kubernetes API; the cache is loaded
    once at startup and after each change. A second replica editing the same store is not a
    supported configuration (the GUI runs one replica), and that limit is stated rather than
    hidden behind a reload interval.
    """

    def __init__(self, client) -> None:
        self._client = client
        self._lock = threading.Lock()
        self._records: list[UserRecord] = []
        self._loaded = False
        # TRI-STATE, and each state means something different:
        #   True  -- the ConfigMap exists (accounts may be empty or populated)
        #   False -- the ConfigMap is confirmed ABSENT (first start: create it)
        #   None  -- the read FAILED and absence could not be confirmed (do not touch it)
        # Treating None as False would let a transient read failure bootstrap a fresh
        # document over live accounts; treating it as True would let an absent store stay
        # unprovisioned forever. Neither assumption is safe, so the state is carried.
        self.exists: bool | None = False

    # -- read ------------------------------------------------------------------

    def load(self) -> list[UserRecord]:
        """Read the store ONCE. Sets `exists`; an unreadable store is an empty list + None."""
        raw = ""
        exists: bool | None = None
        try:
            data = self._client.read()
            if isinstance(data, dict):
                exists = True
                raw = str(data.get(USERS_KEY) or "")
        except Exception as exc:  # noqa: BLE001
            # A MISSING ConfigMap is the normal first-start state and is distinguished from
            # every other failure, because bootstrap only creates the store when absence is
            # CONFIRMED. See the `exists` comment above.
            from weirvern.admin.cluster_config import NotFoundError

            exists = False if isinstance(exc, NotFoundError) else None
            logger.info("user store read: exists=%s (%s)", exists, exc)
        records: list[UserRecord] = []
        if raw.strip():
            try:
                doc = json.loads(raw)
                for entry in (doc.get("users") or []):
                    if isinstance(entry, dict) and entry.get("username"):
                        records.append(UserRecord.from_json(entry))
            except ValueError as exc:
                logger.warning("user store is not valid JSON; refusing to guess at accounts: %s", exc)
                records = []
        with self._lock:
            self._records = records
            self._loaded = True
            self.exists = exists
        return list(records)

    def snapshot(self) -> list[UserRecord]:
        """The cached records. Loads once if nothing has been read yet."""
        with self._lock:
            if not self._loaded:
                pass
            else:
                return list(self._records)
        return self.load()

    def has_users(self) -> bool:
        return bool(self.snapshot())

    def find(self, username: str) -> UserRecord | None:
        name = (username or "").strip().lower()
        for entry in self.snapshot():
            if entry.username == name:
                return entry
        return None

    def public_users(self) -> list[dict[str, Any]]:
        return [u.public() for u in self.snapshot()]

    # -- write -----------------------------------------------------------------

    def _persist(self, records: list[UserRecord]) -> None:
        """Write the whole document, then refresh the cache from what we wrote.

        ONE KEY, WHOLE DOCUMENT. A merge patch that replaced individual user objects would
        need the API to understand list semantics; writing one JSON blob under one key is the
        merge semantics the ConfigMap actually has. Read-modify-write races are possible in
        principle and not defended against: the GUI is a single replica and account changes
        are rare, and pretending to a stronger guarantee would be worse than stating this.
        """
        doc = json.dumps({"users": [u.to_json() for u in records]}, indent=1)
        if self.exists:
            self._client.patch_data({USERS_KEY: doc})
        else:
            try:
                self._client.create({USERS_KEY: doc})
                self.exists = True
            except Exception:  # noqa: BLE001
                # A create that fails because it already exists (another replica, or a race
                # with a previous boot) is fine -- patch it instead.
                self._client.patch_data({USERS_KEY: doc})
                self.exists = True
        with self._lock:
            self._records = list(records)
            self._loaded = True

    def create_user(self, username: str, role: str, password: str,
                    must_change: bool = False) -> UserRecord:
        name = validate_username(username)
        if role not in ROLES:
            raise UserError(f"role must be one of {', '.join(ROLES)}")
        validate_password(password)
        records = self.snapshot()
        if any(u.username == name for u in records):
            raise UserError(f"a user named '{name}' already exists")
        now = _stamp()
        record = UserRecord(username=name, role=role, hash=hash_password(password),
                            must_change=must_change, created_at=now, updated_at=now)
        self._persist(records + [record])
        return record

    def set_password(self, username: str, password: str, must_change: bool = False) -> None:
        validate_password(password)
        records = self.snapshot()
        target = next((u for u in records if u.username == username), None)
        if target is None:
            raise UserError(f"no user named '{username}'")
        target.hash = hash_password(password)
        target.must_change = must_change
        target.updated_at = _stamp()
        self._persist(records)

    def set_role(self, username: str, role: str) -> None:
        if role not in ROLES:
            raise UserError(f"role must be one of {', '.join(ROLES)}")
        records = self.snapshot()
        target = next((u for u in records if u.username == username), None)
        if target is None:
            raise UserError(f"no user named '{username}'")
        # THE LAST ADMIN IS A GUARD, not a courtesy: demoting or deleting the only admin
        # locks account management (and settings editing) behind an account that no longer
        # has the role, with the break-glass token as the only way back in.
        if target.role == ROLE_ADMIN and role != ROLE_ADMIN:
            admins = [u for u in records if u.role == ROLE_ADMIN]
            if len(admins) <= 1:
                raise UserError(
                    "this is the only admin. Create or promote another admin first — "
                    "demoting the last one leaves nobody able to manage accounts."
                )
        target.role = role
        target.updated_at = _stamp()
        self._persist(records)

    def delete_user(self, username: str) -> None:
        records = self.snapshot()
        target = next((u for u in records if u.username == username), None)
        if target is None:
            raise UserError(f"no user named '{username}'")
        if target.role == ROLE_ADMIN:
            admins = [u for u in records if u.role == ROLE_ADMIN]
            if len(admins) <= 1:
                raise UserError(
                    "this is the only admin and cannot be deleted. Create another admin first."
                )
        self._persist([u for u in records if u.username != username])


# ── sessions ─────────────────────────────────────────────────────────────────────────────


class SessionRegistry:
    """In-memory sessions with an absolute TTL. Restart means re-login; see the module doc."""

    def __init__(self, ttl_s: int = SESSION_TTL_S) -> None:
        self._ttl = ttl_s
        self._lock = threading.Lock()
        self._sessions: dict[str, tuple[Identity, float]] = {}

    def create(self, identity: Identity) -> str:
        token = secrets.token_urlsafe(32)
        with self._lock:
            self._prune_locked()
            self._sessions[token] = (identity, time.time() + self._ttl)
        return token

    def get(self, token: str | None) -> Identity | None:
        if not token:
            return None
        with self._lock:
            entry = self._sessions.get(token)
            if entry is None:
                return None
            identity, expires = entry
            if time.time() >= expires:
                del self._sessions[token]
                return None
            return identity

    def revoke(self, token: str | None) -> None:
        if not token:
            return
        with self._lock:
            self._sessions.pop(token, None)

    def revoke_user(self, username: str) -> int:
        """Drop every session for an account. Called when it is deleted or its role changes,
        so an open tab cannot keep acting under the old role until its TTL happens to lapse."""
        name = (username or "").strip().lower()
        with self._lock:
            doomed = [t for t, (ident, _e) in self._sessions.items() if ident.username == name]
            for t in doomed:
                del self._sessions[t]
        return len(doomed)

    def _prune_locked(self) -> None:
        now = time.time()
        for t in [t for t, (_i, e) in self._sessions.items() if now >= e]:
            del self._sessions[t]


class LoginThrottle:
    """A bounded, escalating delay for failed logins, per client address.

    Same shape as the token gate's: enough to make guessing expensive, never a lockout --
    a lockout on a LAN tool lets anyone who can reach the port deny the operator access to
    their own sensor.
    """

    _DELAY_AFTER = 3
    _MAX_DELAY_S = 5.0
    _MAX_TRACKED = 1024

    def __init__(self) -> None:
        self._failures: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def record_failure(self, client: str) -> None:
        if not client:
            return
        with self._lock:
            if len(self._failures) > self._MAX_TRACKED and client not in self._failures:
                self._failures.pop(next(iter(self._failures)), None)
            self._failures.setdefault(client, []).append(time.time())

    def clear(self, client: str) -> None:
        with self._lock:
            self._failures.pop(client or "", None)

    def delay_for(self, client: str) -> float:
        if not client:
            return 0.0
        with self._lock:
            attempts = len(self._failures.get(client, []))
        if attempts < self._DELAY_AFTER:
            return 0.0
        return min(self._MAX_DELAY_S, 0.25 * (attempts - self._DELAY_AFTER + 1))


# ── bootstrap ────────────────────────────────────────────────────────────────────────────


@dataclass
class BootstrapResult:
    """What bootstrap did. `password` is returned to be LOGGED AND DISCARDED, never stored."""

    created: bool = False
    username: str = ""
    password: str = ""
    note: str = ""


def bootstrap(store: UserStore, log: logging.Logger | None = None) -> BootstrapResult:
    """Create the default admin when the store has no accounts. Returns the password once.

    RUNS AT STARTUP, NOT ON FIRST LOGIN. An account that is created on first login would have
    to be created by the request that is trying to authenticate against it -- a
    chicken-and-egg shape that invites a default-credentials window. Creating it at startup
    means the deployment either has an admin with a known-once password, or a visible reason
    why it does not.
    """
    log = log or logger
    if store.has_users():
        return BootstrapResult(created=False, note="accounts already exist")
    if store.exists is None:
        # The store could not be read and its absence could NOT be confirmed. Creating one
        # here could shadow accounts that exist and happened to be unreadable this boot -- a
        # transient failure must never turn into a data-loss event.
        return BootstrapResult(
            created=False,
            note="the user store could not be read; no accounts were created this startup",
        )
    password = secrets.token_urlsafe(9)  # 12 chars, the length floor is 8
    try:
        store.create_user(BOOTSTRAP_USERNAME, ROLE_ADMIN, password, must_change=True)
    except Exception as exc:  # noqa: BLE001
        # Not just UserError: on a cluster-less GUI the create fails for a transport reason,
        # and that is a normal state (a workstation showing local data), not a crash.
        return BootstrapResult(created=False, note=f"could not create the admin account: {exc}")
    # ── WHERE THE PASSWORD IS PUBLISHED, AND WHY NOT THE POD LOG ───────────────────────────────
    #
    # MEASURED DEFECT (triaged from an independent finding, 2026-09-23). This used to log the
    # password at WARNING. The reasoning was sound -- the log is the only place the value is
    # knowable, and `kubectl logs` is what an operator runs at install time -- but the AUDIENCE was
    # wrong. `Role/weirvern-viewer` grants `pods/log: get`, and the README hands viewers exactly
    # that kubeconfig, because reading logs is what a viewer does. So a read-only account could
    # recover an ADMIN credential.
    #
    # The exposure was bounded: the account is created with `must_change=True`, so the password
    # cannot be used indefinitely, and the window is from first startup until the first sign-in.
    # But "a viewer can read the admin password" is a privilege escalation whatever its duration,
    # and it is the kind that would pass a code review because the log line reads like a courtesy.
    #
    # SO IT GOES TO A CONFIGMAP INSTEAD, which the roles treat differently: `weirvern-operator`
    # may read and patch configmaps, and `weirvern-viewer` may not read them at all. The credential
    # is therefore visible to exactly the accounts that can already change the deployment, which is
    # the correct audience for a bootstrap secret.
    #
    # The log line now says WHERE to look rather than what the value is, so an operator following
    # the old instructions finds a pointer instead of nothing, and an installer that greps this
    # message still learns that an account was created.
    published = False
    try:
        _publish_bootstrap_secret(log, BOOTSTRAP_USERNAME, password)
        published = True
    except Exception as exc:  # noqa: BLE001
        # A deployment without the RBAC to write a ConfigMap (a workstation running the GUI
        # locally) is a normal state, not a failure -- but then the value must still be obtainable,
        # so fall back to the log AND say that the fallback is the less private channel.
        log.warning(
            "created the initial admin account. username: %s  password: %s  -- change it after "
            "signing in. (Shown here because this deployment cannot write the bootstrap "
            "ConfigMap: %s. On a cluster deployment the password goes there instead, because "
            "reading pod logs is granted to viewers.)",
            BOOTSTRAP_USERNAME, password, type(exc).__name__,
        )
        return BootstrapResult(created=True, username=BOOTSTRAP_USERNAME, password=password)
    if published:
        log.warning(
            "created the initial admin account. username: %s  -- the password is in the "
            "weirvern-bootstrap ConfigMap (kubectl -n %s get cm weirvern-bootstrap -o "
            "jsonpath='{.data.password}'), which viewers cannot read. Change it after signing in; "
            "it will not be shown again.",
            BOOTSTRAP_USERNAME, _namespace(),
        )
    return BootstrapResult(created=True, username=BOOTSTRAP_USERNAME, password=password)


def _namespace() -> str:
    try:
        with open("/var/run/secrets/kubernetes.io/serviceaccount/namespace") as fh:
            return fh.read().strip()
    except OSError:
        return "weirvern"


def _publish_bootstrap_secret(log, username: str, password: str) -> None:
    """Write the bootstrap credential to a ConfigMap, and make sure the write LANDED.

    ── THE FIRST VERSION OF THIS WAS BROKEN, AND ONLY RUNNING IT SHOWED THAT ───────────────────
    It shelled out to `kubectl apply -f -`. The GUI image does not contain kubectl -- measured in
    the deployed pod:

        FileNotFoundError: [Errno 2] No such file or directory: 'kubectl'

    The code had a fallback, so it would not have crashed: it would have logged the password
    instead, which is precisely the defect this change exists to remove. A fix that silently
    degrades to the thing it is fixing is worse than no fix, because the log line would look like
    the documented behaviour.

    The pod DOES write ConfigMaps already -- `cluster_config.ClusterConfig` talks to the API
    directly with the ServiceAccount token, and the GUI uses it for every settings change. That is
    the mechanism used here, so this path is one the deployment already exercises.

    A ConfigMap rather than a Secret on purpose: the Secret holding the operator token is created
    out of band and is not writable by this ServiceAccount, and adding write access would let a
    compromised GUI rotate the credential it authenticates with. The ConfigMap carries one
    short-lived value, and `weirvern-viewer` has no read on it.

    VERIFIED WITH A READ-BACK rather than trusting the write: this project has been burned by
    commands that succeeded while the effect did not happen, and here the consequence would be an
    operator who cannot sign in at all.
    """
    from weirvern.admin import cluster_config  # noqa: PLC0415

    cm_name = "weirvern-bootstrap"
    payload = {
        "username": username,
        "password": password,
        "note": (
            "the initial admin password. Delete this object once you have signed in and changed "
            "it. It is here rather than in the pod log because reading pod logs is granted to the "
            "viewer role."
        ),
    }
    cfg = cluster_config.ClusterConfig(configmap=cm_name)
    created = False
    try:
        cfg.create(payload)
        created = True
    except cluster_config.ConfigError as exc:
        if "already exists" not in str(exc):
            raise
    if not created:
        # A pre-existing object means a previous startup already published a credential, or this
        # one is being re-run. Replace the data rather than failing: the account that exists NOW is
        # the one whose password must be readable, and a stale value would send the operator to a
        # password that no longer works.
        cfg.patch_data(payload)

    # READ BACK. The write's exit status says the API accepted the request; only a read says the
    # VALUE is there. Lengths are reported rather than contents, so a mismatch cannot leak the
    # password into a log while diagnosing why.
    back = cfg.read()
    if back.get("password") != password:
        raise RuntimeError(
            "the bootstrap ConfigMap did not contain the expected value "
            f"(read back {len(back.get('password') or '')} chars, expected {len(password)})"
        )
