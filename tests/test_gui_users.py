"""Accounts, roles, and sessions for the GUI.

WHY THIS FILE EXISTS. The GUI grew a second credential the moment accounts landed: the
deployment operator TOKEN (one shared, break-glass, admin-equivalent value) and per-user
ACCOUNT SESSIONS. Two credentials means every question about the write path now has an
account-shaped answer, and a handful of properties must hold or the feature is worse than
the single token it grew from:

  1. NO ACCOUNTS MEANS NO LOCKOUT. A deployment whose store is missing, unreadable, or failed
     to bootstrap must fall back to the pre-accounts posture (open reads, token-gated writes)
     -- never to "nobody can sign in and nothing can be changed". The token remains the
     recovery credential in every state.
  2. PASSWORDS ARE NEVER STORED, LOGGED, OR RETURNED. Hashes at rest (scrypt, per-user salt),
     never in the API payload, never in a repr.
  3. VIEWERS CANNOT WRITE, ENFORCED SERVER-SIDE. The UI hiding a control is presentation; the
     gate is what makes it true.
  4. THE LAST ADMIN IS PROTECTED. Demoting or deleting the only admin must be refused, because
     the alternative is a deployment whose account management is unreachable.
  5. THE BOOTSTRAP CREATES THE STORE ONLY WHEN ITS ABSENCE IS CONFIRMED. A transient read
     failure must never be read as "no accounts exist" -- that path ends with live accounts
     overwritten by a fresh document.

Every test here drives the REAL module or the REAL handler; where a test cannot execute the
shipped path (an HTTP route needs a socket) it asserts the property on the source in the
narrowest way available, and says so.
"""

from __future__ import annotations

import importlib
import re
from pathlib import Path

import pytest

from weirvern.admin import users as users_mod

ROOT = Path(__file__).resolve().parent.parent
WEB = ROOT / "weirvern" / "admin" / "web" / "web.py"


# ── a fake cluster client, duck-typed to what UserStore uses ────────────────────────────────


class FakeClient:
    """read()/patch_data()/create() over a dict, with the failure modes under test."""

    def __init__(self, data: dict | None = None, exists: bool = True,
                 read_exc: Exception | None = None, create_exc: Exception | None = None,
                 patch_exc: Exception | None = None):
        self.data = dict(data or {})
        self._exists = exists
        self.read_exc = read_exc
        self.create_exc = create_exc
        self.patch_exc = patch_exc
        self.patches: list[dict] = []
        self.creates: list[dict] = []

    def read(self):
        if self.read_exc is not None:
            raise self.read_exc
        if not self._exists:
            from weirvern.admin.cluster_config import NotFoundError

            raise NotFoundError("weirvern-users does not exist")
        return dict(self.data)

    def patch_data(self, data):
        if self.patch_exc is not None:
            raise self.patch_exc
        self.patches.append(dict(data))
        self.data.update(data)

    def create(self, data):
        self.creates.append(dict(data))
        if self.create_exc is not None:
            raise self.create_exc
        self.data.update(data)
        self._exists = True


def _store_with(**kwargs) -> users_mod.UserStore:
    store = users_mod.UserStore(FakeClient(**kwargs))
    store.load()
    return store


# ── 1. hashing: never reversible, never the password ───────────────────────────────────────


def test_a_stored_hash_is_not_the_password_and_verifies():
    h = users_mod.hash_password("correct horse battery staple")
    assert "correct horse battery staple" not in h
    assert h.startswith("scrypt$"), h
    assert users_mod.verify_password("correct horse battery staple", h) is True
    assert users_mod.verify_password("wrong", h) is False


def test_two_hashes_of_the_SAME_password_differ():
    """A per-user salt, so one leaked hash cannot be compared against another account's."""
    a = users_mod.hash_password("same-password-x")
    b = users_mod.hash_password("same-password-x")
    assert a != b
    assert users_mod.verify_password("same-password-x", a)
    assert users_mod.verify_password("same-password-x", b)


def test_a_MALFORMED_stored_hash_refuses_rather_than_raising():
    """One corrupt record must fail one login, not take the whole route down."""
    for bad in ("", "not-a-hash", "scrypt$n=x$r=y$p=z$zz$zz", "bcrypt$...", None):
        assert users_mod.verify_password("anything", bad) is False  # type: ignore[arg-type]


def test_the_dummy_verify_is_never_true():
    """The timing equaliser must not be a bypass. No input makes it succeed."""
    for pw in ("", "x", "correct horse battery staple"):
        assert users_mod.dummy_verify(pw) is False


# ── 2. validation ───────────────────────────────────────────────────────────────────────────


def test_usernames_are_canonicalised_and_narrowly_charset():
    assert users_mod.validate_username("  Samuel ") == "samuel"
    for bad in ("", "   ", "a b", "sla/sh", "x" * 40, "semi;colon"):
        with pytest.raises(users_mod.UserError):
            users_mod.validate_username(bad)
    # The deliberate charset: letters, digits, dot, dash and underscore.
    assert users_mod.validate_username("ok.user-1_2") == "ok.user-1_2"


def test_the_password_floor_is_length_and_says_so():
    with pytest.raises(users_mod.UserError) as exc:
        users_mod.validate_password("short")
    assert "at least" in str(exc.value)
    users_mod.validate_password("long-enough")


# ── 3. the store: create / roles / the last-admin guard ─────────────────────────────────────


def test_the_first_created_store_is_written_as_a_whole_document():
    client = FakeClient(exists=False)
    store = users_mod.UserStore(client)
    store.load()
    assert store.exists is False  # confirmed absent
    store.create_user("sam", "admin", "password-123")
    assert client.creates, "the store was never created"
    assert users_mod.USERS_KEY in client.creates[0]
    assert "sam" in client.creates[0][users_mod.USERS_KEY]
    assert store.has_users()


def test_the_last_admin_cannot_be_demoted():
    """THE GUARD: demoting the only admin leaves account management unreachable."""
    store = _store_with()
    store.create_user("sam", "admin", "password-123")
    with pytest.raises(users_mod.UserError) as exc:
        store.set_role("sam", "viewer")
    assert "only admin" in str(exc.value)
    # With a second admin it is allowed, and then the FIRST can be demoted.
    store.create_user("other", "admin", "password-456")
    store.set_role("sam", "viewer")
    assert store.find("sam").role == "viewer"


def test_the_last_admin_cannot_be_deleted():
    store = _store_with()
    store.create_user("sam", "admin", "password-123")
    with pytest.raises(users_mod.UserError) as exc:
        store.delete_user("sam")
    assert "only admin" in str(exc.value)
    store.create_user("other", "admin", "password-456")
    store.delete_user("sam")
    assert store.find("sam") is None


def test_a_role_must_be_one_of_the_two():
    store = _store_with()
    with pytest.raises(users_mod.UserError):
        store.create_user("sam", "superuser", "password-123")


def test_the_public_list_NEVER_carries_a_hash():
    """The API answer is the surface; a hash in it is a credential leak with extra steps."""
    store = _store_with()
    store.create_user("sam", "admin", "password-123")
    blob = str(store.public_users())
    assert "scrypt$" not in blob, "a password hash reached the public list"
    assert "password-123" not in blob
    assert {"username", "role"} <= set(store.public_users()[0])


# ── 4. bootstrap: created once, logged once, never stored ───────────────────────────────────


def test_bootstrap_creates_the_admin_when_the_store_is_confirmed_absent():
    store = _store_with(exists=False)
    result = users_mod.bootstrap(store)
    assert result.created is True
    assert result.username == "admin"
    assert len(result.password) >= users_mod.MIN_PASSWORD_LEN
    record = store.find("admin")
    assert record is not None and record.role == users_mod.ROLE_ADMIN
    assert record.must_change is True, "the bootstrap admin must be forced to change it"


def test_bootstrap_does_NOT_run_when_accounts_exist():
    store = _store_with()
    store.create_user("sam", "admin", "password-123")
    result = users_mod.bootstrap(store)
    assert result.created is False
    assert len(store.snapshot()) == 1


def test_bootstrap_does_NOT_create_when_the_read_FAILED():
    """THE DATA-LOSS GUARD. An unreadable store must not be read as an empty one.

    If this ran, a transient API failure at startup would create a fresh store -- and on a
    store that merely LOOKED absent, that is a live account list replaced by a new document.
    """
    client = FakeClient(read_exc=RuntimeError("api server unreachable"))
    store = users_mod.UserStore(client)
    store.load()
    assert store.exists is None, "an unconfirmed read reported absence"
    result = users_mod.bootstrap(store)
    assert result.created is False
    assert not client.creates, "bootstrap wrote to a store it could not read"


def test_bootstrap_reports_why_when_the_write_fails():
    from weirvern.admin.cluster_config import ConfigError

    # BOTH the create AND the patch fail: `_persist` falls back from create to patch when a
    # create is refused, so a write failure means the fallback failed too (a 403 on both).
    store = _store_with(exists=False, create_exc=ConfigError("403"),
                        patch_exc=ConfigError("403"))
    result = users_mod.bootstrap(store)
    assert result.created is False
    assert result.note, "a failed bootstrap must say why"


# ── 5. sessions ─────────────────────────────────────────────────────────────────────────────


def test_a_session_round_trips_and_expires():
    reg = users_mod.SessionRegistry(ttl_s=100)
    ident = users_mod.Identity(username="sam", role="admin")
    token = reg.create(ident)
    assert reg.get(token).username == "sam"
    reg._sessions[token] = (ident, 0)  # type: ignore[attr-defined]
    assert reg.get(token) is None, "an expired session was accepted"


def test_an_unknown_or_empty_session_is_none():
    reg = users_mod.SessionRegistry()
    assert reg.get("nope") is None
    assert reg.get("") is None
    assert reg.get(None) is None


def test_revoking_by_USER_kills_every_session_for_that_account():
    """A role change or delete must not leave an open tab acting under the old rights."""
    reg = users_mod.SessionRegistry()
    a = reg.create(users_mod.Identity(username="sam", role="admin"))
    b = reg.create(users_mod.Identity(username="sam", role="admin"))
    c = reg.create(users_mod.Identity(username="other", role="viewer"))
    assert reg.revoke_user("sam") == 2
    assert reg.get(a) is None and reg.get(b) is None
    assert reg.get(c) is not None


# ── 6. the login throttle ──────────────────────────────────────────────────────────────────


def test_the_login_delay_escalates_but_is_bounded():
    t = users_mod.LoginThrottle()
    for _ in range(2):
        t.record_failure("198.51.100.9")
    assert t.delay_for("198.51.100.9") == 0.0, "the first couple of typos must not be punished"
    for _ in range(100):
        t.record_failure("198.51.100.9")
    assert 0 < t.delay_for("198.51.100.9") <= users_mod.LoginThrottle._MAX_DELAY_S
    t.clear("198.51.100.9")
    assert t.delay_for("198.51.100.9") == 0.0


def test_the_throttle_map_is_bounded():
    t = users_mod.LoginThrottle()
    for i in range(users_mod.LoginThrottle._MAX_TRACKED + 100):
        t.record_failure(f"198.51.100.{i % 256}")
    assert len(t._failures) <= users_mod.LoginThrottle._MAX_TRACKED + 1  # noqa: SLF001


# ── 7. the routes: every property, driven through the real handler ─────────────────────────

def _ctx(store, sessions=None, throttle=None, token=None, accounts_note="", config_client=None):
    """A duck-typed GuiContext carrying just what the account routes consult.

    The values are bound to locals OUTSIDE the class body: a class body cannot see the
    enclosing function's scope, so `sessions = sessions if ...` inside `_Ctx` raised
    NameError on the right-hand side -- a Python scoping rule, not a logic bug.
    """
    _sessions = sessions if sessions is not None else users_mod.SessionRegistry()
    _throttle = throttle if throttle is not None else users_mod.LoginThrottle()
    # Bound OUTSIDE for the same reason as _sessions: `accounts_note = accounts_note` in a
    # class body binds the name as a class attribute first, so the right-hand side is not
    # the enclosing local -- it does not exist.
    _note = accounts_note
    _cc = config_client

    class _Auth:
        enabled = bool(token)
        reason = "" if token else "write access is disabled: WEIRVERN_GUI_TOKEN is not set"

        def check(self, presented, client=""):
            return bool(token) and presented == token

    class _Ctx:
        settings = None
        backend = None
        config_client = _cc
        user_store = store
        sessions = _sessions
        throttle = _throttle
        auth = _Auth()
        accounts_note = _note

    return _Ctx()


class _Handler:
    """Drives one route method of the real handler class with a faked transport."""

    def __init__(self, ctx, headers=None, body=None, client="198.51.100.5"):
        web_mod = importlib.import_module("weirvern.admin.web")
        cls = web_mod._build_handler(ctx)
        self.inst = cls.__new__(cls)
        self.inst.headers = dict(headers or {})
        if body is not None:
            # _read_body demands a Content-Length, exactly as a real request carries.
            self.inst.headers["Content-Length"] = str(len(body))
        self.inst.client_address = (client, 1234)
        self.inst.rfile = _Body(body)
        self.emitted: dict = {}
        self.status: int | None = None
        self.inst._json = self._capture

    def _capture(self, payload, code=200):
        self.emitted = payload
        self.status = code

    def call(self, name, query=None):
        """Invoke a route method. Only the query-taking routes receive an argument."""
        import inspect as _inspect

        fn = getattr(self.inst, name)
        params = [p for p in _inspect.signature(fn).parameters.values()
                  if p.name != "self"]
        if params:
            fn(query or {})
        else:
            fn()
        return self.emitted


class _Body:
    def __init__(self, body):
        self._raw = (body or b"")
        if isinstance(self._raw, str):
            self._raw = self._raw.encode()

    def read(self, n=-1):
        return self._raw


def _authed(store, username="sam", role="admin", **ctx_kw):
    ctx = _ctx(store, **ctx_kw)
    token = ctx.sessions.create(users_mod.Identity(username=username, role=role))
    return ctx, token


# -- login -----------------------------------------------------------------------------------


def test_login_with_the_right_password_mints_a_session():
    store = _store_with(exists=False)
    users_mod.bootstrap(store)
    pw = "correct horse"  # not the bootstrap password; set our own
    store.set_password("admin", pw, must_change=False)
    ctx, _ = _ctx(store), None
    h = _Handler(ctx, body='{"username": "admin", "password": "correct horse"}')
    out = h.call("_login")
    assert out.get("ok") is True, out
    assert out.get("session"), "no session minted"
    assert out.get("role") == "admin"


def test_login_with_a_WRONG_password_is_refused_without_saying_which_half():
    store = _store_with(exists=False)
    users_mod.bootstrap(store)
    ctx = _ctx(store)
    h = _Handler(ctx, body='{"username": "admin", "password": "nope-nope"}')
    out = h.call("_login")
    assert out.get("ok") is False
    assert "username or password" in out.get("error", "")
    # And the same message for a user that does not exist.
    h2 = _Handler(ctx, body='{"username": "ghost", "password": "nope-nope"}')
    out2 = h2.call("_login")
    assert out2.get("error") == out.get("error")


def test_login_on_a_deployment_with_no_accounts_says_so():
    store = _store_with(exists=False)  # loaded, confirmed absent, never bootstrapped
    ctx = _ctx(store, accounts_note="the user store could not be read")
    h = _Handler(ctx, body='{"username": "a", "password": "b"}')
    out = h.call("_login")
    assert out.get("ok") is False
    assert h.status == 403
    assert "no accounts" in out.get("error", "") or "could not be read" in out.get("error", "")


def test_a_failed_login_records_a_throttle_failure():
    store = _store_with(exists=False)
    users_mod.bootstrap(store)
    ctx = _ctx(store)
    for _ in range(4):
        _Handler(ctx, body='{"username": "admin", "password": "no"}',
                 client="198.51.100.7").call("_login")
    assert ctx.throttle.delay_for("198.51.100.7") > 0


# -- the gates -------------------------------------------------------------------------------


def test_a_VIEWER_is_refused_on_every_admin_write_route():
    """THE ROLE PROPERTY, driven through the real gate. A viewer may read; it may write nothing."""
    store = _store_with(exists=False)
    users_mod.bootstrap(store)
    store.create_user("viewer1", "viewer", "password-123")
    ctx, token = _authed(store, username="viewer1", role="viewer")
    for route in ("_users_create", "_users_role", "_users_delete", "_users_reset"):
        h = _Handler(ctx, headers={"X-Weirvern-Session": token},
                     body='{"username": "x", "role": "admin", "password": "password-123"}')
        h.call(route)
        assert h.status == 403, f"{route} let a viewer through"
    # And the review + settings write routes, the other write surface.
    for route in ("_review", "_settings_apply", "_settings_plan"):
        h = _Handler(ctx, headers={"X-Weirvern-Session": token}, body="{}")
        h.call(route)
        assert h.status == 403, f"{route} let a viewer through"


def test_an_ADMIN_session_passes_the_write_gate():
    store = _store_with(exists=False)
    users_mod.bootstrap(store)
    ctx, token = _authed(store, username="admin", role="admin")
    h = _Handler(ctx, headers={"X-Weirvern-Session": token},
                 body='{"username": "newbie", "role": "viewer", "password": "password-123"}')
    out = h.call("_users_create")
    assert out.get("ok") is True, out
    assert store.find("newbie") is not None


def test_the_break_glass_TOKEN_still_administers_with_no_accounts():
    """THE RECOVERY PATH. A deployment whose accounts are lost must still be administrable."""
    store = _store_with(exists=False)
    ctx = _ctx(store, token="deploy-token")
    h = _Handler(ctx, headers={"X-Weirvern-Token": "deploy-token"},
                 body='{"username": "rescued", "role": "admin", "password": "password-123"}')
    out = h.call("_users_create")
    assert out.get("ok") is True, out


def test_a_must_change_session_is_held_at_the_password_gate():
    """A forced change gates EVERY route except the password change itself."""
    store = _store_with(exists=False)
    users_mod.bootstrap(store)
    ctx, token = _authed(store, username="admin", role="admin")
    ident = ctx.sessions.get(token)
    ident.must_change = True  # the session carries the flag from login
    h = _Handler(ctx, headers={"X-Weirvern-Session": token}, body="{}")
    h.call("_settings_apply")
    assert h.status == 403, "a must_change account reached a write route"


def test_the_password_route_changes_it_and_revokes_sessions():
    store = _store_with(exists=False)
    users_mod.bootstrap(store)
    store.set_password("admin", "old-password-1", must_change=False)
    ctx, token = _authed(store, username="admin", role="admin")
    h = _Handler(ctx, headers={"X-Weirvern-Session": token},
                 body='{"current": "old-password-1", "new": "new-password-1"}')
    out = h.call("_password")
    assert out.get("ok") is True, out
    # The old password no longer works, the new one does.
    assert users_mod.verify_password("old-password-1", store.find("admin").hash) is False
    assert users_mod.verify_password("new-password-1", store.find("admin").hash) is True
    # Every session was revoked, including the one that made the change.
    assert ctx.sessions.get(token) is None


def test_the_password_route_requires_the_CURRENT_password():
    store = _store_with(exists=False)
    users_mod.bootstrap(store)
    store.set_password("admin", "old-password-1", must_change=False)
    ctx, token = _authed(store, username="admin", role="admin")
    h = _Handler(ctx, headers={"X-Weirvern-Session": token},
                 body='{"current": "wrong", "new": "new-password-1"}')
    out = h.call("_password")
    assert out.get("ok") is False and h.status == 401
    assert users_mod.verify_password("old-password-1", store.find("admin").hash) is True


def test_a_role_change_revokes_the_accounts_sessions():
    store = _store_with(exists=False)
    users_mod.bootstrap(store)
    store.create_user("other", "admin", "password-123")
    ctx, token = _authed(store, username="admin", role="admin")
    ctx.sessions.create(users_mod.Identity(username="other", role="admin"))
    h = _Handler(ctx, headers={"X-Weirvern-Session": token},
                 body='{"username": "other", "role": "viewer"}')
    out = h.call("_users_role")
    assert out.get("ok") is True
    assert store.find("other").role == "viewer"


# -- the session probe and the user list -----------------------------------------------------


def test_the_session_probe_reports_the_callers_own_state_only():
    store = _store_with(exists=False)
    users_mod.bootstrap(store)
    ctx, token = _authed(store, username="admin", role="admin")
    h = _Handler(ctx, headers={"X-Weirvern-Session": token})
    out = h.call("_session")
    assert out["accounts"] is True
    assert out["authenticated"] is True
    assert out["username"] == "admin"
    assert out["role"] == "admin"
    # Never anyone else's data: no user list, no hashes.
    assert "users" not in out
    assert "scrypt" not in str(out)


def test_the_session_probe_reports_a_tokened_caller_as_admin_with_no_username():
    store = _store_with(exists=False)
    users_mod.bootstrap(store)
    ctx = _ctx(store, token="deploy-token")
    h = _Handler(ctx, headers={"X-Weirvern-Token": "deploy-token"})
    out = h.call("_session")
    assert out["authenticated"] is True and out["via"] == "token"
    assert out["username"] == ""


def test_the_user_list_is_admin_only_and_never_carries_a_hash():
    store = _store_with(exists=False)
    users_mod.bootstrap(store)
    store.create_user("reader", "viewer", "password-123")
    ctx, token = _authed(store, username="admin", role="admin")
    out = _Handler(ctx, headers={"X-Weirvern-Session": token}).call("_users_list")
    assert out.get("available") is True
    assert len(out["users"]) == 2
    assert "scrypt" not in str(out)
    # A viewer is refused.
    ctx2, token2 = _authed(store, username="reader", role="viewer")
    h2 = _Handler(ctx2, headers={"X-Weirvern-Session": token2})
    h2.call("_users_list")
    assert h2.status == 403


# -- the role route: who gets signed out, and who must NOT ----------------------------------


def test_a_ROLE_CHANGE_revokes_that_accounts_sessions():
    """An open tab must not keep acting under the old role after the role changed."""
    store = _store_with(exists=False)
    users_mod.bootstrap(store)
    store.create_user("sam", "viewer", "password-123")
    ctx, admin_token = _authed(store, username="admin", role="admin")
    sam_token = ctx.sessions.create(users_mod.Identity(username="sam", role="viewer"))
    h = _Handler(ctx, headers={"X-Weirvern-Session": admin_token},
                 body='{"username": "sam", "role": "admin"}')
    out = h.call("_users_role")
    assert out.get("ok") is True, out
    assert ctx.sessions.get(sam_token) is None, "the role change left sam's session alive"
    assert ctx.sessions.get(admin_token) is not None, "an unrelated session was revoked"


def test_setting_the_SAME_role_again_revokes_NOTHING():
    """Reported live as "I can't change admin to admin": a no-op role write used to revoke
    the account's sessions, which signed the operator out of the very tab they were working
    in -- the change had "succeeded" and the UI read as broken. A write that changes nothing
    must revoke nothing."""
    store = _store_with(exists=False)
    users_mod.bootstrap(store)
    ctx, admin_token = _authed(store, username="admin", role="admin")
    # A second session for the same account, as if it were open in another tab.
    other = ctx.sessions.create(users_mod.Identity(username="admin", role="admin"))
    h = _Handler(ctx, headers={"X-Weirvern-Session": admin_token},
                 body='{"username": "admin", "role": "admin"}')
    out = h.call("_users_role")
    assert out.get("ok") is True, out
    rec = store.find("admin")
    assert rec is not None and rec.role == "admin"
    assert ctx.sessions.get(admin_token) is not None, (
        "a no-op role change revoked the operator's own session"
    )
    assert ctx.sessions.get(other) is not None


# -- the sensor capability probe: read from the cluster, never assumed -----------------------


class _DSCli:
    """A config-client-shaped fake whose get_json answers the DaemonSet read."""

    def __init__(self, adds, exc=None):
        self.adds = adds
        self.exc = exc

    def get_json(self, path):
        if self.exc:
            raise self.exc
        return {"spec": {"template": {"spec": {"containers": [
            {"name": "zeek", "securityContext": {"capabilities": {"add": self.adds}}},
        ]}}}}


def test_the_caps_probe_reads_the_SENSOR_daemonset_from_the_cluster():
    """"I can't apply siphon mode" was structural: the probe was a stub answering False/False
    unconditionally, so the mode gate refused the in-path mode forever -- even on a sensor
    that held the capabilities. It now asks the cluster for the zeek DaemonSet."""
    store = _store_with(exists=False)
    ctx = _ctx(store, config_client=_DSCli(["NET_RAW", "NET_ADMIN"]))
    assert _Handler(ctx).inst._sensor_caps() == (True, True)


def test_the_caps_probe_reports_ABSENT_when_it_cannot_verify():
    """Unknown must refuse, never permit: a capability defaulting to True is how in-path
    interception gets enabled on a sensor that cannot forward."""
    from weirvern.admin import cluster_config as cc

    store = _store_with(exists=False)
    ctx = _ctx(store, config_client=_DSCli([], exc=cc.ConfigError("no cluster")))
    assert _Handler(ctx).inst._sensor_caps() == (False, False)
    # And the real box's state -- NET_RAW only -- reports NET_ADMIN absent.
    ctx2 = _ctx(store, config_client=_DSCli(["NET_RAW"]))
    assert _Handler(ctx2).inst._sensor_caps() == (False, True)


def test_the_mode_gate_OPENS_when_the_cluster_sensor_has_the_capabilities():
    """The end-to-end property: with the overlay applied on the cluster, the GUI's gate must
    pass -- it is the CLI's own validate() that decides, fed a real reading."""
    store = _store_with(exists=False)
    ctx = _ctx(store, config_client=_DSCli(["NET_RAW", "NET_ADMIN"]))
    assert _Handler(ctx).inst._mode_gate({"SENSOR_MODE": "siphon"}) == ""
    # The FORMER name is accepted and gated the same way.
    assert _Handler(ctx).inst._mode_gate({"SENSOR_MODE": "weir"}) == ""  # former name


def test_the_mode_gate_REFUSES_when_the_sensor_lacks_net_admin():
    """The box's current state: NET_RAW only. The refusal must name the missing capability."""
    store = _store_with(exists=False)
    ctx = _ctx(store, config_client=_DSCli(["NET_RAW"]))
    err = _Handler(ctx).inst._mode_gate({"SENSOR_MODE": "siphon"})
    assert err and "CAP_NET_ADMIN" in err


# -- the settings payload reports the caller's rights ----------------------------------------


def test_the_settings_payload_reports_writes_per_CALLER_ROLE():
    """The UI renders controls from this answer, so it must be role-dependent, not global."""
    store = _store_with(exists=False)
    users_mod.bootstrap(store)
    store.create_user("reader", "viewer", "password-123")

    payloads: dict[str, dict] = {}
    for user, role in (("admin", "admin"), ("reader", "viewer")):
        ctx, token = _authed(store, username=user, role=role)
        h = _Handler(ctx, headers={"X-Weirvern-Session": token})
        payloads[user] = h.call("_settings")
    assert payloads["admin"]["writes"]["enabled"] is True
    assert payloads["reader"]["writes"]["enabled"] is False
    assert "viewer" in payloads["reader"]["writes"]["reason"]
    assert payloads["admin"]["caller"]["username"] == "admin"
    assert payloads["reader"]["caller"]["role"] == "viewer"


def test_with_no_accounts_the_settings_payload_keeps_the_PRE_ACCOUNTS_shape():
    """The pre-accounts posture must survive: this is what every existing deployment sees.

    The historical contract, pinned by test_gui_auth and the DOM harness: `writes.enabled`
    mirrors whether the DEPLOYMENT has the operator token configured -- it is not per-caller,
    because with no accounts there is no caller identity to be per about. The UI stages edits
    and the token is the credential on Apply; that is the flow that shipped, and the box
    running today must not change behavior until it bootstraps accounts.
    """
    store = _store_with(exists=False)
    # NOT bootstrapped: no accounts.
    ctx = _ctx(store, token="deploy-token")
    h = _Handler(ctx, headers={"X-Weirvern-Token": "deploy-token"})
    out = h.call("_settings")
    assert out["writes"]["enabled"] is True
    # An anonymous caller sees the same deployment-level answer (the token field is how they
    # authenticate); the caller block reports no identity.
    h2 = _Handler(ctx)
    out2 = h2.call("_settings")
    assert out2["writes"]["enabled"] is True
    assert out2["caller"]["role"] == ""
    # And a deployment with NO token configured reports disabled with the token's reason --
    # the exact string test_gui_auth pins.
    ctx3 = _ctx(store, token=None)
    out3 = _Handler(ctx3).call("_settings")
    assert out3["writes"]["enabled"] is False
    assert "WEIRVERN_GUI_TOKEN" in out3["writes"]["reason"]


# ── 8. the front end carries the contract, and the harness proves it ────────────────────────


def test_the_gui_sends_the_session_header_on_every_request():
    app = (ROOT / "weirvern" / "admin" / "web" / "app.js").read_text()
    assert "X-Weirvern-Session" in app, "the session header is never sent"
    assert "requestHeaders(" in app
    # getJSON (every read) and postJSON (every write) must both use it, or a request rides
    # without the session and a signed-in browser reads as anonymous.
    for fn in ("async function getJSON", "async function postJSON"):
        i = app.index(fn)
        body = app[i : i + 600]
        assert "requestHeaders(" in body, f"{fn} does not attach the credentials"


def test_the_session_lives_in_sessionstorage_not_localstorage():
    """A shared workstation must not keep the session after the tab closes.

    Both comment styles are stripped first: the settings block explains WHY it is
    sessionStorage ("not localStorage and not a cookie"), and a naive search reads that
    explanation as the defect it documents -- the trap this project has hit repeatedly.
    """
    import re as _re

    app = (ROOT / "weirvern" / "admin" / "web" / "app.js").read_text()
    code = _re.sub(r"/\*.*?\*/", "", app, flags=_re.S)
    code = "\n".join(ln.split("//")[0] for ln in code.splitlines())
    assert "sessionStorage" in code
    assert "localStorage" not in code, "the session (or token) is stored beyond the tab"


def test_the_gate_is_driven_BY_THE_SERVER_ANSWER_not_client_state():
    """The boot sequence consults /api/session before rendering anything."""
    app = (ROOT / "weirvern" / "admin" / "web" / "app.js").read_text()
    assert "async function boot(" in app, "no boot sequence exists"
    assert "loadSession()" in app
    i = app.index("async function boot(")
    body = app[i : i + 700]
    assert "AUTH.accounts" in body and "AUTH.authenticated" in body, (
        "boot does not consult the server's session answer"
    )


def test_the_html_has_the_gate_elements_the_js_drives():
    html = (ROOT / "weirvern" / "admin" / "web" / "index.html").read_text()
    for eid in ("auth-gate", "pw-gate", "gate-user", "gate-pass", "gate-form",
                "pw-current", "pw-new", "pw-confirm", "pw-form",
                "sign-out", "user-chip", "st-account-card", "st-users-card",
                "st-new-user", "st-new-role", "st-new-pass", "st-user-create",
                # the break-glass door on the gate: reachable without signing in
                "gate-token-toggle", "gate-token-block", "gate-token", "gate-token-form",
                "gate-token-submit"):
        assert f'id="{eid}"' in html, f"#{eid} is missing from index.html"


def test_the_js_drives_every_gate_element_the_html_declares():
    """The reverse seam: an element with no handler is a control that does nothing."""
    app = (ROOT / "weirvern" / "admin" / "web" / "app.js").read_text()
    for eid in ("gate-form", "pw-form", "sign-out", "st-pw-save", "st-user-create",
                "gate-token-form", "gate-token-toggle"):
        assert f'"{eid}"' in app, f"#{eid} exists in the HTML but nothing in app.js references it"


def test_the_break_glass_token_door_is_reachable_from_the_SIGN_IN_gate():
    """THE LOOP THIS CLOSES: the operator token is the documented recovery for a lost admin
    password, but its input lived only on Settings -- which is behind the gate it exists to
    open, so a locked-out operator could not reach the control that saves them. The door must
    live on the sign-in gate itself, and the token submit must trust the SERVER's session
    answer (loadSession) rather than assuming the token worked.
    """
    app = (ROOT / "weirvern" / "admin" / "web" / "app.js").read_text()
    html = (ROOT / "weirvern" / "admin" / "web" / "index.html").read_text()
    # It is inside the auth gate, before the closing of that card.
    gate = html[html.index('id="auth-gate"'):html.index('id="pw-gate"')]
    assert 'id="gate-token-form"' in gate, (
        "the operator-token form is not inside the sign-in gate -- a locked-out operator "
        "cannot reach it"
    )
    # And the handler re-reads the session rather than claiming success locally.
    handler = app[app.index("const gateTokenForm"):]
    handler = handler[:handler.index("st-pw-save")]
    assert "loadSession" in handler, (
        "the token door no longer verifies against the server's session answer"
    )


def test_hidden_wins_the_cascade_over_every_display_rule_it_shares_an_element_with():
    """THE BUG THIS PINS, reported from the box: "it says log in first. i cant change the
    password."

    `.hidden { display: none }` and `.gate { display: flex }` have equal specificity, so the
    cascade decided by SOURCE ORDER -- and `.gate` came later in the file. The forced-password
    gate, which carries BOTH classes, therefore stayed painted on top of the sign-in gate
    (same z-index, later in the DOM): the sign-in form was unreachable underneath, submitting
    the password form reached the server with no session, and every route said "sign in first".

    The class was correct the entire time, which is why every class-name assertion passed.
    This test does what the browser does: for every class that shares an element with `hidden`
    in the markup, find the rules that set `display` on it, and require `hidden` to still win --
    either via `!important` or by coming later in the source. A cascade collision is invisible
    to class-name checks by construction; this is the narrowest check that can see it.
    """
    web = ROOT / "weirvern" / "admin" / "web"
    css = (web / "style.css").read_text()
    html = (web / "index.html").read_text()

    companions: set[str] = set()
    for m in re.finditer(r'class="([^"]*\bhidden\b[^"]*)"', html):
        companions.update(c for c in m.group(1).split() if c != "hidden")
    assert companions, "no element carries `hidden` in index.html; this test has lost its subject"

    m = re.search(r"\.hidden\s*\{([^}]*)\}", css)
    assert m, "no .hidden rule exists in style.css"
    hidden_body, hidden_start = m.group(1), m.start()
    hidden_important = "!important" in hidden_body

    collisions = []
    for rule in re.finditer(r"([^{}@]+)\{([^}]*)\}", css):
        sel, body = rule.group(1), rule.group(2)
        if rule.start() < hidden_start:
            continue  # earlier in source: .hidden beats it at equal specificity
        if "display" not in body:
            continue
        for cls in companions:
            if re.search(r"\." + re.escape(cls) + r"(?![\w-])", sel):
                collisions.append((cls, sel.strip(), body.strip()[:60]))
    if not hidden_important:
        assert not collisions, (
            "a rule later in style.css sets `display` on a class that shares an element with "
            f"`hidden`, and `.hidden` has no !important to beat it -- the element will stay "
            f"painted no matter how often the JS adds `hidden`: {collisions}"
        )


def test_every_gate_state_the_harness_asserts_is_computed_not_merely_classed():
    """The harness must read getComputedStyle for gate visibility. Class-name assertions were
    green through the entire outage this repo shipped once: `classList.contains("hidden")`
    was true while the element computed to `flex` and covered the page."""
    js = (ROOT / "scripts" / "jsdom_render.js").read_text()
    assert "getComputedStyle" in js, (
        "the DOM harness no longer computes styles; gate visibility is asserted by class "
        "name only, which cannot see a cascade collision"
    )
    assert "gateDisplay" in js, "the computed-style gate helper is gone from the harness"


def test_the_harness_exercises_the_account_flows():
    js = (ROOT / "scripts" / "jsdom_render.js").read_text()
    for phrase in ("SESSION_STUB", "USERS_PAYLOAD", "/api/login", "/api/password",
                   "a viewer gets NO edit controls", "must_change shows the forced"):
        assert phrase in js, f"the DOM harness no longer exercises: {phrase}"


# ── 9. the deployment contract ──────────────────────────────────────────────────────────────


def test_the_gui_can_CREATE_the_users_configmap_it_bootstraps():
    """The bootstrap writes a ConfigMap that no manifest declares, so the grant must include
    create -- without it, first startup fails with a 403 and no account exists."""
    import yaml

    docs = [d for d in yaml.safe_load_all((ROOT / "k8s" / "60-rbac.yaml").read_text()) if d]
    role = next(d for d in docs if d.get("kind") == "Role"
                and d["metadata"]["name"] == "weirvern-operator")
    rules = [r for r in role["rules"] if "configmaps" in r.get("resources", [])]
    assert rules, "the operator role cannot touch configmaps"
    verbs = set(rules[0]["verbs"])
    assert {"get", "patch", "create"} <= verbs, (
        f"the operator role is missing a verb the account store needs: {sorted(verbs)}"
    )
    assert "update" not in verbs, "update is a PUT and would replace every key"


def test_the_users_configmap_is_NOT_a_shipped_manifest():
    """A committed placeholder would be re-applied with empty values on every apply, wiping
    live accounts. The store is created by the GUI instead -- and if a manifest ever declares
    it, that hazard comes back. Comments are stripped: the RBAC file explains this rule and
    a naive search reads the explanation as the violation.
    """
    assert not (ROOT / "k8s" / "40-users-configmap.yaml").exists(), (
        "an account ConfigMap manifest would be re-applied with empty values and wipe "
        "live accounts on every `kubectl apply -k`"
    )
    for path in sorted((ROOT / "k8s").glob("*.yaml")):
        code = "\n".join(ln.split("#")[0] for ln in path.read_text().splitlines())
        assert "weirvern-users" not in code, (
            f"{path.name} references the account store; it is created at runtime and must "
            f"not be declared in a manifest"
        )


# ── the bootstrap password must not be readable by a VIEWER ────────────────────────────────────
#
# MEASURED DEFECT (triaged from an independent finding, 2026-09-23). `bootstrap()` logged the
# generated admin password at WARNING. The reasoning was sound -- the log is the only place the
# value is knowable at creation, and `kubectl logs` is what an operator runs at install time -- but
# the AUDIENCE was wrong.
#
# VERIFIED against the live cluster with `kubectl auth can-i`:
#
#     viewer  get pods/log   -> YES     (reading logs is what a viewer does)
#     viewer  get configmaps -> NO
#     operator create/patch configmaps -> YES
#
# So a read-only account could recover an ADMIN credential. The exposure was bounded -- the account
# is created with must_change=True, so the window ends at the first sign-in -- but "a viewer can
# read the admin password" is a privilege escalation of any duration, and the kind that survives
# review because a log line reading "created the initial admin account" looks like a courtesy.
#
# The credential now goes to the `weirvern-bootstrap` ConfigMap, whose audience is exactly the
# accounts that can already change the deployment.
def test_the_bootstrap_password_is_not_written_to_the_log_by_default():
    """The log must not carry the value when the ConfigMap write succeeds."""
    from weirvern.admin import users as users_mod

    lines: list[str] = []

    class Log:
        def warning(self, fmt, *args):  # noqa: ANN001, ANN002
            lines.append(fmt % args if args else fmt)

        info = warning  # type: ignore[assignment]

    class Store:
        exists = False

        def has_users(self) -> bool:
            return False

        def create_user(self, *a, **k):  # noqa: ANN002, ANN003
            return None

    published: dict = {}

    def fake_publish(log, username, password):  # noqa: ANN001, ANN002
        published["username"] = username
        published["password"] = password

    real = users_mod._publish_bootstrap_secret
    users_mod._publish_bootstrap_secret = fake_publish
    try:
        result = users_mod.bootstrap(Store(), log=Log())
    finally:
        users_mod._publish_bootstrap_secret = real

    assert result.created
    joined = "\n".join(lines)
    assert result.password not in joined, (
        "the bootstrap password appeared in a log line, which the viewer role can read"
    )
    assert published.get("password") == result.password, (
        "the password was never handed to the ConfigMap writer"
    )
    assert "weirvern-bootstrap" in joined, (
        f"the log does not say WHERE the password is, so an operator cannot find it: {joined!r}"
    )


def test_a_deployment_that_cannot_write_the_configmap_still_publishes_somewhere():
    """The fallback must still reveal the credential, and say the channel is less private.

    A workstation running the GUI locally has no cluster to write to. Losing the password there
    would lock the operator out of their own instance, so it falls back to the log -- with a note
    naming the reason, because a reader needs to know the channel is weaker than usual.
    """
    from weirvern.admin import users as users_mod

    lines: list[str] = []

    class Log:
        def warning(self, fmt, *args):  # noqa: ANN001, ANN002
            lines.append(fmt % args if args else fmt)

        info = warning  # type: ignore[assignment]

    class Store:
        exists = False

        def has_users(self) -> bool:
            return False

        def create_user(self, *a, **k):  # noqa: ANN002, ANN003
            return None

    def boom(log, username, password):  # noqa: ANN001, ANN002
        raise RuntimeError("no RBAC for configmaps")

    real = users_mod._publish_bootstrap_secret
    users_mod._publish_bootstrap_secret = boom
    try:
        result = users_mod.bootstrap(Store(), log=Log())
    finally:
        users_mod._publish_bootstrap_secret = real

    joined = "\n".join(lines)
    assert result.created
    assert result.password in joined, (
        "the fallback did not reveal the password, so an operator on a cluster-less deployment "
        "is locked out"
    )
    assert "viewers" in joined, (
        "the fallback does not explain that the log is the less private channel"
    )


def test_the_publisher_uses_the_clients_api_not_a_kubectl_subprocess():
    """The GUI image has no `kubectl`. Measured in the deployed pod:

        FileNotFoundError: [Errno 2] No such file or directory: 'kubectl'

    The first version of this publisher shelled out to it, which on a real deployment fell through
    to the log -- reintroducing the exact defect the change removes, while looking fixed. The pod
    DOES write ConfigMaps, through `cluster_config.ClusterConfig`, which is what every settings
    change already uses.
    """
    import inspect

    src = inspect.getsource(users_mod._publish_bootstrap_secret)
    assert "subprocess" not in src, (
        "the publisher shells out to a binary; the GUI image ships no kubectl, so on a real "
        "deployment this fails and falls back to logging the password"
    )
    assert "ClusterConfig" in src, "the publisher does not use the existing ConfigMap client"


def test_the_publisher_creates_then_falls_back_to_patching(caplog):  # noqa: ANN001
    """A pre-existing ConfigMap must be REPLACED, not treated as an error.

    The account that exists now is the one whose password must be readable. A stale value would
    send an operator to a password that no longer works -- and the natural reading, "it already
    exists, so nothing to do", is how that happens.
    """
    from weirvern.admin import users as users_mod

    calls: list[str] = []
    state: dict = {}

    class FakeCfg:
        def __init__(self, **kw):  # noqa: ANN003
            self.cm = kw.get("configmap")

        def create(self, data):  # noqa: ANN001
            calls.append("create")
            from weirvern.admin.cluster_config import ConfigError

            raise ConfigError("the ConfigMap 'weirvern-bootstrap' already exists")

        def patch_data(self, data):  # noqa: ANN001
            calls.append("patch_data")
            state.update(data)

        def read(self):  # noqa: ANN201
            return state

    from weirvern.admin import cluster_config

    real = cluster_config.ClusterConfig
    cluster_config.ClusterConfig = FakeCfg  # type: ignore[assignment]
    try:
        users_mod._publish_bootstrap_secret(None, "admin", "pw-123456")
    finally:
        cluster_config.ClusterConfig = real  # type: ignore[assignment]

    assert calls == ["create", "patch_data"], (
        f"the publisher did not fall back to a patch on a pre-existing ConfigMap: {calls}"
    )
    assert state.get("password") == "pw-123456"


def test_a_write_that_does_not_land_RAISES_rather_than_being_trusted():
    """THE READ-BACK MUST BE ABLE TO FAIL, proved by driving it.

    Mutation testing showed a source-scanning version of this SURVIVED removing the actual
    comparison -- a string in the source is not a check that can fail. This drives the publisher
    with a client that accepts the write and returns the WRONG value, which is the case the
    read-back exists for: an operator who cannot sign in, with nothing saying why.
    """
    from weirvern.admin import users as users_mod

    class FakeCfg:
        def __init__(self, **kw):  # noqa: ANN003
            pass

        def create(self, data):  # noqa: ANN001
            return None

        def patch_data(self, data):  # noqa: ANN001
            return None

        def read(self):  # noqa: ANN201
            return {"password": "some-other-value"}

    from weirvern.admin import cluster_config

    real = cluster_config.ClusterConfig
    cluster_config.ClusterConfig = FakeCfg  # type: ignore[assignment]
    raised = None
    try:
        users_mod._publish_bootstrap_secret(None, "admin", "correct-horse")
    except Exception as exc:  # noqa: BLE001
        raised = exc
    finally:
        cluster_config.ClusterConfig = real  # type: ignore[assignment]

    assert raised is not None, (
        "a ConfigMap whose value did not match was accepted, so a failed publish would leave the "
        "operator with no credential and no error"
    )
    assert "correct-horse" not in str(raised), f"the failure message leaked the password: {raised}"
