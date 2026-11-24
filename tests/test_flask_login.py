"""Register, sign in, sign out -- through the rendered UI, on the shared credential path.

The point of these tests is that the SECOND surface does not get its own opinion. Password
verification, timing equalisation, throttling and the audit trail all live in
`requestauth.authenticate`, which the console API calls too, so what is asserted here is that the
Flask routes DELEGATE to it and carry its answer correctly -- not that Flask has a login
implementation of its own.

The cookie is the one deliberate divergence from the API. `gui_auth` refuses a cookie for sessions
because a cookie rides along on cross-site requests; a browser navigating between pages has nowhere
else to put a token, so this surface signs a cookie instead, HttpOnly and SameSite=Strict, and
checks a CSRF nonce on every form post. Those two properties are tested here rather than assumed.
"""

import re

import pytest

flask = pytest.importorskip("flask")

from weirvern.admin import flask_app, requestauth  # noqa: E402
from weirvern.admin import users as users_mod  # noqa: E402

# ── a context with a real store and a real session registry ───────────────────────────────────

class _FakeK8s:
    """The minimal client a UserStore persists through."""

    def __init__(self):
        self.data: dict = {}
        self.exists = False

    def read(self):
        if not self.exists:
            from weirvern.admin.cluster_config import NotFoundError

            raise NotFoundError("weirvern-users does not exist")
        return dict(self.data)

    def create(self, data):
        self.data = dict(data)
        self.exists = True

    def patch_data(self, data):
        self.data = dict(data)
        self.exists = True


def _ctx(*, with_store=True, accounts_note=""):
    note = accounts_note

    class _Auth:
        enabled = False

        def check(self, presented, client=""):
            return False

    class _Ctx:
        settings = None
        backend = None
        config_client = None
        connect_factory = staticmethod(lambda settings: None)
        throttle = users_mod.LoginThrottle()
        sessions = users_mod.SessionRegistry()
        auth = _Auth()
        accounts_note = note

        def __init__(self):
            self.user_store = None

    ctx = _Ctx()
    if with_store:
        store = users_mod.UserStore(_FakeK8s())
        store.load()
        ctx.user_store = store
    return ctx


def _app(ctx, secret="test-secret-not-a-deployment-key"):
    app = flask_app.create_app(ctx, secret_key=secret)
    app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
    return app


def _csrf(client, path="/login"):
    """Read the nonce out of the rendered form, the way a browser would."""
    body = client.get(path).data.decode("utf-8", "replace")
    m = re.search(r'name="csrf" value="([^"]+)"', body)
    assert m, f"no CSRF nonce in the form at {path}: {body[:300]}"
    return m.group(1)


# ── the rendered pages exist and are forms, not string assembly ──────────────────────────────

def test_the_login_page_renders_a_real_form():
    ctx = _ctx(with_store=False)
    body = _app(ctx).test_client().get("/login").data.decode()

    assert "<form" in body and 'method="post"' in body
    assert 'name="username"' in body and 'name="password"' in body
    assert "csrf" in body, "the form carries no CSRF nonce"


def test_register_is_open_on_a_FIRST_RUN_and_says_which_role_it_grants():
    """A self-service register form that accepted a role would be a privilege-escalation hole, so
    the page must state the role it gives rather than offer a choice."""
    ctx = _ctx()                       # a real store with no accounts yet
    body = _app(ctx).test_client().get("/register").data.decode()

    assert 'name="password2"' in body
    assert "viewer" in body.lower(), "the page does not say which role registration grants"
    assert 'name="role"' not in body, "the form offers a role selector -- that is an escalation hole"


def test_register_is_CLOSED_once_an_account_exists():
    ctx = _ctx()
    ctx.user_store.create_user("sam", users_mod.ROLE_ADMIN, "a long enough password")

    got = _app(ctx).test_client().get("/register")

    assert got.status_code == 403
    assert b"self-registration is closed" in got.data


def test_register_is_CLOSED_when_the_store_is_unreadable():
    """An unreadable store is not an empty one; registration must fail closed."""
    class _Broken:
        exists = None

        def has_users(self):
            return False

    ctx = _ctx()
    ctx.user_store = _Broken()

    got = _app(ctx).test_client().get("/register")

    assert got.status_code == 403
    assert b"self-registration is closed" in got.data


def test_an_oversized_body_is_refused_before_it_is_read():
    """Werkzeug must reject it, not the view after get_data() buffered it."""
    got = _app(_ctx()).test_client().post(
        "/login", data=b"x" * (70 * 1024), content_type="application/json")

    assert got.status_code == 413
    assert b"64 KiB" in got.data


# ── the flow ────────────────────────────────────────────────────────────────────────────────

def test_register_then_sign_in_then_sign_out():
    ctx = _ctx()
    app = _app(ctx)
    client = app.test_client()

    nonce = _csrf(client, "/register")
    got = client.post("/register", data={
        "username": "sam", "password": "a long enough password",
        "password2": "a long enough password", "csrf": nonce,
    })
    assert got.status_code == 302, got.data[:300]
    assert got.headers["Location"].endswith("/home")

    # the account landed in the SHARED store, so the console can sign it in too
    assert ctx.user_store.find("sam") is not None

    home = client.get("/home")
    assert home.status_code == 200
    assert b"sam" in home.data

    # sign out revokes the registry token and clears the cookie
    body = client.get("/home").data.decode()
    logout_nonce = re.search(r'name="csrf" value="([^"]+)"', body).group(1)
    out = client.post("/logout", data={"csrf": logout_nonce})
    assert out.status_code == 302
    assert client.get("/home").status_code == 302, "the session survived a sign out"


def test_the_cookie_session_also_authenticates_the_api():
    """One carrier, read and write alike: the rendered form's cookie must not read as anonymous."""
    ctx = _ctx()
    client = _app(ctx).test_client()

    nonce = _csrf(client, "/register")
    client.post("/register", data={
        "username": "sam", "password": "a long enough password",
        "password2": "a long enough password", "csrf": nonce,
    })

    got = client.get("/api/session")

    assert got.status_code == 200
    body = got.get_json()
    assert body["authenticated"] is True
    assert body["username"] == "sam"


def test_cross_origin_api_writes_are_refused():
    got = _app(_ctx()).test_client().post(
        "/api/login", json={}, headers={"Origin": "http://evil.example"})
    assert got.status_code == 403
    assert b"cross-origin" in got.data


def test_form_encoded_api_writes_are_refused():
    got = _app(_ctx()).test_client().post(
        "/api/login", data={"username": "sam"},
        content_type="application/x-www-form-urlencoded")
    assert got.status_code == 415
    assert b"application/json" in got.data


def test_a_wrong_password_is_refused_without_saying_which_half_was_wrong():
    ctx = _ctx()
    ctx.user_store.create_user("sam", users_mod.ROLE_VIEWER, "a long enough password")
    client = _app(ctx).test_client()

    nonce = _csrf(client)
    got = client.post("/login", data={"username": "sam", "password": "wrong", "csrf": nonce})

    assert got.status_code == 401
    body = got.data.decode()
    assert "username or password is not correct" in body
    # neither half may be named specifically
    assert "no such user" not in body.lower()
    assert "wrong password" not in body.lower()


def test_an_unknown_username_gets_the_SAME_sentence():
    ctx = _ctx()
    ctx.user_store.create_user("sam", users_mod.ROLE_VIEWER, "a long enough password")
    client = _app(ctx).test_client()

    nonce = _csrf(client)
    got = client.post("/login", data={"username": "nobody", "password": "wrong", "csrf": nonce})

    assert got.status_code == 401
    assert "username or password is not correct" in got.data.decode()


def test_the_cookie_is_httponly_and_samesite_strict():
    """The one divergence from the header-only API, and the reason it is acceptable."""
    app = _app(_ctx())
    assert app.config["SESSION_COOKIE_HTTPONLY"] is True
    assert app.config["SESSION_COOKIE_SAMESITE"] == "Strict"


def test_a_form_post_without_the_nonce_is_refused():
    ctx = _ctx()
    ctx.user_store.create_user("sam", users_mod.ROLE_VIEWER, "a long enough password")
    client = _app(ctx).test_client()

    got = client.post("/login", data={"username": "sam", "password": "a long enough password"})

    assert got.status_code == 400
    assert b"did not come from this page" in got.data


def test_a_form_post_with_a_WRONG_nonce_is_refused():
    ctx = _ctx()
    ctx.user_store.create_user("sam", users_mod.ROLE_VIEWER, "a long enough password")
    client = _app(ctx).test_client()

    client.get("/login")               # mint a real nonce in the cookie
    got = client.post("/login", data={"username": "sam", "password": "a long enough password",
                                      "csrf": "not-the-nonce"})

    assert got.status_code == 400


# ── the rendered UI refuses to sign cookies without a key ───────────────────────────────────

def test_without_a_signing_key_login_explains_and_refuses():
    """A hardcoded default key would sign every deployment's cookies with a public string. Refusing
    is the honest failure, and the JSON API keeps working because it authenticates by header."""
    ctx = _ctx(with_store=False)
    app = flask_app.create_app(ctx, secret_key="")
    app.config.update(TESTING=True)

    got = app.test_client().get("/login")

    assert b"WEIRVERN_FLASK_SECRET" in got.data, got.data[:300]
    assert b"JSON API still works" in got.data


# ── the shared path, not a second implementation ────────────────────────────────────────────

def test_the_rendered_login_DELEGATES_to_the_shared_credential_check(monkeypatch):
    """If Flask grew its own login, this replaces the shared function and the route must notice."""
    ctx = _ctx()
    called = {}

    def fake_authenticate(context, username, password, *, addr=""):
        called.update(username=username, addr=addr)
        return None, "", "the username or password is not correct"

    monkeypatch.setattr(requestauth, "authenticate", fake_authenticate, raising=True)
    client = _app(ctx).test_client()

    nonce = _csrf(client)
    got = client.post("/login", data={"username": "sam", "password": "x", "csrf": nonce})

    assert got.status_code == 401
    assert called.get("username") == "sam", (
        "the route did not call requestauth.authenticate, so this surface has its own login"
    )
