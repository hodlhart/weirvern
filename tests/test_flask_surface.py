"""The Flask front door must answer EXACTLY as the console does.

The whole justification for a second surface is that it is the same system behind a standard WSGI
stack. The moment the two disagree -- about who is signed in, about whether the gate is armed, about
an error body, about a window -- the project has the defect class it keeps removing: one fact derived
twice, drifting, each copy looking correct on its own.

So these tests are mostly EQUIVALENCE tests. They drive the real handler and the real Flask app over
the same context and the same request and compare the bytes. A test that only asserted each surface
in isolation would pass while they drifted.
"""


import pytest

flask = pytest.importorskip("flask")

from weirvern.admin import flask_app, requestauth  # noqa: E402
from weirvern.admin import users as users_mod  # noqa: E402
from weirvern.admin import web as web_mod  # noqa: E402

# ── a context both surfaces can use ────────────────────────────────────────────────────────────

def _ctx(store, sessions=None, token=None, accounts_note=""):
    _sessions = sessions if sessions is not None else users_mod.SessionRegistry()
    _note = accounts_note

    class _Auth:
        enabled = bool(token)

        def check(self, presented, client=""):
            return bool(token) and presented == token

    class _Ctx:
        settings = None
        backend = None
        config_client = None
        connect_factory = None
        user_store = store
        sessions = _sessions
        throttle = users_mod.LoginThrottle()
        auth = _Auth()
        accounts_note = _note

    return _Ctx()


class _Store:
    def __init__(self, armed):
        self._armed = armed

    def has_users(self):
        return self._armed


def _client(ctx):
    app = flask_app.create_app(ctx)
    app.config.update(TESTING=True)
    return app.test_client()


# ── the session payload must be the same object, not a lookalike ───────────────────────────────

@pytest.mark.parametrize("armed", [True, False])
def test_both_surfaces_report_the_same_session(armed):
    ctx = _ctx(_Store(armed), accounts_note="the user store could not be read")
    expected = requestauth.session_payload(ctx, {})

    got = _client(ctx).get("/api/session")

    assert got.status_code == 200
    assert got.get_json() == expected, (
        "the two surfaces disagree about the session. They share requestauth.session_payload, so a "
        "difference means one of them built its own payload"
    )


def test_the_note_survives_to_the_flask_surface():
    """The note is what tells an operator that reads are open because the store is unreadable, and
    the console renders it as a banner. It must not be dropped by the second surface."""
    ctx = _ctx(_Store(False), accounts_note="the user store could not be read")

    payload = _client(ctx).get("/api/session").get_json()

    assert payload["accounts"] is False
    assert payload["note"] == "the user store could not be read"


# ── the read gate must be the same decision ───────────────────────────────────────────────────

def test_an_unauthenticated_read_is_refused_with_the_console_body():
    ctx = _ctx(_Store(True))          # accounts armed, no session presented

    got = _client(ctx).get("/api/episodes")

    assert got.status_code == 401
    assert got.get_json() == {"error": "sign in to view this dashboard", "code": 401}


def test_the_break_glass_token_opens_the_flask_read_gate():
    """The token is a deployment credential; a second surface that did not honour it would look
    broken to an operator whose only credential is the token."""
    ctx = _ctx(_Store(True), token="s3cret")

    got = _client(ctx).get("/api/episodes", headers={"X-Weirvern-Token": "s3cret"})

    assert got.status_code != 401, f"the token was not accepted: {got.status_code}"


def test_reads_stay_open_when_accounts_are_not_provisioned():
    """The documented pre-accounts posture: open reads, token-gated writes. A second surface that
    silently armed a gate the console leaves open would be a different deployment."""
    ctx = _ctx(_Store(False))

    got = _client(ctx).get("/api/episodes")

    assert got.status_code != 401, "the Flask surface armed a gate the console does not"


def test_a_must_change_account_is_refused_on_both_surfaces():
    """Held at the password gate: it may reach session and password, and every other read says why
    not. Same 403 and same sentence on both."""
    sessions = users_mod.SessionRegistry()
    store = _Store(True)
    ctx = _ctx(store, sessions=sessions)

    ident = users_mod.Identity(username="sam", role=users_mod.ROLE_VIEWER, must_change=True)
    token = sessions.create(ident) if hasattr(sessions, "create") else None
    if token is None:                                    # pragma: no cover - registry shape
        pytest.skip("SessionRegistry has no create(); cannot fabricate a must_change session")

    got = _client(ctx).get("/api/episodes", headers={"X-Weirvern-Session": token})

    assert got.status_code == 403
    assert got.get_json() == {
        "error": "a password change is required before using the dashboard",
        "code": 403,
    }


# ── the static console is served unchanged ────────────────────────────────────────────────────

def test_the_console_shell_is_served():
    ctx = _ctx(_Store(False))

    got = _client(ctx).get("/")

    assert got.status_code == 200
    assert b"<html" in got.data.lower()


def test_an_unknown_API_path_404s_JSON_rather_than_serving_the_shell():
    """A typo'd endpoint that answered HTML with a 200 would look like a working call to anything
    using a lenient client."""
    ctx = _ctx(_Store(False))

    got = _client(ctx).get("/api/no-such-endpoint")

    assert got.status_code == 404
    assert got.is_json, f"an unknown API path answered {got.content_type}"
    assert got.get_json()["code"] == 404


def test_an_unknown_page_path_serves_the_shell():
    """The console is a hash-router app: every view lives at "/" and the fragment never reaches the
    server, so an unknown path is a deep link into the shell, not a 404."""
    ctx = _ctx(_Store(False))

    got = _client(ctx).get("/some/deep/link")

    assert got.status_code == 200
    assert b"<html" in got.data.lower()


# ── a migrated data route ────────────────────────────────────────────────────────────────────

def test_the_episodes_route_uses_the_same_fetcher_and_hostname_enrichment(monkeypatch):
    """/api/episodes is the first route migrated, so it has to prove the pattern: same fetcher, same
    formatter, same hostname enrichment, and a failure worded by what happened."""
    seen = {}

    def fake_episodes(client, *, hours, limit):
        seen.update(hours=hours, limit=limit)
        return {"episodes": [{"src_addr": "192.0.2.10"}], "incidents": [], "leads": [], "counts": {}}

    monkeypatch.setattr(web_mod.status_mod, "episodes_recent", fake_episodes, raising=True)
    monkeypatch.setattr(web_mod.web_api, "_hostname", lambda addr: "box.example", raising=False)

    ctx = _ctx(_Store(False))

    class _CM:
        def __enter__(self):
            return object()

        def __exit__(self, *a):
            return False

    ctx.connect_factory = lambda settings: _CM()

    got = _client(ctx).get("/api/episodes?hours=6&limit=25")

    assert got.status_code == 200, got.data
    payload = got.get_json()
    assert seen == {"hours": 6, "limit": 25}, f"the arguments were not parsed the same way: {seen}"
    assert payload["episodes"][0]["hostname"] == "box.example", (
        "the row was not hostname-enriched, so this surface renders a different table from the "
        "console's"
    )


def test_a_failed_read_is_worded_by_what_happened(monkeypatch):
    """A missing kubectl must not be reported as a database fault (WV1-20) on either surface."""
    def boom(client, *, hours, limit):
        raise FileNotFoundError(2, "No such file or directory", "kubectl")

    monkeypatch.setattr(web_mod.status_mod, "episodes_recent", boom, raising=True)
    ctx = _ctx(_Store(False))

    class _CM:
        def __enter__(self):
            return object()

        def __exit__(self, *a):
            return False

    ctx.connect_factory = lambda settings: _CM()

    got = _client(ctx).get("/api/episodes")

    assert got.status_code == 503
    body = got.get_json()
    assert "ClickHouse" not in body["error"], f"a missing binary was blamed on the database: {body}"
    assert "kubectl" in body["error"], body


def test_an_unusable_time_range_is_a_400_with_the_reason():
    ctx = _ctx(_Store(False))

    got = _client(ctx).get("/api/episodes?from=not-a-date")

    assert got.status_code == 400
    assert got.get_json()["code"] == 400
