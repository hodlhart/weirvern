"""Per-token GUI credentials: mint, use, revoke, and the guarantees around each.

WHY THIS FILE EXISTS. The GUI grew a SECOND kind of token. Before it, "a token" meant one shared
deployment value that was admin everywhere, so every question about tokens had one answer. Now a
token carries a role, can be revoked individually, and is minted through the API -- which means the
properties that make it safe are not obvious from any single route, and each one is worth a test
that can fail:

  1. A VIEWER TOKEN READS AND DOES NOT WRITE. Enforced at the gate, not by hiding a control.
  2. REVOCATION BITES ON THE NEXT REQUEST. No restart, no TTL, no cached verdict to wait out.
  3. A TOKEN CANNOT MANAGE TOKENS. Minting and revoking require a signed-in admin SESSION, in both
     roles, because a credential that can mint credentials can outlive its own revocation.
  4. THE PLAINTEXT IS SHOWN ONCE. It is absent from the list, the audit row, the logs and the store;
     only a SHA-256 digest and an eight-character display prefix are kept.
  5. THE LEGACY OPERATOR TOKEN IS UNTOUCHED. It stays admin-equivalent, and it keeps working even
     when the token store itself is broken -- otherwise the recovery credential depends on the thing
     it is supposed to recover from.

EVERY TEST DRIVES THE REAL FLASK SURFACE. Calling the store directly would prove the store works
while the route forgot to pass the store, or the gate read the wrong header. The routes are the
product; the store is only what they call.
"""

from __future__ import annotations

import hashlib
import json

import pytest

from weirvern.admin import flask_app, gui_auth, requestauth
from weirvern.admin import tokens as tokens_mod
from weirvern.admin import users as users_mod

SECRET = "test-secret-not-a-deployment-key"


# ── fakes: the cluster client, and a context the app can actually run on ──────────────────────


class FakeClient:
    """`read` / `patch_data` / `create` over a dict, with the failure modes under test."""

    def __init__(self, data: dict | None = None, exists: bool = True,
                 read_exc: Exception | None = None,
                 create_exc: Exception | None = None,
                 patch_exc: Exception | None = None):
        self.data = dict(data or {})
        self._exists = exists
        self.read_exc = read_exc
        self.create_exc = create_exc
        self.patch_exc = patch_exc
        self.reads = 0
        self.patches: list[dict] = []
        self.creates: list[dict] = []

    def read(self):
        self.reads += 1
        if self.read_exc is not None:
            raise self.read_exc
        if not self._exists:
            from weirvern.admin.cluster_config import NotFoundError

            raise NotFoundError("weirvern-tokens does not exist")
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


def token_store(client: FakeClient | None = None) -> tokens_mod.TokenStore:
    store = tokens_mod.TokenStore(client or FakeClient(exists=False))
    store.load()
    return store


def _account_store_with_admin() -> users_mod.UserStore:
    """A real account store holding one admin, so the READ gate is armed in these tests.

    Without accounts, reads are open (the documented pre-accounts posture) and a viewer token
    reading a page would prove nothing. The gate has to be ON for the read half to mean anything.
    """
    store = users_mod.UserStore(FakeClient(exists=False))
    store.load()
    store.create_user("admin", users_mod.ROLE_ADMIN, "admin-password-1")
    return store


class _Ctx:
    """A duck-typed GuiContext carrying exactly what the token and account routes consult."""

    settings = None
    backend = None
    config_client = None
    accounts_note = ""
    capabilities = None

    def __init__(self, tokens: tokens_mod.TokenStore, *, legacy: str = "",
                 users_store: users_mod.UserStore | None = None):
        self.token_store = tokens
        self.user_store = users_store or _account_store_with_admin()
        self.sessions = users_mod.SessionRegistry()
        self.throttle = users_mod.LoginThrottle()
        self.auth = gui_auth.AuthState(legacy, token_store=tokens)
        # An INSTANCE attribute, not a staticmethod: an instance attribute is not a descriptor, so
        # calling it passes exactly the settings argument and no implicit self.
        self.connect_factory = lambda _settings: None

    def admin_session(self, username: str = "admin") -> str:
        return self.sessions.create(
            users_mod.Identity(username=username, role=users_mod.ROLE_ADMIN))

    def viewer_session(self, username: str = "reader") -> str:
        return self.sessions.create(
            users_mod.Identity(username=username, role=users_mod.ROLE_VIEWER))


def client_for(ctx: _Ctx):
    app = flask_app.create_app(ctx, secret_key=SECRET)
    app.config.update(TESTING=True)
    return app.test_client()


def _token_headers(value: str) -> dict:
    return {gui_auth.AUTH_HEADER: value}


def _session_headers(value: str) -> dict:
    return {gui_auth.SESSION_HEADER: value}


def mint(ctx: _Ctx, *, role: str = "viewer", name: str = "ci") -> tuple[dict, str]:
    """Mint through the REAL admin route. Returns `(response JSON, plaintext)`."""
    got = client_for(ctx).post("/api/tokens/create", headers=_session_headers(ctx.admin_session()),
                               json={"name": name, "role": role})
    payload = got.get_json() or {}
    assert got.status_code == 200, payload
    assert payload.get("token"), payload
    return payload, payload["token"]


# ── 1. a viewer token reads, and is refused a write with the existing 403 shape ──────────────


def test_a_viewer_token_reads_but_is_refused_on_a_write_route():
    """THE ROLE PROPERTY. A token's role must be enforced by the gate, not by a hidden button."""
    ctx = _Ctx(token_store())
    _payload, viewer = mint(ctx, role="viewer")
    client = client_for(ctx)

    # The gate really is armed: an anonymous read is refused while accounts exist.
    assert client.get("/api/settings").status_code == 401

    read = client.get("/api/settings", headers=_token_headers(viewer))
    assert read.status_code == 200, read.data[:300]
    assert read.get_json().get("caller", {}).get("role") == "viewer", (
        "the read reported a different role than the token carries")

    refused = client.post("/api/settings/apply", headers=_token_headers(viewer), json={})
    payload = refused.get_json() or {}
    assert refused.status_code == 403, payload
    assert payload.get("code") == 403, f"not the console's error shape: {payload}"
    assert "viewer" in payload.get("error", ""), (
        f"the refusal does not say the TOKEN is a viewer: {payload}")


def test_an_admin_token_reads_and_writes():
    """The other half, so the viewer test cannot pass by refusing every token."""
    ctx = _Ctx(token_store())
    _payload, admin = mint(ctx, role="admin")
    client = client_for(ctx)

    assert client.get("/api/settings", headers=_token_headers(admin)).status_code == 200
    created = client.post("/api/users/create", headers=_token_headers(admin),
                          json={"username": "bytoken", "role": "viewer",
                                "password": "password-123", "must_change": True})
    assert created.status_code == 200, created.get_json()
    assert ctx.user_store.find("bytoken") is not None, "an admin token could not create an account"


def test_a_viewer_token_is_not_reported_as_an_admin():
    """The session probe drives the UI's admin controls, so it must report the TOKEN's role."""
    ctx = _Ctx(token_store())
    _payload, viewer = mint(ctx, role="viewer")

    probe = client_for(ctx).get("/api/session", headers=_token_headers(viewer)).get_json()

    assert probe["authenticated"] is True and probe["via"] == "token"
    assert probe["role"] == users_mod.ROLE_VIEWER, probe


# ── 2. revocation bites on the very next request ─────────────────────────────────────────────


def test_a_revoked_token_is_refused_on_the_very_next_request():
    """NO RESTART, NO TTL. The store that wrote the revocation must answer the next request.

    A SECOND LIVE TOKEN IS KEPT ON PURPOSE. With only the revoked one left, `enabled` would report
    the token path off and the request would be refused before the store was ever consulted -- the
    test would pass while `authenticate` happily returned the revoked record. Keeping one live token
    means the store IS consulted, so the `revoked` skip is the only thing that can refuse this
    credential. (Mutation-proofing found exactly that: deleting the skip once left this test green.)
    """
    ctx = _Ctx(token_store())
    payload, admin = mint(ctx, role="admin", name="doomed")
    _other_payload, other = mint(ctx, role="admin", name="kept")
    client = client_for(ctx)

    # It works right up to the revocation...
    assert client.get("/api/settings", headers=_token_headers(admin)).status_code == 200
    assert client.post("/api/users/create", headers=_token_headers(admin),
                       json={"username": "before", "role": "viewer",
                             "password": "password-123"}).status_code == 200

    revoked = client.post("/api/tokens/revoke",
                          headers=_session_headers(ctx.admin_session()),
                          json={"token_id": payload["record"]["token_id"]})
    assert revoked.status_code == 200, revoked.get_json()

    # ...and the NEXT request, on the same app and the same store object, is refused.
    after_read = client.get("/api/settings", headers=_token_headers(admin))
    assert after_read.status_code == 401, (
        f"a revoked token still read the dashboard: {after_read.status_code}")
    after_write = client.post("/api/users/create", headers=_token_headers(admin),
                              json={"username": "after", "role": "viewer",
                                    "password": "password-123"})
    # The status is 401 or 403 depending on whether the deployment still has another live token
    # (the gate's "disabled" branch answers 403, the "wrong or absent credential" branch 401). The
    # property under test is that it is REFUSED and nothing was written, so both are accepted.
    assert after_write.status_code in (401, 403), (
        f"a revoked token still wrote: {after_write.status_code}")
    assert ctx.user_store.find("after") is None
    # The other live token still works: the refusal above is the revocation, not a dead token path.
    assert client.get("/api/settings", headers=_token_headers(other)).status_code == 200


def test_revocation_is_scoped_to_the_one_token():
    """Revoking one credential must not take the rest of the deployment's access with it."""
    ctx = _Ctx(token_store())
    first, one = mint(ctx, role="viewer", name="first")
    _second, two = mint(ctx, role="viewer", name="second")

    client_for(ctx).post("/api/tokens/revoke", headers=_session_headers(ctx.admin_session()),
                         json={"token_id": first["record"]["token_id"]})

    assert client_for(ctx).get("/api/session", headers=_token_headers(one)).status_code == 200
    assert client_for(ctx).get("/api/session", headers=_token_headers(two)).status_code == 200
    assert ctx.token_store.find(first["record"]["token_id"]).revoked is True


# ── 3. a token cannot manage tokens, in either role ──────────────────────────────────────────


@pytest.mark.parametrize("role", ["admin", "viewer"])
def test_a_token_cannot_mint_a_token(role):
    """A credential that can mint credentials can outlive its own revocation."""
    ctx = _Ctx(token_store())
    _payload, presented = mint(ctx, role=role)
    before = len(ctx.token_store.snapshot())

    got = client_for(ctx).post("/api/tokens/create", headers=_token_headers(presented),
                               json={"name": "second", "role": "admin"})

    payload = got.get_json() or {}
    assert got.status_code == 403, f"a {role} token minted a token: {payload}"
    assert "signed-in admin" in payload.get("error", ""), (
        f"the refusal does not say what is missing: {payload}")
    assert len(ctx.token_store.snapshot()) == before, "a token was created anyway"


@pytest.mark.parametrize("role", ["admin", "viewer"])
def test_a_token_cannot_revoke_a_token(role):
    ctx = _Ctx(token_store())
    target, _target_value = mint(ctx, role="viewer", name="target")
    _payload, presented = mint(ctx, role=role, name="presenter")

    got = client_for(ctx).post("/api/tokens/revoke", headers=_token_headers(presented),
                               json={"token_id": target["record"]["token_id"]})

    assert got.status_code == 403, got.get_json()
    assert ctx.token_store.find(target["record"]["token_id"]).revoked is False, (
        "a token revoked another token")


def test_a_token_role_cannot_be_CHANGED_because_no_route_and_no_store_method_exists():
    """The third verb in "a token must not change a role": role is fixed at mint time.

    A token has no owner to re-authenticate, so a role change would be a silent privilege grant on
    a live credential. Rotation is mint + revoke, which leaves both events in the audit trail. This
    is asserted as an ABSENCE because that is how the guarantee is implemented -- there is nothing
    to drive.
    """
    assert not hasattr(tokens_mod.TokenStore, "set_role")
    for path in ("/api/tokens/role", "/api/tokens/set-role"):
        got = client_for(_Ctx(token_store())).post(path, json={"role": "admin"})
        assert got.status_code in (404, 405), f"{path} exists and could change a token's role"


def test_the_token_list_requires_a_signed_in_admin():
    """Inventory is admin data: a token must not enumerate the other tokens either."""
    ctx = _Ctx(token_store())
    _payload, admin_token = mint(ctx, role="admin")
    client = client_for(ctx)

    assert client.get("/api/tokens").status_code == 403
    assert client.get("/api/tokens",
                      headers=_session_headers(ctx.viewer_session())).status_code == 403
    assert client.get("/api/tokens", headers=_token_headers(admin_token)).status_code == 403
    listed = client.get("/api/tokens", headers=_session_headers(ctx.admin_session()))
    assert listed.status_code == 200 and listed.get_json()["available"] is True


# ── 4. the plaintext never leaves the create response ───────────────────────────────────────


def test_the_plaintext_never_reaches_the_list_the_audit_or_the_logs(caplog, monkeypatch):
    """THE ONE SECRET. It is returned once, and nowhere else -- including the log records."""
    import logging

    audit_calls: list[tuple] = []
    monkeypatch.setattr(requestauth, "audit_auth",
                        lambda ctx, action, username, reason: audit_calls.append(
                            (action, username, reason)))

    ctx = _Ctx(token_store())
    with caplog.at_level(logging.DEBUG):
        created, plaintext = mint(ctx, role="viewer", name="deploy-key")
        listed = client_for(ctx).get("/api/tokens",
                                     headers=_session_headers(ctx.admin_session())).get_json()

    assert len(plaintext) > 32 and plaintext.startswith("wvt_"), plaintext
    # The list is not empty, or the negative assertion below would prove nothing.
    assert [t["prefix"] for t in listed["tokens"]] == [plaintext[:8]], listed

    assert plaintext not in json.dumps(listed), "the secret reached the list response"
    assert plaintext not in str(audit_calls), f"the secret reached the audit row: {audit_calls}"
    assert plaintext not in caplog.text, "the secret reached a log record"
    assert plaintext not in json.dumps(ctx.token_store._client.data), (  # noqa: SLF001
        "the secret was written to the store")
    # ...while the fields that ARE meant to be there are: this is not a vacuous pass.
    assert audit_calls and audit_calls[-1][0] == "token-create"
    assert audit_calls[-1][1] == "deploy-key"
    assert "deploy-key" in caplog.text
    assert ctx.token_store.find(created["record"]["token_id"]) is not None


def test_the_store_holds_only_the_digest_and_the_display_prefix():
    """At rest: a SHA-256 digest, an eight-character label, and no recoverable credential."""
    store = token_store()
    record, plaintext = store.create_token("automation", "viewer", created_by="admin")

    document = json.dumps(store._client.data)  # noqa: SLF001
    assert hashlib.sha256(plaintext.encode()).hexdigest() in document
    assert record.token_hash == hashlib.sha256(plaintext.encode()).hexdigest()
    assert plaintext not in document
    assert record.prefix == plaintext[:8] and len(record.prefix) == 8
    # The prefix is an identifier, not the credential: it is far too short to be one.
    assert len(plaintext) - len(record.prefix) >= 32
    assert set(record.to_json()) == {
        "token_id", "name", "role", "token_hash", "prefix", "created_at", "created_by",
        "last_used_at", "revoked_at", "revoked_by"}


def test_a_minted_token_authenticates_and_records_its_last_use():
    store = token_store()
    record, plaintext = store.create_token("nightly", "viewer")

    matched = store.authenticate(plaintext)

    assert matched is not None and matched.token_id == record.token_id
    assert store.find(record.token_id).last_used_at, "a successful use was not recorded"
    assert store._client.patches, "last_used_at was never written back"  # noqa: SLF001
    # A wrong value is a miss, not an exception and not a match.
    assert store.authenticate(plaintext + "x") is None
    assert store.authenticate("") is None


def test_a_token_name_and_role_are_validated_with_sentences():
    store = token_store()
    with pytest.raises(tokens_mod.TokenError, match="name"):
        store.create_token("   ", "viewer")
    with pytest.raises(tokens_mod.TokenError, match="role"):
        store.create_token("ok", "superuser")
    with pytest.raises(tokens_mod.TokenError, match="no token"):
        store.revoke("does-not-exist")


# ── 5. the legacy WEIRVERN_GUI_TOKEN is still the break-glass admin ─────────────────────────


def test_the_legacy_operator_token_still_authorizes_as_admin():
    ctx = _Ctx(token_store(), legacy="break-glass-value")
    client = client_for(ctx)

    probe = client.get("/api/session",
                       headers=_token_headers("break-glass-value")).get_json()
    assert probe["authenticated"] is True and probe["via"] == "token"
    assert probe["role"] == users_mod.ROLE_ADMIN, probe

    created = client.post("/api/users/create", headers=_token_headers("break-glass-value"),
                          json={"username": "rescued", "role": "admin",
                                "password": "password-123"})
    assert created.status_code == 200, created.get_json()
    assert ctx.user_store.find("rescued") is not None


def test_the_legacy_token_survives_an_unreadable_token_store():
    """THE LOCKOUT GUARD. A broken store must degrade to "the legacy token still works"."""
    class BrokenStore:
        def authenticate(self, presented):  # noqa: ANN001, ANN201
            raise RuntimeError("the token store is unreadable")

    ctx = _Ctx(token_store(), legacy="break-glass-value")
    ctx.auth = gui_auth.AuthState("break-glass-value", token_store=BrokenStore())
    client = client_for(ctx)

    ok = client.post("/api/users/create", headers=_token_headers("break-glass-value"),
                     json={"username": "still-here", "role": "viewer",
                           "password": "password-123"})
    assert ok.status_code == 200, ok.get_json()

    # And the failure is a REFUSAL, not a 500: a broken store must not look like a crash.
    refused = client.get("/api/settings", headers=_token_headers("some-other-token"))
    assert refused.status_code == 401, refused.status_code


def test_a_store_only_deployment_accepts_its_tokens():
    """No legacy env token at all: the store is the whole credential path."""
    store = token_store()
    _record, plaintext = store.create_token("only", "admin")
    ctx = _Ctx(store)

    assert ctx.auth.enabled is True, "a token store with a live token reported token auth disabled"
    created = client_for(ctx).post("/api/users/create", headers=_token_headers(plaintext),
                                   json={"username": "storeonly", "role": "viewer",
                                         "password": "password-123"})
    assert created.status_code == 200, created.get_json()


def test_an_empty_store_keeps_the_pre_accounts_posture():
    """A store with no live token must not read as "writes are available".

    Without this, attaching a store (which build_context always does) would flip every
    token-less deployment's Settings page from "writes are disabled, set WEIRVERN_GUI_TOKEN"
    to editable controls that every request refuses.
    """
    ctx = _Ctx(token_store(), legacy="")
    ctx.user_store = users_mod.UserStore(FakeClient(exists=False))
    ctx.user_store.load()

    assert ctx.auth.enabled is False
    body = client_for(ctx).get("/api/settings").get_json()

    assert body["writes"]["enabled"] is False, body["writes"]
    assert gui_auth.TOKEN_ENV in body["writes"]["reason"], body["writes"]


def test_a_mint_turns_the_token_path_on_without_a_restart():
    """The other direction: `enabled` follows the store's live state, not a startup snapshot."""
    ctx = _Ctx(token_store(), legacy="")
    assert ctx.auth.enabled is False
    mint(ctx, role="viewer", name="first")
    assert ctx.auth.enabled is True


def test_the_tokens_card_is_wired_between_the_html_and_the_js():
    """The seam this repo keeps breaking: an element with no handler is a control that does nothing.

    THE ROUTES ARE DRIVEN ELSEWHERE IN THIS FILE; this asserts the DOM half -- every id the panel
    drives exists in the Settings view, and every id in the markup is referenced by app.js. It is
    static on purpose: the full DOM harness does not exercise this card yet, and a renamed id would
    otherwise be invisible until an operator clicked it.
    """
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent
    html = (root / "weirvern" / "admin" / "web" / "index.html").read_text()
    app = (root / "weirvern" / "admin" / "web" / "app.js").read_text()

    view = html[html.index('id="view-settings"'):]
    view = view[:view.index("</section>", view.index('id="view-settings"'))]
    html_ids = ("st-tokens-card", "st-tokens-count", "st-tokens-note", "st-tokens",
                "st-new-token-name", "st-new-token-role", "st-token-create", "st-token-add",
                "st-token-reveal", "st-token-value", "st-token-done", "st-token-result",
                "st-tokens-info")
    for eid in html_ids:
        assert f'id="{eid}"' in view, f"#{eid} is missing from the Settings view"
    # `st-token-add` is a layout wrapper and `st-tokens-info` is opened by the shared info-button
    # handler from its data-info attribute; neither is queried by id, so only the rest must appear.
    for eid in ("st-tokens-card", "st-tokens-count", "st-tokens-note", "st-new-token-name",
                "st-new-token-role", "st-token-create", "st-token-reveal", "st-token-value",
                "st-token-done", "st-token-result"):
        assert f'"{eid}"' in app, f"#{eid} exists in the HTML but nothing in app.js uses it"
    assert "#st-tokens tbody" in app, "the panel never selects its own table body"
    for route in ("/api/tokens", "/api/tokens/create", "/api/tokens/revoke"):
        assert f'"{route}"' in app, f"app.js never calls {route}"
    # A token caller must not be offered the panel: the server refuses those routes without a
    # session, and a button that can only fail is worse than no button.
    panel = app[app.index("async function loadTokens"):]
    panel = panel[:panel.index("function tokensResult")]
    assert 'AUTH.via !== "token"' in panel, (
        "the panel does not hide itself from a token caller")


def test_an_unreadable_store_does_not_cache_the_failure_forever():
    """The F090 shape, for this store: a transient read failure must heal without a restart."""
    class FlakyClient(FakeClient):
        def __init__(self):
            super().__init__(exists=True)
            self.failures = 1

        def read(self):
            if self.failures:
                self.failures -= 1
                raise RuntimeError("transient API failure")
            return {tokens_mod.TOKENS_KEY: json.dumps({"tokens": [
                tokens_mod.TokenRecord(token_id="t1", name="n", role="viewer",
                                       token_hash="00" * 32, prefix="wvt_0000").to_json()]})}

    store = tokens_mod.TokenStore(FlakyClient())
    assert store.has_tokens() is False          # the failing read answered "none"
    assert store.has_tokens() is True, "one transient failure disabled the token store forever"
