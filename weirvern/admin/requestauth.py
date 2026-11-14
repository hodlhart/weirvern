"""Request authentication and the session payload, in ONE place.

WHY THIS MODULE EXISTS. The console's handler and a Flask front door both need to answer the same
three questions for a request -- who is this, is the break-glass token presented, and may this
request read -- and they must answer them identically. Two copies of that logic is the defect this
codebase keeps producing: a value derived in two places, drifting, and each copy looking correct on
its own.

`gui_auth` already reads headers through a narrow duck-typed interface (`handler.headers.get`), so
nothing here needs to know which framework called it. `headers_only()` wraps any request object that
exposes `.headers`.

The handler keeps its methods; they delegate here.
"""

from __future__ import annotations

import logging
from typing import Any

from weirvern.admin import gui_auth
from weirvern.admin import users as users_mod

logger = logging.getLogger(__name__)


class headers_only:
    """Adapt any request object with a `.headers` mapping to the shape `gui_auth` expects.

    `gui_auth.session_from_request` and `token_from_request` only ever call `handler.headers.get`,
    so this is the whole interface. Keeping it this small is what lets the same auth code serve
    http.server and Flask without a second implementation.
    """

    __slots__ = ("headers",)

    def __init__(self, source: Any) -> None:
        # Accept a request object OR a bare headers mapping. `getattr(..., None) or {}` also covers
        # the duck-typed fakes the account tests build, which carry no headers at all -- reading
        # `source.headers` eagerly would raise before gui_auth's own try/except could handle it.
        self.headers = getattr(source, "headers", None) or {}


def accounts_on(ctx: Any) -> bool:
    """Whether accounts are provisioned, i.e. whether the login gate is armed.

    Re-exported from `web` rather than reimplemented: `_accounts_on` is the one definition, and a
    second copy here would be free to disagree with the console about whether the gate is up.
    """
    from weirvern.admin.web import _accounts_on

    return bool(_accounts_on(ctx))


def identity(ctx: Any, headers: Any) -> Any:
    """The signed-in account for this request, or None.

    Sessions are checked FIRST and the token never counts as an identity: a token has no username
    and no password to change. `token_role` answers the separate question.
    """
    sessions = getattr(ctx, "sessions", None)
    if sessions is None:
        return None
    try:
        return sessions.get(gui_auth.session_from_request(headers_only(headers)))
    except Exception:  # noqa: BLE001
        # An unreadable session store must not read as "signed in as nobody in particular and
        # therefore fine". No identity means the read gate refuses.
        logger.debug("session lookup failed", exc_info=True)
        return None


def token_role(ctx: Any, headers: Any, *, client: str = "") -> str:
    """users_mod.ROLE_ADMIN when this request presents the operator token, else "".

    The PASSIVE form, for reporting state. It records no failures and applies no delay -- those
    belong to the gate -- so a read that merely might carry a token cannot be used to rack up
    delays against someone else's address. `client` is passed only by callers that ARE the gate.
    """
    auth = getattr(ctx, "auth", None)
    if auth is None or not getattr(auth, "enabled", False):
        return ""
    presented = gui_auth.token_from_request(headers_only(headers))
    if presented and auth.check(presented, client=client):
        return users_mod.ROLE_ADMIN
    return ""


def session_payload(ctx: Any, headers: Any) -> dict:
    """Who the caller is, and whether the sign-in gate is armed. NEVER anyone else's data.

    Answers for three callers: an anonymous browser deciding whether to show the gate, a signed-in
    account refreshing its role, and the break-glass token (reported as an admin `via: token` with
    no username, because that is exactly what it is).

    The `note` is the server's own explanation of the accounts posture. The console renders it as a
    banner when the gate is OFF, because `accounts: False` with a note is a deployment whose store
    could not be read -- every READ is then served without a session -- and that is a very different
    situation from a first run with nothing configured yet.
    """
    ident = identity(ctx, headers)
    payload: dict = {
        "accounts": accounts_on(ctx),
        "note": getattr(ctx, "accounts_note", "") or "",
    }
    if ident is not None:
        payload.update({"authenticated": True, "username": ident.username,
                        "role": ident.role, "must_change": ident.must_change,
                        "via": "session"})
    elif token_role(ctx, headers):
        payload.update({"authenticated": True, "username": "", "role": users_mod.ROLE_ADMIN,
                        "must_change": False, "via": "token"})
    else:
        payload.update({"authenticated": False, "username": "", "role": "",
                        "must_change": False, "via": ""})
    return payload


def read_refusal(ctx: Any, headers: Any) -> tuple[bool, tuple[int, str] | None]:
    """Whether this request may READ, and the refusal to send when it may not.

    Open when accounts are not provisioned (the documented pre-accounts posture). Otherwise a
    signed-in account or the break-glass token is required. A `must_change` account is held at the
    password gate: it can reach the session and password routes, and every other read says why not,
    so the UI cannot render a dashboard behind the gate.

    Returns `(True, None)` to proceed, or `(False, (code, message))` and the caller sends it. The
    message strings are the console's own and the JS matches on nothing, but keeping them identical
    across surfaces means an operator reading a log sees one vocabulary.
    """
    if not accounts_on(ctx):
        return True, None
    ident = identity(ctx, headers)
    if ident is not None:
        if ident.must_change:
            return False, (403, "a password change is required before using the dashboard")
        return True, None
    if token_role(ctx, headers):
        return True, None
    return False, (401, "sign in to view this dashboard")


# ── the credential check, shared by the console API and the Flask form ────────────────────────
#
# The two surfaces must not disagree about whether a password is right, whether a miss costs the
# same time as a wrong password, or how a failed attempt is throttled. Any of those differing is a
# security bug in one surface only, which is the worst kind to find later.

def audit_auth(ctx: Any, action: str, username: str, reason: str) -> None:
    """Append the authentication fact without ever touching the credential.

    A failed audit write must not turn a valid sign-in into an error -- the same contract as
    settings and fleet writes.
    """
    from weirvern import fleet_store

    try:
        with ctx.connect_factory(ctx.settings) as ch:
            fleet_store.write_audit(
                ch, scope="auth", action=action, target=(username or "(empty)"),
                reason=reason, actor=(username or "(anonymous)"))
    except Exception as exc:  # noqa: BLE001
        logger.warning("authentication audit write failed: %s", exc)


def authenticate(ctx: Any, username: str, password: str, *,
                 addr: str = "") -> tuple[Any, str, str]:
    """Verify a username and password and mint a session.

    Returns `(identity, token, error)`. On success `error` is "" and the caller decides how to carry
    the token (a header for the API, a signed cookie for the rendered UI). On failure `identity` is
    None, `token` is "", and `error` is a sentence safe to show a user.

    THE REFUSAL NEVER SAYS WHICH HALF WAS WRONG: "no such user" and "wrong password" are one
    message, because distinguishing them enumerates accounts. Timing is equalised the same way
    (`users.dummy_verify` runs a real scrypt for unknown usernames). A deployment with NO accounts
    says so plainly instead -- that is a setup fact its operator needs, not an oracle.
    """
    import time

    from weirvern.admin import users as users_mod

    name = str(username or "").strip().lower()
    if not accounts_on(ctx):
        note = getattr(ctx, "accounts_note", "") or "this deployment has no accounts provisioned"
        return None, "", f"cannot sign in: {note}"

    store = getattr(ctx, "user_store", None)
    if store is None:
        return None, "", "the account store is not available on this GUI"
    sessions = getattr(ctx, "sessions", None)
    if sessions is None:
        return None, "", "this GUI has no session registry"
    throttle = getattr(ctx, "throttle", None)

    try:
        record = store.find(name) if name else None
    except Exception:  # noqa: BLE001
        logger.warning("the account store could not be read during a sign-in", exc_info=True)
        return None, "", "the account store could not be read"

    if record is None:
        users_mod.dummy_verify(password)
        ok = False
    else:
        ok = users_mod.verify_password(password, record.hash)

    if record is None or not ok:
        if throttle is not None:
            throttle.record_failure(addr)
            delay = throttle.delay_for(addr)
            if delay:
                time.sleep(delay)
        logger.warning("rejected a sign-in for %r from %s", name or "(empty)", addr or "unknown")
        audit_auth(ctx, "login", name, "rejected")
        return None, "", "the username or password is not correct"

    if throttle is not None:
        throttle.clear(addr)
    ident = users_mod.Identity(username=record.username, role=record.role,
                               must_change=record.must_change)
    token = sessions.create(ident)
    logger.info("signed in %s from %s", record.username, addr or "unknown")
    audit_auth(ctx, "login", record.username, "signed in")
    return ident, token, ""


def create_account(ctx: Any, username: str, password: str, *,
                   role: str | None = None) -> tuple[Any, str]:
    """Register an account through the shared store. Returns `(record, error)`.

    Deliberately does NOT let a caller choose a role by default: a self-service register form that
    accepts `role` from the form would be a privilege-escalation hole. The role comes from the
    caller, and the Flask route passes the store's default rather than a submitted value.
    """
    from weirvern.admin import users as users_mod

    store = getattr(ctx, "user_store", None)
    if store is None:
        return None, "the account store is not available on this GUI"
    try:
        record = store.create_user(username, role or users_mod.ROLE_VIEWER, password)
    except Exception as exc:  # noqa: BLE001
        # `UserError` carries a sentence meant for a user ("a user named 'x' already exists"), so
        # passing it through is right; anything else is a real fault and must not be dressed up.
        return None, str(exc) or "the account could not be created"
    audit_auth(ctx, "register", record.username, "created")
    return record, ""
