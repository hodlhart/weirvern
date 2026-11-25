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
import time
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
        # THREE SHAPES, ALL LEGITIMATE:
        #   * a request object with `.headers` (http.server, Flask, and the duck-typed fakes);
        #   * a BARE MAPPING of headers, which is what the Flask surface passes after it folds the
        #     cookie's token into the header shape;
        #   * nothing usable, which yields an empty mapping so gui_auth's own try/except handles it
        #     rather than this raising before it can.
        #
        # ONLY LOOKING FOR `.headers` WAS A BUG: a plain dict fell through to {} and every credential
        # silently vanished, so a signed-in person was told to sign in by the very next request.
        if hasattr(source, "headers"):
            self.headers = getattr(source, "headers", None) or {}
        elif hasattr(source, "get"):
            self.headers = source
        else:
            self.headers = {}


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
    """The role the presented token carries, or "" when it carries none.

    THE ROLE COMES FROM THE CREDENTIAL, NOT FROM A CONSTANT. There are two kinds of token now:
    the deployment's legacy operator token, which is always admin, and a per-token credential
    from `weirvern-tokens`, which carries the role it was minted with. A viewer token must read
    as a viewer everywhere -- the write gate, the settings payload and the session probe all ask
    this one function.

    The PASSIVE form, for reporting state. It records no failures and applies no delay -- those
    belong to the gate -- so a read that merely might carry a token cannot be used to rack up
    delays against someone else's address. `client` is passed only by callers that ARE the gate.
    """
    auth = getattr(ctx, "auth", None)
    if auth is None:
        return ""
    presented = gui_auth.token_from_request(headers_only(headers))
    if not presented:
        return ""
    role_for = getattr(auth, "role_for", None)
    if callable(role_for):
        return str(role_for(presented, client=client) or "")
    # A duck-typed stand-in with only `check()` (the shape the older tests build) can answer
    # whether the deployment's ONE token matched; it cannot carry a role, and the only token an
    # object of that shape ever represented was the admin break-glass value.
    if getattr(auth, "enabled", False) and auth.check(presented, client=client):
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
    accounts = accounts_on(ctx)
    payload: dict = {
        "accounts": accounts,
        "note": getattr(ctx, "accounts_note", "") or "",
    }
    if ident is not None:
        payload.update({"authenticated": True, "username": ident.username,
                        "role": ident.role, "must_change": ident.must_change,
                        "via": "session"})
    else:
        # THE TOKEN'S OWN ROLE, not a constant, and asked ONCE: a viewer token that reported
        # itself as an admin here would light up every admin control in the UI and then refuse
        # each one at the gate.
        role = token_role(ctx, headers)
        if role:
            payload.update({"authenticated": True, "username": "", "role": role,
                            "must_change": False, "via": "token"})
        else:
            payload.update({"authenticated": False, "username": "", "role": "",
                            "must_change": False, "via": ""})
    # AN ANONYMOUS CALLER IS TOLD THE POSTURE ONLY WHEN THE POSTURE IS "READS ARE OPEN".
    # Two different facts travelled in this one field. With accounts OFF, the note explains why
    # every read is served without a session, and the console paints it as a banner: that is a
    # fault an operator has to see, and withholding it would hide the thing that matters.
    # With accounts ON, the same field carries a bootstrap outcome -- "accounts already exist" --
    # which told anyone who reached the sign-in page that this deployment has accounts, before
    # they presented a credential. Nothing on that page needs it.
    if accounts and not payload.get("authenticated"):
        payload["note"] = ""
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

    # A PENDING ACCOUNT HAS A PASSWORD BUT NO DOOR. Self-registration creates it approved=False;
    # an administrator approves it from the console. The password is checked first, so a wrong
    # password on a pending account still gets the generic refusal and does not confirm the name.
    if not record.approved:
        logger.info("refused a sign-in for %r: awaiting approval", record.username)
        audit_auth(ctx, "login", record.username, "pending approval")
        return None, "", "this account is waiting for an administrator to approve it"

    if throttle is not None:
        throttle.clear(addr)
    ident = users_mod.Identity(username=record.username, role=record.role,
                               must_change=record.must_change)
    token = sessions.create(ident)
    logger.info("signed in %s from %s", record.username, addr or "unknown")
    audit_auth(ctx, "login", record.username, "signed in")
    return ident, token, ""


def create_account(ctx: Any, username: str, password: str, *,
                   role: str | None = None, approved: bool = True) -> tuple[Any, str]:
    """Register an account through the shared store. Returns `(record, error)`.

    Deliberately does NOT let a caller choose a role by default: a self-service register form that
    accepts `role` from the form would be a privilege-escalation hole. The role comes from the
    caller, and the Flask route passes the store's default rather than a submitted value.

    `approved=False` is the self-registration path: the account exists, but `authenticate` refuses
    it until an administrator approves it.
    """
    from weirvern.admin import users as users_mod

    store = getattr(ctx, "user_store", None)
    if store is None:
        return None, "the account store is not available on this GUI"
    try:
        record = store.create_user(username, role or users_mod.ROLE_VIEWER, password,
                                   approved=approved)
    except Exception as exc:  # noqa: BLE001
        # `UserError` carries a sentence meant for a user ("a user named 'x' already exists"), so
        # passing it through is right; anything else is a real fault and must not be dressed up.
        return None, str(exc) or "the account could not be created"
    audit_auth(ctx, "register", record.username, "created")
    return record, ""


# ── the WRITE gate, shared for the same reason as the read gate ──────────────────────────────
#
# Extracted from the console handler rather than rewritten. The ORDER in it was an audit fix
# (F049): the token is evaluated BEFORE the session, because a request carrying a VIEWER session and
# a VALID token was refused as a viewer with the token never examined -- same credential, opposite
# answers, decided by whether the browser happened to be signed in. Reimplementing that order in a
# second surface would be exactly the drift that fix removed.

def write_refusal(ctx: Any, headers: Any, *,
                  addr: str = "") -> tuple[bool, tuple[int, str] | None]:
    """Whether this request may WRITE, and the refusal to send when it may not.

    Two credentials open the write path, both admin-equivalent: a signed-in admin account session,
    or an ADMIN token (the deployment operator token, break-glass: it recovers a lost admin
    password and drives automation).

    A VIEWER TOKEN IS REFUSED, with the same 403 shape a viewer account gets. Before per-token
    credentials existed every token was admin, so "a token is a write credential" was true; it is
    not true now, and the role has to be read rather than assumed.

    `addr` is the caller's real address, and passing it is what makes the token check GATED: a wrong
    token then counts toward the escalating delay. A caller that passes "" gets the passive probe.
    That is the same switch the console handler uses, so both surfaces slow a guesser down.

    Returns `(True, None)` to proceed, or `(False, (code, message))`.
    """
    from weirvern.admin import users as users_mod  # noqa: PLC0415

    auth = getattr(ctx, "auth", None)

    # TOKEN FIRST, regardless of the session. See the note above. A viewer token is REMEMBERED
    # rather than refused here: a request that also carries a valid admin session has a stronger
    # credential on it, and refusing it because a weaker one rode along would be the mirror of
    # F049 -- the same request answered by which credential happened to be present.
    presented = gui_auth.token_from_request(headers_only(headers))
    token_granted = token_role(ctx, headers, client=addr) if presented else ""
    if token_granted == users_mod.ROLE_ADMIN:
        return True, None

    ident = identity(ctx, headers)
    if ident is not None:
        if ident.must_change:
            return False, (403, "change your password before changing anything else")
        if ident.is_admin:
            return True, None
        return False, (403, "this account is a viewer: it can read every view but cannot change "
                            "settings or manage accounts. Ask an admin.")

    if token_granted:
        # A live, correctly presented, non-admin token. 403 like a viewer account, and the wording
        # says which credential is short of rights so an operator does not go looking for a session.
        return False, (403, "this token is a viewer: it can read every view but cannot change "
                            "settings or manage accounts. Ask an admin for a token with the "
                            "admin role.")

    if auth is None:
        return False, (503, "write access is not available: the GUI started without an "
                            "authentication module")
    if not getattr(auth, "enabled", False):
        if accounts_on(ctx):
            return False, (403, "sign in with an admin account to change settings")
        return False, (403, getattr(auth, "reason", "") or "write access is disabled")

    # A token is configured but this request did not present a usable one. The response never
    # distinguishes absent, empty and wrong, and the delay is applied HERE rather than at each
    # call site: two copies of a security control are free to disagree about the escalation.
    try:
        delay = float(auth.delay_for(addr) or 0)
    except Exception:  # noqa: BLE001
        delay = 0.0
    if delay:
        time.sleep(delay)
    logger.warning("rejected an unauthenticated settings write from %s", addr or "unknown")
    return False, (401, "a valid admin session or operator token is required to change settings")
