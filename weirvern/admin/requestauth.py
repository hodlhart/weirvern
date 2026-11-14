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
