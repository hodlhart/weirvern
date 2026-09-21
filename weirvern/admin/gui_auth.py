"""Operator authentication for the web GUI.

WHY THIS EXISTS. The GUI has been read-only since it was built, and deliberately: it is served on
a LAN port with NO authentication, so anything an HTTP request could write would be a way to
reconfigure a sensor from the network. That was the right default and it is now the thing being
changed -- carefully -- because an operator asked to manage settings from the GUI rather than the
TUI.

WHAT CHANGES AND WHAT DOES NOT. WRITES require admin rights: an admin session or the deployment
operator token. READS were open until accounts were added; they now require a signed-in account
(either role), because flow data is sensitive and "a viewer may read" only means something if
reading is attributable. The break-glass token still works everywhere an admin does, so a lost
admin password cannot lock a deployment out, and it remains the credential for automation.

THREAT MODEL, STATED PLAINLY. This is not a public service and is not built like one. It defends
against:

  * another host on the same LAN reaching the port and changing settings;
  * a browser or script guessing the token.

It does NOT defend against: someone with cluster access (they can read the Secret), someone with
the token, or a network attacker who can terminate TLS (there is no TLS here -- the Service is
plain HTTP on a NodePort). Those are accepted, and the boundary is stated rather than implied.

DESIGN CHOICES:

  * `secrets.compare_digest`, not `==`. A byte-wise comparison leaks the position of the first
    wrong character through timing, which is enough to recover a token one character at a time.
  * The token is read from the environment ONCE at startup. Re-reading per request would let a
    partially-written ConfigMap serve a half-token, and would put a file read on the hot path.
  * A MISSING token and an EMPTY token are the same state: writes disabled. An empty string must
    never authenticate, or `WEIRVERN_GUI_TOKEN=` in a manifest would disable the gate -- the
    classic "unset means open" failure.
  * Failures are counted and logged, but the response never says whether the token was absent,
    empty, or wrong. Distinguishing them helps an attacker and not an operator.
"""

from __future__ import annotations

import hmac
import logging
import os
import threading
import time

logger = logging.getLogger(__name__)

# The environment variable holding the operator token. Named for the surface, not for the action,
# so one token can cover every write the GUI ever grows.
TOKEN_ENV = "WEIRVERN_GUI_TOKEN"

# Header first, cookie second. A header is the right mechanism (the browser UI can hold it in
# sessionStorage); the cookie exists so a page reload does not force re-entry.
AUTH_HEADER = "X-Weirvern-Token"
AUTH_COOKIE = "weirvern_token"

# THE SESSION CREDENTIAL, which is a different thing from the operator token above and uses a
# different header on purpose. The token is a deployment-wide break-glass admin credential: one
# value that recovers a lost admin account and drives automation. A session belongs to ONE
# signed-in account and is revoked by signing out. Conflating them would make signing out
# either impossible or a rotation of the deployment secret.
#
# HEADER ONLY, NO COOKIE FALLBACK. A cookie would be attached to requests the browser makes
# from any site, which is the classic CSRF shape; a custom header cannot be set by a
# cross-site form, so header-only means a session cannot ride along on a forged request even
# if the attacker can make the browser try. The UI stores the session in sessionStorage, so a
# reload within the tab keeps it.
SESSION_HEADER = "X-Weirvern-Session"

# How many consecutive failures from one address before the delay grows. Not a lockout: a lockout
# on a LAN tool is a way to deny an operator access to their own sensor. A delay costs a brute-force
# attempt far more than it costs a person who mistyped.
_MAX_TRACKED = 1024
_DELAY_AFTER = 3
_MAX_DELAY_S = 5.0


class AuthState:
    """Whether writes are permitted, and how to verify one.

    One instance per server, built at startup. Holds no reference to the settings object so it
    cannot be mutated by a request handler by accident.
    """

    def __init__(self, token: str | None = None) -> None:
        # `or None` collapses "" and None deliberately: an empty token must not authenticate.
        self._token = (token or "").strip() or None
        self._failures: dict[str, list] = {}
        self._lock = threading.Lock()

    def __repr__(self) -> str:
        """Never render the token.

        In-process `vars()` access implies code execution and is not a security boundary, but
        ACCIDENTAL DISCLOSURE is a real path: a debug log line, a template that renders the object,
        an exception reporter that includes locals. Those are the ways a token actually leaks, so
        the repr is redacted and says what it is rather than showing a blank.
        """
        return f"AuthState(enabled={self.enabled}, token=<{'set' if self.enabled else 'unset'}>)"

    __str__ = __repr__

    @property
    def enabled(self) -> bool:
        """Whether a token is configured. False means writes are refused, not hidden."""
        return self._token is not None

    @property
    def reason(self) -> str:
        """Why writes are unavailable, in the operator's terms.

        Returned to the UI so a disabled control can say WHAT is missing. A greyed-out button with
        no explanation sends someone hunting through manifests to guess.
        """
        if self._token is not None:
            return ""
        return (
            f"write access is disabled: {TOKEN_ENV} is not set. Set it in the "
            f"weirvern-secrets Secret and restart the GUI, or make changes with "
            f"`weirvern config set`."
        )

    def check(self, presented: str | None, *, client: str = "") -> bool:
        """Whether a presented token authorizes a write.

        A constant-time comparison, and an equal amount of work when no token is configured, so
        the response time does not reveal whether the gate is even armed.
        """
        # STRIPPED DELIBERATELY. A human pastes a token and picks up a trailing newline or a
        # leading space; refusing that would be a security theatre that teaches operators to
        # fight their clipboard. It does not widen the search space in any way that matters --
        # an attacker still has to find the same characters.
        presented = (presented or "").strip()
        if self._token is None:
            # Still do a comparison, against a value of the same shape, so timing does not leak
            # the configured/unconfigured distinction.
            hmac.compare_digest(presented, presented)
            self._record_failure(client)
            return False
        ok = bool(presented) and hmac.compare_digest(presented, self._token)
        if ok:
            self._clear(client)
        else:
            self._record_failure(client)
        return ok

    # -- failure tracking ---------------------------------------------------

    def _record_failure(self, client: str) -> None:
        if not client:
            return
        with self._lock:
            # Bounded: an unbounded map keyed by client address is a memory-growth path on a
            # port anyone on the LAN can reach.
            if len(self._failures) > _MAX_TRACKED and client not in self._failures:
                self._failures.pop(next(iter(self._failures)), None)
            self._failures.setdefault(client, []).append(time.time())

    def _clear(self, client: str) -> None:
        if not client:
            return
        with self._lock:
            self._failures.pop(client, None)

    def delay_for(self, client: str) -> float:
        """Seconds to wait before answering a failed attempt from this address.

        Escalating but BOUNDED. The point is to make guessing expensive, not to deny an operator
        their own sensor after a typo -- and a bounded delay cannot be used to hold a connection
        open indefinitely.
        """
        if not client:
            return 0.0
        with self._lock:
            attempts = len(self._failures.get(client, []))
        if attempts < _DELAY_AFTER:
            return 0.0
        return min(_MAX_DELAY_S, 0.25 * (attempts - _DELAY_AFTER + 1))

    def failures_for(self, client: str) -> int:
        with self._lock:
            return len(self._failures.get(client, []))


def from_env(environ: dict | None = None) -> AuthState:
    """Build the auth state from the environment.

    Read once, at startup. An env var is a snapshot of the deployment's configuration; re-reading
    per request would pick up a partially-applied ConfigMap update and could serve a half-written
    token.
    """
    env = environ if environ is not None else os.environ
    return AuthState(env.get(TOKEN_ENV))


def token_from_request(handler) -> str | None:
    """The token a request presents: header first, then cookie.

    Reads through a narrow duck-typed interface rather than importing http.server, so this module
    is testable without a live socket.
    """
    header = ""
    try:
        header = handler.headers.get(AUTH_HEADER, "") or ""
    except Exception:  # noqa: BLE001
        header = ""
    if header.strip():
        return header.strip()
    # Fall back to the cookie so a page reload does not force re-entry.
    try:
        raw = handler.headers.get("Cookie", "") or ""
    except Exception:  # noqa: BLE001
        return None
    for part in raw.split(";"):
        name, _, value = part.strip().partition("=")
        if name == AUTH_COOKIE and value:
            return value.strip()
    return None


def session_from_request(handler) -> str | None:
    """The session a request presents. HEADER ONLY -- see SESSION_HEADER for the CSRF reason.

    Same duck-typed interface as above, so the account tests need no socket either.
    """
    try:
        header = handler.headers.get(SESSION_HEADER, "") or ""
    except Exception:  # noqa: BLE001
        return None
    return header.strip() or None
