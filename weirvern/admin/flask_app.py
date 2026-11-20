"""A Flask front door over the SAME payload layer the console uses.

WHAT THIS IS. The console's server is a hand-rolled `ThreadingHTTPServer` with manual routing, a
hand-maintained static allow-list and hand-rolled TLS. That is a real liability for future work: no
middleware, no WSGI, and every new route a small piece of bespoke plumbing. This module puts Flask in
front so routing, TLS and proxy handling come from a standard stack.

WHAT THIS IS NOT. It is not a rewrite of the console and it does not touch one line of its
JavaScript. The 900-odd checks in `scripts/jsdom_render.js` keep measuring the console exactly as
before, because the console is served unchanged. A big-bang port would have thrown that away to gain
a framework.

THE STRANGLER, AND WHY IT NEEDS A PASSTHROUGH. The console serves 84 distinct API paths (53 GET
reads, 34 POST entries) and the dashboard's own JavaScript calls 59 of them. This app serves ALL 53
reads natively and none of the writes yet. Replacing the console outright would therefore load the
page and break every write, with each panel reporting "no such endpoint" -- a regression dressed as a
migration.

So the front door FORWARDS what it has not taken over. With `proxy_to` set, any path this app does not
own is passed to the legacy server, which keeps running on loopback inside the same process. Flask owns
the rendered pages and the migrated routes; everything else behaves exactly as before. Routes cross one
at a time and the dashboard never notices.

Routes are migrated one at a time. A route is written here natively, against the same
`web_api` payload functions and the same `status_mod` fetchers, and only then is it retired from the
old handler. The console API stays on its own port until every route it serves has a tested
replacement, so nothing is half-migrated at any point.

AUTH IS SHARED, NOT COPIED. `requestauth` is the single implementation of "who is this" and "may
this request read", and the old handler delegates to it too. Two copies of an auth decision is the
one duplication this project cannot afford: they drift, and each copy looks correct alone.

TLS IS THE WSGI SERVER'S JOB. `app.run()` is for development only. In a deployment this app is handed
to gunicorn or waitress, which terminate TLS; the console's own self-signed CA path stays with the
old server until it retires.
"""

from __future__ import annotations

import functools
import hmac
import json
import logging
import os
import secrets
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from flask import Flask, Response, jsonify, redirect, render_template, request, session, stream_with_context, url_for
from flask.json.provider import DefaultJSONProvider

from weirvern.admin import requestauth

logger = logging.getLogger(__name__)


class ConsoleJSONProvider(DefaultJSONProvider):
    """Serialise EXACTLY like the console: `json.dumps(payload, default=str)`.

    THIS WAS A REAL DIVERGENCE, caught by the review write's adjustment. Flask's default provider
    turns a datetime into an RFC 822 string and a UUID into str(); the console falls back to `str()`
    for EVERYTHING unknown. A payload carrying a raw datetime therefore reads differently on the two
    surfaces -- "Thu, 13 Nov 2026 00:00:00 GMT" against "2026-11-13 00:00:00" -- and nothing in the
    route says so, because the value is assembled deep inside a payload builder.

    Overriding `default` is what makes the bytes match. `sort_keys` is off as well: the console
    preserves insertion order, and while JSON objects are unordered, a reader diffing two responses
    should not have to think about that.
    """

    default = staticmethod(str)

# The templates ship inside the package (see pyproject package-data), so this is a path relative to
# the module and not a working-directory guess.
TEMPLATE_DIR = Path(__file__).parent / "templates"

# The role a self-service registration gets. NEVER taken from the submitted form: a register form
# that accepted a role would be a privilege-escalation hole, and the console's own user route has
# the same boundary.
REGISTER_ROLE_FALLBACK = "viewer"


def _truthy(raw: str | None) -> bool:
    return str(raw or "").strip().lower() in ("1", "true", "yes", "on")


def _forwarded_proto() -> str:
    """The scheme the INGRESS saw, lower-cased, or "" when it did not say.

    The pod only ever speaks HTTP: TLS terminates at Traefik. Deciding the scheme from this process's
    own hop would either redirect every request forever or never redirect at all, so the header is
    the only source -- and its absence means "no opinion", not "http".
    """
    return (request.headers.get("X-Forwarded-Proto") or "").split(",")[0].strip().lower()


def _redirect_to_https():
    """308 to the same URL over https, ONLY when the ingress says the request arrived as http.

    A missing or unrecognised scheme returns None: an operator reaching the pod directly over HTTP
    (a port-forward, a probe) must not be bounced to a name that does not resolve. A 308 preserves
    the method and body, so a write is not silently turned into a GET by the redirect.
    """
    if _forwarded_proto() != "http":
        return None
    return redirect(request.url.replace("http://", "https://", 1), code=308)


def _security_headers(response):
    """HSTS only when the ingress says https: over plain http it would poison the browser.

    The header is set here rather than at the edge so a deployment whose ingress does not add it
    still gets one, and so the two cannot disagree about the max-age.
    """
    if _forwarded_proto() == "https":
        response.headers.setdefault(
            "Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    return response


def _json_error(code: int, message: str) -> tuple[Response, int]:
    """The console's own error shape, so a client cannot tell the two surfaces apart.

    Every error in the old server is `{"error": ..., "code": ...}` with a matching status, and the
    console JS relies on the STATUS (postJSON throws on non-2xx). Keeping the body identical means a
    client written against one surface reads the other without special cases.
    """
    return jsonify({"error": message, "code": code}), code


def create_app(ctx: Any, *, static_dir: Any = None, secret_key: str | None = None,
               proxy_to: str = "") -> Flask:
    """Build the Flask app over an assembled GuiContext.

    Takes the same `ctx` the console handler takes, so both surfaces share one connection factory,
    one settings object, one session store and one token gate. Assembling a second context would be
    a second set of credentials and a second way to disagree about them.
    """
    from weirvern.admin.web import STATIC_DIR, STATIC_FILES

    app = Flask(__name__, static_folder=None, template_folder=str(TEMPLATE_DIR))
    # THE SAME JSON AS THE CONSOLE (see ConsoleJSONProvider). Datetimes are the case that made this
    # necessary: Flask's default writes RFC 822, the console writes str().
    app.json = ConsoleJSONProvider(app)
    app.json.sort_keys = False

    # ── THE COOKIE, AND WHY THIS SURFACE HAS ONE WHEN THE API DOES NOT ──────────────────────────
    #
    # The console API is HEADER-ONLY by design: gui_auth refuses a cookie for sessions because a
    # cookie rides along on cross-site requests, the classic CSRF shape. That is right for an API a
    # script calls.
    #
    # A SERVER-RENDERED UI CANNOT WORK THAT WAY. A browser navigating between pages has nowhere to
    # put a header, so persistence needs a cookie. Rather than hide that difference, it is made
    # explicit: this app's signed cookie carries the session token AND a CSRF nonce, it is
    # HttpOnly, and SameSite=Strict so it is not attached to a cross-site request at all. Every
    # state-changing form posts the nonce back and is checked against it.
    #
    # The signing key is REQUIRED and comes from the environment. A default would sign every
    # deployment's cookies with a public string, which is worse than having no rendered UI: without
    # it, login and register refuse and say why, and the header-authenticated API keeps working.
    secret = secret_key if secret_key is not None else os.environ.get("WEIRVERN_FLASK_SECRET", "")
    app.secret_key = secret or None
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
        # Off unless TLS is actually in front of this app: a Secure cookie over plain HTTP is
        # silently never stored, which reads as "login does nothing".
        SESSION_COOKIE_SECURE=_truthy(os.environ.get("WEIRVERN_FLASK_SECURE")),
        PERMANENT_SESSION_LIFETIME=timedelta(hours=12),
    )
    # Flask's default is to escape nothing and sort nothing; both defaults are fine here, but the
    # console expects compact JSON and no trailing newline stripping, so keep it literal.
    app.config["JSON_SORT_KEYS"] = False

    # ── the HTTPS edge, enforced from the FORWARDED scheme ─────────────────────────────────────
    #
    # Traefik terminates TLS and forwards plain HTTP, so the pod's own scheme says nothing. These
    # two hooks are the application's half of the edge: a redirect only when the ingress reports
    # `http`, and HSTS only when it reports `https`. Both refuse to guess when the header is absent.
    @app.before_request
    def _https_redirect():
        return _redirect_to_https()

    @app.after_request
    def _https_headers(response):
        return _security_headers(response)

    root = static_dir if static_dir is not None else STATIC_DIR

    # ── the gate ────────────────────────────────────────────────────────────────────────────────
    def gated(view):
        """Refuse a read the way the console does, using the shared decision."""

        @functools.wraps(view)
        def wrapper(*args, **kwargs):
            ok, refusal = requestauth.read_refusal(ctx, request)
            if not ok:
                # `read_refusal` returns (True, None) or (False, (code, message)). The None branch
                # cannot co-occur with ok=False, but reading it defensively keeps a future edit that
                # breaks that invariant from raising a TypeError inside the gate.
                code, message = refusal if refusal is not None else (401, "sign in to view this dashboard")
                return _json_error(code, message)
            return view(*args, **kwargs)

        return wrapper

    @app.errorhandler(Exception)
    def internal_error(exc):
        """An uncaught exception answers the CONSOLE's 500 body, never Flask's HTML page.

        The console wraps every request in a handler that writes
        `{"error": "internal error: ...", "code": 500}`. A route that raises on one surface and
        renders an HTML error page on the other is a difference a client can see, and it would make
        the failure half of every equivalence test compare two different vocabularies. Routes such as
        `/api/write-trail` deliberately have no catch of their own, so this is their only answer.
        """
        from werkzeug.exceptions import HTTPException  # noqa: PLC0415

        if isinstance(exc, HTTPException):
            return exc
        logger.warning("GUI request failed: %s", exc)
        return _json_error(500, f"internal error: {exc}")

    # ── read-exempt routes ──────────────────────────────────────────────────────────────────────
    # The console's READ_EXEMPT tuple is exactly these two: a browser needs to know whether to draw
    # the sign-in gate before it has a session, and a health probe must answer while signed out.
    @app.get("/api/healthz")
    def healthz():
        return jsonify({"ok": True})

    # NOT named `session`: a view function called `session` shadows flask.session inside this
    # factory, so every later `session.get(...)` in the rendered-UI helpers called the view instead
    # and raised AttributeError. Measured: 10 tests failed with "'function' object has no
    # attribute 'get'" before the rename.
    @app.get("/api/session")
    def api_session():
        return jsonify(requestauth.session_payload(ctx, request))

    # ── the rendered UI: helpers ────────────────────────────────────────────────────────────────
    def _secret_missing() -> bool:
        return not app.secret_key

    def _csrf_token() -> str:
        """The nonce for this browser, minted once and carried in the signed cookie.

        Returns "" when the app has no signing key: touching `session` at all raises
        RuntimeError in that state, and the no-key page must render the explanation rather than
        crash on its way to it.
        """
        if not app.secret_key:
            return ""
        token = session.get("csrf")
        if not token:
            token = secrets.token_urlsafe(32)
            session["csrf"] = token
        return token

    def _csrf_ok() -> bool:
        sent = request.form.get("csrf", "")
        expected = session.get("csrf", "")
        # compare_digest on equal-length str; a missing nonce fails closed rather than raising.
        return bool(sent) and bool(expected) and hmac.compare_digest(sent, expected)

    def _signed_in():
        """The identity carried by the cookie, or None. The token is the registry's, not ours."""
        if not app.secret_key:
            return None
        token = session.get("token") or ""
        sessions = getattr(ctx, "sessions", None)
        if not token or sessions is None:
            return None
        return sessions.get(token)

    def _render(template: str, **kw):
        """Render with the chrome's context, letting the CALLER win on any key it passes.

        The caller winning matters: the register page states the role it grants, which is not the
        signed-in user's role. Passing both explicitly raised
        "render_template() got multiple values for keyword argument 'role'".
        """
        ident = _signed_in()
        chrome = {
            "current_user": ident.username if ident else "",
            "role": ident.role if ident else "",
            "via": ident.via if ident else "",
            "must_change": bool(ident.must_change) if ident else False,
            "csrf_token": _csrf_token(),
        }
        chrome.update(kw)
        return render_template(template, **chrome)

    def user_required(view):
        @functools.wraps(view)
        def wrapper(*args, **kwargs):
            if _signed_in() is None:
                return redirect(url_for("login"))
            return view(*args, **kwargs)

        return wrapper

    def _register_allowed() -> bool:
        """Self-service registration is a first-run convenience, not a standing door.

        Allowed when the operator has explicitly enabled it, or when the store is readable and has
        NO accounts (the bootstrap case). Deliberately not allowed when the store cannot answer: an
        unreadable store is not an invitation to create accounts in it.
        """
        if _truthy(os.environ.get("WEIRVERN_ALLOW_SELF_REGISTER")):
            return True
        store = getattr(ctx, "user_store", None)
        if store is None:
            return False
        try:
            return not store.has_users()
        except Exception:  # noqa: BLE001
            return False

    # ── the rendered UI: routes ────────────────────────────────────────────────────────────────
    @app.get("/login")
    def login():
        if _secret_missing():
            return _render("login.html", error=(
                "the rendered UI is disabled: WEIRVERN_FLASK_SECRET is not set, so this app cannot "
                "sign a session cookie. The JSON API still works and authenticates by header."),
                can_register=False, accounts_note="")
        if _signed_in() is not None:
            return redirect(url_for("home"))
        return _render("login.html", error="",
                       can_register=_register_allowed(),
                       accounts_note=getattr(ctx, "accounts_note", "") or "")

    @app.post("/login")
    def login_post():
        if _secret_missing():
            return _render("login.html", error="the rendered UI is disabled: no signing key",
                           can_register=False, accounts_note=""), 503
        if not _csrf_ok():
            return _render("login.html", error="that form did not come from this page",
                           can_register=_register_allowed(), accounts_note=""), 400
        username = request.form.get("username", "")
        ident, token, error = requestauth.authenticate(
            ctx, username, request.form.get("password", ""),
            addr=request.remote_addr or "",
        )
        if ident is None:
            return _render("login.html", error=error, username=username,
                           can_register=_register_allowed(), accounts_note=""), 401
        session.clear()
        session["token"] = token
        session.permanent = True
        return redirect(url_for("home"))

    @app.get("/register")
    def register():
        if _secret_missing():
            return _render("register.html", error="the rendered UI is disabled: no signing key",
                           role=REGISTER_ROLE_FALLBACK), 503
        if not _register_allowed():
            return _render("login.html", error=(
                "self-registration is closed on this deployment. An administrator creates accounts "
                "from the console."), can_register=False,
                accounts_note=getattr(ctx, "accounts_note", "") or ""), 403
        return _render("register.html", error="", role=REGISTER_ROLE_FALLBACK)

    @app.post("/register")
    def register_post():
        if _secret_missing():
            return _render("register.html", error="the rendered UI is disabled: no signing key",
                           role=REGISTER_ROLE_FALLBACK), 503
        if not _csrf_ok():
            return _render("register.html", error="that form did not come from this page",
                           role=REGISTER_ROLE_FALLBACK), 400
        if not _register_allowed():
            return _render("login.html", error="self-registration is closed on this deployment",
                           can_register=False,
                           accounts_note=getattr(ctx, "accounts_note", "") or ""), 403
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if password != request.form.get("password2", ""):
            return _render("register.html", error="the two passwords are not the same",
                           username=username, role=REGISTER_ROLE_FALLBACK), 400
        record, error = requestauth.create_account(ctx, username, password)
        if record is None:
            return _render("register.html", error=error, username=username,
                           role=REGISTER_ROLE_FALLBACK), 400
        # Sign the new account straight in: it just proved it knows the password it chose.
        ident, token, login_error = requestauth.authenticate(ctx, username, password,
                                                            addr=request.remote_addr or "")
        if ident is None:
            return _render("login.html", error=login_error, username=username,
                           can_register=False,
                           accounts_note=getattr(ctx, "accounts_note", "") or ""), 401
        session.clear()
        session["token"] = token
        session.permanent = True
        return redirect(url_for("home"))

    @app.post("/logout")
    def logout():
        if not _csrf_ok():
            return _render("login.html", error="that form did not come from this page",
                           can_register=_register_allowed(),
                           accounts_note=getattr(ctx, "accounts_note", "") or ""), 400
        ident = _signed_in()
        if ident is not None:
            sessions = getattr(ctx, "sessions", None)
            if sessions is not None:
                sessions.revoke(session.get("token"))
            logger.info("signed out %s (rendered UI)", ident.username)
            requestauth.audit_auth(ctx, "logout", ident.username, "signed out")
        session.clear()
        return redirect(url_for("login"))

    @app.get("/home")
    @user_required
    def home():
        return _render("home.html")

    # ── a data route, migrated in full ──────────────────────────────────────────────────────────
    def _windowed(call):
        """Parse the window arguments and run `call(client, hours, limit)`, shared by data routes.

        THE ARGUMENT PARSING IS SHARED TOO, not just the fetching. `_int_arg` and `window_arg` are the
        console's own, and `window_arg` raises rather than sending so this surface turns the reason
        into its own 400 body. Two parsers would let the surfaces disagree about what a usable range
        is, which is the same drift one layer up.
        """
        from weirvern.admin.web import _int_arg, read_failure, window_arg  # noqa: PLC0415

        query = request.args.to_dict(flat=False)
        limit = _int_arg(query, "limit", 100, 1, 1000)
        try:
            hours = window_arg(query, 24, 1, 24 * 14)
        except ValueError as exc:
            return _json_error(400, f"bad time range: {exc}")
        try:
            with ctx.connect_factory(ctx.settings) as client:
                return jsonify(call(client, hours=hours, limit=limit))
        except Exception as exc:  # noqa: BLE001
            # Worded by what was observed, not by the layer assumed to have failed (WV1-20).
            return _json_error(503, read_failure(exc))

    @app.get("/api/episodes")
    @gated
    def episodes():
        """One row per incident. The shape every migrated route takes.

        NO FETCHING AND NO FORMATTING HERE. `payloads.episodes` owns both, and the console calls the
        same function, so this surface cannot render a table the console renders differently.
        """
        from weirvern.admin import payloads  # noqa: PLC0415

        return _windowed(payloads.episodes)

    # ── the read surface, ported onto the shared payload layer ─────────────────────────────────
    #
    # THESE RETURN THE PAYLOAD THE FETCHER BUILT, INCLUDING ITS FAILURE SHAPE. Some console routes
    # answer a failed read with a 503 and some with a 200 carrying `available: false`; that
    # difference is deliberate per route (a panel that can still draw around a missing card), and a
    # port that "tidied" it into one shape would change what the operator sees.
    def _payload_route(fetcher, *, needs_client=True, settings_positional=False, **kwargs):
        """Call a fetcher and answer its payload.

        `settings_positional` IS NOT CALLED `settings` ANY MORE, and the rename is the fix for a real
        defect: routes that pass `settings=ctx.settings` as a FETCHER KEYWORD were silently setting this
        helper's own flag instead, so the fetcher received settings POSITIONALLY -- and every fetcher
        that declares it keyword-only (`payloads.anomalies`, among others) raised TypeError, which the
        catch below turned into a 503. The dashboard showed "could not read the data: TypeError:
        anomalies() takes 1 positional argument but 2 ... were given" on the Anomalies tab.

        The equivalence harness did not catch it because the route tests replace the FETCHER with a
        permissive lambda, so both surfaces answered the stub and the arity mismatch between what each
        surface passes never ran. Only driving the real fetcher over a real client does.
        """
        from weirvern.admin.web import read_failure  # noqa: PLC0415

        try:
            if not needs_client:
                return jsonify(fetcher(**kwargs))
            with ctx.connect_factory(ctx.settings) as client:
                if settings_positional:
                    return jsonify(fetcher(client, ctx.settings, **kwargs))
                return jsonify(fetcher(client, **kwargs))
        except Exception as exc:  # noqa: BLE001
            return _json_error(503, read_failure(exc))

    def _soft_route(fetcher, failure, **kwargs):
        """A read whose FAILURE is a 200 carrying `available: false`, not a 503.

        Some console routes answer a failed read with a payload the panel can still draw around;
        others raise so the route answers 503. That difference is deliberate per route, and it is
        part of what the operator sees, so it is not tidied away here. The fetcher raises and
        `failure` -- the console's own shape, shared from the payload layer -- builds the body, so
        neither surface can invent its own wording.
        """
        try:
            with ctx.connect_factory(ctx.settings) as client:
                return jsonify(fetcher(client, **kwargs))
        except Exception as exc:  # noqa: BLE001
            return jsonify(failure(exc))

    def _status_route(fetcher, failure, **kwargs):
        """A read that answers with a STATUS of its own, not always 200.

        The capture-probe read is the case: a missing request is a 404 with its own body and a
        failed read a 503, and either one answered as a 200 would tell the operator the wrong thing
        about which happened. The fetcher returns `(status, payload)` so the two surfaces cannot
        disagree about the code any more than about the body.
        """
        try:
            with ctx.connect_factory(ctx.settings) as client:
                code, payload = fetcher(client, **kwargs)
        except Exception as exc:  # noqa: BLE001
            code, payload = failure(exc)
        return jsonify(payload), code

    def _caller_role() -> tuple[str, str]:
        """(role, via) for this request, with the console's precedence: TOKEN first, then session.

        THE ORDER IS LOAD-BEARING (audit F049). The console once returned the session's role without
        consulting the token, so the same valid token was accepted or refused depending on whether
        the browser happened to be signed in as a viewer. Reimplementing that order differently here
        is exactly the drift the fix removed, so this asks the same two shared helpers in the same
        sequence, and reports WHICH credential answered for the settings caller line.
        """
        from weirvern.admin import users as users_mod  # noqa: PLC0415

        headers = _auth_headers()
        role = requestauth.token_role(ctx, headers, client=request.remote_addr or "")
        if role:
            return role, "token"
        ident = requestauth.identity(ctx, headers)
        if ident is not None:
            return (users_mod.ROLE_ADMIN if ident.is_admin else users_mod.ROLE_VIEWER), "session"
        return "", ""

    @app.get("/api/audit")
    @gated
    def audit():
        from weirvern.admin import payloads  # noqa: PLC0415

        return _payload_route(payloads.audit)

    @app.get("/api/sluice/state")
    @gated
    def sluice_state():
        from weirvern.admin import payloads  # noqa: PLC0415

        return _payload_route(payloads.sluice_state)

    @app.get("/api/asset-posture")
    @gated
    def asset_posture():
        from weirvern.admin import payloads  # noqa: PLC0415

        return _payload_route(payloads.asset_posture)

    @app.get("/api/ml/ripple")
    @gated
    def ml_ripple():
        from weirvern.admin import payloads  # noqa: PLC0415

        return _payload_route(payloads.ml_ripple)

    @app.get("/api/ripples")
    @gated
    def ripples():
        """Phase-1 ripple evidence. A failed read is a 200 with an empty list and a reason.

        NOT `_payload_route`: that answers a failed read with a 503, and this card's contract
        (like /api/assets) is that the panel can draw around the failure. `_soft_route` keeps
        the connection failure in the payload layer too, so both surfaces say the same thing.
        """
        from weirvern.admin import payloads, web  # noqa: PLC0415

        try:
            hours = web.window_arg(request.args, 24, 1, 24 * 7)
        except ValueError as exc:
            return _json_error(400, f"bad time range: {exc}")
        return _soft_route(payloads.ripples, payloads.ripples_failure, hours=hours)

    @app.get("/api/ml/data-contract")
    @gated
    def ml_data_contract():
        from weirvern.admin import payloads  # noqa: PLC0415

        return _payload_route(payloads.ml_data_contract)

    @app.get("/api/discover/trends")
    @gated
    def discover_trends():
        """Windowed through `window_arg`, the SAME parser the console uses.

        A bad `hours` is a 400 with the parser's own sentence on both surfaces. Falling back to the
        default would answer a different question than the one asked, silently.
        """
        from weirvern.admin import payloads, web  # noqa: PLC0415

        try:
            hours = web.window_arg(request.args, 24, 1, 24 * 14)
        except ValueError as exc:
            return _json_error(400, str(exc))
        return _payload_route(lambda client: payloads.discover_trends(client, hours))

    @app.get("/api/dns/reverse")
    @gated
    def dns_reverse():
        from weirvern.admin import payloads, web  # noqa: PLC0415

        ip = (request.args.get("ip") or "").strip()
        if not ip or len(ip) > 64:
            return _json_error(400, "give an address: /api/dns/reverse?ip=...")
        try:
            hours = web.window_arg(request.args, 24, 1, 24 * 14)
        except ValueError as exc:
            return _json_error(400, str(exc))
        return _payload_route(lambda client: payloads.dns_reverse(client, ip, hours))

    @app.get("/api/models/calibration")
    @gated
    def models_calibration():
        from weirvern.admin import payloads  # noqa: PLC0415

        return _payload_route(payloads.models_calibration, settings_positional=True)

    @app.get("/api/models/shadow")
    @gated
    def models_shadow():
        from weirvern.admin import payloads  # noqa: PLC0415

        return _payload_route(payloads.models_shadow)

    @app.get("/api/ml/slo")
    @gated
    def ml_slo():
        from weirvern.admin import payloads  # noqa: PLC0415

        return _payload_route(payloads.ml_slo)

    @app.get("/api/ml/coverage")
    @gated
    def ml_coverage():
        from weirvern.admin import payloads  # noqa: PLC0415

        return _payload_route(payloads.ml_coverage)

    @app.get("/api/ml/ledger")
    @gated
    def ml_ledger():
        from weirvern.admin import payloads  # noqa: PLC0415

        return _payload_route(payloads.ml_ledger, needs_client=False)

    @app.get("/api/ml/eval-report")
    @gated
    def ml_eval_report():
        from weirvern.admin import payloads  # noqa: PLC0415

        return _payload_route(payloads.ml_eval_report, needs_client=False)

    @app.get("/api/ml/review")
    @gated
    def ml_review():
        from weirvern.admin import payloads  # noqa: PLC0415

        return _payload_route(payloads.ml_review, needs_client=False)

    @app.get("/api/detectors")
    @gated
    def detectors():
        """The detector registry. Same fetcher the console uses; the registry carries no operator
        data, only which detectors exist and what they caught."""
        from weirvern.admin import payloads  # noqa: PLC0415
        from weirvern.admin.web import read_failure  # noqa: PLC0415

        try:
            with ctx.connect_factory(ctx.settings) as client:
                return jsonify(payloads.detectors(client))
        except Exception as exc:  # noqa: BLE001
            return _json_error(503, read_failure(exc))

    @app.get("/api/baselines")
    @gated
    def baselines():
        """The per-host baseline snapshot, from the same fetcher the console uses."""
        from weirvern.admin import payloads  # noqa: PLC0415

        return _soft_route(payloads.baselines, payloads.baselines_failure)

    # ── the inventory reads: a failed read is a 200 the panel can draw around ──────────────────

    @app.get("/api/assets")
    @gated
    def assets():
        from weirvern.admin import payloads, web  # noqa: PLC0415

        try:
            hours = web.window_arg(request.args, 24, 1, 24 * 14)
        except ValueError as exc:
            return _json_error(400, f"bad time range: {exc}")
        # SCOPE IS RESOLVED, NOT IGNORED. The inventory covers monitored networks only (the
        # operator's rule: an external peer is not an asset we are responsible for). `all` and
        # `monitored` are therefore the two honest readings; `external` cannot be a third, and
        # an unknown value must not quietly return the full set as if the filter had applied.
        scope = str(request.args.get("scope") or "all").strip().lower()
        if scope not in ("all", "monitored"):
            return _json_error(
                400,
                f"unsupported asset scope '{scope}': the inventory covers monitored networks "
                "only, so the supported scopes are 'all' and 'monitored'",
            )
        return _soft_route(payloads.assets, payloads.assets_failure, hours=hours, scope=scope)

    @app.get("/api/asset-changes")
    @gated
    def asset_changes():
        from weirvern.admin import payloads, web  # noqa: PLC0415

        try:
            hours = web.window_arg(request.args, 24, 1, 24 * 14)
        except ValueError as exc:
            return _json_error(400, f"bad time range: {exc}")
        return _soft_route(payloads.asset_changes, payloads.asset_changes_failure, hours=hours)

    @app.get("/api/scan-jobs")
    @gated
    def scan_jobs():
        """The manual-scan queue. `ip` is optional; its own limit of 20 is inside the fetcher."""
        from weirvern.admin import payloads, web  # noqa: PLC0415

        ip = str(web._first(request.args, "ip", "") or "").strip()
        return _soft_route(payloads.scan_jobs, payloads.scan_jobs_failure, ip=ip)

    @app.get("/api/identity")
    @gated
    def host_identity():
        from weirvern.admin import payloads  # noqa: PLC0415

        return _soft_route(payloads.host_identity, payloads.host_identity_failure)

    @app.get("/api/networks")
    @gated
    def networks():
        """The clamped parse is the console's own, so `?hours=9999` is 168 on both surfaces."""
        from weirvern.admin import payloads, web  # noqa: PLC0415

        hours = web._int_arg(request.args, "hours", 24, 1, 168)
        return _soft_route(payloads.networks_overview, payloads.networks_failure, hours=hours)

    @app.get("/api/system")
    @gated
    def system():
        """A procfs read, not a database read: no client and no ClickHouse in the path."""
        from weirvern.admin import payloads, web  # noqa: PLC0415

        sensor = str(web._first(request.args, "sensor", "") or "").strip()
        return jsonify(payloads.system_payload(sensor=sensor))

    @app.get("/api/write-trail")
    @gated
    def write_trail():
        """No catch, deliberately: the console answers an exception here with its own 500 body.

        Inventing a 200 or a 503 would be a change to what the operator sees, and the app's error
        handler already reproduces the console's wording.
        """
        from weirvern.admin import payloads, web  # noqa: PLC0415

        args = web.write_trail_args(request.args)
        with ctx.connect_factory(ctx.settings) as client:
            return jsonify(payloads.write_trail(client, **args))

    @app.get("/api/blocklists")
    @gated
    def blocklists():
        from weirvern.admin import payloads  # noqa: PLC0415

        return _soft_route(payloads.blocklists, payloads.blocklists_failure)

    @app.get("/api/scanner")
    @gated
    def scanner():
        from weirvern.admin import payloads  # noqa: PLC0415

        return _soft_route(payloads.scanner, payloads.scanner_failure)

    @app.get("/api/models")
    @gated
    def models():
        from weirvern.admin import payloads, web  # noqa: PLC0415

        try:
            hours = web.window_arg(request.args, 72, 1, 24 * 30)
        except ValueError as exc:
            return _json_error(400, f"bad time range: {exc}")
        return _soft_route(payloads.models, payloads.models_failure, hours=hours,
                           settings=ctx.settings)

    # ── the windowed read families: same parsers, same fetchers, same 400 wording ──────────────
    #
    # THE CONSOLE PARSES `hours` BEFORE ITS FILTERS, so a request that is bad in both ways answers
    # the time-range sentence. These routes keep that order; swapping it would change which 400 a
    # caller sees for the same URL.

    @app.get("/api/netflow")
    @gated
    def netflow():
        from weirvern.admin import payloads, web  # noqa: PLC0415

        try:
            hours = web.window_arg(request.args, 24, 1, 24 * 14)
        except ValueError as exc:
            return _json_error(400, f"bad time range: {exc}")
        try:
            filters = web.netflow_filters(request.args)
        except ValueError as exc:
            return _json_error(400, str(exc))
        return _soft_route(payloads.netflow, payloads.netflow_failure, hours=hours,
                           filters=filters)

    @app.get("/api/zeek")
    @gated
    def zeek():
        from weirvern.admin import payloads, web  # noqa: PLC0415

        try:
            hours = web.window_arg(request.args, 24, 1, 24 * 14)
        except ValueError as exc:
            return _json_error(400, f"bad time range: {exc}")
        try:
            filters = web.zeek_filters(request.args)
        except ValueError as exc:
            return _json_error(400, str(exc))
        # `partial` binds the filters into the failure payload: the panel still shows what was
        # asked for, and `_soft_route` can only hand the builder an exception.
        failure = functools.partial(payloads.zeek_failure, filters=filters)
        return _soft_route(payloads.zeek, failure, hours=hours, filters=filters)

    @app.get("/api/flows")
    @gated
    def flows():
        from weirvern.admin import payloads, web  # noqa: PLC0415

        try:
            hours = web.window_arg(request.args, 24, 1, 24 * 14)
        except ValueError as exc:
            return _json_error(400, f"bad time range: {exc}")
        try:
            args = web.flows_args(request.args)
        except ValueError as exc:
            return _json_error(400, str(exc))
        return _soft_route(payloads.flows, payloads.flows_failure, hours=hours, **args)

    @app.get("/api/dns")
    @gated
    def dns():
        from weirvern.admin import payloads, web  # noqa: PLC0415

        try:
            hours = web.window_arg(request.args, 24, 1, 24 * 14)
        except ValueError as exc:
            return _json_error(400, f"bad time range: {exc}")
        try:
            args = web.dns_args(request.args)
        except ValueError as exc:
            return _json_error(400, str(exc))
        return _soft_route(payloads.dns, payloads.dns_failure, hours=hours, **args)

    # ── the address-validated detail reads: a 503 on failure, like the console's ───────────────

    @app.get("/api/host")
    @gated
    def host():
        from weirvern.admin import payloads, web  # noqa: PLC0415

        # The console checks the address BEFORE the window, so this order is the contract.
        try:
            addr = web.host_addr(request.args)
        except ValueError as exc:
            return _json_error(400, str(exc))
        try:
            hours = web.window_arg(request.args, 24, 1, 24 * 14)
        except ValueError as exc:
            return _json_error(400, f"bad time range: {exc}")
        return _payload_route(payloads.host, addr=addr, hours=hours)

    @app.get("/api/evidence")
    @gated
    def evidence():
        from weirvern.admin import payloads, web  # noqa: PLC0415

        try:
            args = web.evidence_args(request.args)
        except ValueError as exc:
            return _json_error(400, str(exc))
        return _payload_route(payloads.evidence, **args)

    @app.get("/api/incident")
    @gated
    def incident():
        from weirvern.admin import payloads, web  # noqa: PLC0415

        try:
            args = web.incident_args(request.args)
        except ValueError as exc:
            return _json_error(400, str(exc))
        return _payload_route(payloads.incident, **args)

    @app.get("/api/fingerprints")
    @gated
    def fingerprints():
        from weirvern.admin import payloads, web  # noqa: PLC0415

        try:
            ja4 = web.fingerprints_args(request.args)
        except ValueError as exc:
            return _json_error(400, str(exc))
        return _payload_route(payloads.fingerprints, ja4=ja4)

    @app.get("/api/findings")
    @gated
    def findings():
        from weirvern.admin import payloads, web  # noqa: PLC0415

        try:
            args = web.findings_args(request.args)
        except ValueError as exc:
            return _json_error(400, str(exc))
        return _soft_route(payloads.findings, payloads.findings_failure, **args)

    @app.get("/api/models/retrain")
    @gated
    def model_retrain():
        from weirvern.admin import payloads  # noqa: PLC0415

        return _soft_route(payloads.model_retrain, payloads.model_retrain_failure)

    @app.get("/api/graph")
    @gated
    def graph():
        from weirvern.admin import payloads, web  # noqa: PLC0415

        try:
            hours = web.window_arg(request.args, 24, 1, 24 * 14)
        except ValueError as exc:
            return _json_error(400, f"bad time range: {exc}")
        # getlist, not get: a repeated `host` is the whole point of the tracked selection, and a
        # scalar read would silently track only the first address.
        try:
            tracked = web.graph_hosts(request.args.getlist("host"))
        except ValueError as exc:
            return _json_error(400, str(exc))
        return _soft_route(payloads.graph, payloads.graph_failure, hours=hours, tracked=tracked)

    @app.get("/api/blocked")
    @gated
    def blocked():
        from weirvern.admin import payloads, web  # noqa: PLC0415

        try:
            hours = web.window_arg(request.args, 24, 1, 24 * 14)
        except ValueError as exc:
            return _json_error(400, f"bad time range: {exc}")
        try:
            args = web.blocked_args(request.args)
        except ValueError as exc:
            return _json_error(400, str(exc))
        return _soft_route(payloads.blocked, payloads.blocked_failure, hours=hours, **args)

    @app.get("/api/zeeklog")
    @gated
    def zeeklog():
        from weirvern.admin import payloads, web  # noqa: PLC0415

        # The console resolves the log label BEFORE the window, so a bad log is answered as such
        # even when the window is bad too.
        try:
            args = web.zeeklog_args(request.args)
        except ValueError as exc:
            return _json_error(400, str(exc))
        try:
            hours = web.window_arg(request.args, 24, 1, 24 * 14)
        except ValueError as exc:
            return _json_error(400, f"bad time range: {exc}")
        failure = functools.partial(payloads.zeeklog_failure, label=args["label"])
        return _soft_route(payloads.zeeklog, failure, hours=hours, **args)

    @app.get("/api/update")
    @gated
    def update():
        """No client and no catch: the console lets an exception become its own 500 body."""
        from weirvern.admin import payloads, web  # noqa: PLC0415

        return jsonify(payloads.update_meta(ctx.backend,
                                           refresh=web.update_refresh(request.args)))

    @app.post("/api/models/retrain")
    @app.post("/api/models/retrain/<tail>")
    def models_retrain_write(tail: str = ""):
        from weirvern.admin import payloads, requestauth, web  # noqa: PLC0415

        refused = _gate_write()
        if refused is not None:
            return refused
        try:
            body = web.json_body(request.get_data(cache=False))
        except ValueError as exc:
            return _json_error(400, str(exc))
        try:
            args = web.model_action_args(body, tail)
        except ValueError as exc:
            return _json_error(400, str(exc))
        ident = requestauth.identity(ctx, _auth_headers())
        try:
            with _connect() as client:
                code, payload = payloads.model_action(
                    client, by=(ident.username if ident else "operator"), **args)
        except Exception as exc:  # noqa: BLE001
            code, payload = 502, {"error": f"could not record the request: "
                                           f"{type(exc).__name__}", "code": 502}
        return jsonify(payload), code

    @app.get("/api/overview")
    @gated
    def overview():
        """The landing payload. It takes a CONNECTION FACTORY: the service list is read before the
        database is touched, so a database that will not connect still leaves the page a true fact.
        """
        from weirvern.admin import payloads  # noqa: PLC0415

        return jsonify(payloads.overview(
            lambda: ctx.connect_factory(ctx.settings), backend=ctx.backend,
            settings=ctx.settings, user_store=getattr(ctx, "user_store", None),
            capabilities=ctx.capabilities))

    @app.get("/api/health")
    @gated
    def health():
        from weirvern.admin import payloads, web  # noqa: PLC0415

        try:
            hours = web.window_arg(request.args, 24, 1, 24 * 14)
        except ValueError as exc:
            return _json_error(400, f"bad time range: {exc}")
        return _soft_route(payloads.health_deep, payloads.health_deep_failure, hours=hours,
                           settings=ctx.settings,
                           user_store=getattr(ctx, "user_store", None))

    @app.get("/api/weirlings/detail")
    @gated
    def weirlings_detail():
        from weirvern.admin import payloads, web  # noqa: PLC0415

        try:
            sensor_id = web.weirlings_detail_args(request.args)
        except ValueError as exc:
            return _json_error(400, str(exc))
        return _soft_route(payloads.weirlings_detail, payloads.weirlings_detail_failure,
                           sensor_id=sensor_id)

    @app.get("/api/weirlings/probe")
    @gated
    def weirlings_probe():
        from weirvern.admin import payloads, web  # noqa: PLC0415

        try:
            request_id = web.weirlings_probe_args(request.args)
        except ValueError as exc:
            return _json_error(400, str(exc))
        return _status_route(payloads.weirlings_probe, payloads.weirlings_probe_failure,
                             request_id=request_id)

    @app.get("/api/users")
    @gated
    def users():
        """Admin-only by CONTENT, not by method: the account list is not monitoring data."""
        from weirvern.admin import payloads, requestauth  # noqa: PLC0415
        from weirvern.admin import users as users_mod  # noqa: PLC0415

        if _caller_role()[0] != users_mod.ROLE_ADMIN:
            return _json_error(403, "admin access is required to view accounts")
        return jsonify(payloads.users_list(
            store=getattr(ctx, "user_store", None),
            accounts_on=requestauth.accounts_on(ctx),
            note=getattr(ctx, "accounts_note", "") or ""))

    @app.get("/api/anomalies")
    @gated
    def anomalies():
        from weirvern.admin import payloads, web  # noqa: PLC0415

        try:
            hours = web.window_arg(request.args, 24, 1, 24 * 14)
        except ValueError as exc:
            return _json_error(400, f"bad time range: {exc}")
        try:
            args = web.anomalies_args(request.args)
        except ValueError as exc:
            return _json_error(400, str(exc))
        return _payload_route(payloads.anomalies, hours=hours, settings=ctx.settings, **args)

    @app.get("/api/discover")
    @gated
    def discover():
        from weirvern.admin import payloads, web  # noqa: PLC0415

        try:
            hours = web.window_arg(request.args, 24, 1, 24 * 14)
        except ValueError as exc:
            return _json_error(400, f"bad time range: {exc}")
        # The chips are REPEATED values: getlist, or only the first one survives.
        fields = ("src", "dst", "sport", "dport")
        repeated = {field: request.args.getlist(field) for field in fields}
        try:
            args = web.discover_args(request.args, repeated)
        except ValueError as exc:
            return _json_error(400, str(exc))
        return _soft_route(payloads.discover, payloads.discover_failure, hours=hours, **args)

    @app.get("/api/sluice")
    @gated
    def sluice():
        """A CONNECTION FACTORY again: the policy table and the effective settings render even when
        the database is unreachable, which is the state this payload exists to describe."""
        from weirvern.admin import payloads, web  # noqa: PLC0415

        try:
            hours = web.window_arg(request.args, 24, 1, 24 * 14)
        except ValueError as exc:
            return _json_error(400, f"bad time range: {exc}")
        return jsonify(payloads.sluice(lambda: ctx.connect_factory(ctx.settings),
                                       hours=hours, settings=ctx.settings))

    @app.get("/api/normalize")
    @gated
    def normalize_feed():
        """The feed the operator reads: flows and DNS, filtered, with normalized rows marked."""
        from weirvern import normalize_store  # noqa: PLC0415
        from weirvern.admin import web  # noqa: PLC0415

        try:
            hours = web.window_arg(request.args, 24, 1, 24 * 14)
            port = int(request.args.get("port") or 0)
            offset = int(request.args.get("offset") or 0)
            min_bytes = int(request.args.get("min_bytes") or 0)
        except ValueError as exc:
            return _json_error(400, f"bad filter: {exc}")
        try:
            with ctx.connect_factory(ctx.settings) as client:
                payload = normalize_store.feed(
                    client, hours=hours, source=request.args.get("source", ""),
                    segment=request.args.get("segment", ""), port=port,
                    min_bytes=min_bytes, query=request.args.get("q", ""), offset=offset)
                # THE SIGNATURE LIST LIVES ON THE SAME SURFACE as the flow normalizations: an
                # operator reading "what has this network been taught" should not have to know
                # which module stores which half. One read fills both cards.
                from weirvern import ripple_signatures  # noqa: PLC0415

                payload["signatures"] = ripple_signatures.entries(client)
                payload["signature_summary"] = ripple_signatures.summary(payload["signatures"])
                payload["signature_review_days"] = ripple_signatures.REVIEW_DAYS
        except Exception as exc:  # noqa: BLE001
            payload = {"available": False, "reason": str(exc), "rows": [], "entries": [],
                       "summary": {}, "signatures": [], "signature_summary": {}}
        return jsonify(payload)

    @app.post("/api/normalize")
    def normalize_add():
        """Record the selected traffic as normal. It joins the host baseline at the next retrain."""
        from weirvern import normalize, normalize_store  # noqa: PLC0415

        refused = _gate_write()
        if refused is not None:
            return refused
        body, error = _body_or_refusal()
        if error is not None:
            return error
        selections = body.get("selections") if isinstance(body, dict) else None
        if not isinstance(selections, list) or not selections:
            return _json_error(400, "select at least one row to normalize")
        note = str((body or {}).get("note") or "")
        actor = _caller_name()
        try:
            rows = [normalize.new_entry(note=note, actor=actor, **normalize_selection(sel))
                    for sel in selections]
        except (TypeError, ValueError) as exc:
            return _json_error(400, str(exc))
        try:
            with ctx.connect_factory(ctx.settings) as client:
                added = normalize_store.write(client, rows)
                entries = normalize_store.entries(client)
        except Exception as exc:  # noqa: BLE001
            return _json_error(503, f"could not record the normalization: {exc}")
        return jsonify({"ok": True, "added": added, "entries": entries,
                        "summary": normalize.summarise(entries)})

    @app.post("/api/normalize/remove")
    def normalize_remove():
        """Take one entry out of the normalized set. The row is superseded, never deleted."""
        from weirvern import normalize, normalize_store  # noqa: PLC0415

        refused = _gate_write()
        if refused is not None:
            return refused
        body, error = _body_or_refusal()
        if error is not None:
            return error
        entry_id = str((body or {}).get("entry_id") or "")
        if not entry_id:
            return _json_error(400, "entry_id is required")
        try:
            with ctx.connect_factory(ctx.settings) as client:
                current = next((e for e in normalize_store.entries(client, include_removed=True)
                                if e["entry_id"] == entry_id), None)
                if current is None:
                    return _json_error(404, "no such normalization")
                normalize_store.write(client, [normalize.removal(current, actor=_caller_name())])
                entries = normalize_store.entries(client)
        except Exception as exc:  # noqa: BLE001
            return _json_error(503, f"could not remove the normalization: {exc}")
        return jsonify({"ok": True, "entries": entries,
                        "summary": normalize.summarise(entries)})

    @app.get("/api/ripple-signatures")
    @gated
    def ripple_signatures_list():
        """Every signature the operator has recorded: what is expected, until when, and by whom."""
        from weirvern import ripple_signatures  # noqa: PLC0415

        try:
            with ctx.connect_factory(ctx.settings) as client:
                entries = ripple_signatures.entries(client)
        except Exception as exc:  # noqa: BLE001
            return jsonify({"ok": False, "available": False, "error": str(exc),
                            "entries": [], "summary": {}})
        return jsonify({"ok": True, "available": True, "error": "", "entries": entries,
                        "summary": ripple_signatures.summary(entries),
                        "review_days": ripple_signatures.REVIEW_DAYS,
                        "max_review_days": ripple_signatures.MAX_REVIEW_DAYS})

    @app.get("/api/ripple-signatures/patterns")
    @gated
    def ripple_signatures_patterns():
        """The exact values a channel saw for one host in one window -- the sheet's preview.

        The evidence row carries a statistic (a diversity count), so the console cannot invent
        the value that produced it. This route asks the SAME table the measurement read, for the
        same hour, and returns only the values that actually occurred. It is read-only: a viewer
        may open the preview, and still cannot write.
        """
        from weirvern import monitored as monitored_mod  # noqa: PLC0415
        from weirvern import ripple_signatures  # noqa: PLC0415
        from weirvern.models import ripple_evidence  # noqa: PLC0415

        host = str(request.args.get("host") or "").strip()
        channel = str(request.args.get("channel") or "").strip()
        spec = ripple_signatures.find_spec(ripple_evidence.SPECS, channel)
        if spec is None:
            return jsonify({"ok": True, "capable": False, "values": [],
                            "reason": "no such channel on this deployment"})
        if not ripple_signatures.supports(spec):
            return jsonify({"ok": True, "capable": False, "values": [],
                            "reason": f"{channel} measures a number, not a named value; "
                                      "there is no one pattern to normalize"})
        try:
            end = _moment_arg(request.args.get("end"), datetime.now(UTC))
            start = _moment_arg(request.args.get("start"), end - timedelta(hours=1))
        except ValueError as exc:
            return _json_error(400, str(exc))
        if end <= start:
            return _json_error(400, "the window must end after it starts")
        if end - start > timedelta(days=2):
            return _json_error(400, "the preview window is one ripple, not a history scan")
        try:
            with ctx.connect_factory(ctx.settings) as client:
                nets = [str(net) for net in monitored_mod.networks(client)]
                values = ripple_signatures.candidates(
                    client, spec, host=host, start=start, end=end,
                    scope_cidrs=tuple(nets) or None)
                entries = ripple_signatures.entries(client)
        except Exception as exc:  # noqa: BLE001
            return jsonify({"ok": False, "capable": True, "values": [], "error": str(exc)})
        live = {str(row.get("value")): (str(row.get("review_after") or ""), str(row.get("id") or ""))
                for row in entries if str(row.get("host_addr")) == host
                and str(row.get("channel")) == channel and not row.get("removed_at")}
        today = datetime.now(UTC).date()
        for row in values:
            until, signature_id = live.get(row["value"], ("", ""))
            row["normalized_until"] = until
            row["normalized_id"] = signature_id
        return jsonify({
            "ok": True, "capable": True, "reason": "", "host": host, "channel": channel,
            "family": spec.family, "values": values,
            "review_after_default": (today + timedelta(days=ripple_signatures.REVIEW_DAYS))
                                    .isoformat(),
            "review_days": ripple_signatures.REVIEW_DAYS,
            "max_review_days": ripple_signatures.MAX_REVIEW_DAYS,
        })

    @app.post("/api/ripple-signatures")
    def ripple_signatures_add():
        """Record ONE exact value as expected for ONE host on ONE channel.

        The body is read as a narrow set: host, channel, value, reason, review_after. A `family`
        or any other key is refused rather than ignored, because ignoring it would let a caller
        believe it had widened the claim. `new_signature()` refuses a CIDR, a family name, an
        empty value and any horizon past a year.
        """
        from weirvern import ripple_signatures  # noqa: PLC0415
        from weirvern.models import ripple_evidence  # noqa: PLC0415

        refused = _gate_write()
        if refused is not None:
            return refused
        body, error = _body_or_refusal()
        if error is not None:
            return error
        if not isinstance(body, dict):
            return _json_error(400, "the request must be one JSON object")
        allowed = {"host", "host_addr", "channel", "value", "reason", "review_after"}
        unknown = sorted(set(body) - allowed)
        if unknown:
            return _json_error(400, "a signature names one host, one channel and one exact value; "
                                    f"these fields are not part of that claim: {', '.join(unknown)}")
        try:
            row = ripple_signatures.new_signature(
                host=str(body.get("host") or body.get("host_addr") or ""),
                channel=str(body.get("channel") or ""),
                value=str(body.get("value") or ""),
                reason=str(body.get("reason") or ""),
                review_after=body.get("review_after"),
                channels=ripple_evidence.SIGNATURE_CHANNELS,
                actor=_actor_name(),
            )
        except (TypeError, ValueError) as exc:
            return _json_error(400, str(exc))
        try:
            with ctx.connect_factory(ctx.settings) as client:
                existing = next(
                    (entry for entry in ripple_signatures.entries(client)
                     if entry.get("host_addr") == row["host_addr"]
                     and entry.get("channel") == row["channel"]
                     and entry.get("value") == row["value"]
                     and not entry.get("removed_at")), None)
                if existing is None:
                    ripple_signatures.write(client, [row])
                    entry = row
                else:
                    entry = existing
                entries = ripple_signatures.entries(client)
        except Exception as exc:  # noqa: BLE001
            return _json_error(503, f"could not record the signature: {exc}")
        return jsonify({"ok": True, "entry": entry, "duplicate": existing is not None,
                        "entries": entries, "summary": ripple_signatures.summary(entries)})

    @app.post("/api/ripple-signatures/remove")
    def ripple_signatures_remove():
        """Stop expecting a value. The evidence returns on the next pass; the row is superseded."""
        from weirvern import ripple_signatures  # noqa: PLC0415

        refused = _gate_write()
        if refused is not None:
            return refused
        body, error = _body_or_refusal()
        if error is not None:
            return error
        signature_id = str((body or {}).get("id") or "")
        if not signature_id:
            return _json_error(400, "id is required")
        try:
            with ctx.connect_factory(ctx.settings) as client:
                current = next((entry for entry in ripple_signatures.entries(client)
                                if entry.get("id") == signature_id
                                and not entry.get("removed_at")), None)
                if current is None:
                    return _json_error(404, "no such signature")
                ripple_signatures.write(client, [ripple_signatures.removal(
                    current, actor=_actor_name(), reason=str((body or {}).get("reason") or ""))])
                entries = ripple_signatures.entries(client)
        except Exception as exc:  # noqa: BLE001
            return _json_error(503, f"could not remove the signature: {exc}")
        return jsonify({"ok": True, "entries": entries,
                        "summary": ripple_signatures.summary(entries)})

    @app.get("/api/settings")
    @gated
    def settings_view():
        """Named `settings_view`, not `settings`: a view function called `settings` would shadow the
        keyword the payload call uses, and the next reader would have to work out which is which.
        """
        from weirvern.admin import payloads, requestauth  # noqa: PLC0415

        role, via = _caller_role()
        ident = requestauth.identity(ctx, _auth_headers())
        return jsonify(payloads.settings_payload(
            settings=ctx.settings, backend=ctx.backend,
            config_client=getattr(ctx, "config_client", None),
            auth=getattr(ctx, "auth", None), role=role, via=via, identity=ident,
            accounts_on=requestauth.accounts_on(ctx),
            # The retention row's ARITHMETIC needs the live disk and ingest; nothing else on
            # the page does, and a failed measurement degrades to a sentence rather than
            # blanking the tab.
            connect=(lambda: ctx.connect_factory(ctx.settings))
            if getattr(ctx, "connect_factory", None) else None))

    @app.get("/api/weirlings")
    @gated
    def weirlings():
        """The last read. A connection factory again: the fleet read, the flow evidence and the
        revoked list each open their own connection and each fail on their own."""
        from weirvern.admin import payloads, web  # noqa: PLC0415

        return jsonify(payloads.weirlings(
            lambda: ctx.connect_factory(ctx.settings), settings=ctx.settings,
            **web.weirlings_args(request.args)))

    # ── the write surface, one route at a time ──────────────────────────────────────────────────
    #
    # EVERY write takes `requestauth.write_refusal` FIRST, before the body is even read: the gate
    # decides whether this caller may write at all, and the body cannot change that answer.

    @app.post("/api/watch")
    def watch():
        from weirvern.admin import payloads, requestauth, web  # noqa: PLC0415

        ok, refusal = requestauth.write_refusal(ctx, _auth_headers(),
                                                addr=request.remote_addr or "")
        if not ok:
            code, message = refusal if refusal is not None else (403, "write access is required")
            return _json_error(code, message)
        try:
            body = web.json_body(request.get_data(cache=False))
        except ValueError as exc:
            return _json_error(400, str(exc))
        try:
            args = web.watch_body(body)
        except ValueError as exc:
            return _json_error(400, str(exc))
        try:
            with ctx.connect_factory(ctx.settings) as client:
                code, payload = payloads.watch(client, **args)
        except Exception as exc:  # noqa: BLE001
            code, payload = payloads.watch_failure(exc)
        return jsonify(payload), code

    @app.post("/api/review")
    def review():
        from weirvern.admin import payloads, requestauth, web  # noqa: PLC0415

        ok, refusal = requestauth.write_refusal(ctx, _auth_headers(),
                                                addr=request.remote_addr or "")
        if not ok:
            code, message = refusal if refusal is not None else (403, "write access is required")
            return _json_error(code, message)
        try:
            body = web.json_body(request.get_data(cache=False))
        except ValueError as exc:
            return _json_error(400, str(exc))
        try:
            args = web.review_args(body)
        except ValueError as exc:
            return _json_error(400, str(exc))
        # The unknown-state answer carries `valid_states`, so it is its own body rather than the
        # house error shape; both surfaces ask the same builder.
        state_refusal = payloads.review_state_refusal(args["state"])
        if state_refusal is not None:
            return jsonify(state_refusal), 400
        try:
            with ctx.connect_factory(ctx.settings) as client:
                code, payload = payloads.review(client, **args)
        except Exception as exc:  # noqa: BLE001
            code, payload = payloads.review_failure(exc)
        return jsonify(payload), code

    # ── the account writes: one shape, four field sets ─────────────────────────────────────────

    def _account_write(kind: str, fetcher):
        """Create / role / delete / reset share their gate, body and store check.

        THE STORE CHECK COMES BEFORE THE FIELDS ARE USED, on both surfaces: a GUI built without an
        account store answers 503 whatever the body says, which is the console's order.
        """
        from weirvern.admin import payloads, requestauth, web  # noqa: PLC0415

        ok, refusal = requestauth.write_refusal(ctx, _auth_headers(),
                                                addr=request.remote_addr or "")
        if not ok:
            code, message = refusal if refusal is not None else (403, "write access is required")
            return _json_error(code, message)
        try:
            body = web.json_body(request.get_data(cache=False))
        except ValueError as exc:
            return _json_error(400, str(exc))
        store = getattr(ctx, "user_store", None)
        if store is None:
            return _json_error(503, payloads.ACCOUNTS_UNAVAILABLE)
        args = web.user_write_args(body, kind=kind)
        if kind == "create":
            code, payload = fetcher(store, **args)
        else:
            code, payload = fetcher(store, getattr(ctx, "sessions", None), **args)
        return jsonify(payload), code

    @app.post("/api/users/create")
    def users_create():
        from weirvern.admin import payloads  # noqa: PLC0415

        return _account_write("create", payloads.user_create)

    @app.post("/api/users/role")
    def users_role():
        from weirvern.admin import payloads  # noqa: PLC0415

        return _account_write("role", payloads.user_role)

    @app.post("/api/users/delete")
    def users_delete():
        from weirvern.admin import payloads  # noqa: PLC0415

        return _account_write("delete", payloads.user_delete)

    @app.post("/api/users/reset")
    def users_reset():
        from weirvern.admin import payloads  # noqa: PLC0415

        return _account_write("reset", payloads.user_reset)

    # ── per-token credentials: mint, list, revoke ────────────────────────────────────────────────
    #
    # A TOKEN MAY NOT MANAGE TOKENS. Every route below requires a SIGNED-IN ADMIN SESSION, and the
    # check is on `identity()` -- the session path -- not on `token_role()` and not on
    # `write_refusal()`. That is deliberate: `write_refusal` admits an admin token, and a credential
    # that can mint or revoke credentials is a credential that can outlive its own revocation. The
    # legacy break-glass token is no exception, because losing control of it must still be fixable
    # by a person who can sign in.
    #
    # CSRF: these are JSON routes, reached the same way `/api/settings/apply` is. The session rides
    # in the X-Weirvern-Session header (or the SameSite=Strict signed cookie this app folds into
    # that header), which a cross-site form cannot set, and a form-encoded body is refused by the
    # shared JSON parser. There is no nonce here for the same reason there is none on the other API
    # writes; the rendered-form nonce protects the pages that post forms, not this surface.

    def _admin_session() -> tuple[Any, Any]:
        """The signed-in admin for this request, and the refusal response when there is none.

        BOTH POSITIONS ARE `Any` ON PURPOSE: the caller branches on `refused is not None`, which is
        the invariant this function guarantees (exactly one of the two is set).
        """
        from weirvern.admin import requestauth  # noqa: PLC0415

        ident = requestauth.identity(ctx, _auth_headers())
        if ident is None:
            return None, _json_error(
                403, "managing tokens requires a signed-in admin account; a token cannot mint "
                     "or revoke tokens")
        if ident.must_change:
            return None, _json_error(403, "change your password before managing tokens")
        if not ident.is_admin:
            return None, _json_error(403, "admin access is required to manage tokens")
        return ident, None

    @app.get("/api/tokens")
    def tokens_view():
        from weirvern.admin import payloads  # noqa: PLC0415

        _ident, refused = _admin_session()
        if refused is not None:
            return refused
        return jsonify(payloads.tokens_list(store=getattr(ctx, "token_store", None)))

    @app.post("/api/tokens/create")
    def tokens_create():
        from weirvern.admin import payloads, requestauth, web  # noqa: PLC0415

        ident, refused = _admin_session()
        if refused is not None:
            return refused
        store = getattr(ctx, "token_store", None)
        if store is None:
            return _json_error(503, payloads.TOKENS_UNAVAILABLE)
        try:
            body = web.json_body(request.get_data(cache=False))
        except ValueError as exc:
            return _json_error(400, str(exc))
        args = web.token_create_args(body)
        code, payload = payloads.token_create(store, created_by=ident.username, **args)
        if code == 200:
            # THE AUDIT ROW CARRIES THE NAME AND ROLE, NEVER THE SECRET. `audit_auth` has no
            # parameter that could carry it, which is the point.
            requestauth.audit_auth(ctx, "token-create", args["name"],
                                   f"created a {args['role']} token")
        return jsonify(payload), code

    @app.post("/api/tokens/revoke")
    def tokens_revoke():
        from weirvern.admin import payloads, requestauth, web  # noqa: PLC0415

        ident, refused = _admin_session()
        if refused is not None:
            return refused
        store = getattr(ctx, "token_store", None)
        if store is None:
            return _json_error(503, payloads.TOKENS_UNAVAILABLE)
        try:
            body = web.json_body(request.get_data(cache=False))
        except ValueError as exc:
            return _json_error(400, str(exc))
        args = web.token_revoke_args(body)
        code, payload = payloads.token_revoke(store, revoked_by=ident.username, **args)
        if code == 200:
            record = payload.get("record") or {}
            requestauth.audit_auth(ctx, "token-revoke", str(record.get("name") or ""), "revoked")
        return jsonify(payload), code

    # ── the session routes: sign in, sign out, change your own password ───────────────────────
    #
    # THESE THREE DO NOT USE `_account_write` OR `gated`. /api/login is the door itself, and the other
    # two are the only writes a non-admin account may make: they check the SESSION (not the role, not
    # the operator token), and they check it BEFORE parsing, which is the console's order.

    @app.post("/api/login")
    def api_login():
        from weirvern.admin import payloads, web  # noqa: PLC0415

        # The accounts check comes first: a GUI with no accounts refuses whatever was posted.
        refusal = payloads.login_refusal(ctx)
        if refusal is not None:
            return jsonify(refusal), 403
        try:
            body = web.json_body(request.get_data(cache=False))
        except ValueError as exc:
            return _json_error(400, str(exc))
        code, payload = payloads.login(
            ctx, username=str(body.get("username") or ""),
            password=str(body.get("password") or ""), addr=request.remote_addr or "")
        return jsonify(payload), code

    @app.post("/api/logout")
    def api_logout():
        from weirvern.admin import payloads  # noqa: PLC0415

        ident, refusal = payloads.session_required(ctx, _auth_headers())
        if refusal is not None:
            return jsonify(refusal[1]), refusal[0]
        code, payload = payloads.logout(ctx, ident, _auth_headers())
        return jsonify(payload), code

    @app.post("/api/password")
    def api_password():
        from weirvern.admin import payloads, web  # noqa: PLC0415

        ident, refusal = payloads.session_required(ctx, _auth_headers())
        if refusal is not None:
            return jsonify(refusal[1]), refusal[0]
        try:
            body = web.json_body(request.get_data(cache=False))
        except ValueError as exc:
            return _json_error(400, str(exc))
        code, payload = payloads.password_change(
            ctx, ident, current=str(body.get("current") or ""),
            new=str(body.get("new") or ""))
        return jsonify(payload), code

    # ── the sluice and scan-job writes: rules that can take a network down ──────────────────────
    #
    # THESE CHECK THEIR PREDICATES BEFORE THE DATABASE IS OPENED, on both surfaces: a refused rule
    # answers 400 with the sentence the form shows inline, and never reaches a query.

    @app.post("/api/scan-jobs")
    def scan_job_create():
        from weirvern.admin import payloads, requestauth, web  # noqa: PLC0415

        ok, refusal = requestauth.write_refusal(ctx, _auth_headers(),
                                                addr=request.remote_addr or "")
        if not ok:
            code, message = refusal if refusal is not None else (403, "write access is required")
            return _json_error(code, message)
        try:
            body = web.json_body(request.get_data(cache=False))
        except ValueError as exc:
            return _json_error(400, str(exc))
        try:
            args = web.scan_job_args(body)
        except ValueError as exc:
            return _json_error(400, str(exc))
        try:
            with ctx.connect_factory(ctx.settings) as client:
                code, payload = payloads.scan_job_create(client, **args)
        except Exception as exc:  # noqa: BLE001
            code, payload = payloads.scan_job_failure(exc)
        return jsonify(payload), code

    @app.post("/api/sluice/block")
    def sluice_block():
        from weirvern.admin import payloads, requestauth, web  # noqa: PLC0415

        ok, refusal = requestauth.write_refusal(ctx, _auth_headers(),
                                                addr=request.remote_addr or "")
        if not ok:
            code, message = refusal if refusal is not None else (403, "write access is required")
            return _json_error(code, message)
        try:
            body = web.json_body(request.get_data(cache=False))
        except ValueError as exc:
            return _json_error(400, str(exc))
        try:
            args, rule_refusal = web.sluice_block_args(
                body, settings=ctx.settings, sensor_addrs=web.sensor_addresses(ctx))
        except ValueError as exc:
            return _json_error(400, str(exc))
        if rule_refusal:
            return jsonify({"ok": False, "error": rule_refusal}), 400
        ident = requestauth.identity(ctx, _auth_headers())
        try:
            with ctx.connect_factory(ctx.settings) as client:
                code, payload = payloads.sluice_block(
                    client, by=(ident.username if ident else "operator"), **args,
                    interval_s=int(ctx.settings.sluice_interval_s))
        except Exception as exc:  # noqa: BLE001
            code, payload = payloads.sluice_block_failure(exc)
        return jsonify(payload), code

    @app.post("/api/sluice/revoke")
    def sluice_revoke():
        from weirvern.admin import payloads, requestauth, web  # noqa: PLC0415

        ok, refusal = requestauth.write_refusal(ctx, _auth_headers(),
                                                addr=request.remote_addr or "")
        if not ok:
            code, message = refusal if refusal is not None else (403, "write access is required")
            return _json_error(code, message)
        try:
            body = web.json_body(request.get_data(cache=False))
        except ValueError as exc:
            return _json_error(400, str(exc))
        try:
            args = web.sluice_revoke_args(body)
        except ValueError as exc:
            return _json_error(400, str(exc))
        ident = requestauth.identity(ctx, _auth_headers())
        try:
            with ctx.connect_factory(ctx.settings) as client:
                code, payload = payloads.sluice_revoke(
                    client, by=(ident.username if ident else "operator"), **args,
                    interval_s=int(ctx.settings.sluice_interval_s))
        except Exception as exc:  # noqa: BLE001
            code, payload = payloads.sluice_revoke_failure(exc)
        return jsonify(payload), code

    # ── the rule sheet: three edits that are small but change enforcement ───────────────────────

    @app.post("/api/sluice/rule/mode")
    def sluice_rule_mode():
        from weirvern.admin import payloads, requestauth, web  # noqa: PLC0415

        ok, refusal = requestauth.write_refusal(ctx, _auth_headers(),
                                                addr=request.remote_addr or "")
        if not ok:
            code, message = refusal if refusal is not None else (403, "write access is required")
            return _json_error(code, message)
        try:
            body = web.json_body(request.get_data(cache=False))
        except ValueError as exc:
            return _json_error(400, str(exc))
        try:
            args, mode_refusal = web.sluice_rule_mode_args(body)
        except ValueError as exc:
            return _json_error(400, str(exc))
        if mode_refusal:
            return jsonify({"ok": False, "error": mode_refusal}), 400
        ident = requestauth.identity(ctx, _auth_headers())
        try:
            with ctx.connect_factory(ctx.settings) as client:
                code, payload = payloads.sluice_rule_mode(
                    client, by=(ident.username if ident else "operator"), **args)
        except Exception as exc:  # noqa: BLE001
            code, payload = payloads.sluice_rule_failure(exc)
        return jsonify(payload), code

    @app.post("/api/sluice/rule/domain")
    def sluice_rule_domain():
        from weirvern.admin import payloads, requestauth, web  # noqa: PLC0415

        ok, refusal = requestauth.write_refusal(ctx, _auth_headers(),
                                                addr=request.remote_addr or "")
        if not ok:
            code, message = refusal if refusal is not None else (403, "write access is required")
            return _json_error(code, message)
        try:
            body = web.json_body(request.get_data(cache=False))
        except ValueError as exc:
            return _json_error(400, str(exc))
        try:
            args = web.sluice_rule_domain_args(body)
        except ValueError as exc:
            return _json_error(400, str(exc))
        ident = requestauth.identity(ctx, _auth_headers())
        try:
            with ctx.connect_factory(ctx.settings) as client:
                code, payload = payloads.sluice_rule_domain(
                    client, by=(ident.username if ident else "operator"), **args)
        except Exception as exc:  # noqa: BLE001
            code, payload = payloads.sluice_rule_failure(exc)
        return jsonify(payload), code

    @app.post("/api/sluice/rule/disabled")
    def sluice_rule_disabled():
        from weirvern.admin import payloads, requestauth, web  # noqa: PLC0415

        ok, refusal = requestauth.write_refusal(ctx, _auth_headers(),
                                                addr=request.remote_addr or "")
        if not ok:
            code, message = refusal if refusal is not None else (403, "write access is required")
            return _json_error(code, message)
        try:
            body = web.json_body(request.get_data(cache=False))
        except ValueError as exc:
            return _json_error(400, str(exc))
        try:
            args = web.sluice_rule_disabled_args(body)
        except ValueError as exc:
            return _json_error(400, str(exc))
        ident = requestauth.identity(ctx, _auth_headers())
        try:
            with ctx.connect_factory(ctx.settings) as client:
                code, payload = payloads.sluice_rule_disabled(
                    client, by=(ident.username if ident else "operator"), **args,
                    interval_s=int(ctx.settings.sluice_interval_s))
        except Exception as exc:  # noqa: BLE001
            code, payload = payloads.sluice_rule_disabled_failure(exc)
        return jsonify(payload), code

    # ── the blocklist and network writes: one uniform shape, six routes ─────────────────────────

    def _write_json(parse, call, failure, *, needs_body: bool = True):
        """The shape these six share: gate, body, fields, one client, one fetcher.

        ORDER IS THE CONTRACT and it is the console's: the gate before the body (`write_refusal`), the
        body before the fields, and the fields before the database is opened. `parse` raises ValueError
        for the house 400; `failure` answers what the fetcher could not, including a failed CONNECTION,
        because the console wraps the connection in the same try.
        """
        from weirvern.admin import requestauth, web  # noqa: PLC0415

        ok, refusal = requestauth.write_refusal(ctx, _auth_headers(),
                                                addr=request.remote_addr or "")
        if not ok:
            code, message = refusal if refusal is not None else (403, "write access is required")
            return _json_error(code, message)
        args: dict = {}
        if needs_body:
            try:
                body = web.json_body(request.get_data(cache=False))
            except ValueError as exc:
                return _json_error(400, str(exc))
            try:
                args = parse(body)
            except ValueError as exc:
                return _json_error(400, str(exc))
        try:
            with ctx.connect_factory(ctx.settings) as client:
                code, payload = call(client, **args)
        except Exception as exc:  # noqa: BLE001
            code, payload = failure(exc)
        return jsonify(payload), code

    @app.post("/api/blocklists/sync")
    def blocklist_sync():
        from weirvern.admin import payloads  # noqa: PLC0415

        # NO BODY: the sync takes no input, and the console never reads one.
        return _write_json(lambda body: {}, payloads.blocklist_sync,
                           payloads.blocklist_sync_failure, needs_body=False)

    @app.post("/api/blocklists/source")
    def blocklist_source():
        from weirvern.admin import payloads, web  # noqa: PLC0415

        return _write_json(web.blocklist_source_args, payloads.blocklist_source_add,
                           payloads.blocklist_source_failure)

    @app.post("/api/blocklists/custom")
    def blocklist_custom():
        from weirvern.admin import payloads, web  # noqa: PLC0415

        return _write_json(web.blocklist_custom_args, payloads.blocklist_custom,
                           payloads.blocklist_custom_failure)

    @app.post("/api/blocklists/enable")
    def blocklist_enable():
        from weirvern.admin import payloads, web  # noqa: PLC0415

        return _write_json(web.blocklist_enable_args, payloads.blocklist_enable,
                           payloads.blocklist_enable_failure)

    @app.post("/api/networks/save")
    def networks_save():
        from weirvern.admin import payloads  # noqa: PLC0415

        # THE BODY GOES THROUGH WHOLE: networks.save_scope owns the field rules.
        return _write_json(lambda body: {"body": body}, payloads.network_scope_save,
                           payloads.network_save_failure)

    @app.post("/api/networks/delete")
    def networks_delete():
        from weirvern.admin import payloads  # noqa: PLC0415

        return _write_json(lambda body: {"scope_id": str(body.get("id") or "")},
                           payloads.network_scope_delete, payloads.network_delete_failure)

    # ── the fleet writes: registrations and per-sensor plans ────────────────────────────────────
    #
    # THESE ANSWER `{"ok": false}` FOR A BAD BODY, not the house error shape: the fleet panel renders
    # `error` beside the form either way, and the console has always sent it this way.

    def _gate_write():
        """The write gate, as the caller's refusal response or None."""
        from weirvern.admin import requestauth  # noqa: PLC0415

        ok, refusal = requestauth.write_refusal(ctx, _auth_headers(),
                                                addr=request.remote_addr or "")
        if ok:
            return None
        code, message = refusal if refusal is not None else (403, "write access is required")
        return _json_error(code, message)

    def _caller_name():
        """Who to attribute the write to. A token has no name; an account does."""
        try:
            role, via = _caller_role()
            ident = getattr(_auth_headers(), "get", lambda _k: None)("X-Weirvern-User")
            return str(ident or via or role or "operator")
        except Exception:  # noqa: BLE001
            return "operator"

    def _actor_name():
        """The ACTUAL person or credential behind a write, for provenance.

        `_caller_name` reports the credential's kind ("session"), which is enough to explain a
        write but not to review one. A session knows its username; `identity()` is the shared
        lookup, so this does not invent a second session reader.
        """
        try:
            _role, via = _caller_role()
            if via == "session":
                from weirvern.admin import requestauth  # noqa: PLC0415

                ident = requestauth.identity(ctx, _auth_headers())
                if ident is not None and getattr(ident, "username", ""):
                    return str(ident.username)
            return str(getattr(_auth_headers(), "get", lambda _k: None)("X-Weirvern-User")
                       or via or "operator")
        except Exception:  # noqa: BLE001
            return "operator"

    def _moment_arg(raw: str | None, fallback: datetime) -> datetime:
        """An ISO instant from the query string, as aware UTC. A bad value is a 400, not a guess."""
        if not raw:
            return fallback
        text = str(raw).strip().replace("Z", "+00:00")
        try:
            value = datetime.fromisoformat(text)
        except ValueError as exc:
            raise ValueError(f"not an ISO timestamp: {raw!r}") from exc
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)

    def normalize_selection(sel: dict) -> dict:
        """One feed row -> the arguments `normalize.new_entry` accepts. Validation is its job."""
        if not isinstance(sel, dict):
            raise TypeError("each selection must be an object")
        # A scope re-derives the prefix from the destination address: the sheet lets the
        # operator widen a /24 to its /16 or narrow it to the one host.
        prefix = sel.get("dst_prefix", "")
        scope = str(sel.get("scope") or "").strip()
        if scope:
            from weirvern import normalize  # noqa: PLC0415
            prefix = normalize.scope_prefix(
                str(sel.get("dst_host") or sel.get("dst_addr") or ""), scope)
        return {
            "source": sel.get("source", "flow"),
            "src_addr": sel.get("src_addr", ""),
            "dst_prefix": prefix,
            "dst_port": int(sel.get("dst_port") or 0),
            "proto": int(sel.get("proto") or 0),
            "dns_name": sel.get("dns_name", ""),
            "dns_qtype": int(sel.get("dns_qtype") or 0),
            "flows": int(sel.get("flows") or 0),
            "bytes_": int(sel.get("bytes") or 0),
            "packets": int(sel.get("packets") or 0),
            "samples": int(sel.get("samples") or 0),
            "avg_bytes": float(sel.get("avg_bytes") or 0),
            "var_bytes": float(sel.get("var_bytes") or 0),
            "avg_packets": float(sel.get("avg_packets") or 0),
            "var_packets": float(sel.get("var_packets") or 0),
        }

    def _connect():
        """A fresh connection, per block: the fleet routes open several, as the console does."""
        return ctx.connect_factory(ctx.settings)

    def _body_or_refusal():
        from weirvern.admin import web  # noqa: PLC0415

        try:
            return web.json_body(request.get_data(cache=False)), None
        except ValueError as exc:
            return None, (jsonify({"ok": False, "error": str(exc)}), 400)

    @app.post("/api/weirlings/register")
    def weirlings_register():
        from weirvern.admin import payloads, web  # noqa: PLC0415

        refused = _gate_write()
        if refused is not None:
            return refused
        body, bad = _body_or_refusal()
        if bad is not None:
            return bad
        args = web.weirling_register_args(body)
        try:
            with _connect() as client:
                code, payload = payloads.weirling_register(client, **args)
        except Exception as exc:  # noqa: BLE001
            code, payload = payloads.weirling_save_failure(exc)
        return jsonify(payload), code

    @app.post("/api/weirlings/enable")
    def weirlings_enable():
        from weirvern.admin import payloads, web  # noqa: PLC0415

        refused = _gate_write()
        if refused is not None:
            return refused
        body, bad = _body_or_refusal()
        if bad is not None:
            return bad
        args, refusal = web.weirling_enable_args(body)
        if refusal:
            return jsonify({"ok": False, "error": refusal}), 400
        try:
            with _connect() as client:
                code, payload = payloads.weirling_enable(client, **args)
        except Exception as exc:  # noqa: BLE001
            code, payload = payloads.weirling_save_failure(exc)
        return jsonify(payload), code

    @app.post("/api/weirlings/revoke")
    def weirlings_revoke():
        from weirvern.admin import payloads, requestauth, web  # noqa: PLC0415

        refused = _gate_write()
        if refused is not None:
            return refused
        body, bad = _body_or_refusal()
        if bad is not None:
            return bad
        args, refusal = web.weirling_revoke_args(body)
        if refusal:
            return jsonify({"ok": False, "error": refusal}), 400
        ident = requestauth.identity(ctx, _auth_headers())
        code, payload = payloads.weirling_revoke(
            _connect, actor=(ident.username if ident else "operator"),
            config_client=getattr(ctx, "config_client", None), **args)
        return jsonify(payload), code

    @app.post("/api/weirlings/plan")
    def weirlings_plan():
        from weirvern.admin import payloads, web  # noqa: PLC0415

        refused = _gate_write()
        if refused is not None:
            return refused
        body, bad = _body_or_refusal()
        if bad is not None:
            return bad
        args, refusal = web.weirling_plan_args(body)
        if refusal:
            return jsonify({"ok": False, "error": refusal}), 400
        code, payload = payloads.weirling_plan(_connect, **args)
        return jsonify(payload), code

    @app.post("/api/weirlings/apply")
    def weirlings_apply():
        from weirvern.admin import payloads, requestauth, web  # noqa: PLC0415

        refused = _gate_write()
        if refused is not None:
            return refused
        body, bad = _body_or_refusal()
        if bad is not None:
            return bad
        args, refusal = web.weirling_apply_args(body)
        if refusal:
            return jsonify({"ok": False, "error": refusal}), 400
        ident = requestauth.identity(ctx, _auth_headers())
        code, payload = payloads.weirling_apply(
            _connect, actor=(ident.username if ident else "operator"), **args)
        return jsonify(payload), code

    @app.post("/api/weirlings/probe")
    def weirlings_probe_post():
        # NOT `weirlings_probe`: the GET route above already owns that endpoint name, and Flask refuses
        # two views with one name. The console's handler is `_weirlings_probe_post` for the same reason.
        from weirvern.admin import payloads, web  # noqa: PLC0415

        refused = _gate_write()
        if refused is not None:
            return refused
        body, bad = _body_or_refusal()
        if bad is not None:
            return bad
        args, refusal = web.weirling_probe_args(body)
        if refusal:
            return jsonify({"ok": False, "error": refusal}), 400
        code, payload = payloads.weirling_probe(_connect, **args)
        return jsonify(payload), code

    @app.post("/api/networks/autofill")
    def networks_autofill():
        from weirvern.admin import payloads  # noqa: PLC0415

        # NO BODY: the approval is the whole request, and the console never reads one.
        return _write_json(lambda body: {}, payloads.network_scope_autofill,
                           payloads.network_autofill_failure, needs_body=False)

    @app.post("/api/settings/plan")
    def settings_plan():
        from weirvern.admin import payloads, web  # noqa: PLC0415

        refused = _gate_write()
        if refused is not None:
            return refused
        try:
            body = web.json_body(request.get_data(cache=False))
        except ValueError as exc:
            return _json_error(400, str(exc))
        try:
            args = web.settings_changes_args(body)
        except ValueError as exc:
            return _json_error(400, str(exc))
        # NO DATABASE CONNECTION, deliberately: the console's plan route reads the ConfigMap and
        # nothing else, so opening one here would invent a failure mode the console does not have.
        code, payload = payloads.settings_plan(ctx, **args)
        return jsonify(payload), code

    @app.post("/api/settings/apply")
    def settings_apply():
        from weirvern.admin import payloads, requestauth, web  # noqa: PLC0415

        refused = _gate_write()
        if refused is not None:
            return refused
        try:
            body = web.json_body(request.get_data(cache=False))
        except ValueError as exc:
            return _json_error(400, str(exc))
        try:
            args = web.settings_apply_args(body)
        except ValueError as exc:
            return _json_error(400, str(exc))
        ident = requestauth.identity(ctx, _auth_headers())
        # THE CHECKS AND THE TRAIL NEED A DATABASE CONNECTION, and the ConfigMap write does not: the
        # factory is passed rather than opened here, because the fetcher opens one per block and a
        # failed connection must degrade the CHECKS, not the apply.
        code, payload = payloads.settings_apply(
            ctx, _connect, actor=(ident.username if ident else "operator"), **args)
        return jsonify(payload), code

    @app.post("/api/settings/test")
    def settings_test():
        from weirvern.admin import payloads, web  # noqa: PLC0415

        refused = _gate_write()
        if refused is not None:
            return refused
        try:
            body = web.json_body(request.get_data(cache=False))
        except ValueError as exc:
            return _json_error(400, str(exc))
        try:
            args = web.settings_test_args(body)
        except ValueError as exc:
            return _json_error(400, str(exc))
        # BLOCKS FOR UP TO `seconds`: the result IS the observation window, and the browser shows a
        # running state while it waits. No database connection is opened here -- the probe opens one
        # per liveness read, through the same factory.
        code, payload = payloads.settings_test(ctx, _connect, **args)
        return jsonify(payload), code

    @app.post("/api/settings/sonar")
    def settings_sonar():
        from weirvern.admin import payloads, web  # noqa: PLC0415

        refused = _gate_write()
        if refused is not None:
            return refused
        try:
            body = web.json_body(request.get_data(cache=False))
        except ValueError as exc:
            return _json_error(400, str(exc))
        args = web.sonar_args(body)
        if not body.get("stream"):
            code, payload = payloads.settings_sonar(ctx, _connect, progress=lambda p: None, **args)
            return jsonify(payload), code

        # NDJSON, the same shape the console writes to its socket: one line per step, then the result.
        # THE WORK RUNS ON A THREAD so progress can be yielded WHILE the job runs -- building the whole
        # response first would make the stream a lie.
        import queue as queue_mod  # noqa: PLC0415
        import threading  # noqa: PLC0415

        def generate():
            q: queue_mod.Queue = queue_mod.Queue()
            box: dict = {}

            def work():
                try:
                    box["payload"] = payloads.settings_sonar(
                        ctx, _connect, progress=lambda p: q.put(p), **args)[1]
                except Exception as exc:  # noqa: BLE001
                    box["payload"] = {"ok": False, "error": f"the survey failed: {exc}"}
                finally:
                    q.put(None)

            threading.Thread(target=work, daemon=True).start()
            while True:
                item = q.get()
                if item is None:
                    break
                yield json.dumps({"progress": item}, default=str) + "\n"
            yield json.dumps({"result": box.get("payload")}, default=str) + "\n"

        return Response(stream_with_context(generate()),
                        content_type="application/x-ndjson; charset=utf-8")

    def _auth_headers():
        """The request's headers, with the COOKIE's session token presented as the session header.

        THE SEAM BETWEEN THE TWO CREDENTIAL CARRIERS, and it was briefly lost to a careless edit.
        The API is header-only by design and `requestauth` must stay cookie-free, but the rendered UI
        carries the same registry token in a signed cookie. Rather than teach the shared code about
        cookies, the cookie's token is presented in the header shape it already understands.

        Without this, a person signed in through the rendered form is told to sign in by the very
        next API request.
        """
        from flask import request as _rq

        from weirvern.admin.gui_auth import SESSION_HEADER  # noqa: PLC0415

        headers = dict(_rq.headers)
        token = session.get("token") if app.secret_key else None
        if token and not headers.get(SESSION_HEADER):
            headers[SESSION_HEADER] = token
        return headers

    # ── the proposals API, so a remote agent can ask ────────────────────────────────────────────
    #
    # `fathom` runs on an analyst's machine and Weirvern runs on the box, so HTTP is the correct
    # boundary here rather than a compromise. What matters is that the ENDPOINT and the form call the
    # same `proposals` functions: one reader of the table, one idea of what a status means.
    #
    # A proposal is a WRITE (it changes a record) that enforces nothing, so it takes the write gate.
    @app.get("/api/proposals")
    def api_proposals():
        from weirvern import proposals  # noqa: PLC0415
        from weirvern.admin.web import read_failure  # noqa: PLC0415

        ok, refusal = requestauth.read_refusal(ctx, _auth_headers())
        if not ok:
            code, message = refusal if refusal is not None else (401, "sign in to view this")
            return _json_error(code, message)
        status = request.args.get("status") or None
        try:
            with ctx.connect_factory(ctx.settings) as client:
                rows = proposals.load_proposals(client, status=status)
        except proposals.ProposalError as exc:
            return _json_error(400, str(exc))
        except Exception as exc:  # noqa: BLE001
            return _json_error(503, read_failure(exc))
        return jsonify({"available": True, "proposals": rows, "total": len(rows)})

    @app.post("/api/proposals")
    def api_proposals_post():
        from weirvern import proposals  # noqa: PLC0415
        from weirvern.admin.web import read_failure  # noqa: PLC0415

        ok, refusal = requestauth.write_refusal(ctx, _auth_headers(),
                                                addr=request.remote_addr or "")
        if not ok:
            code, message = refusal if refusal is not None else (403, "write access is required")
            return _json_error(code, message)
        body = request.get_json(silent=True) or {}
        if not isinstance(body, dict):
            return _json_error(400, "the body must be a JSON object")
        # WHO ASKED IS RECORDED, AND A SESSION WINS. An account cannot be impersonated by a body
        # field, so a signed-in caller's name is taken from the session; a token caller has no
        # account, and there `proposed_by` is the caller's own label for the automation.
        ident = requestauth.identity(ctx, _auth_headers())
        actor = f"account:{ident.username}" if ident else str(
            body.get("proposed_by") or "agent:unknown")
        try:
            with ctx.connect_factory(ctx.settings) as client:
                created = proposals.create_proposal(
                    client, dict(body, proposed_by=actor))
        except proposals.ProposalError as exc:
            return _json_error(400, str(exc))
        except Exception as exc:  # noqa: BLE001
            return _json_error(503, read_failure(exc))
        return jsonify({"ok": True, "proposal": created}), 201

    # ── the block proposal form ─────────────────────────────────────────────────────────────────
    #
    # THE SAFETY SPLIT LIVES HERE. Proposing writes a row and changes no enforcement. Applying is a
    # separate POST that a signed-in person drives, and it creates the rule through the same
    # `sluice_store.create_rule` any other rule uses, so a proposal cannot bypass a validation that a
    # manual rule would hit.
    def _proposals_client():
        return ctx.connect_factory(ctx.settings)

    @app.get("/block")
    @user_required
    def block():
        from weirvern import proposals  # noqa: PLC0415

        error = ""
        pending, decided = [], []
        try:
            with _proposals_client() as client:
                pending = proposals.load_proposals(client, status=proposals.STATUS_PROPOSED)
                decided = proposals.load_proposals(client, status=proposals.STATUS_APPLIED)
                decided += proposals.load_proposals(client, status=proposals.STATUS_DISMISSED)
        except Exception as exc:  # noqa: BLE001
            # A failed read says so. An empty queue must not be what a dead database looks like.
            from weirvern.admin.web import read_failure  # noqa: PLC0415

            error = read_failure(exc)
        return _render("block.html", error=error, pending=pending, decided=decided[:25],
                       message="", form=None)

    @app.post("/block")
    @user_required
    def block_post():
        from weirvern import proposals  # noqa: PLC0415
        from weirvern.admin.web import read_failure  # noqa: PLC0415

        if not _csrf_ok():
            return _render("block.html", error="that form did not come from this page",
                           pending=[], decided=[], message="", form=None), 400
        ident = _signed_in()
        form = {
            "host": request.form.get("host", ""),
            "reason": request.form.get("reason", ""),
            "evidence": request.form.get("evidence", ""),
            "ttl_minutes": request.form.get("ttl_minutes", "0"),
        }
        actor = f"account:{ident.username}" if ident else "unknown"
        try:
            with _proposals_client() as client:
                proposals.create_proposal(client, dict(form, proposed_by=actor))
        except proposals.ProposalError as exc:
            # A refusal is the useful answer, and it goes back to the form with the words typed
            # still in it so the operator can fix it rather than retype it.
            return _render("block.html", error=str(exc), pending=[], decided=[], message="",
                           form=form), 400
        except Exception as exc:  # noqa: BLE001
            return _render("block.html", error=read_failure(exc), pending=[], decided=[],
                           message="", form=form), 503
        return redirect(url_for("block"))

    @app.post("/block/<proposal_id>/apply")
    @user_required
    def apply_proposal(proposal_id: str):
        from weirvern import proposals  # noqa: PLC0415

        if not _csrf_ok():
            return _render("block.html", error="that form did not come from this page",
                           pending=[], decided=[], message="", form=None), 400
        ident = _signed_in()
        try:
            with _proposals_client() as client:
                proposals.apply_proposal(client, proposal_id, by=ident.username)
        except proposals.ProposalError as exc:
            return _render("block.html", error=str(exc), pending=[], decided=[], message="",
                           form=None), 400
        except Exception as exc:  # noqa: BLE001
            from weirvern.admin.web import read_failure  # noqa: PLC0415

            return _render("block.html", error=read_failure(exc), pending=[], decided=[],
                           message="", form=None), 503
        return redirect(url_for("block"))

    @app.post("/block/<proposal_id>/dismiss")
    @user_required
    def dismiss_proposal(proposal_id: str):
        from weirvern import proposals  # noqa: PLC0415

        if not _csrf_ok():
            return _render("block.html", error="that form did not come from this page",
                           pending=[], decided=[], message="", form=None), 400
        ident = _signed_in()
        try:
            with _proposals_client() as client:
                proposals.dismiss_proposal(client, proposal_id, by=ident.username)
        except proposals.ProposalError as exc:
            return _render("block.html", error=str(exc), pending=[], decided=[], message="",
                           form=None), 400
        return redirect(url_for("block"))

    # ── the console, served unchanged ───────────────────────────────────────────────────────────
    def _static_view(name: str, ctype: str):
        def view():
            target = root / name
            try:
                body = target.read_bytes()
            except OSError:
                # A missing asset is a packaging bug, and saying so beats an empty 200 that reads
                # like a rendering failure. Same sentence as the console's own.
                return _json_error(
                    500,
                    f"GUI asset {name!r} is missing from the package (expected at {target}). "
                    f"A non-editable install needs weirvern/admin/web in package-data.",
                )
            return Response(body, mimetype=ctype)

        view.__name__ = f"static_{name.replace('.', '_').replace('-', '_')}"
        return view

    for path, (name, ctype) in STATIC_FILES.items():
        app.add_url_rule(path, endpoint=f"static::{path}", view_func=_static_view(name, ctype))

    def _passthrough():
        """Forward this request to the legacy server and return its response verbatim.

        THE HEADERS COME BACK AS-IS, deliberately: the console sets its own security headers and its
        own content types, and a proxy that rewrote them would be a second opinion about them. The body
        is returned unmodified for the same reason -- re-serialising JSON would risk changing what a
        client sees, which is the drift this whole exercise exists to avoid.
        """
        import urllib.error  # noqa: PLC0415
        import urllib.request  # noqa: PLC0415

        target = proxy_to.rstrip("/") + request.full_path.rstrip("?")
        body = request.get_data() or None
        forwarded = {k: v for k, v in request.headers.items()
                     if k.lower() not in ("host", "content-length", "connection")}
        req = urllib.request.Request(target, data=body, headers=forwarded, method=request.method)
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return Response(resp.read(), status=resp.status,
                                headers={k: v for k, v in resp.headers.items()
                                         if k.lower() not in ("transfer-encoding", "connection",
                                                              "content-length")})
        except urllib.error.HTTPError as exc:
            # A refusal from the console is a real answer, not a proxy failure. Pass it through so a
            # 401 from the old handler still reads as a 401 to the browser.
            return Response(exc.read(), status=exc.code,
                            headers={k: v for k, v in exc.headers.items()
                                     if k.lower() not in ("transfer-encoding", "connection",
                                                          "content-length")})
        except Exception as exc:  # noqa: BLE001
            logger.warning("passthrough to %s failed: %s", target, exc)
            return _json_error(502, f"the console backend did not answer: {type(exc).__name__}")

    @app.errorhandler(404)
    def not_found(_exc):
        # WITH A PASSTHROUGH CONFIGURED, an unrouted path is not a 404 -- it is a route this app has
        # not taken over yet, and the legacy server still serves it.
        if proxy_to:
            return _passthrough()
        # Without one, the console is a hash-router app: every view lives at "/" and the fragment
        # never reaches the server, so an unknown path serves the shell -- but an unknown API path
        # must still 404, or a typo'd endpoint would answer HTML.
        if request.path.startswith("/api/"):
            return _json_error(404, f"no such endpoint: {request.path}")
        return _static_view(*STATIC_FILES["/"])()

    return app
