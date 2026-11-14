"""A Flask front door over the SAME payload layer the console uses.

WHAT THIS IS. The console's server is a hand-rolled `ThreadingHTTPServer` with manual routing, a
hand-maintained static allow-list and hand-rolled TLS. That is a real liability for future work: no
middleware, no WSGI, and every new route a small piece of bespoke plumbing. This module puts Flask in
front so routing, TLS and proxy handling come from a standard stack.

WHAT THIS IS NOT. It is not a rewrite of the console and it does not touch one line of its
JavaScript. The 900-odd checks in `scripts/jsdom_render.js` keep measuring the console exactly as
before, because the console is served unchanged. A big-bang port would have thrown that away to gain
a framework.

THE STRANGLER. Routes are migrated one at a time. A route is written here natively, against the same
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
import logging
import os
import secrets
from datetime import timedelta
from pathlib import Path
from typing import Any

from flask import Flask, Response, jsonify, redirect, render_template, request, session, url_for

from weirvern.admin import requestauth, web_api

logger = logging.getLogger(__name__)

# The templates ship inside the package (see pyproject package-data), so this is a path relative to
# the module and not a working-directory guess.
TEMPLATE_DIR = Path(__file__).parent / "templates"

# The role a self-service registration gets. NEVER taken from the submitted form: a register form
# that accepted a role would be a privilege-escalation hole, and the console's own user route has
# the same boundary.
REGISTER_ROLE_FALLBACK = "viewer"


def _truthy(raw: str | None) -> bool:
    return str(raw or "").strip().lower() in ("1", "true", "yes", "on")


def _json_error(code: int, message: str) -> tuple[Response, int]:
    """The console's own error shape, so a client cannot tell the two surfaces apart.

    Every error in the old server is `{"error": ..., "code": ...}` with a matching status, and the
    console JS relies on the STATUS (postJSON throws on non-2xx). Keeping the body identical means a
    client written against one surface reads the other without special cases.
    """
    return jsonify({"error": message, "code": code}), code


def create_app(ctx: Any, *, static_dir: Any = None,
               secret_key: str | None = None) -> Flask:
    """Build the Flask app over an assembled GuiContext.

    Takes the same `ctx` the console handler takes, so both surfaces share one connection factory,
    one settings object, one session store and one token gate. Assembling a second context would be
    a second set of credentials and a second way to disagree about them.
    """
    from weirvern.admin.web import STATIC_DIR, STATIC_FILES

    app = Flask(__name__, static_folder=None, template_folder=str(TEMPLATE_DIR))

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
    @app.get("/api/episodes")
    @gated
    def episodes():
        """One row per incident. The first route migrated, and deliberately a small one.

        It is the shape every future route here takes: parse the arguments, take one client from
        the shared factory, call the same fetcher the console calls, format with the same payload
        function, and report a failure through `read_failure` so the wording does not depend on
        which surface answered.
        """
        from weirvern.admin import status as status_mod  # noqa: PLC0415
        from weirvern.admin.web import (  # noqa: PLC0415
            _int_arg,
            read_failure,  # noqa: PLC0415
            window_arg,
        )

        query = request.args.to_dict(flat=False)
        limit = _int_arg(query, "limit", 100, 1, 1000)
        try:
            # The SAME parser the console uses (web.window_arg). It raises rather than sending, so
            # this surface turns the reason into its own 400 body and the two cannot disagree about
            # what a usable range is.
            hours = window_arg(query, 24, 1, 24 * 14)
        except ValueError as exc:
            return _json_error(400, f"bad time range: {exc}")
        try:
            with ctx.connect_factory(ctx.settings) as client:
                payload = status_mod.episodes_recent(client, hours=hours, limit=limit)
        except Exception as exc:  # noqa: BLE001
            # Worded by what was observed, not by the layer assumed to have failed (WV1-20).
            return _json_error(503, read_failure(exc))
        # The Host column is the fact (the address); the hostname is the convenience. Same cached
        # reverse-DNS path the console uses, so the two tables cannot disagree about a name.
        for row in payload.get("episodes", []):
            row["hostname"] = web_api._hostname(row.get("src_addr"))
        return jsonify(payload)

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

    @app.errorhandler(404)
    def not_found(_exc):
        # The console is a hash-router app: every view lives at "/" and the fragment never reaches
        # the server. An unknown path serves the shell, exactly as the old handler does -- but an
        # unknown API path must still 404, or a typo'd endpoint would answer HTML.
        if request.path.startswith("/api/"):
            return _json_error(404, f"no such endpoint: {request.path}")
        return _static_view(*STATIC_FILES["/"])()

    return app
