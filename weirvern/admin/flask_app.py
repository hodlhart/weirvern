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
reads, 34 POST entries) and the dashboard's own JavaScript calls 59 of them. This app serves 25 of
the reads natively. Replacing the console outright would therefore load the page and break every
endpoint not yet crossed, with each panel reporting "no such endpoint" -- a regression dressed as a
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
import logging
import os
import secrets
from datetime import timedelta
from pathlib import Path
from typing import Any

from flask import Flask, Response, jsonify, redirect, render_template, request, session, url_for

from weirvern.admin import requestauth

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


def create_app(ctx: Any, *, static_dir: Any = None, secret_key: str | None = None,
               proxy_to: str = "") -> Flask:
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
    def _payload_route(fetcher, *, needs_client=True, settings=False):
        from weirvern.admin.web import read_failure  # noqa: PLC0415

        try:
            if not needs_client:
                return jsonify(fetcher())
            with ctx.connect_factory(ctx.settings) as client:
                if settings:
                    return jsonify(fetcher(client, ctx.settings))
                return jsonify(fetcher(client))
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

        return _payload_route(payloads.models_calibration, settings=True)

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
        return _soft_route(payloads.assets, payloads.assets_failure, hours=hours)

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
