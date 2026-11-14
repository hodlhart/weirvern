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
import logging
from typing import Any

from flask import Flask, Response, jsonify, request

from weirvern.admin import requestauth, web_api

logger = logging.getLogger(__name__)


def _json_error(code: int, message: str) -> tuple[Response, int]:
    """The console's own error shape, so a client cannot tell the two surfaces apart.

    Every error in the old server is `{"error": ..., "code": ...}` with a matching status, and the
    console JS relies on the STATUS (postJSON throws on non-2xx). Keeping the body identical means a
    client written against one surface reads the other without special cases.
    """
    return jsonify({"error": message, "code": code}), code


def create_app(ctx: Any, *, static_dir: Any = None) -> Flask:
    """Build the Flask app over an assembled GuiContext.

    Takes the same `ctx` the console handler takes, so both surfaces share one connection factory,
    one settings object, one session store and one token gate. Assembling a second context would be
    a second set of credentials and a second way to disagree about them.
    """
    from weirvern.admin.web import STATIC_DIR, STATIC_FILES

    app = Flask(__name__, static_folder=None)
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

    @app.get("/api/session")
    def session():
        return jsonify(requestauth.session_payload(ctx, request))

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
