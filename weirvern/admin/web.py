"""The web GUI: an HTTP server over the status and analytics data.

WHY THE STANDARD LIBRARY, DELIBERATELY:

No new runtime dependency. FastAPI + uvicorn is roughly 15 MB in the image for
a surface this size, and this project has repeatedly been bitten by deployment
friction (a missing extra broke CI once already, and the worker image is meant to
stay small enough to pull quickly on a homelab). `http.server` is in every Python
installation, so the GUI works with no extra install step at all — which matters
more than idiom for a tool that has to be deployable by someone who has never seen
it before.

This stayed defensible as the surface grew: request bodies are bounded, routes are
explicit, and the write and account gates live in one class rather than in a
framework's middleware. If this ever grows websockets or streaming, that is the
point to move to a real framework, and `web_api.py` is already framework-agnostic
so only this file changes.

WHAT THIS SERVER IS NOW, AND WHAT IT IS NOT:

It began read-only, and that was what made binding it to a LAN address acceptable.
It now writes two things — the deployment configuration (settings) and accounts —
under a signed-in admin account or the deployment operator token, and READS require
a signed-in account (either role) whenever accounts are provisioned. There is
still no code path from an HTTP request to a LIFECYCLE operation: start, stop and
apply stay in the CLI. So the invariant worth stating is narrower and
tested: every mutating route goes through one admin gate, and the only open routes
are the liveness probe, the session probe the UI needs before it can show a login
form, and the login door itself.

WHY READS REQUIRE SIGN-IN. Flow data names hosts and services, which is the map of
a network. "A viewer may read" only means anything if reading is attributable, so
the gate exists once accounts do. When accounts are NOT provisioned (a workstation
running `weirvern gui` against a remote database, or a fresh deployment whose
bootstrap could not reach the cluster), the GUI falls back to its pre-accounts
posture — open reads, token-gated writes — because demanding a sign-in nobody can
satisfy would lock the operator out of their own dashboard.

BINDING: defaults to 127.0.0.1 so that starting the GUI on a workstation does not
unexpectedly publish it. The Kubernetes Deployment sets GUI_HOST=0.0.0.0
explicitly, where being reachable is the entire point and the Service controls who
can get to it.
"""
from __future__ import annotations

import contextlib
import datetime
import json
import logging
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from weirvern import fleet_store
from weirvern.admin import assets as assets_mod
from weirvern.admin import gui_auth, web_api
from weirvern.admin import soc as soc_mod
from weirvern.admin import status as status_mod
from weirvern.admin import users as users_mod

logger = logging.getLogger(__name__)

STATIC_DIR = Path(__file__).resolve().parent / "web"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8088

# GET routes that do not require a signed-in account, and why each is exempt:
#   /api/healthz — the Kubernetes liveness/readiness probe, which cannot present a header.
#   /api/session — how the UI learns whether it must show the sign-in gate at all. It returns
#                  the caller's own auth state and nothing else, so it discloses nothing.
# Static files stay open too: the login screen is built from them.
READ_EXEMPT = ("/api/healthz", "/api/session")

# Only these are served from web/. An explicit allow-list rather than a path join,
# because the latter is a directory-traversal bug waiting to happen (`/../etc/...`)
# and there is no reason to read arbitrary files to serve a static dashboard.
STATIC_FILES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "application/javascript; charset=utf-8"),
    # The SOC views' chart code, kept in its own file so the core dashboard bundle does not
    # grow every time a view is added. Loaded after app.js (see index.html) because it calls
    # the shared helpers -- chartFrame, svgEl, el, fmtBytes -- that app.js defines.
    "/soc.js": ("soc.js", "application/javascript; charset=utf-8"),
    # The Assets inventory and the Network connection graph. Its own file for the same reason
    # as soc.js, and because the force-free graph layout is code a reader should be able to
    # find on its own.
    "/assets.js": ("assets.js", "application/javascript; charset=utf-8"),
    # The Sluice Gate tab. Its own file for the same reason as the others, and because "what is
    # being blocked, and is the gate actually holding" is a distinct concern from what the dashboard
    # shows -- a reader looking for the blocking logic should find it in one place.
    "/sluice.js": ("sluice.js", "application/javascript; charset=utf-8"),
    # The Weirlings fleet tab. Its own file for the same reason as the others, and because
    # "which sensors are expected, and which of them are silent" is a distinct concern from both
    # the dashboard and the gate -- and because the state model it renders (five states that must
    # never be collapsed) is code a reader should be able to find in one place.
    "/weirlings.js": ("weirlings.js", "application/javascript; charset=utf-8"),
    "/style.css": ("style.css", "text/css; charset=utf-8"),
    # The logo, so the dashboard is branded rather than a generic admin page. Served
    # from the same allow-list as everything else; the image is read-only and static.
    "/logo.png": ("logo.png", "image/png"),
    # Browsers request /favicon.ico implicitly, so serving the PNG here (with the
    # right content type) avoids a 404 in the logs on every page load.
    "/favicon.ico": ("favicon.png", "image/png"),
    "/favicon.png": ("favicon.png", "image/png"),
}

# Content that must never be cached: a dashboard showing stale "all healthy" after
# a pod died is worse than one showing nothing.
NO_CACHE = "no-store, must-revalidate"


def _gate_sensor_name() -> str:
    """The sensor identity the Sluice Gate's state rows are keyed by.

    MUST MATCH THE WRITER, or the panel silently reads nothing. Rather than repeat the expression
    the worker uses -- `getattr(settings, "sensor_name", "") or socket.gethostname()` -- this calls
    the worker's own helper. A second convention here would drift: `sensor_name` is read with
    `getattr` because it is NOT a declared field on Settings, so a copy that used attribute access
    would raise on every request, and a copy that guessed a different fallback would show a
    permanently empty panel on any deployment that ever sets one.

    WHY THIS EXISTS AT ALL: the state query used to take the newest row across ALL sensors, so an
    `armed` row left behind by a harness or a CLI run outranked the worker's own, and the panel
    reported ARMED while the node's kernel held zero rules. Naming the sensor is what stops the
    operator reading another process's history.
    """
    import socket  # noqa: PLC0415

    try:
        from weirvern.config import get_settings  # noqa: PLC0415
        from weirvern.worker import _sensor_name  # noqa: PLC0415

        return _sensor_name(get_settings())
    except Exception:  # noqa: BLE001
        # A name is needed to filter a query, and failing to derive one must not fail the route.
        # The worker's own fallback is the hostname, so this still matches the writer.
        return socket.gethostname() or "sensor"


class GuiContext:
    """Everything a request handler needs, assembled once at startup.

    Holds the connection factory rather than a live client: the connection is
    opened per request and closed after, because ClickHouse connections are not
    safe to share across threads and ThreadingHTTPServer serves each request on its
    own thread. The alternative — a global client with a lock — serialises every
    request and makes one slow query block the whole UI.
    """

    def __init__(self, connect_factory, settings, backend=None, capabilities=None,
                 auth=None, config_client=None, user_store=None, sessions=None,
                 throttle=None, accounts_note=""):
        self.connect_factory = connect_factory
        self.settings = settings
        self.backend = backend
        self.capabilities = capabilities
        # The break-glass token gate: whether the deployment operator token can write,
        # and whether one is configured at all. Checked only when a request presents a
        # token; account sessions are resolved against `sessions`/`user_store` instead.
        self.auth = auth
        # The ConfigMap client, for the write path. Held rather than constructed per
        # request so a write and a dry run see the same object.
        self.config_client = config_client
        # The account store, read once at startup then served from memory, so a login
        # never puts a Kubernetes API call on the hot path.
        self.user_store = user_store
        # Sessions and the login throttle. Both in memory; see weirvern/admin/users.py
        # for why a restart signing everyone out is the right trade.
        self.sessions = sessions
        self.throttle = throttle
        # What the bootstrap did, or why it did not. Reported on /api/session so a
        # deployment with no accounts SAYS so instead of rejecting every password.
        self.accounts_note = accounts_note


def _accounts_on(ctx) -> bool:
    """Whether accounts are provisioned, i.e. whether the login gate is armed.

    A module function rather than a ctx method so it works against the duck-typed
    contexts the tests construct, and so the ONE definition is visible from every
    call site that depends on it.
    """
    store = getattr(ctx, "user_store", None)
    if store is None:
        return False
    try:
        return bool(store.has_users())
    except Exception:  # noqa: BLE001
        # A store that cannot answer is not provisioned: the gate stays off and the
        # pre-accounts posture applies (open reads, token-gated writes) rather than a
        # broken store locking everyone out of the dashboard.
        return False


def _build_handler(ctx: GuiContext):
    """Create the request handler class, closing over ctx."""

    class Handler(BaseHTTPRequestHandler):
        server_version = "Weirvern"
        # Suppress the default per-request stderr line: on a busy dashboard it
        # buries real errors, and the access log is reimplemented below.
        sys_version = ""

        def log_message(self, fmt: str, *args) -> None:  # noqa: A003
            logger.debug("%s - %s", self.address_string(), fmt % args)

        # -- helpers -------------------------------------------------------
        def _send(self, code: int, body: bytes, content_type: str) -> None:
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", NO_CACHE)
            # The dashboard is same-origin only; denying framing and sniffing is
            # free and removes a class of browser-side abuse.
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _json(self, payload, code: int = 200) -> None:
            body = json.dumps(payload, default=str).encode()
            self._send(code, body, "application/json; charset=utf-8")

        def _error(self, code: int, message: str) -> None:
            self._json({"error": message, "code": code}, code)

        # -- routing -------------------------------------------------------
        def do_GET(self) -> None:  # noqa: N802
            try:
                self._route()
            except BrokenPipeError:
                # The browser navigated away mid-response. Common and harmless.
                pass
            except Exception as exc:  # noqa: BLE001
                logger.warning("GUI request failed for %s: %s", self.path, exc)
                # The response may already be partly written, in which case
                # sending a 500 would corrupt it. Failing to report the error is
                # acceptable here; the log line above is the primary signal.
                with contextlib.suppress(Exception):
                    self._error(500, f"internal error: {exc}")

        def do_HEAD(self) -> None:  # noqa: N802
            self.do_GET()

        def _route(self) -> None:
            parsed = urlparse(self.path)
            path = parsed.path.rstrip("/") or "/"
            query = parse_qs(parsed.query)

            if path in STATIC_FILES or path == "/":
                return self._static(parsed.path)
            # THE READ GATE. Static files stay open (the sign-in screen is built from them and
            # they carry no data), and so do two API routes: the liveness probe, which cannot
            # present a header, and the session probe, which is how the UI learns that a gate
            # is needed at all. Every other API route requires a signed-in account -- or the
            # break-glass token -- once accounts are provisioned. When they are NOT provisioned
            # the gate passes everything, which is the pre-accounts posture: a workstation
            # running `weirvern gui` has no store to sign in against, and locking its operator
            # out of their own dashboard would be a bug, not a policy.
            if path not in READ_EXEMPT and not self._require_read():
                return
            if path == "/api/overview":
                return self._overview()
            if path == "/api/anomalies":
                return self._anomalies(query)
            # Who the caller is, and whether the sign-in gate is armed. Exempt above; returns
            # the CALLER'S OWN state and nothing about anyone else.
            if path == "/api/session":
                return self._session()
            # Account management. A read route by method, but admin-only by content: the user
            # list is account data, not monitoring data.
            if path == "/api/users":
                return self._users_list()
            if path == "/api/host":
                return self._host(query)
            if path == "/api/evidence":
                return self._evidence(query)
            if path == "/api/fingerprints":
                return self._fingerprints(query)
            if path == "/api/models":
                return self._models(query)
            # The operator's FORCED RETRAIN: the state of the last request and the report it
            # produced. The write that files one is on the POST side, admin-gated like every other
            # mutation -- but this GET is a read of the fleet's own record, so it stays open to
            # viewers like the rest of the monitoring data.
            if path == "/api/models/retrain":
                return self._model_retrain()
            if path == "/api/netflow":
                return self._netflow(query)
            if path == "/api/zeek":
                return self._zeek(query)
            # Click-through from the Netflow charts: the hosts behind one port or one protocol.
            if path == "/api/flows":
                return self._flows(query)
            # The asset inventory and the connection graph. Separate endpoints from /api/host
            # because /api/host answers "tell me about THIS address" while these answer "what
            # hosts exist" and "how are they wired" -- and the graph needs different tables
            # (raw `flows` for per-edge facts, which the aggregate cannot provide).
            if path == "/api/assets":
                return self._assets(query)
            if path == "/api/graph":
                return self._graph(query)
            if path == "/api/zeeklog":
                return self._zeeklog(query)
            # PASSIVE HOST IDENTIFICATION: what each host IS, from traffic already seen.
            if path == "/api/identity":
                return self._host_identity()
            # ── SLUICE GATE ─────────────────────────────────────────────────────────────────
            # GET reads (the tab's payload and a cheap state poll). The writes are POST below and
            # pass the operator gate like every other mutation, so a viewer cannot block a host.
            # Reads stay open: looking at what is blocked never requires a password.
            if path == "/api/sluice":
                return self._sluice()
            if path == "/api/sluice/state":
                return self._sluice_state()
            # ── WEIRLINGS (the fleet) ───────────────────────────────────────────────────────
            # GET reads the fleet. Reads stay open like every other tab: an operator checking
            # whether a sensor is reporting should not need a password. The writes are POST
            # below and pass the operator gate, so a viewer cannot register or retire a sensor.
            if path == "/api/weirlings":
                return self._weirlings(query)
            if path == "/api/weirlings/detail":
                return self._weirlings_detail(query)
            # The DEEP health view. Distinct from /api/healthz on purpose: that one is the
            # Kubernetes liveness probe and must NOT read ClickHouse (a slow database would
            # restart the GUI and hide the real problem); this one exists precisely to answer
            # "is data still arriving", which requires reading it.
            if path == "/api/health":
                return self._health(query)
            # The EFFECTIVE configuration, read-only. See _settings for why it cannot write.
            if path == "/api/settings":
                return self._settings(query)
            if path == "/api/healthz":
                # Liveness for the Kubernetes probe. Deliberately does NOT touch
                # ClickHouse: a probe that fails when the database is slow would
                # restart the GUI and hide the real problem.
                return self._json({"ok": True})
            self._error(404, f"no route for {path}")

        # -- static --------------------------------------------------------
        def _static(self, raw_path: str) -> None:
            name, ctype = STATIC_FILES.get(raw_path, STATIC_FILES["/"])
            target = STATIC_DIR / name
            try:
                body = target.read_bytes()
            except OSError:
                # A missing asset is a packaging bug, and saying so is better than
                # serving an empty 200 that looks like a rendering failure.
                return self._error(
                    500,
                    f"GUI asset {name!r} is missing from the package "
                    f"(expected at {target}). A non-editable install needs "
                    f"weirvern/admin/web in package-data.",
                )
            self._send(200, body, ctype)

        # -- api -----------------------------------------------------------
        def _with_client(self):
            """Connect, returning a context manager yielding a client."""
            return ctx.connect_factory(ctx.settings)

        def _overview(self) -> None:
            services = []
            if ctx.backend is not None:
                try:
                    services = ctx.backend.ps()
                except Exception as exc:  # noqa: BLE001
                    logger.debug("backend.ps failed: %s", exc)

            report = None
            anomalies: list = []
            talkers: list = []
            sensor: dict = {}
            data_error = None
            try:
                with self._with_client() as client:
                    report = status_mod.collect_health(
                        client, ctx.settings,
                        user_store=getattr(ctx, "user_store", None),
                    )
                    anomalies = status_mod.anomalies_detailed(client, limit=25)
                    talkers = status_mod.top_talkers(client, limit=10)
                    # What the sensor reports about itself. Separate from the health
                    # checks above, which answer "is data flowing", not "what is the
                    # sensor doing" -- and for siphon that distinction is the whole point:
                    # a dead intercept still has its mode in the ConfigMap.
                    sensor = status_mod.sensor_status(client)
            except Exception as exc:  # noqa: BLE001
                # WARNING, not debug, and surfaced in the payload. This was debug
                # originally, and the effect was a page that rendered every panel
                # empty with no explanation anywhere -- the in-cluster pod was
                # trying to shell out to kubectl for a tunnel it did not need, and
                # nothing in the UI or the logs said so.
                data_error = str(exc)[:300]
                logger.warning("overview data unavailable: %s", exc)

            payload = web_api.overview_payload(
                services, report, anomalies, talkers, ctx.capabilities, sensor=sensor)
            payload["data_error"] = data_error
            self._json(payload)

        def _anomalies(self, query: dict) -> None:
            limit = _int_arg(query, "limit", 100, 1, 1000)
            min_score = _float_arg(query, "min_score", 0.0, 0.0, 1.0)
            unreviewed_only = (_query_bool(query, "unreviewed") is True)
            try:
                with self._with_client() as client:
                    rows = status_mod.anomalies_detailed(
                        client, limit=limit, min_score=min_score)
                    # SOC-1: merge review state. Read separately (one small query) rather
                    # than joined in SQL because the reviews table may not exist yet on a
                    # deployment whose schema job has not re-run -- a join would make the
                    # WHOLE anomalies view fail, where this degrades to per-row
                    # "review state unavailable" chips while the alerts still render.
                    idx, rev_err, covered_since = status_mod.review_index(client)
                    # covered_since is the index's OWN lower bound, so a row older than the
                    # review window is marked unknowable rather than reading as "unreviewed".
                    # Without it, an analyst re-triages an alert that was already dispositioned.
                    status_mod.attach_reviews(rows, idx, rev_err, covered_since)
                    # THE FILTER IS SKIPPED WHEN THE REVIEWS ARE UNREADABLE. Filtering on a
                    # state we could not read would answer "nothing is unreviewed" -- a
                    # confident claim built from a failed query. Better to return the rows
                    # unfiltered, carrying the unavailable marker, and let the UI say why.
                    if unreviewed_only and rev_err is None:
                        rows = [r for r in rows if r.get("review_state") == ""]
            except Exception as exc:  # noqa: BLE001
                return self._error(503, f"cannot reach ClickHouse: {exc}")
            self._json(web_api.anomalies_payload(rows))

        def _models(self, query: dict) -> None:
            """Model overview: training history, score spread, agreement, deviations.

            Returns 200 with {"available": false, "reason": ...} when the data cannot be
            read, rather than 503. A missing panel should say why it is missing; an
            error page for one panel would take down the views around it.
            """
            hours = _int_arg(query, "hours", 72, 1, 24 * 30)
            try:
                with self._with_client() as client:
                    data = status_mod.model_overview(client, hours=hours, settings=ctx.settings)
            except Exception as exc:  # noqa: BLE001
                return self._json({"available": False,
                                   "reason": f"cannot reach ClickHouse: {exc}"})
            self._json(web_api.models_payload(data))

        def _model_retrain(self) -> None:
            """The last forced retrain: what state it is in, and what it produced.

            A FAILED read is a 200 with `available: false` and the reason, like every other panel:
            an error page for one card would take down the views around it, and an empty report
            would read as "nothing has been trained".
            """
            from weirvern.models import actions  # noqa: PLC0415

            try:
                with self._with_client() as client:
                    row = actions.latest(client, actions.RETRAIN)
                    decision = (actions.latest(client, actions.KEEP)
                                or actions.latest(client, actions.TRASH))
            except Exception as exc:  # noqa: BLE001
                return self._json(web_api.retrain_payload(
                    None, None, available=False, reason=f"cannot reach ClickHouse: {exc}"))
            self._json(web_api.retrain_payload(row, decision))

        def _model_retrain_write(self) -> None:
            """File a retrain, or judge the candidate it produced.

            Body: {"action": "retrain"|"keep"|"trash", "note": "...", "target_id": "..."} -- or the
            action in the URL. The request is a ROW in ClickHouse because the worker (which owns the
            model artifacts) is a different pod; this handler only files it and says what it filed.
            The response is explicit about that: nothing has happened yet when it returns 200.
            """
            if not self._authorize():
                return
            from weirvern.models import actions  # noqa: PLC0415

            try:
                body = self._read_body()
            except ValueError as exc:
                return self._error(400, str(exc))

            action = str(body.get("action") or "").strip().lower()
            if not action:
                # The action may ride in the URL (`/api/models/retrain/keep`), which is the shape a
                # reader would guess from the route table.
                tail = str(getattr(self, "path", "")).split("?")[0].rsplit("/", 1)[-1]
                action = tail if tail in (actions.RETRAIN, actions.KEEP, actions.TRASH) else ""
            if action not in (actions.RETRAIN, actions.KEEP, actions.TRASH):
                return self._error(400, "action must be retrain, keep or trash")

            ident = self._identity()
            by = ident.username if ident else "operator"
            try:
                with self._with_client() as client:
                    if action == actions.RETRAIN:
                        action_id = actions.request(client, action=actions.RETRAIN, by=by,
                                                    note=str(body.get("note") or "").strip())
                        note = ("filed; the worker builds a candidate on its next cycle and "
                                "NOTHING live changes until you keep it")
                    else:
                        target = str(body.get("target_id") or "").strip()
                        if not target:
                            latest = actions.latest(client, actions.RETRAIN) or {}
                            target = str(latest.get("action_id") or "")
                        if not target:
                            return self._error(400, "there is no retrain to judge yet")
                        action_id = actions.request(client, action=action, by=by, target_id=target,
                                                    note="")
                        note = ("filed; the worker applies it on its next cycle"
                                if action == actions.KEEP
                                else "filed; the worker discards the candidate on its next cycle")
            except Exception as exc:  # noqa: BLE001
                logger.warning("model action failed: %s", exc)
                return self._error(502, f"could not record the request: {type(exc).__name__}")
            self._json({"ok": True, "action": action, "action_id": action_id, "note": note})

        def _netflow(self, query: dict) -> None:
            """Netflow shape: volume trend, protocols, ports, fan-out, talkers.

            Every sub-query returns {"available", "reason"} rather than a bare list, and a
            failure in one does NOT take the others down -- a chart that cannot be drawn
            says so in place, while the charts beside it still render. Returns 200 even
            when ClickHouse is unreachable, for the same reason `_models` does: an error
            page for one panel would blank the views around it.
            """
            hours = _int_arg(query, "hours", 24, 1, 24 * 14)
            empty = {"available": False, "reason": "cannot reach ClickHouse", "points": []}
            try:
                with self._with_client() as client:
                    volume = soc_mod.flow_volume_series(client, hours=hours)
                    proto = soc_mod.protocol_mix(client, hours=hours)
                    ports = soc_mod.top_ports(client, hours=hours)
                    spread = soc_mod.destination_spread(client, hours=hours)
                    talkers = status_mod.top_talkers(client, hours=hours, limit=12)
                    # The host lists are filtered; this says by how much, so a reader can tell
                    # "a quiet segment" from "a noisy one with the noise hidden".
                    noise = status_mod.noise_flows(client, hours=hours)
            except Exception as exc:  # noqa: BLE001
                logger.warning("netflow view unavailable: %s", exc)
                return self._json({"volume": empty, "protocols": empty, "ports": empty,
                                   "spread": empty, "talkers": [], "noise": {},
                                   "data_error": f"cannot reach ClickHouse: {exc}"})
            self._json(web_api.netflow_payload(volume, proto, ports, spread, talkers,
                                              noise=noise))

        def _zeek(self, query: dict) -> None:
            """Zeek shape: per-log counts, protocol timeline, services, DNS names.

            The counts helper reports a table it could not count SEPARATELY from a table
            with no rows, because those are different facts and conflating them is how an
            empty panel comes to look like a quiet network.
            """
            hours = _int_arg(query, "hours", 24, 1, 24 * 14)
            empty = {"available": False, "reason": "cannot reach ClickHouse", "points": []}
            try:
                with self._with_client() as client:
                    counts = soc_mod.zeek_counts(client, hours=hours)
                    timeline = soc_mod.zeek_timeline(client, hours=hours)
                    services = soc_mod.zeek_services(client, hours=hours)
                    dns = soc_mod.zeek_dns_names(client, hours=hours)
            except Exception as exc:  # noqa: BLE001
                logger.warning("zeek view unavailable: %s", exc)
                return self._json({"counts": empty, "timeline": empty, "services": empty,
                                   "dns": empty,
                                   "data_error": f"cannot reach ClickHouse: {exc}"})
            self._json(web_api.zeek_payload(counts, timeline, services, dns))

        def _flows(self, query: dict) -> None:
            """The hosts behind one destination port or one IP protocol.

            `port` and `proto` are both optional but ONE is required -- the query refuses an
            unfiltered request, because "every flow" is not a drill-down and would make a chart
            click into a slow full-table scan.
            """
            hours = _int_arg(query, "hours", 24, 1, 24 * 14)
            # -1 means "not supplied". Declared as Optional because the sentinel is replaced by
            # None before use, and leaving the variable typed `int` while assigning None is the
            # mismatch mypy flags.
            port_raw = _int_arg(query, "port", -1, -1, 65535)
            proto_raw = _int_arg(query, "proto", -1, -1, 255)
            port: int | None = port_raw if port_raw >= 0 else None
            proto: int | None = proto_raw if proto_raw >= 0 else None
            if port is None and proto is None:
                return self._error(400, "port or proto is required, e.g. /api/flows?port=443")
            try:
                with self._with_client() as client:
                    payload = soc_mod.flows_matching(client, port=port, proto=proto, hours=hours)
            except Exception as exc:  # noqa: BLE001
                logger.warning("flow drill-down unavailable: %s", exc)
                return self._json({
                    "available": False, "points": [],
                    "reason": f"cannot reach ClickHouse: {type(exc).__name__}",
                    "data_error": str(exc),
                })
            self._json(payload)

        def _health(self, query: dict) -> None:
            """DEEP health: the checks, ingestion trend, table sizes, and the sensor.

            NOT the liveness probe. /api/healthz answers {"ok": true} without touching the
            database so that a slow database cannot restart the GUI; this one reads it,
            because "is data still arriving" cannot be answered otherwise. The two are
            different questions and this endpoint is the second.
            """
            hours = _int_arg(query, "hours", 24, 1, 24 * 14)
            empty = {"available": False, "reason": "cannot reach ClickHouse", "points": []}
            report = None
            sensor: dict = {}
            ingest, sizes = empty, empty
            audit: dict = {"available": False, "reason": "cannot reach ClickHouse",
                           "by_reason": [], "recent": [], "suppressed": 0,
                           "total": 0, "truncated": False, "names": {}}
            try:
                with self._with_client() as client:
                    report = status_mod.collect_health(
                        client, ctx.settings,
                        user_store=getattr(ctx, "user_store", None),
                    )
                    sensor = status_mod.sensor_status(client)
                    ingest = soc_mod.ingestion_series(client, hours=hours)
                    sizes = soc_mod.table_sizes(client)
                    # SOC-8: the alert audit rides on the health payload -- it is the same
                    # question ("is the system doing what it should") and it does not
                    # deserve a route of its own that nobody would look at.
                    audit = soc_mod.alert_audit(client, hours=hours)
            except Exception as exc:  # noqa: BLE001
                logger.warning("health view unavailable: %s", exc)
                return self._json({"health": None, "ingest": empty, "tables": empty,
                                   "sensor": {}, "alerts": audit,
                                   "data_error": f"cannot reach ClickHouse: {exc}"})
            self._json(web_api.health_deep_payload(report, ingest, sizes, sensor, audit))

        def _assets(self, query: dict) -> None:
            """The asset inventory: every host seen, with a per-host summary.

            Read-only and dependency-free like every other route. `hours` bounds the TRAFFIC
            columns only -- a host whose last packet was days ago is still an asset, so it
            appears with zeroed counters rather than being dropped, and the payload reports
            which sources were readable so the panel can explain the zeros.
            """
            hours = _int_arg(query, "hours", 24, 1, 24 * 14)
            try:
                with self._with_client() as client:
                    payload = assets_mod.asset_inventory(client, hours=hours)
            except Exception as exc:  # noqa: BLE001
                logger.warning("asset inventory unavailable: %s", exc)
                return self._json({
                    "available": False, "hosts": [],
                    "reason": f"cannot reach ClickHouse: {type(exc).__name__}",
                    "data_error": str(exc),
                })
            self._json(payload)

        def _graph(self, query: dict) -> None:
            """The connection graph: nodes and edges, optionally restricted to tracked hosts.

            `host` may be repeated to track a chosen set -- `?host=A&host=B`. An EMPTY
            selection means "no restriction" and returns the whole graph, which is what an
            operator expects from a cleared multi-select; the payload says which reading
            applied so a blank graph is never ambiguous.

            The host list is validated the same way /api/host validates an address, and the
            set is capped: an unbounded IN list is a way to make the database do arbitrary
            work from an HTTP request.
            """
            hours = _int_arg(query, "hours", 24, 1, 24 * 14)
            tracked = [h.strip() for h in (query.get("host") or []) if h.strip()]
            for addr in tracked:
                if len(addr) > 64 or not all(c.isalnum() or c in ".:-_" for c in addr):
                    return self._error(400, f"host does not look like an address: {addr!r}")
            if len(tracked) > 64:
                return self._error(400, "too many hosts to track (limit 64)")
            try:
                with self._with_client() as client:
                    if tracked:
                        payload = assets_mod.top_edges_for(client, tracked, hours=hours)
                        # top_edges_for answers "which edges touch these hosts"; the graph view
                        # also wants the node set even when an edge is missing, so the
                        # selection is echoed back for the UI to draw as selected.
                        payload.setdefault("tracked", tracked)
                    else:
                        payload = assets_mod.connection_graph(client, hours=hours)
            except Exception as exc:  # noqa: BLE001
                logger.warning("graph unavailable: %s", exc)
                return self._json({
                    "available": False, "nodes": [], "edges": [],
                    "reason": f"cannot reach ClickHouse: {type(exc).__name__}",
                    "data_error": str(exc),
                })
            self._json(payload)

        def _host_identity(self) -> None:
            """What each host IS, from traffic the sensor already saw. Nothing is sent.

            Named `_host_identity` and NOT `_identity` deliberately: `_identity()` on this class
            already means "who is the CALLER", and it is what the auth path reads. A same-named
            method would shadow it and break sign-in -- a collision mypy caught while the tests
            were still green.

            The shape follows every sibling route: connect, delegate the query to the read layer,
            and report a failure as `available: False` with a reason rather than as an empty list.
            An empty list is a legitimate answer -- "no host identified yet" -- and the two states
            must not look alike on screen.
            """
            try:
                with self._with_client() as client:
                    payload = status_mod.host_identity_view(client)
            except Exception as exc:  # noqa: BLE001
                logger.warning("host identity unavailable: %s", exc)
                return self._json({
                    "available": False, "hosts": [], "count": 0, "coverage": None,
                    "reason": f"cannot reach ClickHouse: {type(exc).__name__}",
                })
            self._json(payload)

        def _sluice(self) -> None:
            """Every rule -- live AND lapsed -- plus the gate's own state.

            Both sets, deliberately: "this rule exists but is not enforced" is a different statement
            from "this rule does not exist", and a view showing only live rules would make a lapsed
            block look DELETED, which is exactly the question an operator asks after a block stops
            working.
            """
            payload: dict = {
                "available": False, "reason": "", "rules": [], "live": 0, "gate": {},
                "policies": {}, "criticality": "", "enabled": False, "iface": "",
            }
            # The policies are STATIC, so they are populated even when the database is unreachable:
            # an operator can read what each level does, and the GUI can render the choice, without
            # a working cluster.
            try:
                from weirvern.sluice import CRITICALITY_POLICIES  # noqa: PLC0415
                payload["policies"] = {
                    k: {"label": v["label"], "description": v["description"],
                        "ttl_minutes": v["ttl_minutes"], "min_severity": v["min_severity"],
                        "min_confidence": v["min_confidence"]}
                    for k, v in CRITICALITY_POLICIES.items()
                }
            except Exception:  # noqa: BLE001
                pass
            try:
                payload["criticality"] = str(ctx.settings.sluice_criticality)
                payload["enabled"] = bool(ctx.settings.sluice_enabled)
                payload["iface"] = str(ctx.settings.sluice_iface or ctx.settings.zeek_iface or "")
            except Exception:  # noqa: BLE001
                pass

            try:
                from weirvern import sluice_store  # noqa: PLC0415
                with self._with_client() as client:
                    rules = sluice_store.load_all_rules(client)
                    gate = sluice_store.load_gate_state(client, sensor=_gate_sensor_name())
                    # ONE RULE STORE, MANY GATES: every box that can enforce reports its own row,
                    # and the operator sees who is actually filtering (and who has stopped).
                    fleet_gates = sluice_store.load_gate_states(client)
            except Exception as exc:  # noqa: BLE001
                logger.warning("sluice view unavailable: %s", exc)
                return self._json({
                    **payload, "available": False,
                    "reason": f"cannot read the gate: {type(exc).__name__}",
                })

            import datetime as _dt  # noqa: PLC0415

            now = _dt.datetime.now(_dt.UTC)
            rows = []
            for r in rules:
                exp = r.expires_at
                if exp is not None and exp.tzinfo is None:
                    # ClickHouse can hand back naive values; comparing one to an aware `now` RAISES,
                    # and the row would then render as neither live nor lapsed.
                    exp = exp.replace(tzinfo=_dt.UTC)
                rows.append({
                    "rule_id": r.rule_id, "describes": r.describes(),
                    "src_cidr": r.src_cidr, "dst_cidr": r.dst_cidr, "protocol": r.protocol,
                    "dst_port": r.dst_port, "direction": r.direction, "reason": r.reason,
                    "origin": r.origin, "severity": r.severity, "created_by": r.created_by,
                    "origin_ref": r.origin_ref, "live": r.is_live(now),
                    "revoked": r.revoked_at is not None,
                    "expires_at": exp.isoformat() if exp else "",
                    # SECONDS, not a timestamp: the GUI should not do clock arithmetic against a
                    # server it may not share a timezone with, and a NEGATIVE value is a meaningful
                    # answer ("lapsed N seconds ago") rather than an error.
                    "expires_in_s": int((exp - now).total_seconds()) if exp else None,
                })
            # A GATE THAT STOPPED IS ITS OWN STATE, not an absent one. Four missed intervals is
            # the threshold: the cadence is minutes, and one slow cycle is not news.
            stale_after = max(180, 4 * int(ctx.settings.sluice_interval_s))
            payload.update({
                "available": True, "rules": rows,
                "live": sum(1 for r in rows if r["live"]), "gate": gate,
                **web_api.gates_payload(fleet_gates, _gate_sensor_name(), stale_after, now),
            })
            self._json(payload)

        def _sluice_state(self) -> None:
            """Just the gate's state, for a cheap poll on a short interval."""
            try:
                from weirvern import sluice_store  # noqa: PLC0415
                with self._with_client() as client:
                    state = sluice_store.load_gate_state(client, sensor=_gate_sensor_name())
            except Exception as exc:  # noqa: BLE001
                return self._json({"available": False,
                                   "reason": f"cannot read the gate: {type(exc).__name__}"})
            self._json(state)

        def _weirlings(self, query: dict) -> None:
            """The fleet: registrations compared against heartbeats.

            ONE PAYLOAD CARRIES BOTH THE ROWS AND THE AVAILABILITY, because the two facts this
            view must never merge -- "you have no sensors" and "the registry could not be read"
            -- are indistinguishable by the time a renderer sees a bare list.
            """
            include_problems = (_query_bool(query, "problems") is True)
            include_revoked = (_query_bool(query, "revoked") is True)
            try:
                with self._with_client() as client:
                    payload = fleet_store.build_fleet(client, problems_only=include_problems)
            except Exception as exc:  # noqa: BLE001
                # A connection failure is the same fact as an unreadable registry from the
                # operator's side, so it takes the same shape rather than a 5xx that would
                # blank the whole tab.
                logger.warning("weirlings unavailable: %s", exc)
                self._json({
                    "available": False,
                    "reason": f"the fleet could not be read: {str(exc)[:200]}",
                    "sensors": [], "summary": None,
                    "heartbeats_available": False, "heartbeat_reason": None,
                })
                return

            # WHICH OF THESE SENSORS RUNS ON THIS HUB. A sensor's runtime can only be changed on
            # the box that runs it -- the hub cannot reach a remote one -- so the fleet payload
            # marks the row whose id is this deployment's own sensor (read through the same
            # helper the Sluice gate uses, so the two cannot drift). The Weirlings drill-down
            # mounts the sensor settings on exactly that row, and says where the settings live
            # for every other one.
            local_name = _gate_sensor_name()
            payload["local_sensor"] = local_name
            for row in payload.get("sensors") or []:
                row["local"] = (row.get("sensor_id") == local_name)

            if include_revoked:
                # Revoked rows are shown on request, for the audit question ("was this ever
                # covered?"). Fetched separately and appended, so the normal view cannot
                # accidentally include them.
                try:
                    with self._with_client() as client:
                        revoked = [r for r in fleet_store.read_registrations(
                            client, include_revoked=True) if not r.live]
                    payload["revoked"] = [
                        {"sensor_id": r.sensor_id, "segment": r.segment,
                         "address": r.address, "expected_mode": r.expected_mode,
                         "note": r.note,
                         "revoked_at": (r.revoked_at.isoformat()
                                        if isinstance(r.revoked_at, datetime.datetime) else None)}
                        for r in revoked
                    ]
                except fleet_store.FleetStoreError as exc:
                    payload["revoked"] = []
                    payload["revoked_reason"] = str(exc)
            self._json(payload)

        def _weirlings_detail(self, query: dict) -> None:
            """One sensor, for the drill-down.

            Reads through the same payload builder as the list, so the detail panel and the
            row it was opened from can never disagree about one sensor.
            """
            sensor_id = str((query.get("sensor") or [""])[0]).strip()
            if not sensor_id:
                return self._error(400, "a sensor id is required: /api/weirlings/detail?sensor=NAME")
            try:
                with self._with_client() as client:
                    row = fleet_store.classify_one(client, sensor_id)
            except Exception as exc:  # noqa: BLE001
                logger.warning("weirlings detail unavailable: %s", exc)
                return self._json({
                    "available": False,
                    "reason": f"the sensor could not be read: {str(exc)[:200]}",
                    "sensor": None,
                })
            if row is None:
                # Deliberately a 200 with `available: true` and a null sensor: "there is no
                # such sensor" is an ANSWER, not a failure, and rendering it as an error would
                # send the operator looking for an outage.
                return self._json({
                    "available": True, "reason": None, "sensor": None,
                    "note": (f"no sensor named {sensor_id!r} is registered or reporting. It may "
                             f"have been revoked, or the spelling may differ."),
                })
            # Same local marker as the list, from the same source: the drill-down decides from
            # it whether to mount the sensor's settings or the note saying where they are.
            row["local"] = (row.get("sensor_id") == _gate_sensor_name())
            self._json({"available": True, "reason": None, "sensor": row})

        def _sluice_block(self) -> None:
            """Create a blocking rule.

            Body: {"src_cidr", "dst_cidr", "protocol", "dst_port", "direction", "ttl_minutes",
                   "reason"}

            THE REFUSALS MATTER MORE THAN THE WRITE. A rule that blocks the wrong thing takes a
            network down, so every predicate is checked here and returned as a sentence the operator
            can act on -- rather than as a 500 from a layer that cannot explain itself.
            """
            if not self._authorize():
                return
            try:
                body = self._read_body()
            except ValueError as exc:
                return self._error(400, str(exc))

            from weirvern import sluice_store  # noqa: PLC0415
            from weirvern.sluice import SluiceError, parse_cidr, refuse_reason  # noqa: PLC0415

            src_raw = str(body.get("src_cidr") or "").strip()
            dst_raw = str(body.get("dst_cidr") or "").strip()
            protocol = str(body.get("protocol") or "").strip().lower()
            direction = str(body.get("direction") or "forward").strip().lower()
            try:
                dst_port = int(body.get("dst_port") or 0)
            except (TypeError, ValueError):
                return self._error(400, "dst_port must be a number")
            # 0 IS A VALUE, NOT AN ABSENCE. `or 60` read a deliberate 0 as "unset" and silently
            # substituted an hour -- the one input an operator reaching for "block it
            # indefinitely" is most likely to send. Absent or blank still defaults to 60.
            raw_ttl = body.get("ttl_minutes")
            try:
                ttl = 60 if raw_ttl is None or raw_ttl == "" else int(raw_ttl)
            except (TypeError, ValueError):
                return self._error(400, "ttl_minutes must be a number")

            try:
                src = parse_cidr(src_raw, "source")
                dst = parse_cidr(dst_raw, "destination")
            except SluiceError as exc:
                return self._json({"ok": False, "error": str(exc)}, 400)

            why = refuse_reason(
                src_cidr=src, dst_cidr=dst, direction=direction,
                iface=str(ctx.settings.sluice_iface or ctx.settings.zeek_iface or ""),
                mgmt_iface=str(ctx.settings.mgmt_iface or ""),
                sensor_addrs=self._sensor_addresses(), protocol=protocol, dst_port=dst_port,
            )
            if why:
                return self._json({"ok": False, "error": why}, 400)

            # OPTIONAL, by the operator's own instruction (2026-10-16). A reason is still the only
            # record of WHY, so a DERIVED block always writes one (derived_rules_for_detections)
            # and the form pre-fills the field from the alert; a manual block left blank records an
            # EMPTY reason rather than a placeholder, because a placeholder in an audit row reads
            # like a fact.
            reason = str(body.get("reason") or "").strip()

            try:
                with self._with_client() as client:
                    ident = self._identity()
                    rule = sluice_store.create_rule(
                        client, src_cidr=src, dst_cidr=dst, protocol=protocol,
                        dst_port=dst_port, direction=direction, ttl_minutes=ttl,
                        created_by=(ident.username if ident else "operator"), reason=reason,
                    )
            except SluiceError as exc:
                return self._json({"ok": False, "error": str(exc)}, 400)
            except Exception as exc:  # noqa: BLE001
                logger.warning("sluice block failed: %s", exc)
                return self._error(502, f"could not record the rule: {type(exc).__name__}")

            self._json({
                "ok": True, "rule_id": rule.rule_id, "describes": rule.describes(),
                "expires_at": rule.expires_at.isoformat() if rule.expires_at else "",
                # The gate arms on its own interval, so say so rather than letting the operator
                # assume the block is instant. An indefinite rule says so as well: "recorded" on
                # its own would read as a bounded block like every other one.
                "note": (f"recorded; enforcement picks it up within "
                         f"{int(ctx.settings.sluice_interval_s)}s"
                         + ("" if rule.expires_at else "; it stays until it is revoked")),
            })

        def _sluice_revoke(self) -> None:
            """Stop enforcing a rule, keeping the RECORD.

            The audit trail of what was blocked and why must not be destroyed by the act of
            unblocking it -- that record is what an incident review reads.
            """
            if not self._authorize():
                return
            try:
                body = self._read_body()
            except ValueError as exc:
                return self._error(400, str(exc))
            rule_id = str(body.get("rule_id") or "").strip()
            if not rule_id:
                return self._error(400, "rule_id is required")
            from weirvern import sluice_store  # noqa: PLC0415
            try:
                with self._with_client() as client:
                    ident = self._identity()
                    ok = sluice_store.revoke_rule(
                        client, rule_id, by=(ident.username if ident else "operator")
                    )
            except Exception as exc:  # noqa: BLE001
                logger.warning("sluice revoke failed: %s", exc)
                return self._error(502, f"could not revoke the rule: {type(exc).__name__}")
            if not ok:
                return self._json({"ok": False, "error": f"no rule with id {rule_id!r}"}, 404)
            self._json({"ok": True, "rule_id": rule_id,
                        "note": f"revoked; enforcement stops within "
                                f"{int(ctx.settings.sluice_interval_s)}s"})

        def _sensor_addresses(self) -> list[str]:
            """This host's own addresses, for the self-block check.

            Best-effort BY DESIGN: if they cannot be determined the check is SKIPPED, not failed. A
            self-block check that errored would refuse every rule on a host where the lookup is
            unavailable, which is worse than occasionally missing one -- the operator still sees the
            rule in the list and can revoke it.

            ── BUT `getaddrinfo(gethostname())` IS NOT THE HOST'S ADDRESSES (glm-5.3 review) ───────

            That call is the whole derivation, and inside a pod it resolves to the POD's address. So
            the two addresses that MUST NOT be blockable -- the management address this tool is
            reached on, and the gateway whose loss takes the segment down -- were never in the list,
            and the self-block check could not refuse them. MEASURED: on this cluster the pod resolves
            to a 10.42.x address while the management address is entirely different, so blocking the
            management interface would have been accepted.

            The intercept path already reads exactly these (see intercept.py's never-intercept roles:
            our_ip, gateway_ip, MGMT_ADDR), so this adds them from the same settings rather than
            inventing a second source. `sluice_iface`'s own address is included too, since a rule
            matching the capture interface's address would block this host's own traffic.
            """
            import socket  # noqa: PLC0415
            out: list[str] = []

            def _add(addr: object) -> None:
                a = str(addr or "").strip()
                if a and a not in out:
                    out.append(a)

            # 1. What the hostname resolves to -- the only source the previous version had.
            try:
                for info in socket.getaddrinfo(socket.gethostname(), None):
                    _add(info[4][0])
            except OSError:
                pass

            # 2. The roles this tool must never block, from the settings the rest of the product
            #    already trusts. Same values the intercept's never-intercept check uses.
            try:
                for attr in ("mgmt_addr", "ours", "our_ip", "gateway", "gateway_ip",
                             "mgmt_iface_addr"):
                    _add(getattr(ctx.settings, attr, ""))
            except Exception:  # noqa: BLE001
                pass

            # 3. The product's OWN host-address probe. `probe_local()` runs the embedded stdlib probe
            #    and reports this host's addresses; `ProbeResult.host_addresses` carries them as of the
            #    fix in interfaces.py, because until now the probe computed them and `parse_probe`
            #    dropped them -- which is why callers had to invent a worse source.
            #
            #    This is the right source rather than a second derivation: it is the same probe the
            #    interface view and the capture-port validation already use, so "this host's addresses"
            #    has one definition in the product instead of one per caller.
            try:
                from weirvern.admin import interfaces as ifaces_mod  # noqa: PLC0415

                for a in ifaces_mod.probe_local(timeout=5).host_addresses or []:
                    _add(a)
            except Exception:  # noqa: BLE001
                # Same best-effort contract as above: an unavailable lookup skips the check rather
                # than refusing every rule.
                pass
            return out

        def _zeeklog(self, query: dict) -> None:
            """Per-log detail for ONE Zeek log, for click-through from the Zeek view.

            Answers "which hosts appear in ssl.log, and how often" -- the drill-down a bar
            chart needs to be useful. `log` names a label from soc.ZEEK_LOGS; anything else is
            rejected rather than interpolated, because the table name reaches the SQL text.
            """
            label = (query.get("log") or [""])[0].strip()
            if not label:
                return self._error(400, "log is required, e.g. /api/zeeklog?log=ssl")
            allowed = dict(soc_mod.ZEEK_LOGS)
            table = allowed.get(label)
            if not table:
                return self._error(
                    400, f"unknown log {label!r}; expected one of: {', '.join(sorted(allowed))}"
                )
            hours = _int_arg(query, "hours", 24, 1, 24 * 14)
            try:
                with self._with_client() as client:
                    payload = soc_mod.zeek_log_hosts(client, table=table, label=label, hours=hours)
            except Exception as exc:  # noqa: BLE001
                logger.warning("zeek log detail unavailable: %s", exc)
                return self._json({
                    "available": False, "points": [], "log": label,
                    "reason": f"cannot reach ClickHouse: {type(exc).__name__}",
                    "data_error": str(exc),
                })
            self._json(payload)

        # -- writes ---------------------------------------------------------
        def _client_addr(self) -> str:
            return self.client_address[0] if self.client_address else ""

        def _identity(self) -> users_mod.Identity | None:
            """The signed-in account for this request, or None.

            Sessions are checked FIRST and the token never counts as an identity: a token has
            no username and no password to change, and the Account panel says so rather than
            offering a form that cannot work. `_token_role` below answers the separate
            question of whether the break-glass token is presented.
            """
            sessions = getattr(ctx, "sessions", None)
            if sessions is None:
                return None
            return sessions.get(gui_auth.session_from_request(self))

        def _token_role(self, *, gated: bool = False) -> str:
            """users_mod.ROLE_ADMIN when this request presents the operator token, else "".

            The PASSIVE form of the token check, for reporting state (the session probe, the
            settings payload). It records no failures and applies no delay -- those belong to
            `_authorize`, which is the gate -- so a read that merely *might* carry a token
            cannot be used to rack up delays against someone else's address.

            `gated=True` is the form the GATE uses, where the address is real and a wrong token
            must count toward the escalating delay. One implementation with a switch, rather than
            two checks that could drift apart.
            """
            auth = getattr(ctx, "auth", None)
            if auth is None or not auth.enabled:
                return ""
            presented = gui_auth.token_from_request(self)
            if presented and auth.check(presented, client=self._client_addr() if gated else ""):
                return users_mod.ROLE_ADMIN
            return ""

        def _caller_role(self) -> tuple[str, str]:
            """(role, via) for this request: ("admin"|"viewer"|"", "session"|"token"|"").

            ── THE TOKEN IS CONSULTED EVEN WHEN A SESSION EXISTS (audit F049) ──────────────────

            This returned the SESSION's role and never looked at the token if any session was
            present, and `_authorize` had the same shape. The consequence, measured against the real
            handler:

                viewer session + VALID token  -> 403 "this account is a viewer"  role=viewer via=session
                no session     + VALID token  -> AUTHORIZED                      role=admin  via=token

            The SAME valid token was accepted or refused depending only on whether the caller
            happened to be signed in as a viewer. Nothing was protected by that: a viewer holding
            the token can simply present it with no session, which is the line above. What was lost
            is the operator's ability to use their break-glass credential from a browser they were
            already signed into -- and the refusal said "ask an admin", pointing at an account
            problem when the credential they needed was already on the request.

            THE TOKEN WINS where both are present. It is admin-equivalent and independent of the
            account, and `via="token"` keeps the write attributable to that credential rather than
            to whichever account it happened to travel alongside.
            """
            role = self._token_role()
            if role:
                return (role, "token")
            ident = self._identity()
            if ident is not None:
                role = users_mod.ROLE_ADMIN if ident.is_admin else users_mod.ROLE_VIEWER
                return (role, "session")
            return ("", "")

        # -- weirlings writes -----------------------------------------------

        def _weirlings_register(self) -> None:
            """Register (or re-register) a sensor.

            The refusal is RETURNED, not raised as a 5xx: a rejected registration is a normal
            outcome of a form an operator is filling in, and an error page would read as the
            feature being broken rather than the input being wrong.
            """
            if not self._authorize():
                return
            try:
                body = self._read_body()
            except ValueError as exc:
                return self._json({"ok": False, "error": str(exc)}, code=400)
            try:
                with self._with_client() as client:
                    reg = fleet_store.register(
                        client,
                        str(body.get("sensor_id") or ""),
                        address=str(body.get("address") or ""),
                        segment=str(body.get("segment") or ""),
                        expected_mode=str(body.get("expected_mode") or "loch"),
                        note=str(body.get("note") or ""),
                    )
            except fleet_store.FleetError as exc:
                # The message names the fix, so it is passed through verbatim rather than
                # wrapped in a generic "invalid input".
                return self._json({"ok": False, "error": str(exc)}, code=400)
            except fleet_store.FleetStoreError as exc:
                return self._json({"ok": False, "error": str(exc)}, code=503)
            except Exception as exc:  # noqa: BLE001
                logger.warning("weirling registration failed: %s", exc)
                return self._json({"ok": False, "error": f"could not save: {str(exc)[:200]}"},
                                  code=500)
            self._json({"ok": True, "sensor_id": reg.sensor_id})

        def _weirlings_enable(self) -> None:
            """Switch a registered sensor on or off WITHOUT revoking it."""
            if not self._authorize():
                return
            try:
                body = self._read_body()
            except ValueError as exc:
                return self._json({"ok": False, "error": str(exc)}, code=400)
            # Strict booleans: `bool("false")` is True, so a client sending the string "false"
            # would silently ENABLE a sensor. Refused rather than coerced.
            enabled = body.get("enabled")
            if not isinstance(enabled, bool):
                return self._json(
                    {"ok": False, "error": "`enabled` must be true or false"}, code=400)
            try:
                with self._with_client() as client:
                    reg = fleet_store.set_enabled(client, str(body.get("sensor_id") or ""), enabled)
            except fleet_store.FleetError as exc:
                return self._json({"ok": False, "error": str(exc)}, code=400)
            except fleet_store.FleetStoreError as exc:
                return self._json({"ok": False, "error": str(exc)}, code=503)
            except Exception as exc:  # noqa: BLE001
                logger.warning("weirling enable failed: %s", exc)
                return self._json({"ok": False, "error": f"could not save: {str(exc)[:200]}"},
                                  code=500)
            self._json({"ok": True, "sensor_id": reg.sensor_id, "enabled": reg.enabled})

        def _weirlings_revoke(self) -> None:
            """Retire a registration. The row is kept; nothing is deleted."""
            if not self._authorize():
                return
            try:
                body = self._read_body()
            except ValueError as exc:
                return self._json({"ok": False, "error": str(exc)}, code=400)
            try:
                with self._with_client() as client:
                    reg = fleet_store.revoke_registration(
                        client, str(body.get("sensor_id") or ""))
            except fleet_store.FleetError as exc:
                return self._json({"ok": False, "error": str(exc)}, code=400)
            except fleet_store.FleetStoreError as exc:
                return self._json({"ok": False, "error": str(exc)}, code=503)
            except Exception as exc:  # noqa: BLE001
                logger.warning("weirling revoke failed: %s", exc)
                return self._json({"ok": False, "error": f"could not save: {str(exc)[:200]}"},
                                  code=500)
            self._json({"ok": True, "sensor_id": reg.sensor_id})


        def _require_read(self) -> bool:
            """Whether this request may READ. Sends the refusal itself.

            Open when accounts are not provisioned (see _route); otherwise a signed-in
            account or the break-glass token is required. A `must_change` account is held at
            the password gate: it can reach /api/session and the password route, and every
            other read says why not, so the UI cannot render a dashboard behind the gate.
            """
            if not _accounts_on(ctx):
                return True
            ident = self._identity()
            if ident is not None:
                if ident.must_change:
                    self._error(403, "a password change is required before using the dashboard")
                    return False
                return True
            if self._token_role():
                return True
            self._error(401, "sign in to view this dashboard")
            return False

        def _require_session(self) -> users_mod.Identity | None:
            """The signed-in identity, or None with the refusal already sent.

            For the routes every account may use regardless of role -- signing out and
            changing one's OWN password. Deliberately not satisfiable by the token: the
            token has no account, so there is no password to change and nothing to sign out
            of, and pretending otherwise would offer the operator a button that cannot work.
            """
            if not _accounts_on(ctx):
                self._error(403, "this deployment has no accounts provisioned")
                return None
            ident = self._identity()
            if ident is None:
                self._error(401, "sign in first")
                return None
            return ident

        def _authorize(self) -> bool:
            """Whether this request may WRITE. Sends the refusal itself.

            Two credentials open the write path, both admin-equivalent:
              * a signed-in admin account session (the normal case), or
              * the deployment operator token -- break-glass: it recovers a lost admin
                password and drives automation, and it is why losing every password cannot
                lock a deployment out of its own configuration.

            ── ORDER: THE TOKEN IS CHECKED REGARDLESS OF THE SESSION (audit F049) ──────────────

            This used to return the session's verdict FIRST, so a request carrying a viewer session
            AND the valid token was refused as a viewer with the token never examined -- measured
            against the real handler:

                viewer session + VALID token  -> 403 "this account is a viewer"
                no session     + VALID token  -> AUTHORIZED

            Same credential, opposite answers, decided by whether the browser happened to be
            signed in. The token is a deployment-wide credential that does not depend on the
            account, so it is now evaluated first and `via="token"` records which one opened the
            gate. Nothing is weakened by that ordering: a viewer without the token still gets the
            viewer refusal below, which is the case that must keep working.

            The TOKEN check is `gated=True` so a wrong token counts toward the escalating delay,
            and a token that is merely ABSENT still falls through to the account path -- the
            difference matters, because a read that carries no token must not be slowed down here.
            """
            presented = gui_auth.token_from_request(self)
            if presented and self._token_role(gated=True):
                return True

            ident = self._identity()
            if ident is not None:
                if ident.must_change:
                    self._error(403, "change your password before changing anything else")
                    return False
                if ident.is_admin:
                    return True
                self._error(403, "this account is a viewer: it can read every view but cannot "
                                 "change settings or manage accounts. Ask an admin.")
                return False
            auth = getattr(ctx, "auth", None)
            if auth is None:
                self._error(503, "write access is not available: the GUI started without an "
                                 "authentication module")
                return False
            if not auth.enabled:
                # No token configured and no session. When accounts exist, the useful thing to
                # say is "sign in"; otherwise it is the token's own explanation.
                if _accounts_on(ctx):
                    self._error(403, "sign in with an admin account to change settings")
                else:
                    self._error(403, auth.reason)
                return False
            addr = self._client_addr()
            # Escalating delay, bounded. The response never distinguishes absent, empty and wrong.
            delay = auth.delay_for(addr)
            if delay:
                time.sleep(delay)
            logger.warning("rejected an unauthenticated settings write from %s", addr or "unknown")
            self._error(401, "a valid admin session or operator token is required to change "
                             "settings")
            return False

        def _read_body(self, limit: int = 65536) -> dict:
            """The request body as JSON, or raise ValueError.

            Bounded: an unbounded read on a LAN port is a memory-growth path.
            """
            length = int(self.headers.get("Content-Length") or 0)
            if length <= 0:
                raise ValueError("a JSON body is required")
            if length > limit:
                raise ValueError(f"body too large ({length} bytes)")
            raw = self.rfile.read(length)
            try:
                parsed = json.loads(raw.decode("utf-8"))
            except (ValueError, UnicodeDecodeError) as exc:
                raise ValueError(f"body is not valid JSON: {exc}") from exc
            if not isinstance(parsed, dict):
                raise ValueError("body must be a JSON object")
            return parsed

        def do_POST(self) -> None:  # noqa: N802
            """The only write surface. Every route here is token-gated.

            Reads stay on GET and stay open. This exists so an operator can manage settings from
            the GUI; it is deliberately narrow (a key allow-list, staged apply,
            stated blast radius) because the port has no TLS and the token is the only control.
            """
            try:
                self._route_post()
            except BrokenPipeError:
                pass
            except Exception as exc:  # noqa: BLE001
                logger.warning("GUI write failed for %s: %s", self.path, exc)
                with contextlib.suppress(Exception):
                    self._error(500, f"internal error: {exc}")

        def _route_post(self) -> None:
            parsed = urlparse(self.path)
            path = parsed.path.rstrip("/") or "/"

            # THE SIGN-IN DOOR. The only write route reachable without a session, because it
            # is how a session is obtained. Its own throttle (per client address) stands in
            # for the gate.
            if path == "/api/login":
                return self._login()
            if path == "/api/logout":
                return self._logout()
            # The password change. Session-gated, not admin-gated: it is how a `must_change`
            # account -- which every OTHER route refuses -- gets out of the gate.
            if path == "/api/password":
                return self._password()
            # Account management. Admin-gated: creating, promoting and deleting accounts.
            if path == "/api/users/create":
                return self._users_create()
            if path == "/api/users/role":
                return self._users_role()
            if path == "/api/users/delete":
                return self._users_delete()
            if path == "/api/users/reset":
                return self._users_reset()
            if path == "/api/settings/plan":
                return self._settings_plan()
            if path == "/api/settings/apply":
                return self._settings_apply()
            # SONAR. A survey of the capture interface's segment, launched as a one-shot
            # Job. A POST rather than a GET because it CREATES a cluster object and spends
            # seconds of the sensor node's time -- a read that must not be repeated by a
            # prefetcher or a refresh. Admin-gated like every other write.
            if path == "/api/settings/sonar":
                return self._settings_sonar()
            # TEST RUN. Flips the configured mode to siphon for a bounded window (default
            # 30s), then reverts to loch -- a probe through the REAL supervision path, so
            # the operator can watch an intercept run without committing to it. This is the
            # most consequential write on the page (while it runs, the sensor is in the
            # traffic path), so it is admin-gated like the rest and its revert runs in a
            # finally (see admin/siphon_probe.py for the full contract).
            if path == "/api/settings/test":
                return self._settings_test()
            # SOC-1: the alert review write. A write like the settings routes, so it goes
            # through the same operator-token gate -- an unauthenticated port must not let
            # anyone on the LAN mark alerts as handled.
            if path == "/api/review":
                return self._review()
            # ── SLUICE GATE writes ────────────────────────────────────────────────────────
            if path == "/api/sluice/block":
                return self._sluice_block()
            # ── FORCED RETRAIN writes ───────────────────────────────────────────────────────
            # `retrain` trains a CANDIDATE and changes nothing live; `keep` installs it over the
            # live artifacts (archiving them); `trash` deletes the candidate. All three are
            # admin-gated: the last two decide what is watching the network.
            if path == "/api/models/retrain" or path.startswith("/api/models/retrain/"):
                # No argument, like every other write route here: the dispatcher's own parser (and
                # the test that reads it) looks up handlers by `def name(self`, and the route is
                # available on `self.path` anyway.
                return self._model_retrain_write()
            if path == "/api/sluice/revoke":
                return self._sluice_revoke()
            # ── WEIRLINGS writes ─────────────────────────────────────────────────────────
            # Admin-gated like every other mutation. Registering a sensor decides what this hub
            # will EXPECT and therefore what it raises as missing, so it is a write even though
            # it touches no remote box.
            if path == "/api/weirlings/register":
                return self._weirlings_register()
            if path == "/api/weirlings/enable":
                return self._weirlings_enable()
            if path == "/api/weirlings/revoke":
                return self._weirlings_revoke()
            self._error(404, f"no write route at {path}")

        # -- accounts -------------------------------------------------------

        def _session(self) -> None:
            """Who the caller is; whether the sign-in gate is armed. NEVER anyone else's data.

            Answers for three callers: an anonymous browser deciding whether to show the gate,
            a signed-in account refreshing its role, and the break-glass token (reported as an
            admin `via: token` with no username, because that is exactly what it is).
            """
            ident = self._identity()
            armed = _accounts_on(ctx)
            payload: dict = {
                "accounts": armed,
                "note": getattr(ctx, "accounts_note", "") or "",
            }
            if ident is not None:
                payload.update({"authenticated": True, "username": ident.username,
                                "role": ident.role, "must_change": ident.must_change,
                                "via": "session"})
            elif self._token_role():
                payload.update({"authenticated": True, "username": "", "role": users_mod.ROLE_ADMIN,
                                "must_change": False, "via": "token"})
            else:
                payload.update({"authenticated": False, "username": "", "role": "",
                                "must_change": False, "via": ""})
            self._json(payload)

        def _login(self) -> None:
            """Verify a username and password, and mint a session.

            The response NEVER says which half was wrong: "no such user" and "wrong password"
            are one message, because distinguishing them enumerates accounts. Timing is
            equalised the same way (`users.dummy_verify` runs a real scrypt for unknown
            usernames). A deployment with NO accounts says so plainly instead -- that is a
            setup fact its operator needs, not an oracle for an attacker.
            """
            if not _accounts_on(ctx):
                note = getattr(ctx, "accounts_note", "") or (
                    "this deployment has no accounts provisioned"
                )
                return self._json({"ok": False, "error": f"cannot sign in: {note}"}, 403)
            try:
                body = self._read_body()
            except ValueError as exc:
                return self._error(400, str(exc))
            username = str(body.get("username") or "").strip().lower()
            password = str(body.get("password") or "")
            addr = self._client_addr()
            throttle = getattr(ctx, "throttle", None)

            store = getattr(ctx, "user_store", None)
            if store is None:
                return self._error(503, "the account store is not available on this GUI")
            record = store.find(username) if username else None
            if record is None:
                # Equalise the cost of a miss with the cost of a wrong password.
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
                logger.warning("rejected a sign-in for %r from %s",
                               username or "(empty)", addr or "unknown")
                return self._json({
                    "ok": False,
                    "error": "the username or password is not correct",
                }, 401)
            if throttle is not None:
                throttle.clear(addr)
            identity = users_mod.Identity(username=record.username, role=record.role,
                                          must_change=record.must_change)
            token = ctx.sessions.create(identity)
            logger.info("signed in %s from %s", record.username, addr or "unknown")
            self._json({
                "ok": True, "session": token, "username": identity.username,
                "role": identity.role, "must_change": identity.must_change,
            })

        def _logout(self) -> None:
            """Drop the caller's session.

            A session is REQUIRED, for the same uniformity as every other account route: an
            audit rule that says "every mutating route presents a session" is one somebody can
            check at a glance, and an exception has to be re-justified forever. The client-side
            flow is unaffected -- a tab whose session already expired catches the refusal and
            clears its own state anyway, which is what signing out does.
            """
            ident = self._require_session()
            if ident is None:
                return
            sessions = getattr(ctx, "sessions", None)
            if sessions is not None:
                sessions.revoke(gui_auth.session_from_request(self))
            logger.info("signed out %s", ident.username)
            self._json({"ok": True})

        def _password(self) -> None:
            """Change the signed-in account's own password.

            Requires the CURRENT password for two reasons: it stops a stolen session token
            from locking the owner out of their account, and it makes `must_change` an
            informed change rather than a form the operator submits blind. Sessions are
            revoked afterwards -- a password change is the one moment where dropping every
            other session is exactly what the operator expects.
            """
            ident = self._require_session()
            if ident is None:
                return
            try:
                body = self._read_body()
            except ValueError as exc:
                return self._error(400, str(exc))
            current = str(body.get("current") or "")
            new = str(body.get("new") or "")
            store = getattr(ctx, "user_store", None)
            if store is None:
                return self._error(503, "the account store is not available on this GUI")
            record = store.find(ident.username)
            if record is None:
                return self._error(404, "this account no longer exists")
            if not users_mod.verify_password(current, record.hash):
                return self._json({
                    "ok": False, "error": "the current password is not correct",
                }, 401)
            try:
                store.set_password(ident.username, new, must_change=False)
            except users_mod.UserError as exc:
                return self._json({"ok": False, "error": str(exc)}, 400)
            except Exception as exc:  # noqa: BLE001
                return self._error(502, f"could not save the new password: {exc}")
            # Every session for this account, including this one: the UI signs in again with
            # the new password, which also proves the change took.
            sessions = getattr(ctx, "sessions", None)
            revoked = sessions.revoke_user(ident.username) if sessions is not None else 0
            logger.info("password changed for %s (%d session(s) revoked)", ident.username, revoked)
            self._json({"ok": True, "signed_out": True,
                        "note": "password changed; sign in again with the new one"})

        def _users_list(self) -> None:
            """Every account, for an admin. Reads are admin-only: the account list is not
            monitoring data, and a viewer has no use for it."""
            role, _via = self._caller_role()
            if role != users_mod.ROLE_ADMIN:
                return self._error(403, "admin access is required to view accounts")
            store = getattr(ctx, "user_store", None)
            if store is None or not _accounts_on(ctx):
                return self._json({"available": False, "users": [],
                                   "reason": getattr(ctx, "accounts_note", "")
                                   or "no accounts provisioned"})
            self._json({"available": True, "users": store.public_users(),
                        "roles": list(users_mod.ROLES)})

        def _users_create(self) -> None:
            """Create an account. Admin only."""
            if not self._authorize():
                return
            try:
                body = self._read_body()
            except ValueError as exc:
                return self._error(400, str(exc))
            store = getattr(ctx, "user_store", None)
            if store is None:
                return self._error(503, "the account store is not available on this GUI")
            try:
                record = store.create_user(
                    str(body.get("username") or ""),
                    str(body.get("role") or users_mod.ROLE_VIEWER),
                    str(body.get("password") or ""),
                    must_change=bool(body.get("must_change")),
                )
            except users_mod.UserError as exc:
                return self._json({"ok": False, "error": str(exc)}, 400)
            except Exception as exc:  # noqa: BLE001
                return self._error(502, f"could not create the account: {exc}")
            logger.info("created account %s with role %s", record.username, record.role)
            self._json({"ok": True, "user": record.public()})

        def _users_role(self) -> None:
            """Change an account's role. Admin only, and the last admin is protected by the
            store: demoting the only admin would leave nobody able to manage accounts."""
            if not self._authorize():
                return
            try:
                body = self._read_body()
            except ValueError as exc:
                return self._error(400, str(exc))
            username = str(body.get("username") or "").strip().lower()
            role = str(body.get("role") or "")
            store = getattr(ctx, "user_store", None)
            if store is None:
                return self._error(503, "the account store is not available on this GUI")
            try:
                # The ROLE STRING, captured before the write: `find()` returns the store's
                # live record, and set_role mutates it in place -- comparing the record's
                # role AFTER the call would always say "unchanged". (Caught by the test for
                # exactly this: the comparison must be between strings.)
                existing = store.find(username)
                before_role = existing.role if existing is not None else None
                store.set_role(username, role)
            except users_mod.UserError as exc:
                return self._json({"ok": False, "error": str(exc)}, 400)
            except Exception as exc:  # noqa: BLE001
                return self._error(502, f"could not change the role: {exc}")
            # An open tab keeps acting under the old role until its session is dropped, so a role
            # CHANGE revokes the account's sessions immediately. A NO-OP -- setting the role the
            # account already has -- changed nothing and must revoke nothing: it used to sign the
            # operator out of the very tab they were working in, which reads as the change having
            # failed (reported live: "I can't change admin to admin").
            if before_role is not None and before_role != role:
                sessions = getattr(ctx, "sessions", None)
                if sessions is not None:
                    sessions.revoke_user(username)
            logger.info("role for %s set to %s", username, role)
            self._json({"ok": True, "username": username, "role": role})

        def _users_delete(self) -> None:
            """Delete an account. Admin only; the last admin cannot be deleted (store guard)."""
            if not self._authorize():
                return
            try:
                body = self._read_body()
            except ValueError as exc:
                return self._error(400, str(exc))
            username = str(body.get("username") or "").strip().lower()
            store = getattr(ctx, "user_store", None)
            if store is None:
                return self._error(503, "the account store is not available on this GUI")
            try:
                store.delete_user(username)
            except users_mod.UserError as exc:
                return self._json({"ok": False, "error": str(exc)}, 400)
            except Exception as exc:  # noqa: BLE001
                return self._error(502, f"could not delete the account: {exc}")
            sessions = getattr(ctx, "sessions", None)
            if sessions is not None:
                sessions.revoke_user(username)
            logger.info("deleted account %s", username)
            self._json({"ok": True, "username": username})

        def _users_reset(self) -> None:
            """Set a new password for ANOTHER account, and force a change at next sign-in.

            The lost-password path that keeps this feature usable without email: an admin
            mints a temporary password and hands it over, and the account is held at the
            password gate until its owner replaces it.
            """
            if not self._authorize():
                return
            try:
                body = self._read_body()
            except ValueError as exc:
                return self._error(400, str(exc))
            username = str(body.get("username") or "").strip().lower()
            password = str(body.get("password") or "")
            store = getattr(ctx, "user_store", None)
            if store is None:
                return self._error(503, "the account store is not available on this GUI")
            try:
                store.set_password(username, password, must_change=True)
            except users_mod.UserError as exc:
                return self._json({"ok": False, "error": str(exc)}, 400)
            except Exception as exc:  # noqa: BLE001
                return self._error(502, f"could not reset the password: {exc}")
            sessions = getattr(ctx, "sessions", None)
            if sessions is not None:
                sessions.revoke_user(username)
            logger.info("password reset for %s (must change at next sign-in)", username)
            self._json({"ok": True, "username": username,
                        "note": "the account must change this password at next sign-in"})

        def _review(self) -> None:
            """Record an analyst's disposition of one anomaly (ack / resolve / false-positive).

            Body: {"window_start": "...", "src_addr": "...", "state": "ack",
                   "note": "optional"}.  An empty state clears the review.

            Returns the stored review so the caller can render from what LANDED rather
            than from what it hoped -- the same read-back rule the settings apply path
            follows for the ConfigMap.
            """
            if not self._authorize():
                return
            try:
                body = self._read_body()
            except ValueError as exc:
                return self._error(400, str(exc))

            window_start = body.get("window_start")
            src_addr = str(body.get("src_addr") or "").strip()
            state = str(body.get("state") or "").strip()
            note = str(body.get("note") or "")[:500]

            if not window_start or not src_addr:
                return self._error(400, "'window_start' and 'src_addr' are required")
            if state not in status_mod.VALID_REVIEW_STATES:
                return self._json({
                    "ok": False,
                    "error": f"unknown review state {state!r}",
                    "valid_states": [s for s in status_mod.VALID_REVIEW_STATES if s],
                }, 400)
            try:
                with self._with_client() as client:
                    status_mod.write_review(
                        client, window_start=window_start, src_addr=src_addr,
                        state=state, note=note)
            except ValueError as exc:
                return self._error(400, str(exc))
            except Exception as exc:  # noqa: BLE001
                return self._error(503, f"could not record the review: {exc}")
            self._json({"ok": True, "state": state, "note": note})

        def _settings_plan(self) -> None:
            """Validate and describe a proposed change WITHOUT touching anything.

            The UI calls this first and shows the result, so the blast radius is stated before the
            change rather than discovered after. Requires the token too: even a dry run reveals the
            deployment's configuration shape.
            """
            if not self._authorize():
                return
            from weirvern.admin import cluster_config as cc

            try:
                body = self._read_body()
            except ValueError as exc:
                return self._error(400, str(exc))

            changes = body.get("changes")
            if not isinstance(changes, dict) or not changes:
                return self._error(400, "a non-empty 'changes' object is required")

            try:
                current = cc.ClusterConfig().read() if ctx.config_client is None else \
                    ctx.config_client.read()
            except cc.ConfigError as exc:
                return self._error(502, str(exc))
            except Exception as exc:  # noqa: BLE001
                return self._error(502, f"could not read the configuration: {exc}")

            try:
                p = cc.plan({k: str(v) for k, v in changes.items()}, current)
            except cc.ConfigError as exc:
                return self._json({"ok": False, "error": str(exc)}, 400)

            # PROPOSALS ECHO THE CALLER'S KEY VOCABULARY. The GUI stages ROW keys
            # (`sensor_mode`); `cc.plan` speaks CONFIGMAP keys (`SENSOR_MODE`) because the
            # validator does. Returning the ConfigMap key here meant the client's warning
            # lookup (`stagedKeys.has(p.key)`) never matched -- so the costly-change
            # confirmation dialog was SKIPPED for exactly the changes that need it (the
            # in-path mode among them), and the staging list showed no warnings. The fix is
            # at the boundary: translate back, so both sides speak the key the caller used.
            caller_key = {cc.to_configmap_key(k): k for k in changes}

            self._json({
                "ok": True,
                "proposals": [
                    {"key": caller_key.get(x.key, x.key), "current": x.current,
                     "proposed": x.proposed, "restarts": x.restarts, "blast": x.blast,
                     "warning": x.warning}
                    for x in p.proposals
                ],
                "restart_targets": p.restart_targets,
            })

        def _settings_apply(self) -> None:
            """Write the configuration, then restart what reads it.

            The write is verified by READ-BACK inside ClusterConfig.apply, so a merge-patch that
            matched nothing is reported as a failure rather than as success. The restart is what
            makes the change take effect -- a ConfigMap env var is read at process start, so
            without it the operator would be told "saved" about a change that is inert.
            """
            if not self._authorize():
                return
            from weirvern.admin import cluster_config as cc

            try:
                body = self._read_body()
            except ValueError as exc:
                return self._error(400, str(exc))

            changes = body.get("changes")
            if not isinstance(changes, dict) or not changes:
                return self._error(400, "a non-empty 'changes' object is required")
            confirmed = bool(body.get("confirmed"))

            client = ctx.config_client or cc.ClusterConfig()
            try:
                current = client.read()
                p = cc.plan({k: str(v) for k, v in changes.items()}, current)
            except cc.ConfigError as exc:
                return self._json({"ok": False, "error": str(exc)}, 400)
            except Exception as exc:  # noqa: BLE001
                return self._error(502, f"could not read the configuration: {exc}")

            # A change with a warning must be confirmed explicitly. The warning exists because the
            # value is legal but costly, and a plan the caller never saw is not consent.
            if not confirmed and any(x.warning for x in p.proposals):
                return self._json({
                    "ok": False,
                    "needs_confirmation": True,
                    "proposals": [
                        {"key": x.key, "current": x.current, "proposed": x.proposed,
                         "warning": x.warning} for x in p.proposals if x.warning
                    ],
                }, 409)

            # The mode change gets the CLI's OWN gate, imported rather than reimplemented: two
            # copies of a safety check drift, and the one that drifts is the one nobody tests.
            mode_error = self._mode_gate(changes)
            if mode_error:
                return self._json({"ok": False, "error": mode_error}, 409)

            try:
                landed = client.apply({k: str(v) for k, v in changes.items()})
            except cc.ConfigError as exc:
                return self._json({"ok": False, "error": str(exc)}, 502)

            restarted: list[str] = []
            restart_errors: list[str] = []
            for target in p.restart_targets:
                try:
                    client.restart(target)
                    restarted.append(target)
                except cc.ConfigError as exc:
                    restart_errors.append(str(exc))

            self._json({
                "ok": True,
                # TRANSLATED AT THE BOUNDARY, same reason as the plan route: `changes` is
                # ROW-keyed (what the GUI staged) and `landed` is the ConfigMap's own data
                # (CONFIGMAP keys). `landed.get(k)` with the row key returned "" for every
                # key, so the confirmation read `saved: reverse_dns=(empty)` AFTER A WRITE
                # THAT ACTUALLY LANDED -- the report contradicted the read-back that had
                # just proved it. The write was right; the receipt lied.
                "applied": {k: landed.get(cc.to_configmap_key(k), "") for k in changes},
                "restarted": restarted,
                # A saved-but-not-restarted change is INERT, so it is reported as a failure of
                # applying rather than quietly folded into success.
                "restart_errors": restart_errors,
                "note": ("restarted " + ", ".join(restarted)) if restarted
                        else "no workload needed a restart",
            })

        def _settings_sonar(self) -> None:
            """Survey the capture interface's segment and return recommendations.

            THE SURVEY RUNS AS A ONE-SHOT JOB, NOT IN THIS PROCESS. This pod has its own
            network namespace and no capabilities, so a survey run here would measure the
            wrong machine and recommend settings for interfaces the sensor node does not
            have. The job runs with the sensor's shape (hostNetwork, pinned to the sensor
            node, NET_RAW for the ARP socket) -- see admin/sonar.py.

            It changes NOTHING: no setting is written (the UI stages the recommendations as
            pending changes), no address is assigned, and the only frames it sends are ARP
            requests. Admin-gated because it creates a cluster object and spends the sensor
            node's time, not because it writes configuration.

            Body: `{"interface": "eth1"}` (optional; defaults to the running capture
            interface), `{"mgmt_interface": "eth0"}` (optional; for the two-port warning).
            """
            if not self._authorize():
                return
            from weirvern.admin import cluster_config as cc
            from weirvern.admin import sonar as sonar_mod

            try:
                body = self._read_body()
            except ValueError as exc:
                return self._error(400, str(exc))

            iface = str(body.get("interface") or "").strip()
            mgmt = str(body.get("mgmt_interface") or "").strip()
            if not iface:
                # The interface the intercept would ACTUALLY run on: CAPTURE_IFACE wins when
                # set (the supervisor's rule), else the configured capture interface. Read
                # from the environment rather than the request so the default cannot drift
                # from what the worker's supervisor uses.
                iface = (os.environ.get("CAPTURE_IFACE")
                         or os.environ.get("ZEEK_IFACE") or "").strip()
            if not mgmt:
                mgmt = (os.environ.get("MGMT_IFACE") or "").strip()
            if not iface:
                return self._json({
                    "ok": False,
                    "error": "no capture interface is configured, so there is nothing to "
                             "survey. Set the capture interface (ZEEK_IFACE) in Settings "
                             "first, or name one in this request.",
                }, 400)

            # ── THE SHAPE CHECK AT THE REQUEST BOUNDARY (audit F091, CONFIRMED) ────────────────
            #
            # `interface`/`mgmt_interface` are the only free-text inputs this page takes, and they
            # went from the body into a privileged Job's env with no contract at all. `build_job`
            # now refuses too, so no caller can bypass this -- and the check is repeated HERE
            # because only here can the refusal carry a sentence an operator reads. Letting it
            # through to build_job would surface it as a 500-class failure with an exception name,
            # which for a typo in an interface name is the wrong story.
            _why = sonar_mod.validate_survey_ifaces(iface, mgmt)
            if _why:
                return self._json({
                    "ok": False,
                    "error": f"cannot survey: {_why}. {sonar_mod.iface_input_remedy()}",
                }, 400)

            if ctx.config_client is not None:
                client = ctx.config_client
            else:
                try:
                    client = cc.ClusterConfig()
                except cc.ConfigError as exc:
                    return self._json({"ok": False, "error": str(exc)}, 503)

            try:
                result = sonar_mod.run_survey_job(client, iface, mgmt)
            except sonar_mod.SonarError as exc:
                return self._json({"ok": False, "error": str(exc)}, 502)

            # A refusal INSIDE the job (it ran, and said no) is passed through with its reason,
            # distinct from a job that could not run at all.
            if isinstance(result, dict) and result.get("ok") is False:
                return self._json(result, 422)
            self._json(result)

        def _settings_test(self) -> None:
            """Run the intercept for a bounded TEST window, then revert the mode to loch.

            THE MOST CONSEQUENTIAL WRITE ON THIS PAGE: while the probe runs, this sensor is
            genuinely in the traffic path for the hosts the plan names -- the ARP mappings are
            real and the traffic really relays. What the probe changes is the ENDING: the mode
            is written back to `loch` in a finally, and the worker's restart stops the
            supervised intercept through its orderly SIGTERM path (the same restore contract
            every production run uses). See admin/siphon_probe.py for the full reasoning,
            including why it drives the ConfigMap instead of spawning its own intercept.

            Body: `{"seconds": 30}` (optional; bounded server-side). Blocking for up to
            `seconds` -- a few tens of seconds is acceptable for a probe whose result IS the
            observation window, and the browser shows a running state while it waits.

            The liveness evidence is collected through status.siphon_liveness -- the same
            check `weirvern status` uses -- so the probe's verdict and the CLI's cannot
            disagree about what "an intercept was running" means.
            """
            if not self._authorize():
                return
            from weirvern.admin import cluster_config as cc
            from weirvern.admin import siphon_probe as probe_mod

            try:
                body = self._read_body()
            except ValueError as exc:
                return self._error(400, str(exc))

            raw_seconds = body.get("seconds")
            try:
                seconds = float(raw_seconds) if raw_seconds is not None else 30.0
            except (TypeError, ValueError):
                return self._error(400, "seconds must be a number")
            if not 5.0 <= seconds <= 600.0:
                return self._error(400, "seconds must be between 5 and 600")

            if ctx.config_client is not None:
                client = ctx.config_client
            else:
                try:
                    client = cc.ClusterConfig()
                except cc.ConfigError as exc:
                    return self._json({"ok": False, "error": str(exc)}, 503)

            def liveness():
                """Intercept evidence via the same check the CLI uses. None-safe."""
                try:
                    with self._with_client() as ch:
                        configured = ""
                        try:
                            configured = str((client.read() or {}).get("SENSOR_MODE") or "")
                        except Exception:  # noqa: BLE001
                            configured = ""
                        return status_mod.siphon_liveness(configured, ch)
                except Exception as exc:  # noqa: BLE001
                    return {"live": False, "error": f"could not read intercept evidence: {exc}"}

            try:
                result = probe_mod.run_probe(client, seconds=seconds, liveness=liveness)
            except Exception as exc:  # noqa: BLE001
                logger.error("siphon probe failed", exc_info=True)
                return self._json({"ok": False, "error": f"the test run failed: {exc}"}, 500)
            if result.get("ok") is False:
                return self._json(result, 422)
            # 200 even when the run produced no evidence: the RUN happened and its outcome
            # (including "no intercept was observed") IS the answer. Only a failed revert is
            # a problem to flag loudly.
            code = 200 if result.get("reverted") else 500
            self._json(result, code)

        def _mode_gate(self, changes: dict) -> str:
            """Reject a mode change that the mode's own prerequisites forbid. "" when fine.

            The gate is `mode.validate`, which is what `weirvern mode siphon` uses. A GUI session must
            not be a way around it: enabling in-path interception without forwarding working takes
            the segment down, and the check that prevents that has to be the same check.
            """
            wanted = None
            for k, v in changes.items():
                if k.strip().upper() == "SENSOR_MODE":
                    wanted = str(v)
            if wanted is None:
                return ""
            from weirvern.admin import mode as mode_mod

            normalised = mode_mod.normalise(wanted)
            has_net_admin, has_net_raw = self._sensor_caps()
            verdict = mode_mod.validate(normalised, has_net_admin=has_net_admin,
                                        has_net_raw=has_net_raw, watchdog_available=True)
            if verdict.ok:
                return ""
            reasons = "; ".join(getattr(verdict, "blockers", []) or [])
            return f"cannot enable {normalised}: {reasons or 'prerequisites are missing'}"

        def _sensor_caps(self) -> tuple[bool, bool]:
            """(net_admin, net_raw) for the SENSOR, read from the cluster's own DaemonSet.

            WHY THE CLUSTER AND NOT THIS PROCESS: the GUI runs in its own pod, and its
            effective capabilities describe the wrong container. The sensor is the thing
            that must forward, so its DaemonSet is authoritative -- an overlay applied or
            reverted on the cluster is visible here whatever any checkout says.

            A capability that cannot be verified is reported ABSENT, never assumed: the
            gate exists so the in-path mode cannot be enabled without the ability to
            forward. (This began as a stub that answered "no" unconditionally, which made
            the mode impossible to enable from the GUI even where the sensor held the
            capabilities -- reported live as "I can't apply siphon mode".)
            """
            from weirvern.admin import cluster_config as cc

            client = getattr(ctx, "config_client", None) or cc.ClusterConfig()
            try:
                ds = client.get_json(
                    f"/apis/apps/v1/namespaces/{cc.NAMESPACE}/daemonsets/zeek")
                containers = (
                    ((ds.get("spec") or {}).get("template") or {}).get("spec") or {}
                ).get("containers") or []
                for container in containers:
                    if container.get("name") == "zeek":
                        adds = ((container.get("securityContext") or {})
                                .get("capabilities") or {}).get("add") or []
                        return ("NET_ADMIN" in adds), ("NET_RAW" in adds)
            except Exception:  # noqa: BLE001
                pass
            return False, False

        def _settings(self, query: dict) -> None:
            """The effective configuration, plus whether this client may CHANGE it.

            The view is a READ; writes go to /api/settings/plan and /api/settings/apply, which are
            token-gated. So this reports two things: the values in effect, and whether writes are
            enabled -- the UI needs the second to decide whether to render editable fields or
            read-only text, and a control that vanishes teaches nothing while a disabled one with a
            stated reason tells the operator exactly what to set.

            Secrets are reported as set or not set by `status.settings_overview`, never in value,
            and are never editable from here regardless of token state.
            """
            del query  # no parameters: the configuration is whatever is running
            # THE LIVE CLUSTER CONFIG IS THE SOURCE, not this pod's startup environment.
            # A settings change restarts the WORKER, not the GUI, so the pod env freezes at
            # its start -- and the tab rendered `loch` through a demonstrably live intercept
            # (measured on the first live test). Reading the ConfigMap per request makes the
            # tab report what the CLUSTER is running; when the cluster is unreachable the
            # pod env remains the honest fallback, and rows keep their provenance labels.
            configmap = None
            try:
                from weirvern.admin import cluster_config as cc  # noqa: PLC0415

                client = ctx.config_client or cc.ClusterConfig()
                configmap = client.read()
            except Exception as exc:  # noqa: BLE001
                logger.debug("settings: live ConfigMap unavailable (%s); showing this "
                             "process's view", exc)
            try:
                # The backend is passed so the VERSION row can report the running image tag
                # rather than the package's own literal, which had drifted (0.4.0 vs 0.5.6).
                payload = status_mod.settings_overview(
                    settings=ctx.settings, backend=ctx.backend, configmap=configmap
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning("settings view unavailable: %s", exc)
                return self._json({
                    "available": False, "groups": {},
                    "reason": f"could not read the configuration: {type(exc).__name__}",
                })
            # Whether THIS caller may offer writes, and why not when they may not. Sent with
            # every settings read so the panel can DISABLE rather than hide: a control that
            # vanishes teaches nothing, a disabled one with a stated reason tells the operator
            # what to do (sign in, ask an admin, change a forced password).
            role, via = self._caller_role()
            ident = self._identity()
            if not _accounts_on(ctx):
                # Pre-accounts posture: the token is the whole story, as before.
                auth = getattr(ctx, "auth", None)
                payload["writes"] = {
                    "enabled": bool(auth and auth.enabled),
                    "reason": (auth.reason if auth else
                               "authentication is not available in this build"),
                }
            elif ident is not None and ident.must_change:
                payload["writes"] = {
                    "enabled": False,
                    "reason": "change your password before changing settings",
                }
            elif role == users_mod.ROLE_ADMIN:
                payload["writes"] = {"enabled": True, "reason": ""}
            elif role == users_mod.ROLE_VIEWER:
                payload["writes"] = {
                    "enabled": False,
                    "reason": "this account is a viewer: it can read every view but not change "
                              "settings. Ask an admin, or sign in as one.",
                }
            else:
                payload["writes"] = {
                    "enabled": False,
                    "reason": "sign in with an admin account to change settings.",
                }
            # WHO the settings write gate sees, for the panel to name the caller instead of
            # saying "an operator" -- the audit trail starts with the page saying who you are.
            payload["caller"] = {"username": (ident.username if ident else ""),
                                 "role": role, "via": via}
            # The editable keys, so the UI offers exactly what the server will accept -- derived
            # here rather than duplicated in JavaScript.
            try:
                from weirvern.admin.cluster_config import (
                    EDITABLE_KEYS,
                    SETTING_CONTROLS,
                    to_row_key,
                )

                # LOWER-CASED TO MATCH THE ROW KEYS. EDITABLE_KEYS are the ConfigMap's own
                # key names (BASE_THRESHOLD, ...) because that is what an apply writes; the
                # settings rows the GUI renders use lowercase Settings attribute names
                # (base_threshold, ...). Sending the upper-case form made the intersection the
                # front end computes empty, so EVERY field rendered read-only and Apply was
                # disabled forever: the whole token/plan/apply path was unreachable while the
                # server would have accepted a POST. Normalise here, at the boundary, so the
                # two vocabularies only ever meet in one place.
                payload["editable_keys"] = [to_row_key(k) for k in EDITABLE_KEYS]
                # The CONTROL each editable key renders as (toggle / select / number / text),
                # in the ROW vocabulary, with numeric bounds and select options. The browser
                # uses this to render the natural control instead of a free-text box, and the
                # bounds come from the same table `validate()` enforces -- the control and the
                # rule cannot disagree because they are one table.
                payload["controls"] = {to_row_key(k): dict(v) for k, v in SETTING_CONTROLS.items()}

                # ── THE DRIFT WARNING (audit F016) ────────────────────────────────────────────
                #
                # CONFIRMED BY RUNNING IT against a live cluster: the GUI wrote
                # DETECT_INTERVAL_S=240, the response reported success and rolled the worker, and
                # the very next `kubectl apply -k k8s/` put it back to 300. The ConfigMap is owned
                # by a manifest, so an apply is entitled to restore it -- the revert is correct
                # Kubernetes behaviour, and the DEFECT was that nothing told the operator.
                #
                # So the view now says it. For every key the GUI has written whose manifest value
                # would override it, the operator gets the value they chose, when they chose it,
                # and the fact that a deploy can take it away. Without this the settings page
                # cannot be trusted on a cluster that gets deployed to, which is all of them.
                #
                # `drift` is a LIST of rows rather than a boolean, because "this page has drifted"
                # is not actionable and "DETECT_INTERVAL_S: you set 240 on the 23rd, a deploy will
                # restore 300" is.
                try:
                    from weirvern.admin.cluster_config import ClusterConfig
                    # THE COMPUTATION LIVES IN `settings_drift`, not here. An earlier version
                    # computed it inline and the tests reimplemented it to check it -- mutation
                    # testing showed that proved NOTHING about this view: breaking the `reverted`
                    # expression here left the whole suite green. One implementation, called by
                    # both, is the only shape where a test of the logic is a test of the view.
                    #
                    # It reads the LIVE ConfigMap, not the rows this view builds: those are the
                    # PROCESS's effective settings, which for the GUI means the values it started
                    # with, so comparing against them would report "reverted" on a healthy cluster
                    # and "fine" on a reverted one.
                    drift = [
                        {**row, "key": to_row_key(row["key"])}
                        for row in ClusterConfig(configmap="weirvern-env").settings_drift()
                    ]
                    payload["gui_written"] = drift
                    if drift:
                        payload["gui_written_note"] = (
                            "These keys were set through this page, not by k8s/*.yaml. "
                            "`kubectl apply -k` restores the manifest's value, so a deploy reverts "
                            "them. Re-apply the setting after a deploy, or put it in "
                            "k8s/20-configmap-env.yaml to make it permanent."
                        )
                except Exception:  # noqa: BLE001
                    # The warning is advisory. A cluster that cannot be read must still render the
                    # page, since that is how an operator would diagnose it.
                    payload["gui_written"] = []
            except Exception:  # noqa: BLE001
                payload["editable_keys"] = []
                payload["controls"] = {}

            self._json(payload)

        def _host(self, query: dict) -> None:
            addr = (query.get("addr") or [""])[0].strip()
            if not addr:
                return self._error(400, "addr is required, e.g. /api/host?addr=198.51.100.5")
            # Validate before it reaches a query parameter. clickhouse-connect
            # parameterises these, so this is not the only defence, but an
            # obviously-wrong address should not become a database round trip.
            if len(addr) > 64 or not all(c.isalnum() or c in ".:-_" for c in addr):
                return self._error(400, "addr does not look like an IP address or hostname")
            hours = _int_arg(query, "hours", 24, 1, 24 * 14)
            try:
                with self._with_client() as client:
                    detail = status_mod.host_detail(client, addr, hours=hours)
            except Exception as exc:  # noqa: BLE001
                return self._error(503, f"cannot reach ClickHouse: {exc}")
            self._json(web_api.host_payload(detail))

        def _evidence(self, query: dict) -> None:
            """The alert-evidence pivot: the RAW records inside one detection window.

            Same validation and error posture as _host: the address is shape-checked
            before it becomes a query parameter, and a database failure is a 503 with
            the reason rather than an empty page.
            """
            addr = (query.get("addr") or [""])[0].strip()
            if not addr:
                return self._error(
                    400, "addr is required, e.g. /api/evidence?addr=198.51.100.5&start=2026-09-17T16:37:00")
            if len(addr) > 64 or not all(c.isalnum() or c in ".:-_" for c in addr):
                return self._error(400, "addr does not look like an IP address or hostname")
            start = (query.get("start") or [""])[0].strip()
            if not start:
                return self._error(
                    400, "start is required (the alert's window_start), e.g. "
                         "/api/evidence?addr=198.51.100.5&start=2026-09-17T16:37:00")
            # Length-capped so a pathological value cannot reach the parser. The
            # query parameterises it, and parseDateTime64BestEffort is tolerant.
            if len(start) > 64:
                return self._error(400, "start is not a valid timestamp")
            end = (query.get("end") or [""])[0].strip() or None
            if end is not None and len(end) > 64:
                return self._error(400, "end is not a valid timestamp")
            try:
                with self._with_client() as client:
                    data = status_mod.alert_evidence(client, addr, start, end)
            except Exception as exc:  # noqa: BLE001
                return self._error(503, f"cannot reach ClickHouse: {exc}")
            self._json(web_api.evidence_payload(data))

        def _fingerprints(self, query: dict) -> None:
            """Which hosts have presented a given JA4 fingerprint -- the hunting pivot.

            The identity card answers "what does this host use?"; this answers "who else uses
            this stack?", which is the direction an analyst actually arrives from: a fingerprint
            seen in one alert, then every other host that presents it. The token is shape-checked
            before it becomes a query parameter, and a database failure is a 503 with the reason
            rather than an empty list that would read as "nobody uses this".
            """
            ja4 = (query.get("ja4") or [""])[0].strip()
            if not ja4:
                return self._error(
                    400, "ja4 is required, e.g. /api/fingerprints?ja4=t13d1516h2_...")
            if len(ja4) > 128 or not all(c.isalnum() or c in "._-:" for c in ja4):
                return self._error(400, "ja4 does not look like a fingerprint")
            try:
                with self._with_client() as client:
                    payload = status_mod.fingerprint_hosts(client, ja4)
            except Exception as exc:  # noqa: BLE001
                return self._error(503, f"cannot reach ClickHouse: {exc}")
            self._json(payload)

    return Handler


def _int_arg(query: dict, name: str, default: int, lo: int, hi: int) -> int:
    """Parse and CLAMP an integer query parameter.

    Clamping rather than rejecting: a client asking for limit=99999 gets the
    maximum allowed, which is friendlier than an error and still protects the
    database from an unbounded scan.
    """
    try:
        value = int((query.get(name) or [default])[0])
    except (TypeError, ValueError):
        return default
    return max(lo, min(hi, value))


def _float_arg(query: dict, name: str, default: float, lo: float, hi: float) -> float:
    try:
        value = float((query.get(name) or [default])[0])
    except (TypeError, ValueError):
        return default
    return max(lo, min(hi, value))


def _query_bool(query: dict, name: str) -> bool | None:
    """A tri-state query flag: True, False, or None when the parameter is absent.

    None is distinct from False on purpose: `unreviewed=` with no value is not the same
    statement as `unreviewed` absent entirely, and a caller that wanted the second must
    not silently get the first. Only explicit truthy spellings turn the flag on.
    """
    if name not in query:
        return None
    raw = (query.get(name) or [""])[0]
    return str(raw).strip().lower() in ("1", "true", "yes", "on", "")


class GuiServer:
    """Threaded HTTP server with a clean stop() for tests and signal handlers."""

    def __init__(self, ctx: GuiContext, host: str = DEFAULT_HOST,
                 port: int = DEFAULT_PORT):
        self._httpd = ThreadingHTTPServer((host, port), _build_handler(ctx))
        # daemon_threads so a request in flight cannot block interpreter exit.
        self._httpd.daemon_threads = True
        self.host = host
        self.port = self._httpd.server_address[1]
        self._thread: threading.Thread | None = None

    def serve_forever(self) -> None:
        self._httpd.serve_forever()

    def start_background(self) -> GuiServer:
        self._thread = threading.Thread(target=self.serve_forever, daemon=True,
                                        name="weirvern-gui")
        self._thread.start()
        return self

    def stop(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()


def build_context(connect_factory, settings, project_dir: Path,
                  namespace: str | None = None) -> GuiContext:
    """Assemble the context the handler needs, tolerating a missing cluster.

    The GUI must start and explain itself even when kubectl is absent or the
    cluster is unreachable: a dashboard that refuses to launch when the thing it
    monitors is down is useless precisely when it is needed.

    `namespace` is accepted for symmetry with the CLI and is NOT passed to
    get_backend, which resolves it from the project dir (see runtime.NAMESPACE).
    """
    del namespace  # resolved by get_backend from the project dir
    backend = None
    caps = None
    try:
        from weirvern.admin.runtime import detect_capabilities, get_backend

        caps = detect_capabilities(project_dir)
        if caps.cluster_available:
            backend = get_backend(project_dir, caps)
    except Exception as exc:  # noqa: BLE001
        logger.debug("GUI starting without cluster access: %s", exc)
    # WRITES ARE OFF UNLESS A TOKEN IS CONFIGURED. `from_env` reads it once, so a partially
    # applied ConfigMap cannot serve a half-written token mid-request.
    auth = None
    try:
        from weirvern.admin import gui_auth

        auth = gui_auth.from_env()
        if auth.enabled:
            logger.info("GUI writes enabled (operator token configured)")
        else:
            logger.info("GUI is read-only: %s", auth.reason)
    except Exception as exc:  # noqa: BLE001
        logger.warning("could not initialise GUI auth: %s", exc)

    # The ConfigMap client, for the write path. Constructed unconditionally: whether the
    # in-cluster token exists is discovered when a write is attempted, and a read-only GUI
    # must still start on a box with no cluster at all.
    try:
        from weirvern.admin.cluster_config import ClusterConfig

        config_client = ClusterConfig()
    except Exception as exc:  # noqa: BLE001
        logger.debug("no cluster config client: %s", exc)
        config_client = None

    # THE ACCOUNT STORE. A second ConfigMap through the same in-cluster client -- see
    # weirvern/admin/users.py for why accounts are a ConfigMap and not a Secret, and why
    # they live in the cluster rather than in ClickHouse (a login gate must work when the
    # database does not). Read once here; a login never touches the API.
    user_store = None
    sessions = users_mod.SessionRegistry()
    throttle = users_mod.LoginThrottle()
    accounts_note = ""
    try:
        from weirvern.admin.cluster_config import ClusterConfig as _CC

        users_client = _CC(configmap=users_mod.USERS_CONFIGMAP)
        store = users_mod.UserStore(users_client)
        store.load()
        # THE BOOTSTRAP, at startup rather than at first login. It logs the generated
        # password ONCE; see users.bootstrap.
        result = users_mod.bootstrap(store, log=logger)
        if result.created:
            accounts_note = ("the initial admin account was created on first startup; its "
                             "password was logged once by this pod and is not recoverable. "
                             "Use the reset flow if it was lost.")
        elif result.note:
            accounts_note = result.note
        user_store = store
    except Exception as exc:  # noqa: BLE001
        logger.warning("could not initialise the account store: %s", exc)
        accounts_note = f"the account store could not be initialised: {exc}"

    return GuiContext(connect_factory, settings, backend=backend, capabilities=caps,
                      auth=auth, config_client=config_client, user_store=user_store,
                      sessions=sessions, throttle=throttle, accounts_note=accounts_note)


def run(connect_factory, settings, project_dir: Path, namespace: str,
        host: str | None = None, port: int | None = None) -> int:
    """Serve until interrupted. Returns a process exit code."""
    host = host or os.environ.get("GUI_HOST", DEFAULT_HOST)
    port = port or int(os.environ.get("GUI_PORT", str(DEFAULT_PORT)))
    ctx = build_context(connect_factory, settings, project_dir, namespace)
    server = GuiServer(ctx, host, port)
    logger.info("Weirvern GUI on http://%s:%d", host, server.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("GUI stopping")
    finally:
        server.stop()
    return 0
