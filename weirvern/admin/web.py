"""The web GUI: a read-only HTTP server over the same data the TUI shows.

WHY THE STANDARD LIBRARY, DELIBERATELY:

No new runtime dependency. FastAPI + uvicorn is roughly 15 MB in the image for
five read-only routes, and this project has repeatedly been bitten by deployment
friction (a missing extra broke CI once already, and the worker image is meant to
stay small enough to pull quickly on a homelab). `http.server` is in every Python
installation, so the GUI works with no extra install step at all — which matters
more than idiom for a tool that has to be deployable by someone who has never seen
it before.

This is defensible specifically BECAUSE the surface is read-only and small. If this
ever grows request bodies, auth, or websockets, that is the point to move to a real
framework, and `web_api.py` is already framework-agnostic so only this file changes.

WHY READ-ONLY, AND WHY THAT IS A SECURITY DECISION:

There is no code path from an HTTP request to a mutating cluster operation. Start,
stop and apply stay in the CLI and TUI, which the operator runs knowingly. That is
what makes it acceptable to bind this to a LAN address at all: an unauthenticated
dashboard that cannot change anything is a much smaller risk than one that can. If
lifecycle buttons are ever added, they need authentication FIRST — this server has
none, and adding a button without it would silently expose cluster control to
anyone who can reach the port.

BINDING: defaults to 127.0.0.1 so that starting the GUI on a workstation does not
unexpectedly publish it. The Kubernetes Deployment sets GUI_HOST=0.0.0.0
explicitly, where being reachable is the entire point and the Service controls who
can get to it.
"""
from __future__ import annotations

import contextlib
import json
import logging
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from weirvern.admin import soc as soc_mod
from weirvern.admin import status as status_mod
from weirvern.admin import web_api

logger = logging.getLogger(__name__)

STATIC_DIR = Path(__file__).resolve().parent / "web"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8088

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


class GuiContext:
    """Everything a request handler needs, assembled once at startup.

    Holds the connection factory rather than a live client: the connection is
    opened per request and closed after, because ClickHouse connections are not
    safe to share across threads and ThreadingHTTPServer serves each request on its
    own thread. The alternative — a global client with a lock — serialises every
    request and makes one slow query block the whole UI.
    """

    def __init__(self, connect_factory, settings, backend=None, capabilities=None):
        self.connect_factory = connect_factory
        self.settings = settings
        self.backend = backend
        self.capabilities = capabilities


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
            if path == "/api/overview":
                return self._overview()
            if path == "/api/anomalies":
                return self._anomalies(query)
            if path == "/api/host":
                return self._host(query)
            if path == "/api/evidence":
                return self._evidence(query)
            if path == "/api/models":
                return self._models(query)
            if path == "/api/netflow":
                return self._netflow(query)
            if path == "/api/zeek":
                return self._zeek(query)
            # The DEEP health view. Distinct from /api/healthz on purpose: that one is the
            # Kubernetes liveness probe and must NOT read ClickHouse (a slow database would
            # restart the GUI and hide the real problem); this one exists precisely to answer
            # "is data still arriving", which requires reading it.
            if path == "/api/health":
                return self._health(query)
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
                    report = status_mod.collect_health(client, ctx.settings)
                    anomalies = status_mod.anomalies_detailed(client, limit=25)
                    talkers = status_mod.top_talkers(client, limit=10)
                    # What the sensor reports about itself. Separate from the health
                    # checks above, which answer "is data flowing", not "what is the
                    # sensor doing" -- and for weir that distinction is the whole point:
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
            try:
                with self._with_client() as client:
                    rows = status_mod.anomalies_detailed(
                        client, limit=limit, min_score=min_score)
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
                    data = status_mod.model_overview(client, hours=hours)
            except Exception as exc:  # noqa: BLE001
                return self._json({"available": False,
                                   "reason": f"cannot reach ClickHouse: {exc}"})
            self._json(web_api.models_payload(data))

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
            except Exception as exc:  # noqa: BLE001
                logger.warning("netflow view unavailable: %s", exc)
                return self._json({"volume": empty, "protocols": empty, "ports": empty,
                                   "spread": empty, "talkers": [],
                                   "data_error": f"cannot reach ClickHouse: {exc}"})
            self._json(web_api.netflow_payload(volume, proto, ports, spread, talkers))

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
            try:
                with self._with_client() as client:
                    report = status_mod.collect_health(client, ctx.settings)
                    sensor = status_mod.sensor_status(client)
                    ingest = soc_mod.ingestion_series(client, hours=hours)
                    sizes = soc_mod.table_sizes(client)
            except Exception as exc:  # noqa: BLE001
                logger.warning("health view unavailable: %s", exc)
                return self._json({"health": None, "ingest": empty, "tables": empty,
                                   "sensor": {}, "data_error": f"cannot reach ClickHouse: {exc}"})
            self._json(web_api.health_deep_payload(report, ingest, sizes, sensor))

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
    return GuiContext(connect_factory, settings, backend=backend, capabilities=caps)


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
