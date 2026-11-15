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
import ipaddress
import json
import logging
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from weirvern import fleet_store
from weirvern.admin import assets as assets_mod
from weirvern.admin import payloads, requestauth, timewindow, web_api
from weirvern.admin import soc as soc_mod
from weirvern.admin import status as status_mod
from weirvern.admin import users as users_mod

logger = logging.getLogger(__name__)


def _iso(value: object) -> str:
    """Render a datetime-like ClickHouse value without assuming the row is typed."""
    fmt = getattr(value, "isoformat", None)
    return str(fmt()) if callable(fmt) else str(value or "")


def _human_age(seconds: float | int | str | None) -> str:
    """How long ago, in the unit a person reads. Unknown age says so; it never reads as zero."""
    if seconds is None:
        return "an unknown time"
    try:
        total = int(max(0.0, float(seconds)))
    except (TypeError, ValueError):
        return "an unknown time"
    if total < 90:
        return f"{total}s"
    if total < 5400:
        return f"{total // 60}m"
    if total < 172800:
        return f"{total // 3600}h"
    return f"{total // 86400}d"


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
    # The sheet standard: one opener/closer for every right-edge editing surface (scrim,
    # Escape, focus). Loaded after app.js and before the views that open a sheet.
    "/sheets.js": ("sheets.js", "application/javascript; charset=utf-8"),
    "/sluice.js": ("sluice.js", "application/javascript; charset=utf-8"),
    # The Weirlings fleet tab. Its own file for the same reason as the others, and because
    # "which sensors are expected, and which of them are silent" is a distinct concern from both
    # the dashboard and the gate -- and because the state model it renders (five states that must
    # never be collapsed) is code a reader should be able to find in one place.
    "/weirlings.js": ("weirlings.js", "application/javascript; charset=utf-8"),
    # The Discover tab: the raw-flow browser. Its own file for the same reason as the others --
    # "show me the flows themselves, filtered" is a distinct concern from every chart above it.
    "/discover.js": ("discover.js", "application/javascript; charset=utf-8"),
    "/dnsview.js": ("dnsview.js", "application/javascript; charset=utf-8"),
    "/blocked.js": ("blocked.js", "application/javascript; charset=utf-8"),
    # The command palette (BF-11). Its own file for the same reason as the others -- and
    # because the shortcut grammar is code a reader should find in one place.
    "/palette.js": ("palette.js", "application/javascript; charset=utf-8"),
    "/style.css": ("style.css", "text/css; charset=utf-8"),
    # The logo, so the dashboard is branded rather than a generic admin page. Served
    # from the same allow-list as everything else; the image is read-only and static.
    "/logo.png": ("logo.png", "image/png"),
    # Installable web app: the manifest, its two raster sizes, and the network-only service
    # worker that gives the installed app an app shell without caching stale dashboards.
    "/manifest.webmanifest": ("manifest.webmanifest", "application/manifest+json"),
    # iOS asks for this conventional root path; explicit sizes are what stops Safari from
    # falling back to a generated letter tile when the link had no size metadata.
    "/apple-touch-icon.png": ("apple-touch-icon.png", "image/png"),
    "/icon-192.png": ("icon-192.png", "image/png"),
    "/icon-512.png": ("icon-512.png", "image/png"),
    "/sw.js": ("sw.js", "application/javascript; charset=utf-8"),
    # The crisp vector mark (TH-1): the raster was pixelated at header sizes; the SVG scales
    # clean. logo.png stays served for apple-touch-icon, which wants a raster.
    "/logo.svg": ("logo.svg", "image/svg+xml"),
    "/favicon.svg": ("favicon.svg", "image/svg+xml"),
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



# ── A READ FAILURE IS WORDED BY WHAT WAS OBSERVED (WV1-20) ────────────────────────────────────
#
# Every data path in this module reported `cannot reach ClickHouse: {exc}` regardless of cause --
# 39 sites. Measured on a box with no database and no kubectl, /api/health returned
#
#     "data_error": "cannot reach ClickHouse: [Errno 2] No such file or directory: 'kubectl'"
#
# so the cause was a missing binary and the message asserted a database fault. cli.py already
# records this exact confusion as a known trap: "the symptom appears as 'the GUI cannot reach
# ClickHouse', which sends you looking" in the wrong place. The GUI went on producing it anyway.
#
# The distinction the reader needs is only this: a connection-shaped failure is a ClickHouse
# problem to chase, anything else (a missing binary, a permission, a bad value) is not, and saying
# "ClickHouse" for those costs someone an afternoon.
_CONNECT_HINTS = (
    "connection refused", "connect call failed", "timed out", "timeout", "unreachable",
    "no route to host", "name or service not known", "nodename nor servname",
    "temporary failure in name resolution", "connection reset", "broken pipe",
    "max retries exceeded", "failed to establish a new connection", "econnrefused",
    "econnreset", "ehostunreach", "enetunreach",
)


def read_failure(exc: BaseException | None) -> str:
    """Word a failed read by what was observed, not by the layer we assume broke."""
    if exc is None:
        return "the data could not be read"
    detail = type(exc).__name__
    text = str(exc).strip()
    if text:
        detail = f"{detail}: {text}"
    lowered = text.lower()
    if isinstance(exc, (ConnectionError, TimeoutError)) or any(h in lowered for h in _CONNECT_HINTS):
        return f"cannot reach ClickHouse: {detail}"
    return f"could not read the data: {detail}"


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


def _interface_network_names(raw: str) -> dict[str, str]:
    """`eth1=Servers,eth2=DMZ` -> {iface: label}. Labels only; malformed tokens are ignored."""
    out: dict[str, str] = {}
    for token in str(raw or "").split(","):
        iface, sep, name = token.partition("=")
        iface, name = iface.strip(), name.strip()
        if sep and iface and name:
            out[iface] = name
    return out


def _flow_exporters(sensors: list[dict]) -> dict[str, list[str]]:
    """Which sampler addresses belong to each sensor.

    A LOCAL sensor's goflow2 writes from loopback even when the sensor's heartbeat carries a
    management address. Checking the address first made the local row query 192.0.2.176 while
    every row in ClickHouse said 127.0.0.1: the fleet showed netflow "not observed" and an
    empty trend beside a Netflow tab full of flows. A remote sensor uses its own address.
    """
    out: dict[str, list[str]] = {}
    for r in sensors or []:
        sid = str(r.get("sensor_id") or "")
        addr = str(r.get("address") or "").strip()
        if r.get("local"):
            addrs = [addr] if addr else []
            addrs.extend(["127.0.0.1", "::1"])
            out[sid] = list(dict.fromkeys(a for a in addrs if a))
        else:
            out[sid] = [addr] if addr else []
    return out


def _attach_anomaly_locations(rows: list, sensors: list,
                             network_names: dict[str, str] | None = None) -> None:
    """Where each alert happened: the weirling that sees that network, and the network.

    Anomalies carry no sensor id -- the detector scores a host window, not a sensor -- so the
    location is resolved from the address against the fleet's declared segments. Most specific
    network wins. A host outside every declared segment carries NO location rather than a guess
    (the UI says "unplaced"), because naming a weirling that cannot see the address would be a
    lie the operator would act on.

    `network_names` (operator, 2026-10-19) gives an interface its human label -- Servers, DMZ --
    and that label rides the location beside the CIDR so an alert says where it happened in the
    operator's vocabulary, not only in addresses.
    """
    import ipaddress as _ip  # noqa: PLC0415

    names = network_names or {}
    nets = []
    for s in sensors or []:
        sid = str(s.get("sensor_id") or "")
        for seg in {s.get("segment"), s.get("reported_segment")}:
            seg = str(seg or "").strip()
            if not seg:
                continue
            try:
                net = _ip.ip_network(seg, strict=False)
            except ValueError:
                continue
            if net.version == 4:
                nets.append((net, sid, str(s.get("iface") or "")))
    for r in rows or []:
        try:
            addr = _ip.ip_address(str(r.get("src_addr") or "").strip())
        except ValueError:
            continue
        matches = [(n, sid, iface) for n, sid, iface in nets if addr in n]
        if not matches:
            continue
        matches.sort(key=lambda x: x[0].prefixlen, reverse=True)
        net, sid, iface = matches[0]
        r["location"] = {"weirling": sid, "network": str(net)}
        label = names.get(iface, "")
        if label:
            r["location"]["network_name"] = label


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
        def _forwarded_proto(self) -> str:
            """The scheme Traefik saw, not the scheme it used to reach this pod.

            The GUI still speaks HTTP to its Service; TLS terminates at the local ingress.
            `X-Forwarded-Proto` is the only place the browser-facing scheme exists. Treat a
            missing header as direct/plain HTTP so a port-forward never silently loses the
            HSTS/redirect guard rails.
            """
            value = (self.headers.get("X-Forwarded-Proto", "") or "").split(",", 1)[0]
            return value.strip().lower()

        def _security_headers(self) -> None:
            """Add HSTS only on the secure path, where a browser can honour it."""
            proto = self._forwarded_proto()
            if proto == "https":
                self.send_header("Strict-Transport-Security",
                                 "max-age=31536000; includeSubDomains")

        def _redirect_to_https(self) -> bool:
            """Return True when this request was redirected before it reached a route.

            The HTTP Ingress exists only to make this redirect. The app sees the ingress's
            `X-Forwarded-Proto: http`; without the header (direct NodePort or a port-forward)
            we deliberately do not guess a public scheme.
            """
            if self._forwarded_proto() != "http":
                return False
            host = (self.headers.get("Host", "") or "").strip()
            if not host:
                return False
            location = "https://" + host + self.path
            self.send_response(308)
            self.send_header("Location", location)
            self.send_header("Content-Length", "0")
            self.send_header("Cache-Control", NO_CACHE)
            self.end_headers()
            return True

        def _send(self, code: int, body: bytes, content_type: str) -> None:
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", NO_CACHE)
            # The dashboard is same-origin only; denying framing and sniffing is
            # free and removes a class of browser-side abuse.
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self._security_headers()
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
            if self._redirect_to_https():
                return
            # The time window a request sets (from/to, absolute) lives in a ContextVar that
            # query builders read. A thread serves many requests, so a window left over from
            # the previous one would answer this request against the wrong stretch of time:
            # cleared here, set again by `_window_arg` only when the request asks for one.
            timewindow.clear_window()
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
            if path == "/api/audit":
                return self._audit()
            # US-10: THE WRITE TRAIL. The fleet_audit table was append-only and invisible;
            # this is its read surface (newest first, filterable by scope / action / target).
            if path == "/api/write-trail":
                return self._write_trail(query)
            if path == "/api/detectors":
                return self._detectors()
            if path == "/api/anomalies":
                return self._anomalies(query)
            if path == "/api/episodes":
                return self._episodes(query)
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
            if path == "/api/incident":
                return self._incident(query)
            if path == "/api/fingerprints":
                return self._fingerprints(query)
            if path == "/api/models":
                return self._models(query)
            if path == "/api/ml/coverage":
                return self._ml_coverage()
            if path == "/api/ml/ripple":
                return self._ml_ripple()
            if path == "/api/ml/data-contract":
                return self._ml_data_contract()
            if path == "/api/ml/slo":
                return self._ml_slo()
            if path == "/api/ml/review":
                return self._ml_review()
            if path == "/api/ml/eval-report":
                return self._ml_eval_report()
            if path == "/api/ml/ledger":
                return self._ml_ledger()
            if path == "/api/models/calibration":
                return self._models_calibration()
            if path == "/api/models/shadow":
                return self._models_shadow()
            # AB-1: the per-host adaptive baselines -- what each host normally does, and
            # what the baseline has flagged. A read, like the rest of the monitoring data.
            if path == "/api/baselines":
                return self._baselines()
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
            # DISCOVER: the raw-flow browser (Kibana's Discover, over `flows`). A GET with a
            # filter bar -- flow type, address, port, sensor -- and paging.
            if path == "/api/discover":
                return self._discover(query)
            # Three header sparklines (operator, 2026-10-19): feed health at a glance,
            # without paging three raw feeds through the browser.
            if path == "/api/discover/trends":
                return self._discover_trends(query)
            # DNS ON PORT 53, MADE READABLE: the operator's ask ("can we view dns"). Rows are
            # Q/A pairs out of `zeek_dns`; the reverse side (address -> names) comes from the
            # materialized map in schema/016, which is also what domain rules resolve through.
            if path == "/api/dns":
                return self._dns(query)
            if path == "/api/dns/reverse":
                return self._dns_reverse(query)
            # THE BLOCKED LEDGER (the operator's ask: "We need a blocked tab too"): recorded
            # hits plus the live rules split by what they do now, with the gate's state along.
            if path == "/api/blocked":
                return self._blocked(query)
            if path == "/api/flows":
                return self._flows(query)
            # The asset inventory and the connection graph. Separate endpoints from /api/host
            # because /api/host answers "tell me about THIS address" while these answer "what
            # hosts exist" and "how are they wired" -- and the graph needs different tables
            # (raw `flows` for per-edge facts, which the aggregate cannot provide).
            if path == "/api/assets":
                return self._assets(query)
            # The other half of the inventory: what CHANGED between scans. Read-only; the
            # posture score is shadow data and never gates traffic.
            if path == "/api/findings":
                return self._findings(query)
            if path == "/api/asset-changes":
                return self._asset_changes(query)
            if path == "/api/asset-posture":
                return self._asset_posture()
            # Manual scans are a read here (the queue) and a write below (the request). The
            # scanner claims the row; this route never runs Nmap in the web process.
            if path == "/api/scan-jobs":
                return self._scan_jobs(query)
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
                return self._sluice(query)
            if path == "/api/blocklists":
                return self._blocklists_get()
            if path == "/api/sluice/state":
                return self._sluice_state()
            # ── WEIRLINGS (the fleet) ───────────────────────────────────────────────────────
            # GET reads the fleet. Reads stay open like every other tab: an operator checking
            # whether a sensor is reporting should not need a password. The writes are POST
            # below and pass the operator gate, so a viewer cannot register or retire a sensor.
            if path == "/api/weirlings":
                return self._weirlings(query)
            if path == "/api/scanner":
                return self._scanner()
            if path == "/api/weirlings/detail":
                return self._weirlings_detail(query)
            if path == "/api/weirlings/probe":
                return self._weirlings_probe_get(query)
            # The DEEP health view. Distinct from /api/healthz on purpose: that one is the
            # Kubernetes liveness probe and must NOT read ClickHouse (a slow database would
            # restart the GUI and hide the real problem); this one exists precisely to answer
            # "is data still arriving", which requires reading it.
            if path == "/api/health":
                return self._health(query)
            # Host CPU/memory and interface counters. A reading surface, not a write route;
            # it reads the host's procfs mounted read-only at /host-proc.
            if path == "/api/system":
                return self._system(query)
            # RELEASE METADATA, read-only. The Settings card may check whether a newer
            # release exists; it never applies one. See weirvern/admin/update.py.
            if path == "/api/update":
                return self._update(query)
            # The EFFECTIVE configuration, read-only. See _settings for why it cannot write.
            if path == "/api/settings":
                return self._settings(query)
            # OPERATOR-DECLARED NETWORK SCOPES. A read like settings: viewers may see what is
            # monitored; only an admin may change it (the POST routes below enforce write authorization).
            if path == "/api/networks":
                return self._networks(query)
            if path == "/panic":
                return self._panic()
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
            # SHARED WITH THE FLASK SURFACE (payloads.overview). It takes `_with_client` rather than
            # an open client because the service list is read BEFORE the database is touched, and a
            # database that will not connect must still leave the page something true to say.
            self._json(payloads.overview(
                self._with_client, backend=ctx.backend, settings=ctx.settings,
                user_store=getattr(ctx, "user_store", None), capabilities=ctx.capabilities))

        def _anomalies(self, query: dict) -> None:
            hours = self._window_arg(query, 24, 1, 24 * 14)
            if hours is None:
                return
            try:
                args = anomalies_args(query)
            except ValueError as exc:
                return self._error(400, str(exc))
            try:
                with self._with_client() as client:
                    # SHARED WITH THE FLASK SURFACE (payloads.anomalies): the grouped rows, the
                    # header tiles and every per-row state ride one fetcher, so the two surfaces
                    # cannot disagree about which alerts are unreviewed or watched.
                    payload = payloads.anomalies(
                        client, hours=hours, settings=ctx.settings, **args)
            except Exception as exc:  # noqa: BLE001
                return self._error(503, read_failure(exc))
            self._json(payload)
        def _episodes(self, query: dict) -> None:
            """One row per incident: the episode view, not the five-minute window list."""
            limit = _int_arg(query, "limit", 100, 1, 1000)
            hours = self._window_arg(query, 24, 1, 24 * 14)
            if hours is None:
                return
            try:
                with self._with_client() as client:
                    # THE FETCH AND THE FORMAT ARE SHARED (weirvern/admin/payloads.py). The Flask
                    # surface calls this same function, so the two queues cannot disagree about a
                    # hostname or a payload key.
                    payload = payloads.episodes(client, hours=hours, limit=limit)
            except Exception as exc:  # noqa: BLE001
                return self._error(503, read_failure(exc))
            self._json(payload)

        def _panic(self) -> None:
            """The no-JS fallback page (BF-14). Read-only; every section self-guards."""
            import datetime as _dt  # noqa: PLC0415

            from weirvern import fleet_store  # noqa: PLC0415

            fleet = None
            audit = None
            alerts = None
            try:
                with self._with_client() as client:
                    try:
                        fleet = fleet_store.build_fleet(client)
                        # THE STALENESS STAMP: the newest heartbeat is the data's own clock.
                        # Read from the FLEET ROWS, which carry the parsed ISO timestamp --
                        # the raw heartbeat rows are a different shape, and reading the wrong
                        # one silently produced a page with no stamp at all (caught by the
                        # box probe, 2026-10-17).
                        newest = max((str(r.get("last_seen") or "")
                                      for r in (fleet.get("sensors") or [])), default="")
                        if newest:
                            fleet["data_as_of"] = newest
                    except Exception:  # noqa: BLE001
                        fleet = None
                    try:
                        alerts = status_mod.anomaly_discipline_counts(client)
                    except Exception:  # noqa: BLE001
                        alerts = None
                    try:
                        audit = status_mod.pipeline_audit(client)
                    except Exception:  # noqa: BLE001
                        audit = None
            except Exception:  # noqa: BLE001
                pass
            page = web_api.panic_page(
                fleet=fleet, audit=audit, alerts=alerts,
                rendered_at=_dt.datetime.now(_dt.UTC).strftime("%Y-%m-%d %H:%M:%S"))
            body = page.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self._security_headers()
            self.end_headers()
            self.wfile.write(body)

        def _write_trail(self, query: dict) -> None:
            """US-10: the write trail, newest first, filterable by scope, action and target.

            Read-only like the rest of the surface. Degrades the HOUSE way: an unreadable trail
            is `available: false` with its reason, never an empty list that reads as a quiet
            history. The filter menus are derived from the table itself (distinct scopes and
            actions), so a scope can never be offered that no row has.
            """
            args = write_trail_args(query)
            with self._with_client() as client:
                # SHARED WITH THE FLASK SURFACE (payloads.write_trail). No try, deliberately: this
                # route has always answered an exception with the server's own 500, and the port
                # does not get to invent a 200 the operator never saw.
                payload = payloads.write_trail(client, **args)
            self._json(payload)

        def _audit(self) -> None:
            """The pipeline's self-audit read (BF-13). Read-only like the rest of the surface."""
            try:
                with self._with_client() as client:
                    out = status_mod.pipeline_audit(client)
            except Exception as exc:  # noqa: BLE001
                return self._error(503, read_failure(exc))
            self._json(out)

        def _detectors(self) -> None:
            """The detector registry with its catch counts: who owns what, who may page.

            Read-only and unauthenticated like the rest of the read surface -- it carries no
            operator data, only which detectors exist and what they caught.
            """
            try:
                with self._with_client() as client:
                    out = status_mod.detectors_overview(client)
            except Exception as exc:  # noqa: BLE001
                return self._error(503, read_failure(exc))
            self._json(out)

        def _models_calibration(self) -> None:
            """Shadow calibration readout; a failed read is a 200 with available:false."""
            try:
                with self._with_client() as client:
                    data = status_mod.calibration_overview(client, ctx.settings)
            except Exception as exc:  # noqa: BLE001
                return self._json({"available": False,
                                   "reason": read_failure(exc), "rows": []})
            self._json(web_api.calibration_payload(data))

        def _models_shadow(self) -> None:
            """Shadow ML channel counts; a failed read is a state, not an empty success."""
            try:
                with self._with_client() as client:
                    data = status_mod.shadow_overview(client)
            except Exception as exc:  # noqa: BLE001
                return self._json({"available": False,
                                   "reason": read_failure(exc), "rows": []})
            self._json(data)

        def _ml_ledger(self) -> None:
            """PR-3: the append-only decision trail, read-only."""
            try:
                from pathlib import Path  # noqa: PLC0415

                from weirvern.models import ledger  # noqa: PLC0415
                path = Path(__file__).resolve().parents[2] / "docs" / "ledger" / "ml-decisions.jsonl"
                rows = ledger.read(path)
                self._json({"available": bool(rows), "path": str(path), "rows": rows[-20:]})
            except Exception as exc:  # noqa: BLE001
                self._json({"available": False, "reason": f"cannot read the decision ledger: {exc}"})

        def _ml_eval_report(self) -> None:
            """CE-3: the archived fixed-budget report, read-only."""
            try:
                from pathlib import Path  # noqa: PLC0415

                from weirvern.models import eval_report  # noqa: PLC0415
                self._json(eval_report.latest_report(Path(__file__).resolve().parents[2]))
            except Exception as exc:  # noqa: BLE001
                self._json({"available": False, "reason": f"cannot read the evaluation report: {exc}"})

        def _ml_review(self) -> None:
            """OP-3: the archived review is read from disk, never recomputed in the GUI."""
            try:
                from pathlib import Path  # noqa: PLC0415

                from weirvern.models import review  # noqa: PLC0415
                root = Path(__file__).resolve().parents[2]
                self._json(review.latest_report(root))
            except Exception as exc:  # noqa: BLE001
                self._json({"available": False, "reason": f"cannot read the archived review: {exc}"})

        def _ml_slo(self) -> None:
            """OP-1: the operating numbers, with window/source and explicit not-measured states."""
            try:
                with self._with_client() as client:
                    from weirvern.models import quality  # noqa: PLC0415
                    data = quality.report(client)
            except Exception as exc:  # noqa: BLE001
                return self._json({"available": False,
                                   "reason": f"cannot read the ML SLO report: {exc}",
                                   "windows": [], "live_precision": "not measured"})
            self._json(data)

        def _ml_coverage(self) -> None:
            """GT-3: the source/role truth report. Read-only and explicitly unavailable on failure."""
            try:
                with self._with_client() as client:
                    from weirvern.models import source_coverage  # noqa: PLC0415
                    data = source_coverage.collect(client)
            except Exception as exc:  # noqa: BLE001
                return self._json({"available": False,
                                   "reason": f"cannot read source coverage: {exc}",
                                   "sources": [], "roles": {}, "models": [],
                                   "promotion_ok": False})
            self._json(data)

        def _ml_ripple(self) -> None:
            """RIP-5: the latest fused ripple evaluation; unavailable is a named state.

            The payload carries the whole explanation -- contributors, families, scales and the
            named unknown channels -- because the question this view answers is "why did it or
            did it not fire", not "what is the score".
            """
            try:
                with self._with_client() as client:
                    data = status_mod.ripple_overview(client)
            except Exception as exc:  # noqa: BLE001
                return self._json({"available": False,
                                   "reason": read_failure(exc),
                                   "rows": [], "pageable": False, "counts": {},
                                   "contributors": [], "scales": [], "families": [],
                                   "unknown": []})
            self._json(data)

        def _ml_data_contract(self) -> None:
            """DATA-0: what 'covered' means, measured against the live tables.

            The answer carries the denominator (monitored hosts), the per-source state and
            accepted missingness, the per-host coverage and the family usability. A failure is
            `available:false` with the reason, never an empty list that reads as full coverage.
            """
            try:
                with self._with_client() as client:
                    from weirvern.models import data_contract  # noqa: PLC0415
                    data = data_contract.inventory(client)
            except Exception as exc:  # noqa: BLE001
                return self._json({"available": False,
                                   "reason": f"cannot read the data contract: {exc}",
                                   "sources": [], "families": [], "gaps": [], "hosts": [],
                                   "population": {}, "promotion_ok": False})
            self._json(data)

        def _models(self, query: dict) -> None:
            """Model overview: training history, score spread, agreement, deviations.

            Returns 200 with {"available": false, "reason": ...} when the data cannot be
            read, rather than 503. A missing panel should say why it is missing; an
            error page for one panel would take down the views around it.
            """
            hours = self._window_arg(query, 72, 1, 24 * 30)
            if hours is None:
                return
            try:
                with self._with_client() as client:
                    # SHARED WITH THE FLASK SURFACE (payloads.models): the registry read and its
                    # own failure state travel with the overview, so a broken card query cannot
                    # hide the training history on one surface and not the other.
                    payload = payloads.models(client, hours=hours, settings=ctx.settings)
            except Exception as exc:  # noqa: BLE001
                return self._json(payloads.models_failure(exc))
            self._json(payload)

        def _baselines(self) -> None:
            """The per-host baseline snapshot: the latest row per host, when it refreshed,
            and what the detector has flagged lately. Every panel can say why it is
            missing rather than rendering as an empty list."""
            try:
                with self._with_client() as client:
                    # SHARED WITH THE FLASK SURFACE (payloads.baselines).
                    payload = payloads.baselines(client)
            except Exception as exc:  # noqa: BLE001
                # A FAILED read is a 200 with available: false and the reason, like every other
                # panel: an error page for one card would take down the views around it.
                return self._json({"available": False, "reason": read_failure(exc)})
            self._json(payload)

        def _model_retrain(self) -> None:
            """The last forced retrain: what state it is in, and what it produced.

            A FAILED read is a 200 with `available: false` and the reason, like every other panel:
            an error page for one card would take down the views around it, and an empty report
            would read as "nothing has been trained".
            """
            try:
                with self._with_client() as client:
                    # SHARED WITH THE FLASK SURFACE (payloads.model_retrain).
                    payload = payloads.model_retrain(client)
            except Exception as exc:  # noqa: BLE001
                return self._json(payloads.model_retrain_failure(exc))
            self._json(payload)

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

            # BF-9: choosing the model this deployment will serve (or discarding the candidate)
            # is a decision like any other -- the note is required for keep and trash and is
            # recorded with the actor and the time on the same row.
            ident = self._identity()
            by = ident.username if ident else "operator"
            note_in = str(body.get("note") or "").strip()
            if action in (actions.KEEP, actions.TRASH) and not note_in:
                return self._error(400, "choosing the model to serve is a decision; a note is "
                                        "required for keep and trash and is recorded with your "
                                        "name")
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

        def _window_arg(self, query: dict, default: int, lo: int, hi: int) -> int | None:
            """The request's time window: `hours` (relative) or `from`/`to` (absolute).

            The console's global time control sends BOTH: `hours` so every view still has a
            number to print, and `from`/`to` when the operator chose an absolute range. The
            absolute pair wins and is installed for the whole request (weirvern/admin/
            timewindow.py), so every windowed query answers the same stretch of time. A bad
            range is a 400 with the reason -- silently falling back to `hours` would answer a
            different question than the one that was asked.
            """
            # ONE IMPLEMENTATION (see window_arg above). This method keeps the job it alone can do:
            # turning the reason into a 400 on THIS response.
            try:
                return window_arg(query, default, lo, hi)
            except ValueError as exc:
                self._error(400, f"bad time range: {exc}")
                return None

        def _netflow(self, query: dict) -> None:
            """Netflow shape: volume trend, protocols, ports, fan-out, talkers.

            Every sub-query returns {"available", "reason"} rather than a bare list, and a
            failure in one does NOT take the others down -- a chart that cannot be drawn
            says so in place, while the charts beside it still render. Returns 200 even
            when ClickHouse is unreachable, for the same reason `_models` does: an error
            page for one panel would blank the views around it.
            """
            hours = self._window_arg(query, 24, 1, 24 * 14)
            if hours is None:
                return
            # THE DASHBOARD-WIDE FILTER (the operator, 2026-10-16: "if i click in any dashboard it
            # should filter that entire dashboard"): one source address, one protocol, one
            # destination port -- every panel below receives them, and the aggregate-backed panels
            # switch to the raw table when proto/port demand it (soc.flow_filter).
            try:
                filters = netflow_filters(query)
            except ValueError as exc:
                return self._error(400, str(exc))
            try:
                with self._with_client() as client:
                    # SHARED WITH THE FLASK SURFACE (payloads.netflow).
                    payload = payloads.netflow(client, hours=hours, filters=filters)
            except Exception as exc:  # noqa: BLE001
                return self._json(payloads.netflow_failure(exc))
            self._json(payload)

        def _zeek(self, query: dict) -> None:
            """Zeek shape: per-log counts, protocol timeline, services, DNS names.

            The counts helper reports a table it could not count SEPARATELY from a table
            with no rows, because those are different facts and conflating them is how an
            empty panel comes to look like a quiet network.
            """
            hours = self._window_arg(query, 24, 1, 24 * 14)
            if hours is None:
                return
            try:
                filters = zeek_filters(query)
            except ValueError as exc:
                return self._error(400, str(exc))
            try:
                with self._with_client() as client:
                    # SHARED WITH THE FLASK SURFACE (payloads.zeek).
                    payload = payloads.zeek(client, hours=hours, filters=filters)
            except Exception as exc:  # noqa: BLE001
                return self._json(payloads.zeek_failure(exc, filters=filters))
            self._json(payload)

        def _flows(self, query: dict) -> None:
            """The hosts behind one destination port, one IP protocol, or one source address.

            `port`, `proto` and `src` are all optional but ONE is required -- the query refuses
            an unfiltered request, because "every flow" is not a drill-down and would make a
            chart click into a slow full-table scan.
            """
            hours = self._window_arg(query, 24, 1, 24 * 14)
            if hours is None:
                return
            try:
                args = flows_args(query)
            except ValueError as exc:
                return self._error(400, str(exc))
            try:
                with self._with_client() as client:
                    # SHARED WITH THE FLASK SURFACE (payloads.flows).
                    payload = payloads.flows(client, hours=hours, **args)
            except Exception as exc:  # noqa: BLE001
                return self._json(payloads.flows_failure(exc))
            self._json(payload)

        def _discover_trends(self, query: dict) -> None:
            """The Flows header's three feed trends: NetFlow, Zeek and DNS."""
            hours = self._window_arg(query, 24, 1, 24 * 14)
            if hours is None:
                return
            try:
                with self._with_client() as client:
                    payload = soc_mod.discover_trends(client, hours=hours)
            except Exception as exc:  # noqa: BLE001
                return self._json({"available": False, "feeds": {},
                                   "reason": read_failure(exc),
                                   "data_error": str(exc)})
            self._json(payload)

        def _discover(self, query: dict) -> None:
            """DISCOVER: raw flows with a filter bar -- Kibana's Discover over the flow table.

            The operator's ask: "select flow types or weirling and see all traffic". Unlike
            /api/flows (a chart drill-down that REQUIRES a port or proto), this endpoint
            deliberately answers an unfiltered question -- "all traffic" is the point -- bounded
            by the global time range and a page limit.
            """
            hours = self._window_arg(query, 24, 1, 24 * 14)
            if hours is None:
                return
            fields = ("src", "dst", "sport", "dport")
            try:
                args = discover_args(
                    query, {field: query.get(field) or [] for field in fields})
            except ValueError as exc:
                return self._error(400, str(exc))
            try:
                with self._with_client() as client:
                    # SHARED WITH THE FLASK SURFACE (payloads.discover), feed branch included.
                    payload = payloads.discover(client, hours=hours, **args)
            except Exception as exc:  # noqa: BLE001
                return self._json(payloads.discover_failure(exc))
            self._json(payload)
        def _dns(self, query: dict) -> None:
            """The DNS view: Q/A rows, filters, histogram and facets. Read-only.

            Every filter is optional -- "show me the whole window" is the first thing an
            operator wants -- and every value that cannot be read is a 400 with a sentence,
            never a silently dropped filter (which would show MORE than was asked for).
            """
            hours = self._window_arg(query, 24, 1, 24 * 14)
            if hours is None:
                return
            try:
                args = dns_args(query)
            except ValueError as exc:
                return self._error(400, str(exc))
            try:
                with self._with_client() as client:
                    # SHARED WITH THE FLASK SURFACE (payloads.dns).
                    payload = payloads.dns(client, hours=hours, **args)
            except Exception as exc:  # noqa: BLE001
                return self._json(payloads.dns_failure(exc))
            self._json(payload)

        def _blocked(self, query: dict) -> None:
            """The Blocked tab: hits + live blocks + live alerts + gate state, one read."""
            hours = self._window_arg(query, 24, 1, 24 * 14)
            if hours is None:
                return
            try:
                args = blocked_args(query)
            except ValueError as exc:
                return self._error(400, str(exc))
            try:
                with self._with_client() as client:
                    # SHARED WITH THE FLASK SURFACE (payloads.blocked): the gate state is read
                    # beside the hits, so the tab cannot show one without the other.
                    payload = payloads.blocked(client, hours=hours, **args)
            except Exception as exc:  # noqa: BLE001
                return self._json(payloads.blocked_failure(exc))
            self._json(payload)

        def _dns_reverse(self, query: dict) -> None:
            """Which names pointed at this address, inside the window."""
            ip = (query.get("ip") or [""])[0].strip()
            if not ip or len(ip) > 64:
                return self._error(400, "give an address: /api/dns/reverse?ip=...")
            hours = self._window_arg(query, 24, 1, 24 * 14)
            if hours is None:
                return
            try:
                with self._with_client() as client:
                    payload = soc_mod.dns_reverse_for(client, ip, hours=hours)
            except Exception as exc:  # noqa: BLE001
                logger.warning("reverse lookup unavailable: %s", exc)
                return self._json({"available": False, "domains": [], "reason":
                                   read_failure(exc)})
            self._json(payload)

        def _system(self, query: dict) -> None:
            """The sensor host's CPU, memory, and interface counters.

            A process-level read of procfs, not a database query: it is cheap and has no
            ClickHouse dependency, so an unavailable database cannot make the system cards
            disappear. The sampler owns its own bounded history.

            `sensor` scopes the read to a fleet member. Only this hub's host is sampled; a
            remote sensor has not reported host counters, and saying so is better than
            presenting the hub's numbers under another sensor's name.
            """
            sensor = str(_first(query, "sensor", "") or "").strip()
            # SHARED WITH THE FLASK SURFACE (payloads.system_payload), including the non-local
            # sensor branch: the hub's numbers must never render under another sensor's name.
            self._json(payloads.system_payload(sensor=sensor))

        def _update(self, query: dict) -> None:
            """Release metadata for Settings → Software update.

            Read-only: this answers "is there a newer release" and never changes the running
            deployment. Applying an update remains a pipeline operation, not an HTTP verb.
            """
            # SHARED WITH THE FLASK SURFACE (payloads.update_meta), including the version fallback
            # when the backend cannot report one.
            self._json(payloads.update_meta(ctx.backend, refresh=update_refresh(query)))

        def _health(self, query: dict) -> None:
            """DEEP health: the checks, ingestion trend, table sizes, and the sensor.

            NOT the liveness probe. /api/healthz answers {"ok": true} without touching the
            database so that a slow database cannot restart the GUI; this one reads it,
            because "is data still arriving" cannot be answered otherwise. The two are
            different questions and this endpoint is the second.
            """
            hours = self._window_arg(query, 24, 1, 24 * 14)
            if hours is None:
                return
            try:
                with self._with_client() as client:
                    # SHARED WITH THE FLASK SURFACE (payloads.health_deep).
                    payload = payloads.health_deep(
                        client, settings=ctx.settings,
                        user_store=getattr(ctx, "user_store", None), hours=hours)
            except Exception as exc:  # noqa: BLE001
                return self._json(payloads.health_deep_failure(exc))
            self._json(payload)

        def _assets(self, query: dict) -> None:
            """The asset inventory: every host seen, with a per-host summary.

            Read-only and dependency-free like every other route. `hours` bounds the TRAFFIC
            columns only -- a host whose last packet was days ago is still an asset, so it
            appears with zeroed counters rather than being dropped, and the payload reports
            which sources were readable so the panel can explain the zeros.
            """
            hours = self._window_arg(query, 24, 1, 24 * 14)
            if hours is None:
                return
            try:
                with self._with_client() as client:
                    # SHARED WITH THE FLASK SURFACE (payloads.assets), so the two cannot disagree
                    # about a column, a zero or the failure shape.
                    payload = payloads.assets(client, hours=hours)
            except Exception as exc:  # noqa: BLE001
                return self._json(payloads.assets_failure(exc))
            self._json(payload)

        def _findings(self, query: dict) -> None:
            """Recorded scanner findings for the Findings drill. Read-only.

            Findings are historical evidence: the global time window does not hide them,
            because a finding observed last week is still a fact about the host today. The
            severity filter is an allow-list, and the host filter is a plain equality on a
            parameterized value.
            """
            try:
                args = findings_args(query)
            except ValueError as exc:
                return self._error(400, str(exc))
            try:
                with self._with_client() as client:
                    # SHARED WITH THE FLASK SURFACE (payloads.findings), filter echo included.
                    payload = payloads.findings(client, **args)
            except Exception as exc:  # noqa: BLE001
                return self._json(payloads.findings_failure(exc))
            self._json(payload)

        def _asset_changes(self, query: dict) -> None:
            """Recent service changes and their shadow posture score.

            `hours` is the same global window the rest of the console uses. An unreadable table
            is reported as unavailable, not as "no changes" -- the distinction this codebase
            keeps relearning.
            """
            hours = self._window_arg(query, 24, 1, 24 * 14)
            if hours is None:
                return
            try:
                with self._with_client() as client:
                    # SHARED WITH THE FLASK SURFACE (payloads.asset_changes).
                    payload = payloads.asset_changes(client, hours=hours)
            except Exception as exc:  # noqa: BLE001
                return self._json(payloads.asset_changes_failure(exc))
            self._json(payload)

        def _asset_posture(self) -> None:
            """The shadow asset-posture scorer's state. Read-only and advisory."""
            try:
                with self._with_client() as client:
                    payload = assets_mod.asset_posture_overview(client)
            except Exception as exc:  # noqa: BLE001
                logger.warning("asset posture unavailable: %s", exc)
                return self._json({"available": False, "reason": "the data could not be read",
                                   "model_version": "asset-posture-1", "scored": 0,
                                   "total_changes": 0, "bands": {}, "last_scored": ""})
            self._json(payload)

        def _scan_jobs(self, query: dict) -> None:
            """The manual-scan queue: recent requests, optionally for one address."""
            ip = str((query.get("ip") or [""])[0]).strip()
            try:
                with self._with_client() as client:
                    # SHARED WITH THE FLASK SURFACE (payloads.scan_jobs), including the timestamp
                    # serialisation: a job's requested_at is the same string on both surfaces.
                    payload = payloads.scan_jobs(client, ip=ip)
            except Exception as exc:  # noqa: BLE001
                return self._json(payloads.scan_jobs_failure(exc))
            self._json(payload)

        def _scan_job_create(self) -> None:
            """Queue one host scan for the scanner to claim under a lease."""
            if not self._authorize():
                return
            try:
                body = self._read_body()
            except ValueError as exc:
                return self._error(400, str(exc))
            try:
                args = scan_job_args(body)
            except ValueError as exc:
                return self._error(400, str(exc))
            try:
                with self._with_client() as client:
                    # SHARED WITH THE FLASK SURFACE (payloads.scan_job_create), status included. The
                    # CONNECTION is inside the try for the same reason: the console has always
                    # answered an unreachable cluster with the same "table is not ready" sentence.
                    code, payload = payloads.scan_job_create(client, **args)
            except Exception as exc:  # noqa: BLE001
                code, payload = payloads.scan_job_failure(exc)
            self._json(payload, code)

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
            hours = self._window_arg(query, 24, 1, 24 * 14)
            if hours is None:
                return
            try:
                tracked = graph_hosts(query.get("host") or [])
            except ValueError as exc:
                return self._error(400, str(exc))
            try:
                with self._with_client() as client:
                    # SHARED WITH THE FLASK SURFACE (payloads.graph).
                    payload = payloads.graph(client, hours=hours, tracked=tracked)
            except Exception as exc:  # noqa: BLE001
                return self._json(payloads.graph_failure(exc))
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
                    # SHARED WITH THE FLASK SURFACE (payloads.host_identity).
                    payload = payloads.host_identity(client)
            except Exception as exc:  # noqa: BLE001
                return self._json(payloads.host_identity_failure(exc))
            self._json(payload)

        def _sluice(self, query: dict) -> None:
            """Every rule -- live AND lapsed -- plus the gate's own state.

            Both sets, deliberately: "this rule exists but is not enforced" is a different statement
            from "this rule does not exist", and a view showing only live rules would make a lapsed
            block look DELETED, which is exactly the question an operator asks after a block stops
            working.
            """
            hours = self._window_arg(query, 24, 1, 24 * 14)
            if hours is None:
                return
            # SHARED WITH THE FLASK SURFACE (payloads.sluice). It takes `_with_client` because the
            # policy table and the effective settings are populated even when the database is
            # unreachable, and that is the case the payload exists to describe.
            self._json(payloads.sluice(self._with_client, hours=hours, settings=ctx.settings))
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
            # SHARED WITH THE FLASK SURFACE (payloads.weirlings). It takes `_with_client` because
            # the console opens a SEPARATE connection for the fleet read, the flow evidence and the
            # revoked list, and each block has its own failure behaviour.
            self._json(payloads.weirlings(
                self._with_client, settings=ctx.settings, **weirlings_args(query)))

        def _scanner(self) -> None:
            """Scanner readiness for the hub and every registered weirling.

            The scanner writes `scanner_status`; this route is a read. A sensor with no row is
            NOT "basic" -- it is "not reported", which is a different fact and needs the setup
            sheet rather than a clean-looking profile.
            """
            try:
                with self._with_client() as client:
                    # SHARED WITH THE FLASK SURFACE (payloads.scanner): a sensor with no row is
                    # "not_reported", never a clean-looking profile.
                    payload = payloads.scanner(client)
            except Exception as exc:  # noqa: BLE001
                return self._json(payloads.scanner_failure(exc))
            self._json(payload)

        def _weirlings_probe_get(self, query: dict) -> None:
            """Read one queued/complete capture probe. A read: no login required."""
            try:
                request_id = weirlings_probe_args(query)
            except ValueError as exc:
                return self._error(400, str(exc))
            try:
                with self._with_client() as client:
                    # SHARED WITH THE FLASK SURFACE (payloads.weirlings_probe). It returns a STATUS
                    # too: a missing request is a 404, a failed read a 503.
                    code, payload = payloads.weirlings_probe(client, request_id=request_id)
            except Exception as exc:  # noqa: BLE001
                code, payload = payloads.weirlings_probe_failure(exc)
            self._json(payload, code)

        def _weirlings_probe_post(self) -> None:
            """Queue a READ-ONLY capture-liveness probe for a remote weirling.

            Body: `{sensor_id, iface?, seconds?}`. The sensor's own agent claims it on its plan poll
            and measures its own NIC; the hub never reaches into the box. The refusal shapes and the
            interface-resolution order live in payloads.weirling_probe.
            """
            if not self._authorize():
                return
            try:
                body = self._read_body()
            except ValueError as exc:
                return self._json({"ok": False, "error": str(exc)}, 400)
            args, refusal = weirling_probe_args(body)
            if refusal:
                return self._json({"ok": False, "error": refusal}, 400)
            code, payload = payloads.weirling_probe(self._with_client, **args)
            self._json(payload, code)

        def _weirlings_detail(self, query: dict) -> None:
            """One sensor, for the drill-down.

            Reads through the same payload builder as the list, so the detail panel and the
            row it was opened from can never disagree about one sensor.
            """
            try:
                sensor_id = weirlings_detail_args(query)
            except ValueError as exc:
                return self._error(400, str(exc))
            try:
                with self._with_client() as client:
                    # SHARED WITH THE FLASK SURFACE (payloads.weirlings_detail).
                    payload = payloads.weirlings_detail(client, sensor_id=sensor_id)
            except Exception as exc:  # noqa: BLE001
                return self._json(payloads.weirlings_detail_failure(exc))
            self._json(payload)

        def _sluice_block(self) -> None:
            """Create a blocking rule.

            Body: {"src_cidr", "dst_cidr", "protocol", "dst_port", "direction", "ttl_minutes",
                   "reason"}

            THE REFUSALS LIVE IN sluice_block_args (shared with the Flask surface), because a rule
            that blocks the wrong thing takes a network down and every predicate has to answer with a
            sentence the operator can act on rather than a 500 from a layer that cannot explain
            itself. Two 400 shapes come out of it and both are preserved.
            """
            if not self._authorize():
                return
            try:
                body = self._read_body()
            except ValueError as exc:
                return self._error(400, str(exc))
            try:
                args, refusal = sluice_block_args(
                    body, settings=ctx.settings, sensor_addrs=sensor_addresses(ctx))
            except ValueError as exc:
                return self._error(400, str(exc))
            if refusal:
                return self._json({"ok": False, "error": refusal}, 400)
            ident = self._identity()
            try:
                with self._with_client() as client:
                    code, payload = payloads.sluice_block(
                        client, by=(ident.username if ident else "operator"), **args,
                        interval_s=int(ctx.settings.sluice_interval_s))
            except Exception as exc:  # noqa: BLE001
                code, payload = payloads.sluice_block_failure(exc)
            self._json(payload, code)

        def _blocklists_sync(self) -> None:
            """Sync every enabled source NOW. Slow on purpose: it fetches megabytes."""
            if not self._authorize():
                return
            try:
                with self._with_client() as client:
                    # SHARED WITH THE FLASK SURFACE (payloads.blocklist_sync), status included.
                    code, payload = payloads.blocklist_sync(client)
            except Exception as exc:  # noqa: BLE001
                code, payload = payloads.blocklist_sync_failure(exc)
            self._json(payload, code)

        def _blocklists_get(self) -> None:
            """The blocklist pane: every source with its state, plus the custom names.

            A read; the toggle is the only write. Custom names ride along so the pane shows the
            whole watch set in one place, wherever it lives in the page."""
            try:
                with self._with_client() as client:
                    # SHARED WITH THE FLASK SURFACE (payloads.blocklists).
                    payload = payloads.blocklists(client)
            except Exception as exc:  # noqa: BLE001
                return self._json(payloads.blocklists_failure(exc))
            self._json(payload)

        def _blocklists_enable(self) -> None:
            """Click a list on or off (the operator, 2026-10-16). A WRITE: what the deployment watches
            changes, and off drops the list's names from the watch set at the next load."""
            if not self._authorize():
                return
            try:
                body = self._read_body()
            except ValueError as exc:
                return self._error(400, str(exc))
            try:
                args = blocklist_enable_args(body)
            except ValueError as exc:
                return self._error(400, str(exc))
            try:
                with self._with_client() as client:
                    code, payload = payloads.blocklist_enable(client, **args)
            except Exception as exc:  # noqa: BLE001
                code, payload = payloads.blocklist_enable_failure(exc)
            self._json(payload, code)

        def _sluice_rule_domain(self) -> None:
            """Rename a rule -- including adding a `*.` marker. Stored as typed; subdomains were
            always covered."""
            if not self._authorize():
                return
            try:
                body = self._read_body()
            except ValueError as exc:
                return self._error(400, str(exc))
            try:
                args = sluice_rule_domain_args(body)
            except ValueError as exc:
                return self._error(400, str(exc))
            ident = self._identity()
            try:
                with self._with_client() as client:
                    code, payload = payloads.sluice_rule_domain(
                        client, by=(ident.username if ident else "operator"), **args)
            except Exception as exc:  # noqa: BLE001
                code, payload = payloads.sluice_rule_failure(exc)
            self._json(payload, code)

        def _blocklists_source(self) -> None:
            """Add a URL source, with its format named and validated (by the store).

            The form is deliberately explicit: a list with no stated format imports nothing and looks
            like a broken list. The common one-domain-per-line shape is the default; hosts and dnsmasq
            are accepted; Adblock/RPZ are refused with the reason.
            """
            if not self._authorize():
                return
            try:
                body = self._read_body()
            except ValueError as exc:
                return self._error(400, str(exc))
            try:
                args = blocklist_source_args(body)
            except ValueError as exc:
                return self._error(400, str(exc))
            try:
                with self._with_client() as client:
                    code, payload = payloads.blocklist_source_add(client, **args)
            except Exception as exc:  # noqa: BLE001
                code, payload = payloads.blocklist_source_failure(exc)
            self._json(payload, code)

        def _blocklists_custom(self) -> None:
            """Add or remove one operator-entered name. Validated like a domain rule."""
            if not self._authorize():
                return
            try:
                body = self._read_body()
            except ValueError as exc:
                return self._error(400, str(exc))
            try:
                args = blocklist_custom_args(body)
            except ValueError as exc:
                return self._error(400, str(exc))
            try:
                with self._with_client() as client:
                    code, payload = payloads.blocklist_custom(client, **args)
            except Exception as exc:  # noqa: BLE001
                code, payload = payloads.blocklist_custom_failure(exc)
            self._json(payload, code)

        def _sluice_rule_mode(self) -> None:
            """Change a rule's mode in place -- the Blocked tab's "open the rule and modify it".

            MOVING TO block ARMS THE KERNEL, so it needs `"confirmed": true` in the body -- the same
            friction every enforcement change carries, checked by sluice_rule_mode_args BEFORE any
            query. Moving back to alert needs none: widening what gets dropped is not the dangerous
            direction.
            """
            if not self._authorize():
                return
            try:
                body = self._read_body()
            except ValueError as exc:
                return self._error(400, str(exc))
            try:
                args, refusal = sluice_rule_mode_args(body)
            except ValueError as exc:
                return self._error(400, str(exc))
            if refusal:
                return self._json({"ok": False, "error": refusal}, 400)
            ident = self._identity()
            try:
                with self._with_client() as client:
                    code, payload = payloads.sluice_rule_mode(
                        client, by=(ident.username if ident else "operator"), **args)
            except Exception as exc:  # noqa: BLE001
                code, payload = payloads.sluice_rule_failure(exc)
            self._json(payload, code)

        def _sluice_revoke(self) -> None:
            """Stop enforcing a rule, keeping the RECORD.

            The audit trail of what was blocked and why must not be destroyed by the act of
            unblocking it -- that record is what an incident review reads. The store soft-deletes;
            the shared fetcher (payloads.sluice_revoke) reports per-id failures on a bulk revoke
            rather than swallowing them.
            """
            if not self._authorize():
                return
            try:
                body = self._read_body()
            except ValueError as exc:
                return self._error(400, str(exc))
            try:
                args = sluice_revoke_args(body)
            except ValueError as exc:
                return self._error(400, str(exc))
            ident = self._identity()
            try:
                with self._with_client() as client:
                    code, payload = payloads.sluice_revoke(
                        client, by=(ident.username if ident else "operator"), **args,
                        interval_s=int(ctx.settings.sluice_interval_s))
            except Exception as exc:  # noqa: BLE001
                code, payload = payloads.sluice_revoke_failure(exc)
            self._json(payload, code)

        def _sluice_rule_disabled(self) -> None:
            """Park a rule or put it back (the operator, 2026-10-16).

            A single rule_id or a rule_ids selection; the shared fetcher re-reads every rule FINAL
            before flipping it and reports the ones it refused instead of guessing past them.
            """
            if not self._authorize():
                return
            try:
                body = self._read_body()
            except ValueError as exc:
                return self._error(400, str(exc))
            try:
                args = sluice_rule_disabled_args(body)
            except ValueError as exc:
                return self._error(400, str(exc))
            ident = self._identity()
            try:
                with self._with_client() as client:
                    code, payload = payloads.sluice_rule_disabled(
                        client, by=(ident.username if ident else "operator"), **args,
                        interval_s=int(ctx.settings.sluice_interval_s))
            except Exception as exc:  # noqa: BLE001
                code, payload = payloads.sluice_rule_disabled_failure(exc)
            self._json(payload, code)

        def _sensor_addresses(self) -> list[str]:
            """This host's own addresses, for the self-block check (see sensor_addresses)."""
            return sensor_addresses(ctx)

        def _zeeklog(self, query: dict) -> None:
            """Per-log detail for ONE Zeek log, for click-through from the Zeek view.

            Answers "which hosts appear in ssl.log, and how often" -- the drill-down a bar
            chart needs to be useful. `log` names a label from soc.ZEEK_LOGS; anything else is
            rejected rather than interpolated, because the table name reaches the SQL text.
            """
            try:
                args = zeeklog_args(query)
            except ValueError as exc:
                return self._error(400, str(exc))
            hours = self._window_arg(query, 24, 1, 24 * 14)
            if hours is None:
                return
            try:
                with self._with_client() as client:
                    # SHARED WITH THE FLASK SURFACE (payloads.zeeklog).
                    payload = payloads.zeeklog(client, hours=hours, **args)
            except Exception as exc:  # noqa: BLE001
                return self._json(payloads.zeeklog_failure(exc, label=args["label"]))
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
            # ONE IMPLEMENTATION (see requestauth). The Flask front door asks the same question
            # through the same code, so the two surfaces cannot drift apart on who is signed in.
            return requestauth.identity(ctx, self)

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
            # ONE IMPLEMENTATION (see requestauth). `gated` still decides whether the address is
            # real, because only the gate may count a failure toward the escalating delay.
            return requestauth.token_role(
                ctx, self,
                client=self._client_addr() if gated else "",
            )

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

        def _plan_subject(self, sensor_id: str):
            """Resolve the sensor a per-sensor plan write targets: (registration, refusal).

            THE DECISION IS SHARED (payloads.plan_subject): the local sensor is refused there because
            its runtime is configured in the cluster ConfigMap, not in a registry row, and storing a
            plan for it would be a second source that nothing reads.
            """
            return payloads.plan_subject(self._with_client, sensor_id)

        def _weirlings_plan(self) -> None:
            """What a per-sensor plan change WOULD do. Touches nothing.

            Body: `{"sensor_id": "weirvern-eth2", "changes": {"mode": "siphon", ...}}`.

            The same staged-then-applied shape the Settings tab uses, against the sensor's own plan
            instead of the hub's ConfigMap: payloads.weirling_plan validates with the same
            `fleet.plan_from_changes` the write uses, so a client cannot skip the confirmation by
            staging a plan itself.
            """
            if not self._authorize():
                return
            try:
                body = self._read_body()
            except ValueError as exc:
                return self._json({"ok": False, "error": str(exc)}, code=400)
            args, refusal = weirling_plan_args(body)
            if refusal:
                return self._json({"ok": False, "error": refusal}, code=400)
            code, payload = payloads.weirling_plan(self._with_client, **args)
            self._json(payload, code)

        def _weirlings_apply(self) -> None:
            """Write a per-sensor plan. The sensor picks it up on its next refresh.

            Body: `{"sensor_id": "...", "changes": {...}, "reason": "..."}`. Same validation as the
            plan step -- the write path cannot be looser than the preview, or the preview is theatre.
            """
            if not self._authorize():
                return
            try:
                body = self._read_body()
            except ValueError as exc:
                return self._json({"ok": False, "error": str(exc)}, code=400)
            args, refusal = weirling_apply_args(body)
            if refusal:
                return self._json({"ok": False, "error": refusal}, code=400)
            ident = self._identity()
            code, payload = payloads.weirling_apply(
                self._with_client, actor=(ident.username if ident else "operator"), **args)
            self._json(payload, code)

        def _weirlings_register(self) -> None:
            """Register (or re-register) a sensor.

            The refusal is RETURNED, not raised as a 5xx: a rejected registration is a normal outcome
            of a form an operator is filling in, and an error page would read as the feature being
            broken rather than the input being wrong.
            """
            if not self._authorize():
                return
            try:
                body = self._read_body()
            except ValueError as exc:
                return self._json({"ok": False, "error": str(exc)}, code=400)
            args = weirling_register_args(body)
            try:
                with self._with_client() as client:
                    code, payload = payloads.weirling_register(client, **args)
            except Exception as exc:  # noqa: BLE001
                code, payload = payloads.weirling_save_failure(exc)
            self._json(payload, code)

        def _weirlings_enable(self) -> None:
            """Switch a registered sensor on or off WITHOUT revoking it."""
            if not self._authorize():
                return
            try:
                body = self._read_body()
            except ValueError as exc:
                return self._json({"ok": False, "error": str(exc)}, code=400)
            args, refusal = weirling_enable_args(body)
            if refusal:
                return self._json({"ok": False, "error": refusal}, code=400)
            try:
                with self._with_client() as client:
                    code, payload = payloads.weirling_enable(client, **args)
            except Exception as exc:  # noqa: BLE001
                code, payload = payloads.weirling_save_failure(exc)
            self._json(payload, code)

        def _weirlings_revoke(self) -> None:
            """Retire a registration. The row is kept; nothing is deleted.

            THE CONFIGMAP CLEAR LIVES IN payloads.weirling_revoke, with the reason it exists: clearing
            only the registry row left the worker forwarding and intercepting after a revoke, because
            the plan is read from the cluster environment and not from ClickHouse.
            """
            if not self._authorize():
                return
            try:
                body = self._read_body()
            except ValueError as exc:
                return self._json({"ok": False, "error": str(exc)}, code=400)
            args, refusal = weirling_revoke_args(body)
            if refusal:
                return self._json({"ok": False, "error": refusal}, code=400)
            ident = self._identity()
            code, payload = payloads.weirling_revoke(
                self._with_client, actor=(ident.username if ident else "operator"),
                config_client=getattr(ctx, "config_client", None), **args)
            self._json(payload, code)

        def _require_read(self) -> bool:
            """Whether this request may READ. Sends the refusal itself.

            Open when accounts are not provisioned (see _route); otherwise a signed-in
            account or the break-glass token is required. A `must_change` account is held at
            the password gate: it can reach /api/session and the password route, and every
            other read says why not, so the UI cannot render a dashboard behind the gate.
            """
            ok, refusal = requestauth.read_refusal(ctx, self)
            if ok:
                return True
            if refusal is not None:
                code, message = refusal
                self._error(code, message)
            return False

        def _require_session(self) -> users_mod.Identity | None:
            """The signed-in identity, or None with the refusal already sent.

            THE DECISION IS SHARED (payloads.session_required): a deployment with no accounts answers
            403 and an unknown caller 401, identically on both surfaces. Deliberately not satisfiable
            by the token: the token has no account, so there is no password to change and nothing to
            sign out of, and pretending otherwise would offer a button that cannot work.
            """
            ident, refusal = payloads.session_required(ctx, self)
            if ident is None:
                assert refusal is not None
                self._json(refusal[1], refusal[0])
            return ident

        def _authorize(self) -> bool:
            """Whether this request may WRITE. Sends the refusal itself.

            ONE IMPLEMENTATION (see requestauth.write_refusal). The order, the five refusals and the
            escalating delay all live there now, so the console and the Flask front door cannot
            disagree about who may change something -- which they did: the two copies ended on a 403
            and a 401 with different sentences for the same request.
            """
            ok, refusal = requestauth.write_refusal(ctx, self, addr=self._client_addr())
            if ok:
                return True
            code, message = refusal if refusal is not None else (403, "write access is refused")
            self._error(code, message)
            return False

        def _read_body(self, limit: int = 65536) -> dict:
            """The request body as JSON, or raise ValueError.

            Bounded: an unbounded read on a LAN port is a memory-growth path. The PARSE is shared
            (`web.json_body`), so the messages a caller sees are the same on both surfaces.
            """
            length = int(self.headers.get("Content-Length") or 0)
            if length <= 0:
                raise ValueError("a JSON body is required")
            if length > limit:
                raise ValueError(f"body too large ({length} bytes)")
            return json_body(self.rfile.read(length), limit=limit)

        def do_POST(self) -> None:  # noqa: N802
            if self._redirect_to_https():
                return
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
            # ── NETWORK SCOPES ─────────────────────────────────────────────────────────────
            # These decide which hosts are eligible for per-host baselines and alerts, so
            # they are configuration writes and go through the same admin gate as Settings.
            if path == "/api/networks/autofill":
                self._networks_autofill()
                return
            if path == "/api/networks/save":
                return self._networks_save()
            if path == "/api/networks/delete":
                return self._networks_delete()
            # SOC-1: the alert review write. A write like the settings routes, so it goes
            # through the same operator-token gate -- an unauthenticated port must not let
            # anyone on the LAN mark alerts as handled.
            if path == "/api/review":
                return self._review()
            # THE ALERT ACTION CELL'S WATCH TOGGLE. Gated like every other write: an
            # unauthenticated port must not let anyone on the LAN rewrite the operator's
            # tracking list.
            if path == "/api/watch":
                return self._watch()
            # ── SLUICE GATE writes ────────────────────────────────────────────────────────
            if path == "/api/sluice/block":
                return self._sluice_block()
            # A manual scan is a request, not a scan run in the GUI process. The scanner
            # claims it under a lease; the Assets row polls the result through the queue read.
            if path == "/api/scan-jobs":
                return self._scan_job_create()
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
            # An EDIT, not a delete-and-recreate: the rule keeps its id, its reason and its
            # history (see sluice_store.update_rule_mode).
            if path == "/api/sluice/rule/mode":
                return self._sluice_rule_mode()
            # A rule's NAME is editable too -- "modify it like adding a *" (the operator,
            # 2026-10-16). Same in-place semantics as the mode edit.
            if path == "/api/sluice/rule/domain":
                return self._sluice_rule_domain()
            # Park a rule or put it back -- one rule or a checkbox selection (the operator,
            # 2026-10-16). Not an edit of what it matches; a change of whether it applies.
            if path == "/api/sluice/rule/disabled":
                return self._sluice_rule_disabled()
            # ── BLOCKLISTS ──────────────────────────────────────────────────────────────────
            # Both admin-gated: importing a list decides what this deployment WATCHES (and,
            # once a rule blocks, what it stops), which is a change to the configuration.
            if path == "/api/blocklists/sync":
                return self._blocklists_sync()
            if path == "/api/blocklists/source":
                return self._blocklists_source()
            if path == "/api/blocklists/custom":
                return self._blocklists_custom()
            # Clicking a list to turn it on or off (the operator, 2026-10-16). A write: what the
            # deployment WATCHES changes, and off drops the list's names from the watch set.
            if path == "/api/blocklists/enable":
                return self._blocklists_enable()
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
            # THE PER-SENSOR INTERCEPT PLAN, staged then applied, exactly like the Settings tab's
            # ConfigMap writes: the plan step validates and reports the blast radius, the apply
            # step writes the sensor's own row. Separate routes because the browser must never
            # be able to skip the preview.
            if path == "/api/weirlings/plan":
                return self._weirlings_plan()
            if path == "/api/weirlings/apply":
                return self._weirlings_apply()
            if path == "/api/weirlings/probe":
                return self._weirlings_probe_post()
            self._error(404, f"no write route at {path}")

        # -- accounts -------------------------------------------------------

        def _session(self) -> None:
            """Who the caller is; whether the sign-in gate is armed. NEVER anyone else's data.

            Answers for three callers: an anonymous browser deciding whether to show the gate,
            a signed-in account refreshing its role, and the break-glass token (reported as an
            admin `via: token` with no username, because that is exactly what it is).
            """
            # ONE IMPLEMENTATION (see requestauth.session_payload). The Flask front door returns
            # the same payload from the same function, because the console JS renders the `note`
            # as a banner when accounts are off and two payload builders could disagree about it.
            self._json(requestauth.session_payload(ctx, self))

        def _audit_auth(self, action: str, username: str, reason: str) -> None:
            """Append the authentication fact without ever touching the credential.

            The write trail is the operator's audit surface; a sign-in is a privileged action
            even when it fails. A failed audit write must not turn a valid sign-in into an
            error -- the same contract as settings and fleet writes.
            """
            # ONE IMPLEMENTATION (see requestauth.audit_auth), so the rendered UI writes the same
            # audit fact in the same shape as the API.
            requestauth.audit_auth(ctx, action, username, reason)

        def _login(self) -> None:
            """Verify a username and password, and mint a session.

            THE CHECK IS SHARED (payloads.login, over requestauth.authenticate): the console API and
            the rendered form ask the same function the same question, so they cannot disagree about a
            password, about timing, or about throttling. Only the TRANSPORT of the answer differs: a
            token in JSON here, a signed cookie in the rendered UI. The accounts check comes FIRST,
            before the body is parsed -- a deployment with no accounts refuses the sign-in whatever
            was posted.
            """
            refusal = payloads.login_refusal(ctx)
            if refusal is not None:
                return self._json(refusal, 403)
            try:
                body = self._read_body()
            except ValueError as exc:
                return self._error(400, str(exc))
            code, payload = payloads.login(
                ctx, username=str(body.get("username") or ""),
                password=str(body.get("password") or ""), addr=self._client_addr())
            self._json(payload, code)

        def _logout(self) -> None:
            """Drop the caller's session.

            A session is REQUIRED, for the same uniformity as every other account route: an audit
            rule that says "every mutating route presents a session" is one somebody can check at a
            glance, and an exception has to be re-justified forever. The client-side flow is
            unaffected -- a tab whose session already expired catches the refusal and clears its own
            state anyway, which is what signing out does.
            """
            ident, refusal = payloads.session_required(ctx, self)
            if ident is None:
                assert refusal is not None
                return self._json(refusal[1], refusal[0])
            code, payload = payloads.logout(ctx, ident, self)
            self._json(payload, code)

        def _password(self) -> None:
            """Change the signed-in account's own password.

            THE CURRENT PASSWORD IS REQUIRED (payloads.password_change owns why): it stops a stolen
            session token from locking the owner out, and it makes `must_change` an informed change
            rather than a form the operator submits blind. Sessions are revoked afterwards -- a
            password change is the one moment where dropping every other session is exactly what the
            operator expects.
            """
            ident, refusal = payloads.session_required(ctx, self)
            if ident is None:
                assert refusal is not None
                return self._json(refusal[1], refusal[0])
            try:
                body = self._read_body()
            except ValueError as exc:
                return self._error(400, str(exc))
            code, payload = payloads.password_change(
                ctx, ident, current=str(body.get("current") or ""),
                new=str(body.get("new") or ""))
            self._json(payload, code)

        def _users_list(self) -> None:
            """Every account, for an admin. Reads are admin-only: the account list is not
            monitoring data, and a viewer has no use for it."""
            role, _via = self._caller_role()
            if role != users_mod.ROLE_ADMIN:
                return self._error(403, "admin access is required to view accounts")
            # SHARED WITH THE FLASK SURFACE (payloads.users_list). The ROLE GATE stays here and on
            # the route: the fetcher answers "what are the accounts", not "who may see them".
            self._json(payloads.users_list(
                store=getattr(ctx, "user_store", None),
                accounts_on=_accounts_on(ctx),
                note=getattr(ctx, "accounts_note", "") or ""))

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
                return self._error(503, payloads.ACCOUNTS_UNAVAILABLE)
            # SHARED WITH THE FLASK SURFACE (payloads.user_create), status included.
            code, payload = payloads.user_create(store, **user_write_args(body, kind="create"))
            self._json(payload, code)

        def _users_role(self) -> None:
            """Change an account's role. Admin only.

            The last admin is protected by the STORE, not here: demoting the only admin would leave
            nobody able to manage accounts. The no-op rule (a role change that changes nothing must
            revoke nothing) lives in payloads.user_role, shared with the Flask surface.
            """
            if not self._authorize():
                return
            try:
                body = self._read_body()
            except ValueError as exc:
                return self._error(400, str(exc))
            store = getattr(ctx, "user_store", None)
            if store is None:
                return self._error(503, payloads.ACCOUNTS_UNAVAILABLE)
            code, payload = payloads.user_role(
                store, getattr(ctx, "sessions", None), **user_write_args(body, kind="role"))
            self._json(payload, code)

        def _users_delete(self) -> None:
            """Delete an account. Admin only; the last admin cannot be deleted (store guard)."""
            if not self._authorize():
                return
            try:
                body = self._read_body()
            except ValueError as exc:
                return self._error(400, str(exc))
            store = getattr(ctx, "user_store", None)
            if store is None:
                return self._error(503, payloads.ACCOUNTS_UNAVAILABLE)
            code, payload = payloads.user_delete(
                store, getattr(ctx, "sessions", None), **user_write_args(body, kind="delete"))
            self._json(payload, code)

        def _users_reset(self) -> None:
            """Set a new password for ANOTHER account, and force a change at next sign-in.

            The lost-password path that keeps this feature usable without email: an admin mints a
            temporary password and hands it over, and the account is held at the password gate until
            its owner replaces it.
            """
            if not self._authorize():
                return
            try:
                body = self._read_body()
            except ValueError as exc:
                return self._error(400, str(exc))
            store = getattr(ctx, "user_store", None)
            if store is None:
                return self._error(503, payloads.ACCOUNTS_UNAVAILABLE)
            code, payload = payloads.user_reset(
                store, getattr(ctx, "sessions", None), **user_write_args(body, kind="reset"))
            self._json(payload, code)

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
            try:
                args = review_args(body)
            except ValueError as exc:
                return self._error(400, str(exc))
            # THE STATE HAS ITS OWN 400 SHAPE (with `valid_states`), checked BEFORE the database
            # is touched, which is where the console has always checked it.
            refusal = payloads.review_state_refusal(args["state"])
            if refusal is not None:
                return self._json(refusal, 400)
            try:
                with self._with_client() as client:
                    # SHARED WITH THE FLASK SURFACE (payloads.review), status included.
                    code, payload = payloads.review(client, **args)
            except Exception as exc:  # noqa: BLE001
                code, payload = payloads.review_failure(exc)
            self._json(payload, code)

        def _watch(self) -> None:
            """Toggle one host's place on the watch list (the alert action cell's Watch).

            Body: {"src_addr": "...", "on": true}. Returns the state READ BACK from the
            store so the caller renders what LANDED, not what it asked for -- the same
            read-back rule _review follows for a disposition.
            """
            if not self._authorize():
                return
            try:
                body = self._read_body()
            except ValueError as exc:
                return self._error(400, str(exc))
            try:
                args = watch_body(body)
            except ValueError as exc:
                return self._error(400, str(exc))
            try:
                with self._with_client() as client:
                    # SHARED WITH THE FLASK SURFACE (payloads.watch), status included: the write
                    # either lands and is read back, or answers why it did not.
                    code, payload = payloads.watch(client, **args)
            except Exception as exc:  # noqa: BLE001
                code, payload = payloads.watch_failure(exc)
            self._json(payload, code)

        def _settings_plan(self) -> None:
            """Validate and describe a proposed change WITHOUT touching anything.

            The UI calls this first and shows the result, so the blast radius is stated before the
            change rather than discovered after. Requires the token too: even a dry run reveals the
            deployment's configuration shape.

            The key translation (ConfigMap keys back to the caller's row keys) lives in
            payloads.settings_plan, at the boundary, so a client's warning lookup cannot miss.
            """
            if not self._authorize():
                return
            try:
                body = self._read_body()
            except ValueError as exc:
                return self._error(400, str(exc))
            try:
                args = settings_changes_args(body)
            except ValueError as exc:
                return self._error(400, str(exc))
            code, payload = payloads.settings_plan(ctx, **args)
            self._json(payload, code)

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
            reason = str(body.get("reason") or "").strip()

            # BF-9: A DESTRUCTIVE SETTING NEEDS A REASON, AND THE REASON IS RECORDED. Enabling
            # siphon moves the sensor IN PATH -- it becomes a cut point for its segment -- and
            # the write trail must answer who took it in-path and why. The refusal names the
            # requirement so a caller cannot miss it.
            siphon_now = any(
                str(k).strip().lower() == "sensor_mode" and str(v).strip().lower() == "siphon"
                for k, v in changes.items())
            if siphon_now and not reason:
                return self._json({
                    "ok": False,
                    "error": "enabling siphon puts this deployment in the traffic path; a reason "
                             "is required and is recorded with your name and the time",
                }, 400)

            raw_changes = {k: str(v) for k, v in changes.items()}
            client = ctx.config_client or cc.ClusterConfig()
            try:
                current = client.read()
                p = cc.plan(raw_changes, current)
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

            # THE PLAN OWNS THE CAPTURE PORT LIST. A per-NIC plan already says which ports
            # capture and which siphon; the legacy ZEEK_IFACES list can still name a NIC the
            # plan leaves unassigned, and then Settings says "capture" where the fleet row says
            # "unassigned" -- the mismatch the operator reported. Reconcile in the same write:
            # siphon needs Zeek too, so the effective list is capture ports ∪ siphon ports.
            if "intercept_plans" in raw_changes:
                try:
                    from weirvern.nic_plans import NicPlanSet  # noqa: PLC0415

                    plans = NicPlanSet.from_json(raw_changes.get("intercept_plans") or "")
                    ports = plans.capture_ports()
                    if ports:
                        raw_changes["zeek_ifaces"] = ",".join(ports)
                        current_capture = str(current.get("CAPTURE_IFACE") or "").strip()
                        if current_capture not in ports:
                            raw_changes["capture_iface"] = ports[0]
                except Exception as exc:  # noqa: BLE001
                    # A malformed plan is refused by ClusterConfig.plan below with its own
                    # message; do not turn it into a derivation traceback here.
                    logger.warning("could not derive capture ports from intercept_plans: %s", exc)
            # The effective plan, including the reconciled keys, is what every later step uses
            # (apply-time checks, restart targets, write and receipt).
            try:
                p = cc.plan(raw_changes, current)
            except cc.ConfigError as exc:
                return self._json({"ok": False, "error": str(exc)}, 400)

            # APPLY-TIME CHECKS (BF-14): named assertions between the plan and the write. A
            # failure BLOCKS the apply and names itself; a check that cannot run says why
            # (the UI's "N passed, M skipped -- why?" reads this payload). The checks judge
            # the EFFECTIVE configuration -- current merged with what is being staged.
            from weirvern import apply_checks  # noqa: PLC0415

            try:
                norm_changes = {cc.to_configmap_key(k): v for k, v in raw_changes.items()}
                with self._with_client() as ch:
                    checks = apply_checks.run_apply_checks(
                        changes=norm_changes, current=current, ch_client=ch)
            except Exception as exc:  # noqa: BLE001
                # THE CHECKS THEMSELVES FAILING MUST NOT FAIL THE APPLY: they are a gate on
                # the CHANGE, not a dependency of the write. The operator sees the skip.
                logger.warning("apply-time checks could not run: %s", exc)
                checks = {"results": [], "blocked": False, "failed": [],
                          "summary": f"the apply-time checks could not run ({type(exc).__name__})"}
            if checks.get("blocked"):
                return self._json({
                    "ok": False,
                    "blocked": True,
                    "error": "blocked by apply-time checks: " + "; ".join(checks.get("failed") or []),
                    "tests": checks.get("results") or [],
                    "summary": checks.get("summary") or "",
                }, 409)

            ident = self._identity()
            try:
                landed = client.apply(raw_changes, reason=reason,
                                      by=(ident.username if ident else "operator"))
            except cc.ConfigError as exc:
                # A REFUSED WRITE STILL OWES A PER-ITEM RECEIPT. The apply's read-back raised, but
                # a fresh read can still say which values ARE there -- "failed, and here is the
                # reason per key" beats a whole-batch error the operator cannot act on.
                after = None
                try:
                    after = client.read()
                except Exception:  # noqa: BLE001
                    after = None
                return self._json({
                    "ok": False,
                    "error": str(exc),
                    "at": datetime.datetime.now(datetime.UTC).isoformat(timespec="seconds"),
                    "items": cc.receipt_items(raw_changes,
                                              None, after=after, error=str(exc)),
                }, 502)

            restarted: list[str] = []
            restart_errors: list[str] = []
            for target in p.restart_targets:
                try:
                    client.restart(target)
                    restarted.append(target)
                except cc.ConfigError as exc:
                    restart_errors.append(str(exc))

            # US-10: THE TRAIL GETS THE SETTINGS WRITE TOO. One row PER KEY -- a multi-key apply
            # must stay linkable from a single key's provenance row (an exact target match).
            # A failed audit write does not fail the apply (the write landed); it is logged so
            # the gap is findable, the same contract as the fleet writes.
            action = "revert" if body.get("revert") else "apply"
            try:
                with self._with_client() as ch:
                    for key in raw_changes:
                        fleet_store.write_audit(
                            ch, scope="settings", action=action, target=str(key),
                            reason=reason, actor=(ident.username if ident else "operator"))
            except Exception as exc:  # noqa: BLE001
                logger.warning("settings audit write failed: %s", exc)
            self._json({
                "ok": True,
                # TRANSLATED AT THE BOUNDARY, same reason as the plan route: `changes` is
                # ROW-keyed (what the GUI staged) and `landed` is the ConfigMap's own data
                # (CONFIGMAP keys). `landed.get(k)` with the row key returned "" for every
                # key, so the confirmation read `saved: reverse_dns=(empty)` AFTER A WRITE
                # THAT ACTUALLY LANDED -- the report contradicted the read-back that had
                # just proved it. The write was right; the receipt lied.
                "applied": {k: landed.get(cc.to_configmap_key(k), "") for k in raw_changes},
                "restarted": restarted,
                # A saved-but-not-restarted change is INERT, so it is reported as a failure of
                # applying rather than quietly folded into success.
                "restart_errors": restart_errors,
                "note": ("restarted " + ", ".join(restarted)) if restarted
                        else "no workload needed a restart",
                "at": datetime.datetime.now(datetime.UTC).isoformat(timespec="seconds"),
                # THE RECEIPT: per key, the value, the verdict and (on failure) the reason.
                "items": cc.receipt_items(raw_changes, landed),
                # ...and the apply-time checks that let this write through.
                "tests": checks.get("results") or [],
                "summary": checks.get("summary") or "",
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
            interface), `{"mgmt_interface": "eth0"}` (optional; for the two-port warning),
            `{"sensor": "weirvern-eth2"}` (optional; survey FOR that weirling instead).

            ── THE `sensor` FORM: A SURVEY FOR A NAMED WEIRLING ──────────────────────────────

            A weirling's plan belongs to THAT sensor (fleet.SensorPlan), so the survey that
            seeds it must measure THAT sensor's port, not the hub's. The interface then resolves
            in a deliberate order -- an explicit name, else the sensor's own declared capture
            interface, else its single reported NIC -- and REFUSES, naming the candidates, when
            the answer is ambiguous: surveying the wrong port produces a confident plan for a
            segment the sensor is not on, which is worse than no survey at all.

            The job itself is unchanged (hostNetwork, pinned to the sensor node, NET_RAW): on
            this deployment every in-cluster weirling runs on the node that carries the
            `weirvern.io/sensor-node` label, which is exactly what the pin selects. A sensor on
            ANOTHER box is not in-cluster, so the job cannot reach it -- and it says so through
            Sonar's own refusal ("no such interface on this node, interfaces present: ...")
            rather than pretending to have measured something.
            """
            if not self._authorize():
                return
            from weirvern.admin import cluster_config as cc
            from weirvern.admin import sonar as sonar_mod

            try:
                body = self._read_body()
            except ValueError as exc:
                return self._error(400, str(exc))

            # NDJSON progress: one line per step, then {"result": ...}. A browser fetch reads
            # the stream so the sheet can say "DHCP" / "passive" / "ARP" while the Job runs;
            # callers that do not ask for it get the same one-shot JSON as before.
            stream = bool(body.get("stream"))

            def emit(payload, code: int = 200) -> None:
                if stream:
                    with contextlib.suppress(BrokenPipeError, OSError):
                        self.wfile.write((json.dumps({"result": payload}, default=str) + "\n").encode())
                        self.wfile.flush()
                else:
                    self._json(payload, code)

            def emit_progress(payload) -> None:
                if stream:
                    with contextlib.suppress(BrokenPipeError, OSError):
                        self.wfile.write((json.dumps({"progress": payload}, default=str) + "\n").encode())
                        self.wfile.flush()

            if stream:
                self.send_response(200)
                self.send_header("Content-Type", "application/x-ndjson; charset=utf-8")
                self.send_header("Cache-Control", NO_CACHE)
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("X-Frame-Options", "DENY")
                self.send_header("Connection", "close")
                self._security_headers()
                self.end_headers()
                self.close_connection = True

            sensor_id = str(body.get("sensor") or "").strip()
            iface = str(body.get("interface") or "").strip()
            mgmt = str(body.get("mgmt_interface") or "").strip()
            if sensor_id and sensor_id != _gate_sensor_name():
                # A NAMED WEIRLING, so the port comes from the SENSOR's own report/plan.
                # BOTH READS ARE TYPED: the declaration from the registry
                # (`plan_subject`), the report from the heartbeat rows -- never a
                # presentation payload.
                try:
                    from weirvern import fleet_store  # noqa: PLC0415
                    with self._with_client() as ch:
                        reg, refusal = fleet_store.plan_subject(ch, sensor_id)
                        if refusal:
                            return emit({"ok": False, "error": refusal}, 400)
                        hb_rows, _hb_err = fleet_store.read_heartbeats(ch)
                except Exception as exc:  # noqa: BLE001
                    return emit({
                        "ok": False,
                        "error": f"the sensor could not be read: {str(exc)[:200]}",
                    }, 503)
                if not iface:
                    iface = str(reg.plan.iface if reg is not None else "").strip()
                if not iface:
                    nics = next(([str(n) for n in (hb.get("interfaces") or [])]
                                 for hb in hb_rows if hb.get("sensor_id") == sensor_id), [])
                    if len(nics) == 1:
                        iface = nics[0]
                    elif nics:
                        return emit({
                            "ok": False,
                            "error": (f"{sensor_id} reports several NICs ({', '.join(nics)}), so "
                                      f"which one to survey is a choice, not a guess: name the "
                                      f"capture interface."),
                            "sensor": sensor_id,
                            "interfaces": nics,
                        }, 400)
                    else:
                        return emit({
                            "ok": False,
                            "error": (f"{sensor_id} has not reported its NICs and no capture "
                                      f"interface is set in its plan, so there is nothing to "
                                      f"survey for it yet. The sensor reports its interfaces on "
                                      f"every heartbeat -- wait for one, or name an interface."),
                            "sensor": sensor_id,
                        }, 400)
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
                return emit({
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
                return emit({
                    "ok": False,
                    "error": f"cannot survey: {_why}. {sonar_mod.iface_input_remedy()}",
                }, 400)

            # A NAMED REMOTE SENSOR IS NOT A JOB IN THIS CLUSTER. The request goes through
            # the same ClickHouse handoff the remote agent already polls; the sensor runs
            # sonar.survey() on its own network and posts the measured result back. This
            # branch must come BEFORE ClusterConfig/Job creation, or a hub interface with
            # the same name would be surveyed and returned under the remote sensor's id.
            if sensor_id and sensor_id != _gate_sensor_name():
                try:
                    with self._with_client() as ch:
                        result = sonar_mod.run_remote_survey(
                            ch, sensor_id, iface, mgmt, progress=emit_progress)
                except sonar_mod.SonarError as exc:
                    return emit({"ok": False, "error": str(exc), "sensor": sensor_id}, 502)
                if isinstance(result, dict):
                    result["sensor"] = sensor_id
                return emit(result, 200 if result.get("ok") else 422)

            if ctx.config_client is not None:
                client = ctx.config_client
            else:
                try:
                    client = cc.ClusterConfig()
                except cc.ConfigError as exc:
                    return emit({"ok": False, "error": str(exc)}, 503)

            try:
                result = sonar_mod.run_survey_job(client, iface, mgmt, progress=emit_progress)
            except sonar_mod.SonarError as exc:
                return emit({"ok": False, "error": str(exc)}, 502)

            # A refusal INSIDE the job (it ran, and said no) is passed through with its reason,
            # distinct from a job that could not run at all.
            if isinstance(result, dict) and result.get("ok") is False:
                result["sensor"] = sensor_id
                return emit(result, 422)
            # STAMPED WITH THE SENSOR IT RAN FOR, so the reply cannot be staged against another
            # one's plan -- the client shows what this survey belongs to, and the harness can
            # assert it. Empty means the hub's own capture port (the pre-existing form).
            if isinstance(result, dict):
                result["sensor"] = sensor_id
            emit(result)

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
            """(net_admin, net_raw) for the WORKER, which is what runs the intercept.

            WHY THE WORKER AND NOT ZEEK: `weirvern intercept` is a control-plane command; it
            executes in the worker pod. The worker forges the ARP frames, installs the
            policy route and drives the forwarding path. The zeek pod only captures, and
            giving the packet parser NET_ADMIN widens the wrong process. The worker's
            Deployment is therefore the authoritative place to read the capabilities that
            siphon actually needs.

            WHY THE CLUSTER AND NOT THIS PROCESS: the GUI runs in its own pod, and its
            effective capabilities describe the wrong container.

            A capability that cannot be verified is reported ABSENT, never assumed: the
            gate exists so the in-path mode cannot be enabled without the ability to
            forward. (This began as a stub that answered "no" unconditionally.)
            """
            from weirvern.admin import cluster_config as cc

            client = getattr(ctx, "config_client", None) or cc.ClusterConfig()
            try:
                dep = client.get_json(
                    f"/apis/apps/v1/namespaces/{cc.NAMESPACE}/deployments/weirvern-worker")
                containers = (
                    ((dep.get("spec") or {}).get("template") or {}).get("spec") or {}
                ).get("containers") or []
                for container in containers:
                    if container.get("name") == "worker":
                        adds = ((container.get("securityContext") or {})
                                .get("capabilities") or {}).get("add") or []
                        return ("NET_ADMIN" in adds), ("NET_RAW" in adds)
            except Exception:  # noqa: BLE001
                pass
            return False, False

        def _networks(self, query: dict) -> None:
            """Read-only network coverage for Settings and the Weirlings tab."""
            # The same clamped parse both surfaces use (`_int_arg` defaults and clamps, deliberately).
            hours = _int_arg(query, "hours", 24, 1, 168)
            try:
                with self._with_client() as client:
                    # SHARED WITH THE FLASK SURFACE (payloads.networks_overview), suggestion block
                    # included, so both surfaces offer the same starting points.
                    payload = payloads.networks_overview(client, hours=hours)
            except Exception as exc:  # noqa: BLE001
                return self._json(payloads.networks_failure(exc))
            self._json(payload)

        def _networks_autofill(self) -> None:
            """Create the scopes already implied by monitored networks, after one approval.

            This is deliberately a POST, not a GET side effect: reading coverage must never change
            what is monitored. The proposals come only from INTERCEPT_PLANS -- segments the operator
            already configured the sensor to watch -- never from observed traffic or an RFC1918 guess.
            The 409 on existing scopes lives in payloads.network_scope_autofill.
            """
            if not self._authorize():
                return
            try:
                with self._with_client() as client:
                    code, payload = payloads.network_scope_autofill(client)
            except Exception as exc:  # noqa: BLE001
                code, payload = payloads.network_autofill_failure(exc)
            self._json(payload, code)

        def _networks_save(self) -> None:
            """Create or update one operator-declared network scope.

            THE BODY GOES TO THE STORE UNPARSED (payloads.network_scope_save): `save_scope` owns the
            field rules, so a second parser here would be free to disagree with the sentences the form
            shows.
            """
            if not self._authorize():
                return
            try:
                body = self._read_body()
            except ValueError as exc:
                return self._error(400, str(exc))
            try:
                with self._with_client() as client:
                    code, payload = payloads.network_scope_save(client, body)
            except Exception as exc:  # noqa: BLE001
                code, payload = payloads.network_save_failure(exc)
            self._json(payload, code)

        def _networks_delete(self) -> None:
            """Retire one scope with a tombstone; the history remains until the merge window."""
            if not self._authorize():
                return
            try:
                body = self._read_body()
            except ValueError as exc:
                return self._error(400, str(exc))
            try:
                with self._with_client() as client:
                    code, payload = payloads.network_scope_delete(
                        client, str(body.get("id") or ""))
            except Exception as exc:  # noqa: BLE001
                code, payload = payloads.network_delete_failure(exc)
            self._json(payload, code)

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
            role, via = self._caller_role()
            ident = self._identity()
            # SHARED WITH THE FLASK SURFACE (payloads.settings_payload). The request-scoped facts
            # (role, identity, accounts armed) are computed here and handed IN, because they belong
            # to this request; both surfaces derive them from the same shared helpers.
            self._json(payloads.settings_payload(
                settings=ctx.settings, backend=ctx.backend,
                config_client=getattr(ctx, "config_client", None),
                auth=getattr(ctx, "auth", None), role=role, via=via, identity=ident,
                accounts_on=_accounts_on(ctx)))
        def _host(self, query: dict) -> None:
            # Validate before it reaches a query parameter. clickhouse-connect parameterises these,
            # so this is not the only defence, but an obviously-wrong address should not become a
            # database round trip. The sentence is the console's, from the shared parser.
            try:
                addr = host_addr(query)
            except ValueError as exc:
                return self._error(400, str(exc))
            hours = self._window_arg(query, 24, 1, 24 * 14)
            if hours is None:
                return
            try:
                with self._with_client() as client:
                    # SHARED WITH THE FLASK SURFACE (payloads.host): the exposure annotation and
                    # its own unavailable state travel with the detail.
                    payload = payloads.host(client, addr=addr, hours=hours)
            except Exception as exc:  # noqa: BLE001
                return self._error(503, read_failure(exc))
            self._json(payload)

        def _evidence(self, query: dict) -> None:
            """The alert-evidence pivot: the RAW records inside one detection window.

            Same validation and error posture as _host: the address is shape-checked
            before it becomes a query parameter, and a database failure is a 503 with
            the reason rather than an empty page.
            """
            try:
                args = evidence_args(query)
            except ValueError as exc:
                return self._error(400, str(exc))
            try:
                with self._with_client() as client:
                    # SHARED WITH THE FLASK SURFACE (payloads.evidence).
                    payload = payloads.evidence(client, **args)
            except Exception as exc:  # noqa: BLE001
                return self._error(503, read_failure(exc))
            self._json(payload)

        def _incident(self, query: dict) -> None:
            """One incident object: actor + asset + window + evidence + review provenance.

            The episode API answers the queue; this is the page an analyst opens from it. A
            missing incident is an explicit `available:false` answer, not an empty success.
            """
            try:
                args = incident_args(query)
            except ValueError as exc:
                return self._error(400, str(exc))
            try:
                with self._with_client() as client:
                    # SHARED WITH THE FLASK SURFACE (payloads.incident).
                    payload = payloads.incident(client, **args)
            except Exception as exc:  # noqa: BLE001
                return self._error(503, read_failure(exc))
            self._json(payload)

        def _fingerprints(self, query: dict) -> None:
            """Which hosts have presented a given JA4 fingerprint -- the hunting pivot.

            The identity card answers "what does this host use?"; this answers "who else uses
            this stack?", which is the direction an analyst actually arrives from: a fingerprint
            seen in one alert, then every other host that presents it. The token is shape-checked
            before it becomes a query parameter, and a database failure is a 503 with the reason
            rather than an empty list that would read as "nobody uses this".
            """
            try:
                ja4 = fingerprints_args(query)
            except ValueError as exc:
                return self._error(400, str(exc))
            try:
                with self._with_client() as client:
                    # SHARED WITH THE FLASK SURFACE (payloads.fingerprints).
                    payload = payloads.fingerprints(client, ja4=ja4)
            except Exception as exc:  # noqa: BLE001
                return self._error(503, read_failure(exc))
            self._json(payload)

    return Handler


def _first(query: dict, name: str, default=None):
    """The first value for `name`, accepting BOTH query shapes this project passes around.

    THE CONSOLE AND FLASK HAND OVER DIFFERENT THINGS. The console parses with `parse_qs`, which gives
    a dict of LISTS, so `query.get(name)[0]` is the value. Flask's `request.args` is a MultiDict whose
    `.get` returns a SCALAR, and `"9999"[0]` is `"9"`, not an error. Measured consequence: `?hours=9999`
    reached the fetcher as 336 hours on the console and as 9 hours on the new surface, so the same URL
    asked the database for two different time ranges. A silent divergence, not a crash, which is why it
    is normalised here once instead of being remembered at every call site.
    """
    value = query.get(name)
    if value is None:
        return default
    if isinstance(value, str):
        return value
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    try:
        return value[0] if len(value) else default
    except TypeError:
        return value


def _int_arg(query: dict, name: str, default: int, lo: int, hi: int) -> int:
    """Parse and CLAMP an integer query parameter.

    Clamping rather than rejecting: a client asking for limit=99999 gets the
    maximum allowed, which is friendlier than an error and still protects the
    database from an unbounded scan.
    """
    raw = _first(query, name)
    try:
        value = int(default if raw is None else raw)
    except (TypeError, ValueError):
        return default
    return max(lo, min(hi, value))



def write_trail_args(query: dict) -> dict:
    """The write trail's filters, parsed once for both surfaces.

    THE TRUNCATION IS PART OF THE CONTRACT: scope and action are cut to 32 characters and target to
    128 before they reach the query, so an over-long value is bounded rather than refused. The limit
    defaults and clamps rather than rejecting, like every other numeric argument here.
    """
    return {
        "scope": (_first(query, "scope", "") or "").strip()[:32],
        "action": (_first(query, "action", "") or "").strip()[:32],
        "target": (_first(query, "target", "") or "").strip()[:128],
        "limit": _int_arg(query, "limit", 50, 1, 200),
    }


def netflow_filters(query: dict) -> dict[str, str]:
    """The dashboard-wide flow filters, validated once for both surfaces.

    RAISES ValueError with the console's own sentence: its handler turns that into `_error(400, ...)`
    and the Flask route into `{"error", "code"}` with the same words. A filter that cannot be parsed
    is REFUSED, never dropped, because dropping it would show more traffic than was asked for.
    """
    filters = {"src": str(_first(query, "src", "") or "").strip(),
               "dst": str(_first(query, "dst", "") or "").strip(),
               "proto": str(_first(query, "proto", "") or "").strip(),
               "dport": str(_first(query, "dport", "") or "").strip()}
    for key in ("src", "dst"):
        if len(filters[key]) > 64:
            raise ValueError(f"{key} filter is implausibly long")
    for key, hi in (("proto", 255), ("dport", 65535)):
        raw = filters[key]
        if raw and (not raw.isdigit() or int(raw) > hi):
            raise ValueError(f"{key} must be a number <= {hi}")
    return filters


def zeek_filters(query: dict) -> dict[str, str]:
    """The Zeek filters, validated against the log list the read layer actually knows."""
    filters: dict[str, str] = {}
    for key in ("log", "service", "query", "host"):
        raw = str(_first(query, key, "") or "").strip()
        if not raw:
            continue
        limit = 64 if key == "host" else 253
        if len(raw) > limit:
            raise ValueError(f"{key} is too long to filter on")
        filters[key] = raw
    if filters.get("log") and filters["log"] not in dict(soc_mod.ZEEK_LOGS):
        raise ValueError(f"unknown log {filters['log']!r}")
    return filters


def flows_args(query: dict) -> dict:
    """The flow drill-down's selectors: port, protocol or an address, and one of them is required.

    -1 is the "not supplied" sentinel for the numeric pair, which is why it is replaced by None
    before the fetcher sees it.
    """
    port_raw = _int_arg(query, "port", -1, -1, 65535)
    proto_raw = _int_arg(query, "proto", -1, -1, 255)
    port: int | None = port_raw if port_raw >= 0 else None
    proto: int | None = proto_raw if proto_raw >= 0 else None
    src = str(_first(query, "src", "") or "").strip()
    dst = str(_first(query, "dst", "") or "").strip()
    for key, value in (("src", src), ("dst", dst)):
        if len(value) > 64:
            raise ValueError(f"{key} filter is implausibly long")
    if port is None and proto is None and not src and not dst:
        raise ValueError("port, proto or src is required (dst is also accepted), "
                         "e.g. /api/flows?port=443")
    return {"port": port, "proto": proto, "src": src, "dst": dst}


def dns_args(query: dict) -> dict:
    """The DNS view's filters and paging, parsed once for both surfaces.

    qtype and rcode are REFUSED when they do not parse, and the sentence is the console's own,
    including the odd case of an out-of-range value: it says "does not look like a number" rather
    than inventing a second wording. Reproduced rather than tidied.
    """
    domain = str(_first(query, "domain", "") or "").strip()
    client_ip = str(_first(query, "client", "") or "").strip()
    qtype_raw = str(_first(query, "qtype", "") or "").strip()
    rcode_raw = str(_first(query, "rcode", "") or "").strip()
    offset = _int_arg(query, "offset", 0, 0, 1000000)
    limit = _int_arg(query, "limit", 100, 1, 500)
    if len(domain) > 200 or len(client_ip) > 64:
        raise ValueError("domain or client filter is implausibly long")
    qtype: int | None = None
    rcode: int | None = None
    for raw, name, lo, hi in ((qtype_raw, "qtype", 0, 65535), (rcode_raw, "rcode", 0, 255)):
        if not raw:
            continue
        try:
            value = int(raw)
            if not lo <= value <= hi:
                raise ValueError
        except ValueError:
            raise ValueError(f"{name} does not look like a number: {raw!r}") from None
        if name == "qtype":
            qtype = value
        else:
            rcode = value
    return {"domain": domain, "client_ip": client_ip, "qtype": qtype, "rcode": rcode,
            "offset": offset, "limit": limit}


FINDING_SEVERITIES = frozenset({"critical", "high", "medium", "low", "info", "unknown"})


def _address_ok(value: str, limit: int = 64) -> bool:
    """The console's shape check for an address-like value. NOT a validator.

    It rejects the obviously wrong before it becomes a database round trip. clickhouse-connect
    parameterises every value, so this is a guard rather than the only defence, which is why it has
    always been this loose: an IP, a hostname and a partially-qualified name all pass.
    """
    return len(value) <= limit and all(c.isalnum() or c in ".:-_" for c in value)


def host_addr(query: dict) -> str:
    """`addr` for /api/host, refused with the console's own sentences."""
    addr = str(_first(query, "addr", "") or "").strip()
    if not addr:
        raise ValueError("addr is required, e.g. /api/host?addr=198.51.100.5")
    if not _address_ok(addr):
        raise ValueError("addr does not look like an IP address or hostname")
    return addr


def evidence_args(query: dict) -> dict:
    """`addr`, `start` and optional `end` for the evidence pivot, in the console's check ORDER."""
    addr = str(_first(query, "addr", "") or "").strip()
    if not addr:
        raise ValueError("addr is required, e.g. "
                         "/api/evidence?addr=198.51.100.5&start=2026-09-17T16:37:00")
    if not _address_ok(addr):
        raise ValueError("addr does not look like an IP address or hostname")
    start = str(_first(query, "start", "") or "").strip()
    if not start:
        raise ValueError("start is required (the alert's window_start), e.g. "
                         "/api/evidence?addr=198.51.100.5&start=2026-09-17T16:37:00")
    # Length-capped so a pathological value cannot reach the parser. The query parameterises it,
    # and parseDateTime64BestEffort is tolerant.
    if len(start) > 64:
        raise ValueError("start is not a valid timestamp")
    end = str(_first(query, "end", "") or "").strip() or None
    if end is not None and len(end) > 64:
        raise ValueError("end is not a valid timestamp")
    return {"addr": addr, "start": start, "end": end}


def incident_args(query: dict) -> dict:
    """`addr` and `start` for the incident page.

    ONE combined sentence when either is absent, which is the console's wording; splitting it into
    two messages would change what an analyst sees for half the bad requests.
    """
    addr = str(_first(query, "addr", "") or "").strip()
    start = str(_first(query, "start", "") or "").strip()
    if not addr or not start:
        raise ValueError("addr and start are required, e.g. "
                         "/api/incident?addr=198.51.100.5&start=2026-10-30T00:00:00")
    if not _address_ok(addr):
        raise ValueError("addr does not look like an IP address or hostname")
    if len(start) > 64:
        raise ValueError("start is not a valid timestamp")
    return {"addr": addr, "start": start}


def fingerprints_args(query: dict) -> str:
    """`ja4` for the hunting pivot, with its own shape check and its own sentence."""
    ja4 = str(_first(query, "ja4", "") or "").strip()
    if not ja4:
        raise ValueError("ja4 is required, e.g. /api/fingerprints?ja4=t13d1516h2_...")
    if len(ja4) > 128 or not all(c.isalnum() or c in "._-:" for c in ja4):
        raise ValueError("ja4 does not look like a fingerprint")
    return ja4


def findings_args(query: dict) -> dict:
    """`ip`, `severity` and an UNCLAMPED `limit` for the findings queue.

    The limit is not bounded here, and that is the console's contract: this route hands the number
    straight to the query. Do not add a clamp during a port -- it would answer a different number
    than the operator asked for, and the two surfaces would agree on the wrong thing.
    """
    ip = str(_first(query, "ip", "") or "").strip()
    if ip and not _address_ok(ip):
        raise ValueError("ip does not look like an address")
    severity = str(_first(query, "severity", "") or "").strip().lower()
    if severity and severity not in FINDING_SEVERITIES:
        raise ValueError("severity must be critical, high, medium, low, info or unknown")
    try:
        limit = int(str(_first(query, "limit", "500")))
    except (TypeError, ValueError):
        raise ValueError("limit must be an integer") from None
    return {"ip": ip, "severity": severity, "limit": limit}


def graph_hosts(values) -> list[str]:
    """The tracked-host selection for /api/graph, from a LIST of repeated query values.

    TAKES THE LIST, NOT THE QUERY. The console's `parse_qs` hands a list for a repeated key and
    Flask's `MultiDict` needs `getlist` to produce one, so a parser that read `query.get("host")`
    would see only the first value on the framework side. The two call sites pass different things
    and this function is the seam.
    """
    tracked = [str(v).strip() for v in values if str(v).strip()]
    for addr in tracked:
        if not _address_ok(addr):
            raise ValueError(f"host does not look like an address: {addr!r}")
    # An unbounded IN list is a way to make the database do arbitrary work from an HTTP request.
    if len(tracked) > 64:
        raise ValueError("too many hosts to track (limit 64)")
    return tracked


def blocked_args(query: dict) -> dict:
    """The Blocked tab's filters and paging."""
    domain = str(_first(query, "domain", "") or "").strip()
    if len(domain) > 200:
        raise ValueError("the domain filter is implausibly long")
    client_ip = str(_first(query, "client", "") or "").strip()
    if len(client_ip) > 64:
        raise ValueError("the client filter is implausibly long")
    return {"domain": domain, "client_ip": client_ip,
            "offset": _int_arg(query, "offset", 0, 0, 1000000),
            "limit": _int_arg(query, "limit", 200, 1, 500)}


def zeeklog_args(query: dict) -> dict:
    """`log`, its table from the allow-list, and the optional service/query filters.

    THE TABLE NAME IS RESOLVED HERE, from `soc.ZEEK_LOGS`, because it reaches the SQL text. A parser
    that passed the label through would let a request choose a table.
    """
    label = str(_first(query, "log", "") or "").strip()
    if not label:
        raise ValueError("log is required, e.g. /api/zeeklog?log=ssl")
    allowed = dict(soc_mod.ZEEK_LOGS)
    table = allowed.get(label)
    if not table:
        raise ValueError(
            f"unknown log {label!r}; expected one of: {', '.join(sorted(allowed))}")
    filters: dict[str, str] = {"log": label}
    for key in ("service", "query"):
        raw = str(_first(query, key, "") or "").strip()
        if not raw:
            continue
        if len(raw) > 253:
            raise ValueError(f"{key} is too long to filter on")
        filters[key] = raw
    return {"table": table, "label": label, "filters": filters}


def update_refresh(query: dict) -> bool:
    """The `refresh` flag on the update card. No strip: the console has always compared as-is."""
    raw = str(_first(query, "refresh", "") or "").lower()
    return raw in {"1", "true", "yes", "on"}


def weirlings_detail_args(query: dict) -> str:
    """`sensor` for the drill-down."""
    sensor_id = str(_first(query, "sensor", "") or "").strip()
    if not sensor_id:
        raise ValueError("a sensor id is required: /api/weirlings/detail?sensor=NAME")
    return sensor_id


def weirlings_probe_args(query: dict) -> str:
    """`request` for the capture-probe read."""
    request_id = str(_first(query, "request", "") or "").strip()
    if not request_id:
        raise ValueError("a request id is required: /api/weirlings/probe?request=ID")
    return request_id


def discover_args(query: dict, repeated: dict[str, list]) -> dict:
    """The Discover filter bar. `repeated` carries the MULTI-VALUED chips.

    THE REPEATED VALUES COME IN SEPARATELY because the two surfaces read them differently: the
    console's parse_qs hands a list and Flask needs `getlist`. A parser that read
    `query.get(field)` would see only the first chip on one surface -- a filter that silently
    ignores most of the operator's selection.
    """
    feed = str(_first(query, "feed", "netflow") or "netflow").strip().lower() or "netflow"
    if feed not in ("netflow", "dns", "zeek"):
        raise ValueError(
            f"'{feed}' is not a feed this view reads; expected netflow, dns or zeek")
    proto_raw = str(_first(query, "proto", "") or "").strip()
    addr = str(_first(query, "addr", "") or "").strip()
    sensor = str(_first(query, "sensor", "") or "").strip()
    port_raw = str(_first(query, "port", "") or "").strip()
    offset = _int_arg(query, "offset", 0, 0, 1000000)
    limit = _int_arg(query, "limit", 100, 1, 500)
    try:
        proto = soc_mod.proto_number(proto_raw)
    except ValueError as exc:
        raise ValueError(str(exc)) from None
    for value, name in ((addr, "addr"), (sensor, "sensor")):
        if value and not _address_ok(value):
            raise ValueError(f"{name} does not look like an address or a name: {value!r}")
    port: int | None = None
    if port_raw:
        try:
            port = int(port_raw)
            if not 0 <= port <= 65535:
                raise ValueError
        except ValueError:
            raise ValueError(f"port does not look like a port: {port_raw!r}") from None
    lists: dict[str, list] = {}
    for field in ("src", "dst"):
        values = [str(v).strip() for v in repeated.get(field, []) if str(v).strip()]
        for value in values:
            if not _address_ok(value):
                raise ValueError(f"{field} does not look like an address: {value!r}")
        lists[field] = values
    for field in ("sport", "dport"):
        nums: list[int] = []
        for raw in repeated.get(field, []):
            try:
                n = int(raw)
                if not 0 <= n <= 65535:
                    raise ValueError
            except (TypeError, ValueError):
                raise ValueError(f"{field} does not look like a port: {raw!r}") from None
            nums.append(n)
        lists[field] = nums
    return {"feed": feed, "proto": proto, "addr": addr, "sensor": sensor, "port": port,
            "offset": offset, "limit": limit,
            "src": lists["src"], "dst": lists["dst"],
            "sport": lists["sport"], "dport": lists["dport"]}


def anomalies_args(query: dict) -> dict:
    """The anomaly queue's window, score floor and filters.

    THE FILTER-LENGTH CHECKS MOVED OUT OF THE CLIENT BLOCK. They used to run after the connection
    opened, so a bad filter against an unreachable database answered 503 rather than 400. The
    request is bad either way, and now both surfaces answer it the same way.
    """
    host = str(_first(query, "host", "") or "").strip()
    severity = str(_first(query, "severity", "") or "").strip()
    model = str(_first(query, "model", "") or "").strip()
    feature = str(_first(query, "feature", "") or "").strip()
    if len(host) > 64 or len(severity) > 24 or len(model) > 64:
        raise ValueError("host, severity or model filter is implausibly long")
    if len(feature) > 64:
        raise ValueError("feature filter is implausibly long")
    return {"limit": _int_arg(query, "limit", 100, 1, 1000),
            "min_score": _float_arg(query, "min_score", 0.0, 0.0, 1.0),
            "host": host, "severity": severity, "model": model, "feature": feature,
            "unreviewed_only": _query_bool(query, "unreviewed") is True,
            "watched_only": _query_bool(query, "watched") is True}


def weirlings_args(query: dict) -> dict:
    """The fleet view's two booleans: problem sensors only, and include revoked rows."""
    return {"include_problems": _query_bool(query, "problems") is True,
            "include_revoked": _query_bool(query, "revoked") is True}


def json_body(raw: bytes, *, limit: int = 65536) -> dict:
    """The request body as a JSON OBJECT, or raise ValueError with the console's own sentence.

    TAKES RAW BYTES, NOT A REQUEST. http.server hands over what it read from `rfile` and Flask hands
    over `request.get_data()`, and the messages below are part of what a caller sees, so they live in
    one place rather than in two parsers that would drift.

    Bounded: an unbounded read on a LAN port is a memory-growth path.
    """
    length = len(raw)
    if length <= 0:
        raise ValueError("a JSON body is required")
    if length > limit:
        raise ValueError(f"body too large ({length} bytes)")
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValueError(f"body is not valid JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise ValueError("body must be a JSON object")
    return parsed


def watch_body(body: dict) -> dict:
    """The watch toggle's validated fields, with the console's sentences.

    `on` must be a BOOLEAN, not a truthy string: "off" is truthy, and a toggle that read it as
    true would stop un-watching from ever working.
    """
    src_addr = str(body.get("src_addr") or "").strip()
    if not src_addr:
        raise ValueError("'src_addr' is required")
    on = body.get("on")
    if not isinstance(on, bool):
        raise ValueError("'on' must be true or false")
    return {"src_addr": src_addr, "on": on}


def review_args(body: dict) -> dict:
    """The review write's fields, validated for presence with the console's sentence.

    `state` is returned unchecked: an unknown state answers a DIFFERENT 400 (with `valid_states`),
    which `review_state_refusal` builds, and that check must happen before the database is touched.
    """
    window_start = body.get("window_start")
    src_addr = str(body.get("src_addr") or "").strip()
    state = str(body.get("state") or "").strip()
    note = str(body.get("note") or "")[:500]
    if not window_start or not src_addr:
        raise ValueError("'window_start' and 'src_addr' are required")
    return {"window_start": window_start, "src_addr": src_addr, "state": state,
            "note": note, "adjustment": body.get("adjustment")}


def user_write_args(body: dict, *, kind: str) -> dict:
    """The account write's fields. `kind` is one of create, role, delete, reset.

    CREATE KEEPS THE NAME AS TYPED; every other kind strips and lowercases it. The store normalises
    on create anyway, and changing the other three would alter which row a name matches. The role
    defaults to viewer on create and is NOT defaulted on role, where an empty string is the store's
    to reject with its own sentence.
    """
    raw_name = str(body.get("username") or "")
    if kind == "create":
        return {
            "username": raw_name,
            "role": str(body.get("role") or users_mod.ROLE_VIEWER),
            "password": str(body.get("password") or ""),
            "must_change": bool(body.get("must_change")),
        }
    username = raw_name.strip().lower()
    if kind == "role":
        return {"username": username, "role": str(body.get("role") or "")}
    if kind == "reset":
        return {"username": username, "password": str(body.get("password") or "")}
    return {"username": username}


def scan_job_args(body: dict) -> dict:
    """One address, and it must be ONE address: a range or a name is a 400 with a sentence."""
    raw_ip = str(body.get("ip") or "").strip()
    try:
        ipaddress.ip_address(raw_ip)
    except ValueError as exc:
        raise ValueError("'ip' must be a single IP address") from exc
    return {"ip": raw_ip}


def sluice_block_args(body: dict, *, settings: Any,
                      sensor_addrs: list[str]) -> tuple[dict, str | None]:
    """The block form, validated in the console's ORDER, and the rule predicates that refuse it.

    TWO 400 SHAPES COME OUT OF HERE and they are not interchangeable: a malformed NUMBER raises
    ValueError and becomes the house `{"error", "code"}` body, while a refused RULE returns its
    sentence (the form renders `{"ok": false, "error"}` inline beside the fields). Collapsing them
    would change a body a client reads.

    THE REFUSALS MATTER MORE THAN THE WRITE: a rule that blocks the wrong thing takes a network down,
    so every predicate answers with something the operator can act on rather than a 500 from a layer
    that cannot explain itself.
    """
    from weirvern.sluice import SluiceError, parse_cidr, refuse_reason  # noqa: PLC0415

    src_raw = str(body.get("src_cidr") or "").strip()
    dst_raw = str(body.get("dst_cidr") or "").strip()
    domain_raw = str(body.get("domain") or "").strip()
    mode_raw = str(body.get("mode") or "block").strip().lower()
    protocol = str(body.get("protocol") or "").strip().lower()
    direction = str(body.get("direction") or "forward").strip().lower()
    try:
        dst_port = int(body.get("dst_port") or 0)
    except (TypeError, ValueError) as exc:
        raise ValueError("dst_port must be a number") from exc
    # 0 IS A VALUE, NOT AN ABSENCE. `or 60` read a deliberate 0 as "unset" and silently substituted an
    # hour -- the one input an operator reaching for "block it indefinitely" is most likely to send.
    raw_ttl = body.get("ttl_minutes")
    try:
        ttl = 60 if raw_ttl is None or raw_ttl == "" else int(raw_ttl)
    except (TypeError, ValueError) as exc:
        raise ValueError("ttl_minutes must be a number") from exc

    if domain_raw:
        # A DOMAIN RULE NAMES A NAME, NOT ADDRESSES: the address predicates do not apply, and
        # validate_domain (called by create_rule) owns the name's checks -- one place for the form,
        # this route and any importer.
        src = dst = ""
        why = ""
    else:
        try:
            src = parse_cidr(src_raw, "source")
            dst = parse_cidr(dst_raw, "destination")
        except SluiceError as exc:
            return {}, str(exc)
        why = refuse_reason(
            src_cidr=src, dst_cidr=dst, direction=direction,
            iface=str(settings.sluice_iface or settings.zeek_iface or ""),
            mgmt_iface=str(settings.mgmt_iface or ""),
            sensor_addrs=sensor_addrs, protocol=protocol, dst_port=dst_port)
        if why:
            return {}, why

    # OPTIONAL, by the operator's own instruction (2026-10-16). A reason is still the only record of
    # WHY, so a DERIVED block always writes one; a manual block left blank records an EMPTY reason
    # rather than a placeholder, because a placeholder in an audit row reads like a fact.
    reason = str(body.get("reason") or "").strip()
    # WHERE THE RULE CAME FROM: "dns" is a rule pushed from the DNS tab, "manual" is the Sluice form.
    # Detection-derived rules are stamped by the derivation path itself, never by a caller.
    origin_raw = str(body.get("origin") or "manual").strip().lower()
    origin = origin_raw if origin_raw in ("manual", "dns") else "manual"
    return {
        "src_cidr": src, "dst_cidr": dst, "domain": domain_raw, "mode": mode_raw,
        "protocol": protocol, "dst_port": dst_port, "direction": direction,
        "ttl_minutes": ttl, "reason": reason, "origin": origin,
    }, None


def sluice_revoke_args(body: dict) -> dict:
    """A rule id or a selection, plus the reason this route has always required."""
    rule_id = str(body.get("rule_id") or "").strip()
    ids = [str(x or "").strip() for x in (body.get("rule_ids") or []) if str(x or "").strip()]
    if not rule_id and not ids:
        raise ValueError("rule_id (or rule_ids, for a bulk revoke) is required")
    # BF-9: unblocking what the gate was holding is a destructive decision, so the reason is required.
    reason = str(body.get("reason") or "").strip()
    if not reason:
        raise ValueError("a reason is required to revoke a rule; it is recorded with your name and "
                         "the time")
    return {"rule_id": rule_id, "rule_ids": ids, "reason": reason}


def sluice_rule_mode_args(body: dict) -> tuple[dict, str | None]:
    """A rule id and a mode, plus the `confirmed` friction when the mode ARMS THE KERNEL.

    THE REFUSAL IS NOT THE HOUSE 400: it answers `{"ok": false, "error"}`, which the rule sheet renders
    beside the switch. Returning it rather than raising keeps that shape explicit.
    """
    rule_id = str(body.get("rule_id") or "").strip()
    mode = str(body.get("mode") or "").strip().lower()
    if mode == "block" and body.get("confirmed") is not True:
        return {}, ("moving a rule to block changes what the kernel drops; "
                    "resend with confirmed: true")
    return {"rule_id": rule_id, "mode": mode}, None


def sluice_rule_domain_args(body: dict) -> dict:
    """A rule id and the name to store. Stored AS TYPED, `*.` marker included."""
    rule_id = str(body.get("rule_id") or "").strip()
    domain = str(body.get("domain") or "").strip()
    if not domain:
        raise ValueError("a domain is required")
    return {"rule_id": rule_id, "domain": domain}


def sluice_rule_disabled_args(body: dict) -> dict:
    """One rule id or a selection, plus the state to set.

    `disabled` is a TRUTHY read rather than a strict boolean, as on the console: the form posts a
    checkbox, and a JSON `true` and a form `on` both mean the same thing here.
    """
    rule_id = str(body.get("rule_id") or "").strip()
    ids = [str(x or "").strip() for x in (body.get("rule_ids") or []) if str(x or "").strip()]
    if not rule_id and not ids:
        raise ValueError("rule_id (or rule_ids) is required")
    return {"rule_id": rule_id, "rule_ids": ids, "disabled": bool(body.get("disabled"))}


def blocklist_source_args(body: dict) -> dict:
    """A URL, a display name and a FORMAT. The store validates all three and names what it refuses."""
    return {"url": str(body.get("url") or ""), "name": str(body.get("name") or ""),
            "fmt": str(body.get("format") or "domains")}


def blocklist_custom_args(body: dict) -> dict:
    """`add` or `remove`, and the name. Any other action is a 400 that quotes what arrived."""
    action = str(body.get("action") or "add").strip().lower()
    if action not in ("add", "remove"):
        raise ValueError(f"action must be add or remove, not {action!r}")
    return {"action": action, "domain": str(body.get("domain") or "").strip()}


def blocklist_enable_args(body: dict) -> dict:
    """A source id and a REAL boolean: `"true"` from a query string is not a state the store can set."""
    source_id = str(body.get("source_id") or "").strip()
    enabled = body.get("enabled")
    if not source_id or not isinstance(enabled, bool):
        raise ValueError("source_id and a boolean enabled are required")
    return {"source_id": source_id, "enabled": enabled}


def weirling_register_args(body: dict) -> dict:
    """Registration fields. Nothing is validated here: the store owns the rules and names the fix.

    `expected_mode` DEFAULTS TO loch -- the mode a sensor is expected to run before anyone says
    otherwise, which is what the fleet view compares against.
    """
    return {"sensor_id": str(body.get("sensor_id") or ""),
            "address": str(body.get("address") or ""),
            "segment": str(body.get("segment") or ""),
            "expected_mode": str(body.get("expected_mode") or "loch"),
            "note": str(body.get("note") or ""),
            "topology": str(body.get("topology") or "")}


def weirling_enable_args(body: dict) -> tuple[dict, str | None]:
    """A sensor id and a STRICT boolean.

    `bool("false")` IS TRUE, so a client sending the string "false" would silently ENABLE a sensor.
    Refused rather than coerced -- the refusal is `{"ok": false}`, the shape this family of routes uses.
    """
    enabled = body.get("enabled")
    if not isinstance(enabled, bool):
        return {}, "`enabled` must be true or false"
    return {"sensor_id": str(body.get("sensor_id") or ""), "enabled": enabled}, None


def weirling_revoke_args(body: dict) -> tuple[dict, str | None]:
    """A sensor id and a REASON: revoking retires this deployment's memory of the sensor.

    BF-9: the reason rides the same rule as the other destructive actions, and the sentence says what
    it is for rather than just demanding a value.
    """
    reason = str(body.get("reason") or "").strip()
    if not reason:
        return {}, ("revoking a registration is a decision, not a cleanup; a reason is required and "
                    "is recorded with your name and the time")
    return {"sensor_id": str(body.get("sensor_id") or ""), "reason": reason}, None


def weirling_plan_args(body: dict) -> tuple[dict, str | None]:
    """A sensor id and a NON-EMPTY `changes` object.

    A plan with nothing to change is refused here rather than written as a no-op: "saved" would then
    claim a change that did not happen.
    """
    changes = body.get("changes")
    if not isinstance(changes, dict) or not changes:
        return {}, "`changes` must be an object naming at least one plan field to change"
    return {"sensor_id": str(body.get("sensor_id") or "").strip(), "changes": changes}, None


def weirling_apply_args(body: dict) -> tuple[dict, str | None]:
    """`weirling_plan_args` plus the optional reason.

    THE REASON'S OWN RULE CANNOT BE CHECKED HERE: whether it is required depends on the MERGED plan's
    mode, so that check lives in the fetcher, after the merge and before the write.
    """
    args, refusal = weirling_plan_args(body)
    if refusal:
        return {}, refusal
    args["reason"] = str(body.get("reason") or "").strip()
    return args, None


def weirling_probe_args(body: dict) -> tuple[dict, str | None]:
    """A sensor id, an optional interface and a bounded duration.

    THE HUB DOES NOT GUESS AN INTERFACE: an empty `iface` is passed through, and the fetcher resolves it
    from the sensor's plan or its single reported NIC, refusing a multi-NIC sensor outright.
    """
    sensor_id = str(body.get("sensor_id") or "").strip()
    if not sensor_id:
        return {}, "sensor_id is required"
    try:
        from weirvern import probe_store  # noqa: PLC0415

        seconds = int(body.get("seconds") or probe_store.DEFAULT_SECONDS)
    except (TypeError, ValueError):
        return {}, "seconds must be a number"
    return {"sensor_id": sensor_id, "iface": str(body.get("iface") or ""), "seconds": seconds}, None


def settings_changes_args(body: dict) -> dict:
    """A non-empty `changes` object. A plan with nothing to change is refused, not written as a no-op."""
    changes = body.get("changes")
    if not isinstance(changes, dict) or not changes:
        raise ValueError("a non-empty 'changes' object is required")
    return {"changes": changes}


def sensor_addresses(ctx) -> list[str]:
    """This host's own addresses, for the self-block check.

    Best-effort BY DESIGN: if they cannot be determined the check is SKIPPED, not failed. A self-block
    check that errored would refuse every rule on a host where the lookup is unavailable, which is
    worse than occasionally missing one -- the operator still sees the rule and can revoke it.

    `getaddrinfo(gethostname())` ALONE IS NOT THE HOST'S ADDRESSES: inside a pod it resolves to the
    POD's address, so the two addresses that must never be blockable -- the management address and the
    gateway -- were never in the list. The roles are added from the same settings the intercept's
    never-intercept check reads, plus `probe_local().host_addresses`, so "this host's addresses" has
    one definition in the product instead of one per caller.
    """
    import socket  # noqa: PLC0415

    out: list[str] = []

    def _add(addr: object) -> None:
        a = str(addr or "").strip()
        if a and a not in out:
            out.append(a)

    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            _add(info[4][0])
    except OSError:
        pass
    try:
        for attr in ("mgmt_addr", "ours", "our_ip", "gateway", "gateway_ip", "mgmt_iface_addr"):
            _add(getattr(ctx.settings, attr, ""))
    except Exception:  # noqa: BLE001
        pass
    try:
        from weirvern.admin import interfaces as ifaces_mod  # noqa: PLC0415

        for a in ifaces_mod.probe_local(timeout=5).host_addresses or []:
            _add(a)
    except Exception:  # noqa: BLE001
        pass
    return out


def window_arg(query: dict, default: int, lo: int, hi: int) -> int:
    """The request's time window: `hours` (relative) or `from`/`to` (absolute).

    The console's global time control sends BOTH: `hours` so every view still has a number to print,
    and `from`/`to` when the operator chose an absolute range. The absolute pair wins and is
    installed for the whole request (weirvern/admin/timewindow.py), so every windowed query answers
    the same stretch of time.

    RAISES ValueError with the reason rather than sending a response, so both the console handler
    and the Flask front door can use it: one parses and sends a 400, the other returns a 400 body.
    Silently falling back to `hours` would answer a different question than the one that was asked.
    """
    hours = _int_arg(query, "hours", default, lo, hi)
    frm = _first(query, "from")
    to = _first(query, "to")
    if not frm and not to:
        return hours
    since, until = timewindow.parse_range(frm, to)
    timewindow.set_window(since, until)
    span = (until - since).total_seconds() / 3600.0
    return max(1, min(hi, int(span) + (1 if span % 1 else 0)))


def _float_arg(query: dict, name: str, default: float, lo: float, hi: float) -> float:
    """Parse and clamp a float query parameter. Normalised through `_first` for the same reason
    `_int_arg` is: `"0.5"[0]` is `"0"`, so a scalar query value would have clamped to zero."""
    raw = _first(query, name)
    try:
        value = float(default if raw is None else raw)
    except (TypeError, ValueError):
        return default
    return max(lo, min(hi, value))


def _query_bool(query: dict, name: str) -> bool | None:
    """A tri-state query flag: True, False, or None when the parameter is absent.

    None is distinct from False on purpose: `unreviewed=` with no value is not the same
    statement as `unreviewed` absent entirely, and a caller that wanted the second must
    not silently get the first. Only explicit truthy spellings turn the flag on.

    READS THROUGH `_first`, because the two surfaces hand over different query shapes: the
    console's dict holds lists and Flask's MultiDict holds scalars, and `"true"[0]` is `"t"`.
    """
    if name not in query:
        return None
    raw = _first(query, name, "")
    return str(raw if raw is not None else "").strip().lower() in ("1", "true", "yes", "on", "")


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
