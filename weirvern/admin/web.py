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

import ipaddress
import json
import logging
from pathlib import Path
from typing import Any

from weirvern.admin import soc as soc_mod
from weirvern.admin import timewindow
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


def settings_apply_args(body: dict) -> dict:
    """The apply form: a non-empty `changes` object, the confirmation, the reason and the revert flag.

    `confirmed` and `revert` are read for truth, as on the console: the form posts checkboxes.
    """
    changes = body.get("changes")
    if not isinstance(changes, dict) or not changes:
        raise ValueError("a non-empty 'changes' object is required")
    return {"changes": changes, "confirmed": bool(body.get("confirmed")),
            "reason": str(body.get("reason") or "").strip(),
            "revert": bool(body.get("revert"))}


def sensor_caps(ctx) -> tuple[bool, bool]:
    """(net_admin, net_raw) for the WORKER, which is what runs the intercept.

    WHY THE WORKER AND NOT ZEEK: `weirvern intercept` is a control-plane command; it executes in the
    worker pod. The worker forges the ARP frames, installs the policy route and drives the forwarding
    path. The zeek pod only captures, and giving the packet parser NET_ADMIN widens the wrong process.

    WHY THE CLUSTER AND NOT THIS PROCESS: the GUI runs in its own pod, and its effective capabilities
    describe the wrong container. A capability that cannot be verified is reported ABSENT, never
    assumed: the gate exists so the in-path mode cannot be enabled without the ability to forward.
    """
    from weirvern.admin import cluster_config as cc  # noqa: PLC0415

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


def mode_gate(ctx, changes: dict) -> str:
    """Reject a mode change that the mode's own prerequisites forbid. "" when fine.

    THE GATE IS `mode.validate`, which is what `weirvern mode siphon` uses: a GUI session must not be a
    way around it, because enabling in-path interception without forwarding working takes the segment
    down, and the check that prevents that has to be the same check.

    ── THE APPLY GRANTS WHAT THE PLAN REQUIRES (measured 2026-11-17) ─────────────────────────────

    This used to judge the change against the capabilities the worker has RIGHT NOW, which produced a
    dead end: selecting siphon in the console was refused with "enabling siphon widens the worker's
    privileges", as if the operator had to widen them by hand and come back. But the apply already
    does exactly that, later and deliberately -- `ClusterConfig.restart` calls
    `reconcile_capabilities`, which sets the worker's block to `required_capabilities` of the config
    it is about to run, so a plan naming siphon comes up with NET_RAW and NET_ADMIN before the
    supervisor arms anything.

    So the gate now asks the question it can actually answer: does this plan require a privilege the
    apply knows how to grant? If it does, the requirement is satisfied BY THE PLAN, and the refusal
    would be asking the operator to pre-do work the same request performs. Everything that cannot be
    granted this way still refuses: the management-NIC rule, an unknown mode, a missing watchdog.
    """
    wanted = None
    for k, v in changes.items():
        if k.strip().upper() == "SENSOR_MODE":
            wanted = str(v)
    if wanted is None:
        return ""
    from weirvern.admin import mode as mode_mod  # noqa: PLC0415

    normalised = mode_mod.normalise(wanted)
    has_net_admin, has_net_raw = sensor_caps(ctx)
    if normalised == mode_mod.MODE_SIPHON:
        # THE PLAN IMPLIES THE PRIVILEGE. `required_capabilities({"SENSOR_MODE": "siphon"})` is
        # exactly NET_RAW + NET_ADMIN, and `restart()` reconciles the worker to that set before it
        # rolls. Treating them as present here is not an assumption: it is the same decision, taken
        # once, in the place that can carry it out.
        has_net_raw = True
        has_net_admin = True
    verdict = mode_mod.validate(normalised, has_net_admin=has_net_admin,
                                has_net_raw=has_net_raw, watchdog_available=True)
    if verdict.ok:
        return ""
    reasons = "; ".join(getattr(verdict, "blockers", []) or [])
    return f"cannot enable {normalised}: {reasons or 'prerequisites are missing'}"


def settings_test_args(body: dict) -> dict:
    """The test run's duration: a number, bounded server-side.

    The bounds are the console's: under 5 seconds is not an observation, and over 600 would hold a
    request open longer than anyone is watching.
    """
    raw_seconds = body.get("seconds")
    try:
        seconds = float(raw_seconds) if raw_seconds is not None else 30.0
    except (TypeError, ValueError) as exc:
        raise ValueError("seconds must be a number") from exc
    if not 5.0 <= seconds <= 600.0:
        raise ValueError("seconds must be between 5 and 600")
    return {"seconds": seconds}


def sonar_args(body: dict) -> dict:
    """The survey's three optional inputs, all free text (validated by the survey module's own check)."""
    return {"sensor_id": str(body.get("sensor") or "").strip(),
            "iface": str(body.get("interface") or "").strip(),
            "mgmt": str(body.get("mgmt_interface") or "").strip()}


def model_action_args(body: dict, tail: str = "") -> dict:
    """The action, the note and the target. `tail` is the URL's last segment, if any.

    THE BODY WINS OVER THE URL: `/api/models/retrain/keep` is the shape a reader guesses from the route
    table, and a body naming a different action must not be silently overridden by it.
    """
    from weirvern.models import actions  # noqa: PLC0415

    action = str(body.get("action") or "").strip().lower()
    if not action and tail in (actions.RETRAIN, actions.KEEP, actions.TRASH):
        action = tail
    if action not in (actions.RETRAIN, actions.KEEP, actions.TRASH):
        raise ValueError("action must be retrain, keep or trash")
    note = str(body.get("note") or "").strip()
    # BF-9: choosing the model this deployment will serve (or discarding the candidate) is a decision
    # like any other -- the note is required for keep and trash.
    if action in (actions.KEEP, actions.TRASH) and not note:
        raise ValueError("choosing the model to serve is a decision; a note is required for keep and "
                         "trash and is recorded with your name")
    return {"action": action, "note": note,
            "target_id": str(body.get("target_id") or "").strip()}


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


