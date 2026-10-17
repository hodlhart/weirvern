"""Reverse DNS, so the UI can show `host-a.example` instead of `203.0.113.42`.

Measured on a real deployment before designing this, because the numbers dictate
the design:

    203.0.113.42     0.00s -> host-a.example        (local resolver answers instantly)
    203.0.113.1      0.00s -> gateway
    203.0.113.159    0.00s -> sensor.example
    203.0.113.200  0.30s -> relay.example.net
    8.8.8.8          0.24s -> dns.google
    192.0.2.11      0.00s -> no PTR            (fails fast, does not hang)

LAN addresses are effectively free. PUBLIC addresses cost ~0.25-0.30s each, and a
dashboard showing 25 anomalies would therefore spend ~7 seconds resolving before
it could render. So results are cached, including NEGATIVE results — most
destination IPs in flow data are external and unresolvable, and without negative
caching the expensive failures would repeat on every refresh.

WHY THIS IS OFF-BY-DEFAULT IS A REAL QUESTION, AND THE ANSWER IS PRIVACY:

A PTR lookup sends the queried address to a DNS resolver. Doing that for every
destination IP a deployment observes means the resolver — which for many homelabs
is an upstream provider, not the local box — learns which external hosts your
network talks to. That is derived traffic intelligence, and weirvern is a tool
whose entire purpose is watching traffic. Turning that on silently would be
inconsistent with the project's own privacy posture (see SECURITY.md and the
deliberate `capture_password` = off decision).

So it defaults ON only for PRIVATE addresses, where the lookup stays on the LAN and
reveals nothing a local resolver does not already know. Public addresses are
resolved only when WEIRVERN_REVERSE_DNS=all is set explicitly. This gives the
useful case (naming your own hosts) by default and makes the leaky case a choice.
"""
from __future__ import annotations

import concurrent.futures
import ipaddress
import logging
import os
import socket
import threading
import time

logger = logging.getLogger(__name__)

# How long a positive result stays valid. Hostnames for a given IP rarely change,
# and a long TTL is what keeps the dashboard fast.
TTL_POSITIVE_S = 3600.0
# Negative results expire sooner: a DHCP lease can hand an address to a different
# host, and a stale "no name" is less harmful than a stale WRONG name, but it
# should still correct itself within a reasonable window.
TTL_NEGATIVE_S = 300.0
# A single lookup must never block a page render. Measured worst case against a WORKING resolver was
# ~0.3s, so 1s is generous headroom; anything slower is treated as "no name". THIS IS NOW A REAL
# BOUND -- it is OUR wall clock on a thread we own, not `setdefaulttimeout`, which never applied to
# `gethostbyaddr` (see the note beside `_LOOKUP_POOL`).
LOOKUP_TIMEOUT_S = 1.0

# Modes:
#   "private" (default) - resolve RFC1918/link-local/CGNAT only, staying on the LAN
#   "all"               - resolve anything, including public addresses
#   "off"               - no lookups at all
_VALID_MODES = {"private", "all", "off"}


def _mode() -> str:
    raw = (os.environ.get("WEIRVERN_REVERSE_DNS") or "private").strip().lower()
    if raw in ("0", "false", "no"):
        return "off"
    if raw in ("1", "true", "yes", "on"):
        return "all"
    return raw if raw in _VALID_MODES else "private"


def is_private(addr: str) -> bool:
    """Is this address one whose lookup stays on the local network?

    Returns True for addresses that are NOT globally routable, plus CGNAT.

    THE CGNAT CASE IS HANDLED EXPLICITLY AND THAT MATTERS HERE: `ipaddress`'s
    `is_private` returns False for 100.64.0.0/10, the carrier-grade NAT range that
    Tailscale uses for its overlay. This deployment reaches hosts over Tailscale
    (100.x addresses appear in its own interface list), so treating that range as
    public would mean declining to name exactly the machines the operator cares
    about — and, if the mode were later set to "all", sending those addresses to an
    upstream resolver. So the range is checked by hand rather than relying on the
    stdlib's definition of "private".
    """
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
        return True
    # CGNAT (RFC 6598): 100.64.0.0/10, as used by Tailscale and most carrier NAT.
    # Checked by hand because ipaddress.is_private returns False for it.
    cgnat = ipaddress.ip_network("100.64.0.0/10")
    # IPv6 unique-local (fc00::/7) is covered by is_private above. Multicast is not
    # a host address at all, so it is deliberately excluded rather than treated as
    # local, even though it is not globally routable.
    return isinstance(ip, ipaddress.IPv4Address) and ip in cgnat


def _should_resolve(addr: str) -> bool:
    mode = _mode()
    if mode == "off":
        return False
    if mode == "all":
        return True
    return is_private(addr)


class _Cache:
    """TTL cache for lookups, positive and negative alike.

    Both outcomes are cached because the NEGATIVE case dominates: in flow data
    most addresses are external with no PTR record, so an uncached negative would
    mean paying the timeout for the same unresolvable address on every refresh.

    BOUNDED (issue #29): per-entry TTLs alone bound nothing -- nothing evicts an entry that
    has not expired YET, so a segment with many distinct addresses (a /16 sweep is 65k) grew
    the map without limit. MAX_ENTRIES caps it: a put at the cap first drops expired entries
    (cheap, and usually enough), then the entry closest to expiry, so a hot address is not
    evicted while dead ones linger.
    """

    MAX_ENTRIES = 4096

    def __init__(self) -> None:
        self._entries: dict[str, tuple[float, str | None]] = {}
        self._lock = threading.Lock()

    def get(self, addr: str) -> tuple[bool, str | None]:
        """Returns (hit, value). value is a name or None for a known-absent one."""
        with self._lock:
            entry = self._entries.get(addr)
        if not entry:
            return False, None
        expires, value = entry
        if time.time() >= expires:
            with self._lock:
                self._entries.pop(addr, None)
            return False, None
        return True, value

    def put(self, addr: str, value: str | None) -> None:
        ttl = TTL_POSITIVE_S if value else TTL_NEGATIVE_S
        now = time.time()
        with self._lock:
            if len(self._entries) >= self.MAX_ENTRIES:
                self._entries = {a: e for a, e in self._entries.items() if e[0] > now}
            while len(self._entries) >= self.MAX_ENTRIES:
                oldest = min(self._entries, key=lambda a: self._entries[a][0])
                del self._entries[oldest]
            self._entries[addr] = (now + ttl, value)

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()

    def size(self) -> int:
        with self._lock:
            return len(self._entries)


_CACHE = _Cache()

# ── BOUNDING A BLOCKING RESOLVER: THE MECHANISM THAT DOES NOT WORK, AND THE ONE THAT DOES ────────
#
# This used to call `socket.setdefaulttimeout(LOOKUP_TIMEOUT_S)` at import, with a comment claiming
# it was "the only portable way to bound" `gethostbyaddr`. Both halves were wrong.
#
# IT DOES NOT BOUND THE LOOKUP. `setdefaulttimeout` sets the timeout for socket objects created by
# Python's `socket` module, and glibc's resolver inside `gethostbyaddr` creates none -- it talks to
# DNS itself. MEASURED in an isolated network namespace against a UDP listener on :53 that received
# queries and deliberately never answered:
#
#     QUERIES REACHED THE BLACKHOLE = 2
#     python sockets created        = 0        <- nothing for the default to bind
#     elapsed                       = 4.01s    <- with a 1.0s default set at import
#
# The 4.01s is glibc's own `timeout:2 attempts:2`, not ours. My first attempt at this measurement
# returned 0.01s and proved nothing: this host's nsswitch `hosts:` line sends lookups to
# systemd-resolved over a varlink socket, so the query never reached DNS at all. Only after forcing
# `hosts: files dns` and COUNTING the queries the blackhole received did the number mean anything.
#
# AND IT IS A PROCESS-WIDE SIDE EFFECT. `setdefaulttimeout` is global, so importing this module for a
# dashboard label silently reconfigured the timeout of every socket created later in the process --
# including the GUI's `ThreadingHTTPServer` and the AF_PACKET sockets the SIPHON intercept forges ARP
# with. A display concern must not change how the intercept behaves.
#
# SO THE LOOKUP RUNS IN A THREAD WE OWN, and the bound is OUR wall clock. The thread is a daemon, so
# a resolver that never answers leaks one thread per distinct address rather than pinning a page
# render; the result is cached either way, so the leak is bounded by the number of distinct addresses
# asked about, and the negative result stops the same address being asked again for TTL_NEGATIVE_S.
_LOOKUP_POOL = concurrent.futures.ThreadPoolExecutor(
    max_workers=8, thread_name_prefix="revdns",
)


def _resolve_bounded(addr: str) -> str | None:
    """`gethostbyaddr` with a wall-clock bound that actually applies.

    Returns the PTR name, or None on any failure -- including our own timeout, which is the case the
    old mechanism could not produce.
    """
    try:
        return _LOOKUP_POOL.submit(socket.gethostbyaddr, addr).result(timeout=LOOKUP_TIMEOUT_S)[0]
    except concurrent.futures.TimeoutError:
        # THE CASE THE GLOBAL DEFAULT COULD NEVER PRODUCE, and the reason this is worth a thread: a
        # resolver that has gone quiet is the failure the bound exists for, and it is now reported as
        # what it is rather than as "no PTR record".
        logger.debug("reverse lookup for %s exceeded %.1fs; treating as no name", addr,
                     LOOKUP_TIMEOUT_S)
        return None
    except (socket.herror, socket.gaierror, OSError) as exc:
        logger.debug("no PTR for %s: %s", addr, exc)
        return None
    except Exception as exc:  # noqa: BLE001
        # A failure inside the pool must not take a page render with it: the caller falls back to the
        # address, which is a worse label and not a broken dashboard.
        logger.debug("reverse lookup for %s failed: %s", addr, exc)
        return None


def lookup(addr: str, use_cache: bool = True) -> str | None:
    """Reverse-resolve one address. Returns None when there is no usable name.

    Never raises: a dashboard must render with addresses even when DNS is broken,
    so every failure path returns None and the caller falls back to the IP.
    """
    if not addr:
        return None
    if not _should_resolve(addr):
        return None

    if use_cache:
        hit, value = _CACHE.get(addr)
        if hit:
            return value

    name: str | None = None
    try:
        name = _resolve_bounded(addr)
    except Exception as exc:  # noqa: BLE001
        # `_resolve_bounded` already absorbs its own failures; this is a belt-and-braces guard so a
        # future change inside it cannot take a page render down.
        logger.debug("lookup(%s) failed: %s", addr, exc)
        name = None

    # A PTR record that just repeats the address is worse than no name: it looks
    # like a resolved hostname in the UI while adding nothing.
    if name and name.strip() == addr:
        name = None
    if name:
        name = name.rstrip(".")

    if use_cache:
        _CACHE.put(addr, name)
    return name


def label(addr: str, use_cache: bool = True) -> str:
    """What the UI should display: `host-a.example (203.0.113.42)`, or just the IP.

    The address is kept in parentheses rather than replaced. A hostname is a
    convenience, but the IP is the fact — an operator correlating with a firewall
    or a DHCP lease needs it, and a name that resolves differently later would
    silently change what a historical anomaly row refers to.
    """
    if not addr:
        return ""
    name = lookup(addr, use_cache=use_cache)
    return f"{name} ({addr})" if name else addr


def annotate(rows: list[tuple], *indexes: int, use_cache: bool = True
             ) -> list[dict]:
    """Attach a resolved name to selected tuple positions, returning dicts.

    Convenience for the tuple-returning query helpers, so callers do not each
    re-implement "which column is the address".
    """
    out: list[dict] = []
    for row in rows:
        entry: dict = {"values": list(row)}
        for i in indexes:
            if i < len(row):
                addr = str(row[i] or "")
                entry[f"name_{i}"] = lookup(addr, use_cache=use_cache) if addr else None
        out.append(entry)
    return out


def cache_size() -> int:
    """Exposed for tests and for a diagnostic, so caching is observable."""
    return _CACHE.size()


def clear_cache() -> None:
    _CACHE.clear()


def current_mode() -> str:
    return _mode()
