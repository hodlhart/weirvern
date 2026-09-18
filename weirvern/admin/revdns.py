"""Reverse DNS, so the UI can show `spyro.home` instead of `192.168.2.42`.

Measured on a real deployment before designing this, because the numbers dictate
the design:

    192.168.2.42     0.00s -> spyro.home        (local resolver answers instantly)
    192.168.2.1      0.00s -> unifi
    192.168.2.159    0.00s -> Weirvern.home
    162.248.221.199  0.30s -> derp21b.tailscale.com
    8.8.8.8          0.24s -> dns.google
    10.20.30.11      0.00s -> no PTR            (fails fast, does not hang)

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
# A single lookup must never block a page render. Measured worst case was ~0.3s,
# so 1s is generous headroom; anything slower is treated as "no name".
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
    """

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
        with self._lock:
            self._entries[addr] = (time.time() + ttl, value)

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()

    def size(self) -> int:
        with self._lock:
            return len(self._entries)


_CACHE = _Cache()

# Resolving is done with a socket timeout rather than in a thread pool. gethostbyaddr
# is blocking with no timeout argument, so setdefaulttimeout is the only portable
# way to bound it; per-call threads would add unbounded thread creation on a
# dashboard listing hundreds of addresses.
socket.setdefaulttimeout(LOOKUP_TIMEOUT_S)


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
        name = socket.gethostbyaddr(addr)[0]
    except (socket.herror, socket.gaierror, OSError) as exc:
        logger.debug("no PTR for %s: %s", addr, exc)
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
    """What the UI should display: `spyro.home (192.168.2.42)`, or just the IP.

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
