"""Which addresses are HOSTS, and which are only FRAMES.

MEASURED ON A LIVE SEGMENT (2026-10-16, the first real siphon session). The Netflow tab's
top talkers were, in order: `fe80::aa9c:6cff:fe96:b62d` (the gateway's link-local, NDP),
`ff02::fb` (mDNS), `224.0.0.251` (mDNS again, v4), and `192.168.3.255` (subnet broadcast).
The connection graph drew the all-routers group `ff02::2` as a node with three peers. Every
one of those frames is real -- and none of it is a HOST. A view that ranks them as talkers is
unreadable, and worse, a model that treats them as hosts learns about multicast groups.

So the test lives in one place, phrased as a question about ADDRESS CLASS rather than a
per-call denylist: "could this address be the unicast address of a host?" -- which is the
question every caller actually has.
"""

from __future__ import annotations

import ipaddress

# Address classes that are never the unicast address of a host: multicast (v4 + v6),
# the limited broadcast, IPv6 link-local (NDP/RS), IPv4 link-local (APIPA), loopback,
# and the unspecified addresses. Kept as CIDR strings because ClickHouse answers the
# same question with `isIPAddressInRange`, so ONE list serves both languages -- two
# lists would drift and the drifting copy would be the one nobody tested.
NOISE_CIDRS: tuple[str, ...] = (
    "224.0.0.0/4",        # IPv4 multicast, mDNS (224.0.0.251) included
    "255.255.255.255/32",  # limited broadcast
    "ff00::/8",           # IPv6 multicast, incl. ff02::fb (mDNS) and ff02::2 (all-routers)
    "fe80::/10",          # IPv6 link-local, incl. every EUI-64 NDP address
    "169.254.0.0/16",     # IPv4 link-local
    "127.0.0.0/8",        # loopback
    "0.0.0.0/32",
    "::1/128",
    "::/128",
)


def is_noise(addr: str | None) -> bool:
    """True when this address cannot be a host: multicast, broadcast, link-local, loopback.

    Returns False for anything that does not parse as an address -- an unparseable string is
    not evidence of noise, and guessing here would hide real rows.
    """
    if not addr:
        return False
    try:
        ip = ipaddress.ip_address(str(addr).strip())
    except ValueError:
        return False
    if ip.is_multicast or ip.is_loopback or ip.is_unspecified:
        return True
    # `is_link_local` covers fe80::/10 on v6 and 169.254/16 on v4 in CPython's ipaddress.
    if ip.is_link_local:
        return True
    if isinstance(ip, ipaddress.IPv4Address):
        if int(ip) == 0xFFFFFFFF:
            return True
        # The subnet-directed broadcast, e.g. 192.168.3.255 -- same stated /24 assumption as
        # `sql_host`, and the same cost if a host is ever numbered x.x.x.255.
        if str(ip).endswith(".255"):
            return True
    return False


def sql_host(column: str) -> str:
    """A SQL fragment (ClickHouse) that is true only for addresses that can be hosts.

    One fragment per COLUMN, so a query can ask the question of `src_addr`, `dst_addr`, or
    both endpoints of an edge, and the same rows answer to the same rule everywhere.

    A SUBNET-DIRECTED BROADCAST (`192.168.3.255` on a /24) carries no marker that separates
    it from a host address without the segment's mask -- but LAN segments are /24 in every
    deployment this has been run on, and a tech reading `x.x.x.255` as "a machine" is the
    exact confusion this module exists to prevent. So the last-octet rule is included, and
    the cost is stated: it would hide a host that is literally numbered x.x.x.255. If that
    ever matters, the rule is one line, in one place, with this paragraph next to it.
    """
    tests = [f"isIPAddressInRange({column}, '{cidr}')" for cidr in NOISE_CIDRS]
    tests.append(f"endsWith({column}, '.255')")
    return "(" + " OR ".join(tests) + ") = 0"


def noise_sql(column: str) -> str:
    """The complement of `sql_host`, for COUNTING what a host-only view leaves out.

    The project rule is that an exclusion is stated rather than silent, so every panel that
    filters has a way to say how many rows it filtered.
    """
    tests = [f"isIPAddressInRange({column}, '{cidr}')" for cidr in NOISE_CIDRS]
    tests.append(f"endsWith({column}, '.255')")
    return "(" + " OR ".join(tests) + ") = 1"
