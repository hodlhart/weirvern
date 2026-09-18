"""In-path intercept (weir mode): the ARP dataplane.

WHAT THIS IS, AND WHAT IT IS NOT. Weirvern inserts itself into the path between hosts and
their gateway by forging ARP mappings, then RELAYS the traffic it intercepts. This is an
L2/L3 redirection -- **not** a TLS intercept. Nothing is decrypted and no certificate is
substituted. The point is coverage: on a veth (which is what a container gets) the bridge
does not flood switched unicast, so a passive sensor sees only broadcast noise. Measured
on the test deployment: ~73% of what reached the passive sensor was broadcast, and Zeek
reported 62-65% capture loss. Traffic addressed to us cannot be "missed" the same way.

WHY A WATCHDOG IS NOT OPTIONAL. In weir mode Weirvern is a ROUTER. If it stops forwarding
-- crash, OOM kill, node reboot -- every host whose ARP cache we poisoned loses the network
until that entry expires, which is typically minutes. That is the difference between a
monitoring gap and a LAN outage, and it is why `mode.py` refuses to enable weir without a
watchdog. This module always arms the watchdog BEFORE sending the first poison frame, so
there is no window in which a mapping exists unmanaged.

WHY THE FORWARDING IS DONE IN THE KERNEL. We do not copy packets in userspace. Poisoning
makes the kernel the next hop for the victim's traffic; with `ip_forward=1` it routes it
onwards. That is far cheaper than a userspace relay and it means a packet is never held in
a process that can die. The failure mode is then a routing one, which the watchdog covers
by withdrawing the mappings.

WHAT IS DELIBERATELY NOT HERE: no packet payload is inspected, stored, or modified. The
relay is the kernel's, so by construction this process never holds the traffic.
"""
from __future__ import annotations

import logging
import re
import socket
import struct
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

ETH_P_ARP = 0x0806
ETH_P_ALL = 0x0003

# How often to re-send poison frames. ARP cache entries on modern hosts live minutes, but
# some stacks (and some switch/AP combinations) age faster. 5s is well inside the shortest
# common timeout and costs 2 tiny frames per host per interval.
DEFAULT_REFRESH_S = 5.0


# ---------------------------------------------------------------------------
# reading the real network state
# ---------------------------------------------------------------------------


def read_mac(iface: str) -> str | None:
    """The interface's own MAC, or None if it cannot be read."""
    path = Path(f"/sys/class/net/{iface}/address")
    try:
        mac = path.read_text().strip()
    except OSError:
        return None
    return mac or None


def read_neighbour_mac(iface: str, ip: str) -> str | None:
    """The MAC currently known for `ip`, from the kernel neighbour table.

    Read from /proc rather than by shelling out to `ip neigh`: this runs in a container
    that has NO `ip` command (the zeek image ships busybox, perl and Zeek only -- verified).
    Shelling out would work on a dev host and fail in production, which is the wrong way
    round.

    NUD states other than REACHABLE/STALE/DELAY/PROBE mean the entry is not usable
    (INCOMPLETE/FAILED), so the MAC is not returned for those.
    """
    try:
        lines = Path("/proc/net/arp").read_text().splitlines()
    except OSError:
        return None
    want_flags = {"0x2", "0x0"}  # 0x2 = ATF_COM (complete)
    for line in lines[1:]:
        parts = line.split()
        if len(parts) < 6:
            continue
        addr, _hwtype, flags, mac, _mask, dev = parts[:6]
        if addr != ip or dev != iface:
            continue
        if mac in ("00:00:00:00:00:00", ""):
            return None
        if flags not in want_flags and flags != "0x2":
            continue
        return mac.lower()
    return None


def ping_host(iface: str, ip: str, timeout_s: float = 1.0) -> bool:
    """Send one ICMP echo to populate the neighbour table.

    WHY: to forge a mapping FOR a host we must already know its real MAC, which means the
    kernel must have resolved it. A host that has not been spoken to recently has no
    neighbour entry, so we probe first. Without this the first intercept attempt fails with
    "unknown host MAC" and the operator sees nothing happen.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as s:
            s.settimeout(timeout_s)
            # ICMP echo request, id 0, seq 0
            packet = struct.pack("!BBHHH", 8, 0, 0, 0, 1)
            checksum = _icmp_checksum(packet)
            packet = struct.pack("!BBHHH", 8, 0, checksum, 0, 1)
            s.sendto(packet, (ip, 0))
    except (OSError, PermissionError):
        return False
    return True


def _icmp_checksum(data: bytes) -> int:
    """Standard one's-complement checksum over 16-bit words."""
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def resolve_mac(iface: str, ip: str, attempts: int = 3, wait_s: float = 0.4) -> str | None:
    """Best-effort MAC for `ip`, probing the neighbour table first."""
    mac = read_neighbour_mac(iface, ip)
    if mac:
        return mac
    for _ in range(attempts):
        if not ping_host(iface, ip):
            break
        time.sleep(wait_s)
        mac = read_neighbour_mac(iface, ip)
        if mac:
            return mac
    return None


# ---------------------------------------------------------------------------
# the packet sender
# ---------------------------------------------------------------------------


class ArpSender:
    """Writes Ethernet frames to an AF_PACKET socket.

    Raw sockets need CAP_NET_RAW, which `mode.py` already requires for weir. Kept as a
    class so the watchdog (which takes a `sender` callable) can be given a fake in tests.
    """

    def __init__(self, iface: str) -> None:
        self.iface = iface
        self._sock: socket.socket | None = None

    def open(self) -> None:
        if self._sock is None:
            self._sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ARP))
            self._sock.bind((self.iface, 0))

    def __call__(self, frame: bytes, kind: str = "poison") -> None:
        self.open()
        assert self._sock is not None
        self._sock.send(frame)

    def close(self) -> None:
        if self._sock is not None:
            self._sock.close()
            self._sock = None


# ---------------------------------------------------------------------------
# forwarding prerequisites
# ---------------------------------------------------------------------------


@dataclass
class ForwardingState:
    ip_forward: bool
    rp_filter_off: bool
    problems: list[str] = field(default_factory=list)
    # The policy-routing pieces. See ensure_forwarding_path for why they are mandatory.
    rule_installed: bool = False
    table_installed: bool = False

    @property
    def ready(self) -> bool:
        return not self.problems


def sysctl_path(name: str, iface: str = "") -> Path:
    """Where a sysctl lives under /proc/sys.

    Dots become slashes, `all`/interface-qualified names keep their second component.
    Examples:
        net.ipv4.ip_forward            -> /proc/sys/net/ipv4/ip_forward
        net.ipv4.conf.all.rp_filter    -> /proc/sys/net/ipv4/conf/all/rp_filter
    """
    parts = name.split(".")
    return Path("/proc/sys") / "/".join(parts)


def read_sysctl(name: str) -> int | None:
    try:
        return int(sysctl_path(name).read_text().strip())
    except (OSError, ValueError):
        return None


def check_forwarding(iface: str) -> ForwardingState:
    """Verify the two kernel settings weir mode cannot work without.

    Both failures have a specific symptom, recorded here because a misconfigured intercept
    presents as "the network is slow/broken" rather than as an error:

      * `ip_forward=0`      -> we poison the mapping and then DROP the traffic. The victim
                               loses the network completely: the worst possible outcome,
                               and it looks like a hardware fault.
      * `rp_filter != 0`    -> the kernel's reverse-path check discards relayed packets
                               whose return path does not match the interface they arrived
                               on. Symptom: one-way traffic, so TCP connects hang.
    """
    state = ForwardingState(ip_forward=False, rp_filter_off=False)

    fwd = read_sysctl("net.ipv4.ip_forward")
    if fwd is None:
        state.problems.append("could not read net.ipv4.ip_forward")
    elif fwd != 1:
        state.problems.append(
            "net.ipv4.ip_forward is 0: relayed traffic would be DROPPED, so poisoning "
            "would take hosts off the network rather than pass traffic through"
        )
    else:
        state.ip_forward = True

    # rp_filter must be 0 for `all` and for the capture interface. `all` alone is not
    # enough: the per-interface setting is more restrictive when set.
    for scope in ("all", iface):
        name = f"net.ipv4.conf.{scope}.rp_filter"
        value = read_sysctl(name)
        if value is None:
            # A missing per-interface file means the interface does not exist yet, which
            # is its own problem but not one to report twice.
            if scope == iface:
                state.problems.append(f"interface {iface} has no rp_filter setting")
            continue
        if value != 0:
            state.problems.append(
                f"{name} is {value}: the reverse-path check will drop relayed packets "
                f"whose return route differs from {scope}, giving one-way traffic"
            )
        elif scope == iface:
            state.rp_filter_off = True

    return state


# ---------------------------------------------------------------------------
# the forwarding path -- the part ip_forward alone does not give you
# ---------------------------------------------------------------------------

# A dedicated routing table for relayed traffic, and the rule priority that selects it.
# 1000 sits between the kernel's `local` rule (0) and `main` (32766), so it wins for the
# traffic we care about without disturbing anything else.
POLICY_TABLE = 100
POLICY_PRIORITY = 1000


def _run(*args: str) -> tuple[int, str]:
    """Run a command, returning (rc, combined output). Never raises."""
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.SubprocessError) as exc:
        return 1, str(exc)
    return p.returncode, (p.stdout + p.stderr).strip()


def forwarding_rule_text(iface: str) -> str:
    """`ip rule show` output, for asserting the policy rule exists."""
    rc, out = _run("ip", "rule", "show")
    return out if rc == 0 else ""


def forwarding_table_text() -> str:
    """`ip route show table <POLICY_TABLE>` output."""
    rc, out = _run("ip", "route", "show", "table", str(POLICY_TABLE))
    return out if rc == 0 else ""


def _rule_installed(iface: str) -> bool:
    return re.search(rf"iif\s+{re.escape(iface)}\s+lookup\s+{POLICY_TABLE}\b",
                     forwarding_rule_text(iface)) is not None


def _table_has_default(iface: str, gateway: str) -> bool:
    text = forwarding_table_text()
    return re.search(rf"default\s+via\s+{re.escape(gateway)}\s+dev\s+{re.escape(iface)}\b",
                     text) is not None


def forwarding_path_problems(iface: str, gateway: str,
                             sample_src: str | None = None) -> list[str]:
    """Whether a FORWARDED packet would actually leave by the capture interface.

    THE BUG THIS EXISTS FOR, measured on a live boot:

        ip route get 192.0.2.1 from 192.168.3.193 iif eth1
            -> via 192.168.2.1 dev eth0                 <-- WRONG INTERFACE
        with `iif eth1 -> table 100` installed:
            -> via 192.168.3.1 dev eth1 table 100       <-- correct

    `ip_forward=1` makes the kernel willing to forward; it does NOT decide WHERE. A relayed
    packet's destination is a public address, so it matches the DEFAULT route -- which on a
    two-NIC sensor points at the management network. The packet then leaves by the wrong
    interface carrying the victim's source address onto a segment that does not serve it,
    where an upstream router drops it as a martian.

    The symptom is "the network is slow or flaky", not an error, which is why this is
    checked rather than assumed from `ip_forward`.

    HOW IT CHECKS, and why not simply `ip route get`. Measured: the form WITHOUT a source
    address FAILS on this iproute2 --

        ip route get 192.0.2.1 iif eth1
            -> RTNETLINK answers: Invalid argument

    -- because specifying `iif` requires a source to select the rule. Reading that error as
    "the route goes elsewhere" made this function report a problem whenever no source was
    supplied, which would have aborted EVERY real intercept with a misleading message. So
    the rule and table are inspected directly, which is deterministic, and the route lookup
    is used only as corroboration when a representative source address is available.
    """
    problems: list[str] = []
    remedy = (f"Install it with: ip rule add iif {iface} lookup {POLICY_TABLE}, plus a "
              f"default via {gateway} dev {iface} in table {POLICY_TABLE}.")

    if not _rule_installed(iface):
        problems.append(
            f"no policy rule sends traffic arriving on {iface} to table {POLICY_TABLE}, so "
            f"a FORWARDED packet would match the default route and leave by a different "
            f"interface -- carrying the victim's source address onto the wrong segment, "
            f"where it is dropped upstream. {remedy}"
        )
    if not _table_has_default(iface, gateway):
        problems.append(
            f"table {POLICY_TABLE} has no default via {gateway} dev {iface}, so relayed "
            f"traffic has nowhere to go on this interface. {remedy}"
        )

    # Corroboration only: this needs a non-local source to represent forwarded traffic, and
    # it errors outright without one. Absence of a sample is not a problem.
    if sample_src:
        # NOTE the pipe is gone. `sh -c "... | head -1"` reports the exit status of `head`,
        # which is 0 even when `ip route get` FAILED -- so the error text "RTNETLINK answers:
        # Invalid argument" was read as a route and reported as "would leave via a different
        # interface". Measured live: that produced a bogus BLOCKED on a correct
        # configuration. No pipe, so the command's real status is visible.
        rc, out = _run("ip", "route", "get", "192.0.2.1", "from", sample_src, "iif", iface)
        first = out.splitlines()[0] if out else ""
        # A routing ERROR is not a misroute. Report nothing rather than a false blocker; the
        # rule and table checks above are the authoritative ones.
        clean = bool(first) and "RTNETLINK" not in first and "Error" not in first
        if rc == 0 and clean and f"dev {iface}" not in first:
            problems.append(
                f"a packet from {sample_src} arriving on {iface} would leave via a "
                f"different interface ({first.strip()})."
            )
    return problems


def ensure_forwarding_path(iface: str, gateway: str,
                           gateway_mac: str | None = None) -> list[str]:
    """Install the policy route that makes forwarded traffic use the capture interface.

    Idempotent: deletes and re-adds, so a stale entry from a previous run cannot persist.
    Returns a list of problems; empty means the path is correct.

    Also refuses to touch anything if the gateway is not reachable on this interface, so a
    wrong --gateway cannot install a route that black-holes the segment.

    `gateway_mac` should be supplied when the caller already knows it (the plan does). The
    fallback lookup reads the kernel neighbour table, which is empty when the capture
    interface has no address yet -- the normal state while an operator is still choosing one
    -- so relying on the lookup alone refuses a perfectly valid plan.
    """
    problems: list[str] = []

    # Refuse to install a default route via a gateway we cannot reach. Getting this wrong is
    # worse than not installing it: a bad default in table 100 would black-hole all relayed
    # traffic rather than merely misrouting it.
    mac = gateway_mac or resolve_mac(iface, gateway)
    if not mac:
        return [f"gateway {gateway} did not resolve on {iface}, so a route via it would "
                f"black-hole relayed traffic. Check --gateway and the interface."]

    _run("ip", "route", "flush", "table", str(POLICY_TABLE))
    rc, out = _run("ip", "route", "add", "default", "via", gateway, "dev", iface,
                   "table", str(POLICY_TABLE))
    if rc != 0:
        problems.append(f"could not add the policy route: {out}")

    _run("ip", "rule", "del", "iif", iface, "lookup", str(POLICY_TABLE))
    rc, out = _run("ip", "rule", "add", "iif", iface, "lookup", str(POLICY_TABLE),
                   "priority", str(POLICY_PRIORITY))
    if rc != 0:
        problems.append(f"could not add the policy rule: {out}")

    problems.extend(forwarding_path_problems(iface, gateway))
    return problems


def remove_forwarding_path(iface: str) -> None:
    """Withdraw the policy route. Idempotent, and never raises.

    Called on teardown because a leftover rule sends ALL traffic arriving on that interface
    to table 100 -- which, once the address is removed, is a table with no routes. That
    would break traffic the operator never intended to touch.
    """
    _run("ip", "rule", "del", "iif", iface, "lookup", str(POLICY_TABLE))
    _run("ip", "route", "flush", "table", str(POLICY_TABLE))


def add_address(iface: str, address: str, segment: str) -> tuple[int, str]:
    """Put `address` on `iface` with the segment's prefix length. (rc, output).

    WHY THIS IS PART OF THE INTERCEPT AND NOT LEFT TO THE OPERATOR. Without an address on the
    capture interface the kernel has no route on that interface, so it cannot forward relayed
    traffic, and neighbour lookups for anything on the segment fail. Measured live: the plan
    refused to build with "cannot resolve the gateway" purely because the interface had no
    address -- the gateway was answering ARP the whole time. Poisoning without an address
    would therefore take hosts off the network instead of relaying them.

    The prefix comes from the segment so a mistyped address cannot silently land on the wrong
    netmask. Idempotent in effect: adding an address the interface already holds is reported
    by the kernel, and the caller checks first.
    """
    import ipaddress

    try:
        prefix = ipaddress.ip_network(segment, strict=False).prefixlen
    except ValueError as exc:
        return 1, f"bad segment {segment!r}: {exc}"
    rc, out = _run("ip", "addr", "add", f"{address}/{prefix}", "dev", iface)
    if rc == 0:
        # Bring it up explicitly: an address on a down interface looks configured and does
        # nothing, which is a confusing way to fail.
        _run("ip", "link", "set", iface, "up")
    return rc, out


def remove_address(iface: str, address: str, segment: str) -> None:
    """Withdraw the address this run added. Idempotent, never raises.

    Called on every exit path. Leaving an address behind changes the host's behaviour
    permanently -- a leftover address on the capture interface keeps a route and keeps
    accepting traffic for a segment the operator never asked to be involved in.
    """
    import ipaddress

    try:
        prefix = ipaddress.ip_network(segment, strict=False).prefixlen
    except ValueError:
        prefix = 24
    _run("ip", "addr", "del", f"{address}/{prefix}", "dev", iface)


SYSCTL_WRITE_HINT = (
    "weir mode needs, inside the container:\n"
    "    sysctl -w net.ipv4.ip_forward=1\n"
    "    sysctl -w net.ipv4.conf.all.rp_filter=0\n"
    "    sysctl -w net.ipv4.conf.<iface>.rp_filter=0\n"
    "In Kubernetes these belong in the pod's securityContext (sysctls: []) or in the "
    "node's config, since a container cannot set them by default."
)


def find_free_addresses(iface: str, segment: str, src_ip: str,
                        count: int = 3, exclude: set[str] | None = None) -> list[str]:
    """Candidate addresses on `segment` that nothing answered ARP for.

    WHY THIS IS OFFERED RATHER THAN AUTO-ASSIGNED: intercept needs an address on the
    segment to relay from, and picking one silently risks an address conflict on someone
    else's network -- a worse outcome than not testing at all. So the operator is shown the
    segment, told which addresses are already taken, and offered free ones.

    WHY NOT DHCP: a DHCP address can change or be withdrawn mid-intercept, and that is the
    one failure the watchdog cannot distinguish from idleness. If the lease goes away the
    connected route disappears, so the poisoned hosts keep believing we are the gateway
    while we can no longer forward for them -- a segment-wide outage with a health monitor
    reporting "quiet", because the forwarding counter never advanced. A static address we
    set, verify free, and can remove deterministically on teardown has none of that.

    `src_ip` must be an address the interface already has, or most stacks will not answer
    the probe and the sweep would report an empty network that is actually full.
    """
    import ipaddress

    from weirvern.admin.intercept import arp_sweep

    net = ipaddress.ip_network(segment, strict=False)
    skip = set(exclude or ()) | {src_ip}
    candidates = [str(h) for h in net.hosts() if str(h) not in skip]
    if not candidates:
        return []

    our_mac = read_mac(iface)
    if not our_mac:
        return []
    taken = arp_sweep(iface, our_mac, src_ip, candidates)
    free = [ip for ip in candidates if ip not in taken]

    # Prefer the TOP of the range: DHCP pools conventionally hand out from the bottom, so
    # a high address is least likely to collide with a future lease. This is a heuristic,
    # which is exactly why the result is presented for confirmation rather than applied.
    def _sort_key(addr: str) -> int:
        return -int(addr.split(".")[-1])

    return sorted(free, key=_sort_key)[:count]


def describe_segment(iface: str, segment: str, src_ip: str) -> tuple[dict[str, str], str]:
    """(used addresses, error) for reporting the blast radius before poisoning.

    Every host listed is one whose ARP cache would be forged, so this is the number that
    says how much of the network a mistake would take down.
    """
    import ipaddress

    from weirvern.admin.intercept import arp_sweep

    net = ipaddress.ip_network(segment, strict=False)
    our_mac = read_mac(iface)
    if not our_mac:
        return {}, f"cannot read a MAC for {iface}"
    candidates = [str(h) for h in net.hosts()]
    if len(candidates) > 4094:
        return {}, f"{segment} is too large to sweep ({len(candidates)} addresses)"
    return arp_sweep(iface, our_mac, src_ip, candidates), ""
