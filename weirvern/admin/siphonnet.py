"""In-path intercept (siphon mode): the ARP dataplane.

WHAT THIS IS, AND WHAT IT IS NOT. Weirvern inserts itself into the path between hosts and
their gateway by forging ARP mappings, then RELAYS the traffic it intercepts. This is an
L2/L3 redirection -- **not** a TLS intercept. Nothing is decrypted and no certificate is
substituted. The point is coverage: on a veth (which is what a container gets) the bridge
does not flood switched unicast, so a passive sensor sees only broadcast noise. Measured
on the test deployment: ~73% of what reached the passive sensor was broadcast, and Zeek
reported 62-65% capture loss. Traffic addressed to us cannot be "missed" the same way.

WHY A WATCHDOG IS NOT OPTIONAL. In siphon mode Weirvern is a ROUTER. If it stops forwarding
-- crash, OOM kill, node reboot -- every host whose ARP cache we poisoned loses the network
until that entry expires, which is typically minutes. That is the difference between a
monitoring gap and a LAN outage, and it is why `mode.py` refuses to enable siphon without a
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

    Raw sockets need CAP_NET_RAW, which `mode.py` already requires for siphon. Kept as a
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
    # Commands that would clear the problems found. Separate from `problems` because a diagnosis and
    # an action are different things, and a caller may want to show one without the other.
    remedies: list[str] = field(default_factory=list)

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


# ── the host firewall's FORWARD policy: the failure that takes a segment down ─────────────────
#
# FOUND ON A REAL NODE, and it is not exotic: k3s -- the runtime this project DEPLOYS -- sets
#
#     iptables -P FORWARD DROP
#
# on the host, and its own rules only ACCEPT forwarded traffic involving pod and service subnets.
# A siphon intercept relays traffic between two hosts on a LAN segment, which is neither. So the
# kernel forwards the packet into the FORWARD hook, the hook's policy drops it, and the segment
# loses its gateway exactly as if ip_forward were 0 -- while every check this module already
# performed reads healthy.
#
# That is the most dangerous shape a bug can take here: the operator sees a clean dry-run, arms the
# intercept, and breaks a network. And the tool's OWN sysctl checks make it worse, because they
# return "forwarding is enabled" -- true, and irrelevant.
#
# WHY THIS IS A CHECK AND NOT AN AUTO-FIX. Changing the host's firewall is a bigger act than
# changing a sysctl: the policy may be load-bearing for that host's own security, and silently
# widening it so a sensor can relay would be the tool deciding it knows better. So this REPORTS
# with the exact command, and the operator decides. `--force-unsafe` does not override it.

def forward_policy() -> tuple[str, str]:
    """The host's FORWARD chain policy, and where it was read from.

    Returns (policy, source): policy is 'ACCEPT'/'DROP'/'UNKNOWN'. Read from `iptables -S` rather
    than by running iptables-save, because the policy line is the only thing needed and the full
    ruleset can be very large on a Kubernetes node.

    'UNKNOWN' is returned rather than assuming ACCEPT: an unreadable policy is not a permissive
    one, and treating "could not read" as "fine" is how a blackhole looks healthy.
    """
    for cmd in (["iptables", "-S", "FORWARD"], ["ip6tables", "-S", "FORWARD"]):
        try:
            proc = subprocess.run(  # noqa: S603
                cmd, capture_output=True, text=True, timeout=10, check=False
            )
        except (OSError, subprocess.SubprocessError):
            continue
        if proc.returncode != 0:
            continue
        for line in proc.stdout.splitlines():
            if line.startswith("-P FORWARD"):
                parts = line.split()
                if len(parts) >= 3:
                    return parts[2].upper(), " ".join(cmd[:2])
    return "UNKNOWN", "iptables"


def forward_policy_problem(iface: str) -> str:
    """A sentence if the host firewall would DROP relayed traffic, else empty.

    Only consulted for a siphon intercept, and only about the FORWARD chain: a loch sensor never
    forwards anything, so a DROP policy is irrelevant to it and warning there would be noise.
    """
    policy, source = forward_policy()
    if policy == "ACCEPT":
        return ""
    if policy == "UNKNOWN":
        return (
            f"could not read the host's FORWARD policy ({source}); if it is DROP, relayed traffic "
            "will be discarded and the segment will lose its gateway. Check with: "
            "iptables -S FORWARD | head -1\n"
            "      If it reports DROP (k3s does this by default on a node), allow the relay:\n"
            "        sudo iptables -I FORWARD 1 -i <capture-iface> -j ACCEPT\n"
            "        sudo iptables -I FORWARD 1 -o <capture-iface> -j ACCEPT"
        )
    return (
        f"the host firewall DROPS forwarded traffic (iptables -P FORWARD {policy}), which is how "
        f"k3s configures a node by default. An intercept on {iface} relays traffic between two "
        "hosts on the segment, which that policy discards: the ARP mapping would be forged, the "
        "packets would be dropped, and the segment would lose its gateway while every other check "
        "here reads healthy.\n"
        "      Fix, ON THE NODE, once you have decided this is safe for this host:\n"
        "        sudo iptables -I FORWARD 1 -i <capture-iface> -j ACCEPT\n"
        "        sudo iptables -I FORWARD 1 -o <capture-iface> -j ACCEPT\n"
        "      (inserted at the top, and interface-scoped, so it does not widen the host's posture "
        "for traffic that is not being relayed)"
    )


def check_forwarding(iface: str) -> ForwardingState:
    """Verify the two kernel settings siphon mode cannot work without.

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
            # THE REMEDY IS CARRIED WITH THE PROBLEM, because this process CANNOT apply it.
            #
            # In the deployed container /proc/sys is READ-ONLY -- verified: every write returns
            # "Read-only file system" -- so the node's sysctls are set by the overlay's privileged
            # init container or by hand. Reporting "BLOCKED" with no remedy sends the reader looking
            # for a configuration knob that does not exist, and an earlier version did exactly that:
            # a correct deployment reported a blocker whose only visible cause was this message.
            state.remedies.append(f"sysctl -w {name}=0")
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

        ip route get 192.0.2.1 from 198.51.100.193 iif eth1
            -> via 203.0.113.1 dev eth0                 <-- WRONG INTERFACE
        with `iif eth1 -> table 100` installed:
            -> via 198.51.100.1 dev eth1 table 100       <-- correct

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

    # THE HOST FIREWALL, LAST BECAUSE IT IS THE ONE MOST LIKELY TO BE TRUE.
    # Every check above can pass while this one fails, and when it fails the segment loses its
    # gateway -- k3s sets `-P FORWARD DROP` on a node by default and its rules only accept traffic
    # involving pod subnets, which a relayed LAN packet is not. Included here rather than in a new
    # function so every existing caller (--dry-run, the CLI, the GUI's capability panel, the
    # supervisor) inherits it without a new call site to forget.
    policy_problem = forward_policy_problem(iface)
    if policy_problem:
        problems.append(policy_problem)

    return problems


def ensure_forwarding_path(iface: str, gateway: str,
                           gateway_mac: str | None = None,
                           segment: str = "") -> list[str]:
    """Install the policy route that makes forwarded traffic use the capture interface.

    Idempotent: deletes and re-adds, so a stale entry from a previous run cannot persist.
    Returns a list of problems; empty means the path is correct.

    Also refuses to touch anything if the gateway is not reachable on this interface, so a
    wrong --gateway cannot install a route that black-holes the segment.

    ── THE RETURN PATH NEEDS THE CONNECTED SEGMENT ROUTE (glm-5.3 review, MEASURED ON A KERNEL) ──

    Table 100 used to receive ONLY `default via <gateway> dev <iface>`. A policy rule pointing at a
    table whose default matches EVERY destination means the lookup never falls through to main's
    connected-segment route, so the return direction was broken: the gateway sends a host on the
    segment back to us, we look that host up in table 100, match the DEFAULT, and send it straight
    back at the gateway.

    MEASURED on a real kernel in an isolated namespace, with a bridge carrying gateway, sensor and
    peer on one segment:

        BASELINE (no intercept)     198.51.100.20 from 198.51.100.1 dev br0              <- on-link
        AS SHIPPED (default only)   198.51.100.20 from 198.51.100.1 via 198.51.100.1 dev br0  <- BACK AT THE GW
        WITH the segment route      198.51.100.20 from 198.51.100.1 dev br0 table 100    <- on-link, correct

    and the forward direction (an off-segment destination) still resolved via the gateway, so the fix
    does not break what the default is for.

    WHY THIS MATTERS OUT OF PROPORTION TO ITS SIZE: it is the best available explanation for the
    report that the network broke during a whole-VLAN intercept test. A single-host intercept can
    survive it; a whole-segment one cannot, because every host's return traffic becomes a loop.

    The segment is OPTIONAL so a caller that cannot supply one keeps the previous behaviour rather
    than silently gaining a route it did not ask for. Callers SHOULD pass it -- `intercept.py` passes
    `plan.segment`.

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
        # ── THE RULE MUST NOT GO IN WITHOUT THE ROUTE (audit F032, CONFIRMED BY RUNNING IT) ──
        #
        # This function used to append the problem and then install the policy rule anyway.
        # Measured by failing only the route add: the route was absent from table 100 and
        # `1000: iif eth1 lookup 100` was installed regardless -- which is precisely the
        # black-hole this module's own docstrings describe, because a rule selecting an empty
        # table DROPS the traffic it matches. The caller then refused to poison and raised, and
        # nothing removed the rule it had just added, so a REFUSED intercept left the segment's
        # ingress policy broken.
        #
        # The rule is the dangerous half: an absent route alone changes nothing, while a rule
        # pointing at an empty table drops traffic. So the failure short-circuits here and the
        # caller's cleanup removes anything already installed.
        return problems

    # ── THE RETURN PATH (glm-5.3 review) ─────────────────────────────────────────────────────────
    #
    # The connected segment, so a packet for a host ON the segment is delivered on-link instead of
    # being handed back to the gateway. Added BEFORE the policy rule, so the rule only ever goes in
    # once the table can resolve BOTH directions -- the same ordering rule the F032 note above
    # applies to the default route.
    if segment:
        rc, out = _run("ip", "route", "add", segment, "dev", iface, "table", str(POLICY_TABLE))
        if rc != 0:
            problems.append(
                f"could not add the connected segment route {segment} dev {iface} to table "
                f"{POLICY_TABLE}: {out}. Without it, return traffic for a host on the segment "
                f"matches the default and is sent back at the gateway, so the segment loses its "
                f"gateway. This is the whole-VLAN failure mode."
            )
            return problems

    _run("ip", "rule", "del", "iif", iface, "lookup", str(POLICY_TABLE))
    rc, out = _run("ip", "rule", "add", "iif", iface, "lookup", str(POLICY_TABLE),
                   "priority", str(POLICY_PRIORITY))
    if rc != 0:
        problems.append(f"could not add the policy rule: {out}")

    problems.extend(forwarding_path_problems(iface, gateway))
    return problems


def remove_forwarding_path(iface: str) -> list[str]:
    """Withdraw the policy route and EVERY rule that references the policy table. Never raises.

    RETURNS THE FAILURES, and that return is the point (audit F031, CONFIRMED BY RUNNING IT).

    This used to return nothing while running five `ip` commands whose return codes it discarded.
    Measured by making every command fail with "Operation not permitted" -- what a node without
    CAP_NET_ADMIN produces -- the function returned None and the caller could not tell that
    NOTHING had been removed. A teardown that reports success over a leftover rule is the worst
    shape of this bug, because the docstring below describes exactly what the leftover does:

        a leftover rule sends matching traffic to table 100 -- which, once the address is removed,
        is a table with no routes, so the rule DROPS that traffic.

    So the failure mode is not "a cosmetic rule remained". It is that traffic the operator never
    asked us to touch gets black-holed, silently, after a clean-looking stop. The caller
    (`intercept.stop`) now reports what could not be withdrawn.

    WHY A LIST OF STRINGS RATHER THAN RAISING: teardown must complete every step regardless. If the
    rule deletion fails, the route flush and the sysctl restore still have to run, and one of them
    failing must not skip the others. Collecting failures lets each step be attempted AND reported.

    A COMMAND THAT FAILS BECAUSE THERE WAS NOTHING TO DELETE IS NOT A FAILURE, and is filtered out.
    `ip rule del` returns an error when no such rule exists, which is the normal case for a second
    stop -- reporting that would make every clean teardown look broken, and a warning that is
    usually wrong is a warning an operator stops reading.
    """
    failures: list[str] = []

    def _attempt(*args: str) -> None:
        rc, out = _run(*args)
        if rc == 0:
            return
        # "No such file or directory" / "No such process" style refusals mean the thing was
        # already gone, which is the desired end state rather than a failure to reach it.
        if _is_absence(out):
            return
        failures.append(f"{' '.join(args)}: {out or f'exit {rc}'}")

    # ── THE GUARD IS GONE, AND THE SWEEP BELOW REPLACED IT (audit F097) ────────────────────────
    #
    # This used to be two deletions: an unconditional `del priority 1000`, then a sweep over every
    # priority that selects our table. Measured on a real kernel, the first one deleted a FOREIGN
    # rule planted at that priority and reported `[]`:
    #
    #     planted:  1000:  from all lookup 200
    #     remove_forwarding_path returned: []
    #     GONE -- a routing rule belonging to something else was DELETED
    #
    # I first fixed it by guarding the priority deletion with a selector check, and MUTATION TESTING
    # SHOWED THE GUARD WAS REDUNDANT: with it returning False, the sweep still issued
    # `ip rule del priority 1000` for our own rule, because the sweep derives its priorities from
    # `_policy_rule_priorities()` -- which is already table-scoped. So the guarded line and the
    # sweep's first iteration were the SAME command, reached two ways, and no test could tell which
    # one fired.
    #
    # ONE PATH, NOT TWO. The sweep is strictly safer (it deletes only priorities whose rule selects
    # our table) and strictly more complete (it covers every such priority, not just POLICY_PRIORITY).
    # The unconditional line is deleted rather than guarded, because a redundant second path is one
    # that can drift from the first and has to be reasoned about twice.

    # By parsing: covers ANY priority selecting the table, including forms we did not anticipate.
    # This is the ONLY priority-based deletion, and it cannot match a rule that selects another
    # table -- which is what makes it safe to run against a shared rule set.
    for priority in _policy_rule_priorities():
        _attempt("ip", "rule", "del", "priority", str(priority))

    # Last resort for the exact form, in case the rule has no readable priority.
    _attempt("ip", "rule", "del", "iif", iface, "lookup", str(POLICY_TABLE))

    _attempt("ip", "route", "flush", "table", str(POLICY_TABLE))
    return failures


def _is_absence(output: str) -> bool:
    """True when an `ip` command failed because the thing was already absent.

    Kept as its own function with its own name because the distinction it draws is the difference
    between "teardown is broken" and "teardown ran twice", and those must not be reported the same
    way: the first needs action, the second is normal.
    """
    lowered = output.lower()
    return any(
        marker in lowered
        for marker in (
            "no such file or directory",
            "no such process",
            "cannot find device",
            "not found",
            "does not exist",
        )
    )


def _policy_rule_priorities() -> list[int]:
    """Priorities of every routing rule that selects the policy table.

    Parsed rather than assumed, because the rule set is shared with the host's own networking and a
    wrong guess could delete someone else's rule. Only rules mentioning OUR table number are
    returned.
    """
    rc, out = _run("ip", "rule", "show")
    if rc != 0:
        return []
    found: list[int] = []
    for line in out.splitlines():
        parts = line.split()
        if not parts or not parts[0].rstrip(":").isdigit():
            continue
        # A rule line looks like: "1000:	from all iif eth1 lookup 100"
        if f"lookup {POLICY_TABLE}" not in line:
            continue
        try:
            found.append(int(parts[0].rstrip(":")))
        except ValueError:
            continue
    return found


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
    "siphon mode needs, inside the container:\n"
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
    # ── AN UNUSABLE SOURCE IS REFUSED, NOT REPHRASED AS "ALL FREE" (glm-5.3 review) ──────────────
    #
    # `arp_sweep` now raises rather than returning {} for an empty/0.0.0.0 source (see its docstring).
    # Without this branch the raise would escape this function as an unhandled ValueError, but the
    # alternative -- letting it fall back to {} -- is what made this function dangerous in the first
    # place: every candidate would come back FREE, so a caller could pick an address that a live host
    # already holds.
    #
    # Returns [] for the same reason the unreadable-MAC branch above does: this function's contract is
    # "addresses nothing answered for", and it has no honest answer to give when it could not ask.
    # Callers already treat [] as "no candidates", which is the conservative reading.
    if not src_ip or src_ip == "0.0.0.0":
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
    # ── AN UNUSABLE SOURCE IS AN ERROR HERE, AND THIS FUNCTION HAS SOMEWHERE TO PUT IT ───────────
    #
    # Returns `(used, error)`, so unlike `find_free_addresses` it can say why it has nothing. The
    # empty dict it used to return alongside err="" was read by the CLI as "nothing answered ARP --
    # either the segment is empty, or this interface cannot reach it", which is a GUESS between two
    # causes when the real cause was a third one it could have named: the sweep never sent a request.
    if not src_ip or src_ip == "0.0.0.0":
        return {}, (
            f"cannot sweep {segment}: no usable source address on {iface} ({src_ip!r}). A request "
            f"from an empty or 0.0.0.0 source is ignored by most stacks, so an empty result would "
            f"say nothing about the segment."
        )
    return arp_sweep(iface, our_mac, src_ip, candidates), ""
