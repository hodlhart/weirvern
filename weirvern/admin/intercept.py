"""In-path intercept orchestration (weir mode).

SCOPE: a whole segment (the operator's choice). That means Weirvern becomes the path for
every host on the chosen network, and a container restart is a network outage for all of
them. The design consequence is that the watchdog is not an add-on but the load-bearing
safety mechanism: the mappings must be withdrawn automatically and quickly, because the
blast radius is the entire segment.

WHY TARGETS ARE DISCOVERED RATHER THAN SETTLED. To forge a mapping FOR a host we must know
its real MAC, so the host has to be in the neighbour table. Rather than requiring the
operator to list hosts, we sweep the segment with ARP (a broadcast request is answered by
every live host, so one probe enumerates the segment) and intercept everyone who responds
except the gateway and ourselves. That also means hosts that appear later are picked up on
a later sweep, which is what "whole segment" has to mean to be useful.

WHAT IS RELAYED, AND HOW. We poison each host's cache for the gateway, and the gateway's
cache for each host, so traffic flows host -> us -> gateway and back. We do NOT copy
packets: the kernel routes them because we are now the next hop and `ip_forward=1`. This
process therefore never holds the traffic, which is why it can die without dropping a
packet in flight.

THE ORDERING RULE, WHICH IS THE WHOLE POINT:
    1. verify forwarding prerequisites   (no ip_forward => poisoning is sabotage)
    2. arm the watchdog                   (before any mapping exists)
    3. poison
    4. keep refreshing until stopped
    5. restore on every exit path
Every step is ordered so that a mapping is never held by a process that has not yet
accepted responsibility for undoing it.
"""
from __future__ import annotations

import ipaddress
import logging
import socket
import struct
import time
from dataclasses import dataclass, field

from weirvern.admin.watchdog import FailOpenWatchdog, Interception
from weirvern.admin.weirnet import (
    DEFAULT_REFRESH_S,
    ArpSender,
    ForwardingState,
    check_forwarding,
    read_mac,
    read_neighbour_mac,
    resolve_mac,
)

logger = logging.getLogger(__name__)

ETH_P_ARP = 0x0806


# ---------------------------------------------------------------------------
# discovery
# ---------------------------------------------------------------------------


def parse_cidr(value: str) -> list[str]:
    """Every usable host address in a CIDR, as strings.

    Excludes network and broadcast. A /24 is the common case; a /16 would be 65534 hosts
    and is refused rather than silently attempted, because poisoning 65k entries is not a
    thing anyone means to do by accident.
    """
    net = ipaddress.ip_network(value, strict=False)
    if net.num_addresses > 1024:
        raise ValueError(
            f"{value} contains {net.num_addresses} addresses; intercepting more than "
            f"1024 hosts at once is refused as almost certainly a mistake"
        )
    return [str(h) for h in net.hosts()]


def arp_sweep(iface: str, our_mac: str, our_ip: str, targets: list[str],
              timeout_s: float = 2.0) -> dict[str, str]:
    """Send ARP requests for every target and return {ip: mac} for those that answered.

    A broadcast ARP REQUEST is answered by the owner, which is what fills the neighbour
    table. Reading /proc/net/arp after the sweep is more reliable than parsing replies
    ourselves, and it works without privileged packet parsing.
    """
    request_tmpl = _arp_request_builder(our_mac, our_ip)
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ARP))
    try:
        sock.bind((iface, 0))
        for ip in targets:
            try:
                sock.send(request_tmpl(ip))
            except OSError:
                continue
        time.sleep(timeout_s)
    finally:
        sock.close()

    found: dict[str, str] = {}
    for ip in targets:
        mac = read_neighbour_mac(iface, ip)
        if mac:
            found[ip] = mac
    return found


def _arp_request_builder(our_mac: str, our_ip: str):
    """Returns a function ip -> ARP-request frame.

    Built as a closure so the frame layout is in one place and the broadcast destination
    cannot be accidentally omitted.
    """
    from weirvern.admin.watchdog import mac_to_bytes

    broadcast = "ff:ff:ff:ff:ff:ff"

    def build(target_ip: str) -> bytes:
        frame = mac_to_bytes(broadcast) + mac_to_bytes(our_mac)
        frame += struct.pack("!H", ETH_P_ARP)
        frame += struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1)  # 1 = request
        frame += mac_to_bytes(our_mac) + socket.inet_aton(our_ip)
        frame += mac_to_bytes("00:00:00:00:00:00") + socket.inet_aton(target_ip)
        return frame

    return build


# ---------------------------------------------------------------------------
# the intercept
# ---------------------------------------------------------------------------


@dataclass
class InterceptPlan:
    """What we intend to do, computed before anything changes.

    Kept separate from applying it so the whole plan can be shown to an operator and
    tested without a socket. Given that applying it can take a segment offline, being able
    to inspect it first is not a nicety.
    """

    iface: str
    segment: str
    our_mac: str
    our_ip: str
    gateway_ip: str
    gateway_mac: str
    hosts: dict[str, str] = field(default_factory=dict)  # host_ip -> host_mac

    @property
    def host_count(self) -> int:
        return len(self.hosts)

    def mappings(self) -> list[Interception]:
        """The mappings to install: two per host.

        Per host:
          * host's cache for the GATEWAY -> our MAC  (its outbound traffic comes to us)
          * gateway's cache for the HOST   -> our MAC  (its inbound traffic comes to us)
        Both directions are required. With only the first, replies take the direct path and
        the sensor sees a one-sided conversation.
        """
        out: list[Interception] = []
        for host_ip, host_mac in self.hosts.items():
            out.append(Interception(
                host_ip=host_ip, host_mac=host_mac,
                claim_ip=self.gateway_ip, real_mac=self.gateway_mac,
                iface=self.iface, our_mac=self.our_mac,
            ))
            out.append(Interception(
                host_ip=self.gateway_ip, host_mac=self.gateway_mac,
                claim_ip=host_ip, real_mac=host_mac,
                iface=self.iface, our_mac=self.our_mac,
            ))
        return out

    def describe(self) -> str:
        lines = [
            f"  interface : {self.iface}",
            f"  segment   : {self.segment}",
            f"  our MAC   : {self.our_mac}",
            f"  gateway   : {self.gateway_ip} ({self.gateway_mac})",
            f"  hosts     : {self.host_count}",
        ]
        for ip, mac in sorted(self.hosts.items()):
            lines.append(f"      {ip:<16} {mac}")
        return "\n".join(lines)


def build_plan(iface: str, segment: str, our_ip: str, gateway_ip: str,
               exclude: set[str] | None = None) -> InterceptPlan | None:
    """Discover what exists on `segment` and decide what to intercept.

    Returns None (with a reason logged) rather than raising, because every failure here is
    an environmental one -- no MAC, no gateway MAC, nothing alive -- and each has a
    different operator action.
    """
    our_mac = read_mac(iface)
    if not our_mac:
        logger.error("cannot read a MAC for %s; is the interface present?", iface)
        return None

    skip = set(exclude or ()) | {our_ip, gateway_ip}
    try:
        candidates = [h for h in parse_cidr(segment) if h not in skip]
    except ValueError as exc:
        logger.error("bad segment %r: %s", segment, exc)
        return None

    gateway_mac = resolve_mac(iface, gateway_ip)
    if not gateway_mac:
        logger.error(
            "cannot resolve the gateway %s on %s. Interception needs its real MAC both to "
            "forge its address and to restore it. Check the gateway is reachable from this "
            "interface.",
            gateway_ip, iface,
        )
        return None

    hosts = arp_sweep(iface, our_mac, our_ip, candidates)
    # A host that answered as our own MAC is us (or a mirror); never intercept ourselves.
    hosts = {ip: mac for ip, mac in hosts.items() if mac.lower() != our_mac.lower()}

    return InterceptPlan(iface=iface, segment=segment, our_mac=our_mac, our_ip=our_ip,
                         gateway_ip=gateway_ip, gateway_mac=gateway_mac, hosts=hosts)


class Intercept:
    """A running interception. Context-managed so teardown cannot be forgotten.

    Usage:
        with Intercept(plan, sender) as ic:
            ic.wait()

    The `__exit__` path restores every mapping, and so does the watchdog's signal handler.
    Both are idempotent, so a normal exit after a signal is harmless.
    """

    def __init__(self, plan: InterceptPlan, sender=None, refresh_s: float = DEFAULT_REFRESH_S,
                 forwarding: ForwardingState | None = None) -> None:
        self.plan = plan
        self._sender = sender or ArpSender(plan.iface)
        self.refresh_s = refresh_s
        self.forwarding = forwarding
        self.watchdog: FailOpenWatchdog | None = None
        self._started = False
        self.started_at: float = 0.0

    # -- preflight -------------------------------------------------------------
    def preflight(self) -> list[str]:
        """Everything that must be true before a single poison frame is sent.

        Returned as a list so an operator sees ALL the problems at once rather than fixing
        them one per run. Empty list == safe to proceed.
        """
        problems: list[str] = []
        state = self.forwarding or check_forwarding(self.plan.iface)
        problems.extend(state.problems)

        if not self.plan.hosts:
            # Not fatal, but almost certainly not what the operator wanted, and silently
            # "intercepting nothing" is how a weir deployment looks broken.
            problems.append(
                f"no hosts responded to an ARP sweep of {self.plan.segment}. Nothing would "
                f"be intercepted. Check the segment and that {self.plan.iface} has L2 "
                f"reachability to it."
            )
        if self.plan.our_mac.lower() == self.plan.gateway_mac.lower():
            problems.append(
                "our MAC equals the gateway's MAC, so poisoning would make us claim an "
                "address we cannot relay for"
            )
        return problems

    # -- lifecycle -------------------------------------------------------------
    def start(self) -> None:
        """Arm the watchdog, THEN poison. The order is the safety property."""
        if self._started:
            return

        # 1. watchdog FIRST, so no mapping ever exists without something responsible for
        #    restoring it. A crash between poisoning and arming would leave the segment
        #    poisoned with no undo.
        self.watchdog = FailOpenWatchdog(
            iface=self.plan.iface, our_mac=self.plan.our_mac, sender=self._sender,
            refresh_s=self.refresh_s,
        )
        for ic in self.plan.mappings():
            self.watchdog.register(ic)

        # 2. Now it is safe to poison.
        self.watchdog.start()
        self._started = True
        self.started_at = time.time()
        logger.warning(
            "weir: intercepting %d host(s) on %s via %s. Weirvern is now in the path; "
            "if this process stops, the watchdog restores the mappings.",
            self.plan.host_count, self.plan.segment, self.plan.iface,
        )

    def stop(self) -> None:
        """Withdraw every mapping. Idempotent."""
        if self.watchdog is not None:
            self.watchdog.stop()
        close = getattr(self._sender, "close", None)
        if callable(close):
            close()
        self._started = False

    @property
    def active(self) -> bool:
        return self._started and self.watchdog is not None and self.watchdog.active > 0

    def wait(self, stop_after_s: float | None = None) -> None:
        """Block until interrupted, or for `stop_after_s`."""
        deadline = None if stop_after_s is None else time.time() + stop_after_s
        try:
            while True:
                time.sleep(0.5)
                if deadline is not None and time.time() >= deadline:
                    return
        except KeyboardInterrupt:
            return

    def __enter__(self) -> Intercept:
        self.start()
        return self

    def __exit__(self, *exc) -> None:
        self.stop()

    def status(self) -> dict[str, object]:
        return {
            "iface": self.plan.iface,
            "segment": self.plan.segment,
            "hosts": self.plan.host_count,
            "mappings": self.plan.host_count * 2,
            "running": self.active,
            "uptime_s": round(time.time() - self.started_at, 1) if self.started_at else 0.0,
            "watchdog_restores": self.watchdog.restored_count if self.watchdog else 0,
            "watchdog_refreshes": self.watchdog.refresh_count if self.watchdog else 0,
            "watchdog_failures": list(self.watchdog.failures) if self.watchdog else [],
        }
