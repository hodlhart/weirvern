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

import contextlib
import ipaddress
import logging
import signal
import socket
import struct
import time
from dataclasses import dataclass, field
from typing import Any

from weirvern.admin.watchdog import FailOpenWatchdog, Interception
from weirvern.admin.weirnet import (
    DEFAULT_REFRESH_S,
    ArpSender,
    ForwardingState,
    check_forwarding,
    ensure_forwarding_path,
    read_mac,
    read_neighbour_mac,
    remove_forwarding_path,
    resolve_mac,
)


class InterceptError(RuntimeError):
    """Raised when interception cannot be started safely.

    Distinct from a warning: this means NO poison frames were sent, because sending
    them would take the segment off the network rather than relay it.
    """


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
              timeout_s: float = 3.0) -> dict[str, str]:
    """Send ARP requests for every target and return {ip: mac} for those that answered.

    REPLIES ARE PARSED FROM THE SOCKET, NOT READ FROM /proc/net/arp.
    This was a real bug and it produced a confident wrong answer: reading the kernel's
    neighbour table returned ZERO hosts on a live segment with ELEVEN, because the kernel
    only installs a neighbour entry for addresses the interface actually OWNS. Replies for
    every other address arrive on the wire and are discarded -- so a sweep that looked
    correct reported an empty network and made the dry-run advise that intercepting it
    would be pointless.

    Verified against the same segment both ways: /proc/net/arp -> 0 hosts, parsing the
    socket -> 11 hosts (gateway + 10 peers).

    A further trap in the same area: ARP replies are UNICAST to the sender, so the socket
    must be bound to the interface and must capture outgoing frames too. Binding to
    (iface, 0) with ETH_P_ARP and reading with a timeout does both.

    `our_ip` should be an address the segment will accept as a source. A request from
    0.0.0.0 is ignored by most stacks, which also yields a false "empty network" -- the
    second way this function could lie.
    """
    request_tmpl = _arp_request_builder(our_mac, our_ip)
    found: dict[str, str] = {}

    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ARP))
    try:
        sock.bind((iface, 0))
        sock.settimeout(0.4)

        # SEND IN BATCHES AND DRAIN BETWEEN THEM.
        #
        # Blasting all 254 requests and then reading finds only a handful: the socket
        # receive buffer fills, and because ARP replies are UNICAST (not flooded) each one
        # exists only as a single queued frame that a full buffer drops. Measured on a
        # live segment: all-at-once found 1 host, batched found 11.
        #
        # 32 per batch with a bounded drain window is enough for a /24 on a LAN; larger
        # segments simply take more batches, which is what the loop is for.
        for start in range(0, len(targets), 32):
            for ip in targets[start:start + 32]:
                try:
                    sock.send(request_tmpl(ip))
                except OSError:
                    continue
            end = time.time() + max(0.5, timeout_s / max(1, len(targets) // 32))
            while time.time() < end:
                try:
                    frame = sock.recv(2048)
                except OSError:
                    break
                # Reply frame layout: dst(6) src(6) ethertype(2) htype(2) ptype(2)
                # hlen(1) plen(1) op(2) sender_mac(6) sender_ip(4) target_mac(6)
                # target_ip(4) -- so sender_mac is bytes 22:28 and sender_ip 28:32.
                if len(frame) < 42:
                    continue
                if int.from_bytes(frame[12:14], "big") != ETH_P_ARP:
                    continue
                if int.from_bytes(frame[20:22], "big") != 2:      # 2 = reply
                    continue
                sender_ip = socket.inet_ntoa(frame[28:32])
                sender_mac = ":".join(f"{b:02x}" for b in frame[22:28])
                if sender_mac != "00:00:00:00:00:00":
                    found[sender_ip] = sender_mac
    finally:
        sock.close()

    # Fall back to the kernel table only to FILL GAPS, never as the primary source: it is
    # authoritative for addresses we own and blind to everything else.
    for ip in targets:
        if ip not in found:
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
               exclude: set[str] | None = None,
               only: set[str] | None = None) -> InterceptPlan | None:
    """Discover what exists on `segment` and decide what to intercept.

    `only` restricts interception to named hosts. THAT IS THE SAFER DEFAULT FOR A FIRST
    TEST, and it is why the option exists: poisoning a whole segment makes Weirvern the
    path for every device on it, so a crash is an outage for all of them until their ARP
    caches expire. Two or three hosts prove relaying works and show the traffic, while
    keeping the number of devices that would notice a mistake small.

    A named host that did NOT answer the sweep is reported rather than silently dropped:
    the operator asked for it, so silently intercepting fewer hosts than requested would
    look like success while testing less than they think.

    Returns None (with a reason logged) rather than raising, because every failure here is
    an environmental one -- no MAC, no gateway MAC, nothing alive -- and each has a
    different operator action.
    """
    our_mac = read_mac(iface)
    if not our_mac:
        logger.error("cannot read a MAC for %s; is the interface present?", iface)
        return None

    # The gateway is NOT a sweep target (never intercept it), but its MAC is still required,
    # so it is surveyed separately. An earlier version excluded it from the candidate list and
    # then expected it in the results -- measured live, the operator saw all 11 hosts listed
    # including the gateway, and then a message saying that same gateway "answered neither the
    # ARP sweep nor the neighbour table".
    skip = set(exclude or ()) | {our_ip, gateway_ip}
    try:
        candidates = [h for h in parse_cidr(segment) if h not in skip]
    except ValueError as exc:
        logger.error("bad segment %r: %s", segment, exc)
        return None

    # SWEEP FIRST, THEN TAKE THE GATEWAY'S MAC FROM THE SAME MECHANISM.
    #
    # The order matters and was wrong. `resolve_mac` reads the kernel neighbour table, which
    # only fills for addresses the interface can reach at L3 -- and at plan time the capture
    # interface typically has NO address yet (the operator is still choosing one), so the
    # lookup fails and the plan was refused with "cannot resolve the gateway" while the survey
    # had just printed that gateway's real MAC.
    #
    # `arp_sweep` gets MACs without an assigned address (it sources requests from an
    # unassigned probe address and parses replies off the socket), so it is the primary
    # source. The gateway is probed in the SAME sweep as the hosts, as its own target, so both
    # come from one mechanism and one code path.
    hosts = arp_sweep(iface, our_mac, our_ip, candidates)
    # A host that answered as our own MAC is us (or a mirror); never intercept ourselves.
    hosts = {ip: mac for ip, mac in hosts.items() if mac.lower() != our_mac.lower()}

    gw_probe = arp_sweep(iface, our_mac, our_ip, [gateway_ip])
    gateway_mac = ((gw_probe.get(gateway_ip) or hosts.get(gateway_ip)
                    or resolve_mac(iface, gateway_ip) or "").lower() or None)
    if not gateway_mac:
        logger.error(
            "cannot resolve the gateway %s on %s -- it answered neither the ARP sweep of "
            "%s nor the neighbour table. Interception needs its real MAC both to forge its "
            "address and to restore it, so without it a poison frame could never be undone. "
            "Check --gateway and that %s has L2 reachability to the segment.",
            gateway_ip, iface, segment, iface,
        )
        return None

    # The gateway is in `hosts` too (it answered the sweep). Intercepting the gateway ITSELF
    # would forge the gateway's view of its own peers, which is not the intent and is the
    # fastest way to black-hole a segment -- so it is never a target, only ever the address
    # we claim. `skip` already excluded it from the candidate list, but a sweep result can
    # still contain it, so remove it explicitly.
    hosts.pop(gateway_ip, None)

    if only:
        missing = sorted(only - set(hosts))
        if missing:
            logger.warning(
                "%d requested host(s) did not answer an ARP sweep and would NOT be "
                "intercepted: %s. Intercepting fewer hosts than asked is reported rather "
                "than silent, because it would otherwise look like success.",
                len(missing), ", ".join(missing),
            )
        hosts = {ip: mac for ip, mac in hosts.items() if ip in only}

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

        # ip_forward only makes the kernel WILLING to forward, and it is the one part of the
        # path the OPERATOR owns (a container cannot set it). The policy route that decides
        # WHERE the packet goes is installed by start() -- see the note below.
        # The forwarding PATH is NOT checked here, because start() INSTALLS it.
        #
        # This distinction is the difference between the command working and never working.
        # Preflighting the policy route made `weirvern intercept` refuse every time it was run:
        # the route is created by start(), so requiring it beforehand is a prerequisite nothing
        # can ever satisfy -- a deadlock whose message tells the operator to fix something that
        # was never their job.
        #
        # What preflight genuinely gates on is what the OPERATOR must provide and what we must
        # not proceed without: the kernel being willing to forward at all, and the sysctls that
        # would silently make the relay one-way. Installing the route is ours, and start() does
        # it before any poison frame exists so a failure there aborts with nothing sent.

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

        # 1. the forwarding path, before anything claims to be the gateway. If the route is
        #    wrong, poisoning makes the kernel the next hop for traffic it cannot deliver --
        #    the victim loses the network instead of being relayed. Installing it first means
        #    a failure here aborts with NO poison frames sent.
        path_problems = ensure_forwarding_path(self.plan.iface, self.plan.gateway_ip,
                                               gateway_mac=self.plan.gateway_mac)
        if path_problems:
            raise InterceptError(
                "refusing to poison: the forwarding path is not correct, so relayed "
                "traffic would not reach the gateway. " + " ".join(path_problems)
            )

        # 2. watchdog NEXT, so no mapping ever exists without something responsible for
        #    restoring it. A crash between poisoning and arming would leave the segment
        #    poisoned with no undo.
        self.watchdog = FailOpenWatchdog(
            iface=self.plan.iface, our_mac=self.plan.our_mac, sender=self._sender,
            refresh_s=self.refresh_s,
        )
        for ic in self.plan.mappings():
            self.watchdog.register(ic)

        # 3. Now it is safe to poison.
        self.watchdog.start()
        self._started = True
        self.started_at = time.time()
        logger.warning(
            "weir: intercepting %d host(s) on %s via %s. Weirvern is now in the path; "
            "if this process stops, the watchdog restores the mappings.",
            self.plan.host_count, self.plan.segment, self.plan.iface,
        )

    def stop(self) -> None:
        """Withdraw every mapping and the forwarding path. Idempotent."""
        if self.watchdog is not None:
            self.watchdog.stop()
        # The policy rule must go too: left behind, it sends ALL traffic arriving on this
        # interface to a table that has no routes once the address is removed, which would
        # break traffic the operator never asked us to touch.
        remove_forwarding_path(self.plan.iface)
        close = getattr(self._sender, "close", None)
        if callable(close):
            close()
        self._started = False

    @property
    def active(self) -> bool:
        return self._started and self.watchdog is not None and self.watchdog.active > 0

    def wait(self, stop_after_s: float | None = None) -> None:
        """Block until interrupted, or for `stop_after_s`.

        SIGNALS: WHAT THIS DOES AND DOES NOT DO.

        A SIGTERM/SIGINT handler already exists -- `WeirWatchdog._install_signal_handlers` installs
        one at start, and it is the one that restores the mappings ("signal 2 received -- restoring
        ARP mappings" in a real run). This method previously caught only `KeyboardInterrupt`.

        The two are NOT the same thing, which is why both are kept:

          * `KeyboardInterrupt` is raised INSIDE this loop, so it unwinds through the caller's
            `finally` in `cmd_intercept`, which calls `runner.stop()`.
          * The watchdog's handler raises `SystemExit(0)` -- it never returns -- so it does NOT
            unwind this loop and the caller's `finally` does not run. The restore then depends on
            the watchdog's own `stop()`, which it does call. That works, and it is why the
            observed runs restored cleanly.

        WHAT NEITHER COVERS, and the honest limit of this code: a `kubectl exec` client that is
        SIGKILLed, or an SSH session that vanishes, may deliver NO signal to the in-pod process at
        all. No handler can run if no signal arrives. The protections that actually hold in that
        case are (a) `--seconds`, which bounds the run inside the process, and (b) the forged ARP
        entries EXPIRING, which is why the watchdog's expiry backstop exists and why SIGKILL is
        explicitly documented there.

        So this handler is a BELT: it covers SIGHUP (a dropped SSH session usually does deliver
        SIGHUP) and gives the loop a clean stop path that unwinds the caller. It is not the primary
        protection, and nothing here should be read as "an orphan is now impossible".
        """
        stop = False

        def _request_stop(_signum, _frame) -> None:
            nonlocal stop
            stop = True

        installed: list[tuple[signal.Signals, Any]] = []
        for sig in (signal.SIGHUP,):
            # SIGHUP ONLY. SIGTERM and SIGINT already have a handler that restores the mappings;
            # installing ours over it would replace a working restore path with a flag that only
            # stops this loop -- a downgrade dressed as a fix.
            try:
                previous = signal.signal(sig, _request_stop)
            except (ValueError, OSError):
                # Not the main thread, or the platform lacks the signal. Ctrl-C still works, so
                # this is a degradation rather than a failure.
                logger.debug("could not install a handler for signal %s", sig)
            else:
                installed.append((sig, previous))

        deadline = None if stop_after_s is None else time.time() + stop_after_s
        try:
            while not stop:
                time.sleep(0.5)
                if deadline is not None and time.time() >= deadline:
                    return
        except KeyboardInterrupt:
            return
        finally:
            for sig, previous in installed:
                # Restoring the previous handler must never mask the real outcome of the run.
                with contextlib.suppress(ValueError, OSError):
                    signal.signal(sig, previous)

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
