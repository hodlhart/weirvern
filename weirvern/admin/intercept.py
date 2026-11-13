"""In-path intercept orchestration (siphon mode).

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
import os
import signal
import socket
import struct
import subprocess
import time
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from weirvern.admin.siphonnet import (
    DEFAULT_REFRESH_S,
    POLICY_TABLE,
    ArpSender,
    ForwardingState,
    check_forwarding,
    ensure_forwarding_path,
    read_mac,
    read_neighbour_mac,
    remove_forwarding_path,
    resolve_mac,
)
from weirvern.admin.sysctl_guard import SysctlGuard
from weirvern.admin.watchdog import FailOpenWatchdog, Interception


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

    IPv4 ONLY, refused explicitly rather than degraded. The whole dataplane is v4: the
    frames are built with `inet_aton`, the sysctls are `net.ipv4.*`, and the relay path
    is v4 routing. An IPv6 segment that reached the sweep would fail per-send with a
    swallowed OSError and present as "no hosts answered" -- the false-empty-network shape
    this module produces whenever a refusal is missing instead of explicit.
    """
    net = ipaddress.ip_network(value, strict=False)
    if net.version != 4:
        raise ValueError(
            f"{value} is IPv6; siphon mode is IPv4-only (ARP, the forwarding sysctls and "
            f"the relay are all v4), so a v6 segment cannot be intercepted. Use loch "
            f"mode, which observes without being in the path."
        )
    if net.num_addresses > 1024:
        raise ValueError(
            f"{value} contains {net.num_addresses} addresses; intercepting more than "
            f"1024 hosts at once is refused as almost certainly a mistake"
        )
    return [str(h) for h in net.hosts()]


# Path to the resolver list. Module-level so a test can point it at a fixture rather than
# depending on the machine's real resolver configuration.
RESOLV_CONF_PATH = "/etc/resolv.conf"


def _resolv_nameservers() -> list[str]:
    """Nameservers listed in /etc/resolv.conf, best-effort.

    A missing or unreadable file returns no nameservers rather than raising: the check
    this feeds is an extra refusal, and a host without a resolv.conf must not lose the
    ability to intercept at all.
    """
    out: list[str] = []
    try:
        text = Path(RESOLV_CONF_PATH).read_text()
    except OSError:
        return out
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] == "nameserver":
            out.append(parts[1])
    return out


def management_addresses(iface: str) -> list[str]:
    """IPv4 addresses configured on the management interface, read from the kernel.

    MGMT_ADDR is an optional explicit override, but most deployments only set MGMT_IFACE.
    On a two-NIC sensor whose monitored segment contains the management address, the
    whole-segment path had no way to know that address and could forge its mapping — the
    exact conflict that cuts the box off from the console managing it. Derive it instead.
    """
    name = str(iface or "").strip()
    if not name:
        return []
    try:
        out = subprocess.run(
            ["ip", "-4", "-o", "addr", "show", "dev", name],
            capture_output=True, text=True, timeout=3, check=False,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    found: list[str] = []
    for line in out.splitlines():
        parts = line.split()
        for i, token in enumerate(parts):
            if token == "inet" and i + 1 < len(parts):
                addr = parts[i + 1].split("/", 1)[0].strip()
                if addr:
                    found.append(addr)
    return found


def never_intercept_hits(targets: Iterable[str], *, our_ip: str = "",
                         gateway_ip: str = "") -> dict[str, str]:
    """Which targets match a never-intercept role that is derivable ON THIS HOST.

    `mode.py`'s NEVER_INTERCEPT list states the roles; this turns the DERIVABLE ones into
    an enforcement check, because a list rendered only as prose is advice, and advice
    does not stop a `--hosts` argument. Forging the mappings for one of these breaks the
    thing the sensor itself depends on: the resolver it uses, the control plane it
    reports to, or (via the gateway) its own path out.

    Only roles establishable from this host are included, and the omission of the rest is
    deliberate -- an unverifiable guess would either refuse valid plans or, worse, be
    trusted as complete. Derivable here:

      * our own address and the gateway being claimed (structural, always known)
      * every nameserver in /etc/resolv.conf -- the sensor's own resolver; poisoning it
        breaks name resolution for the sensor AND for every host it relays for
      * MGMT_ADDR -- the sensor's management address, when configured separately from
        the intercept address
      * KUBERNETES_SERVICE_HOST -- the API server, whose address exists in every pod's
        environment; forging it breaks the sensor's own control plane

    Returns {ip: role}; empty means nothing derivable matches.
    """
    known: dict[str, str] = {}
    if our_ip:
        known[our_ip] = "the sensor's own address"
    if gateway_ip:
        known[gateway_ip] = "the gateway whose address is being claimed"
    for ns in _resolv_nameservers():
        known.setdefault(ns, "a DNS resolver this sensor itself uses")
    mgmt = (os.environ.get("MGMT_ADDR") or "").strip()
    if mgmt:
        known.setdefault(mgmt, "the sensor's management address")
    # MGMT_IFACE alone is the normal deployment shape. Without this, a monitored segment that
    # contains the management address (e.g. eth2 siphon on 203.0.113.0/24 while mgmt is
    # 203.0.113.176 on eth0) could have its mapping forged by the whole-segment sweep.
    mgmt_iface = (os.environ.get("MGMT_IFACE") or "").strip()
    if mgmt_iface:
        for addr in management_addresses(mgmt_iface):
            known.setdefault(addr, "the sensor's management address")
    api = (os.environ.get("KUBERNETES_SERVICE_HOST") or "").strip()
    if api:
        known.setdefault(api, "the Kubernetes API server")

    target_set = set(targets)
    return {ip: role for ip, role in known.items() if ip in target_set}


# Requests per batch. See arp_sweep for why a whole /24 cannot be sent at once.
ARP_BATCH = 32


def _drain_window(timeout_s: float, n_targets: int) -> float:
    """How long to drain replies for ONE batch of up to ARP_BATCH requests.

    `timeout_s` is the TOTAL drain budget, divided across the batches that will be sent,
    with a 0.5s floor per batch (a LAN reply arrives in milliseconds; the floor covers a
    slow stack). One batch gets the full budget; a /24 gets 3s across 8 batches.

    Separated from the socket loop so the arithmetic is testable without root: the
    previous formula divided by a flooring count, which handed every segment under 64
    targets the FULL timeout for EVERY batch while its comment claimed a bounded window.
    """
    batches = max(1, (n_targets + ARP_BATCH - 1) // ARP_BATCH)
    return max(0.5, timeout_s / batches)


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

    ── AN UNUSABLE SOURCE IS REFUSED, NOT SWEPT (glm-5.3 review, CONFIRMED) ──────────────────────

    Both ways this function can lie end in the same place: an empty dict that the caller reads as
    "this segment is empty". MEASURED, both mechanisms:

      * an EMPTY source raises inside the request builder -- `socket.inet_aton('')` raises OSError
        ("illegal IP address string passed to inet_aton") -- and the send loop's `except OSError:
        continue` swallowed it, so zero frames went on the wire and the function returned {};
      * a 0.0.0.0 source builds and sends a VALID 42-byte request that most stacks ignore, so nothing
        answers and it returns {} again.

    The damage is downstream and already documented by the callers: `siphonnet.find_free_addresses`
    returns every candidate not in the result as FREE, so a sweep that could not send offers the
    WHOLE NETWORK as free addresses on a populated segment, and the CLI prints "nothing answered ARP
    -- either the segment is empty, or this interface cannot reach it ... (intercepting it would
    affect nobody, which is safe but pointless)". An operator assigning an address from that list
    collides with a live host.

    So the refusal happens HERE, before the socket is opened, and it is a refusal rather than a false
    empty. Raise, for the same reason `add_address` raises on a bad prefix: a caller that gets a
    result must be able to trust it, and there is no empty-dict answer that is honest about "I could
    not ask". The zero-MAC case is refused by the caller (`sweep_probe.py` checks it first), which is
    the same shape at the layer that knows the difference.
    """
    if not our_ip or our_ip == "0.0.0.0":
        raise ValueError(
            f"refusing to sweep {iface} from source {our_ip!r}: a request from an empty or 0.0.0.0 "
            f"source is ignored by most stacks, so the sweep would return an empty result that "
            f"callers read as 'this segment is empty' -- and find_free_addresses would then offer "
            f"every address on a populated segment as free. Supply an address the segment will "
            f"accept as a source."
        )

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
        # segments simply take more batches, which is what the loop is for. The window
        # comes from _drain_window so the total budget is divided across the batches
        # rather than repeated per batch.
        drain_s = _drain_window(timeout_s, len(targets))
        for start in range(0, len(targets), ARP_BATCH):
            for ip in targets[start:start + ARP_BATCH]:
                try:
                    sock.send(request_tmpl(ip))
                except OSError:
                    continue
            end = time.time() + drain_s
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
    policy_table: int = POLICY_TABLE

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
               only: set[str] | None = None,
               force_unsafe: bool = False,
               policy_table: int | None = None) -> InterceptPlan | None:
    """Discover what exists on `segment` and decide what to intercept.

    `only` restricts interception to named hosts. THAT IS THE SAFER DEFAULT FOR A FIRST
    TEST, and it is why the option exists: poisoning a whole segment makes Weirvern the
    path for every device on it, so a crash is an outage for all of them until their ARP
    caches expire. Two or three hosts prove relaying works and show the traffic, while
    keeping the number of devices that would notice a mistake small.

    A named host that did NOT answer the sweep is reported rather than silently dropped:
    the operator asked for it, so silently intercepting fewer hosts than requested would
    look like success while testing less than they think.

    NEVER-INTERCEPT ROLES ARE ENFORCED, not just advised. `mode.py` states the roles a
    target must never hold; the ones derivable on this host (our own address, the
    claimed gateway, the sensor's configured resolver, its management address, the
    cluster API server) are REFUSED here with the role named, so the reasoning is
    visible rather than a bare rejection. A separate `--force-unsafe` on the CLI
    bypasses the extra check only for the roles whose harm depends on intent (a
    resolver that is genuinely a target of investigation); the structural ones -- our
    own address and the gateway -- remain impossible regardless, because forging them
    cannot relay anything at all.

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
    # ── AND THE SAME ROLES APPLY TO A WHOLE-SEGMENT BUILD (audit F098, CONFIRMED BY RUNNING IT) ──
    #
    # `skip` excludes only `{our_ip, gateway_ip}`, so on a whole-segment intercept the OTHER
    # derivable roles were never removed. Measured on a /24 that contains them:
    #
    #     K8s API server (.55) in the intercept targets: YES
    #     sensor mgmt addr (.44) in the intercept targets: YES
    #     hosts in plan: 252
    #
    # `never_intercept_hits` KNOWS both roles -- it derives them from KUBERNETES_SERVICE_HOST and
    # MGMT_ADDR -- and was consulted only under `if only:`. So the safer-looking path (a whole
    # segment, no explicit names) was the one that could forge the mapping for the control plane
    # the sensor reports to, which is the failure this check exists to prevent.
    #
    # A whole-segment build CANNOT refuse the way the named path does, because refusing would make
    # the feature impossible on any segment that contains a nameserver or an API server -- which is
    # every real segment. So these roles are EXCLUDED from the candidate set, and the exclusion is
    # REPORTED, because a silently-smaller intercept would look like full coverage.
    if not only:
        role_ips = set(never_intercept_hits(
            [str(h) for h in parse_cidr(segment)],
            our_ip=our_ip, gateway_ip=gateway_ip,
        ))
        # Our own address and the gateway are already skipped; excluding them here as well is
        # harmless and keeps the reported list honest about what was removed.
        role_ips -= {our_ip, gateway_ip}
        if role_ips:
            excluded_roles = never_intercept_hits(
                sorted(role_ips), our_ip=our_ip, gateway_ip=gateway_ip)
            for ip, role in sorted(excluded_roles.items()):
                logger.info(
                    "not intercepting %s: it is %s, and forging that mapping would break the "
                    "sensor's own path while it relays",
                    ip, role,
                )
            exclude = set(exclude or ()) | role_ips

    skip = set(exclude or ()) | {our_ip, gateway_ip}
    try:
        candidates = [h for h in parse_cidr(segment) if h not in skip]
    except ValueError as exc:
        logger.error("bad segment %r: %s", segment, exc)
        return None

    # ENFORCE THE NEVER-INTERCEPT ROLES for hosts the operator NAMED. A whole-segment
    # sweep cannot contain our own address or the gateway (both are in `skip`), but
    # `--hosts` names are not filtered through `skip` until much later -- the named form
    # is exactly where a resolver or management address could be requested, and it is the
    # form a first test uses. Refusing here, with the role named, turns a prose warning
    # into a check that fires.
    #
    if only:
        hits = never_intercept_hits(only, our_ip=our_ip, gateway_ip=gateway_ip)
        structural = {ip: role for ip, role in hits.items()
                      if role in ("the sensor's own address",
                                  "the gateway whose address is being claimed")}
        if structural:
            for ip, role in sorted(structural.items()):
                logger.error("refusing to intercept %s: it is %s", ip, role)
            return None
        if hits and not force_unsafe:
            for ip, role in sorted(hits.items()):
                logger.error(
                    "refusing to intercept %s: it is %s. Forging this mapping breaks the "
                    "sensor's own path while it relays. If the host is genuinely the object "
                    "of investigation, pass --force-unsafe to accept the risk.",
                    ip, role,
                )
            return None
        if hits and force_unsafe:
            for ip, role in sorted(hits.items()):
                logger.warning(
                    "intercepting %s despite it being %s (--force-unsafe)", ip, role)

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
    #
    # ── A SWEEP THAT COULD NOT SEND MUST NOT BECOME A PLAN (glm-5.3 review) ──────────────────────
    #
    # `arp_sweep` raises for an empty/0.0.0.0 source instead of returning {}, because an empty result
    # here would flow straight into the plan: `hosts` would be empty (so `only` reports every
    # requested host as "did not answer"), and the gateway probe would come back empty too, leaving
    # only `resolve_mac` -- which this comment already records as unreliable at plan time because the
    # capture interface usually has no address yet. That path ends at "cannot resolve the gateway",
    # which blames the gateway for a sweep that never asked. Refusing here names the real cause.
    try:
        hosts = arp_sweep(iface, our_mac, our_ip, candidates)
    except ValueError as exc:
        logger.error("%s", exc)
        return None
    # A host that answered as our own MAC is us (or a mirror); never intercept ourselves.
    hosts = {ip: mac for ip, mac in hosts.items() if mac.lower() != our_mac.lower()}

    try:
        gw_probe = arp_sweep(iface, our_mac, our_ip, [gateway_ip])
    except ValueError as exc:
        logger.error("%s", exc)
        return None
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
                         policy_table=POLICY_TABLE if policy_table is None else int(policy_table),
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
                 forwarding: ForwardingState | None = None,
                 max_runtime_s: float | None = None,
                 allow_management_iface: bool = False) -> None:
        self.plan = plan
        self.table = int(getattr(plan, "policy_table", POLICY_TABLE) or POLICY_TABLE)
        self._sender = sender or ArpSender(plan.iface)
        self.refresh_s = refresh_s
        self.forwarding = forwarding
        self.watchdog: FailOpenWatchdog | None = None
        # Propagated to the watchdog's self-destruct deadline (siphon-2): the outermost
        # bound on how long forged mappings can outlive their operator.
        self.max_runtime_s = max_runtime_s
        self._started = False
        self.started_at: float = 0.0
        # AN EXPLICIT ESCAPE HATCH FOR THE MANAGEMENT-INTERFACE REFUSAL (audit F033).
        #
        # Default False, so the check fires unless a caller deliberately opts out. A single-NIC
        # test host genuinely has one interface for both roles, and refusing outright would make
        # that case impossible rather than merely dangerous -- so the door exists, but it has to be
        # opened on purpose and it is visible in the call rather than inherited from a flag that
        # happened to be set. The refusal message names the alternative (split the roles, or set
        # MGMT_IFACE elsewhere) before anyone reaches for this.
        self.allow_management_iface = allow_management_iface
        # Records the node's network sysctls BEFORE this intercept changes them, so `stop()` can put
        # the exact previous values back. Measured on a real host: they were left at the intercept's
        # values hours after a clean-looking teardown, and `rp_filter=0` on a whole node disables a
        # spoofing defence for every interface -- a test that does that has damaged the host.
        self._sysctls = SysctlGuard(plan.iface)

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
            # "intercepting nothing" is how a siphon deployment looks broken.
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
        """Arm the watchdog, THEN poison. The order is the safety property.

        ── THE LAST GATE BEFORE ANYTHING IS POISONED (audit F033, CONFIRMED BY RUNNING IT) ───────

        The "never intercept the management interface" rule was PROSE on this path. `mode.py`
        states it in NEVER_INTERCEPT, the CLI enforces it when a mode is enabled, and
        `cluster_config.validate` enforces it when a ConfigMap is written -- but measured, there
        were ZERO references to MGMT_IFACE in intercept.py, siphon_supervisor.py or worker.py, and
        an `InterceptPlan` for the management interface constructed and armed without objection.

        That matters because BOTH write-time checks are bypassable: the CLI has `--force` (for the
        watchdog, but it writes the mode anyway) and the ConfigMap can be edited by anyone with
        cluster access. Intercepting the management port cuts the sensor off from the cluster that
        manages it -- and in siphon mode the relay is also what keeps the segment reachable, so the
        failure is not "the sensor goes dark", it is "the sensor goes dark while holding the
        segment's traffic".

        CHECKED HERE, at the point of no return, because a check that only exists upstream is a
        check that can be skipped by anything that does not go through the upstream.
        """
        if self._started:
            return

        # THE MANAGEMENT-INTERFACE REFUSAL, FIRST, before the sysctls are recorded and before
        # anything is installed. Deliberately NOT skippable: this is the structural role, and
        # forging mappings on the path the sensor itself depends on cannot relay anything -- it
        # only cuts the sensor off.
        if not self.allow_management_iface:
            mgmt = (os.environ.get("MGMT_IFACE") or "").strip()
            if mgmt and mgmt == self.plan.iface:
                raise InterceptError(
                    f"refusing to intercept on {self.plan.iface}: it is the MANAGEMENT interface "
                    f"(MGMT_IFACE). Intercepting the management path cuts this sensor off from the "
                    f"cluster that manages it, and in siphon mode the relay is what keeps the "
                    f"segment reachable -- so the sensor would go dark while still holding the "
                    f"segment's traffic. Set a separate capture interface, or set MGMT_IFACE to a "
                    f"different interface if this host genuinely has only one."
                )

        # 0. RECORD THE SYCTLS BEFORE TOUCHING ANYTHING. Reading them later would capture the
        #    intercept's own values, and restoring those is the same as not restoring at all.
        #
        #    Nothing here CHANGES a sysctl: the mode check and the Kubernetes init container own
        #    that, and duplicating it would give two places that can disagree. This only remembers
        #    what was there so the restore has an honest target.
        #
        # ── THE RESULT MUST BE READ (glm-5.3 review, CONFIRMED) ──────────────────────────────────
        #
        # This was `self._sysctls.apply()`, result discarded. `apply()` returns the sysctls that
        # could NOT be set -- and in the deployed container, where /proc/sys is read-only, it returns
        # the ones that are WRONG and cannot be corrected from here. Measured against the live class:
        # a node with ip_forward=0 yields a populated list, and a correct node yields an empty one.
        #
        # Discarding it meant start() poisoned ARP with forwarding misconfigured. ip_forward=0 makes
        # the kernel unwilling to forward at all, so the sensor becomes the segment's next hop for
        # traffic it will drop: the victim loses the network rather than being relayed, which is the
        # precise outcome the check exists to prevent. And `preflight()` cannot cover it -- start()
        # is the point of no return, reachable directly, and the module's own history (see below) is
        # a list of checks that existed upstream and were skipped by callers that bypassed them.
        #
        # This is deliberately NOT gated on `preflight()` having run. Doing that was already tried
        # here and produced a deadlock, because preflight refuses on prerequisites that start()
        # itself installs. The question answered here needs no prerequisite: are the sysctls siphon
        # depends on actually in effect right now? If not, refuse BEFORE any poison frame.
        # The sysctls are handled in `preflight()`, via `check_forwarding`. That helper is reached
        # at line 570 in `preflight()` -- but preflight is a SEPARATE entry point, and start() is
        # the point of no return, so a caller that constructs an Intercept and calls start()
        # (the documented usage) reached the point of no return with the sysctls unexamined.
        #
        # Checked here too, using the SAME helper and the SAME injected seam (`self.forwarding`)
        # rather than a second derivation of the same facts. The result is read, which the direct
        # call above did not do.
        state = self.forwarding or check_forwarding(self.plan.iface)
        if not state.ready:
            # Same contract as the path failure below: a refused start leaves NO trace, so the exit
            # cleans up before raising and the exception describes a node actually back to its
            # previous state.
            withdrawn = remove_forwarding_path(self.plan.iface)
            unrestored = self._sysctls.restore()
            detail = ""
            if withdrawn or unrestored:
                detail = (
                    f" Cleanup was also incomplete: could not withdraw {withdrawn}; could not "
                    f"restore {unrestored}."
                )
            raise InterceptError(
                "refusing to poison: the forwarding sysctls are not in effect, so relayed traffic "
                "would be dropped instead of delivered. " + " ".join(state.problems) + detail
            )

        # 1. the forwarding path, before anything claims to be the gateway. If the route is
        #    wrong, poisoning makes the kernel the next hop for traffic it cannot deliver --
        #    the victim loses the network instead of being relayed. Installing it first means
        #    a failure here aborts with NO poison frames sent.
        # THE SEGMENT, so the policy table gets a connected route and return traffic for a
        # host ON the segment is delivered on-link instead of being sent back at the gateway.
        if self.table == POLICY_TABLE:
            path_problems = ensure_forwarding_path(
                self.plan.iface, self.plan.gateway_ip,
                gateway_mac=self.plan.gateway_mac, segment=self.plan.segment)
        else:
            path_problems = ensure_forwarding_path(
                self.plan.iface, self.plan.gateway_ip,
                gateway_mac=self.plan.gateway_mac, segment=self.plan.segment,
                table=self.table)
        if path_problems:
            # ── A REFUSED START MUST LEAVE NOTHING BEHIND (audit F032, CONFIRMED BY RUNNING IT) ──
            #
            # This used to raise immediately. `ensure_forwarding_path` could have installed part
            # of the path before failing -- measured: the route add failed and the policy rule was
            # installed anyway -- and the sysctls were already written by step 0. So a REFUSED
            # intercept left the node with rp_filter relaxed and a rule selecting an empty table,
            # which drops the traffic it matches. The operator saw an error and a segment that had
            # quietly lost its ingress policy.
            #
            # The failure is still reported as an error (the caller must know the intercept did
            # not arm), but the cleanup happens FIRST so the raised exception describes a node that
            # is actually back to its previous state.
            withdrawn = remove_forwarding_path(self.plan.iface)
            unrestored = self._sysctls.restore()
            detail = ""
            if withdrawn or unrestored:
                detail = (
                    f" Cleanup was also incomplete: could not withdraw {withdrawn}; could not "
                    f"restore {unrestored}."
                    if (withdrawn or unrestored) else ""
                )
            raise InterceptError(
                "refusing to poison: the forwarding path is not correct, so relayed "
                "traffic would not reach the gateway. " + " ".join(path_problems) + detail
            )

        # 2. watchdog NEXT, so no mapping ever exists without something responsible for
        #    restoring it. A crash between poisoning and arming would leave the segment
        #    poisoned with no undo.
        self.watchdog = FailOpenWatchdog(
            iface=self.plan.iface, our_mac=self.plan.our_mac, sender=self._sender,
            refresh_s=self.refresh_s,
            max_runtime_s=self.max_runtime_s,
        )
        for ic in self.plan.mappings():
            self.watchdog.register(ic)

        # 3. Now it is safe to poison.
        self.watchdog.start()
        self._started = True
        self.started_at = time.time()
        logger.warning(
            "siphon: intercepting %d host(s) on %s via %s. Weirvern is now in the path; "
            "if this process stops, the watchdog restores the mappings.",
            self.plan.host_count, self.plan.segment, self.plan.iface,
        )

    def stop(self) -> None:
        """Withdraw every mapping and the forwarding path. Idempotent.

        ── THE TEARDOWN REPORTS WHAT IT COULD NOT DO (audit F031, CONFIRMED BY RUNNING IT) ──────

        `remove_forwarding_path` used to discard every `ip` command's return code, so a teardown
        that removed NOTHING was indistinguishable from one that removed everything. Measured by
        failing all five commands: the function returned None and this method carried on as if the
        node were clean.

        That is the worst shape of this bug, because a leftover rule sends matching traffic to
        table 100 -- which, with the address withdrawn, has no routes, so the rule DROPS it. The
        operator would see a clean stop and a segment that quietly lost connectivity.

        Reported rather than raised, for the same reason `restore()` reports instead of raising: the
        remaining teardown steps still have to run. A sysctl that cannot be restored is a separate
        and worse problem than a rule that cannot be deleted, and one must not skip the other.
        """
        if self.watchdog is not None:
            # THE RETURN IS READ (WV1-27). Its two neighbours here -- remove_forwarding_path below
            # and _sysctls.restore() after it -- were both fixed to read their results; the
            # watchdog was the one that restores the forged ARP mappings, and it was the one whose
            # outcome nobody looked at. The watchdog logs the detail; this warns once, here, because
            # a caller reading teardown output should not have to parse another module's log lines.
            restored = self.watchdog.stop()
            if restored == 0 and getattr(self.watchdog, "restore_attempted", 0):
                logger.warning(
                    "NO ARP mapping was restored on %s: every restore frame failed to send, so "
                    "host(s) still believe this box is their gateway. Their entries expire on their "
                    "own, but until then traffic may be relayed or dropped. Do not report this "
                    "segment as clean.", self.plan.iface,
                )
        # The policy rule must go too: left behind, it sends ALL traffic arriving on this
        # interface to a table that has no routes once the address is removed, which would
        # break traffic the operator never asked us to touch.
        failures = (remove_forwarding_path(self.plan.iface) if self.table == POLICY_TABLE
                    else remove_forwarding_path(self.plan.iface, table=self.table))
        if failures:
            logger.warning(
                "could NOT withdraw %d forwarding rule(s) or route(s) on %s: %s. A rule left "
                "behind sends matching traffic to policy table %s, which now has no routes, so "
                "that traffic is being DROPPED. Check with: ip rule show; ip route show table %s",
                len(failures), self.plan.iface, "; ".join(failures), self.table, self.table,
            )
        close = getattr(self._sender, "close", None)
        if callable(close):
            close()

        # LAST, and never before the rules: with rp_filter back at its original value, any packet
        # still being routed through table 100 would be dropped by the reverse-path check. Order
        # matters here, and this is the only place it is decided.
        #
        # `restore()` is idempotent and returns the sysctls it could NOT put back, which is reported
        # rather than swallowed: a silent failure here leaves the node's spoofing defence off, and
        # the operator has no other way to learn that.
        #
        # ── TWO DIFFERENT FACTS, REPORTED DIFFERENTLY (audit F034, CONFIRMED BY RUNNING IT) ────
        #
        # `restore()` in the DEPLOYED container returns every managed name, because /proc/sys is
        # read-only there and nothing could be written -- so the old code logged "could NOT restore
        # 5 network sysctl(s) ... Set them back by hand" on EVERY stop, in the deployment where
        # that is the NORMAL state. Measured: applied=[], unrestorable=5 entries.
        #
        # That warning was false in the way that matters. This process changed none of those
        # values; the overlay's privileged init container owns them. A warning that fires on every
        # clean stop trains the operator to ignore it, and then the one that matters is ignored
        # too -- which is the same reasoning `apply()` already applies to per-sysctl write
        # failures, and the reason `needs_node_restore()` exists.
        #
        # So: a sysctl WE changed and cannot put back is a WARNING with the way back. A sysctl we
        # merely could not write is a LIMITATION, stated once at debug, because in this deployment
        # it is expected.
        unrestored = self._sysctls.restore()
        ours = self._sysctls.changed_by_us()
        if ours:
            logger.warning(
                "could NOT restore %d network sysctl(s) that THIS intercept changed: %s. The node "
                "is still configured for an intercept -- rp_filter=0 disables reverse-path "
                "filtering for EVERY interface. Set them back by hand.",
                len(ours), ", ".join(ours),
            )
            # PRINT THE WAY BACK, not just the problem. In the deployed container /proc/sys is
            # read-only, so this process CANNOT restore the node -- the sysctls were set by the
            # overlay's init container. `node_restore_command()` builds the exact shell line from
            # the values recorded BEFORE the intercept changed them; it was written for this and
            # had no caller, so the operator learned about the unrestored state (if they saw the
            # log) with no way back that did not involve reconstructing values by hand.
            command = self._sysctls.snapshot.node_restore_command()
            if command:
                logger.warning(
                    "run this on the node to put the sysctls back (values recorded before "
                    "this intercept changed anything):\n%s", command,
                )
        elif unrestored:
            # Read-only /proc/sys: the normal state in the deployment. Nothing here was changed by
            # this process, so there is nothing to undo -- the node-side init container owns them.
            logger.debug(
                "%d network sysctl(s) are set node-side and were not changed by this process (%s); "
                "the overlay's init container owns them",
                len(unrestored), ", ".join(unrestored),
            )
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
        case are (a) `--seconds`, which bounds the run inside the process, (b) the self-destruct
        deadline (`--max-runtime`, defaulted to `--seconds` + 120s), which restores from a timer
        thread even when nothing can signal or stop this process from outside -- the loop above
        returns when it fires -- and (c) the forged ARP entries EXPIRING as the last resort,
        measured and documented in the watchdog's module docstring (~1 minute for an active
        host, seconds from the next packet for an idle one).

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
                # The self-destruct deadline (siphon-2) restores the mappings from its own
                # timer thread; when that fires, this loop must ALSO return so the caller
                # unwinds -- the case it exists for is precisely one where no signal will
                # ever arrive to break this loop.
                if self.watchdog is not None and self.watchdog.deadline_reached:
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
            "watchdog_restore_attempted": (self.watchdog.restore_attempted
                                           if self.watchdog else 0),
            "watchdog_refreshes": self.watchdog.refresh_count if self.watchdog else 0,
            "watchdog_failures": list(self.watchdog.failures) if self.watchdog else [],
            "watchdog_failures_overflow": self.watchdog.failures_overflow if self.watchdog else 0,
            # Health ticks where forwarding had NEVER been observed. "Quiet" and "broken"
            # look identical until forwarding has been seen working at least once, and this
            # count is how an operator tells which one they are looking at.
            "quiet_samples": self.watchdog.quiet_samples if self.watchdog else 0,
            "forwarding_observed": bool(self.watchdog and self.watchdog.forwarding_observed),
            # Whether the self-destruct deadline fired (no signal, no caller -- the
            # orphaned-session case). Reported so the end of the run does not read like
            # an orderly stop when it was nothing of the kind.
            "deadline_reached": bool(self.watchdog and self.watchdog.deadline_reached),
        }
