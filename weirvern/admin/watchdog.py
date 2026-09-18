"""Fail-open watchdog for weir (in-path intercept) mode.

WHY THIS IS A PREREQUISITE AND NOT A FEATURE
--------------------------------------------
In weir mode Weirvern becomes a router. Hosts are told that Weirvern's MAC is the
gateway, so their traffic arrives here and is relayed on. If Weirvern stops relaying
without telling them otherwise, those hosts have no network until their ARP entries
expire — a LAN outage caused by the monitoring tool. That is categorically worse than a
sensor that captures nothing.

The verified behaviour this module relies on (measured on the test box):

  * A graceful stop that restores the real ARP mappings returns traffic IMMEDIATELY.
  * A hard kill (SIGKILL, power loss) leaves the forged entries in place, but they
    EXPIRE on their own and traffic recovers unaided. Measured: after flushing the
    poisoned caches the victim reached the internet directly again.

So there are two layers of safety, and both matter: an orderly restore on every path we
control, and an expiry-based backstop for the paths we do not. This module implements
the first and documents the second.

WHAT IT DOES NOT DO: it does not forward packets. Forwarding is the kernel's job
(ip_forward plus a route). This watches that the kernel is still doing it and acts when
it is not, which is why the health check reads packet counters rather than probing
anything itself.

DESIGN NOTE ON THE HEALTH CHECK: it reads the kernel's own forwarding counter instead
of sending test traffic. Probe traffic would be visible to an attacker and would add
load to the very path being watched; the counter is free and authoritative.
"""
from __future__ import annotations

import logging
import signal
import socket
import struct
import threading
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# ARP hardware/protocol constants. Linux-only, which is fine: the sensor is Linux.
ARP_OP_REQUEST = 1
ARP_OP_REPLY = 2
ETH_P_ARP = 0x0806
BROADCAST = "ff:ff:ff:ff:ff:ff"

# How often to re-assert a forged mapping. Hosts refresh ARP entries on a timer
# (commonly ~30s for a complete entry, up to ~20 minutes in some stacks), and Linux
# starts probing a stale entry after a few minutes. Re-asserting every 10s keeps the
# entry firmly in place without materially adding to broadcast load.
DEFAULT_REFRESH_S = 10.0

# How often to check that forwarding is alive. Independent of the refresh interval:
# a forwarding stall must be caught in about a second, not in ten.
DEFAULT_HEALTH_S = 1.0


def mac_to_bytes(mac: str) -> bytes:
    return bytes.fromhex(mac.replace(":", "").replace("-", ""))


def build_arp_reply(src_mac: str, src_ip: str, dst_mac: str, dst_ip: str) -> bytes:
    """An unsolicited ARP reply: "src_ip is at src_mac".

    A REPLY rather than a request because a host accepts an unsolicited reply for an
    entry it already holds, which is what makes the mapping take effect immediately.
    Pure function so the frame construction is testable without a socket or root.
    """
    frame = mac_to_bytes(dst_mac) + mac_to_bytes(src_mac) + struct.pack("!H", ETH_P_ARP)
    frame += struct.pack("!HHBBH", 1, 0x0800, 6, 4, ARP_OP_REPLY)
    frame += mac_to_bytes(src_mac) + socket.inet_aton(src_ip)
    frame += mac_to_bytes(dst_mac) + socket.inet_aton(dst_ip)
    return frame


@dataclass
class Interception:
    """One forged mapping, and how to undo it.

    `host_ip` is whose cache we are poisoning. `claim_ip` is the address we are
    claiming to own (usually the gateway). `real_mac` is who actually owns it, so the
    restore is the same frame with the true MAC — which is why the real MAC is stored
    rather than rediscovered later, when the network may be in the broken state we are
    trying to fix.
    """

    host_ip: str          # the host whose ARP cache we poison
    host_mac: str         # that host's real MAC (the destination of our frames)
    claim_ip: str         # the address we claim, e.g. the gateway
    real_mac: str         # the MAC that genuinely owns claim_ip
    iface: str            # interface to send from
    our_mac: str          # our MAC, i.e. the lie we are telling

    def poison_frame(self) -> bytes:
        """Forge: claim_ip is at OUR mac, sent to the host."""
        return build_arp_reply(self.our_mac, self.claim_ip, self.host_mac, self.host_ip)

    def restore_frame(self) -> bytes:
        """Correct: claim_ip is at the REAL mac, sent to the host."""
        return build_arp_reply(self.real_mac, self.claim_ip, self.host_mac, self.host_ip)


class ForwardingMonitor:
    """Watches the kernel's forwarding counters for a stall.

    Reads /proc/net/snmp's Ip: Forwarding field, which counts datagrams forwarded by
    the kernel. Monotonic increase == forwarding alive. Wrapping is not a practical
    concern (2^32 packets) but a DECREASE is treated as a reset rather than an error,
    because it means the counter source changed underneath us.
    """

    def __init__(self, sample: int = 0):
        self._last = sample
        self._stalls = 0

    @staticmethod
    def read() -> int:
        """The Ip: Forwarding counter, or -1 when it cannot be read."""
        try:
            with open("/proc/net/snmp") as fh:
                lines = fh.read().splitlines()
        except OSError:
            return -1
        # Two consecutive "Ip:" lines: the header row of names, then the values.
        names: list[str] = []
        for line in lines:
            if not line.startswith("Ip: "):
                continue
            parts = line.split()[1:]
            if not names:
                names = parts
                continue
            if len(parts) != len(names):
                continue
            try:
                return int(parts[names.index("Forwarding")])
            except (ValueError, IndexError):
                return -1
        return -1

    def advanced(self) -> bool | None:
        """True if the counter moved since the last call.

        Returns None when the counter is unavailable, so a caller can distinguish
        "not forwarding" from "cannot tell" — conflating those is how a watchdog
        either never fires or fires constantly.
        """
        now = self.read()
        if now < 0:
            return None
        moved = now > self._last
        self._last = now
        return moved


class FailOpenWatchdog:
    """Keeps forged mappings alive, and guarantees they are withdrawn.

    Usage:
        wd = FailOpenWatchdog(iface, our_mac, sender)
        wd.register(Interception(...))          # per host
        wd.start()
        ...
        wd.stop()                                # restores everything, idempotently

    `sender` is injected so the logic is testable without root: production passes a
    function that writes the frame to an AF_PACKET socket.
    """

    def __init__(self, iface: str, our_mac: str, sender=None,
                 refresh_s: float = DEFAULT_REFRESH_S,
                 health_s: float = DEFAULT_HEALTH_S) -> None:
        self.iface = iface
        self.our_mac = our_mac
        self._sender = sender
        self.refresh_s = refresh_s
        self.health_s = health_s

        self._interceptions: dict[tuple[str, str], Interception] = {}
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._restored = False
        self._forwarding = ForwardingMonitor()
        self._stall_strikes = 0
        # Whether forwarding has EVER been seen to work since the mappings went in. Until
        # it has, a still counter is uninformative -- an idle segment looks identical to a
        # broken one -- so the health loop must not treat stillness as a stall. See
        # _health_loop for why treating it as one makes weir flap.
        self._forwarding_observed = False
        # Ticks where nothing was being forwarded yet. Reported rather than counted toward
        # a failure, so an operator can tell "quiet" from "broken".
        self._quiet_samples = 0
        self._threads: list[threading.Thread] = []
        # Recorded so status output can explain WHY the watchdog fired.
        self.failures: list[str] = []
        self.restored_count = 0
        self.refresh_count = 0

    # -- registration ----------------------------------------------------------
    def register(self, ic: Interception) -> None:
        """Add a mapping to keep alive."""
        with self._lock:
            self._interceptions[(ic.host_ip, ic.claim_ip)] = ic
            # Reset the restore latch: a new interception must be covered by a
            # later restore.
            self._restored = False

    def unregister(self, host_ip: str, claim_ip: str) -> None:
        """Withdraw one mapping: restore it, then stop refreshing it."""
        with self._lock:
            ic = self._interceptions.pop((host_ip, claim_ip), None)
        if ic is not None:
            self._send(ic.restore_frame(), "restore")

    @property
    def active(self) -> int:
        with self._lock:
            return len(self._interceptions)

    # -- the two loops ---------------------------------------------------------
    def start(self) -> None:
        """Start refreshing and monitoring. Installs signal handlers.

        Signal handlers are installed here rather than in main() so any caller gets
        fail-open behaviour without having to remember it — the whole point is that it
        cannot be forgotten.
        """
        self._install_signal_handlers()
        for target, name in ((self._refresh_loop, "weirvern-weir-refresh"),
                             (self._health_loop, "weirvern-weir-health")):
            t = threading.Thread(target=target, name=name, daemon=True)
            t.start()
            self._threads.append(t)

        # Assert the mappings IMMEDIATELY, not on the first refresh tick.
        #
        # The refresh loop waits `refresh_s` (5s) before its first iteration, so without
        # this there is a window in which start() has returned, the caller reports
        # "intercepting N hosts", and NOT ONE poison frame has been sent -- the ARP caches
        # are untouched, so traffic is not actually flowing through us. Interception that
        # silently is not happening is the worst failure mode this module has, because
        # everything downstream looks healthy.
        #
        # This runs LAST, after the signal handlers and both loops are live, so the
        # guarantee "no mapping exists without something responsible for restoring it"
        # still holds: by the time a frame is on the wire, restore-on-signal is installed
        # and the health monitor is running.
        self._poison_all("initial")
        logger.info("fail-open watchdog started on %s (%d mapping(s))",
                    self.iface, self.active)

    def _poison_all(self, kind: str) -> int:
        """Send a poison frame for every registered mapping. Returns the count sent."""
        with self._lock:
            items = list(self._interceptions.values())
        sent = 0
        for ic in items:
            if self._send(ic.poison_frame(), kind):
                sent += 1
        return sent

    def _install_signal_handlers(self) -> None:
        """SIGTERM/SIGINT restore before exiting.

        SIGKILL cannot be caught, which is exactly why the expiry backstop matters:
        the forged entries age out and the network recovers without us.
        """
        def handler(signum, _frame):
            logger.warning("signal %s received — restoring ARP mappings", signum)
            self.stop()
            raise SystemExit(0)

        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                signal.signal(sig, handler)
            except (ValueError, OSError):
                # Not on the main thread (e.g. under a test runner); the restore on
                # stop() still applies, only the signal path is unavailable.
                logger.debug("could not install handler for %s", sig)

    def _refresh_loop(self) -> None:
        while not self._stop.wait(self.refresh_s):
            # Shares _poison_all with the initial assertion, so the initial and periodic
            # paths cannot drift apart -- a difference between them would mean the first
            # frames and the maintained frames were built or counted differently.
            self.refresh_count += self._poison_all("refresh")

    def _health_loop(self) -> None:
        """Watch forwarding. Two consecutive missed samples before acting.

        One missed sample is normal: /proc/net/snmp updates periodically, so a single
        quiet second proves nothing. Acting on it would produce spurious restores,
        which are themselves disruptive.

        WHY A QUIET NETWORK IS NOT A STALL. The counter only advances when traffic is
        actually being forwarded. On an idle segment -- or a test harness, or overnight on
        a home LAN -- it legitimately does not move, and treating that as "we broke
        forwarding" makes weir flap: poison, restore, poison, restore. Each flap is a brief
        outage, so a benign condition would become a continuous one.

        The distinction that matters is whether we have OBSERVED forwarding working. If the
        counter has never advanced since the mappings went in, we cannot conclude anything
        from its stillness, so the watchdog stays armed but silent and the ARP cache
        expiry backstop covers a genuine failure. Once forwarding has been seen to work,
        a stall IS meaningful, because we know we broke something that was working.
        """
        while not self._stop.wait(self.health_s):
            advanced = self._forwarding.advanced()
            if advanced is None:
                continue
            if advanced:
                self._stall_strikes = 0
                self._forwarding_observed = True
                continue
            if not self._forwarding_observed:
                # Nothing has ever been forwarded. Stillness is uninformative here, so
                # record it once rather than accumulating strikes that would trip a restore.
                self._quiet_samples += 1
                continue
            self._stall_strikes += 1
            if self._stall_strikes < 2:
                continue
            msg = (f"forwarding stalled for {self._stall_strikes} samples on "
                   f"{self.iface} after previously working; failing open")
            logger.error(msg)
            self.failures.append(msg)
            self.stop()
            return

    # -- stopping --------------------------------------------------------------
    def stop(self) -> None:
        """Restore every mapping. Idempotent and safe to call from any thread.

        Ordering matters: stop the loops FIRST, then restore. Restoring while the
        refresh loop is still running would let it re-poison the caches immediately
        after we corrected them — leaving the network broken while claiming success.
        """
        with self._lock:
            if self._restored:
                return
            self._stop.set()
            items = list(self._interceptions.values())
            self._interceptions.clear()

        for ic in items:
            self._send(ic.restore_frame(), "restore")
        self.restored_count = len(items)
        with self._lock:
            self._restored = True
        logger.info("restored %d ARP mapping(s); traffic is no longer through Weirvern",
                    len(items))

    # -- io --------------------------------------------------------------------
    def _send(self, frame: bytes, kind: str) -> bool:
        if self._sender is None:
            return False
        try:
            # `kind` MUST be forwarded. Dropping it made restore and refresh frames
            # indistinguishable to the sender (both arrived as the default "poison"), so a
            # sender could not log, route, or count them differently -- and a test could
            # not tell a restore from a re-poison. That distinction is the whole reason
            # `kind` exists here.
            self._sender(frame, kind)
            return True
        except OSError as exc:
            # A send failure during RESTORE is the dangerous one: it means a host may
            # still believe we are the gateway. Recorded so status can surface it.
            msg = f"{kind} send failed on {self.iface}: {exc}"
            logger.error(msg)
            if kind == "restore":
                self.failures.append(msg)
            return False


def preflight_sysctls() -> list[tuple[str, str, str]]:
    """Read the forwarding sysctls weir mode depends on.

    Returns (name, current_value, required_value) for each. Read-only: weir mode
    requires these to be set by whoever deployed the sensor, so a mismatch is reported
    rather than silently corrected. Silently changing network knobs on a host is
    precisely the behaviour that makes an operator distrust a monitoring tool.
    """
    from weirvern.admin.mode import REQUIRED_SYSCTLS

    out = []
    for name, want, _symptom in REQUIRED_SYSCTLS:
        path = "/proc/sys/" + name.replace(".", "/")
        try:
            with open(path) as fh:
                current = fh.read().strip()
        except OSError:
            current = "?"
        out.append((name, current, want))
    return out
