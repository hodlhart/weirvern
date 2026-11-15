"""Fail-open watchdog for siphon (in-path intercept) mode.

WHY THIS IS A PREREQUISITE AND NOT A FEATURE
--------------------------------------------
In siphon mode Weirvern becomes a router. Hosts are told that Weirvern's MAC is the
gateway, so their traffic arrives here and is relayed on. If Weirvern stops relaying
without telling them otherwise, those hosts have no network until their ARP entries
expire — a LAN outage caused by the monitoring tool. That is categorically worse than a
sensor that captures nothing.

The verified behaviour this module relies on (measured on the test box):

  * A graceful stop that restores the real ARP mappings returns traffic IMMEDIATELY.
  * A hard kill (SIGKILL, power loss) leaves the forged entries in place, but they
    EXPIRE on their own and traffic recovers unaided.

THE EXPIRY BACKSTOP, MEASURED. The earlier version of this docstring said recovery was
"measured" but quoted a MANUAL cache flush -- i.e. it measured us fixing it by hand, not
the kernel's own timer. Re-measured properly, in a container with NET_ADMIN, poisoning a
host's gateway entry and watching the neighbour state machine on stock Linux defaults
(base_reachable_time_ms=30000, gc_stale_time=60, ucast_solicit=3):

  * BUSY HOST (sending traffic the whole time): REACHABLE for ~44s, then
    STALE -> DELAY (5s) -> PROBE -> FAILED -> the host re-resolves via broadcast
    ARP. Measured recovery: ~55 seconds, worst observed ~60s.
  * IDLE HOST (no traffic after the poison): the entry sits REACHABLE until gc, goes
    STALE ~65s, and NOTHING recovers it until the host next tries to send -- at which
    point the first packet triggers DELAY (5s) -> PROBE (3 unicast solicits) -> FAILED
    -> broadcast re-resolve; measured ~8-10 seconds from that first packet. A host that
    never sends never notices; a host that sends recovers within seconds of trying.

So the honest bound for the orphan case is: traffic recovers WITHIN ABOUT A MINUTE for a
host that is actively using the network, and within seconds of that host's next packet
otherwise. It is not instantaneous, and it depends on kernel neighbour-table defaults
that a deployment could have tuned -- which is why this module ALSO bounds the run from
the inside (max_runtime_s below) rather than trusting the backstop alone.

So there are three layers of safety, and all three matter: an orderly restore on every
path we control, a self-destruct deadline for the paths where no signal arrives (a
SIGKILLed `kubectl exec` client leaves the in-pod process ALIVE -- it just cannot be
signalled from outside), and the kernel's expiry as the last resort. This module
implements the first two and documents the third.

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

    KEPT FOR THE RESTORE ONLY. See build_arp_announcement for why a REPLY cannot install a
    mapping on a modern host; this function is retained because correcting a mapping back to
    the truth is a different case (see Interception.restore_frame).

    Pure function so the frame construction is testable without a socket or root.
    """
    frame = mac_to_bytes(dst_mac) + mac_to_bytes(src_mac) + struct.pack("!H", ETH_P_ARP)
    frame += struct.pack("!HHBBH", 1, 0x0800, 6, 4, ARP_OP_REPLY)
    frame += mac_to_bytes(src_mac) + socket.inet_aton(src_ip)
    frame += mac_to_bytes(dst_mac) + socket.inet_aton(dst_ip)
    return frame


def build_arp_announcement(claimed_mac: str, claimed_ip: str,
                           dst_mac: str, dst_ip: str) -> bytes:
    """A forged ARP REQUEST that installs a mapping: "who-has dst_ip tell claimed_ip".

    THIS IS THE FRAME THAT ACTUALLY POISONS, and the reason is a Linux behaviour that
    silently ignores the frame the product originally sent.

    MEASURED against a real host on a live segment (198.51.100.193), each frame type sent 8
    times, reading the destination MAC of the host's reply to an off-link probe:

        forged ARP reply, unicast         ->  ignored   (reply still went to the real gateway)
        forged ARP REQUEST, unicast       ->  TOOK      (reply came to us, 3/3)
        gratuitous broadcast reply        ->  ignored

    Linux will not update a neighbour entry that is in REACHABLE state from an UNSOLICITED
    ARP REPLY. A host's gateway entry is essentially always REACHABLE, because the host
    talks to its gateway constantly -- so the reply was discarded every time, while the
    frame itself was perfectly well formed. That is why every earlier attempt concluded
    "the poison never took": it genuinely never did.

    An ARP REQUEST is processed as an announcement of the sender's mapping ("I am
    claimed_ip at claimed_mac") regardless of the receiving entry's state, so it installs
    the mapping. The request still asks `who-has dst_ip`, which the target answers on the
    wire; we ignore that answer, since our own mapping is already installed.

    A reply is still the right frame for a RESTORE, where the goal is to correct an entry
    that is currently wrong-and-stale rather than to displace a healthy one.
    """
    frame = mac_to_bytes(dst_mac) + mac_to_bytes(claimed_mac) + struct.pack("!H", ETH_P_ARP)
    frame += struct.pack("!HHBBH", 1, 0x0800, 6, 4, ARP_OP_REQUEST)
    frame += mac_to_bytes(claimed_mac) + socket.inet_aton(claimed_ip)
    frame += b"\x00" * 6 + socket.inet_aton(dst_ip)
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
        """Forge: claim_ip is at OUR mac, sent to the host.

        An ANNOUNCEMENT (ARP request), not a reply. Measured against a real host: a forged
        reply is silently ignored for a REACHABLE entry, and a host's gateway entry is
        always reachable -- so the reply form never installed anything. See
        build_arp_announcement.
        """
        return build_arp_announcement(self.our_mac, self.claim_ip,
                                      self.host_mac, self.host_ip)

    def restore_frame(self) -> bytes:
        """Correct: claim_ip is at the REAL mac, sent to the host.

        The same frame form as the poison, for the same reason: the announcement installs a
        mapping regardless of the entry's state. A reply would be processed for a STALE
        entry (which is what the poisoned entry is), but relying on a state distinction for
        the RESTORE is the wrong place to be clever -- the restore is the safety property,
        so it uses the form that provably works in every state.
        """
        return build_arp_announcement(self.real_mac, self.claim_ip,
                                      self.host_mac, self.host_ip)


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
                 health_s: float = DEFAULT_HEALTH_S,
                 max_runtime_s: float | None = None) -> None:
        self.iface = iface
        self.our_mac = our_mac
        self._sender = sender
        self.refresh_s = refresh_s
        self.health_s = health_s
        # SELF-DESTRUCT DEADLINE (siphon-2's third layer). Covers the case where the
        # process is ALIVE but no signal can reach it -- a `kubectl exec` client that was
        # SIGKILLed leaves the in-pod process running with nobody able to sign it. A
        # graceful signal restores; this thread restores at the deadline regardless.
        #
        # It does NOT cover the process itself being SIGKILLed (that kills this thread
        # too); the kernel's ARP expiry is the last resort there, measured and documented
        # in the module docstring. None disables it.
        self.max_runtime_s = max_runtime_s
        self.deadline_reached = False
        self._deadline_handle: threading.Timer | None = None

        self._interceptions: dict[tuple[str, str], Interception] = {}
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._restored = False
        # PRIMED WITH THE CURRENT COUNTER, not with the default zero.
        #
        # ForwardingMonitor reads "the counter is greater than my last sample" as evidence of
        # forwarding. Constructed with the default 0, the FIRST call therefore always looked
        # like progress -- the real counter is in the millions on any live host -- which set
        # `_forwarding_observed = True` without a single packet having been forwarded.
        #
        # Consequence, measured on a live intercept: the watchdog believed forwarding was
        # already proven working, so the first quiet second became a "stall" and siphon failed
        # open on a healthy network. Everything below depends on `_forwarding_observed`
        # meaning something, and it was being set by arithmetic rather than by evidence.
        self._forwarding = ForwardingMonitor(sample=max(0, ForwardingMonitor.read()))
        self._stall_strikes = 0
        # Whether forwarding has EVER been seen to work since the mappings went in. Until
        # it has, a still counter is uninformative -- an idle segment looks identical to a
        # broken one -- so the health loop must not treat stillness as a stall. See
        # _health_loop for why treating it as one makes siphon flap.
        self._forwarding_observed = False
        # Ticks where nothing was being forwarded yet. Reported rather than counted toward
        # a failure, so an operator can tell "quiet" from "broken".
        self._quiet_samples = 0
        self._threads: list[threading.Thread] = []
        # Recorded so status output can explain WHY the watchdog fired.
        #
        # CAPPED, with an overflow count. A restore-send failure is recorded on every
        # failed send, and the refresh loop re-sends every few seconds -- so on a flapping
        # NIC this list grew without bound over a long intercept and every status read
        # returned the whole thing. The count is what matters ("it happened 400 times");
        # the first few are the diagnostic sample.
        self.failures: list[str] = []
        self.failures_overflow = 0
        self.restored_count = 0
        # What stop() was asked to restore, so a caller can tell "nothing to do" from "all failed".
        self.restore_attempted = 0
        self.refresh_count = 0

    MAX_FAILURES_RECORDED = 20

    def _record_failure(self, msg: str) -> None:
        """Append to the failure log, keeping it bounded."""
        if len(self.failures) < self.MAX_FAILURES_RECORDED:
            self.failures.append(msg)
        else:
            self.failures_overflow += 1

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
    def quiet_samples(self) -> int:
        """Health ticks where forwarding had never yet been observed.

        Read by status output so an operator can tell "quiet segment" from "broken relay":
        until forwarding has been seen working at least once, a still counter is
        uninformative, and this count is the evidence of how long the ambiguity lasted.
        """
        return self._quiet_samples

    @property
    def forwarding_observed(self) -> bool:
        """Whether the forwarding counter has EVER advanced since the mappings went in.

        The latch that makes stillness interpretable: False means a still counter proves
        nothing (an idle segment looks identical to a broken relay), True means a stall is
        meaningful because we know we broke something that was working.
        """
        return self._forwarding_observed

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
        if self.max_runtime_s is not None and self.max_runtime_s > 0:
            # A Timer, not a third forever-loop: it fires exactly once and then the thread
            # is done. Fires slightly AFTER the deadline value so a run stopped by its own
            # wait() bound (which uses the same number) restores through the normal path
            # first -- the Timer is the backstop for when that path never got to run.
            self._deadline_handle = threading.Timer(self.max_runtime_s + 1.0, self._deadline)
            self._deadline_handle.daemon = True
            self._deadline_handle.start()
        for target, name in ((self._refresh_loop, "weirvern-siphon-refresh"),
                             (self._health_loop, "weirvern-siphon-health")):
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

    def _deadline(self) -> None:
        """Fired when max_runtime_s elapsed. Restore, loudly.

        The distinguishing property of this path is that NOTHING asked for the stop: no
        signal, no caller. That makes it the one place where the log line is the only
        evidence the operator will ever see, so it states the reason in full.

        NOTE ON PROCESS EXIT: this runs on a Timer thread, and a SystemExit raised here
        would end only this thread, not the process. The restore is what must happen
        unconditionally and it does; the main thread finds `deadline_reached` set when
        its wait loop next ticks and unwinds normally (see Intercept.wait).
        """
        if self._restored:
            return
        self.deadline_reached = True
        msg = (f"self-destruct deadline reached ({self.max_runtime_s}s): restoring ARP "
               f"mappings without being asked. No signal or caller arrived to stop this "
               f"intercept, which is the orphaned-session case the deadline exists for.")
        logger.warning(msg)
        self.stop()

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
        forwarding" makes siphon flap: poison, restore, poison, restore. Each flap is a brief
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
            self._record_failure(msg)
            self.stop()
            return

    # -- stopping --------------------------------------------------------------
    def stop(self) -> int:
        """Restore every mapping. Idempotent and safe to call from any thread.

        RETURNS THE NUMBER OF RESTORE FRAMES THAT WERE ACTUALLY SENT (WV1-27). It used to return
        None and set `restored_count = len(items)` -- the number of mappings it TRIED, not the
        number that went out. A restore frame can fail to send (`_send` returns False on OSError),
        and in that case this method still reported the full count while logging "traffic is no
        longer through Weirvern". That is the one sentence a teardown must never print on a
        failure, because the host keeps believing this box is its gateway.


        Ordering matters: stop the loops FIRST, then restore. Restoring while the
        refresh loop is still running would let it re-poison the caches immediately
        after we corrected them — leaving the network broken while claiming success.
        """
        with self._lock:
            if self._restored:
                return self.restored_count
            self._stop.set()
            items = list(self._interceptions.values())
            self._interceptions.clear()
        # The deadline Timer must not fire after a deliberate stop: it would log a
        # self-destruct that never happened. Idempotent by itself, but the record would lie.
        if self._deadline_handle is not None:
            self._deadline_handle.cancel()
            self._deadline_handle = None

        sent = 0
        for ic in items:
            if self._send(ic.restore_frame(), "restore"):
                sent += 1
        self.restore_attempted = len(items)
        self.restored_count = sent
        with self._lock:
            self._restored = True
        if sent == len(items):
            logger.info("restored %d ARP mapping(s); traffic is no longer through Weirvern", sent)
        else:
            # NOT a normal teardown: hosts whose restore never left still point at this box.
            logger.error(
                "restored ONLY %d of %d ARP mapping(s) on %s: %d host(s) may still believe this "
                "box is their gateway. Their ARP entries expire on their own, but until then that "
                "traffic is being relayed or dropped. The send failures are recorded; check "
                "`weirvern intercept status` before assuming the segment is clean.",
                sent, len(items), self.iface, len(items) - sent,
            )
        return sent

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
                self._record_failure(msg)
            return False


def preflight_sysctls() -> list[tuple[str, str, str]]:
    """Read the forwarding sysctls siphon mode depends on.

    Returns (name, current_value, required_value) for each. Read-only: siphon mode
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
