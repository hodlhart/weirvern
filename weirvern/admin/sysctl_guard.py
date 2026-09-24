"""Save and restore the node's network sysctls around an intercept.
PRIOR ART -- CHECKED AGAINST THE TOOLS THAT HAVE DONE THIS FOR TWENTY YEARS.

This was written before checking, which was backwards: these projects have hit every footgun in this
area and their source is free. The comparison is worth recording, because it confirms the design and
names an alternative that would avoid the problem entirely.

BETTERCAP does EXACTLY what this module does. It reads /proc/sys/net/ipv4/ip_forward, records the
original in `f.forwarding`, and `Restore()` writes that recorded value back -- not a constant --
guarded by a `restore bool` so it runs once. Same record-then-restore shape, same idempotence flag.
So this is established practice rather than an invention.

ETTERCAP solves the problem differently, and the difference is instructive. `ec_main.c` calls
`disable_ip_forward()` with the comment:

    "always disable the kernel ip forwarding ... the forwarding will be done by ettercap"

It forwards in USERSPACE. The kernel never routes relayed traffic, so ettercap needs NEITHER
`rp_filter=0` NOR `send_redirects=0` -- the two settings that make this module necessary at all.

SCAPY's ARP-spoof documentation does neither: it tells the OPERATOR to run
`sysctl net.ipv4.conf.<iface>.send_redirects=0` and `sysctl net.ipv4.ip_forward=1` by hand, with no
automation and no restore. That is the situation Weirvern was in before this module existed.

THE CHOICE WEIRVERN MAKES, stated plainly: kernel forwarding, because it is far faster than userspace
and this sensor must relay at line rate. That speed is bought with node-level mutation, and the price
is that the mutation MUST be undone. Userspace forwarding would remove this entire class of hazard at
a throughput cost -- a legitimate alternative for a future revision, not a bug to be fixed now.


WHY THIS EXISTS. `siphon` mode changes THREE NODE-WIDE sysctls:

    net.ipv4.ip_forward                     -> 1
    net.ipv4.conf.all.rp_filter             -> 0
    net.ipv4.conf.all.send_redirects        -> 0

Measured on a real host: after an intercept was stopped and restored -- address withdrawn, policy
rule removed, table flushed -- the sysctls were STILL at the intercept's values hours later, and had
to be put back BY HAND.

That matters more than the other teardown gaps, because it is a SECURITY change, not a routing one:

    rp_filter=2 (strict) is reverse-path filtering. Setting it to 0 on the whole node disables a
    spoofing defence for EVERY interface -- including the management interface and the cluster's
    own traffic -- and nothing puts it back. `send_redirects=0` likewise persists.

A test that leaves a host's spoofing defence off is a test that damaged the host.

WHY THE ORIGINAL VALUE IS RECORDED RATHER THAN ASSUMED. The "correct" values are not universal:
`rp_filter` is 2 in some distributions and 0 in others, and a node running container networking may
legitimately have `ip_forward=1` already. Restoring a HARDCODED value would "restore" to something
that was never there. So each value is read before it is changed, and that exact value is written
back. If a value could not be read, it is NOT restored -- guessing is how a restore makes things
worse.

WHY THIS IS A CONTEXT MANAGER. The restore must happen on every exit path: normal end, Ctrl-C,
SIGTERM, or an exception. A `try/finally` around the whole intercept is the only shape that covers
all of them, and the object records what it changed so a nested or repeated call cannot double-apply.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from weirvern.admin.siphonnet import read_sysctl, sysctl_path

logger = logging.getLogger(__name__)

# The sysctls siphon mode requires, with the value it needs and the interface-scoped counterpart that
# must move with the `all` value. `net.ipv4.conf.all.rp_filter` is not enough on its own: the
# EFFECTIVE value for an interface is the maximum of `all` and the per-interface setting, which is
# why a node can have `all=0` and still filter on the capture interface.
MANAGED: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    (
        "net.ipv4.ip_forward",
        "1",
        (),
    ),
    (
        "net.ipv4.conf.all.rp_filter",
        "0",
        ("net.ipv4.conf.{iface}.rp_filter",),
    ),
    (
        "net.ipv4.conf.all.send_redirects",
        "0",
        ("net.ipv4.conf.{iface}.send_redirects",),
    ),
)


@dataclass
class SysctlSnapshot:
    """The values found before the intercept changed anything.

    `original` maps a sysctl NAME to the integer it held, or to None when it could not be read.
    None is deliberately distinct from 0: a sysctl that could not be read must NOT be restored,
    because writing a guessed value is worse than leaving the intercept's.
    """

    original: dict[str, int | None] = field(default_factory=dict)
    applied: list[str] = field(default_factory=list)
    unrestorable: list[str] = field(default_factory=list)

    def changed_anything(self) -> bool:
        return bool(self.applied)

    def describe(self) -> str:
        if not self.applied:
            return "no sysctls were changed by this process"
        parts = []
        for name in self.applied:
            was = self.original.get(name)
            parts.append(f"{name}: {was} -> restore on exit" if was is not None
                         else f"{name}: unreadable, will NOT be restored")
        return "; ".join(parts)

    def node_restore_command(self) -> str:
        """A shell command that puts the node back, for when this process CANNOT.

        WHY THIS EXISTS. In the deployed container /proc/sys is read-only, so this guard cannot
        restore anything -- the sysctls were set by the overlay's privileged init container and only
        something with a writable /proc/sys can undo them. Printing the command is the difference
        between "Weirvern restored the node" and "Weirvern left the node configured for an intercept
        and told nobody until it was noticed hours later".

        Only values that were actually READ appear: restoring to a value we never saw is a guess.
        """
        lines = []
        for name, value in self.original.items():
            if value is None:
                continue
            lines.append(f"sysctl -w {name}={value}")
        return "\n".join(lines)


def _write(name: str, value: int) -> bool:
    """Write one sysctl. Returns success. Never raises."""
    path = sysctl_path(name)
    try:
        path.write_text(str(value))
    except OSError as exc:
        logger.warning("could not write %s=%s (%s): %s", name, value, path, exc)
        return False
    return True


@dataclass
class SysctlCapability:
    """Whether this process can actually WRITE the sysctls, established by TESTING, not by guessing.

    A guard that assumes it can write will log a failure per sysctl per run and restore nothing. A
    guard that assumes it cannot would silently skip the bare-metal case where it works. So the
    ability is probed once, by attempting a write of the value a readable sysctl ALREADY has --
    which changes nothing if it succeeds and reveals the truth either way.
    """

    can_write: bool
    reason: str

    def describe(self) -> str:
        return "writable" if self.can_write else f"read-only ({self.reason})"


def probe_writable() -> SysctlCapability:
    """Can this process write /proc/sys? Tested against a sysctl we can safely read back.

    `net.ipv4.ip_forward` is used because it always exists on Linux. Writing back the value it
    already holds is a no-op when permitted, so the probe is safe: it cannot change behaviour even
    if it succeeds.
    """
    name = "net.ipv4.ip_forward"
    current = read_sysctl(name)
    if current is None:
        return SysctlCapability(False, "cannot read the probe sysctl")

    path = sysctl_path(name)
    try:
        path.write_text(str(current))
    except OSError as exc:
        # The expected result inside a container: /proc/sys is mounted read-only.
        return SysctlCapability(False, f"{type(exc).__name__}: {exc}")
    return SysctlCapability(True, "")


class SysctlGuard:
    """Record the sysctls siphon mode changes, and put them back on exit.

    Usage:

        guard = SysctlGuard(iface)
        guard.apply()
        try:
            ...intercept...
        finally:
            guard.restore()

    `apply()` returns the list of sysctls it could NOT set, so the caller can refuse to run rather
    than poison a segment it cannot relay -- the existing mode check covers that, and this stays a
    pure save/restore so the two concerns cannot drift.
    """

    def __init__(self, iface: str) -> None:
        self.iface = iface
        self.snapshot = SysctlSnapshot()
        self._restored = False
        # Probed once, by test, rather than assumed either way.
        self.capability = probe_writable()

    def names(self) -> list[str]:
        """Every sysctl this will touch, expanded for the interface."""
        out: list[str] = []
        for name, _want, iface_scoped in MANAGED:
            out.append(name)
            out.extend(t.format(iface=self.iface) for t in iface_scoped)
        return out

    def apply(self, write: bool = True) -> list[str]:
        """Record the originals, and optionally set the required values.

        Returns the sysctls that could NOT be set, so a caller that needs them can refuse to proceed.

        READ-ONLY BY DEFAULT FOR `snapshot()`, WRITE FOR `apply()`. The distinction that matters is
        that an UNREADABLE sysctl is never written and never scheduled for restore:

          * unreadable and we write it anyway -> the restore has no honest target, and whatever we
            write back is a guess. The live bug this replaced did exactly that.
          * unreadable because the interface does not exist -> an interface-scoped sysctl that is
            simply absent. Setting it would fail; scheduling it for restore would produce a spurious
            warning on every teardown.

        Either way the value is recorded as None, which `restore()` treats as "do not touch".
        """
        failed: list[str] = []

        # READ FIRST, ALWAYS -- AND ONLY ONCE PER VALUE (glm-5.3 review).
        #
        # The value to restore is the value that was here before WE touched it, which is not knowable
        # from a constant -- rp_filter is 2 on some distributions and 0 on others.
        #
        # This used to assign unconditionally, so a SECOND apply() on the same guard overwrote the
        # true pre-intercept originals with the values the FIRST apply() had just written
        # (ip_forward=1, rp_filter=0). `restore()` would then write those back and report success
        # while the node kept the intercept's settings -- a clean-looking teardown that changed
        # nothing. The module's own docstring claims the originals are the objective record, so it has
        # to be first-wins for that to be true.
        for name in self.names():
            if name not in self.snapshot.original:
                self.snapshot.original[name] = read_sysctl(name)

        if not self.capability.can_write:
            # NOT A FAILURE THAT THIS PROCESS CANNOT WRITE. /proc/sys is read-only in the deployed
            # container by design: the node's sysctls are set by the overlay's privileged init
            # container, which is the only thing with a writable /proc/sys. The recorded values are
            # still the useful output, so this returns without per-sysctl write failures -- reporting
            # five of them on every run trains the reader to ignore them, and then the one that
            # matters is ignored too.
            #
            # ── BUT READ-ONLY DOES NOT MEAN SET (glm-5.3 review, CONFIRMED LIVE) ────────────────
            #
            # This returned `[]` -- "nothing failed" -- WITHOUT EVER COMPARING the recorded values to
            # the values siphon needs. It assumed the init container had done its job. MEASURED on the
            # live node: the deployed DaemonSet has NO initContainers (`kubectl get ds zeek -o
            # jsonpath='{...initContainers[*].name}'` is empty), so on this cluster the sysctls are
            # correct for some OTHER reason and nothing in the product checked or set them. If they
            # had been wrong, every path here would still have reported success, the intercept would
            # have poisoned, and the segment would have lost its gateway with a clean-looking log.
            #
            # So the read-only branch now VERIFIES instead of assuming. A wrong value is reported as
            # a failure, because the caller's contract is that an empty problem list means "safe to
            # poison" -- and an unchecked value cannot support that claim.
            self.snapshot.unrestorable.extend(self.names())
            for name, want, iface_scoped in MANAGED:
                for target in [name] + [t.format(iface=self.iface) for t in iface_scoped]:
                    current = self.snapshot.original.get(target)
                    if current is None:
                        # Unreadable: cannot confirm, so it is not confirmed-good either.
                        failed.append(
                            f"{target} could not be read, so it could not be verified. Siphon needs "
                            f"{want}."
                        )
                        continue
                    if int(current) != int(want):
                        failed.append(
                            f"{target} is {current} but siphon needs {want}, and this container's "
                            f"/proc/sys is READ-ONLY so it cannot be corrected from here. Set it on "
                            f"the node (the overlay's privileged init container does this, or: "
                            f"sysctl -w {target.replace('/', '.')}={want}). Until then an intercept "
                            f"would poison ARP with forwarding misconfigured, which loses the "
                            f"segment's gateway."
                        )
            return failed

        for name, want, iface_scoped in MANAGED:
            for target in [name] + [t.format(iface=self.iface) for t in iface_scoped]:
                if self.snapshot.original.get(target) is None:
                    # NOT WRITTEN, regardless of whether it is the `all` value or an interface one.
                    # An earlier version exempted the main sysctl here with `target != name`, so an
                    # unreadable `all.rp_filter` was written to 0 and then "restored" to a guess.
                    self.snapshot.unrestorable.append(target)
                    continue
                if write and not _write(target, int(want)):
                    failed.append(target)
                    continue
                if write and target not in self.snapshot.applied:
                    self.snapshot.applied.append(target)
        return failed

    def needs_node_restore(self) -> bool:
        """True when this process recorded originals it cannot put back itself.

        The deployed case: read-only /proc/sys, node-side init container did the setting. The caller
        must then either report the command (interactive) or accept that the node stays configured
        for siphon mode until something restores it (a deployment that is genuinely running siphon).
        """
        return bool(self.snapshot.applied) and not self.capability.can_write or (
            not self.snapshot.applied and not self.capability.can_write and bool(self.snapshot.original)
        )

    def changed_by_us(self) -> list[str]:
        """The sysctls THIS PROCESS actually wrote, and therefore must put back.

        ── WHY THIS EXISTS (audit F034, CONFIRMED BY RUNNING IT) ────────────────────────────────

        `restore()` returns `unrestorable`, which in the deployed container is populated by
        `apply()` with EVERY managed name -- because /proc/sys is read-only here, so nothing in
        this process could be written. Measured with `can_write = False`:

            applied after a read-only apply:  []
            unrestorable:                     5 entries
            restore() returned:               5 names

        `intercept.stop()` then logs "could NOT restore 5 network sysctl(s) ... Set them back by
        hand" on EVERY stop, in the deployment where that is the NORMAL state. The warning is
        false: this process changed none of them, and the overlay's privileged init container owns
        them. A warning that fires on every clean stop is one an operator learns to ignore, and
        then the one that matters is ignored too -- which is the same reasoning `apply()` already
        uses for not reporting five per-sysctl write failures.

        So the caller needs both facts separately: what WE changed (report the way back when we
        cannot restore it) versus what we merely could not read (report as a limitation, once).
        """
        return [n for n in self.snapshot.applied if self.snapshot.original.get(n) is not None]

    def record_only(self) -> list[str]:
        """Record the originals WITHOUT changing anything. For a dry run or an audit.

        Named `record_only` rather than `snapshot`: the instance already has a `snapshot` ATTRIBUTE,
        and a method of the same name shadows it, so `guard.snapshot.original` would resolve to the
        method. mypy caught that; the rename is the fix rather than suppressing it.
        """
        return self.apply(write=False)

    def restore(self) -> list[str]:
        """Put back every value that was changed AND was readable. Returns those left unrestored.

        Idempotent: a second call does nothing, so it is safe in a `finally` that may run after an
        explicit restore.
        """
        if self._restored:
            return list(self.snapshot.unrestorable)
        self._restored = True

        left: list[str] = []
        for name in reversed(self.snapshot.applied):
            was = self.snapshot.original.get(name)
            if was is None:
                # Deliberate: this value was never read, so there is nothing honest to write back.
                # Repeating the intercept's own value would look like a restore while changing
                # nothing.
                left.append(name)
                logger.warning("%s was never readable; leaving it rather than guessing", name)
                continue
            if not _write(name, was):
                left.append(name)
        return left + list(self.snapshot.unrestorable)
