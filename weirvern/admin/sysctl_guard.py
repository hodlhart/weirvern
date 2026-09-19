"""Save and restore the node's network sysctls around an intercept.

WHY THIS EXISTS. `weir` mode changes THREE NODE-WIDE sysctls:

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

from weirvern.admin.weirnet import read_sysctl, sysctl_path

logger = logging.getLogger(__name__)

# The sysctls weir mode requires, with the value it needs and the interface-scoped counterpart that
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
            return "no sysctls were changed"
        parts = []
        for name in self.applied:
            was = self.original.get(name)
            parts.append(f"{name}: {was} -> restore on exit" if was is not None
                         else f"{name}: unreadable, will NOT be restored")
        return "; ".join(parts)


def _write(name: str, value: int) -> bool:
    """Write one sysctl. Returns success. Never raises."""
    path = sysctl_path(name)
    try:
        path.write_text(str(value))
    except OSError as exc:
        logger.warning("could not write %s=%s (%s): %s", name, value, path, exc)
        return False
    return True


class SysctlGuard:
    """Record the sysctls weir mode changes, and put them back on exit.

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

        # READ FIRST, ALWAYS. The value to restore is the value that was here, which is not knowable
        # from a constant -- rp_filter is 2 on some distributions and 0 on others.
        for name in self.names():
            self.snapshot.original[name] = read_sysctl(name)

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
