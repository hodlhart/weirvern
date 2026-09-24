"""The intercept must put the node's network sysctls back when it stops.

WHY THIS FILE EXISTS. Measured on a real host: an intercept was stopped and reported as restored --
address withdrawn, policy rule gone, table flushed -- and the node's sysctls were STILL at the
intercept's values hours later:

    net.ipv4.conf.all.rp_filter        0   (was 2)
    net.ipv4.conf.all.send_redirects   0   (was 1)

They had to be put back by hand. That is worse than a routing leak, because it is a SECURITY change:

    rp_filter=2 is reverse-path filtering. Setting it to 0 across a node disables a spoofing defence
    for EVERY interface -- including the management interface and the cluster's own traffic.

A test that leaves a host's spoofing defence off has damaged the host.

WHAT THESE TESTS PIN DOWN:
  * the ORIGINAL value is what gets restored, not a hardcoded "correct" one -- rp_filter is 2 on
    some distributions and 0 on others, and a node with container networking may already have
    ip_forward=1
  * a value that could NOT be read is NOT restored, because writing a guessed value is worse than
    leaving the intercept's
  * restore runs after the policy rules are removed, not before, or the reverse-path check would
    drop traffic still being routed through the policy table
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from weirvern.admin import sysctl_guard  # noqa: E402


class FakeProcSys:
    """A stand-in for /proc/sys/net that records reads and writes.

    A fake rather than a real write: these tests must not change the machine they run on, and a test
    that sets `rp_filter=0` on a developer's box to prove it can would be doing the exact damage the
    module exists to prevent.
    """

    def __init__(self, initial: dict[str, int | None]) -> None:
        self.values = dict(initial)
        self.writes: list[tuple[str, int]] = []

    def read(self, name: str) -> int | None:
        return self.values.get(name)

    def write(self, name: str, value: int) -> bool:
        self.writes.append((name, value))
        self.values[name] = value
        return True


@pytest.fixture
def proc(monkeypatch):
    """Point the guard at a fake /proc/sys and return it.

    The guard reads through `read_sysctl` and writes through `sysctl_path`, so both are patched --
    patching only one would leave the test writing to the real filesystem.
    """
    fake = FakeProcSys({
        "net.ipv4.ip_forward": 1,
        "net.ipv4.conf.all.rp_filter": 2,
        "net.ipv4.conf.all.send_redirects": 1,
        "net.ipv4.conf.eth1.rp_filter": 2,
        "net.ipv4.conf.eth1.send_redirects": 1,
    })
    monkeypatch.setattr(sysctl_guard, "read_sysctl", fake.read)

    class _Path:
        def __init__(self, name: str) -> None:
            self.name = name

        def write_text(self, text: str) -> None:
            fake.write(self.name, int(text))

    monkeypatch.setattr(sysctl_guard, "sysctl_path", lambda name: _Path(name))
    return fake


# ── the reported failure ──────────────────────────────────────────────────────────────────────

def test_the_original_value_is_restored_not_a_hardcoded_one(proc):
    """THE REGRESSION. rp_filter 2 -> 0 during the intercept, back to 2 after it.

    A restore to a hardcoded 0 would "restore" to the intercept's own value -- a change that looks
    like a restore while changing nothing, which is how the node stayed unprotected.
    """
    guard = sysctl_guard.SysctlGuard("eth1")
    guard.apply()
    assert proc.values["net.ipv4.conf.all.rp_filter"] == 0, "the intercept did not take effect"
    assert proc.values["net.ipv4.ip_forward"] == 1

    guard.restore()
    assert proc.values["net.ipv4.conf.all.rp_filter"] == 2, "rp_filter was NOT restored"
    assert proc.values["net.ipv4.conf.all.send_redirects"] == 1, "send_redirects was NOT restored"
    assert proc.values["net.ipv4.conf.eth1.rp_filter"] == 2, "the iface-scoped value was NOT restored"


def test_the_interface_scoped_value_is_restored_too(proc):
    """`all` alone is not enough: the effective value is the max of `all` and the interface's.

    A node can have `all=0` and still filter on the capture interface, so restoring only `all`
    would leave filtering off where it matters.
    """
    guard = sysctl_guard.SysctlGuard("eth1")
    guard.apply()
    guard.restore()
    assert proc.values["net.ipv4.conf.eth1.send_redirects"] == 1


# ── the honesty rules ─────────────────────────────────────────────────────────────────────────

def test_an_unreadable_value_is_not_restored(monkeypatch):
    """A sysctl that could not be read must NOT be written back.

    Writing a guessed value is worse than leaving the intercept's: it would look like a restore and
    could change the node to a value it never had.
    """
    class Fake:
        def __init__(self) -> None:
            self.values: dict[str, int | None] = {"net.ipv4.conf.all.rp_filter": None}
            self.writes: list[tuple[str, int]] = []

        def read(self, name: str):
            return self.values.get(name)

    fake = Fake()
    monkeypatch.setattr(sysctl_guard, "read_sysctl", fake.read)

    class _Path:
        def __init__(self, name: str) -> None:
            self.name = name

        def write_text(self, text: str) -> None:
            fake.writes.append((self.name, int(text)))

    monkeypatch.setattr(sysctl_guard, "sysctl_path", lambda name: _Path(name))

    guard = sysctl_guard.SysctlGuard("eth1")
    guard.apply()
    left = guard.restore()

    restored_names = {n for n, _ in fake.writes}
    assert "net.ipv4.conf.all.rp_filter" not in restored_names, (
        "a value that was never readable was written back -- a guessed value is not a restore"
    )
    assert "net.ipv4.conf.all.rp_filter" in left, "the unrestorable value was not reported"


def test_restore_is_idempotent(proc):
    """`stop()` may run twice (signal path plus finally). A second restore must not change anything."""
    guard = sysctl_guard.SysctlGuard("eth1")
    guard.apply()
    guard.restore()
    after_first = dict(proc.values)
    guard.restore()
    assert proc.values == after_first, "a second restore wrote something"


def test_a_node_that_already_had_the_required_values_is_unchanged(proc):
    """A node already at 0/0 must be left at 0/0 -- the originals win, whatever they are.

    This is the case a hardcoded restore gets wrong in the other direction: it would force 2 onto a
    node that legitimately runs 0.
    """
    proc.values.update({
        "net.ipv4.conf.all.rp_filter": 0,
        "net.ipv4.conf.all.send_redirects": 0,
    })
    guard = sysctl_guard.SysctlGuard("eth1")
    guard.apply()
    guard.restore()
    assert proc.values["net.ipv4.conf.all.rp_filter"] == 0
    assert proc.values["net.ipv4.conf.all.send_redirects"] == 0


def test_describe_reports_what_will_be_restored(proc):
    """The summary must name the previous value, so a failure to restore is diagnosable."""
    guard = sysctl_guard.SysctlGuard("eth1")
    guard.apply()
    text = guard.snapshot.describe()
    assert "rp_filter" in text
    assert "restore on exit" in text


# ── wiring ────────────────────────────────────────────────────────────────────────────────────

def test_the_intercept_restores_sysctls_after_the_rules_not_before():
    """ORDER: the policy rules must be gone before rp_filter returns to its original value.

    With rp_filter restored while a rule still routes traffic through the policy table, the kernel
    would drop that traffic on the reverse-path check -- a teardown that breaks the traffic it was
    supposed to hand back.
    """
    src = (ROOT / "weirvern" / "admin" / "intercept.py").read_text()
    stop = src.index("def stop(self)")
    body = src[stop:src.index("def active", stop)]
    rules_at = body.index("remove_forwarding_path")
    sysctl_at = body.index("self._sysctls.restore()")
    assert rules_at < sysctl_at, (
        "sysctls are restored BEFORE the policy rules are removed; the reverse-path check would "
        "drop traffic still routed through the policy table"
    )


def test_the_intercept_records_originals_before_it_changes_anything():
    """The read must come before the forwarding path is installed, or it captures our own values."""
    src = (ROOT / "weirvern" / "admin" / "intercept.py").read_text()
    start = src.index("def start(self)")
    body = src[start:src.index("def stop(self)", start)]
    record_at = body.index("self._sysctls.apply()")
    path_at = body.index("ensure_forwarding_path")
    assert record_at < path_at, (
        "the sysctl snapshot is taken AFTER the forwarding path is installed, so it may record the "
        "intercept's own values and 'restore' them"
    )


# ── GLM 5.3 REVIEW: READ-ONLY DOES NOT MEAN SET, AND A SECOND APPLY MUST NOT EAT THE ORIGINALS ───
#
# These use the file's own `proc` fixture (a FakeProcSys behind read_sysctl/sysctl_path) rather than a
# second home-grown fake -- my first attempt invented its own dict keys with slashes instead of dots
# and tested nothing.


def test_the_readonly_branch_VERIFIES_instead_of_assuming(proc, monkeypatch):
    """THE DEFECT (glm-5.3 review, confirmed live).

    In the read-only branch `apply()` returned `[]` -- "nothing failed" -- without ever comparing the
    recorded values to the values siphon needs. It ASSUMED the overlay's privileged init container had
    set them. MEASURED on the live cluster: the deployed Zeek DaemonSet has NO initContainers, so on
    that node the sysctls are correct for some other reason and nothing in the product checked them.
    Had they been wrong, every path would still have reported success, the intercept would have
    poisoned, and the segment would have lost its gateway behind a clean-looking log.

    The fixture's node has rp_filter=2 and send_redirects=1 -- NOT siphon's required 0 -- so a guard
    that cannot write must now say so instead of reporting success.
    """
    guard = sysctl_guard.SysctlGuard("eth1")
    monkeypatch.setattr(guard.capability, "can_write", False, raising=False)

    failed = guard.apply(write=False)
    assert failed, (
        f"the read-only branch reported success on a node whose sysctls are WRONG "
        f"(rp_filter={proc.values['net.ipv4.conf.all.rp_filter']}, "
        f"send_redirects={proc.values['net.ipv4.conf.all.send_redirects']}). It cannot write them, "
        f"which is fine, but an empty failure list means 'safe to poison'"
    )
    joined = " ".join(failed)
    assert "rp_filter" in joined and "READ-ONLY" in joined, joined


def test_the_readonly_branch_is_clean_when_the_values_are_CORRECT(monkeypatch):
    """The other direction: a properly configured node must not produce noise."""
    fake = FakeProcSys({
        "net.ipv4.ip_forward": 1,
        "net.ipv4.conf.all.rp_filter": 0,
        "net.ipv4.conf.all.send_redirects": 0,
        "net.ipv4.conf.eth1.rp_filter": 0,
        "net.ipv4.conf.eth1.send_redirects": 0,
    })
    monkeypatch.setattr(sysctl_guard, "read_sysctl", fake.read)

    guard = sysctl_guard.SysctlGuard("eth1")
    monkeypatch.setattr(guard.capability, "can_write", False, raising=False)

    failed = guard.apply(write=False)
    assert failed == [], f"a correctly configured node reported problems: {failed}"


def test_a_SECOND_apply_does_not_overwrite_the_true_originals(proc):
    """THE OTHER DEFECT.

    apply() re-read every sysctl unconditionally, so a second apply recorded the FIRST apply's own
    values as the originals. `restore()` would then write those back and report success while the node
    kept the intercept's settings -- a clean-looking teardown that changed nothing. The docstring
    claims the originals are the objective record, so it has to be first-wins.

    The fixture starts at rp_filter=2 / send_redirects=1, which is the pre-intercept truth.
    """
    guard = sysctl_guard.SysctlGuard("eth1")
    guard.apply()
    first = dict(guard.snapshot.original)
    assert first["net.ipv4.conf.all.rp_filter"] == 2, (
        f"the first apply recorded {first['net.ipv4.conf.all.rp_filter']} rather than the node's true 2"
    )

    guard.apply()          # a SECOND apply, as a repeated setup would do
    second = dict(guard.snapshot.original)
    assert second == first, (
        f"a second apply() changed the recorded originals: {first} -> {second}. The values it "
        f"recorded the second time are the ones the FIRST apply wrote, so restore() would 'restore' "
        f"the intercept's own settings and report success"
    )

    # And the end-to-end consequence: restore still puts the node back to the TRUE values.
    guard.restore()
    assert proc.values["net.ipv4.conf.all.rp_filter"] == 2, (
        f"after two applies and a restore, rp_filter is {proc.values['net.ipv4.conf.all.rp_filter']} "
        f"rather than the node's original 2 -- the teardown reported success and changed nothing"
    )
    assert proc.values["net.ipv4.conf.all.send_redirects"] == 1, (
        f"send_redirects was left at {proc.values['net.ipv4.conf.all.send_redirects']}, not its "
        f"original 1"
    )
