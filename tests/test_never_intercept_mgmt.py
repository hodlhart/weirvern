"""The never-intercept rule must be a check, not a sentence.

── WHY THIS FILE EXISTS (audit F033, CONFIRMED BY RUNNING IT) ───────────────────────────────────

`mode.py` states the roles a target must never hold, and the first entry is "the management
interface's own subnet gateway". Host roles are enforced on the arming path
(`never_intercept_hits`). The INTERFACE rule was not.

Measured: ZERO references to `MGMT_IFACE` in `intercept.py`, `siphon_supervisor.py` or
`worker.py`; an `InterceptPlan` for the management interface constructed and armed without
objection. The two places that DID check were both write-time:

  * `cli.py`, when a mode is enabled -- and that command takes `--force`
  * `cluster_config.validate`, when a ConfigMap is written -- and anyone with cluster access can
    edit a ConfigMap

So both doors could be walked around, and the path that actually forges mappings had no door at
all. The consequence in siphon mode is not "the sensor goes dark": the relay is also what keeps the
segment reachable, so the sensor would go dark WHILE HOLDING the segment's traffic.

WHAT THESE TESTS PIN: the gate fires at the point of no return, it fires only on a real conflict,
it does NOT fire when it cannot know, and the escape hatch is explicit and off by default.
"""

from __future__ import annotations

import pytest

from weirvern.admin import intercept as ic


class _Guard:
    """A sysctl guard that records nothing and writes nothing.

    A real `SysctlGuard` touches /proc/sys, which a test must not do -- and the F033 gate sits
    BEFORE it, which is itself a property worth having: a refusal should not have modified the node.
    """

    class snapshot:  # noqa: N801 - mirrors the real attribute name
        @staticmethod
        def node_restore_command() -> str:
            return ""

    def __init__(self) -> None:
        self.applied = False
        self.restored = False

    def apply(self) -> None:
        self.applied = True

    def restore(self) -> list[str]:
        self.restored = True
        return []


@pytest.fixture
def isolated(monkeypatch):
    """Stub every stage AFTER the interface gate, so a refusal can only come from the gate.

    Without this, a test using a nonexistent interface is refused by the forwarding-path check and
    a bug in the F033 gate would be masked -- the first version of my manual probe hit exactly that
    confound.
    """
    monkeypatch.setattr(ic, "ensure_forwarding_path", lambda *a, **kw: [])

    class _WD:
        def __init__(self, **kw):
            self.active = 1

        def register(self, *a, **kw):
            pass

        def start(self):
            pass

        def stop(self):
            pass

    monkeypatch.setattr(ic, "FailOpenWatchdog", _WD)
    monkeypatch.setattr(ic, "ArpSender", lambda iface: type("S", (), {"close": lambda s: None})())


def _plan(iface: str) -> ic.InterceptPlan:
    return ic.InterceptPlan(
        iface=iface, segment="198.51.100.0/24",
        our_mac="11:22:33:44:55:66", our_ip="198.51.100.2",
        gateway_ip="198.51.100.1", gateway_mac="aa:bb:cc:dd:ee:ff",
        hosts={"198.51.100.9": "aa:aa:aa:aa:aa:aa"},
    )


def _attempt(monkeypatch, mgmt: str | None, iface: str, hatch: bool = False):
    """Arm an intercept and report what happened, plus the guard so a caller can inspect it."""
    if mgmt is None:
        monkeypatch.delenv("MGMT_IFACE", raising=False)
    else:
        monkeypatch.setenv("MGMT_IFACE", mgmt)
    guard = _Guard()
    inst = ic.Intercept(_plan(iface), allow_management_iface=hatch)
    inst._sysctls = guard
    try:
        inst.start()
    except ic.InterceptError as exc:
        return f"REFUSED:{exc}", guard
    except Exception as exc:  # noqa: BLE001
        return f"OTHER:{type(exc).__name__}", guard
    return "ARMED", guard


# ── the gate itself ──────────────────────────────────────────────────────────────────────────

def test_intercepting_the_MANAGEMENT_interface_is_refused(isolated, monkeypatch):
    """THE DEFECT. Before the fix this armed without objection."""
    outcome, _ = _attempt(monkeypatch, "ens19", "ens19")
    assert outcome.startswith("REFUSED"), (
        f"an intercept armed on the MANAGEMENT interface. Intercepting that path cuts the sensor "
        f"off from the cluster that manages it, and in siphon mode the relay is what keeps the "
        f"segment reachable, so the sensor goes dark while holding the segment's traffic. "
        f"Got: {outcome}"
    )


def test_the_refusal_NAMES_the_interface_and_the_way_out(isolated, monkeypatch):
    """An operator who is refused needs to know which interface collided and what to do instead --
    a bare 'refused' sends them to the source."""
    outcome, _ = _attempt(monkeypatch, "ens19", "ens19")
    assert "ens19" in outcome, f"the refusal does not name the interface: {outcome}"
    assert "MGMT_IFACE" in outcome, f"the refusal does not name the setting: {outcome}"
    assert "management" in outcome.lower()


def test_a_DIFFERENT_management_interface_is_fine(isolated, monkeypatch):
    """The two-NIC shape, which is the documented deployment. A gate that refuses this is worse
    than no gate, because it blocks the correct configuration."""
    outcome, _ = _attempt(monkeypatch, "ens18", "ens19")
    assert outcome == "ARMED", f"a valid two-NIC plan was refused: {outcome}"


def test_an_UNSET_management_interface_does_not_block(isolated, monkeypatch):
    """With nothing to compare against, the check cannot know, and refusing would break every
    deployment that has not set MGMT_IFACE. The CLI warns about that case separately; this gate
    must not turn an unknown into a refusal."""
    outcome, _ = _attempt(monkeypatch, None, "ens19")
    assert outcome == "ARMED", f"an unset MGMT_IFACE blocked a valid plan: {outcome}"


def test_the_ESCAPE_HATCH_is_explicit_and_off_by_default(isolated, monkeypatch):
    """A single-NIC test host genuinely has one interface for both roles, so the door has to exist.
    It must be opened deliberately rather than inherited, which is why the default is False and the
    refusal message names the alternative first."""
    import inspect

    sig = inspect.signature(ic.Intercept.__init__)
    assert sig.parameters["allow_management_iface"].default is False, (
        "the management-interface hatch defaults to allowing it, so the check would never fire"
    )
    outcome, _ = _attempt(monkeypatch, "ens19", "ens19", hatch=True)
    assert outcome == "ARMED", f"the explicit hatch did not work: {outcome}"


def test_the_refusal_happens_BEFORE_the_node_is_modified(isolated, monkeypatch):
    """The gate sits at the top of `start()`. A refusal that has already written sysctls or
    installed a route leaves the node changed by an intercept that never armed -- which is the
    shape of audit F032, and not worth repeating."""
    outcome, guard = _attempt(monkeypatch, "ens19", "ens19")
    assert outcome.startswith("REFUSED")
    assert guard.applied is False, (
        "the sysctls were recorded (and would be changed) before the refusal, so a rejected "
        "intercept has already modified the node"
    )


# ── the ZEEK_IFACE fallback the finding also names ───────────────────────────────────────────

def test_an_unset_capture_interface_does_not_silently_become_the_management_one():
    """The second half of the finding: a fallback that resolves an unset capture interface to the
    management interface would create the collision the gate exists to catch, and the gate would
    then be refusing a configuration the product itself produced.

    Asserted on the RESOLUTION rather than on the gate, because that is where the defect would be.
    """
    import os

    from weirvern import config

    # An unset ZEEK_IFACE must resolve to empty, never to MGMT_IFACE's value.
    os.environ["MGMT_IFACE"] = "ens18"
    os.environ.pop("ZEEK_IFACE", None)
    try:
        settings = config.Settings()
        assert settings.zeek_iface == "", (
            f"an unset ZEEK_IFACE resolved to {settings.zeek_iface!r} -- if it fell back to "
            f"MGMT_IFACE, the product would construct the very collision its own gate refuses"
        )
    finally:
        os.environ.pop("MGMT_IFACE", None)


# ── F034: the normal state must not produce a warning every time ─────────────────────────────

def test_a_READ_ONLY_proc_sys_does_not_report_sysctls_this_process_never_changed():
    """THE DEFECT. In the deployed container /proc/sys is read-only, so `apply()` records the
    originals and writes nothing -- yet it also marks every managed name `unrestorable`, which
    `restore()` returns. Measured with can_write=False: applied=[], unrestorable=5 entries,
    restore() returned 5 names.

    `intercept.stop()` then logged "could NOT restore 5 network sysctl(s) ... Set them back by
    hand" on EVERY stop in the deployment where that is the NORMAL state. The warning was false:
    this process changed none of them, and the overlay's init container owns them.
    """
    from weirvern.admin import sysctl_guard as sg

    guard = sg.SysctlGuard("ens19")
    guard.capability.can_write = False
    guard.snapshot.original = {n: 2 for n in guard.names()}
    guard.apply()

    assert guard.snapshot.applied == [], (
        "the fixture no longer models the read-only case: something was applied"
    )
    assert guard.restore(), "restore() no longer reports the unreadable names at all"
    assert guard.changed_by_us() == [], (
        "sysctls this process never wrote are reported as changed by us, so every stop in the "
        "deployed container would warn that the node was left configured for an intercept"
    )


def test_a_sysctl_WE_changed_and_could_not_restore_IS_reported():
    """The other direction, and the reason the fix keeps `restore()`'s return value: a value this
    process actually wrote and could not put back is a REAL problem, and must still warn."""
    from weirvern.admin import sysctl_guard as sg

    guard = sg.SysctlGuard("ens19")
    guard.capability.can_write = True
    names = guard.names()
    guard.snapshot.original = {n: 2 for n in names}
    guard.snapshot.applied = list(names)
    # The writes fail, so these are genuinely unrestored.
    guard._restored = False
    import weirvern.admin.sysctl_guard as sgm
    original_write = sgm._write
    sgm._write = lambda name, value: False
    try:
        left = guard.restore()
    finally:
        sgm._write = original_write

    assert left, "a failed restore reported nothing"
    assert guard.changed_by_us(), (
        "sysctls this process DID write are not reported as ours, so a genuine unrestored value "
        "would be downgraded to a debug line"
    )


def test_a_sysctl_we_wrote_but_never_READ_is_not_claimed_as_restorable():
    """A value that was never read has nothing honest to write back, so it must not be counted as
    'ours to restore' -- otherwise the warning would promise an undo that does not exist."""
    from weirvern.admin import sysctl_guard as sg

    guard = sg.SysctlGuard("ens19")
    guard.capability.can_write = True
    names = guard.names()
    guard.snapshot.applied = list(names[:2])
    guard.snapshot.original = {names[0]: 2}  # only the first was readable
    ours = guard.changed_by_us()
    assert names[0] in ours
    assert names[1] not in ours, (
        f"{names[1]!r} was never read, so there is no recorded value to restore it to: {ours}"
    )


def test_STOP_does_not_warn_when_it_changed_NOTHING(isolated, monkeypatch, caplog):
    """THE OBSERVABLE SYMPTOM, and the test my earlier version was missing.

    The unit-level assertions above cover `changed_by_us()`; this one covers what `intercept.stop()`
    actually LOGS, because that is what an operator sees. Mutation testing found the gap: making
    `stop()` fall back to warning on any unrestored name left the whole file green.

    The deployed case is /proc/sys read-only: nothing was changed, so a warning claiming the node
    was left configured for an intercept is FALSE, and it fires on every single stop.
    """
    import logging

    from weirvern.admin import intercept as icm

    monkeypatch.setattr(icm, "remove_forwarding_path", lambda iface: [])

    class _ReadOnlyGuard:
        """The deployed shape: originals recorded, nothing applied, restore() still reports names."""

        class snapshot:  # noqa: N801
            @staticmethod
            def node_restore_command() -> str:
                return "sysctl -w net.ipv4.conf.all.rp_filter=1"

        def apply(self) -> None:
            pass

        def restore(self) -> list[str]:
            return ["net.ipv4.conf.all.rp_filter", "net.ipv4.conf.ens19.rp_filter"]

        def changed_by_us(self) -> list[str]:
            return []

    inst = icm.Intercept(_plan("ens19"))
    inst._sysctls = _ReadOnlyGuard()
    inst._started = True

    with caplog.at_level(logging.WARNING, logger="weirvern.admin.intercept"):
        inst.stop()

    warnings = [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]
    false_alarms = [w for w in warnings if "could NOT restore" in w]
    assert not false_alarms, (
        f"stop() warned that it could not restore sysctls it never changed, in the deployment "
        f"where read-only /proc/sys is the NORMAL state. A warning that fires on every clean stop "
        f"is one an operator learns to ignore. Got: {false_alarms}"
    )


def test_STOP_DOES_warn_when_it_changed_something_it_cannot_restore(isolated, monkeypatch, caplog):
    """The paired case, so the fix cannot pass by suppressing the warning unconditionally. A sysctl
    this process wrote and could not put back is a real problem, and the way back must be printed."""
    import logging

    from weirvern.admin import intercept as icm

    monkeypatch.setattr(icm, "remove_forwarding_path", lambda iface: [])

    class _ChangedGuard:
        class snapshot:  # noqa: N801
            @staticmethod
            def node_restore_command() -> str:
                return "sysctl -w net.ipv4.conf.all.rp_filter=1"

        def apply(self) -> None:
            pass

        def restore(self) -> list[str]:
            return ["net.ipv4.conf.all.rp_filter"]

        def changed_by_us(self) -> list[str]:
            return ["net.ipv4.conf.all.rp_filter"]

    inst = icm.Intercept(_plan("ens19"))
    inst._sysctls = _ChangedGuard()
    inst._started = True

    with caplog.at_level(logging.WARNING, logger="weirvern.admin.intercept"):
        inst.stop()

    warnings = [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]
    text = "\n".join(warnings)
    assert "could NOT restore" in text, (
        f"a sysctl this process changed and could not restore produced no warning: {warnings}"
    )
    assert "THIS intercept changed" in text, (
        f"the warning does not distinguish a value we changed from one we merely could not read: {text}"
    )
    assert "sysctl -w" in text, (
        f"the warning does not print the way back, which is the whole reason "
        f"node_restore_command exists: {text}"
    )
