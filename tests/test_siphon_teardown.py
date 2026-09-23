"""A teardown that removes nothing must not look like a teardown that removed everything.

── WHY THIS FILE EXISTS (audit F031 and F032, BOTH CONFIRMED BY RUNNING THEM) ───────────────────

F031 -- THE SILENT TEARDOWN. `remove_forwarding_path` ran five `ip` commands and discarded every
return code, returning nothing. Measured by making all of them fail with "Operation not permitted"
(what a node without CAP_NET_ADMIN produces):

    return value: None
    -> the caller could not tell that NOTHING had been removed

The consequence is not cosmetic. A leftover rule sends matching traffic to policy table 100, which
with the address withdrawn has NO ROUTES -- so the rule DROPS that traffic. The operator sees a
clean stop and a segment that quietly lost connectivity.

F032 -- THE REFUSED START. `ensure_forwarding_path` appended a problem when the route add failed and
then INSTALLED THE POLICY RULE ANYWAY. Measured by failing only the route add:

    could not add the policy route: RTNETLINK answers: Network is unreachable
    but the policy rule was still added: ['policy rule ADDED']

That is the same black-hole, created by the failure path rather than by the teardown. The caller
raised without removing what had just been installed, and the sysctls from step 0 were left relaxed.

WHAT THESE TESTS PIN: that a failure is REPORTED, that it is reported SPECIFICALLY (an absence is
not a failure), and that the ordering that prevents the black-hole is enforced.
"""

from __future__ import annotations

import pytest

from weirvern.admin import siphonnet


@pytest.fixture
def fake_ip(monkeypatch):
    """Replace the `ip` runner and record every command.

    `_run` is the boundary the module already uses for every kernel interaction, so replacing it
    exercises the real control flow rather than a reimplementation of it.
    """
    state: dict = {"calls": [], "results": {}}

    def _run(*args):
        cmd = " ".join(str(a) for a in args)
        state["calls"].append(cmd)
        for fragment, result in state["results"].items():
            if fragment in cmd:
                return result
        return 0, ""

    monkeypatch.setattr(siphonnet, "_run", _run)
    return state


# ── F031: the teardown reports what it could not do ─────────────────────────────────────────

def test_a_teardown_that_removes_NOTHING_reports_the_failures(fake_ip):
    """THE DEFECT. Every command failing must produce a non-empty result, or the caller cannot tell
    a clean node from a poisoned one."""
    fake_ip["results"] = {"ip": (2, "RTNETLINK answers: Operation not permitted")}

    failures = siphonnet.remove_forwarding_path("eth1")

    assert failures, (
        "every `ip` command failed and remove_forwarding_path reported nothing, so a teardown that "
        "removed NOTHING is indistinguishable from one that removed everything -- and a leftover "
        "rule pointing at an empty table DROPS the traffic it matches"
    )
    assert all("Operation not permitted" in f for f in failures), (
        f"the failures do not carry the kernel's own reason, which is what tells an operator "
        f"whether it is a permission problem or a missing table: {failures}"
    )


def test_a_SUCCESSFUL_teardown_reports_nothing(fake_ip):
    """The other direction, so the warning cannot pass by always firing. A warning that shows up on
    every clean stop is one an operator learns to ignore."""
    fake_ip["results"] = {"ip": (0, "")}
    assert siphonnet.remove_forwarding_path("eth1") == []


def test_an_ABSENT_rule_is_not_a_failure(fake_ip):
    """`ip rule del` fails when there is no such rule, which is the NORMAL case for a second stop.
    Reporting it would make idempotent teardown look broken."""
    fake_ip["results"] = {"ip": (2, "RTNETLINK answers: No such file or directory")}
    assert siphonnet.remove_forwarding_path("eth1") == [], (
        "an absent rule was reported as a failure, so every repeated stop would warn"
    )


def test_a_real_failure_after_an_absence_is_still_reported(fake_ip):
    """Mixed results must not be swallowed by the absence filter -- that filter is the one place a
    real failure could hide."""
    def _run(*args):
        cmd = " ".join(str(a) for a in args)
        fake_ip["calls"].append(cmd)
        if "flush" in cmd:
            return 2, "RTNETLINK answers: Permission denied"
        return 2, "RTNETLINK answers: No such file or directory"

    import weirvern.admin.siphonnet as sn
    sn._run = _run  # type: ignore[assignment]
    try:
        failures = sn.remove_forwarding_path("eth1")
    finally:
        sn._run = fake_ip.get("_orig")  # restored by monkeypatch teardown regardless
    assert any("Permission denied" in f for f in failures), (
        f"a genuine permission failure was filtered out alongside the absences: {failures}"
    )


def test_the_teardown_attempts_EVERY_step(fake_ip):
    """One failing step must not skip the others. The rule deletion, the parsed-priority sweep, the
    exact-form deletion and the route flush are four separate chances to clean up."""
    fake_ip["results"] = {"rule del priority 1000": (2, "RTNETLINK answers: Operation not permitted")}
    siphonnet.remove_forwarding_path("eth1")

    joined = " | ".join(fake_ip["calls"])
    assert "rule del priority" in joined, "the priority-based deletion was skipped"
    assert "route flush" in joined, (
        f"the route flush was skipped after an earlier failure, so the empty table is left behind: "
        f"{fake_ip['calls']}"
    )


# ── F032: the rule must not be installed without the route ──────────────────────────────────

def test_the_policy_rule_is_NOT_installed_when_the_route_fails(fake_ip, monkeypatch):
    """THE DEFECT, and the ordering that prevents it. An absent route changes nothing; a rule
    pointing at an empty table DROPS traffic. So the route is the precondition."""
    monkeypatch.setattr(siphonnet, "resolve_mac", lambda iface, gw: "aa:bb:cc:dd:ee:ff")
    monkeypatch.setattr(siphonnet, "forwarding_path_problems", lambda iface, gw: [])
    fake_ip["results"] = {"route add": (2, "RTNETLINK answers: Network is unreachable")}

    problems = siphonnet.ensure_forwarding_path("eth1", "198.51.100.1")

    assert problems, "the failed route add was not reported"
    rule_adds = [c for c in fake_ip["calls"] if "rule add" in c]
    assert not rule_adds, (
        f"the policy rule was installed even though the route it depends on was not, which "
        f"black-holes the traffic it matches: {rule_adds}"
    )


def test_a_successful_setup_still_installs_both(fake_ip, monkeypatch):
    """And the normal path must be unaffected, or the fix would trade a black-hole for a broken
    intercept."""
    monkeypatch.setattr(siphonnet, "resolve_mac", lambda iface, gw: "aa:bb:cc:dd:ee:ff")
    monkeypatch.setattr(siphonnet, "forwarding_path_problems", lambda iface, gw: [])
    fake_ip["results"] = {}

    problems = siphonnet.ensure_forwarding_path("eth1", "198.51.100.1")

    assert problems == [], f"a clean setup reported problems: {problems}"
    joined = " | ".join(fake_ip["calls"])
    assert "route add" in joined and "rule add" in joined, fake_ip["calls"]


def test_an_UNREACHABLE_gateway_still_refuses_before_installing_anything(fake_ip, monkeypatch):
    """The pre-existing guard, so this fix does not weaken it: no route at all may be installed
    when the gateway cannot be reached."""
    monkeypatch.setattr(siphonnet, "resolve_mac", lambda iface, gw: "")

    problems = siphonnet.ensure_forwarding_path("eth1", "198.51.100.1")

    assert problems and "did not resolve" in problems[0], problems
    assert not [c for c in fake_ip["calls"] if "add" in c], (
        f"something was installed despite an unreachable gateway: {fake_ip['calls']}"
    )


# ── the caller's cleanup ────────────────────────────────────────────────────────────────────

def test_a_REFUSED_start_withdraws_what_it_installed(monkeypatch):
    """F032's second half. The caller raised without removing the partially-installed path, so a
    refused intercept left the node changed. Verified by driving the real `start()` and asserting
    the cleanup ran, rather than by reading the source."""
    from weirvern.admin import intercept as ic

    order: list[str] = []

    monkeypatch.setattr(ic, "ensure_forwarding_path",
                        lambda *a, **kw: order.append("ensure") or ["route add failed"])
    monkeypatch.setattr(ic, "remove_forwarding_path",
                        lambda iface: order.append("withdraw") or [])

    class _Guard:
        """A no-op sysctl guard: this test is about CLEANUP ORDER, and a real one would try to
        write /proc/sys from the test process."""

        class snapshot:  # noqa: N801 - mirrors the real attribute
            @staticmethod
            def node_restore_command() -> str:
                return ""

        def apply(self) -> None:
            order.append("sysctl-apply")

        def restore(self) -> list[str]:
            order.append("sysctl-restore")
            return []

    inst = ic.Intercept(_minimal_plan())
    inst._sysctls = _Guard()
    with pytest.raises(ic.InterceptError):
        inst.start()

    # THE ORDER THAT MATTERS is `ensure` before `withdraw` (you cannot withdraw what was not
    # installed) and BOTH cleanup steps after the refusal. The first version of this asserted
    # `order[0] == "ensure"`, which failed on the code being RIGHT: `_sysctls.apply()` runs first by
    # design, because it RECORDS the previous values before anything changes -- reading them later
    # would capture the intercept's own values and restore the wrong thing.
    assert "ensure" in order, f"the refusal did not come from the forwarding path: {order}"
    assert order.index("ensure") < order.index("withdraw"), (
        f"the withdraw happened before the install it was cleaning up: {order}"
    )
    assert "withdraw" in order, (
        f"a refused start did not withdraw the path it partially installed, so the node keeps a "
        f"rule selecting an empty table: {order}"
    )
    assert "sysctl-restore" in order, (
        f"a refused start left the sysctls it recorded applied, so rp_filter stays relaxed on a "
        f"node that is not intercepting: {order}"
    )


def test_the_refusal_still_RAISES(monkeypatch):
    """The cleanup must not turn a refusal into a success. An intercept that silently did not arm
    is worse than one that errors, because the operator believes they are watching traffic."""
    from weirvern.admin import intercept as ic

    monkeypatch.setattr(ic, "ensure_forwarding_path", lambda *a, **kw: ["route add failed"])
    monkeypatch.setattr(ic, "remove_forwarding_path", lambda iface: [])

    class _Guard:
        class snapshot:  # noqa: N801
            @staticmethod
            def node_restore_command() -> str:
                return ""

        def apply(self) -> None:
            pass

        def restore(self) -> list[str]:
            return []

    inst = ic.Intercept(_minimal_plan())
    inst._sysctls = _Guard()
    with pytest.raises(ic.InterceptError) as exc:
        inst.start()
    assert "refusing to poison" in str(exc.value), (
        f"the error no longer explains WHY nothing armed: {exc.value}"
    )


def test_a_CLEANUP_that_ALSO_fails_is_reported_in_the_error(monkeypatch):
    """If the cleanup itself cannot complete, the operator must be told in the error they are
    already reading, not only in a log line they may never see."""
    from weirvern.admin import intercept as ic

    monkeypatch.setattr(ic, "ensure_forwarding_path", lambda *a, **kw: ["route add failed"])
    monkeypatch.setattr(ic, "remove_forwarding_path", lambda iface: ["ip rule del: denied"])

    class _Guard:
        class snapshot:  # noqa: N801
            @staticmethod
            def node_restore_command() -> str:
                return ""

        def apply(self) -> None:
            pass

        def restore(self) -> list[str]:
            return ["net.ipv4.conf.eth1.rp_filter"]

    inst = ic.Intercept(_minimal_plan())
    inst._sysctls = _Guard()
    with pytest.raises(ic.InterceptError) as exc:
        inst.start()

    message = str(exc.value)
    assert "Cleanup was also incomplete" in message, (
        f"the error does not mention that the node was left changed: {message}"
    )
    assert "rp_filter" in message and "ip rule del" in message, (
        f"the error does not name WHAT could not be cleaned up: {message}"
    )


def _minimal_plan():
    from weirvern.admin.intercept import InterceptPlan
    return InterceptPlan(
        iface="eth1", segment="198.51.100.0/24",
        our_mac="11:22:33:44:55:66", our_ip="198.51.100.2",
        gateway_ip="198.51.100.1", gateway_mac="aa:bb:cc:dd:ee:ff",
        hosts={},
    )
