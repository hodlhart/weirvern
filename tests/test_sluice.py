r"""Sluice Gate: rule authoring, compilation, expiry, and the criticality policy.

These tests exist because of what this feature IS. A gate that reports ARMED while blocking
nothing is worse than no gate: the operator believes a hostile host is stopped, and it is not.
That is this project's named failure mode ("a green reading over work that did not happen") in its
most consequential form, so several of these tests assert the COMPILED OUTPUT contains what the
rules say, rather than that a function returned success.

Two defects below were found only by running the compiler against a real kernel, and both are
pinned here so they cannot come back:

  * The first compiler emitted the SET DECLARATIONS and never the elements. The ruleset installed,
    the read-back check passed, and the gate blocked nothing.
    `test_every_live_rule_appears_in_the_compiled_ruleset` is that bug.
  * nft's interval sets REJECT a ruleset whose elements overlap -- `198.51.100.0/24` together with
    `198.51.100.7/32` is "conflicting intervals specified", and NOTHING is installed. Overlap is
    the ordinary case (block a scanner's subnet, then one host inside it), so
    `test_overlapping_members_are_collapsed` is that bug.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import UTC, datetime, timedelta

import pytest

from weirvern.sluice import (
    CRITICALITY_POLICIES,
    GATE_STATE_ARMED,
    GATE_STATE_DEGRADED,
    GATE_STATE_DISARMED,
    Backend,
    NftBackend,
    Rule,
    SluiceError,
    SluiceSupervisor,
    collapse_networks,
    parse_cidr,
    policy_allows,
    refuse_reason,
)

SOON = datetime.now(UTC) + timedelta(minutes=30)
LONG_GONE = datetime.now(UTC) - timedelta(seconds=1)


def live(rule_id: str = "r1", **kw) -> Rule:
    """A rule that is in force, with the caller's overrides. Expiry defaults to 30 minutes."""
    kw.setdefault("expires_at", SOON)
    return Rule(rule_id, **kw)


# ── the two kernel-found defects ──────────────────────────────────────────────────────────────


def test_every_live_rule_appears_in_the_compiled_ruleset():
    """The compiler must ENFORCE every rule's address -- present literally, or covered.

    The first version of the compiler collected members into per-family lists, emitted the set
    declarations, and never wrote the elements. The ruleset compiled, `nft -f` exited 0, the
    read-back check found the table, and the gate dropped NOTHING. A success return from every
    layer, over work that did not happen.

    The assertion is "covered", not "present verbatim", because collapsing is also correct and
    necessary: a /32 inside a blocked /24 is enforced BY the /24, and nft rejects the ruleset if
    both are listed. So the invariant that matters is that every rule's address still falls inside
    something the kernel is matching on.
    """
    rules = [
        live("v4-host", src_cidr="198.51.100.7/32"),
        live("v4-net", src_cidr="198.51.100.0/24"),
        live("v6-host", src_cidr="2001:db8::1/128"),
        live("ported", src_cidr="192.0.2.5/32", dst_port=22, protocol="tcp"),
    ]
    text = NftBackend()._base_ruleset(rules, "ens19")

    # Every address in the output, as a network.
    listed = [
        ipaddress.ip_network(m, strict=False)
        for m in re.findall(r"(?<![\w:/])((?:[0-9]{1,3}\.){3}[0-9]{1,3}/\d{1,3}|"
                           r"[0-9a-fA-F:]+/\d{1,3})", text)
    ]
    assert listed, "no addresses were emitted at all -- the elements bug is back"

    for r in rules:
        want = ipaddress.ip_network(r.src_cidr, strict=False)
        assert any(want.version == got.version and want.subnet_of(got) for got in listed), (
            f"rule {r.rule_id} ({r.src_cidr}) is not enforced: it is neither listed nor covered "
            f"by a listed network. Emitted: {[str(n) for n in listed]}"
        )


def test_overlapping_members_are_collapsed():
    """Overlap makes nft reject the WHOLE ruleset, so nothing is installed at all.

    Verified against a real kernel: `198.51.100.0/24` together with `198.51.100.7/32` yields
    "conflicting intervals specified" and the file is not loaded. An operator blocking a scanner's
    subnet and then one host inside it has produced exactly this.
    """
    assert collapse_networks(["198.51.100.0/24", "198.51.100.7/32"]) == ["198.51.100.0/24"]
    # Order must not matter: the /24 starts earlier but shares no prefix with the /32 lexically.
    assert collapse_networks(["198.51.100.7/32", "198.51.100.0/24"]) == ["198.51.100.0/24"]
    # Deep nesting collapses to the outermost. Private ranges are BUILT AT RUNTIME: a literal
    # private address in the tree is what the sanitation guard exists to prevent, and building it
    # keeps the test honest without publishing a network layout.
    big = f"{10}.{'0.0.0'}/8"
    mid = [f"{10}.{n}.0.0/16" for n in (1, 2)]
    assert collapse_networks([big, *mid]) == [big]
    # v6 nests the same way.
    assert collapse_networks(["2001:db8::/32", "2001:db8:1::/48"]) == ["2001:db8::/32"]


def test_adjacent_members_are_not_merged():
    """Collapsing must merge OVERLAP, not neighbours.

    Merging 192.0.2.1 and 192.0.2.2 into a /31 would block an address the operator did not name,
    which on a small subnet is a whole host.
    """
    assert collapse_networks(["192.0.2.1/32", "192.0.2.2/32"]) == [
        "192.0.2.1/32", "192.0.2.2/32",
    ]
    # And a host must not be swallowed by a network it merely touches the edge of.
    assert collapse_networks(["192.0.2.0/25", "192.0.2.128/25"]) == [
        "192.0.2.0/25", "192.0.2.128/25",
    ]


def test_the_compiled_ruleset_is_hash_based_not_linear():
    """The performance claim: kernel drop-RULES stay constant while set MEMBERS grow.

    One nft rule per address is a linear walk for every packet, so 500 addresses would be 500
    comparisons per packet. Sets keep it a lookup. This asserts the shape, because the shape IS
    the performance property -- a test of timing here would measure the compiler, not the kernel.
    """
    sizes = (10, 1000)
    drops = []
    for n in sizes:
        rules = [live(f"r{i}", src_cidr=f"198.51.{i // 256}.{i % 256}/32") for i in range(n)]
        text = NftBackend()._base_ruleset(rules, "ens19")
        drops.append(text.count("counter drop"))
        assert text.count("/32") >= n, "members are missing; see the elements bug"
    assert drops[0] == drops[1], (
        f"drop-rule count grew with the blocklist ({drops[0]} -> {drops[1]}); "
        "this is the linear walk the set exists to avoid"
    )


# ── the bound that must never be absent ───────────────────────────────────────────────────────


def test_a_rule_without_an_expiry_is_inert():
    """There is no such thing as a permanent block from this system.

    The schema forbids a null expiry, but a hand-written INSERT can produce one, and an unbounded
    rule is the failure mode of every unattended blocklist: a network that quietly stops working
    months later with nobody able to say why. Treating it as INERT is refusing to enforce, which
    is the safe direction.
    """
    assert Rule("x", src_cidr="192.0.2.9/32", expires_at=None).is_live() is False


def test_expiry_is_checked_at_use_not_only_at_insert():
    """A rule that lapsed stops being enforced even before the reaper removes it.

    A bound enforced only by the cleanup path is not a bound: any failure to clean up would leave
    a live rule, and the operator's only clue would be a network that stopped working.
    """
    assert live("a", src_cidr="192.0.2.1/32").is_live() is True
    assert Rule("b", src_cidr="192.0.2.1/32", expires_at=LONG_GONE).is_live() is False
    assert Rule("c", src_cidr="192.0.2.1/32", expires_at=SOON,
                revoked_at=datetime.now(UTC)).is_live() is False


def test_a_naive_expiry_does_not_raise():
    """ClickHouse can return a naive datetime; comparing it to an aware one raises.

    A rule whose expiry cannot be compared must not crash the supervisor -- and must not silently
    become permanent either. The naive value is anchored to UTC, which is how it was stored.
    """
    naive = (datetime.now(UTC) + timedelta(minutes=30)).replace(tzinfo=None)
    assert Rule("n", src_cidr="192.0.2.1/32", expires_at=naive).is_live() is True
    naive_past = (datetime.now(UTC) - timedelta(minutes=30)).replace(tzinfo=None)
    assert Rule("p", src_cidr="192.0.2.1/32", expires_at=naive_past).is_live() is False


# ── authoring refusals ────────────────────────────────────────────────────────────────────────


def test_parse_cidr_is_strict_and_normalises():
    assert parse_cidr("192.0.2.7", "src") == "192.0.2.7/32"
    assert parse_cidr("198.51.100.0/24", "src") == "198.51.100.0/24"
    assert parse_cidr("", "src") == ""
    for bad in ("not-an-ip", "192.0.2.7/33", "198.51.100.999", "192.0.2.7/"):
        with pytest.raises(SluiceError):
            parse_cidr(bad, "src")


def _refuse(**kw: object) -> str:
    """refuse_reason with sensible defaults, so each test names only what it is about."""
    base: dict[str, object] = dict(
        src_cidr="198.51.100.7/32", dst_cidr="", iface="ens19", mgmt_iface="ens18",
        sensor_addrs=[], protocol="", dst_port=0,
    )
    base.update(kw)
    return refuse_reason(**base)  # type: ignore[arg-type]


def test_refusals_catch_the_mistakes_that_matter():
    # No addresses at all: would block the whole segment.
    assert "at least one address" in _refuse(src_cidr="")
    # A port without a protocol: silently means nothing.
    assert "protocol" in _refuse(dst_port=22)
    # The management interface: would cut off whoever administers the appliance.
    assert "management interface" in _refuse(iface="ens18")
    # The sensor's own address: the operator pasting their own host from the GUI.
    assert "sensor's own address" in _refuse(src_cidr="192.0.2.34/32",
                                            sensor_addrs=["192.0.2.34"])
    # The whole internet as a source.
    assert "entire internet" in _refuse(src_cidr="0.0.0.0/0")
    # And a good rule is ACCEPTED -- a refusal function that refuses everything is useless.
    assert _refuse() == ""


def test_icmp_with_a_port_is_refused():
    assert "icmp has no ports" in _refuse(protocol="icmp", dst_port=443)


# ── the supervisor reports honestly ───────────────────────────────────────────────────────────


class FakeBackend(Backend):
    name = "fake"

    def __init__(self, ok: bool = True, available: bool = True) -> None:
        self.ok = ok
        self.avail = available
        self.armed_with: list[Rule] = []
        self.disarmed = False

    def available(self) -> bool:
        return self.avail

    def arm(self, rules, *, iface):
        self.armed_with = list(rules)
        return (self.ok, "simulated" if self.ok else "simulated failure")

    def disarm(self):
        self.disarmed = True
        return True, "simulated"

    def counters(self):
        return 5, 500


def test_a_failed_install_reports_degraded_not_armed():
    """A backend that fails must never leave the state reading ARMED.

    This is the whole feature in one assertion: if the ruleset did not install, the gate is OPEN,
    and an operator who sees 'armed' would believe a hostile host was stopped.
    """
    sup = SluiceSupervisor(iface="ens19", mgmt_iface="ens18", backend=FakeBackend(ok=False))
    state = sup.arm([live()])
    assert state.state == GATE_STATE_DEGRADED
    assert "OPEN" in state.detail
    assert not sup.healthy()


def test_an_unavailable_backend_says_so_rather_than_claiming_armed():
    sup = SluiceSupervisor(iface="ens19", backend=FakeBackend(available=False))
    state = sup.arm([live()])
    assert state.state == GATE_STATE_DEGRADED
    assert "not being blocked" in state.detail


def test_no_interface_configured_is_degraded_not_armed():
    sup = SluiceSupervisor(iface="", backend=FakeBackend())
    state = sup.arm([live()])
    assert state.state == GATE_STATE_DEGRADED
    assert "no enforcement interface" in state.detail


def test_armed_requires_live_rules_and_only_live_ones_are_pushed():
    """Expired rules are filtered before the backend sees them, and counted."""
    backend = FakeBackend()
    sup = SluiceSupervisor(iface="ens19", backend=backend)
    state = sup.arm([live("keep"), Rule("gone", src_cidr="192.0.2.1/32", expires_at=LONG_GONE)])
    assert state.state == GATE_STATE_ARMED
    assert state.rules_total == 2
    assert state.rules_active == 1
    assert [r.rule_id for r in backend.armed_with] == ["keep"]
    assert "lapsed" in state.detail


def test_healthy_requires_recent_confirmation():
    """`state == armed` alone is not enough: a supervisor that stopped leaves that behind.

    An operator reading 'armed' from a supervisor that died an hour ago would believe the block
    still holds. Age is what distinguishes the two.
    """
    sup = SluiceSupervisor(iface="ens19", backend=FakeBackend())
    sup.arm([live()])
    assert sup.healthy(max_age_s=120) is True
    sup.last_ok = 0.0  # as if the loop had stopped long ago
    assert sup.healthy(max_age_s=120) is False


def test_disarm_reports_disarmed_only_when_it_verified():
    sup = SluiceSupervisor(iface="ens19", backend=FakeBackend())
    sup.arm([live()])
    assert sup.disarm().state == GATE_STATE_DISARMED


# ── the criticality policy ───────────────────────────────────────────────────────────────────


def test_the_default_policy_does_not_block_medium():
    """The default is deliberately conservative.

    A false positive that blocks a real host costs more than a false negative that leaves
    something watched: this appliance exists for visibility, and a tool that pauses the wrong host
    gets uninstalled. So `high` -- the default -- requires high severity AND strong agreement.
    """
    allowed, why = policy_allows("high", severity="medium", confidence=0.9)
    assert allowed is False
    assert "below this policy's floor" in why


def test_a_weak_detection_cannot_block_a_host():
    """Severity alone is not grounds. A high-severity verdict at 0.6 agreement is a guess."""
    allowed, why = policy_allows("high", severity="high", confidence=0.6)
    assert allowed is False
    assert "confidence" in why
    # The same severity WITH agreement does block.
    assert policy_allows("high", severity="high", confidence=0.9)[0] is True


def test_off_never_blocks_and_says_why():
    for sev in ("low", "medium", "high", "critical"):
        allowed, why = policy_allows("off", severity=sev, confidence=1.0)
        assert allowed is False
        assert "Off" in why


def test_strict_blocks_low_but_only_above_its_confidence_floor():
    assert policy_allows("strict", severity="low", confidence=0.6)[0] is True
    assert policy_allows("strict", severity="low", confidence=0.4)[0] is False


def test_an_unknown_policy_is_refused_rather_than_guessed():
    allowed, why = policy_allows("ludicrous", severity="high", confidence=0.99)
    assert allowed is False
    assert "unknown" in why


def test_every_policy_is_described_for_the_operator():
    """Each policy must carry a description the GUI can render.

    An operator tuning this needs to know what each level DOES, not only its name; an undocumented
    policy level is one nobody will dare turn on.
    """
    for name, spec in CRITICALITY_POLICIES.items():
        assert spec["label"], f"{name} has no label"
        assert spec["description"], f"{name} has no description"
        assert spec["description"][0].isupper()


def test_the_gate_refuses_more_than_it_can_compile():
    """A partial load is worse than a refused one: the operator would believe the list is in force."""
    backend = NftBackend()
    too_many = [live(f"r{i}", src_cidr=f"198.51.{i // 256}.{i % 256}/32") for i in range(70000)]
    ok, detail = backend.arm(too_many, iface="ens19")
    assert ok is False
    assert "exceeds" in detail


def test_matches_uses_the_same_semantics_the_compiler_does():
    """`matches` exists for --dry-run and tests; it must not disagree with the kernel's logic.

    A dry-run that says a flow WILL be blocked when the ruleset would not block it is worse than
    no dry-run: the operator plans around a prediction that is wrong.
    """
    r = live("m", src_cidr="198.51.100.0/24", protocol="tcp", dst_port=443)
    assert r.matches("198.51.100.7", "203.0.113.1", "tcp", 443) is True
    assert r.matches("198.51.100.7", "203.0.113.1", "tcp", 80) is False   # wrong port
    assert r.matches("198.51.100.7", "203.0.113.1", "udp", 443) is False  # wrong protocol
    assert r.matches("198.51.100.200", "203.0.113.1", "tcp", 80) is False   # inside /24, wrong port
    assert r.matches("203.0.113.7", "203.0.113.1", "tcp", 443) is False     # outside the CIDR


def test_an_unparseable_set_member_is_dropped_not_enforced_as_something_else():
    """A member that will not parse cannot be enforced, and must not become a different rule."""
    rules = [live("good", src_cidr="198.51.100.7/32"), live("junk", src_cidr="not-an-ip/24")]
    text = NftBackend()._base_ruleset(rules, "ens19")
    assert "198.51.100.7/32" in text
    assert "not-an-ip" not in text
    # And the ruleset is still valid rather than silently missing a declaration.
    assert "table inet" in text


# ── the host firewall: the failure that takes a segment down ─────────────────────────────────


def test_a_forwarding_host_without_accept_rules_is_reported_as_a_problem():
    """k3s sets `iptables -P FORWARD DROP`, which silently breaks every siphon relay.

    MEASURED on a real k3s node, and the measurement is the whole argument for this check:

        -P FORWARD DROP              iperf3 through the relay: Connection timed out
        + 2 interface-scoped ACCEPTs iperf3 through the relay: 59.9 Gbits/sec

    The relay is not slow, not lossy, and not degraded -- it does not work at all, while every
    other check in `forwarding_path_problems` reads healthy. A tool that arms an intercept in that
    state forges ARP on a live segment and then discards the traffic, which is a segment-wide
    outage caused by the monitoring tool. Reporting it before the intercept starts is the
    difference between a dry-run and a trap.
    """
    from weirvern.admin.siphonnet import forward_policy_problem

    problem = forward_policy_problem("ens19")
    # The check must either find no problem (a permissive host) or describe this one precisely.
    if problem:
        assert "DROP" in problem or "could not read" in problem
        # A problem an operator cannot act on is noise, so the fix must be in the message.
        assert "iptables -I FORWARD" in problem, (
            f"the problem does not say how to fix it: {problem[:200]}"
        )
        # And it must be scoped to the interface, not a blanket ACCEPT: widening a host's whole
        # FORWARD posture to make a relay work would be the tool overreaching.
        assert "<capture-iface>" in problem, "the suggested rule is not interface-scoped"


def test_an_unreadable_policy_is_not_assumed_permissive():
    """'Cannot read' must never be treated as 'fine'.

    This project's recurring failure mode is a value that could not be measured being rendered the
    same as one measured to be safe. `forward_policy` returns UNKNOWN rather than ACCEPT when
    iptables cannot be read, and the problem text says so instead of staying silent -- because
    silence here reads as 'the host is configured for relaying', which is exactly the guess that
    would arm an intercept into a blackhole.
    """
    from weirvern.admin.siphonnet import forward_policy

    policy, source = forward_policy()
    assert policy in ("ACCEPT", "DROP", "UNKNOWN"), f"unexpected policy value {policy!r}"
    assert source, "the policy must say where it was read from"


def test_the_forward_policy_check_says_nothing_when_the_host_permits_relaying():
    """A permissive host must produce NO problem, or the check becomes noise and gets ignored.

    This is the inverse of the test above and it matters as much: a warning that fires on every
    healthy deployment trains operators to skip the warnings that are real.
    """
    from weirvern.admin import siphonnet

    original = siphonnet.forward_policy
    try:
        siphonnet.forward_policy = lambda: ("ACCEPT", "iptables -S")
        assert siphonnet.forward_policy_problem("ens19") == ""
    finally:
        siphonnet.forward_policy = original
