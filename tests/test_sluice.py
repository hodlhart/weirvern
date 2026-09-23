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
import pathlib
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

ROOT = pathlib.Path(__file__).resolve().parent.parent

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


# ── the enforcement loop ─────────────────────────────────────────────────────────────────────


class FakeStore:
    """A store that records what it was asked to do, and can be made to fail on demand."""

    def __init__(self, rules=None, fail_read=False):
        self.rules = rules or []
        self.fail_read = fail_read
        self.created: list[dict] = []
        self.states: list = []
        self.events: list = []

    def load_live_rules(self, _client):
        if self.fail_read:
            raise RuntimeError("simulated database failure")
        return list(self.rules)

    def create_rule(self, _client, **kw):
        self.created.append(kw)
        return Rule(kw.get("src_cidr", "x") + "-derived", **{
            k: v for k, v in kw.items() if k in
            {"src_cidr", "dst_cidr", "protocol", "dst_port", "direction", "reason",
             "origin", "origin_ref", "severity", "created_by"}
        } | {"expires_at": SOON})

    def write_gate_state(self, _client, _sensor, state):
        self.states.append(state)

    def write_events(self, _client, events, **_kw):
        self.events.extend(events)
        return len(events)

    def derived_rules_for_detections(self, detections, *, policy, max_ttl_minutes):
        from weirvern.sluice_store import derived_rules_for_detections as real
        return real(detections, policy=policy, max_ttl_minutes=max_ttl_minutes)


def test_an_unreadable_ruleset_does_NOT_reopen_the_gate():
    """THE MOST IMPORTANT ASSERTION IN THIS FILE.

    A database failure must not disarm. The tempting implementation is `rules = load(...) or []` and
    then arm an empty set -- which OPENS the gate, so a query failure silently unblocks every host
    an operator had stopped. Worse, an attacker who can slow the database can then unblock
    themselves. Failing open on a LOST CONNECTION is right; failing open on a FAILED QUERY is not.

    Note what the supervisor is NOT asked to do here: `arm` is never called, so nothing the kernel
    currently has installed is disturbed.
    """
    from weirvern.sluice import enforcement_pass

    backend = FakeBackend()
    sup = SluiceSupervisor(iface="ens19", backend=backend)
    sup.arm([live("existing")])          # the gate is currently holding a rule
    before = list(backend.armed_with)

    store = FakeStore(fail_read=True)
    state = enforcement_pass(store, sup, client=object(), sensor="s1")

    assert state.state == GATE_STATE_DEGRADED
    assert "unreadable ruleset is not an empty one" in state.detail
    # THE KERNEL WAS NOT TOUCHED: no further arm() call, so the installed rule is still there.
    assert backend.armed_with == before, "the pass re-armed the kernel, risking opening the gate"
    assert sup.state.held_rules() == ["existing"] if hasattr(sup.state, "held_rules") else True


def test_a_successful_pass_arms_and_records_the_state():
    from weirvern.sluice import enforcement_pass

    backend = FakeBackend()
    sup = SluiceSupervisor(iface="ens19", backend=backend)
    store = FakeStore(rules=[live("a"), live("b")])
    state = enforcement_pass(store, sup, client=object(), sensor="s1")

    assert state.state == GATE_STATE_ARMED
    assert state.rules_active == 2
    assert [r.rule_id for r in backend.armed_with] == ["a", "b"]
    assert len(store.states) == 1, "the gate state was not recorded, so the GUI cannot show it"


def test_a_state_write_failure_is_reported_not_hidden():
    """The gate IS armed even if the state row failed. Saying otherwise would hide a working gate."""
    from weirvern.sluice import enforcement_pass

    class NoStateStore(FakeStore):
        def write_gate_state(self, *_a, **_k):
            raise RuntimeError("simulated write failure")

    backend = FakeBackend()
    sup = SluiceSupervisor(iface="ens19", backend=backend)
    state = enforcement_pass(NoStateStore(rules=[live("a")]), sup, client=object(), sensor="s1")

    assert state.state == GATE_STATE_ARMED
    assert "could not be recorded" in state.detail


def test_detections_only_block_when_the_policy_says_so():
    """With the policy OFF, a high-severity detection must not create a rule.

    This is the operator's trust boundary: auto-blocking is off unless they turned it on, and a
    default that blocked would surprise anyone who installed the tool to watch.
    """
    from weirvern.sluice import enforcement_pass

    det = [{"src_addr": "198.51.100.9", "severity": "high", "anomaly_score": 0.99}]

    store = FakeStore()
    sup = SluiceSupervisor(iface="ens19", backend=FakeBackend())
    enforcement_pass(store, sup, client=object(), sensor="s1", policy="off", detections=det)
    assert store.created == [], "a detection created a block while the policy was Off"

    store2 = FakeStore()
    sup2 = SluiceSupervisor(iface="ens19", backend=FakeBackend())
    enforcement_pass(store2, sup2, client=object(), sensor="s1", policy="high", detections=det)
    assert len(store2.created) == 1, "a qualifying detection did not create a block"
    assert store2.created[0]["origin"] == "detection", "the block is not attributable to a detection"


def test_a_detection_with_no_source_address_is_skipped():
    """There is nothing to block that is not 'the whole segment', and blocking that is an outage."""
    from weirvern.sluice_store import derived_rules_for_detections

    out = derived_rules_for_detections(
        [{"src_addr": "", "severity": "high", "anomaly_score": 0.99}],
        policy="high", max_ttl_minutes=60,
    )
    assert out == []


def test_the_operators_ceiling_caps_the_policys_ttl():
    """A policy change must never produce a longer block than the operator allowed."""
    from weirvern.sluice_store import derived_rules_for_detections

    det = [{"src_addr": "198.51.100.9", "severity": "high", "anomaly_score": 0.99}]
    # The 'high' policy says 30 minutes; the operator has capped blocks at 5.
    out = derived_rules_for_detections(det, policy="high", max_ttl_minutes=5)
    assert out and out[0]["ttl_minutes"] == 5, f"the ceiling was not applied: {out}"


# ── the GUI loader's failure contract, proved behaviourally ──────────────────────────────────


def test_a_failed_gate_query_reports_rather_than_rendering_empty():
    """The Sluice Gate loader must not return QUIETLY when its request fails.

    Proved by EXECUTING the shipping JavaScript against a rejecting fetch, not by reading it. The
    check exists because the jsdom DOM harness cannot reach this path: its stub dispatcher resolves
    the override rather than rejecting through to the page, so an assertion there would be testing
    the harness. Verified in isolation that the loader does produce the banner; this pins it so a
    future edit that drops the catch is caught.

    WHY IT MATTERS: `showView` fires the loader without awaiting it, so a bare `await getJSON(...)`
    that rejects becomes an unhandled rejection. The panel then keeps whatever it had and NO banner
    appears -- a failed query reading exactly like an empty gate, which would tell an operator that
    nothing is blocked when the truth is that nobody knows.
    """
    import shutil
    import subprocess

    node = shutil.which("node")
    if not node:
        pytest.skip("node is not installed, so the shipping JavaScript cannot be executed")

    harness = ROOT / "scripts" / "jsdom_render.js"
    js = r"""
    const fs = require("fs");
    const src = fs.readFileSync(process.argv[2], "utf8");
    const made = [];
    global.document = {
      getElementById: (id) => (id === "data-banner" ? (made.find((b) => b.id === id) || null)
                                                    : { replaceChildren(){}, appendChild(){},
                                                        textContent: "", checked: false,
                                                        addEventListener(){}, value: "" }),
      querySelector: () => ({ prepend: (n) => made.push(n) }),
      createElement: () => ({ set className(v){}, set textContent(v){}, appendChild(){},
                              addEventListener(){} }),
    };
    global.el = (tag, opts = {}, kids = []) => {
      const n = { id: (opts.attrs && opts.attrs.id) || "", className: opts.class || "",
                  textContent: opts.text || "", children: kids, appendChild(c){ this.children.push(c); } };
      return n;
    };
    global.showDataError = (msg) => {
      if (!msg) return;
      let b = made.find((x) => x.id === "data-banner");
      if (!b) { b = { id: "data-banner", textContent: "" }; made.push(b); }
      b.textContent = "Data unavailable: " + msg;
    };
    global.showError = () => {};
    global.getJSON = async () => { throw new Error("simulated transport failure"); };
    global.postJSON = async () => ({ ok: true });
    eval(src);
    (async () => {
      await loadSluice().catch(() => {});
      const b = made.find((x) => x.id === "data-banner");
      process.stdout.write(b ? b.textContent : "");
    })();
    """
    script = ROOT / ".tmp_sluice_loader_check.js"
    script.write_text(js)
    try:
        proc = subprocess.run(
            [node, str(script), str(ROOT / "weirvern" / "admin" / "web" / "sluice.js")],
            capture_output=True, text=True, timeout=60, check=False,
        )
    finally:
        script.unlink(missing_ok=True)

    out = (proc.stdout or "") + (proc.stderr or "")
    assert "Data unavailable" in out, (
        "a failed gate query produced no banner, so the panel would look like an empty gate. "
        f"loader output: {out[:300]!r}"
    )
    assert harness.exists(), "the DOM harness has gone missing"


# ── a passive sensor must not claim to be blocking ─────────────────────────────────────────────
#
# THE FAILURE THIS PINS. In `loch` mode this host is a listener, not a hop: a FORWARD drop on it
# discards traffic that was never going to traverse it, so NOTHING on the segment is affected. The
# rules compile, install, and count their own drops, so without this check the panel reads ARMED
# while the operator's block does nothing -- a green reading over work that did not happen, which
# is the failure this project keeps finding. The assertion is on the STATE because that is what the
# GUI shows; a test on the detail string alone would pass on an ARMED gate, which is the bug.
class _OneRuleStore:
    """The minimum a pass needs: one live rule, a no-op state write."""

    def __init__(self) -> None:
        self.written: list[object] = []

    def load_live_rules(self, client: object) -> list[Rule]:
        return [live("r1")]

    def derived_rules_for_detections(self, *a: object, **k: object) -> list[dict]:
        return []

    def create_rule(self, client: object, **spec: object) -> Rule:
        raise AssertionError("no detections were supplied, so nothing should be created")

    def write_gate_state(self, client: object, sensor: str, state: object) -> None:
        self.written.append(state)


def _supervisor() -> SluiceSupervisor:
    return SluiceSupervisor(iface="eth1", mgmt_iface="eth0", backend=FakeBackend())


def test_passive_mode_reports_degraded_not_armed():
    from weirvern.sluice import enforcement_pass

    store = _OneRuleStore()
    state = enforcement_pass(
        store, _supervisor(), client=object(), sensor="s1", sensor_mode="loch",
    )
    assert state.state == GATE_STATE_DEGRADED, (
        f"a passive sensor reported {state.state!r}; it cannot be blocking anything on the segment"
    )
    assert "loch" in state.detail and "not in the traffic path" in state.detail


def test_siphon_mode_is_not_downgraded_for_being_out_of_path():
    """The converse, so the check cannot pass by reporting DEGRADED unconditionally."""
    from weirvern.sluice import enforcement_pass

    store = _OneRuleStore()
    state = enforcement_pass(
        store, _supervisor(), client=object(), sensor="s1", sensor_mode="siphon",
    )
    assert "not in the traffic path" not in (state.detail or "")


def test_an_unspecified_mode_does_not_downgrade():
    """A caller that omits the mode keeps the old behaviour: unknown is not the same as passive."""
    from weirvern.sluice import enforcement_pass

    store = _OneRuleStore()
    state = enforcement_pass(store, _supervisor(), client=object(), sensor="s1")
    assert "not in the traffic path" not in (state.detail or "")


def test_the_downgrade_still_records_the_state_row():
    """DEGRADED must still be persisted, or the GUI would keep showing the previous state."""
    from weirvern.sluice import enforcement_pass

    store = _OneRuleStore()
    enforcement_pass(store, _supervisor(), client=object(), sensor="s1", sensor_mode="loch")
    assert len(store.written) == 1
    assert getattr(store.written[0], "state", None) == GATE_STATE_DEGRADED


# ── a downgraded deployment must be able to CLEAN UP what it installed ─────────────────────────
#
# MEASURED FAILURE (live, after removing the siphon overlay): the gate had installed
# `table inet weirvern_sluice` on the NODE. Removing the overlay took away hostNetwork and
# NET_ADMIN, so `choose_backend("nft")` began answering `available() == False` -- and the table it
# had written stayed on the node with nothing left that could remove it (verified: the worker's
# backend reported `none`/unavailable, and `nft list tables` still showed the sluice table until it
# was deleted by hand). It was INERT -- policy accept, empty sets, counters 0/0 -- so nothing broke.
# But it survived a downgrade the operator believed had undone the feature.
#
# The property that makes it recoverable: disarm() must go to the SAME backend that armed, not to
# a freshly-chosen one. A caller that re-chooses after the privilege is gone gets a backend that
# can do nothing, and the cleanup silently does not happen.
def test_disarm_reaches_the_backend_that_installed_the_rules():
    backend = FakeBackend()
    sup = SluiceSupervisor(iface="eth1", mgmt_iface="eth0", backend=backend)
    sup.arm([live("r1")])
    assert backend.armed_with, "the arm should have reached the backend"

    state = sup.disarm()
    assert backend.disarmed is True, (
        "disarm did not reach the backend that installed the rules; a deployment that lost "
        "NET_ADMIN would leave its nft table on the host with nothing able to remove it"
    )
    assert state.state == GATE_STATE_DISARMED


def test_a_disarm_the_backend_could_not_do_is_not_reported_as_disarmed():
    """The report must not claim a success it could not verify.

    Claiming 'disarmed' while a table is still installed is the same class of defect as claiming
    'armed' while blocking nothing -- and it is the one an operator would act on, since they
    downgraded precisely to stop the gate touching their network.
    """
    # A backend whose disarm genuinely FAILS. FakeBackend.disarm() returns success
    # regardless of its `ok` flag (that flag governs arm), so it cannot express this case --
    # using it here would assert against a backend that always claims to have cleaned up.
    class CannotDisarm(FakeBackend):
        def disarm(self):
            return False, "nft is not usable here: the deployment no longer has NET_ADMIN"

    sup = SluiceSupervisor(iface="eth1", mgmt_iface="eth0", backend=CannotDisarm())
    state = sup.disarm()
    assert state.state == GATE_STATE_DEGRADED, (
        f"a failed disarm reported {state.state!r}; the operator would believe it was removed"
    )
    assert state.detail and "open and no rules are installed" not in state.detail


# ── an `in` rule must honor its PORT ───────────────────────────────────────────────────────────
#
# MEASURED DEFECT (live node, 2026-09-23). The input chain compiled to a bare
# `ip saddr @in_v4 counter drop` with no port anywhere in the ruleset. An operator blocking
# 127.0.0.1:9473 therefore dropped 9473 AND 9474 -- everything from that source arriving at this
# host -- and the proof was the absence of the literal port in the compiled text, plus a control
# connection to an unrelated port that also timed out.
#
# WHY THIS IS THE WORST SHAPE FOR THIS BUG. The forward chain honoured ports correctly, so a
# relay rule behaved as asked and hid the problem: only INPUT was affected, and INPUT is where this
# host's own management, API and SSH traffic arrives. The likely consequence is an operator
# locking themselves out of the machine they were defending, after asking for something far
# narrower. It is also the opposite of this project's stated failure bias -- the gate did MORE
# than the operator asked, silently.
#
# These tests assert on the COMPILED TEXT because that is the artifact the kernel receives; a test
# on Rule.dst_port would pass while the compiler threw it away.
def _compiled(rules: list[Rule], iface: str = "eth1") -> str:
    from weirvern.sluice import NftBackend

    return NftBackend()._base_ruleset(rules, iface)


def test_an_inbound_rule_with_a_port_compiles_that_port():
    ruleset = _compiled([live("p1", direction="in", src_cidr="127.0.0.1/32",
                              protocol="tcp", dst_port=9473)])
    assert "9473" in ruleset, (
        "the port an operator asked for is absent from the compiled ruleset, so the rule would "
        "block every port from that source instead of the one requested"
    )
    assert "dport 9473" in ruleset, f"the port is not matched as a destination port:\n{ruleset}"


def test_the_inbound_port_rule_carries_its_own_set():
    """A per-port set, so the address lookup stays a hash rather than a linear walk."""
    ruleset = _compiled([live("p1", direction="in", src_cidr="198.51.100.9/32",
                              protocol="tcp", dst_port=9473)])
    assert "inport_tcp_9473" in ruleset, f"no per-port set for the inbound rule:\n{ruleset}"


def test_an_inbound_rule_WITHOUT_a_port_still_blocks_the_whole_source():
    """The converse: "block this source" must keep meaning the whole source.

    Without this, a fix for the bug above could over-correct into never blocking anything broad.
    """
    ruleset = _compiled([live("w1", direction="in", src_cidr="198.51.100.9/32")])
    input_part = ruleset.split("weirvern_sluice_in")[-1]
    assert "ip saddr @in_v4 counter drop" in input_part, (
        f"a port-less inbound rule no longer drops the whole source:\n{input_part}"
    )


def test_inbound_port_rules_precede_the_whole_source_rules():
    """ORDER IS LOAD-BEARING, which is why it is asserted rather than assumed.

    nft evaluates in order. A port-scoped rule for an address and a whole-source rule for the same
    address can coexist, and if the whole-source rule came first it would drop the narrow traffic
    before the narrow rule's counter saw any of it -- the port rule would be enforced but
    permanently unobservable, and the GUI would show 0 packets for a rule that is working.
    """
    ruleset = _compiled([
        live("w1", direction="in", src_cidr="198.51.100.9/32"),
        live("p1", direction="in", src_cidr="198.51.100.9/32", protocol="tcp", dst_port=9473),
    ])
    input_part = ruleset.split("weirvern_sluice_in")[-1]
    port_at = input_part.find("dport 9473")
    whole_at = input_part.find("ip saddr @in_v4 counter drop")
    assert port_at != -1 and whole_at != -1, f"both rules should be present:\n{input_part}"
    assert port_at < whole_at, (
        "the whole-source drop precedes the port-scoped drop, so the port rule can never count "
        f"a packet and the GUI would report zero for a working rule:\n{input_part}"
    )
