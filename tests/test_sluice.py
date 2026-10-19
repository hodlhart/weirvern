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
    NFT_TABLE,
    NFT_TABLE_IN,
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


# ── the bound, and the one case where it is deliberately absent ───────────────────────────────


def test_a_rule_with_no_expiry_is_live_until_it_is_revoked():
    """A duration of 0 means UNTIL REVOKED, and that is now the INTENDED state.

    This assertion was `is False` until 2026-10-16: 011 made `expires_at` NOT NULL and this side
    refused to enforce a rule with no bound, on the reasoning that an unbounded rule outlives the
    person who wrote it and refusing to enforce is the safe direction. The operator asked for the
    capability explicitly, so the direction reverses -- and the check stays, in the other
    direction: a null expiry must be LIVE, because a bare `expires_at > now()` evaluates to NULL
    for these rows and would drop every indefinite rule out of enforcement without a word.
    """
    assert Rule("x", src_cidr="192.0.2.9/32", expires_at=None).is_live() is True
    # Revocation is the only stop, and it does stop it.
    assert Rule("y", src_cidr="192.0.2.9/32", expires_at=None,
                revoked_at=datetime.now(UTC)).is_live() is False


def test_zero_ttl_records_an_unbounded_rule_and_a_negative_one_is_refused():
    """0 -> NULL -> until revoked; -5 is a typo and is refused. The refusal names the fix, because
    "must be positive" was true when every block was bounded and is not any more."""
    import pytest

    from weirvern.sluice import SluiceError
    from weirvern.sluice_store import create_rule

    class _Rec:
        def __init__(self):
            self.inserts = []

        def insert(self, table, rows, column_names=None):
            self.inserts.append((table, rows, column_names))

    client = _Rec()
    rule = create_rule(client, src_cidr="198.51.100.7", ttl_minutes=0)
    assert rule.expires_at is None, "a zero ttl produced an expiry"
    assert client.inserts, "nothing was written"
    # BY NAME, not by index: the insert grew domain/mode columns (schema/017) and a positional
    # assertion broke for the wrong reason -- the intent is "the stored row carries NULL".
    columns = client.inserts[0][2]
    assert client.inserts[0][1][0][columns.index("expires_at")] is None, (
        "the stored row carries a date, not NULL")

    bounded = create_rule(client, src_cidr="198.51.100.8", ttl_minutes=15)
    assert bounded.expires_at is not None

    with pytest.raises(SluiceError) as excinfo:
        create_rule(client, src_cidr="198.51.100.9", ttl_minutes=-5)
    assert "0 means until revoked" in str(excinfo.value)


def test_the_live_rule_query_treats_a_null_expiry_as_live():
    """The SQL filter is the OTHER place a null expiry silently drops a rule out of enforcement.
    The Python check alone would not save it: the query never returns the row in the first place,
    so the rule is absent rather than inert, and the rules list would show it as live while
    nothing enforced it."""
    from weirvern.sluice_store import LIVE_RULE_SQL

    assert "expires_at IS NULL OR expires_at > now()" in LIVE_RULE_SQL


def test_a_derived_block_never_has_an_empty_reason():
    """A reason is OPTIONAL for an operator and mandatory for the machine. A derived block is the
    one nobody was watching, so it is the one that must explain itself; both the policy path and
    the threshold path fill the field."""
    from weirvern.sluice_store import derived_rules_for_detections

    detections = [{"src_addr": "198.51.100.9", "severity": "low", "anomaly_score": 0.95},
                  {"src_addr": "198.51.100.10", "severity": "high", "anomaly_score": 0.90}]
    out = derived_rules_for_detections(detections, policy="high", max_ttl_minutes=60,
                                       auto_score=0.9)
    assert out and all(r["reason"].strip() for r in out), out


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


def test_a_rule_with_both_a_source_and_a_destination_is_refused():
    """Both fields used to compile as "everything from the source" while describes() and the
    dry-run described the narrower rule -- an over-block, and the GUI offers both fields, so it
    is the shape an operator reaches for."""
    why = _refuse(src_cidr="198.51.100.7/32", dst_cidr="203.0.113.9/32")
    assert "not both" in why
    # The destination-only rule this is confused with is still accepted.
    assert _refuse(src_cidr="", dst_cidr="203.0.113.9/32") == ""


def test_a_destination_only_inbound_rule_is_refused():
    """It would compile to nothing -- the input chain splits by source -- while still reading
    as enforced: the "green reading over work that did not happen" shape, inside the gate."""
    why = _refuse(src_cidr="", dst_cidr="203.0.113.9/32", direction="in")
    assert "source" in why


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


def test_the_compiler_refuses_a_rule_it_cannot_express_instead_of_widening_it():
    """The second belt: even a hand-written row must never compile into a wider block (or into
    nothing) -- it fails the arm instead, which is reported."""
    backend = NftBackend()
    with pytest.raises(SluiceError):
        backend._base_ruleset(
            [live("both", src_cidr="198.51.100.7/32", dst_cidr="203.0.113.9/32")], "ens19")
    with pytest.raises(SluiceError):
        backend._base_ruleset(
            [live("in-dst", dst_cidr="203.0.113.9/32", direction="in")], "ens19")


def test_arm_reports_a_refused_ruleset_rather_than_claiming_armed():
    def runner(args, **kw):
        return (True, "")
    ok, detail = NftBackend(runner=runner).arm(
        [live("both", src_cidr="198.51.100.7/32", dst_cidr="203.0.113.9/32")], iface="ens19")
    assert ok is False
    assert "refused" in detail


def test_every_predicate_of_a_valid_rule_appears_in_the_compiled_text():
    """The property behind the whole class: for every rule shape the gate ACCEPTS, each of its
    predicates must appear in the compiled text. A rule that compiles without one of its
    predicates is over- or under-blocking, and both are silent."""
    rules = [
        live("src", src_cidr="198.51.100.7/32"),
        live("dst", dst_cidr="203.0.113.9/32"),
        live("srcport", src_cidr="198.51.100.8/32", protocol="tcp", dst_port=8443),
        live("in", src_cidr="198.51.100.9/32", direction="in"),
        live("inport", src_cidr="198.51.100.10/32", direction="in", protocol="udp",
             dst_port=5353),
    ]
    text = NftBackend()._base_ruleset(rules, "ens19")
    for fragment, what in (
        ("198.51.100.7/32", "a source"),
        ("203.0.113.9/32", "a destination"),
        ("198.51.100.8/32", "a port-scoped source"),
        ("8443", "its port"),
        ("198.51.100.9/32", "an inbound source"),
        ("198.51.100.10/32", "an inbound port-scoped source"),
        ("5353", "its inbound port"),
    ):
        assert fragment in text, f"{what} ({fragment}) is missing from the compiled text"


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

    def derived_rules_for_detections(self, detections, *, policy, max_ttl_minutes,
                                      auto_score=0.0):
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


# ── the operator's own threshold (SLUICE_AUTO_SCORE) ─────────────────────────────────────────


def test_the_operators_threshold_blocks_without_any_policy():
    """TWO WAYS IN. With the severity policy OFF -- which alone blocks nothing -- a detection at
    or above the operator's threshold still yields a rule, and one below it still yields nothing.
    The reason string names the threshold, because the question asked about a block three weeks
    later is always "why is this blocked"."""
    from weirvern.sluice_store import derived_rules_for_detections

    strong = [{"src_addr": "198.51.100.9", "severity": "medium", "anomaly_score": 0.95}]
    out = derived_rules_for_detections(strong, policy="off", max_ttl_minutes=60, auto_score=0.9)
    assert len(out) == 1, "a detection above the operator's threshold was not blocked"
    assert "auto-block threshold 0.90" in out[0]["reason"]
    assert out[0]["src_cidr"] == "198.51.100.9/32"
    # The score-triggered default TTL is 30 minutes, under the operator's 60-minute ceiling.
    assert out[0]["ttl_minutes"] == 30

    weak = [{"src_addr": "198.51.100.9", "severity": "high", "anomaly_score": 0.40}]
    assert derived_rules_for_detections(weak, policy="off", max_ttl_minutes=60,
                                         auto_score=0.9) == []

    # With the threshold off, policy=off still blocks nothing -- the default is unchanged.
    assert derived_rules_for_detections(strong, policy="off", max_ttl_minutes=60) == []


def test_the_two_instruments_are_independent():
    """A low-severity detection the policy refuses is blocked by the threshold; a high-severity
    one below the threshold is blocked by the policy; one clearing neither is not blocked."""
    from weirvern.sluice_store import derived_rules_for_detections

    by_policy = [{"src_addr": "198.51.100.1", "severity": "high", "anomaly_score": 0.90}]
    out = derived_rules_for_detections(by_policy, policy="high", max_ttl_minutes=60, auto_score=0.99)
    assert len(out) == 1 and "auto-block threshold" not in out[0]["reason"]

    by_score = [{"src_addr": "198.51.100.2", "severity": "low", "anomaly_score": 0.95}]
    out = derived_rules_for_detections(by_score, policy="high", max_ttl_minutes=60, auto_score=0.9)
    assert len(out) == 1 and "auto-block threshold 0.90" in out[0]["reason"]

    neither = [{"src_addr": "198.51.100.3", "severity": "low", "anomaly_score": 0.50}]
    assert derived_rules_for_detections(neither, policy="high", max_ttl_minutes=60,
                                         auto_score=0.9) == []


def test_a_score_triggered_block_respects_the_operators_ceiling():
    """The new path is capped by the SAME ceiling as the policy path, and an empty source is
    skipped exactly as before."""
    from weirvern.sluice_store import derived_rules_for_detections

    det = [{"src_addr": "198.51.100.9", "severity": "low", "anomaly_score": 0.99}]
    out = derived_rules_for_detections(det, policy="off", max_ttl_minutes=5, auto_score=0.9)
    assert out and out[0]["ttl_minutes"] == 5
    assert derived_rules_for_detections([{"src_addr": "", "anomaly_score": 1.0}], policy="off",
                                         max_ttl_minutes=60, auto_score=0.9) == []


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
      // The shipping file wires controls at the top level (the blocklist panel, 2026-10-16); a
      // real DOM always has this, so the mock must too -- the previous mock predated top-level
      // wiring and the loader check failed on the MOCK's gap, not on the file.
      addEventListener() {},
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
    """The converse, so the check cannot pass by reporting DEGRADED unconditionally.

    UPDATED 2026-10-15 (the channel round): "siphon is not downgraded" now means VERIFIED
    siphon -- live intercept evidence (`siphon_live=True`, the same fact `status.siphon_liveness`
    reports to the CLI). The unverified cases are their own tests in tests/test_channel.py: a
    CONFIGURED siphon with no live intercept is not in the traffic path, and the gate says so.
    """
    from weirvern.sluice import enforcement_pass

    store = _OneRuleStore()
    state = enforcement_pass(
        store, _supervisor(), client=object(), sensor="s1", sensor_mode="siphon",
        siphon_live=True,
    )
    assert "not in the traffic path" not in (state.detail or "")
    assert state.state == GATE_STATE_ARMED


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


# ── a STALE state row must not read as a current one ───────────────────────────────────────────
#
# MEASURED (live, 2026-09-23). Two test harnesses wrote an 'armed' row, exited, and left it. The
# GUI then showed ARMED with 1 rule enforced while the node had ZERO sluice tables -- nothing was
# blocked. Every reading on the panel was a historical fact presented as current, including the
# drop counters, and an operator has no way to tell from the panel.
#
# The store already refuses to report ARMED alongside a backend mismatch, for the same reason. A
# row's own timestamp is the extra evidence available, so it is used: the gate writes a row every
# minute, and a row several minutes old means the writer has stopped.
class _Result:
    def __init__(self, rows) -> None:
        self.result_rows = rows


class _GateStore:
    """A store whose query returns a prepared row, so staleness can be driven directly.

    The column order must match the SELECT in load_gate_state exactly, including the two backend
    columns and the enforcement path -- a fake that ignores the column list is how this project
    once produced a test that passed against a payload the server could never emit.
    """

    def __init__(self, updated_at, state: str = "armed") -> None:
        self._row = ("sensor1", updated_at, state, "eth1", "eth0", 1, 1,
                     5, 500, "detail text", "nft", "nft", "channel")

    def query(self, sql, *a, **k):  # noqa: ANN001, ANN002, ANN003
        return _Result([self._row])


def _load_gate_state(updated_at, state: str = "armed") -> dict:
    from weirvern.sluice_store import load_gate_state

    return load_gate_state(_GateStore(updated_at, state))


def test_a_fresh_state_row_is_not_flagged_stale():
    from datetime import UTC, datetime

    out = _load_gate_state(datetime.now(UTC))
    assert "stale" not in out, f"a fresh row was flagged stale: {out.get('warning')}"
    assert out["age_s"] < 5


def test_an_old_state_row_is_flagged_stale_and_explained():
    from datetime import UTC, datetime, timedelta

    out = _load_gate_state(datetime.now(UTC) - timedelta(minutes=20))
    assert out.get("stale") is True, "a 20-minute-old 'armed' row was reported as current"
    assert out["age_s"] >= 1200
    assert "HISTORICAL" in out["warning"], f"the warning does not say what to do: {out['warning']}"


def test_a_naive_timestamp_is_read_as_UTC_rather_than_giving_up():
    """ClickHouse returns aware datetimes; a naive one must still yield an AGE.

    THE FIRST VERSION OF THIS TEST WAS WORTHLESS, and mutation testing is what showed it: it
    asserted only `available is True`, which holds whether the timestamp was normalised OR the
    subtraction blew up and the except swallowed it. Both paths leave the read "successful", so the
    test could not tell a working staleness check from a missing one.

    What actually matters is that the row still gets an age. A naive timestamp that is silently
    treated as unreadable means the staleness warning never fires for that row -- the gate could be
    dead for a day and the panel would show a fresh ARMED.
    """
    from datetime import UTC, datetime

    # Naive, but representing UTC -- which is what the conversion assumes.
    naive_utc = datetime.now(UTC).replace(tzinfo=None)
    out = _load_gate_state(naive_utc)
    assert out["available"] is True, f"the read failed outright: {out.get('reason')}"
    assert out.get("age_s") is not None, (
        "a naive timestamp produced no age, so no staleness warning can ever fire for this row"
    )
    assert out["age_s"] < 60, f"a just-written naive row read as {out['age_s']}s old"


def test_a_timestamp_that_cannot_be_subtracted_is_treated_as_unknown():
    """The `except` branch is reachable, which mutation testing proved it was not before.

    A datetime whose tzinfo raises is the case: `isinstance(written, datetime)` is True, so the
    conversion is attempted, and the subtraction itself fails. That is the only way into the
    handler -- the previous test passed a STRING, which fails the isinstance check and never
    reaches it at all, so the branch was dead code as far as the suite was concerned.
    """
    from datetime import datetime, tzinfo

    class Hostile(tzinfo):
        def utcoffset(self, dt):  # noqa: ANN001, ANN201
            raise ValueError("this timezone cannot be resolved")

        def dst(self, dt):  # noqa: ANN001, ANN201
            return None

        def tzname(self, dt):  # noqa: ANN001, ANN201
            return "hostile"

    out = _load_gate_state(datetime(2026, 9, 22, 21, 0, 0, tzinfo=Hostile()))
    assert out["available"] is True, f"the read failed: {out.get('reason')}"
    assert "stale" not in out, "an unreadable timestamp was reported as a stale gate"
    assert "age_s" not in out, (
        "an age was reported for a timestamp that could not be read, so the number is invented"
    )


def test_an_unreadable_timestamp_is_not_evidence_of_staleness():
    """Cannot-measure is not the same as measured-stale.

    Reporting "stale" because a timestamp could not be read would be a conclusion drawn from the
    instrument failing -- the failure mode the stress harness had to fix three times.
    """
    out = _load_gate_state("not a datetime")
    assert "stale" not in out, "an unreadable timestamp was reported as a stale gate"


# ── the sensor identity must be STABLE and MUST MATCH between writer and reader ────────────────
#
# MEASURED IN CLUSTER (2026-09-23), and this is the defect that made the previous fix wrong.
# `socket.gethostname()` inside a pod returns the POD NAME. The worker wrote gate state under
# `weirvern-worker-84899c6f55-9z7g2` while the GUI computed `weirvern-gui-79c77d8667-b7c7q` for
# itself. So:
#
#   * a panel filtering to its own sensor finds NOTHING and reports "the gate has not run yet" on a
#     gate that is running correctly -- the fix for one silent failure would have created another;
#   * the name carries the ReplicaSet hash, so it CHANGES ON EVERY RESTART and rows accumulate
#     under throwaway identities. No query can follow one gate across a rollout, which is exactly
#     when an operator looks.
#
# The order tested here is the contract: an explicit name wins, then the node (stable, identical in
# every pod on that node), then the hostname for a non-cluster run.
def _name_with(node_name: str | None = "UNSET"):  # noqa: ANN001
    """Resolve the sensor name under a controlled NODE_NAME.

    `None` means UNSET (delete it), which is the non-cluster case. A sentinel default of "UNSET"
    is needed because `None` is meaningful here -- the first version of this helper passed None to
    os.environ.update and raised TypeError instead of testing the fallback.
    """
    import os
    from types import SimpleNamespace

    from weirvern.worker import _sensor_name

    saved = os.environ.get("NODE_NAME")
    try:
        if node_name == "UNSET":
            pass  # leave the environment as it is
        elif node_name is None:
            os.environ.pop("NODE_NAME", None)
        else:
            os.environ["NODE_NAME"] = node_name
        return _sensor_name(SimpleNamespace())
    finally:
        if saved is None:
            os.environ.pop("NODE_NAME", None)
        else:
            os.environ["NODE_NAME"] = saved


def test_the_node_name_wins_over_the_naive_hostname():
    """In cluster, NODE_NAME must be used -- the pod name is neither stable nor shared."""
    got = _name_with("sensor-node-a")
    assert got == "sensor-node-a", (
        f"resolved to {got!r}; a pod hostname would change on every restart and could never "
        "match what another pod on the same node writes"
    )


def test_an_explicit_name_beats_the_node():
    """A deployment that names itself keeps that name. This is the weirlings hook."""
    from types import SimpleNamespace

    from weirvern.worker import _sensor_name

    assert _sensor_name(SimpleNamespace(sensor_name="edge-01")) == "edge-01"


def test_the_hostname_is_the_fallback_when_there_is_no_cluster():
    """A bare CLI or test run has no NODE_NAME, and the hostname IS the box there."""
    import os
    import socket

    got = _name_with(None)
    assert got == socket.gethostname(), (
        f"resolved to {got!r}; a non-cluster run should fall back to the hostname"
    )
    assert not os.environ.get("NODE_NAME")


def test_an_empty_node_name_falls_through_rather_than_producing_a_blank_sensor():
    """An empty sensor name cannot be attributed to a box, which is worse than no row.

    An empty string is falsy, so it must fall through to the hostname. A gate whose rows carry an
    empty sensor is one no query can attribute to a machine -- and once there is more than one
    sensor that is worse than having no row at all.
    """
    import socket

    got = _name_with("")
    assert got != "", "an empty NODE_NAME produced an empty sensor name"
    assert got == socket.gethostname(), f"resolved to {got!r} instead of falling through"


def test_the_gui_and_the_worker_agree_on_the_identity():
    """THE ACTUAL INVARIANT. A reader that computes a different name than the writer finds nothing.

    This is what failed live, so it is asserted directly rather than left implied by the two
    components' own tests passing.
    """
    import os

    from weirvern.admin.web import _gate_sensor_name
    from weirvern.worker import _sensor_name

    saved = os.environ.get("NODE_NAME")
    os.environ["NODE_NAME"] = "sensor-node-a"
    try:
        written = _sensor_name(__import__("types").SimpleNamespace())
        read = _gate_sensor_name()
        assert written == read, (
            f"the worker writes under {written!r} but the GUI reads {read!r}; the panel would "
            "report that the gate has never run"
        )
    finally:
        if saved is None:
            os.environ.pop("NODE_NAME", None)
        else:
            os.environ["NODE_NAME"] = saved


# ── the DISABLED gate: does the shipped default record anything? ───────────────────────────────
#
# MEASURED (live, 2026-09-23). A default deployment (SLUICE_ENABLED=0) writes NO state row and no
# log line at all. The reason is a guard in the disabled branch:
#
#     if _SLUICE["armed"] or sup.state.state != GATE_STATE_DISARMED:
#         ... disarm, record, log ...
#     return
#
# A FRESH supervisor's state IS already "disarmed" (GateState defaults to it), so on a process that
# never armed, the condition is False and the entire block is skipped -- deliberately, since
# re-disarming 1440 times a day would shell out to nft for nothing.
#
# The SKIP IS SAFE: a process that never armed installed no rules, so there is nothing to remove.
# But it has a consequence worth stating rather than discovering: a fresh default deployment leaves
# the gate state table EMPTY, so the Sluice panel's "the gate has not run yet" is the permanent
# state of a deployment that has not turned the gate on. That is honest -- nothing has run -- and
# it is not the same as the panel being broken, which is why the empty case carries its own reason.
#
# These tests pin the behaviour so a future change to the guard is a DECISION.
def test_a_fresh_supervisor_starts_disarmed():
    from weirvern.sluice import GATE_STATE_DISARMED, SluiceSupervisor

    assert SluiceSupervisor().state.state == GATE_STATE_DISARMED, (
        "a fresh supervisor no longer starts disarmed, so the disabled branch would now disarm "
        "and record on every start -- a behaviour change, not necessarily a bug, but not silent"
    )


def test_the_empty_state_read_says_why_rather_than_looking_broken():
    """An empty gate table must be distinguishable from an unreadable one.

    The route convention this project uses everywhere: a failure and an empty result must not look
    alike, because the operator acts differently on each. For a default deployment the EMPTY case is
    the normal one, so it must read as a statement rather than as an error.
    """
    from weirvern.sluice_store import load_gate_state

    class NoRows:
        def query(self, *a, **k):  # noqa: ANN002, ANN003
            class R:
                result_rows: list = []
            return R()

    out = load_gate_state(NoRows(), sensor="weirvern")
    assert out["available"] is True, "an empty table was reported as a read failure"
    assert out["state"] == "disarmed"
    assert "has not run yet" in out["detail"], (
        f"the empty case does not explain itself: {out['detail']!r}"
    )


# ── THE HEARTBEAT MUST USE THE SAME IDENTITY AS EVERYTHING ELSE ──────────────────────────────
#
# MEASURED DEFECT, 2026-09-23. The heartbeat loop computed its own sensor id:
#
#     sid = os.environ.get("SENSOR_ID") or os.environ.get("HOSTNAME", "worker")
#
# `HOSTNAME` in a Kubernetes pod is THE POD NAME, which carries the ReplicaSet hash. So the id
# changed on every restart and left a row behind under the old one each time. After ONE rollout the
# fleet carried TWENTY-THREE distinct `weirvern-worker-<hash>-<suffix>` identities, and two were
# reporting as FRESH at that moment -- a healthy deployment looking like it had unknown sensors
# feeding it, which is exactly the security-relevant case the fleet view raises.
#
# `_sensor_name` already solved this (explicit -> NODE_NAME -> hostname) and the gate's state row
# used it. This write site re-derived the rule and got it wrong, which is how the two drifted apart.
#
# HOW THESE TESTS AVOID PROVING NOTHING. The first version re-implemented the FIXED expression and
# asserted on that, so it stayed green with worker.py reverted to the bug -- it tested the test.
# These drive the REAL `_heartbeat_thread` with stubbed collaborators and capture the `sensor_id`
# it actually hands to `status.heartbeat`, which is the value that reaches the database.

def _heartbeat_writes(node_name="UNSET", sensor_id=None, sensor_name="", once=True):
    """Run the PRODUCT's heartbeat thread briefly and return the sensor_id(s) it wrote.

    Everything the thread touches is stubbed -- the database, the observation, the interval -- so
    this exercises the identity expression at its real site without a cluster. The thread is asked
    to stop after `once` passes.
    """
    import os
    import threading as _threading
    import time as _time
    from types import SimpleNamespace

    from weirvern import worker as worker_mod
    from weirvern.admin import sensorwatch, status

    written: list[str] = []
    saved = {k: os.environ.get(k) for k in ("NODE_NAME", "SENSOR_ID", "HOSTNAME")}
    real_heartbeat = status.heartbeat
    real_observe = sensorwatch.observe
    real_stop = worker_mod._stop

    class _Ctx:
        def __enter__(self):
            return object()

        def __exit__(self, *a):
            return False

    try:
        if node_name is None:
            os.environ.pop("NODE_NAME", None)
        elif node_name != "UNSET":
            os.environ["NODE_NAME"] = node_name
        if sensor_id is None:
            os.environ.pop("SENSOR_ID", None)
        else:
            os.environ["SENSOR_ID"] = sensor_id
        # A pod-name-shaped HOSTNAME: what makes the old expression wrong.
        os.environ["HOSTNAME"] = "weirvern-worker-84899c6f55-9z7g2"

        import weirvern.db as db_mod

        worker_mod._stop = _threading.Event()
        status.heartbeat = lambda client, *, sensor_id, **kw: (written.append(sensor_id), True)[1]
        sensorwatch.observe = lambda *a, **k: {}
        db_mod.connect = lambda *a, **k: _Ctx()

        settings = SimpleNamespace(heartbeat_interval_s=1, sensor_name=sensor_name)
        th = _threading.Thread(target=worker_mod._heartbeat_thread, args=(settings,),
                               kwargs={"siphon": None}, daemon=True)
        th.start()
        deadline = _time.monotonic() + 2.0
        while not written and _time.monotonic() < deadline:
            _time.sleep(0.02)
        worker_mod._stop.set()
        th.join(timeout=2.0)
        return written
    finally:
        status.heartbeat = real_heartbeat
        sensorwatch.observe = real_observe
        worker_mod._stop = real_stop
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def test_the_heartbeat_uses_the_NODE_name_not_the_pod_name():
    """THE DEFECT: the heartbeat wrote rows under a name that changed on every restart."""
    written = _heartbeat_writes(node_name="weirvern")
    assert written, "the heartbeat thread wrote nothing, so this test proves nothing"
    assert written[0] == "weirvern", (
        "the heartbeat must identify itself by the NODE: with the pod name, every rollout leaves a "
        "ghost row and a healthy deployment looks like it has unknown sensors feeding it"
    )
    assert "84899c6f55" not in written[0], "the pod name must not reach the sensor id"


def test_an_explicit_SENSOR_ID_still_wins_for_the_heartbeat():
    """A deployment that names its sensors wants that name everywhere, heartbeat included."""
    written = _heartbeat_writes(node_name="weirvern", sensor_id="floor3-idf")
    assert written and written[0] == "floor3-idf"


def test_an_explicit_settings_sensor_name_wins_over_the_node():
    written = _heartbeat_writes(node_name="weirvern", sensor_name="lab-sensor")
    assert written and written[0] == "lab-sensor"


def test_with_no_node_name_the_hostname_is_still_the_answer():
    """A bare CLI or test run has no NODE_NAME, and there the hostname IS the box."""
    written = _heartbeat_writes(node_name=None)
    assert written and written[0]


# ── GLM 5.3 REVIEW: THE GATE MUST NOT REPORT ARMED OVER AN INSTALL THAT FAILED ──────────────────
#
# `arm()` called `self._run([...])` WITHOUT UNPACKING, inside a try/except, and `_nft_run` RETURNS
# (False, err) rather than raising -- so the except was dead code for the real backend, a rejected
# ruleset was discarded, and arm() reported success. The read-back that follows is not a substitute:
# it asks whether a TABLE by that name exists, which a stale table from a previous arm satisfies.


class _ScriptedNft:
    """A fake nft whose install and read-back can be scripted independently."""

    def __init__(self, *, install_ok=True, table_present=True):
        self.install_ok = install_ok
        self.table_present = table_present
        self.calls: list[list[str]] = []

    def __call__(self, args, stdin=None, capture=False):  # noqa: ANN001
        self.calls.append(list(args))
        if list(args)[:3] == ["nft", "delete", "table"]:
            # Absence on a first arm: nft errors, which arm() ignores by design.
            return (True, "")
        if "list" in args:
            return (True, "table inet weirvern_sluice {}" if self.table_present else "")
        if "-f" in args:
            return (self.install_ok, "" if self.install_ok else "syntax error, unexpected drop")
        return (True, "")


def test_arm_REPORTS_FAILURE_when_nft_rejects_the_ruleset():
    """THE DEFECT. A rejected install must not read as armed."""
    fake = _ScriptedNft(install_ok=False, table_present=True)  # a stale table exists

    ok, reason = NftBackend(runner=fake).arm([live("r1", src_cidr="198.51.100.5/32")], iface="ens19")
    assert ok is False, (
        f"arm() reported SUCCESS while nft REJECTED the ruleset -- a stale table from a previous arm "
        f"satisfies the read-back, so 'rejected' and 'armed with the new rules' were "
        f"indistinguishable. reason={reason!r}"
    )
    assert "rejected" in reason, reason


def test_arm_still_reports_success_when_the_install_really_worked(monkeypatch):
    """The other direction, so the fix cannot be 'always fail'."""
    fake = _ScriptedNft(install_ok=True, table_present=True)
    ok, reason = NftBackend(runner=fake).arm([live("r1", src_cidr="198.51.100.5/32")], iface="ens19")
    assert ok is True, reason


def test_arm_DELETES_both_tables_before_installing():
    """ARM MUST BE A REPLACE, NOT AN ACCUMULATE (glm-5.3 review).

    `_base_ruleset` is purely declarative -- no flush, no delete -- so arming twice could only ADD to
    what the previous arm left, and `disarm()` is the only code that removes kernel state while the
    enforcement cycle never calls it between passes. MEASURED consequence: a rule that EXPIRED or was
    REVOKED stopped being compiled while its installed drop rule kept matching, so traffic stayed
    blocked after the block was withdrawn. For a gate that is supposed to fail OPEN, that is the worst
    failure available.
    """
    fake = _ScriptedNft()

    NftBackend(runner=fake).arm([live("r1", src_cidr="198.51.100.5/32")], iface="ens19")

    deletes = [c for c in fake.calls if c[:3] == ["nft", "delete", "table"]]
    tables = {c[4] for c in deletes if len(c) > 4}
    assert NFT_TABLE in tables, (
        f"arm() did not delete {NFT_TABLE} before installing, so a rule removed from the list would "
        f"keep blocking. deletes={deletes}"
    )
    assert NFT_TABLE_IN in tables, (
        f"arm() did not delete {NFT_TABLE_IN}; an inbound drop rule would survive its own removal. "
        f"deletes={deletes}"
    )
    # And the delete must come BEFORE the install, or it would wipe what was just added.
    i_delete = next(i for i, c in enumerate(fake.calls) if c[:3] == ["nft", "delete", "table"])
    i_install = next(i for i, c in enumerate(fake.calls) if "-f" in c)
    assert i_delete < i_install, "the tables were deleted AFTER the install, wiping the new ruleset"


def test_arm_REPORTS_FAILURE_when_the_install_left_no_table():
    """A SUCCESSFUL exit is not the same as an installed gate -- this project's recurring failure mode.

    `nft -f` returning 0 and the table being absent cannot both be true of a working install, so the
    read-back is a real check, not a formality. Without a test it was a line that could be deleted
    silently.
    """
    fake = _ScriptedNft(install_ok=True, table_present=False)

    ok, reason = NftBackend(runner=fake).arm([live("r1", src_cidr="198.51.100.5/32")], iface="ens19")
    assert ok is False, (
        "arm() reported success after an install that left no table behind. The gate would read as "
        "ARMED while blocking nothing"
    )
    assert "not present" in reason, reason


# ── the disabled-at-restart sweep ──────────────────────────────────────────────────────────────


class _SweepBackend(Backend):
    """A kernel with a table in it (or not), counting how often anyone looked."""

    name = "sweep-fake"

    def __init__(self, present: bool) -> None:
        self.present = present
        self.disarms = 0
        self.checks = 0

    def available(self) -> bool:
        return True

    def arm(self, rules, *, iface):
        return True, "simulated"

    def disarm(self):
        self.disarms += 1
        self.present = False
        return True, "simulated"

    def counters(self):
        return 0, 0

    def installed(self) -> bool:
        self.checks += 1
        return self.present


def _disabled_settings():
    class _S:
        sluice_enabled = False
        sluice_iface = "eth9"
        channel_upstream = ""
        channel_downstream = ""
        zeek_iface = "eth9"
        mgmt_iface = "eth8"
        sensor_name = "unit-test"
        sluice_criticality = "off"
        sluice_max_block_s = 3600
        sluice_interval_s = 60

    return _S()


def _wire_disabled_sweep(monkeypatch, backend):
    import weirvern.worker as worker
    from weirvern import sluice_store
    from weirvern.admin import channel

    monkeypatch.setattr("weirvern.sluice.choose_backend", lambda *a, **k: backend)
    monkeypatch.setattr(channel, "detect",
                        lambda u, d: type("_C", (), {"bridge": "", "active": False})())
    writes: list = []
    monkeypatch.setattr(sluice_store, "write_gate_state",
                        lambda client, sensor, state: writes.append(state))
    worker._SLUICE.update({"supervisor": None, "last_pass": 0.0, "armed": False, "swept": False})
    return worker, writes


def test_a_disabled_worker_sweeps_a_table_a_previous_run_left_behind(monkeypatch):
    """MEASURED on the test box: SLUICE_ENABLED=0 across a worker restart left the (now inert)
    `table inet weirvern_sluice` in the kernel. The in-memory 'armed' flag cannot see it -- THIS
    process never armed anything -- so 'disabled' quietly meant 'disarmed in the last process'.
    Only the kernel can answer the question, and it now gets asked once per process."""
    backend = _SweepBackend(present=True)
    worker, writes = _wire_disabled_sweep(monkeypatch, backend)

    worker._sluice_maybe(_disabled_settings(), client=object())
    assert backend.disarms == 1, "the leftover table was not removed"
    assert writes, "the swept state was not recorded for the panel"
    assert backend.checks == 1

    # ONE sweep per process: a second pass must not shell out to nft again.
    worker._sluice_maybe(_disabled_settings(), client=object())
    assert backend.disarms == 1, "the sweep repeated on every pass"
    assert backend.checks == 1, "installed() ran again after the sweep decision was made"


def test_a_disabled_worker_with_no_leftovers_never_touches_the_backend(monkeypatch):
    """The common case must stay free: with nothing present, one check and no disarm at all."""
    backend = _SweepBackend(present=False)
    worker, writes = _wire_disabled_sweep(monkeypatch, backend)

    worker._sluice_maybe(_disabled_settings(), client=object())
    worker._sluice_maybe(_disabled_settings(), client=object())
    assert backend.disarms == 0
    assert backend.checks == 1, "the kernel is asked once per process, not once per pass"
    assert writes == [], "a clean disabled start writes nothing"


def test_a_rule_describes_itself_as_a_sentence():
    """US-SL1: the rules list must read as policy, not as a row of protocol columns.

    One wording everywhere -- the table, the audit row and the API all call describes().
    """
    from weirvern.sluice import Rule

    block = Rule(rule_id="a", domain="ads.example.com", mode="block",
                 resolved_ips=["192.0.2.1"]).describes()
    assert block == "block ads.example.com (resolves to 1 address)", block

    alert = Rule(rule_id="b", domain="x.example", mode="alert",
                 resolved_ips=["1.1.1.1", "2.2.2.2"]).describes()
    assert alert == "alert on x.example (resolves to 2 addresses)", alert

    tuple_rule = Rule(rule_id="c", src_cidr="198.51.100.0/24", dst_port=443,
                      protocol="tcp").describes()
    assert tuple_rule == "block traffic from 198.51.100.0/24 on tcp/443", tuple_rule

    # An empty predicate is a data defect and must not be dressed up as a sentence.
    assert Rule(rule_id="d").describes() == "(no predicate)"


def test_a_failed_nft_list_does_not_count_as_a_present_table():
    """ENOENT names the table in stderr.

    `nft list table inet weirvern_sluice` on a box with no such table exits non-zero and prints
    "list table inet weirvern_sluice". Reading the text alone made every absence look like a
    leftover table, so the live gate reported "degraded: these tables are still present after
    deletion" forever while `nft list tables` showed neither.
    """
    from weirvern.sluice import NftBackend

    def runner(args, stdin=None, capture=False):
        return False, "Error: No such file or directory\nlist table inet weirvern_sluice"

    backend = NftBackend(runner=runner)
    assert backend.installed() is False
    ok, detail = backend.disarm()
    assert ok is True and "still present" not in detail
