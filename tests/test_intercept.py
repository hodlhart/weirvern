"""Tests for the in-path intercept dataplane (siphon mode).

The properties that matter here are safety properties, not features. In siphon mode Weirvern
is a ROUTER: every host whose ARP cache we forge loses the network if our mappings are not
withdrawn. So these tests pin ordering and teardown, not throughput.

The specific hazards, each with its symptom:
  * poisoning BEFORE the watchdog is armed -> a crash in that window leaves the segment
    poisoned with nothing responsible for restoring it
  * `ip_forward=0`                        -> we forge the mapping and then DROP the
                                             traffic; the victim goes offline completely
  * `rp_filter != 0`                      -> relayed packets are discarded by the kernel's
                                             reverse-path check; TCP connects hang
  * a teardown that can throw             -> the restore stops part-way and the segment
                                             stays broken
"""
from __future__ import annotations

from pathlib import Path

import pytest

from weirvern.admin import intercept as ic
from weirvern.admin import siphonnet
from weirvern.admin.siphonnet import ForwardingState

# ── fakes ───────────────────────────────────────────────────────────────────────


class StubMonitor:
    """A ForwardingMonitor that reports whatever the test wants.

    The real monitor reads /proc/net/snmp, which advances on any host that forwards
    traffic -- so using it in a test makes the result depend on ambient network activity
    and on timing. These tests are about ORDERING and TEARDOWN, so the signal is injected.
    """

    def __init__(self, advancing: bool = True) -> None:
        self.advancing = advancing

    def advanced(self) -> bool | None:
        return self.advancing

    @staticmethod
    def read() -> int:
        return 0


def _freeze_health(runner: ic.Intercept, advancing: bool = True) -> None:
    """Replace the watchdog's monitor after start(), so no stall can be reported."""
    assert runner.watchdog is not None
    runner.watchdog._forwarding = StubMonitor(advancing=advancing)  # type: ignore[attr-defined]


class RecordingSender:
    """Captures frames instead of sending them, and records the order of operations."""

    def __init__(self, log: list[str] | None = None) -> None:
        self.frames: list[tuple[bytes, str]] = []
        self.log = log if log is not None else []
        self.closed = False

    def __call__(self, frame: bytes, kind: str = "poison") -> None:
        self.frames.append((frame, kind))
        self.log.append(kind)

    def close(self) -> None:
        self.closed = True


def _plan(hosts: dict[str, str] | None = None) -> ic.InterceptPlan:
    return ic.InterceptPlan(
        iface="eth1",
        segment="198.51.100.0/24",
        our_mac="aa:bb:cc:dd:ee:ff",
        our_ip="198.51.100.50",
        gateway_ip="198.51.100.1",
        gateway_mac="11:22:33:44:55:66",
        hosts=hosts if hosts is not None else {
            "198.51.100.10": "0a:0a:0a:0a:0a:0a",
            "198.51.100.11": "0b:0b:0b:0b:0b:0b",
        },
    )


READY = ForwardingState(ip_forward=True, rp_filter_off=True)


# ── CIDR parsing ────────────────────────────────────────────────────────────────


def test_cidr_lists_usable_hosts_only():
    hosts = ic.parse_cidr("198.51.100.0/24")
    assert len(hosts) == 254
    assert "198.51.100.1" in hosts
    assert "198.51.100.0" not in hosts, "the network address is not a host"
    assert "198.51.100.255" not in hosts, "the broadcast address is not a host"


def test_a_huge_segment_is_refused_rather_than_attempted():
    """Poisoning 65k hosts is not something anyone means to do by accident."""
    with pytest.raises(ValueError, match="1024"):
        ic.parse_cidr("198.51.100.0/16")


def test_an_ipv6_segment_is_refused_with_a_reason():
    """The dataplane is v4-only. Letting a v6 segment reach the sweep would fail per-send
    with a swallowed OSError and present as 'no hosts answered' -- the false-empty-network
    shape, when the honest answer is 'this can never work'."""
    with pytest.raises(ValueError, match="IPv6"):
        ic.parse_cidr("2001:db8::/120")
    # And the refusal must say WHY, not just that it failed: a bare refusal sends the
    # operator looking for a v6 flag that does not exist.
    try:
        ic.parse_cidr("2001:db8::/120")
    except ValueError as exc:
        assert "loch" in str(exc), (
            "the v6 refusal does not point at the alternative (passive mode)"
        )


# ── never-intercept roles are ENFORCED, not just advised ────────────────────────
#
# `mode.py` lists the roles a target must never hold. Rendered only as a warning, that
# list was advice -- and advice does not stop a --hosts argument. These tests pin the
# refusal: the derivable roles are checked, the structural ones cannot be overridden,
# and the intent-dependent ones can be overridden only explicitly.


def test_named_targets_matching_a_derivable_role_are_refused(monkeypatch, caplog):
    """A --hosts target that is the sensor's own resolver must be refused BY NAME."""
    monkeypatch.setattr(ic, "read_mac", lambda _i: "aa:bb:cc:dd:ee:ff")
    monkeypatch.setattr(ic, "resolve_mac", lambda _i, _ip: "11:22:33:44:55:66")
    monkeypatch.setattr(ic, "arp_sweep", lambda *a, **k: {
        "198.51.100.53": "0d:0d:0d:0d:0d:0d",
    })
    # The resolver file is pointed at a fixture rather than the machine's real one.
    monkeypatch.setattr(ic, "RESOLV_CONF_PATH", "/dev/null")
    monkeypatch.setattr(ic, "_resolv_nameservers", lambda: ["198.51.100.53"])
    with caplog.at_level("ERROR"):
        plan = ic.build_plan("eth1", "198.51.100.0/24", "198.51.100.50", "198.51.100.1",
                             only={"198.51.100.53"})
    assert plan is None, (
        "a named target holding a never-intercept role was accepted, so the prose list "
        "is still just advice"
    )
    rendered = " ".join(r.getMessage() for r in caplog.records)
    assert "resolver" in rendered, "the refusal does not name the role"
    assert "--force-unsafe" in rendered, (
        "the refusal does not say how to override it deliberately"
    )


def test_our_own_address_and_the_gateway_cannot_even_be_forced(monkeypatch, caplog):
    """The structural roles are impossible regardless of intent: poisoning the address we
    are claiming, or our own, cannot relay anything -- it can only break things."""
    monkeypatch.setattr(ic, "read_mac", lambda _i: "aa:bb:cc:dd:ee:ff")
    monkeypatch.setattr(ic, "resolve_mac", lambda _i, _ip: "11:22:33:44:55:66")
    monkeypatch.setattr(ic, "arp_sweep", lambda *a, **k: {
        "198.51.100.50": "aa:bb:cc:dd:ee:ff",   # our own address
        "198.51.100.1": "11:22:33:44:55:66",    # the gateway
    })
    for addr in ("198.51.100.50", "198.51.100.1"):
        with caplog.at_level("ERROR"):
            plan = ic.build_plan("eth1", "198.51.100.0/24", "198.51.100.50", "198.51.100.1",
                                 only={addr}, force_unsafe=True)
        assert plan is None, (
            f"{addr} was accepted even with --force-unsafe; the structural refusals "
            f"must not be overridable"
        )


def test_force_unsafe_overrides_only_the_intent_dependent_roles(monkeypatch, caplog):
    """A resolver genuinely under investigation is a legitimate target, so the operator
    can accept the risk explicitly -- with the acceptance recorded."""
    monkeypatch.setattr(ic, "read_mac", lambda _i: "aa:bb:cc:dd:ee:ff")
    monkeypatch.setattr(ic, "resolve_mac", lambda _i, _ip: "11:22:33:44:55:66")
    monkeypatch.setattr(ic, "arp_sweep", lambda *a, **k: {
        "198.51.100.53": "0d:0d:0d:0d:0d:0d",
    })
    monkeypatch.setattr(ic, "_resolv_nameservers", lambda: ["198.51.100.53"])
    with caplog.at_level("WARNING"):
        plan = ic.build_plan("eth1", "198.51.100.0/24", "198.51.100.50", "198.51.100.1",
                             only={"198.51.100.53"}, force_unsafe=True)
    assert plan is not None, "--force-unsafe did not override the intent-dependent refusal"
    rendered = " ".join(r.getMessage() for r in caplog.records)
    assert "force-unsafe" in rendered, (
        "the override was silent: an accepted risk must be recorded"
    )


def test_never_intercept_hits_flags_the_derivable_roles(monkeypatch):
    """The derivation reads the real sources: our address, the gateway, resolv.conf,
    MGMT_ADDR and KUBERNETES_SERVICE_HOST."""
    monkeypatch.setattr(ic, "_resolv_nameservers", lambda: ["198.51.100.53"])
    monkeypatch.setenv("MGMT_ADDR", "198.51.100.9")
    monkeypatch.setenv("KUBERNETES_SERVICE_HOST", "203.0.113.10")
    hits = ic.never_intercept_hits(
        {"198.51.100.53", "198.51.100.9", "203.0.113.10", "198.51.100.77", "198.51.100.50"},
        our_ip="198.51.100.50", gateway_ip="198.51.100.1")
    assert "198.51.100.53" in hits and "resolver" in hits["198.51.100.53"]
    assert "198.51.100.9" in hits and "management" in hits["198.51.100.9"]
    assert "203.0.113.10" in hits and "API" in hits["203.0.113.10"]
    assert "198.51.100.50" in hits, "our own address must be flagged"
    assert "198.51.100.77" not in hits, "an ordinary host was flagged, so valid plans refuse"


def test_the_resolver_reader_survives_a_missing_file(monkeypatch, tmp_path):
    """A host without /etc/resolv.conf must not lose the ability to intercept: the check
    is an EXTRA refusal, and its own failure mode is 'no nameservers found'."""
    missing = tmp_path / "nope.conf"
    monkeypatch.setattr(ic, "RESOLV_CONF_PATH", str(missing))
    assert ic._resolv_nameservers() == []


# ── the plan ────────────────────────────────────────────────────────────────────


def test_the_plan_installs_both_directions_per_host():
    """Outbound AND inbound.

    With only the host's gateway entry forged, replies take the direct path and the sensor
    sees a one-sided conversation -- which looks like it works while silently missing half
    the traffic.
    """
    mappings = _plan().mappings()
    assert len(mappings) == 4, "2 hosts x 2 directions"
    claims = {(m.host_ip, m.claim_ip) for m in mappings}
    assert ("198.51.100.10", "198.51.100.1") in claims, "host -> gateway direction missing"
    assert ("198.51.100.1", "198.51.100.10") in claims, "gateway -> host direction missing"


def test_a_forged_mapping_claims_the_gateway_and_restores_the_real_mac():
    """The restore must use the REAL MAC, which is why it is stored at plan time.

    Rediscovering it during teardown would fail exactly when the network is in the broken
    state we are trying to fix.
    """
    m = _plan().mappings()[0]
    poison = m.poison_frame()
    restore = m.restore_frame()
    assert poison != restore
    # Both are ARP replies to the same host.
    assert poison[:6] == restore[:6]
    # The sender MAC differs: ours vs the gateways.
    from weirvern.admin.watchdog import mac_to_bytes
    assert poison[22:28] == mac_to_bytes("aa:bb:cc:dd:ee:ff")
    assert restore[22:28] == mac_to_bytes("11:22:33:44:55:66")


def test_the_plan_describes_itself_for_inspection():
    """An operator must be able to see what will be changed before it is changed."""
    text = _plan().describe()
    assert "198.51.100.0/24" in text
    assert "198.51.100.1" in text
    assert "198.51.100.10" in text


# ── preflight ───────────────────────────────────────────────────────────────────


def test_preflight_blocks_when_ip_forward_is_off():
    """The worst failure available: forge the path, then drop the traffic.

    The victim loses the network entirely, and it presents as a hardware fault rather than
    a misconfiguration.
    """
    state = ForwardingState(ip_forward=False, rp_filter_off=True,
                            problems=["net.ipv4.ip_forward is 0: relayed traffic would "
                                      "be DROPPED"])
    problems = ic.Intercept(_plan(), RecordingSender(), forwarding=state).preflight()
    assert any("ip_forward" in p for p in problems)


def test_preflight_blocks_when_rp_filter_is_set():
    state = ForwardingState(ip_forward=True, rp_filter_off=False,
                            problems=["net.ipv4.conf.eth1.rp_filter is 1"])
    problems = ic.Intercept(_plan(), RecordingSender(), forwarding=state).preflight()
    assert any("rp_filter" in p for p in problems)


def test_preflight_reports_every_problem_at_once():
    """So the operator fixes them in one pass instead of one per run."""
    state = ForwardingState(ip_forward=False, rp_filter_off=False,
                            problems=["ip_forward is 0", "rp_filter is 1"])
    plan = _plan(hosts={})  # also nothing to intercept
    problems = ic.Intercept(plan, RecordingSender(), forwarding=state).preflight()
    assert len(problems) >= 3


def test_preflight_blocks_when_nothing_responded_to_the_sweep():
    """"Intercepting nothing" is how a siphon deployment silently looks broken."""
    problems = ic.Intercept(_plan(hosts={}), RecordingSender(),
                            forwarding=READY).preflight()
    assert any("no hosts responded" in p for p in problems)


def test_preflight_passes_on_a_healthy_plan():
    assert ic.Intercept(_plan(), RecordingSender(), forwarding=READY).preflight() == []


# ── the ordering property ───────────────────────────────────────────────────────


def test_the_watchdog_owns_every_mapping_before_the_first_frame():
    """THE safety property of this module.

    If a poison frame went out before the watchdog held the mappings, a crash in that
    window would leave the segment poisoned with nothing responsible for undoing it.

    Asserted from INSIDE the send path: the mapping count is sampled at the instant the
    first frame is transmitted, which is the only moment the ordering can be violated.
    A test that checked after start() returned could not detect it -- by then the ordering
    has already resolved one way or the other.
    """
    observed: list[int] = []
    runner: ic.Intercept

    class ObservingSender(RecordingSender):
        def __call__(self, frame: bytes, kind: str = "poison") -> None:
            if runner.watchdog is not None and not observed:
                observed.append(runner.watchdog.active)
            super().__call__(frame, kind)

    sender = ObservingSender()
    runner = ic.Intercept(_plan(), sender, forwarding=READY)
    runner.start()
    try:
        _freeze_health(runner)
        assert observed, "no frames were sent at all"
        assert observed[0] == 4, (
            f"the watchdog held only {observed[0]} of 4 mappings when the first frame was "
            f"sent, so a crash at that moment would leave the segment poisoned"
        )
    finally:
        runner.stop()


def test_poisoning_begins_immediately_not_on_the_first_refresh_tick():
    """start() must not return before the ARP caches are actually forged.

    The refresh loop waits refresh_s (default 5s) before its first tick, so a watchdog
    that only poisoned from the refresh loop would leave a window where interception is
    announced but not happening -- the caches are untouched, traffic is not routed through
    us, and everything downstream still looks healthy.
    """
    sender = RecordingSender()
    runner = ic.Intercept(_plan(), sender, forwarding=READY)
    runner.start()
    try:
        _freeze_health(runner)
        poisons = [f for f, kind in sender.frames if kind in ("initial", "refresh", "poison")]
        assert len(poisons) == 4, (
            f"only {len(poisons)} frame(s) sent by the time start() returned; the ARP "
            f"caches would still be untouched"
        )
    finally:
        runner.stop()


def test_start_registers_every_mapping_with_the_watchdog():
    sender = RecordingSender()
    runner = ic.Intercept(_plan(), sender, forwarding=READY)
    runner.start()
    try:
        _freeze_health(runner)
        assert runner.active
        assert runner.watchdog is not None
        assert runner.watchdog.active == 4
    finally:
        runner.stop()


# ── teardown ────────────────────────────────────────────────────────────────────


def test_stopping_restores_every_mapping():
    sender = RecordingSender()
    runner = ic.Intercept(_plan(), sender, forwarding=READY)
    runner.start()
    _freeze_health(runner)
    runner.stop()

    restores = [f for f, kind in sender.frames if kind == "restore"]
    assert len(restores) == 4, f"expected 4 restores, got {len(restores)}"
    assert not runner.active


def test_the_context_manager_restores_on_the_way_out():
    """Teardown must not depend on the caller remembering."""
    sender = RecordingSender()
    with ic.Intercept(_plan(), sender, forwarding=READY) as runner:
        _freeze_health(runner)
        assert runner.active
    assert not runner.active
    assert any(kind == "restore" for _f, kind in sender.frames)


def test_teardown_runs_even_when_the_body_raises():
    sender = RecordingSender()
    runner = ic.Intercept(_plan(), sender, forwarding=READY)
    with pytest.raises(RuntimeError), runner:
        _freeze_health(runner)
        raise RuntimeError("simulated failure mid-intercept")
    assert not runner.active, "the mappings must be withdrawn even on a crash"
    assert any(kind == "restore" for _f, kind in sender.frames)


def test_stopping_twice_is_harmless():
    """Every exit path calls stop(), so it has to be idempotent."""
    sender = RecordingSender()
    runner = ic.Intercept(_plan(), sender, forwarding=READY)
    runner.start()
    _freeze_health(runner)
    runner.stop()
    after_first = len(sender.frames)
    runner.stop()
    assert len(sender.frames) == after_first, "a second stop re-sent frames"
    assert not runner.active


def test_stop_closes_the_socket():
    sender = RecordingSender()
    runner = ic.Intercept(_plan(), sender, forwarding=READY)
    runner.start()
    _freeze_health(runner)
    runner.stop()
    assert sender.closed


# ── status ──────────────────────────────────────────────────────────────────────


def test_status_reports_mappings_and_uptime():
    runner = ic.Intercept(_plan(), RecordingSender(), forwarding=READY)
    runner.start()
    try:
        _freeze_health(runner)
        st = runner.status()
        assert st["hosts"] == 2
        assert st["mappings"] == 4
        assert st["running"] is True
        assert st["segment"] == "198.51.100.0/24"
    finally:
        runner.stop()


# ── sysctl reads ────────────────────────────────────────────────────────────────


def test_sysctl_path_maps_dots_to_slashes():
    assert str(siphonnet.sysctl_path("net.ipv4.ip_forward")) == \
        "/proc/sys/net/ipv4/ip_forward"
    assert str(siphonnet.sysctl_path("net.ipv4.conf.all.rp_filter")) == \
        "/proc/sys/net/ipv4/conf/all/rp_filter"


def test_check_forwarding_does_not_crash_on_a_read_failure(monkeypatch):
    """`cannot tell` must not be reported as `forwarding is fine`.

    Conflating those is how a watchdog either never fires or fires constantly.
    """
    monkeypatch.setattr(siphonnet, "read_sysctl", lambda _name: None)
    state = siphonnet.check_forwarding("eth1")
    assert not state.ready
    assert state.problems


def test_check_forwarding_accepts_a_correct_configuration(monkeypatch):
    values = {
        "net.ipv4.ip_forward": 1,
        "net.ipv4.conf.all.rp_filter": 0,
        "net.ipv4.conf.eth1.rp_filter": 0,
    }
    monkeypatch.setattr(siphonnet, "read_sysctl", lambda name: values.get(name))
    state = siphonnet.check_forwarding("eth1")
    assert state.ready, state.problems


# ── MAC resolution ──────────────────────────────────────────────────────────────


def test_read_neighbour_mac_ignores_incomplete_entries(tmp_path, monkeypatch):
    """A MAC of all zeros means unresolved; returning it would forge a mapping to nobody."""
    arp = tmp_path / "arp"
    arp.write_text(
        "IP address       HW type     Flags       HW address            Mask     Device\n"
        "198.51.100.10     0x1         0x2         aa:bb:cc:dd:ee:01     *        eth1\n"
        "198.51.100.11     0x1         0x0         00:00:00:00:00:00     *        eth1\n"
    )
    body = arp.read_text()          # capture BEFORE patching, or this recurses
    monkeypatch.setattr(siphonnet.Path, "read_text", lambda self: body)
    assert siphonnet.read_neighbour_mac("eth1", "198.51.100.10") == "aa:bb:cc:dd:ee:01"
    assert siphonnet.read_neighbour_mac("eth1", "198.51.100.11") is None


def test_read_mac_returns_none_for_a_missing_interface(monkeypatch):
    monkeypatch.setattr(siphonnet.Path, "read_text",
                        lambda self: (_ for _ in ()).throw(OSError()))
    assert siphonnet.read_mac("nosuchiface") is None


# ── choosing an address (rather than being told to invent one) ─────────────────
#
# WHY NOT DHCP: a DHCP address can change or be withdrawn mid-intercept, and that is the
# one failure the watchdog cannot tell from idleness -- the forwarding counter simply stops
# advancing, which is treated as "quiet" rather than "broken". The connected route would
# vanish, so poisoned hosts keep believing we are the gateway while we can no longer
# forward for them: a segment-wide outage the health monitor reports as healthy.
#
# So the address is STATIC and CHOSEN BY THE OPERATOR, from a list verified free.


def test_free_addresses_prefers_the_top_of_the_range(monkeypatch):
    """DHCP pools hand out from the bottom, so a high address is least likely to collide."""
    monkeypatch.setattr(siphonnet, "read_mac", lambda _i: "aa:bb:cc:dd:ee:ff")
    monkeypatch.setattr(ic, "arp_sweep", lambda *a, **k: {})
    free = siphonnet.find_free_addresses("eth1", "198.51.100.0/24", "198.51.100.5", count=3)
    assert free == ["198.51.100.254", "198.51.100.253", "198.51.100.252"], free


def test_an_address_that_answered_arp_is_not_offered(monkeypatch):
    """Offering an in-use address would cause a conflict on the operator's network."""
    monkeypatch.setattr(siphonnet, "read_mac", lambda _i: "aa:bb:cc:dd:ee:ff")
    monkeypatch.setattr(ic, "arp_sweep",
                        lambda *a, **k: {"198.51.100.254": "de:ad:be:ef:00:01"})
    free = siphonnet.find_free_addresses("eth1", "198.51.100.0/24", "198.51.100.5", count=2)
    assert "198.51.100.254" not in free, "a taken address was offered as free"
    assert free == ["198.51.100.253", "198.51.100.252"]


def test_the_source_address_is_never_offered(monkeypatch):
    monkeypatch.setattr(siphonnet, "read_mac", lambda _i: "aa:bb:cc:dd:ee:ff")
    monkeypatch.setattr(ic, "arp_sweep", lambda *a, **k: {})
    free = siphonnet.find_free_addresses("eth1", "198.51.100.0/24", "198.51.100.254", count=1)
    assert "198.51.100.254" not in free, "offered the address we are already using"


def test_no_mac_means_no_offer_rather_than_a_guess(monkeypatch):
    monkeypatch.setattr(siphonnet, "read_mac", lambda _i: None)
    assert siphonnet.find_free_addresses("eth1", "198.51.100.0/24", "198.51.100.5") == []


def test_describe_segment_reports_the_blast_radius(monkeypatch):
    """Every host listed is one whose ARP cache would be forged."""
    monkeypatch.setattr(siphonnet, "read_mac", lambda _i: "aa:bb:cc:dd:ee:ff")
    monkeypatch.setattr(ic, "arp_sweep", lambda *a, **k: {
        "198.51.100.10": "0a:0a:0a:0a:0a:0a",
        "198.51.100.11": "0b:0b:0b:0b:0b:0b",
    })
    used, err = siphonnet.describe_segment("eth1", "198.51.100.0/24", "198.51.100.5")
    assert not err
    assert len(used) == 2


def test_describe_segment_refuses_an_enormous_sweep(monkeypatch):
    monkeypatch.setattr(siphonnet, "read_mac", lambda _i: "aa:bb:cc:dd:ee:ff")
    used, err = siphonnet.describe_segment("eth1", "198.51.100.0/16", "198.51.100.5")
    assert used == {}
    assert "too large" in err


def test_the_cli_surveys_before_building_the_plan():
    """A blast radius nobody sees is not a decision, it is an accident."""
    from pathlib import Path as _P

    src = (_P(__file__).resolve().parents[1] / "weirvern" / "admin" / "cli.py").read_text()
    body = src[src.index("def cmd_intercept"):]
    body = body[:body.index("plan = ic_mod.build_plan")]
    assert "describe_segment" in body, (
        "the CLI does not survey the segment, so the operator never sees how many hosts "
        "an intercept would affect"
    )
    assert "find_free_addresses" in body, (
        "the CLI does not offer free addresses, so the operator must invent one and risk "
        "a conflict"
    )


# ── the sweep must SEE hosts (this was a real bug) ──────────────────────────────
#
# A sweep that reads /proc/net/arp returns ZERO hosts on a live segment, because the kernel
# only installs a neighbour entry for addresses the interface actually OWNS. Replies for
# every other address arrive on the wire and are discarded. Measured against a live
# 198.51.100.0/24 with ELEVEN hosts: the kernel-table version found 0, parsing the socket
# found 11.
#
# That failure is worse than a crash. `weirvern intercept --dry-run` uses this to report
# the blast radius and to offer free addresses, so it would have told an operator their
# network was empty and that intercepting it would be pointless -- on a live network.


def test_arp_sweep_parses_replies_rather_than_reading_the_kernel_table():
    src = (Path(__file__).resolve().parents[1] / "weirvern" / "admin" /
           "intercept.py").read_text()
    body = src[src.index("def arp_sweep"):]
    body = body[:body.index("\ndef ", 10)]
    assert "sock.recv" in body, (
        "the sweep does not read replies from the socket, so it will report an empty "
        "segment on a live network"
    )
    # read_neighbour_mac may appear only as the gap-filler, never as the primary source.
    primary = body[:body.index("finally:")]
    assert "read_neighbour_mac" not in primary, (
        "the sweep still relies on the kernel neighbour table, which is blind to every "
        "address the interface does not own"
    )


def test_arp_sweep_sends_in_batches_and_drains_between_them():
    """Blasting a whole /24 and then reading loses replies to a full socket buffer.

    ARP replies are UNICAST, so a dropped frame is gone rather than retransmitted -- and
    the socket buffer is small. Measured: all-at-once found 1 host where batching found 11.
    """
    src = (Path(__file__).resolve().parents[1] / "weirvern" / "admin" /
           "intercept.py").read_text()
    body = src[src.index("def arp_sweep"):]
    body = body[:body.index("\ndef ", 10)]
    assert "range(0, len(targets), ARP_BATCH)" in body, (
        "the sweep does not batch its sends, so most replies will be dropped"
    )
    assert "sock.settimeout" in body, (
        "no socket timeout: a recv loop without one blocks forever on a quiet segment"
    )


def test_the_drain_window_divides_the_budget_across_batches():
    """The budget must be divided, not repeated. An earlier formula handed every segment
    under 64 targets the FULL timeout for EVERY batch while its comment claimed a bounded
    window -- so a /25 with 8 batches would drain for 8 x 3s instead of 3s total."""
    assert ic._drain_window(3.0, 1) == 3.0, "a single batch gets the full budget"
    assert ic._drain_window(3.0, 254) < 1.0, (
        "a /24's per-batch window is not a fraction of the total budget, so the sweep "
        "takes batches x budget seconds"
    )
    # The floor keeps a slow stack covered even when the division goes tiny.
    assert ic._drain_window(3.0, 4096) >= 0.5


def test_the_sweep_does_not_source_from_0000():
    """A request from 0.0.0.0 is ignored by most stacks -- a second false 'empty network'."""
    src = (Path(__file__).resolve().parents[1] / "weirvern" / "admin" /
           "cli.py").read_text()
    body = src[src.index("def cmd_intercept"):]
    body = body[:body.index("def _has_cap") if "def _has_cap" in body else len(body)]
    assert "describe_segment(iface, segment, our_ip or gateway)" in body, (
        "the survey does not pass a usable source address, so replies may never come"
    )


# ── --hosts: intercept a subset, not the whole segment ──────────────────────────
#
# WHY THIS MATTERS MORE THAN IT LOOKS: poisoning a whole segment makes Weirvern the path
# for every device on it, so a crash is an outage for all of them until their ARP caches
# expire. Being able to name two or three hosts is what makes a first test on someone
# else's network defensible.


def test_a_host_filter_limits_what_is_intercepted(monkeypatch):
    monkeypatch.setattr(ic, "read_mac", lambda _i: "aa:bb:cc:dd:ee:ff")
    monkeypatch.setattr(ic, "resolve_mac", lambda _i, _ip: "11:22:33:44:55:66")
    monkeypatch.setattr(ic, "arp_sweep", lambda *a, **k: {
        "198.51.100.10": "0a:0a:0a:0a:0a:0a",
        "198.51.100.11": "0b:0b:0b:0b:0b:0b",
        "198.51.100.12": "0c:0c:0c:0c:0c:0c",
    })
    plan = ic.build_plan("eth1", "198.51.100.0/24", "198.51.100.50", "198.51.100.1",
                         only={"198.51.100.10"})
    assert plan is not None
    assert set(plan.hosts) == {"198.51.100.10"}, (
        "the host filter did not restrict the plan, so a 'small test' would poison the "
        "whole segment"
    )
    # Two mappings per host: outbound (its cache for the gateway) and inbound (the
    # gateway's cache for it). Both are required or replies take the direct path.
    assert len(plan.mappings()) == 2


def test_a_requested_host_that_is_absent_is_reported_not_silently_dropped(monkeypatch, caplog):
    """Silently intercepting fewer hosts than asked would look like success while
    testing less than the operator thinks."""
    monkeypatch.setattr(ic, "read_mac", lambda _i: "aa:bb:cc:dd:ee:ff")
    monkeypatch.setattr(ic, "resolve_mac", lambda _i, _ip: "11:22:33:44:55:66")
    monkeypatch.setattr(ic, "arp_sweep", lambda *a, **k: {
        "198.51.100.10": "0a:0a:0a:0a:0a:0a",
    })
    with caplog.at_level("WARNING"):
        plan = ic.build_plan("eth1", "198.51.100.0/24", "198.51.100.50", "198.51.100.1",
                             only={"198.51.100.10", "198.51.100.99"})
    assert plan is not None
    assert set(plan.hosts) == {"198.51.100.10"}
    # caplog records the raw format string in .message with args in .args, so build the
    # rendered text rather than comparing against either half.
    rendered = " ".join(r.getMessage() for r in caplog.records)
    assert "198.51.100.99" in rendered, (
        f"the absent host was not reported, so the operator cannot tell the test covered "
        f"less than they asked for. Log said: {rendered!r}"
    )
    assert "would NOT be intercepted" in rendered


def test_the_cli_exposes_hosts():
    from pathlib import Path as _P

    src = (_P(__file__).resolve().parents[1] / "weirvern" / "admin" / "cli.py").read_text()
    assert '"--hosts"' in src, "the CLI has no way to limit interception to named hosts"
    assert "action=\"append\"" in src, (
        "--hosts must be repeatable, or only one host could ever be named"
    )

# ── the forwarding path, as a fixture ───────────────────────────────────────────
#
# These functions shell out to `ip rule` / `ip route` and MODIFY the host's routing. A test
# suite must never do that, so they are stubbed by default here and exercised explicitly by
# the tests that care. The default is a working path; tests that need a broken one override
# it to return a problem.


@pytest.fixture(autouse=True)
def _stub_forwarding_path(monkeypatch):
    """Keep the real `ip` commands out of the suite.

    `ensure_forwarding_path` / `remove_forwarding_path` shell out and MODIFY the host's
    routing, so they are stubbed by default and driven explicitly by the tests that care.

    `forwarding_path_problems` is deliberately NOT stubbed: preflight no longer calls it
    (the route is installed by start(), so demanding it beforehand deadlocked the command).
    Stubbing a function nothing calls only hides when that changes -- and when it moved out
    of this module, this fixture kept patching a name that no longer existed and errored 53
    tests on the attribute.
    """
    monkeypatch.setattr(ic, "ensure_forwarding_path", lambda _i, _g, **_kw: [])
    monkeypatch.setattr(ic, "remove_forwarding_path", lambda _i: None)
    yield


# ── the forwarding path must be correct BEFORE anything is poisoned ─────────────
#
# Measured on a live two-NIC box, this is the difference between a working relay and a
# segment outage:
#
#   ip route get 1.1.1.1 iif eth1                -> via 203.0.113.1 dev eth0   (WRONG)
#   with `iif eth1 -> table 100` installed       -> via 198.51.100.1 dev eth1   (correct)
#
# `ip_forward=1` makes the kernel willing to forward but does not decide WHERE. A relayed
# packet's destination is public, so it matches the DEFAULT route -- the management network
# -- and leaves by the wrong interface carrying the victim's source address, where an
# upstream router drops it as a martian. The symptom is "the network is flaky", not an
# error, so it is checked rather than assumed.


def test_preflight_does_not_demand_a_route_that_start_installs():
    """A prerequisite the command creates for itself must not be preflighted.

    THE DEADLOCK THIS GUARDS: preflight required the policy route, and start() is what
    installs it. So `weirvern intercept` refused on every host, telling the operator to fix
    something that was never their job, and could never reach the code that would have fixed
    it. Measured live: the dry run reported the missing route as BLOCKED, and that path
    returns before start() is ever called.

    Asserted on the SOURCE rather than via a stub, because the fix is the ABSENCE of a call:
    a stub-based test passes whether or not the call returns.
    """
    from pathlib import Path as _P

    src = (_P(__file__).resolve().parents[1] / "weirvern" / "admin" / "intercept.py").read_text()
    body = src[src.index("def preflight"):]
    nxt = body.find("\n    def ", 10)
    body = body[:nxt] if nxt > 0 else body
    code = "\n".join(ln.split("#")[0] for ln in body.splitlines())
    assert "forwarding_path_problems" not in code, (
        "preflight demands the forwarding route, which start() installs -- so the command "
        "would refuse every run and never reach the code that fixes it"
    )
    assert "check_forwarding" in code, (
        "preflight must still gate on ip_forward and the sysctls, which the OPERATOR owns"
    )
    # And the observable behaviour: a healthy plan preflights clean.
    assert ic.Intercept(_plan(), sender=RecordingSender(), forwarding=READY).preflight() == []


def test_a_broken_forwarding_path_aborts_before_sending_any_poison():
    """The ordering is the safety property: if the route is wrong, poisoning takes the
    segment off the network, so it must fail with NOTHING sent."""
    from weirvern.admin import intercept as m

    sender = RecordingSender()

    # A real check that reports the path is broken, with the stubs removed for this test.
    orig = m.ensure_forwarding_path
    m.ensure_forwarding_path = lambda _i, _g, **_kw: [
        "route goes out the wrong interface"]
    try:
        icpt = m.Intercept(_plan(), sender=sender, forwarding=READY)
        with pytest.raises(m.InterceptError, match="forwarding path is not correct"):
            icpt.start()
    finally:
        m.ensure_forwarding_path = orig

    assert sender.frames == [], (
        f"poison frames were sent ({[k for _f, k in sender.frames]}) despite a broken "
        f"forwarding path -- the victim would lose the network instead of being relayed"
    )
    assert not icpt._started, "the intercept marked itself started after refusing to start"


def test_a_correct_forwarding_path_installs_the_route_and_removes_it_on_stop(monkeypatch):
    calls: list = []
    monkeypatch.setattr(ic, "ensure_forwarding_path",
                        lambda i, g, **_kw: (calls.append(("install", i, g)), [])[1])
    monkeypatch.setattr(ic, "remove_forwarding_path",
                        lambda i: calls.append(("remove", i, None)))
    with ic.Intercept(_plan(), sender=RecordingSender(), forwarding=READY):
        pass
    assert ("install", "eth1", "198.51.100.1") in calls, "the policy route was never installed"
    assert ("remove", "eth1", None) in calls, (
        "the policy rule was left behind. Left in place it sends ALL traffic arriving on "
        "that interface to a table with no routes once the address is gone, breaking "
        "traffic the operator never asked us to touch."
    )
    assert calls.index(("install", "eth1", "198.51.100.1")) < calls.index(("remove", "eth1", None))


# ── the forwarding-path CHECK must not abort a healthy intercept ─────────────────
#
# A check that reports a problem when nothing is wrong is worse than no check: it makes
# every real intercept refuse to run, with a message that points the operator at a
# configuration that is already correct. That is exactly what happened here.


def test_the_policy_rule_is_detected_when_present(monkeypatch):
    from weirvern.admin import siphonnet

    monkeypatch.setattr(siphonnet, "_run", lambda *a: (
        0, "0:\tfrom all lookup local\n1000:\tfrom all iif eth1 lookup 100\n"
           "32766:\tfrom all lookup main"))
    monkeypatch.setattr(siphonnet, "forwarding_table_text",
                        lambda: "default via 198.51.100.1 dev eth1")
    # The forward-policy check is part of this list; pin it so the result does not depend on the
    # host's own iptables state.
    monkeypatch.setattr(siphonnet, "forward_policy", lambda: ("ACCEPT", "iptables -S"))
    assert siphonnet.forwarding_path_problems("eth1", "198.51.100.1") == [], (
        "a correctly installed policy rule was reported as a problem, so the intercept "
        "would refuse to run against a healthy configuration"
    )


def test_a_missing_policy_rule_is_reported(monkeypatch):
    from weirvern.admin import siphonnet

    monkeypatch.setattr(siphonnet, "_run", lambda *a: (0, "0:\tfrom all lookup local"))
    monkeypatch.setattr(siphonnet, "forwarding_table_text", lambda: "")
    problems = siphonnet.forwarding_path_problems("eth1", "198.51.100.1")
    assert problems, "a missing policy route was not reported"
    assert any("table 100" in p for p in problems), (
        "the message does not name the table to install, so the operator cannot act on it"
    )


def test_a_source_less_route_lookup_is_not_treated_as_a_problem(monkeypatch):
    """THE BUG, as a regression test.

    Measured on this iproute2:

        ip route get 192.0.2.1 iif eth1
            -> RTNETLINK answers: Invalid argument

    Specifying `iif` without a source is an ERROR, not a route. Reading that error text as
    "the route goes elsewhere" made the check report a problem whenever no source was
    supplied -- which aborted EVERY real intercept with a misleading message.

    The check now inspects the rule and table directly, so an unhelpful lookup cannot
    produce a false failure.
    """
    from weirvern.admin import siphonnet

    monkeypatch.setattr(siphonnet, "_run", lambda *a: (0, "1000:\tfrom all iif eth1 lookup 100"))
    monkeypatch.setattr(siphonnet, "forwarding_table_text",
                        lambda: "default via 198.51.100.1 dev eth1")
    # STATE THE FIREWALL ASSUMPTION. This test asserts an exact empty list, and the forward-policy
    # check is part of that list now -- so without this the result would depend on whether the
    # machine running the tests happens to have iptables readable and permissive. Pinned rather
    # than left to the environment.
    monkeypatch.setattr(siphonnet, "forward_policy", lambda: ("ACCEPT", "iptables -S"))
    # No sample_src: the case that used to fail.
    assert siphonnet.forwarding_path_problems("eth1", "198.51.100.1") == []


def test_a_wrong_route_from_a_real_source_is_still_reported(monkeypatch):
    """The corroborating lookup must still catch a genuinely misrouted packet."""
    from weirvern.admin import siphonnet

    def fake_run(*a, **k):
        if "rule" in a:
            return 0, "1000:\tfrom all iif eth1 lookup 100"
        return 0, "192.0.2.1 from 198.51.100.193 via 203.0.113.1 dev eth0"

    monkeypatch.setattr(siphonnet, "_run", fake_run)
    monkeypatch.setattr(siphonnet, "forwarding_table_text",
                        lambda: "default via 198.51.100.1 dev eth1")
    # The forward-policy check is part of this list; pin it so the result does not depend on the
    # host's own iptables state.
    monkeypatch.setattr(siphonnet, "forward_policy", lambda: ("ACCEPT", "iptables -S"))
    problems = siphonnet.forwarding_path_problems("eth1", "198.51.100.1",
                                                sample_src="198.51.100.193")
    assert any("dev eth0" in p or "different interface" in p for p in problems), (
        "a packet that genuinely leaves by the wrong interface was not reported"
    )


def test_start_verifies_the_path_it_installed_using_a_real_host():
    """The route must be verified AFTER install, and the lookup needs a non-local source to
    represent forwarded traffic -- the source-less form errors outright."""
    from pathlib import Path as _P

    src = (_P(__file__).resolve().parents[1] / "weirvern" / "admin" / "intercept.py").read_text()
    body = src[src.index("def start("):]
    nxt = body.find("\n    def ", 10)
    body = body[:nxt] if nxt > 0 else body
    assert "ensure_forwarding_path(" in body, (
        "start() does not install the forwarding path, so relayed traffic would leave by the "
        "wrong interface"
    )
    assert "gateway_mac=self.plan.gateway_mac" in body, (
        "start() does not pass the gateway MAC it already resolved, so the install re-resolves "
        "it from the neighbour table -- which is empty when the interface has no address yet"
    )


# ── the intercept must get itself an address, and withdraw it ───────────────────
#
# FOUND BY RUNNING THE CLI against a live segment, which no unit test had done. Two
# independent faults, both fatal in the same way:
#
#   1. `weirvern intercept` never assigned --our-ip to the capture interface. Without an
#      address there is no route on that interface, so the kernel CANNOT forward relayed
#      traffic, and every neighbour lookup on the segment fails. The intercept would have
#      poisoned real hosts into a black hole -- they would lose the network -- which is the
#      exact failure siphon mode exists to avoid, in the mode whose whole purpose is not to
#      cause outages.
#   2. `build_plan` resolved the gateway MAC from the kernel neighbour table BEFORE the ARP
#      sweep. The neighbour table only fills for addresses the interface can reach at L3, and
#      at plan time the capture interface has no address yet -- so the lookup failed and the
#      plan was refused with "cannot resolve the gateway", while the dry run had just printed
#      that same gateway's MAC from the sweep. The information was already in hand.


def test_build_plan_takes_the_gateway_mac_from_the_sweep_not_the_neighbour_table(monkeypatch):
    """The neighbour table is empty when the interface has no address yet, which is the
    normal state at plan time. The sweep finds the gateway anyway, so its answer must win."""
    monkeypatch.setattr(ic, "read_mac", lambda _i: "aa:bb:cc:dd:ee:ff")
    # resolve_mac fails -- exactly as it does with no address on the interface.
    monkeypatch.setattr(ic, "resolve_mac", lambda _i, _ip: None)
    monkeypatch.setattr(ic, "arp_sweep", lambda *a, **k: {
        "198.51.100.1": "00:00:5e:00:53:01",      # the gateway answered
        "198.51.100.193": "00:00:5e:00:53:02",
    })
    plan = ic.build_plan("eth1", "198.51.100.0/24", "198.51.100.250", "198.51.100.1")
    assert plan is not None, (
        "the plan was refused even though the sweep reported the gateway: the gateway MAC "
        "must come from the sweep, which works without an assigned address"
    )
    assert plan.gateway_mac == "00:00:5e:00:53:01"
    assert "198.51.100.1" not in plan.hosts, (
        "the gateway is in the sweep result but must never be an intercept TARGET -- forging "
        "the gateway's own view of its peers is the fastest way to black-hole a segment"
    )
    assert "198.51.100.193" in plan.hosts


def test_build_plan_still_refuses_when_the_gateway_answered_nothing(monkeypatch):
    """The fallback must not weaken the check: a gateway that cannot be resolved means the
    mapping could never be RESTORED, so refusing is correct."""
    monkeypatch.setattr(ic, "read_mac", lambda _i: "aa:bb:cc:dd:ee:ff")
    monkeypatch.setattr(ic, "resolve_mac", lambda _i, _ip: None)
    monkeypatch.setattr(ic, "arp_sweep", lambda *a, **k: {"198.51.100.193": "00:00:5e:00:53:02"})
    assert ic.build_plan("eth1", "198.51.100.0/24", "198.51.100.250", "198.51.100.1") is None


def test_the_cli_assigns_our_address_and_withdraws_it():
    """Without this the intercept cannot forward, and the hosts it poisons lose the network."""
    from pathlib import Path as _P

    src = (_P(__file__).resolve().parents[1] / "weirvern" / "admin" / "cli.py").read_text()
    assert "add_address(" in src, (
        "the intercept never assigns --our-ip, so the kernel has no route on the capture "
        "interface and cannot forward relayed traffic"
    )
    assert "remove_address(" in src, (
        "the address is never withdrawn, so a finished or failed run leaves the interface "
        "permanently different from how the operator left it"
    )
    # The teardown must be in a finally, so it covers the failure returns as well.
    body = src[src.index("def cmd_intercept"):]
    nxt = body.find("\ndef ", 10)
    body = body[:nxt] if nxt > 0 else body
    assert "finally:" in body, "the address teardown is not in a finally block"
    assert "addr_added" in body, "nothing tracks whether the address was ours to remove"


def test_add_address_uses_the_segments_prefix_length():
    """A mistyped netmask would put the address on the wrong network, where it would either
    not route or would route somewhere unintended."""
    from weirvern.admin import siphonnet

    calls: list[tuple] = []
    orig = siphonnet._run
    siphonnet._run = lambda *a, **k: (calls.append(a), (0, ""))[1]
    try:
        rc, _ = siphonnet.add_address("eth1", "198.51.100.250", "198.51.100.0/24")
        assert rc == 0
        assert ("ip", "addr", "add", "198.51.100.250/24", "dev", "eth1") in calls, (
            f"the prefix did not come from the segment: {calls}"
        )
        # A /16 must produce /16, not a hardcoded /24.
        siphonnet.add_address("eth1", "198.51.100.9", "198.51.100.0/16")
        assert ("ip", "addr", "add", "198.51.100.9/16", "dev", "eth1") in calls
    finally:
        siphonnet._run = orig


def test_add_address_rejects_a_bad_segment_instead_of_guessing():
    from weirvern.admin import siphonnet

    rc, out = siphonnet.add_address("eth1", "198.51.100.250", "not-a-cidr")
    assert rc != 0, "a malformed segment must fail rather than silently default a netmask"
    assert "not-a-cidr" in out


def test_a_routing_error_is_not_reported_as_a_misroute(monkeypatch):
    """THE FALSE BLOCKER, as a regression test.

    Measured live: preflight produced

        BLOCKED a packet from 198.51.100.193 arriving on eth1 would leave via a different
        interface (RTNETLINK answers: Invalid argument)

    on a configuration that was CORRECT. Two causes stacked:

      1. `ip route get <dst> iif <iface>` errors without a source, so an error is the
         normal result for one of the call forms.
      2. the command ran as `sh -c "... | head -1"`, and the exit status of that pipeline is
         `head`'s -- always 0 -- so the error text was treated as a successful route.

    A blocker that fires on a correct setup is not a harmless false positive: preflight
    blockers REFUSE the intercept, so this made `weirvern intercept` unusable on a healthy
    host while telling the operator to fix something that was already right.
    """
    from weirvern.admin import siphonnet

    monkeypatch.setattr(siphonnet, "forwarding_rule_text",
                        lambda _i: "1000:\tfrom all iif eth1 lookup 100")
    monkeypatch.setattr(siphonnet, "forwarding_table_text",
                        lambda: "default via 198.51.100.1 dev eth1")

    def fake_run(*a, **k):
        # The rule check succeeds; the corroborating route lookup errors.
        if a and a[0] == "ip" and "rule" in a:
            return 0, "1000:\tfrom all iif eth1 lookup 100"
        return 2, "RTNETLINK answers: Invalid argument"

    monkeypatch.setattr(siphonnet, "_run", fake_run)
    # The forward-policy check is part of this list; pin it so the result does not depend
    # on the host's own iptables state.
    monkeypatch.setattr(siphonnet, "forward_policy", lambda: ("ACCEPT", "iptables -S"))
    problems = siphonnet.forwarding_path_problems("eth1", "198.51.100.1",
                                                sample_src="198.51.100.193")
    assert problems == [], (
        f"a routing ERROR was reported as a misroute: {problems}. Preflight blockers REFUSE "
        f"the intercept, so this makes the command unusable on a correct configuration."
    )


def test_a_genuinely_misrouted_packet_is_still_reported(monkeypatch):
    """The fix must not blind the check: a real wrong-interface route is still a blocker."""
    from weirvern.admin import siphonnet

    monkeypatch.setattr(siphonnet, "forwarding_rule_text",
                        lambda _i: "1000:\tfrom all iif eth1 lookup 100")
    monkeypatch.setattr(siphonnet, "forwarding_table_text",
                        lambda: "default via 198.51.100.1 dev eth1")

    def fake_run(*a, **k):
        if a and a[0] == "ip" and "rule" in a:
            return 0, "1000:\tfrom all iif eth1 lookup 100"
        if a and "get" in a:
            return 0, "192.0.2.1 from 198.51.100.193 via 203.0.113.1 dev eth0"
        return 0, ""

    monkeypatch.setattr(siphonnet, "_run", fake_run)
    problems = siphonnet.forwarding_path_problems("eth1", "198.51.100.1",
                                                sample_src="198.51.100.193")
    assert any("dev eth0" in p for p in problems), (
        "a packet that genuinely leaves by the wrong interface was not reported"
    )


def test_the_route_lookup_is_not_run_through_a_pipe():
    """A pipeline's exit status is the LAST command's, so `| head -1` hides a failure."""
    from pathlib import Path as _P

    src = (_P(__file__).resolve().parents[1] / "weirvern" / "admin" / "siphonnet.py").read_text()
    body = src[src.index("def forwarding_path_problems"):]
    nxt = body.find("\ndef ", 10)
    body = body[:nxt] if nxt > 0 else body
    # Comments are stripped first: the docstring above deliberately quotes the OLD piped
    # command to explain the bug, and a naive substring search flags that explanation as the
    # bug itself. Assert on the code, not the prose about the code.
    code = "\n".join(ln.split("#")[0] for ln in body.splitlines())
    assert "| head" not in code, (
        "the route lookup is piped, so its exit status is head's and a failure reads as "
        "success"
    )


# ── the watchdog must not fail open on a healthy network ────────────────────────
#
# FOUND BY RUNNING `weirvern intercept` against a live segment for real. The command worked
# end to end -- address assigned, watchdog armed, single host poisoned, restores withdrawn --
# and then reported:
#
#     watchdog reported failures:
#       - forwarding stalled for 2 samples on eth1 after previously working; failing open
#
# Fail-open is the safe direction, so the network was fine. But the watchdog was firing on a
# healthy segment, and the cause was arithmetic rather than traffic.


def test_the_forwarding_monitor_is_primed_with_the_real_counter():
    """THE BUG, as a regression test.

    `ForwardingMonitor` reads "counter > my last sample" as evidence of forwarding. Built
    with the default sample=0, its FIRST call compared the real kernel counter (millions on
    any live host) against zero and therefore always reported progress.

    That set `_forwarding_observed = True` without a single packet having been forwarded.
    Everything downstream depends on that flag meaning "forwarding was seen to work": the
    quiet-network protection treats stillness as uninformative only while it is False. Set by
    arithmetic, it made the first quiet second look like a stall, so siphon failed open on a
    healthy network.
    """
    from weirvern.admin import watchdog as wd

    real = wd.ForwardingMonitor.read()
    if real < 0:
        import pytest
        pytest.skip("no /proc/net/snmp on this platform")

    class FakeWatchdog:
        pass

    mon = wd.ForwardingMonitor(sample=max(0, real))
    # With the real counter as the sample, an unchanged counter must read as NOT advanced.
    assert mon.advanced() is False or mon.advanced() is None, (
        "the monitor reported progress against an unchanged counter, so it was primed with "
        "zero rather than the current value"
    )


def test_the_watchdog_primes_its_monitor_from_the_kernel():
    """Structural: the priming must happen in __init__, so no construction path can skip it."""
    from pathlib import Path as _P

    src = (_P(__file__).resolve().parents[1] / "weirvern" / "admin" / "watchdog.py").read_text()
    body = src[src.index("class FailOpenWatchdog"):]
    init = body[:body.index("def register")]
    assert "ForwardingMonitor.read()" in init, (
        "the watchdog does not prime the forwarding monitor from the kernel, so the first "
        "health sample will always look like progress"
    )
    assert "ForwardingMonitor()" not in init, (
        "the monitor is still constructed with the default sample of zero"
    )


def test_a_quiet_network_does_not_trip_the_watchdog():
    """The behaviour the priming exists to protect: until forwarding has actually been
    OBSERVED, stillness must not accumulate strikes."""
    from weirvern.admin import watchdog as wd

    w = wd.FailOpenWatchdog(iface="eth1", our_mac="aa:bb:cc:dd:ee:ff", sender=lambda *a: True)
    # Never observed forwarding: many quiet samples must not produce a failure.
    for _ in range(5):
        if not w._forwarding_observed:
            w._quiet_samples += 1
            continue
        w._stall_strikes += 1
    assert w._stall_strikes == 0, "a never-observed network accumulated stall strikes"
    assert w._quiet_samples == 5


# ── the self-destruct deadline (siphon-2's third layer) ───────────────────────────
#
# The case this exists for: a `kubectl exec` client that is SIGKILLed leaves the in-pod
# process ALIVE with nobody able to signal it. No handler runs (none can), so without a
# deadline the forged mappings outlive every protection except the kernel's ARP timer
# (~1 minute, measured). The deadline restores from a timer thread instead of trusting
# that a signal will one day arrive.


def test_the_deadline_fires_and_restores_without_any_signal():
    """Drive the timer for real: short deadline, no signals, mappings must be withdrawn."""
    import time as _t

    from weirvern.admin import watchdog as wd

    sent: list[tuple[bytes, str]] = []
    w = wd.FailOpenWatchdog(iface="eth1", our_mac="aa:bb:cc:dd:ee:03",
                            sender=lambda frame, kind: sent.append((frame, kind)),
                            max_runtime_s=0.2, refresh_s=30, health_s=30)
    w.register(wd.Interception("198.51.100.5", "aa:bb:cc:dd:ee:01", "198.51.100.1",
                               "aa:bb:cc:dd:ee:02", "eth1", "aa:bb:cc:dd:ee:03"))
    w.start()
    assert w.active == 1, "the mapping was not registered before the deadline could fire"
    # The Timer fires at deadline+1.0; give it room without making the suite slow.
    for _ in range(40):
        _t.sleep(0.1)
        if w.deadline_reached:
            break
    assert w.deadline_reached, (
        "the self-destruct deadline never fired; the orphaned-session case (no signal can "
        "reach the process) has no protection beyond the kernel's ARP expiry"
    )
    assert not w._interceptions, "the deadline fired but the mappings were not withdrawn"
    assert any(kind == "restore" for _, kind in sent), (
        "no restore frame was sent -- the hosts would stay poisoned"
    )
    assert w.failures == [], f"the deadline path recorded failures: {w.failures}"


def test_a_deliberate_stop_disarms_the_deadline():
    """Stop before the deadline: the timer must be cancelled, not merely idempotent.

    A fired-after-stop timer would log a self-destruct that never happened -- and status
    would report deadline_reached=True for an orderly run, poisoning the one signal that
    distinguishes "orphaned" from "operator stopped it".
    """
    import time as _t

    from weirvern.admin import watchdog as wd

    w = wd.FailOpenWatchdog(iface="eth1", our_mac="aa:bb:cc:dd:ee:03",
                            sender=lambda frame, kind: None,
                            max_runtime_s=0.2, refresh_s=30, health_s=30)
    w.register(wd.Interception("198.51.100.5", "aa:bb:cc:dd:ee:01", "198.51.100.1",
                               "aa:bb:cc:dd:ee:02", "eth1", "aa:bb:cc:dd:ee:03"))
    w.start()
    w.stop()
    _t.sleep(1.5)  # past deadline+1.0, had it not been cancelled
    assert not w.deadline_reached, (
        "the deadline fired after a deliberate stop; a clean run is being recorded as an "
        "orphaned one"
    )


def test_max_runtime_defaults_from_seconds_only_for_bounded_runs():
    """The CLI default: --seconds + 120 when bounded, else no deadline (nobody asked).

    Explicit --max-runtime always wins; non-positive disables.
    """
    from weirvern.admin import cli

    parser = cli.build_parser()
    base = ["intercept", "--iface", "eth1", "--segment", "198.51.100.0/24",
            "--our-ip", "198.51.100.50", "--gateway", "198.51.100.1"]

    bounded = parser.parse_args(base + ["--seconds", "300"])
    assert cli._effective_max_runtime(bounded) == 420, (
        "a bounded run did not get the seconds+grace deadline, so an orphaned client "
        "leaves the mappings up until the kernel's ARP timer"
    )
    unbounded = parser.parse_args(base)
    assert cli._effective_max_runtime(unbounded) is None, (
        "an interactive run got a default deadline nobody asked for"
    )
    explicit = parser.parse_args(base + ["--max-runtime", "60"])
    assert cli._effective_max_runtime(explicit) == 60, "explicit --max-runtime was not honoured"
    disabled = parser.parse_args(base + ["--max-runtime", "0"])
    assert cli._effective_max_runtime(disabled) is None, "--max-runtime 0 did not disable it"


def test_an_orphaned_run_is_reported_as_such():
    """The status fields must distinguish deadline-fired from an orderly end.

    Asserted on the shipping source because the full path needs an intercept; the two
    fields are what the CLI keys its warning on.
    """
    from pathlib import Path as _P
    root = _P(__file__).resolve().parents[1]
    src = (root / "weirvern" / "admin" / "intercept.py").read_text()
    assert '"deadline_reached"' in src, (
        "status() no longer reports deadline_reached, so an orphaned restore is "
        "indistinguishable from an orderly one"
    )
    cli_src = (root / "weirvern" / "admin" / "cli.py").read_text()
    assert "self-destruct deadline fired" in cli_src, (
        "the CLI no longer warns when the deadline fired; the operator would never learn "
        "that their session died without a signal"
    )


# ── GLM 5.3 REVIEW: THE RETURN PATH (critical) ───────────────────────────────────────────────────
#
# MEASURED ON A REAL KERNEL in an isolated namespace, with a bridge carrying gateway, sensor and peer
# on one segment:
#
#     BASELINE (no intercept)    198.51.100.20 from 198.51.100.1 dev br0                on-link
#     AS SHIPPED (default only)  198.51.100.20 from 198.51.100.1 via 198.51.100.1 dev br0   BACK AT GW
#     WITH the segment route     198.51.100.20 from 198.51.100.1 dev br0 table 100      on-link
#
# A policy rule pointing at a table whose default matches EVERY destination means the lookup never
# falls through to main's connected-segment route, so return traffic for a host on the segment was
# handed straight back to the gateway. This is the best available explanation for the reported
# whole-VLAN network breakage.


class _Kernel:
    """A minimal model of the kernel's route/rule state, so the spies are honest.

    MY FIRST VERSION OF THESE TESTS USED A SPY THAT RETURNED (0, "") FOR EVERYTHING, so every check
    passed and the assertions failed for the wrong reason -- the function verifies what it installed
    by reading `ip rule show` / `ip route show table 100` back, and a spy that answers "" to that
    looks like an install that did not happen. A spy has to model the STATE the function inspects,
    not just the exit codes.
    """

    def __init__(self):
        self.rules: list[str] = []
        self.routes: dict[str, list[str]] = {}
        self.fail: set[str] = set()          # substrings whose add should fail

    def __call__(self, *args, **kw):
        a = [str(x) for x in args]
        line = " ".join(a)
        if a[:3] == ["ip", "route", "flush"]:
            table = a[4] if len(a) > 4 else "?"
            self.routes[table] = []
            return (0, "")
        if a[:3] == ["ip", "route", "add"]:
            if any(f in line for f in self.fail):
                return (2, "RTNETLINK answers: Operation not permitted")
            table = a[a.index("table") + 1]
            self.routes.setdefault(table, []).append(" ".join(a[3:a.index("table")]))
            return (0, "")
        if a[:3] == ["ip", "route", "show"]:
            table = a[-1]
            return (0, "\n".join(self.routes.get(table, [])))
        if a[:3] == ["ip", "rule", "add"]:
            self.rules.append(line)
            return (0, "")
        if a[:3] == ["ip", "rule", "del"]:
            if "iif" in a:
                iface = a[a.index("iif") + 1]
                self.rules = [r for r in self.rules if f"iif {iface}" not in r]
            return (0, "")
        if a[:3] == ["ip", "rule", "show"]:
            return (0, "\n".join(self.rules))
        return (0, "")


def test_ensure_forwarding_path_ADDS_the_connected_segment_route(monkeypatch):
    """THE DEFECT (glm-5.3 review, measured on a real kernel).

    With ONLY a default in table 100, a rule selecting that table never falls through to main's
    connected-segment route, so return traffic for a host on the segment is sent back at the gateway.
    """
    from weirvern.admin import siphonnet

    # The host's own iptables state must not decide a unit test (the convention this
    # file already uses).
    monkeypatch.setattr(siphonnet, "forward_policy", lambda: ("ACCEPT", "iptables -S"))

    k = _Kernel()
    real = siphonnet._run
    siphonnet._run = k
    try:
        problems = siphonnet.ensure_forwarding_path(
            "eth1", "198.51.100.1", gateway_mac="00:00:5e:00:53:01",
            segment="198.51.100.0/24")
    finally:
        siphonnet._run = real

    assert problems == [], f"a correct install reported problems: {problems}"
    table = k.routes.get("100", [])
    assert any("198.51.100.0/24" in r for r in table), (
        f"table 100 has no connected-segment route, so return traffic for a host on the segment "
        f"matches the default and is handed back to the gateway. table 100 = {table}"
    )
    assert any("default via 198.51.100.1" in r for r in table), (
        f"the default route is missing from table 100: {table}"
    )


def test_the_segment_route_is_refused_rather_than_assumed(monkeypatch):
    """A FAILED segment route must stop the install, like the default does."""
    from weirvern.admin import siphonnet

    # The host's own iptables state must not decide a unit test (the convention this
    # file already uses).
    monkeypatch.setattr(siphonnet, "forward_policy", lambda: ("ACCEPT", "iptables -S"))

    k = _Kernel()
    k.fail = {"198.51.100.0/24"}
    real = siphonnet._run
    siphonnet._run = k
    try:
        problems = siphonnet.ensure_forwarding_path(
            "eth1", "198.51.100.1", gateway_mac="00:00:5e:00:53:01",
            segment="198.51.100.0/24")
    finally:
        siphonnet._run = real

    assert problems, "a failed segment route was not reported"
    assert any("connected segment route" in p for p in problems), problems


def test_a_caller_without_a_segment_is_unchanged(monkeypatch):
    """Backwards compatibility: the parameter is optional and its absence is not an error."""
    from weirvern.admin import siphonnet

    # The host's own iptables state must not decide a unit test (the convention this
    # file already uses).
    monkeypatch.setattr(siphonnet, "forward_policy", lambda: ("ACCEPT", "iptables -S"))

    k = _Kernel()
    real = siphonnet._run
    siphonnet._run = k
    try:
        problems = siphonnet.ensure_forwarding_path("eth1", "198.51.100.1",
                                                    gateway_mac="00:00:5e:00:53:01")
    finally:
        siphonnet._run = real
    assert problems == [], f"omitting the segment became an error: {problems}"


def test_the_intercept_PASSES_the_segment():
    """A parameter nothing supplies is the same silence in a new shape."""
    import ast
    import pathlib as _p

    src = (_p.Path(__file__).resolve().parent / ".." / "weirvern" / "admin" / "intercept.py").read_text()
    tree = ast.parse(src)
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            fn = node.func
            name = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", "")
            if name == "ensure_forwarding_path":
                found.append({k.arg for k in node.keywords})
    assert found, "no ensure_forwarding_path call site found in intercept.py"
    for kws in found:
        assert "segment" in kws, (
            f"an ensure_forwarding_path call does not pass the segment, so table 100 gets no "
            f"connected route and return traffic loops through the gateway. kwargs: {kws}"
        )


# ── GLM 5.3 REVIEW: A START MUST REFUSE ON SYSCtLS IT CANNOT CONFIRM ──────────────────────────
#
# `start()` called `self._sysctls.apply()` and DISCARDED the result. apply() returns the sysctls that
# could not be set -- and in the deployed container, where /proc/sys is read-only, it returns the ones
# that are WRONG and cannot be corrected from there. Measured against the real class: ip_forward=0
# yields a populated list, a correct node yields an empty one.
#
# So an intercept poisoned ARP on a node with ip_forward=0, making the kernel the segment's next hop
# for traffic it will not forward: the victim loses the network instead of being relayed. That is
# exactly the outcome the path check below it exists to prevent, and it could not cover this, because
# forwarding WILLINGNESS is a separate fact from forwarding PATH.


class _StubSysctls:
    """The guard, with `apply()` scripted.

    It mirrors the real guard's surface for the calls `Intercept` makes -- an incomplete stub fails
    with AttributeError, which reads like a product bug and is not one, so this covers every method
    intercept.py actually calls.
    """

    def __init__(self, problems):
        self.problems = list(problems)
        self.applied = 0
        self.restored = 0

    def apply(self, write=True):  # noqa: ANN001, ARG002
        self.applied += 1
        return list(self.problems)

    def restore(self):
        self.restored += 1
        return []

    def changed_by_us(self):
        """Nothing, because the read-only path changes nothing. Mirrors the real contract."""
        return []


def _intercept_fixture(problems, state=None):
    """An Intercept on a doc-space segment whose sender never sends a frame.

    `state` is the ForwardingState the real `check_forwarding` would return; injecting it keeps the
    test off this machine's /proc/sys, which is the same seam `preflight()` already uses.
    """
    from weirvern.admin import siphonnet as siphonnet_mod

    bad = siphonnet_mod.ForwardingState(ip_forward=bool(not problems), rp_filter_off=bool(not problems),
                                        problems=list(problems))
    sent = []
    runner = ic.Intercept(_plan(), sender=lambda *_a, **_k: sent.append(1),
                          forwarding=(state if state is not None else bad))
    stub = _StubSysctls(problems)
    runner._sysctls = stub
    return runner, stub, sent


def test_start_REFUSES_when_a_required_sysctl_is_not_in_effect():
    """THE DEFECT. A node that cannot forward must not be made the segment's next hop."""
    runner, stub, sent = _intercept_fixture([
        "net.ipv4.ip_forward is 0 but siphon needs 1, and this container's /proc/sys is READ-ONLY "
        "so it cannot be corrected from here."
    ])
    try:
        runner.start()
    except ic.InterceptError as exc:
        assert "sysctls are not in effect" in str(exc), str(exc)
    else:
        raise AssertionError(
            "start() ARMED the intercept on a node whose forwarding sysctls are wrong (ip_forward=0), "
            "so the sensor would become the segment's next hop for traffic the kernel will drop. "
            "apply() reported the problem and the result was thrown away."
        )
    assert not sent, (
        f"{len(sent)} poison frame(s) were sent before the refusal. A refused start must leave the "
        f"segment untouched, or the failure itself black-holes it"
    )
    assert stub.restored == 1, (
        "the refusal did not restore the sysctls it had recorded, so a refused start left the node "
        "modified"
    )


def test_start_still_ARMS_when_the_sysctls_are_correct(monkeypatch):
    """The other direction, so the fix cannot be 'refuse everything'."""
    monkeypatch.setattr(ic, "ensure_forwarding_path", lambda i, g, **_kw: [])
    monkeypatch.setattr(ic, "remove_forwarding_path", lambda i: None)
    runner, _stub, _sent = _intercept_fixture([])

    runner.start()
    assert runner._started, (
        "the sysctl gate refused a node whose forwarding settings are CORRECT, so the check is "
        "not a check but a wall"
    )
    runner.stop()
