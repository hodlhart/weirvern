"""Tests for the in-path intercept dataplane (weir mode).

The properties that matter here are safety properties, not features. In weir mode Weirvern
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
from weirvern.admin import weirnet
from weirvern.admin.weirnet import ForwardingState

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
        segment="192.168.3.0/24",
        our_mac="aa:bb:cc:dd:ee:ff",
        our_ip="192.168.3.50",
        gateway_ip="192.168.3.1",
        gateway_mac="11:22:33:44:55:66",
        hosts=hosts if hosts is not None else {
            "192.168.3.10": "0a:0a:0a:0a:0a:0a",
            "192.168.3.11": "0b:0b:0b:0b:0b:0b",
        },
    )


READY = ForwardingState(ip_forward=True, rp_filter_off=True)


# ── CIDR parsing ────────────────────────────────────────────────────────────────


def test_cidr_lists_usable_hosts_only():
    hosts = ic.parse_cidr("192.168.3.0/24")
    assert len(hosts) == 254
    assert "192.168.3.1" in hosts
    assert "192.168.3.0" not in hosts, "the network address is not a host"
    assert "192.168.3.255" not in hosts, "the broadcast address is not a host"


def test_a_huge_segment_is_refused_rather_than_attempted():
    """Poisoning 65k hosts is not something anyone means to do by accident."""
    with pytest.raises(ValueError, match="1024"):
        ic.parse_cidr("10.0.0.0/16")


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
    assert ("192.168.3.10", "192.168.3.1") in claims, "host -> gateway direction missing"
    assert ("192.168.3.1", "192.168.3.10") in claims, "gateway -> host direction missing"


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
    assert "192.168.3.0/24" in text
    assert "192.168.3.1" in text
    assert "192.168.3.10" in text


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
    """"Intercepting nothing" is how a weir deployment silently looks broken."""
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
        assert st["segment"] == "192.168.3.0/24"
    finally:
        runner.stop()


# ── sysctl reads ────────────────────────────────────────────────────────────────


def test_sysctl_path_maps_dots_to_slashes():
    assert str(weirnet.sysctl_path("net.ipv4.ip_forward")) == \
        "/proc/sys/net/ipv4/ip_forward"
    assert str(weirnet.sysctl_path("net.ipv4.conf.all.rp_filter")) == \
        "/proc/sys/net/ipv4/conf/all/rp_filter"


def test_check_forwarding_does_not_crash_on_a_read_failure(monkeypatch):
    """`cannot tell` must not be reported as `forwarding is fine`.

    Conflating those is how a watchdog either never fires or fires constantly.
    """
    monkeypatch.setattr(weirnet, "read_sysctl", lambda _name: None)
    state = weirnet.check_forwarding("eth1")
    assert not state.ready
    assert state.problems


def test_check_forwarding_accepts_a_correct_configuration(monkeypatch):
    values = {
        "net.ipv4.ip_forward": 1,
        "net.ipv4.conf.all.rp_filter": 0,
        "net.ipv4.conf.eth1.rp_filter": 0,
    }
    monkeypatch.setattr(weirnet, "read_sysctl", lambda name: values.get(name))
    state = weirnet.check_forwarding("eth1")
    assert state.ready, state.problems


# ── MAC resolution ──────────────────────────────────────────────────────────────


def test_read_neighbour_mac_ignores_incomplete_entries(tmp_path, monkeypatch):
    """A MAC of all zeros means unresolved; returning it would forge a mapping to nobody."""
    arp = tmp_path / "arp"
    arp.write_text(
        "IP address       HW type     Flags       HW address            Mask     Device\n"
        "192.168.3.10     0x1         0x2         aa:bb:cc:dd:ee:01     *        eth1\n"
        "192.168.3.11     0x1         0x0         00:00:00:00:00:00     *        eth1\n"
    )
    body = arp.read_text()          # capture BEFORE patching, or this recurses
    monkeypatch.setattr(weirnet.Path, "read_text", lambda self: body)
    assert weirnet.read_neighbour_mac("eth1", "192.168.3.10") == "aa:bb:cc:dd:ee:01"
    assert weirnet.read_neighbour_mac("eth1", "192.168.3.11") is None


def test_read_mac_returns_none_for_a_missing_interface(monkeypatch):
    monkeypatch.setattr(weirnet.Path, "read_text",
                        lambda self: (_ for _ in ()).throw(OSError()))
    assert weirnet.read_mac("nosuchiface") is None


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
    monkeypatch.setattr(weirnet, "read_mac", lambda _i: "aa:bb:cc:dd:ee:ff")
    monkeypatch.setattr(ic, "arp_sweep", lambda *a, **k: {})
    free = weirnet.find_free_addresses("eth1", "192.168.3.0/24", "192.168.3.5", count=3)
    assert free == ["192.168.3.254", "192.168.3.253", "192.168.3.252"], free


def test_an_address_that_answered_arp_is_not_offered(monkeypatch):
    """Offering an in-use address would cause a conflict on the operator's network."""
    monkeypatch.setattr(weirnet, "read_mac", lambda _i: "aa:bb:cc:dd:ee:ff")
    monkeypatch.setattr(ic, "arp_sweep",
                        lambda *a, **k: {"192.168.3.254": "de:ad:be:ef:00:01"})
    free = weirnet.find_free_addresses("eth1", "192.168.3.0/24", "192.168.3.5", count=2)
    assert "192.168.3.254" not in free, "a taken address was offered as free"
    assert free == ["192.168.3.253", "192.168.3.252"]


def test_the_source_address_is_never_offered(monkeypatch):
    monkeypatch.setattr(weirnet, "read_mac", lambda _i: "aa:bb:cc:dd:ee:ff")
    monkeypatch.setattr(ic, "arp_sweep", lambda *a, **k: {})
    free = weirnet.find_free_addresses("eth1", "192.168.3.0/24", "192.168.3.254", count=1)
    assert "192.168.3.254" not in free, "offered the address we are already using"


def test_no_mac_means_no_offer_rather_than_a_guess(monkeypatch):
    monkeypatch.setattr(weirnet, "read_mac", lambda _i: None)
    assert weirnet.find_free_addresses("eth1", "192.168.3.0/24", "192.168.3.5") == []


def test_describe_segment_reports_the_blast_radius(monkeypatch):
    """Every host listed is one whose ARP cache would be forged."""
    monkeypatch.setattr(weirnet, "read_mac", lambda _i: "aa:bb:cc:dd:ee:ff")
    monkeypatch.setattr(ic, "arp_sweep", lambda *a, **k: {
        "192.168.3.10": "0a:0a:0a:0a:0a:0a",
        "192.168.3.11": "0b:0b:0b:0b:0b:0b",
    })
    used, err = weirnet.describe_segment("eth1", "192.168.3.0/24", "192.168.3.5")
    assert not err
    assert len(used) == 2


def test_describe_segment_refuses_an_enormous_sweep(monkeypatch):
    monkeypatch.setattr(weirnet, "read_mac", lambda _i: "aa:bb:cc:dd:ee:ff")
    used, err = weirnet.describe_segment("eth1", "10.0.0.0/16", "10.0.0.5")
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
# 192.168.3.0/24 with ELEVEN hosts: the kernel-table version found 0, parsing the socket
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
    assert "range(0, len(targets), 32)" in body, (
        "the sweep does not batch its sends, so most replies will be dropped"
    )
    assert "sock.settimeout" in body, (
        "no socket timeout: a recv loop without one blocks forever on a quiet segment"
    )


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
        "192.168.3.10": "0a:0a:0a:0a:0a:0a",
        "192.168.3.11": "0b:0b:0b:0b:0b:0b",
        "192.168.3.12": "0c:0c:0c:0c:0c:0c",
    })
    plan = ic.build_plan("eth1", "192.168.3.0/24", "192.168.3.50", "192.168.3.1",
                         only={"192.168.3.10"})
    assert plan is not None
    assert set(plan.hosts) == {"192.168.3.10"}, (
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
        "192.168.3.10": "0a:0a:0a:0a:0a:0a",
    })
    with caplog.at_level("WARNING"):
        plan = ic.build_plan("eth1", "192.168.3.0/24", "192.168.3.50", "192.168.3.1",
                             only={"192.168.3.10", "192.168.3.99"})
    assert plan is not None
    assert set(plan.hosts) == {"192.168.3.10"}
    # caplog records the raw format string in .message with args in .args, so build the
    # rendered text rather than comparing against either half.
    rendered = " ".join(r.getMessage() for r in caplog.records)
    assert "192.168.3.99" in rendered, (
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
