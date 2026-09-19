"""Sensor modes, and the watchdog that makes in-path intercept defensible.

The mode names are Weirvern's own: a weir is a barrier water flows THROUGH, so the
in-path mode is `weir` and the still-water observer is `loch`.

The tests that matter most here are about SAFETY, not features: weir mode must refuse
to enable without the pieces that make it fail open, and the watchdog must actually
restore the ARP caches it poisoned. A monitoring tool that takes the LAN down when it
stops is worse than no monitoring tool, so these are asserted rather than assumed.
"""
from __future__ import annotations

import struct
import time

import pytest

from weirvern.admin import mode as mode_mod
from weirvern.admin import watchdog as wd


# --- naming --------------------------------------------------------------------
def test_the_two_modes_are_named_after_the_product():
    """Weirvern's own vocabulary, not generic networking terms.

    The names encode the difference that matters: `weir` is in-path (traffic passes
    through, and the failure mode is an outage), `loch` is passive (still water, you
    watch without impeding).
    """
    assert mode_mod.MODE_LOCH == "loch"
    assert mode_mod.MODE_WEIR == "weir"


def test_an_undefined_mode_is_rejected():
    """Only `loch` and `weir` are modes. An unrecognised value must be reported rather
    than silently coerced into one of them, because coercing it would pick a behaviour
    the operator did not ask for."""
    assert mode_mod.normalise("nonsense") == "nonsense", "unknown values pass through"
    v = mode_mod.validate("nonsense")
    assert not v.ok
    assert any("unknown sensor mode" in b for b in v.blockers)
    assert "unknown mode" in v.summary()


def test_the_default_mode_is_the_safe_one():
    """A fresh install must never default into an in-path configuration."""
    assert mode_mod.DEFAULT_MODE == mode_mod.MODE_LOCH
    assert mode_mod.normalise("") == mode_mod.MODE_LOCH


@pytest.mark.parametrize("typed,expected", [
    ("loch", "loch"), ("LOCH", "loch"), ("Loch", "loch"),
    ("weir", "weir"), ("WEIR", "weir"),
    # Mechanism words are accepted on input so an operator reaching for the familiar
    # term is not punished, but they store as the product's name.
    ("promisc", "loch"), ("passive", "loch"), ("span", "loch"), ("mirror", "loch"),
    ("tap", "loch"),
    ("intercept", "weir"), ("arp", "weir"), ("spoof", "weir"), ("inline", "weir"),
])
def test_mode_input_is_tolerant_but_storage_uses_product_names(typed, expected):
    assert mode_mod.normalise(typed) == expected


def test_each_mode_states_its_failure_mode():
    """The operator cannot infer the blast radius from the word 'weir'. It is stated."""
    assert "monitoring gap" in mode_mod.IMPACT[mode_mod.MODE_LOCH]
    assert "outage" in mode_mod.IMPACT[mode_mod.MODE_WEIR].lower()
    assert "loch — " in mode_mod.describe("loch")
    assert "weir — " in mode_mod.describe("weir")


# --- gating --------------------------------------------------------------------
def test_loch_mode_has_no_blockers():
    """Passive capture cannot break the network, so nothing should stop it."""
    v = mode_mod.validate(mode_mod.MODE_LOCH)
    assert v.ok and not v.blockers


def test_weir_mode_is_blocked_without_all_three_prerequisites():
    """The asymmetry is deliberate: loch failing is a gap, weir failing is an outage."""
    v = mode_mod.validate(mode_mod.MODE_WEIR)
    assert not v.ok
    joined = " ".join(v.blockers)
    assert "CAP_NET_RAW" in joined
    assert "CAP_NET_ADMIN" in joined
    assert "watchdog" in joined


def test_weir_mode_enables_when_everything_is_present():
    v = mode_mod.validate(mode_mod.MODE_WEIR, has_net_admin=True, has_net_raw=True,
                          watchdog_available=True)
    assert v.ok, v.blockers
    assert not v.blockers
    # Even when enabled it must warn about the sysctls and the authorisation boundary.
    joined = " ".join(v.warnings)
    assert "rp_filter" in joined
    assert "send_redirects" in joined
    assert "authorised" in joined


def test_weir_mode_requires_net_admin_specifically():
    """The passive sensor deliberately lacks NET_ADMIN. Enabling weir widens the
    container's privileges, which must be stated rather than done silently."""
    v = mode_mod.validate(mode_mod.MODE_WEIR, has_net_raw=True, watchdog_available=True)
    assert not v.ok
    assert any("CAP_NET_ADMIN" in b for b in v.blockers)
    assert any("privileges" in b for b in v.blockers)


@pytest.mark.parametrize("name,want", [
    ("net.ipv4.ip_forward", "1"),
    ("net.ipv4.conf.all.rp_filter", "0"),
    ("net.ipv4.conf.all.send_redirects", "0"),
])
def test_every_required_sysctl_has_a_named_symptom(name, want):
    """Each setting was verified necessary in a sandbox, and each has a specific
    symptom when missing. A bare list of settings would not be actionable."""
    entries = {n: (w, s) for n, w, s in mode_mod.REQUIRED_SYSCTLS}
    assert name in entries
    got_want, symptom = entries[name]
    assert got_want == want
    assert len(symptom) > 40, f"{name} needs a real explanation, got: {symptom!r}"


def test_the_never_intercept_list_protects_management_paths():
    """Spoofing the sensor's own gateway or the cluster API would break the tool with
    the tool — the failure is self-inflicted and total."""
    joined = " ".join(mode_mod.NEVER_INTERCEPT).lower()
    for danger in ("gateway", "own address", "kubernetes", "dns"):
        assert danger in joined, f"{danger} must be listed as never-intercept"


# --- ARP frame construction ----------------------------------------------------
def test_poison_frame_claims_our_mac_for_the_claimed_ip():
    """The poison must be an ANNOUNCEMENT (ARP request), not a reply.

    MEASURED against a real host on a live segment, each form sent 8 times, reading the
    destination MAC of the host's reply to an off-link probe:

        forged ARP reply, unicast    ->  ignored  (traffic still went to the real gateway)
        forged ARP REQUEST, unicast  ->  TOOK     (traffic came to us, 3/3)
        gratuitous broadcast reply   ->  ignored

    Linux does not update a neighbour entry in REACHABLE state from an unsolicited reply,
    and a host's gateway entry is always reachable -- so the reply form was silently
    discarded while being perfectly well formed. That is why every live attempt concluded
    "the poison never took": it genuinely never did.

    This test previously asserted opcode 2 ("must be an ARP reply"), encoding the wrong
    assumption. It is updated to the measured behaviour, not relaxed to pass.
    """
    ic = wd.Interception(host_ip="198.51.100.5", host_mac="aa:bb:cc:dd:ee:01",
                         claim_ip="198.51.100.1", real_mac="aa:bb:cc:dd:ee:02",
                         iface="eth1", our_mac="aa:bb:cc:dd:ee:03")
    frame = ic.poison_frame()
    # Ethernet: dst is the host, src is us, ethertype ARP.
    assert frame[0:6] == bytes.fromhex("aabbccddee01")
    assert frame[6:12] == bytes.fromhex("aabbccddee03")
    assert struct.unpack("!H", frame[12:14])[0] == 0x0806
    assert struct.unpack("!H", frame[20:22])[0] == 1, (
        "must be an ARP REQUEST: a reply is ignored for a REACHABLE entry, so it would "
        "never install the mapping"
    )
    # "claim_ip is at OUR mac" — the lie we are telling. In a request this rides in the
    # SENDER fields, which is what makes it an announcement the target records.
    assert frame[22:28] == bytes.fromhex("aabbccddee03")
    assert frame[28:32] == bytes.fromhex("c6336401")   # 198.51.100.1
    # The target field is the host we are asking about; its MAC is left zero because the
    # request asks "who-has", and a fabricated answer there would be a false claim.
    assert frame[32:38] == b"\x00" * 6
    assert frame[38:42] == bytes.fromhex("c6336405")   # 198.51.100.5


def test_restore_frame_tells_the_truth():
    """The restore names the REAL mac, and uses the same frame form as the poison.

    Same form deliberately: the announcement installs a mapping regardless of the entry's
    state, and the restore is the safety property — the wrong place to rely on a state
    distinction going the right way while a network is in the state we are trying to fix.
    """
    ic = wd.Interception(host_ip="198.51.100.5", host_mac="aa:bb:cc:dd:ee:01",
                         claim_ip="198.51.100.1", real_mac="aa:bb:cc:dd:ee:02",
                         iface="eth1", our_mac="aa:bb:cc:dd:ee:03")
    frame = ic.restore_frame()
    assert frame[22:28] == bytes.fromhex("aabbccddee02"), "must name the real owner"
    assert frame[28:32] == bytes.fromhex("c6336401")
    assert frame[0:6] == bytes.fromhex("aabbccddee01"), "still addressed to the host"
    assert struct.unpack("!H", frame[20:22])[0] == 1, (
        "the restore must use the form that provably installs a mapping"
    )
    # The Ethernet source must be the real owner's MAC, because that is the frame's actual
    # origin: a frame whose Ethernet source disagreed with its ARP sender field would be
    # inconsistent, and some stacks drop those.
    assert frame[6:12] == bytes.fromhex("aabbccddee02")


def test_the_restore_is_never_sent_as_an_arp_reply():
    """A guard on the specific regression: someone 'restoring' the reply form because it
    looks more like a correction, reintroducing the bug that made interception a no-op."""
    ic = wd.Interception(host_ip="198.51.100.5", host_mac="aa:bb:cc:dd:ee:01",
                         claim_ip="198.51.100.1", real_mac="aa:bb:cc:dd:ee:02",
                         iface="eth1", our_mac="aa:bb:cc:dd:ee:03")
    for name, frame in (("poison", ic.poison_frame()), ("restore", ic.restore_frame())):
        op = struct.unpack("!H", frame[20:22])[0]
        assert op == 1, (
            f"the {name} frame is an ARP reply (opcode 2). Measured: a reply is ignored "
            f"for a REACHABLE neighbour entry, so this frame would silently do nothing."
        )


def test_poison_and_restore_differ_only_in_the_macs_they_name():
    """A restore that differed structurally would be a different kind of packet and
    might not be accepted as a correction.

    TWO regions legitimately differ: the ARP sender MAC (bytes 22-27, the lie vs the
    truth) AND the Ethernet source MAC (bytes 6-11, which must also be the frame's actual
    origin). Everything else — the destination, the ethertype, the opcode, the addresses
    and lengths — must be identical or the frame is a different class of packet.
    """
    ic = wd.Interception(host_ip="198.51.100.5", host_mac="aa:bb:cc:dd:ee:01",
                         claim_ip="198.51.100.1", real_mac="aa:bb:cc:dd:ee:02",
                         iface="eth1", our_mac="aa:bb:cc:dd:ee:03")
    a, b = ic.poison_frame(), ic.restore_frame()
    assert len(a) == len(b)
    diff = [i for i in range(len(a)) if a[i] != b[i]]
    allowed = set(range(6, 12)) | set(range(22, 28))
    assert all(i in allowed for i in diff), (
        f"differences outside the two MAC fields: "
        f"{[i for i in diff if i not in allowed]}"
    )
    # And the fields that decide how the packet is INTERPRETED must not move.
    assert a[0:6] == b[0:6], "destination MAC must be unchanged"
    assert a[12:22] == b[12:22], "ethertype, opcode, and lengths must be unchanged"
    assert a[28:32] == b[28:32], "the claimed IP must be unchanged"


# --- the watchdog's safety behaviour -------------------------------------------
class FakeSender:
    def __init__(self, fail_on=()):
        self.sent: list[bytes] = []
        self.fail_on = fail_on

    def __call__(self, frame: bytes, kind: str = "poison") -> None:
        # `kind` is part of the sender contract: _send forwards it so a sender can tell a
        # restore from a refresh from a poison. Signature updated when that forwarding was
        # fixed -- before that, every frame arrived as the default and the distinction was
        # silently lost.
        if len(self.sent) in self.fail_on:
            raise OSError("simulated send failure")
        self.sent.append(frame)


def _watchdog(sender=None, **kw) -> wd.FailOpenWatchdog:
    return wd.FailOpenWatchdog("eth1", "aa:bb:cc:dd:ee:03", sender=sender, **kw)


def test_stop_restores_every_mapping():
    """THE core safety property: what was poisoned must be corrected."""
    s = FakeSender()
    w = _watchdog(s)
    ic = wd.Interception("198.51.100.5", "aa:bb:cc:dd:ee:01", "198.51.100.1",
                         "aa:bb:cc:dd:ee:02", "eth1", "aa:bb:cc:dd:ee:03")
    w.register(ic)
    w.stop()
    assert len(s.sent) == 1
    assert s.sent[0] == ic.restore_frame(), "the frame sent must be the truthful one"
    assert w.active == 0
    assert w.restored_count == 1


def test_stop_is_idempotent():
    """Called from a signal handler and then from cleanup, it must not double-restore
    or raise."""
    s = FakeSender()
    w = _watchdog(s)
    w.register(wd.Interception("198.51.100.5", "aa:bb:cc:dd:ee:01", "198.51.100.1",
                               "aa:bb:cc:dd:ee:02", "eth1", "aa:bb:cc:dd:ee:03"))
    w.stop()
    first = len(s.sent)
    w.stop()
    w.stop()
    assert len(s.sent) == first, "further stops must not resend"


def test_stop_with_nothing_registered_is_harmless():
    w = _watchdog(FakeSender())
    w.stop()
    assert w.active == 0


def test_a_send_failure_during_restore_is_recorded_not_swallowed():
    """A failed restore means a host may still believe we are the gateway — the most
    dangerous possible error state, so it must be visible."""
    s = FakeSender(fail_on=(0,))          # the very first (restore) send fails
    w = _watchdog(s)
    w.register(wd.Interception("198.51.100.5", "aa:bb:cc:dd:ee:01", "198.51.100.1",
                               "aa:bb:cc:dd:ee:02", "eth1", "aa:bb:cc:dd:ee:03"))
    w.stop()
    assert w.failures, "a failed restore must be recorded"
    assert any("restore send failed" in f for f in w.failures)


def test_the_refresh_loop_reasserts_the_poison():
    """ARP entries age out, so a one-shot spoof stops working after a few minutes and
    the intercept silently reverts to passive."""
    s = FakeSender()
    w = _watchdog(s, refresh_s=0.05)
    ic = wd.Interception("198.51.100.5", "aa:bb:cc:dd:ee:01", "198.51.100.1",
                         "aa:bb:cc:dd:ee:02", "eth1", "aa:bb:cc:dd:ee:03")
    w.register(ic)
    w.start()
    time.sleep(0.3)
    w.stop()
    assert w.refresh_count >= 1, "the poison was never re-asserted"
    assert w.refresh_count >= 2, f"expected repeated refresh, got {w.refresh_count}"


def test_restore_is_not_undone_by_the_refresh_loop():
    """THE ORDERING BUG THIS GUARDS: if the refresh loop is still running when we
    restore, it re-poisons the caches immediately afterwards — leaving the network
    broken while the tool reports success.

    Checked by asserting that the LAST frame sent is a restore frame, and that no
    poison frame appears after it.
    """
    s = FakeSender()
    w = _watchdog(s, refresh_s=0.05)
    ic = wd.Interception("198.51.100.5", "aa:bb:cc:dd:ee:01", "198.51.100.1",
                         "aa:bb:cc:dd:ee:02", "eth1", "aa:bb:cc:dd:ee:03")
    w.register(ic)
    w.start()
    time.sleep(0.25)
    w.stop()
    restored_at = len(s.sent) - 1
    # Give any surviving loop thread a chance to misbehave.
    time.sleep(0.25)
    after = s.sent[restored_at + 1:]
    assert not after, (
        f"{len(after)} frame(s) were sent AFTER the restore, so the caches were "
        f"re-poisoned and the network was left broken"
    )
    assert s.sent[restored_at] == ic.restore_frame()


def test_unregister_restores_just_that_host():
    s = FakeSender()
    w = _watchdog(s)
    a = wd.Interception("198.51.100.5", "aa:bb:cc:dd:ee:01", "198.51.100.1",
                        "aa:bb:cc:dd:ee:02", "eth1", "aa:bb:cc:dd:ee:03")
    b = wd.Interception("198.51.100.6", "aa:bb:cc:dd:ee:04", "198.51.100.1",
                        "aa:bb:cc:dd:ee:02", "eth1", "aa:bb:cc:dd:ee:03")
    w.register(a)
    w.register(b)
    assert w.active == 2
    w.unregister("198.51.100.5", "198.51.100.1")
    assert w.active == 1
    assert s.sent[-1] == a.restore_frame(), "only the removed host should be restored"
    assert s.sent[-1] != b.restore_frame()


def test_a_forwarding_stall_triggers_fail_open():
    """The whole point: if forwarding dies, withdraw the interception so the LAN
    recovers, rather than holding the path and blackholing traffic."""
    s = FakeSender()
    w = _watchdog(s, health_s=0.02)
    ic = wd.Interception("198.51.100.5", "aa:bb:cc:dd:ee:01", "198.51.100.1",
                         "aa:bb:cc:dd:ee:02", "eth1", "aa:bb:cc:dd:ee:03")
    w.register(ic)

    # The stall must happen AFTER forwarding has been seen to work.
    #
    # That is the whole subtlety: a counter that has NEVER advanced is uninformative,
    # because an idle segment looks exactly like a broken one. Treating that as a stall
    # makes weir flap -- poison, restore, poison -- turning a quiet network into a
    # continuous outage. So the sequence modelled here is the real one: traffic flows,
    # then it stops.
    seq = {"n": 0}

    def advancing() -> bool:
        seq["n"] += 1
        return seq["n"] == 1          # one healthy sample, then stalled

    w._forwarding.advanced = advancing  # type: ignore[method-assign]
    w.start()
    deadline = time.time() + 3
    while time.time() < deadline and not w.failures:
        time.sleep(0.02)
    assert w.failures, "a sustained stall must fail open"
    assert any("stalled" in f for f in w.failures)
    assert w.active == 0, "mappings must be withdrawn on fail-open"
    assert any(s.sent[i] == ic.restore_frame() for i in range(len(s.sent)))
    w.stop()          # cleanup; already restored


def test_a_single_missed_health_sample_does_not_fail_open():
    """An occasional quiet second is normal: /proc/net/snmp updates on a timer. Acting
    on one sample would cause spurious restores, which are themselves disruptive."""
    s = FakeSender()
    w = _watchdog(s, health_s=0.02)
    w.register(wd.Interception("198.51.100.5", "aa:bb:cc:dd:ee:01", "198.51.100.1",
                               "aa:bb:cc:dd:ee:02", "eth1", "aa:bb:cc:dd:ee:03"))
    calls = {"n": 0}

    def one_miss():
        calls["n"] += 1
        return calls["n"] != 1            # miss once, then advance

    w._forwarding.advanced = one_miss     # type: ignore[method-assign]
    w.start()
    time.sleep(0.3)
    stopped_early = bool(w.failures)
    w.stop()
    assert not stopped_early, f"failed open after a single missed sample: {w.failures}"


def test_unavailable_forwarding_counter_is_not_treated_as_a_stall():
    """'Cannot tell' must not be conflated with 'not forwarding', or the watchdog would
    either never fire or fire constantly."""

    class NoCounter(wd.ForwardingMonitor):
        def advanced(self):
            return None

    s = FakeSender()
    w = _watchdog(s, health_s=0.02)
    w._forwarding = NoCounter()
    w.register(wd.Interception("198.51.100.5", "aa:bb:cc:dd:ee:01", "198.51.100.1",
                               "aa:bb:cc:dd:ee:02", "eth1", "aa:bb:cc:dd:ee:03"))
    w.start()
    time.sleep(0.2)
    fired = bool(w.failures)
    w.stop()
    assert not fired, "an unreadable counter must not be reported as a stall"


def test_forwarding_monitor_reads_the_real_counter():
    """Against this machine's /proc. Skips if unavailable rather than failing."""
    value = wd.ForwardingMonitor.read()
    if value < 0:
        pytest.skip("/proc/net/snmp has no Ip: Forwarding counter here")
    m = wd.ForwardingMonitor(sample=value)
    assert m.advanced() in (True, False)


def test_preflight_sysctls_reports_current_and_required():
    rows = wd.preflight_sysctls()
    assert len(rows) == len(mode_mod.REQUIRED_SYSCTLS)
    for name, current, want in rows:
        assert name.startswith("net.ipv4.")
        assert want in ("0", "1")
        assert current != "", f"{name} reported nothing (unreadable should be '?')"


def test_signal_handlers_are_installed_for_term_and_int():
    """SIGKILL cannot be caught — which is precisely why the ARP-expiry backstop
    matters. What we CAN handle, we must."""
    import signal as sig

    w = _watchdog(FakeSender())
    before_term = sig.getsignal(sig.SIGTERM)
    before_int = sig.getsignal(sig.SIGINT)
    try:
        w._install_signal_handlers()
        assert sig.getsignal(sig.SIGTERM) is not before_term
        assert sig.getsignal(sig.SIGINT) is not before_int
    finally:
        sig.signal(sig.SIGTERM, before_term)
        sig.signal(sig.SIGINT, before_int)


def test_a_never_advancing_counter_does_not_fail_open():
    """An idle segment must NOT be treated as a stall.

    The counter only moves when traffic is forwarded, so on a quiet network -- a home LAN
    overnight, or any test harness -- it never advances. Failing open on that would make
    weir flap continuously: each restore withdraws the mappings and the next refresh
    reinstates them, inventing a repeating outage out of silence.

    Staying armed-but-silent is safe because the ARP cache expiry backstop still covers a
    real failure that we cannot distinguish from idleness.
    """
    s = FakeSender()
    w = _watchdog(s, health_s=0.02)
    w.register(wd.Interception("198.51.100.5", "aa:bb:cc:dd:ee:01", "198.51.100.1",
                               "aa:bb:cc:dd:ee:02", "eth1", "aa:bb:cc:dd:ee:03"))
    w._forwarding.advanced = lambda: False  # type: ignore[method-assign]

    w.start()
    time.sleep(0.3)
    try:
        assert not w.failures, (
            f"a never-advancing counter must not fail open, got {w.failures}"
        )
        assert w.active == 1, "the mappings must still be held"
    finally:
        w.stop()
