"""Three siphon defects where a cleanup or a check answered the wrong question.

All three are read-from-code findings in the audit, and all three share a shape this project keeps
hitting: a function reports success for work it never did, or a check answers a question close to
the one asked.

WV1-23  A refused intercept cleaned table 100 while the install used its own table.
WV1-24  A withdrawal that failed was reported as a withdrawal.
WV1-25  The address-presence check was a substring match.
"""

import pytest

from weirvern.admin import intercept as ic
from weirvern.admin import siphonnet
from weirvern.admin.intercept import ForwardingState, InterceptError, InterceptPlan, POLICY_TABLE


class RecordingSender:
    def __init__(self):
        self.frames = []

    def send(self, frame, kind="poison"):
        self.frames.append((frame, kind))

    def close(self):
        pass


READY = ForwardingState(ip_forward=True, rp_filter_off=True)


def _plan(table):
    return InterceptPlan(
        iface="eth1",
        segment="198.51.100.0/24",
        our_mac="aa:bb:cc:dd:ee:ff",
        our_ip="198.51.100.50",
        gateway_ip="198.51.100.1",
        gateway_mac="11:22:33:44:55:66",
        hosts={"198.51.100.10": "0a:0a:0a:0a:0a:0a"},
        policy_table=table,
    )


# ── WV1-23 ───────────────────────────────────────────────────────────────────────────────────

def test_a_refused_start_cleans_the_TABLE_THE_INSTALL_USED(monkeypatch):
    """`remove_forwarding_path` defaults to POLICY_TABLE (100), and a supervised intercept is never
    on 100 -- `siphonnet.policy_table_for(iface)` returns 100 + 1 + crc32(iface) % 900.

    So a refused start installed the rule and its routes into its own table and then cleaned table
    100, which the install never touched. The table-100 commands succeed as ABSENCE, the failure
    list comes back empty, and the raised error told the operator the node was back to its previous
    state while `iif <iface> lookup <table>` and its routes were still installed. That leftover
    sends matching traffic into a table with a gateway route and no live relay behind it, which is
    the blackhole the forwarding-path checks exist to prevent.

    install() and stop() already branched this way; the two refusal paths did not.
    """
    asked: list[tuple[str, int | None]] = []
    monkeypatch.setattr(ic, "remove_forwarding_path",
                        lambda iface, table=None: (asked.append((iface, table)), [])[1])
    monkeypatch.setattr(ic, "ensure_forwarding_path", lambda _i, _g, **_kw: [
        "route goes out the wrong interface"])

    per_iface_table = 1273  # what policy_table_for returns for some interface
    assert per_iface_table != POLICY_TABLE, "this test is pointless on the default table"

    with pytest.raises(InterceptError):
        ic.Intercept(_plan(per_iface_table), sender=RecordingSender(),
                     forwarding=READY).start()

    assert asked, "the refusal path cleaned nothing at all"
    assert asked == [("eth1", per_iface_table)], (
        f"the refusal cleaned {asked}; the install used table {per_iface_table}. Cleaning table 100 "
        f"succeeds as absence, so the error would claim the node was restored while the policy rule "
        f"and its routes were still installed"
    )


def test_a_refused_start_on_the_DEFAULT_table_still_cleans_it(monkeypatch):
    """The fix must not change behaviour at the default, where the old single-argument call was
    already right."""
    asked: list = []
    monkeypatch.setattr(ic, "remove_forwarding_path",
                        lambda iface, table=None: (asked.append((iface, table)), [])[1])
    monkeypatch.setattr(ic, "ensure_forwarding_path", lambda _i, _g, **_kw: ["broken"])

    with pytest.raises(InterceptError):
        ic.Intercept(_plan(POLICY_TABLE), sender=RecordingSender(), forwarding=READY).start()

    assert asked == [("eth1", None)], f"the default path changed shape: {asked}"


# ── WV1-24 ───────────────────────────────────────────────────────────────────────────────────

def test_a_FAILED_address_withdrawal_is_returned_not_swallowed(monkeypatch):
    """`remove_address` discarded `_run`'s result and returned None while its own docstring said a
    leftover address "changes the host's behaviour permanently". The CLI then printed
    "withdrew <ip> from <iface>" on every exit path."""
    monkeypatch.setattr(siphonnet, "_run",
                        lambda *a: (2, "RTNETLINK answers: Operation not permitted"))

    failures = siphonnet.remove_address("eth1", "198.51.100.50", "198.51.100.0/24")

    assert failures, "a failed withdrawal returned success"
    assert any("Operation not permitted" in f for f in failures), failures


def test_an_ALREADY_ABSENT_address_is_not_a_failure(monkeypatch):
    """Teardown running twice is normal, and `_is_absence` exists for exactly this distinction.
    Reporting it as a failure would train the operator to ignore the warning."""
    monkeypatch.setattr(siphonnet, "_run",
                        lambda *a: (1, "Cannot find device \"eth1\""))

    assert siphonnet.remove_address("eth1", "198.51.100.50", "198.51.100.0/24") == []


def test_a_SUCCESSFUL_withdrawal_returns_nothing(monkeypatch):
    monkeypatch.setattr(siphonnet, "_run", lambda *a: (0, ""))

    assert siphonnet.remove_address("eth1", "198.51.100.50", "198.51.100.0/24") == []


# ── WV1-25 ───────────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("present,asked,expected", [
    # The measured case: asking about .1 found .19, so add_address was skipped and the intercept
    # armed with its our_ip unassigned -- poisoning with no address to receive the traffic.
    ("198.51.100.19/24", "198.51.100.1", False),
    ("198.51.100.100/24", "198.51.100.10", False),
    ("198.51.100.1/24", "198.51.100.1", True),
    ("198.51.100.1/24", "198.51.100.100", False),
    # A different address on the same interface must not match either.
    ("192.0.2.9/24 198.51.100.7/24", "198.51.100.7", True),
])
def test_the_presence_check_compares_exact_addresses(monkeypatch, present, asked, expected):
    import subprocess as real_sp

    class _Out:
        stdout = f"2: eth1    inet {present} scope global eth1\\       valid_lft forever"

    monkeypatch.setattr(real_sp, "run", lambda *a, **k: _Out())
    monkeypatch.setattr(siphonnet, "require_iface_name", lambda *a, **k: None)

    from weirvern.admin import cli

    got = cli._iface_has_address("eth1", asked)
    assert got is expected, (
        f"asked whether {asked} is on the interface carrying {present}: got {got}, expected "
        f"{expected}. A substring match answers the wrong question and skips add_address"
    )


# ── WV1-26: A SWEEP THAT COULD NOT ASK IS NOT AN EMPTY SEGMENT ───────────────────────────────

def test_a_sweep_where_EVERY_send_failed_refuses_instead_of_reporting_empty(monkeypatch):
    """Every per-send failure was dropped with no count, so a sweep where ALL sends failed -- an
    interface down mid-sweep, ENOBUFS, a sandbox without raw sockets -- fell through to the kernel
    neighbour table, which on a fresh interface is empty, and returned a result indistinguishable
    from "nobody answered". `find_free_addresses` then offers every address on a populated segment
    as free, and the CLI tells the operator the segment may be empty.

    The module's own docstring calls a false empty "the worst lie" and fixed it for the empty-SOURCE
    case. This is the same shape one level down, at the send site.
    """
    class DeadSock:
        def bind(self, *_a):
            pass

        def settimeout(self, *_a):
            pass

        def send(self, *_a):
            raise OSError(105, "No buffer space available")   # ENOBUFS

        def recv(self, *_a):
            raise OSError(11, "Resource temporarily unavailable")

        def close(self):
            pass

    monkeypatch.setattr(ic.socket, "socket", lambda *a, **k: DeadSock())
    # No neighbour entries either, so the fallback cannot rescue the result.
    monkeypatch.setattr(ic, "read_neighbour_mac", lambda *_a: None)

    with pytest.raises(ValueError) as exc:
        ic.arp_sweep("eth1", "aa:bb:cc:dd:ee:ff", "198.51.100.50",
                     ["198.51.100.10", "198.51.100.11"], timeout_s=0.1)

    text = str(exc.value)
    assert "could not transmit" in text or "failed to send" in text, text
    assert "No buffer space available" in text, (
        f"the underlying send error must survive, or the operator cannot act on it: {text!r}"
    )


def test_a_PARTIAL_send_failure_still_returns_what_was_asked(monkeypatch):
    """One dead send out of three must not refuse the whole sweep -- the result covers what was
    actually asked, which is still information."""
    class HalfSock:
        def __init__(self):
            self.n = 0

        def bind(self, *_a):
            pass

        def settimeout(self, *_a):
            pass

        def send(self, *_a):
            self.n += 1
            if self.n == 1:
                raise OSError(105, "No buffer space available")

        def recv(self, *_a):
            raise OSError(11, "Resource temporarily unavailable")

        def close(self):
            pass

    monkeypatch.setattr(ic.socket, "socket", lambda *a, **k: HalfSock())
    monkeypatch.setattr(ic, "read_neighbour_mac", lambda *_a: None)

    got = ic.arp_sweep("eth1", "aa:bb:cc:dd:ee:ff", "198.51.100.50",
                       ["198.51.100.10", "198.51.100.11"], timeout_s=0.1)
    assert got == {}, f"expected an empty-but-asked result, got {got}"


# ── WV1-30: ONLY THE HOSTS WE ASKED ──────────────────────────────────────────────────────────

def _arp_reply(sender_ip: str, sender_mac: str) -> bytes:
    """A 42-byte ARP reply in the layout arp_sweep parses."""
    import socket as _s

    frame = bytearray(42)
    frame[12:14] = (0x0806).to_bytes(2, "big")        # ETH_P_ARP
    frame[20:22] = (2).to_bytes(2, "big")             # op = reply
    frame[22:28] = bytes(int(x, 16) for x in sender_mac.split(":"))
    frame[28:32] = _s.inet_aton(sender_ip)
    frame[38:42] = _s.inet_aton(sender_ip)            # the address the reply is about
    return bytes(frame)


def test_a_reply_from_a_host_we_never_asked_about_is_not_recorded(monkeypatch):
    """The socket sees every ARP frame on the segment and the loop recorded the sender of each
    reply without checking it was one of `targets`. A gratuitous reply, a device announcing itself,
    or a reply to another station's request became a host IN THE PLAN -- and on the whole-segment
    path there is no `only` filter, so the intercept could poison a host outside the CIDR the
    operator named and report it as coverage of that CIDR.
    """
    asked = ["198.51.100.10", "198.51.100.11"]
    frames = [_arp_reply("203.0.113.77", "00:00:5e:00:53:aa")]  # NOT a target

    class Sock:
        def bind(self, *_a):
            pass

        def settimeout(self, *_a):
            pass

        def send(self, *_a):
            pass

        def recv(self, *_a):
            if frames:
                return frames.pop()
            raise OSError(11, "Resource temporarily unavailable")

        def close(self):
            pass

    monkeypatch.setattr(ic.socket, "socket", lambda *a, **k: Sock())
    monkeypatch.setattr(ic, "read_neighbour_mac", lambda *_a: None)

    got = ic.arp_sweep("eth1", "aa:bb:cc:dd:ee:ff", "198.51.100.50", asked, timeout_s=0.2)

    assert "203.0.113.77" not in got, (
        f"a host outside the named targets was recorded: {got}. It would be poisoned and counted "
        f"as coverage of the segment the operator named"
    )
    assert got == {}, got


def test_a_reply_from_a_target_IS_recorded(monkeypatch):
    """The filter must not throw away the answer we asked for."""
    frames = [_arp_reply("198.51.100.10", "00:00:5e:00:53:01")]

    class Sock:
        def bind(self, *_a):
            pass

        def settimeout(self, *_a):
            pass

        def send(self, *_a):
            pass

        def recv(self, *_a):
            if frames:
                return frames.pop()
            raise OSError(11, "Resource temporarily unavailable")

        def close(self):
            pass

    monkeypatch.setattr(ic.socket, "socket", lambda *a, **k: Sock())
    monkeypatch.setattr(ic, "read_neighbour_mac", lambda *_a: None)

    got = ic.arp_sweep("eth1", "aa:bb:cc:dd:ee:ff", "198.51.100.50",
                       ["198.51.100.10", "198.51.100.11"], timeout_s=0.2)
    assert got.get("198.51.100.10") == "00:00:5e:00:53:01", got


# ── WV1-31: build_plan KEEPS ITS "RETURNS None" PROMISE ─────────────────────────────────────

def test_an_IPv6_SEGMENT_returns_None_instead_of_raising(monkeypatch):
    """`parse_cidr(segment)` was called on the whole-segment path ABOVE the try/except guarding the
    very same call, so a v6 segment raised straight out of build_plan -- breaking the docstring's
    promise that it returns None with a reason logged, which the named-host path keeps for the same
    input. The refusal text never reached the operator."""
    monkeypatch.setattr(ic, "read_mac", lambda *_a: "aa:bb:cc:dd:ee:ff")

    got = ic.build_plan("eth1", "2001:db8::/64", "198.51.100.50", "198.51.100.1")

    assert got is None, f"build_plan returned {got!r} for a v6 segment instead of refusing"


def test_an_OVERSIZED_segment_returns_None_instead_of_raising(monkeypatch):
    monkeypatch.setattr(ic, "read_mac", lambda *_a: "aa:bb:cc:dd:ee:ff")

    got = ic.build_plan("eth1", "198.51.100.0/8", "198.51.100.50", "198.51.100.1")

    assert got is None, f"build_plan returned {got!r} for a /8 instead of refusing"


# ── WV1-32: A v6 POLICY IS NOT THE HOST'S v4 POLICY ─────────────────────────────────────────

def test_a_v6_ACCEPT_does_not_mask_a_v4_DROP(monkeypatch):
    """The probe list was tried in order and the first command that SUCCEEDED was taken as the
    host's FORWARD policy. On a host with ip6tables present and iptables absent, a v6 ACCEPT masked
    a v4 DROP and the check passed -- the false-pass direction, so the intercept armed and the
    kernel dropped every relayed packet. The nft fallback already covers the no-iptables host."""
    import subprocess as _sp

    def fake_run(cmd, **_kw):
        prog = cmd[0]
        if prog == "ip6tables":
            # The REAL `ip6tables -S FORWARD` shape. The first version of this fixture used the
            # human `iptables -L` form, "Chain FORWARD (policy ACCEPT)", which
            # _policy_from_forward_listing does not parse -- so it returned "" and the check fell
            # through to UNKNOWN anyway. Measured: with ip6tables put BACK in the probe list the
            # test still passed, which is a fixture that cannot see the defect it exists for.
            return _sp.CompletedProcess(cmd, 0, "-P FORWARD ACCEPT\n")
        raise FileNotFoundError(prog)   # iptables and nft absent

    monkeypatch.setattr(_sp, "run", fake_run)

    policy, detail = siphonnet.forward_policy()

    assert policy != "ACCEPT", (
        f"an ip6tables ACCEPT was read as this host's v4 FORWARD policy ({detail!r}). The "
        f"intercept would arm and the kernel would drop every relayed packet"
    )
    assert policy == "UNKNOWN", (
        f"a host whose v4 policy cannot be read must be UNKNOWN and refused, not assumed: {policy}"
    )


# ── WV1-29: ONE INTERCEPT PER (INTERFACE, TABLE) ────────────────────────────────────────────

def test_a_SECOND_intercept_on_the_same_table_is_refused(tmp_path, monkeypatch):
    """`ensure_forwarding_path` FLUSHES the policy table and `remove_forwarding_path` DELETES every
    rule selecting it, so two intercepts sharing a table take each other down: the second flush
    wipes the first's routes and either teardown deletes the other's rule, leaving traffic routed
    into a table with no live relay behind it.

    Nothing coordinated this before. The supervised path gives each interface its own table, but
    every caller that does not pass one shares POLICY_TABLE = 100.
    """
    monkeypatch.setattr(ic, "INTERCEPT_LOCK_DIR", str(tmp_path))
    monkeypatch.setattr(ic, "ensure_forwarding_path", lambda _i, _g, **_kw: [])
    monkeypatch.setattr(ic, "remove_forwarding_path", lambda *a, **k: [])

    first = ic.Intercept(_plan(POLICY_TABLE), sender=RecordingSender(), forwarding=READY)
    first._acquire_lock()
    try:
        second = ic.Intercept(_plan(POLICY_TABLE), sender=RecordingSender(), forwarding=READY)
        with pytest.raises(ic.InterceptError) as exc:
            second._acquire_lock()
        text = str(exc.value)
        assert "policy table 100" in text, text
        assert "FLUSH" in text or "flush" in text, (
            f"the refusal must say WHY sharing a table is destructive: {text!r}"
        )
    finally:
        first._release_lock()


def test_a_DIFFERENT_table_is_not_blocked(tmp_path, monkeypatch):
    """A supervised intercept gets its own table, so it must be able to run beside a manual one."""
    monkeypatch.setattr(ic, "INTERCEPT_LOCK_DIR", str(tmp_path))

    a = ic.Intercept(_plan(POLICY_TABLE), sender=RecordingSender(), forwarding=READY)
    b = ic.Intercept(_plan(1273), sender=RecordingSender(), forwarding=READY)
    a._acquire_lock()
    try:
        b._acquire_lock()   # must not raise
        assert b._lock_fd is not None
    finally:
        b._release_lock()
        a._release_lock()


def test_the_lock_is_released_after_stop(tmp_path, monkeypatch):
    """stop() must free the table, or the next run after a clean exit is refused."""
    monkeypatch.setattr(ic, "INTERCEPT_LOCK_DIR", str(tmp_path))
    monkeypatch.setattr(ic, "ensure_forwarding_path", lambda _i, _g, **_kw: [])
    monkeypatch.setattr(ic, "remove_forwarding_path", lambda *a, **k: [])

    first = ic.Intercept(_plan(POLICY_TABLE), sender=RecordingSender(), forwarding=READY)
    first._acquire_lock()
    assert first._lock_fd is not None

    first.stop()   # a teardown that holds the lock must free it
    assert first._lock_fd is None, "stop() did not release the table"

    again = ic.Intercept(_plan(POLICY_TABLE), sender=RecordingSender(), forwarding=READY)
    again._acquire_lock()   # must not raise once the first has stopped
    assert again._lock_fd is not None
    again._release_lock()


def test_an_unwritable_lock_dir_does_not_make_the_host_uninterceptable(tmp_path, monkeypatch):
    """The lock is coordination, not a safety gate. A read-only /run must degrade to the old
    behaviour with a warning, not refuse every run on that host."""
    monkeypatch.setattr(ic, "INTERCEPT_LOCK_DIR", str(tmp_path / "nope" / "deeper"))

    det = ic.Intercept(_plan(POLICY_TABLE), sender=RecordingSender(), forwarding=READY)
    det._acquire_lock()   # must not raise
    assert det._lock_fd is None, "no fd should be recorded when the lock could not be created"
