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
