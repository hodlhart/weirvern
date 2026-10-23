"""Counter carry-over across the periodic re-arm.

`SluiceSupervisor.arm()` replaces the nft tables on every pass, so the kernel's counters are
zero immediately after each arm. Reading them only after the arm made a working gate report
0 packets forever. These tests drive the pre-arm / post-arm sequence directly.
"""
from weirvern.sluice import GATE_STATE_ARMED, Backend, Rule, SluiceSupervisor


class _RearmingBackend(Backend):
    name = "rearming-fake"

    def __init__(self, packets: int = 34, bytes_: int = 2040) -> None:
        self.packets = packets
        self.bytes = bytes_
        self.arms = 0
        self.fail = False

    def available(self) -> bool:
        return True

    def arm(self, rules, *, iface):
        self.arms += 1
        if self.fail:
            return False, "simulated failure"
        self.packets = 0
        self.bytes = 0
        return True, "simulated"

    def disarm(self):
        return True, "simulated"

    def counters(self):
        return self.packets, self.bytes


def _rule() -> Rule:
    return Rule("r1", dst_cidr="192.0.2.10/32", mode="block")


def test_a_rearm_does_not_erase_the_packets_dropped_before_it():
    backend = _RearmingBackend()
    sup = SluiceSupervisor(iface="eth2", backend=backend)

    first = sup.arm([_rule()])
    assert first.state == GATE_STATE_ARMED
    assert first.packets_blocked == 34, "the first pass lost the counters read before the re-arm"
    assert first.bytes_blocked == 2040

    backend.packets, backend.bytes = 7, 420
    second = sup.arm([_rule()])
    assert second.packets_blocked == 41, "a later interval was not added to the running total"
    assert second.bytes_blocked == 2460


def test_a_failed_arm_does_not_count_the_same_counter_twice():
    backend = _RearmingBackend()
    sup = SluiceSupervisor(iface="eth2", backend=backend)
    sup.arm([_rule()])                 # 34 read before the successful arm

    backend.packets, backend.bytes = 3, 180
    backend.fail = True
    failed = sup.arm([_rule()])        # the table survives, counters remain 3
    assert failed.packets_blocked == 37
    again = sup.arm([_rule()])         # still 3; must not add another 3
    assert again.packets_blocked == 37
