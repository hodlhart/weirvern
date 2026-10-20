"""Smoke matrix: every NIC role combination flows to the right mechanism.

SYNTHETIC ON PURPOSE. This runs no kernel and no capture: it proves the PLAN -> mechanism
mapping (capture list, one siphon per NIC with its own table, one gate per blocking NIC with
its own nft table) and that a blocking rule still matches the packets it names. The live
kernel checks are separate tests; this matrix is what catches the combination bugs the old
single-interface model could not represent.
"""
import json
from itertools import product

from weirvern.admin.siphon_supervisor import configs_from_env
from weirvern.nic_plans import NicPlanSet
from weirvern.sluice import GATE_STATE_ARMED, NftBackend, Rule, SluiceGateGroup

SEGMENT = {"segment": "198.51.100.0/24", "addr": "198.51.100.10",
           "gateway": "198.51.100.1", "targets": "*"}
BLOCKED = "192.0.2.66"
CLEAN = "192.0.2.67"


class FakeNft:
    """The compiler is real; the kernel is not. Each NIC gets a distinct table."""
    name = "nft"

    def __init__(self, iface):
        self.iface = iface
        self.table = f"weirvern_sluice_{iface}"
        self.text = ""

    def available(self):
        return True

    def arm(self, rules, *, iface):
        self.text = NftBackend()._base_ruleset(rules, iface)
        return True, ""

    def counters(self):
        return 3, 300

    def installed(self):
        return True

    def disarm(self):
        self.text = ""
        return True, ""


def rule():
    return Rule(rule_id="smoke", src_cidr=f"{BLOCKED}/32")


def test_every_capture_siphon_sluice_combination_flows_to_its_own_mechanism():
    seen = set()
    for capture, siphon, sluice in product((False, True), repeat=3):
        name = f"capture={capture} siphon={siphon} sluice={sluice}"
        plan = {"capture": capture, "siphon": siphon, "sluice": sluice}
        if siphon:
            plan.update(SEGMENT)
        raw = json.dumps({"eth1": plan})
        plans = NicPlanSet.from_json(raw)

        assert plans.capture_ifaces() == (["eth1"] if capture else []), name
        assert plans.siphon_ifaces() == (["eth1"] if siphon else []), name
        assert plans.sluice_ifaces() == (["eth1"] if sluice else []), name
        assert plans.validate() == [], name
        seen.add((capture, siphon, sluice))

        configs = configs_from_env({"INTERCEPT_PLANS": raw})
        assert [c.iface for c in configs] == (["eth1"] if siphon else []), name
        if siphon:
            assert configs[0].mode == "siphon"
            assert configs[0].policy_table >= 101

        group = SluiceGateGroup(plans, backend_factory=FakeNft)
        assert list(group.supervisors) == (["eth1"] if sluice else []), name
        if sluice:
            group.arm([rule()])
            state = group.states()["eth1"]
            assert state.state == GATE_STATE_ARMED, name
            assert state.rules_active == 1
            backend = group.supervisors["eth1"].backend
            assert backend.table == "weirvern_sluice_eth1"
            assert "counter drop" in backend.text, name
            assert BLOCKED in backend.text
    assert seen == set(product((False, True), repeat=3))


def test_two_blocking_nics_get_two_tables_and_two_independent_arms():
    plans = NicPlanSet.from_json('''
      {"eth1": {"sluice": true}, "eth2": {"sluice": true}}
    ''')
    group = SluiceGateGroup(plans, backend_factory=FakeNft)
    group.arm([rule()])
    states = group.states()
    tables = {i: s.backend.table for i, s in group.supervisors.items()}
    assert tables == {"eth1": "weirvern_sluice_eth1",
                      "eth2": "weirvern_sluice_eth2"}
    assert set(states) == {"eth1", "eth2"}
    assert all(s.state == GATE_STATE_ARMED for s in states.values())
    # Arming one does not empty the other's compiled ruleset.
    assert "counter drop" in group.supervisors["eth1"].backend.text
    assert "counter drop" in group.supervisors["eth2"].backend.text


def test_a_blocking_rule_matches_the_named_host_and_no_other_host():
    r = rule()
    assert r.matches(BLOCKED, "203.0.113.9", "tcp", 443)
    assert not r.matches(CLEAN, "203.0.113.9", "tcp", 443)


def test_a_siphon_nic_without_route_facts_is_refused_while_other_nics_still_flow():
    plans = NicPlanSet.from_json('''
      {"eth1": {"siphon": true, "segment": "198.51.100.0/24"},
       "eth2": {"capture": true, "sluice": true}}
    ''')
    problems = plans.validate()
    assert problems and "addr" in problems[0] and "gateway" in problems[0]
    # The invalid siphon does not erase the valid gate plan.
    assert plans.sluice_ifaces() == ["eth2"]
    assert plans.capture_ifaces() == ["eth2"]


def test_the_management_nic_cannot_carry_any_active_role():
    plans = NicPlanSet.from_json('{"eth0": {"capture": true, "siphon": true, "sluice": true}}')
    problems = plans.validate(mgmt_iface="eth0")
    assert problems and "management interface" in problems[0]


def test_one_sensor_can_run_siphon_on_one_nic_and_a_gate_on_another():
    plans = NicPlanSet.from_json('''
      {"eth1": {"capture": true, "siphon": true, "segment": "198.51.100.0/24",
                 "addr": "198.51.100.10", "gateway": "198.51.100.1", "targets": "*"},
       "eth2": {"capture": true, "sluice": true}}
    ''')
    assert plans.validate() == []
    configs = configs_from_env({"INTERCEPT_PLANS": plans_json(plans)})
    assert [c.iface for c in configs] == ["eth1"]
    group = SluiceGateGroup(plans, backend_factory=FakeNft)
    assert list(group.supervisors) == ["eth2"]
    group.arm([rule()])
    assert group.states()["eth2"].state == GATE_STATE_ARMED
    # The siphon NIC's policy table and the gate NIC's nft table are unrelated namespaces.
    assert configs[0].policy_table != 100
    assert group.supervisors["eth2"].backend.table == "weirvern_sluice_eth2"


def plans_json(plans):
    import json
    return json.dumps({
        iface: {"capture": p.capture, "siphon": p.siphon, "sluice": p.sluice,
                "segment": p.segment, "addr": p.addr,
                "gateway": p.gateway, "targets": p.targets}
        for iface, p in plans.plans.items()})


def test_a_per_nic_gate_arms_and_disarms_BOTH_of_its_own_tables():
    """The forward table was per-NIC; the input table was not.

    `NftBackend(suffix="eth1")` compiles its input rules into
    `weirvern_sluice_eth1_in`, but arm/disarm/installed/counters still named the module-level
    `weirvern_sluice_in`. A per-NIC input block therefore survived every disarm and every
    re-arm, and `disarm()` reported the gate removed while that table was still installed.
    """
    calls: list[list[str]] = []

    def runner(args, capture=False, stdin=None):
        calls.append(list(args))
        if args[:3] == ["nft", "list", "table"]:
            return False, ""          # absence is the normal state in this stub
        return True, ""

    b = NftBackend(runner=runner, suffix="eth1")
    b.arm([Rule(rule_id="r", src_cidr="192.0.2.66/32", protocol="tcp",
                dst_port=443, direction="in")], iface="eth1")
    deletes = [c for c in calls if c[:3] == ["nft", "delete", "table"]]
    assert ["nft", "delete", "table", "inet", "weirvern_sluice_eth1"] in deletes
    assert ["nft", "delete", "table", "inet", "weirvern_sluice_eth1_in"] in deletes
    assert ["nft", "delete", "table", "inet", "weirvern_sluice_in"] not in deletes

    calls.clear()
    ok, _ = b.disarm()
    assert ok is True
    deletes = [c for c in calls if c[:3] == ["nft", "delete", "table"]]
    assert ["nft", "delete", "table", "inet", "weirvern_sluice_eth1"] in deletes
    assert ["nft", "delete", "table", "inet", "weirvern_sluice_eth1_in"] in deletes
    assert ["nft", "delete", "table", "inet", "weirvern_sluice_in"] not in deletes
