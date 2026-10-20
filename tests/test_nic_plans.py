import pytest

from weirvern.nic_plans import NicPlanError, NicPlanSet


def test_two_nics_can_have_different_roles_and_plans():
    plans = NicPlanSet.from_json('''
      {"eth1": {"capture": true, "siphon": true, "segment": "192.0.2.0/24",
                 "addr": "192.0.2.10", "gateway": "192.0.2.1", "targets": "*"},
       "eth2": {"capture": true, "sluice": true}}
    ''')
    assert plans.capture_ifaces() == ["eth1", "eth2"]
    assert plans.siphon_ifaces() == ["eth1"]
    assert plans.sluice_ifaces() == ["eth2"]
    assert plans.plans["eth1"].armed_mode == "siphon"


def test_a_siphon_plan_must_carry_its_route_facts():
    plans = NicPlanSet.from_json('{"eth1": {"siphon": true, "segment": "192.0.2.0/24"}}')
    problems = plans.validate()
    assert any("addr" in p and "gateway" in p for p in problems)


def test_the_management_nic_is_refused_for_every_active_role():
    plans = NicPlanSet.from_json('{"eth0": {"capture": true, "sluice": true}}')
    problems = plans.validate(mgmt_iface="eth0")
    assert problems and "management interface" in problems[0]


def test_malformed_json_says_so():
    with pytest.raises(NicPlanError):
        NicPlanSet.from_json("[1, 2]")
