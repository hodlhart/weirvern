"""The gate follows the capability: any sensor that CAN enforce, does -- with the hub's checks.

THE DESIGN THIS PINS. One rule store, many gates: the hub derives rules from detections, and every
box that sits in the path installs the same rules on its own segment. Three properties make that
safe, and each has a test here:

  * a weirling gate DERIVES NOTHING. The hub is the single writer; a second deriver would mint a
    second rule for one detection, and the operator who revoked one would keep blocking on the
    other -- the worst way for two gates to disagree.
  * it runs the HUB'S OWN PASS rather than a parallel implementation that could keep passing while
    the hub's own path broke. The checks travel with the code: the gate must be enabled, the rules
    must be READABLE (an unreadable ruleset is not an empty one), the enforcement path must be
    VERIFIED rather than configured, and the interface is never the management NIC.
  * a gate that STOPPED is visible as stopped. A segment the operator believes is filtered and is
    not is the worst state this feature can produce, so the fleet's gates are listed with ages and
    an unknown age counts as stale.
"""

import dataclasses
from datetime import UTC, datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class _Channel:
    active = False
    bridge = ""


class _Sup:
    iface = "eth1"
    mgmt_iface = "eth0"
    state = None

    def disarm(self) -> None:
        pass


def _settings(**over):
    from weirvern.config import get_settings

    return dataclasses.replace(
        get_settings(), sluice_enabled=True, sluice_criticality="high",
        sluice_interval_s=5, sluice_iface="eth1", sensor_mode="loch", **over,
    )


def test_a_weirling_gate_enforces_but_derives_nothing(monkeypatch):
    """The contrast IS the test: the same pass, called with derive=False, arms the rules the hub
    wrote and reads no detections; called the hub's way, it derives as well."""
    from weirvern import sluice as sluice_mod
    from weirvern import worker
    from weirvern.admin import channel as channel_mod

    calls = {"enforced": 0, "detections_read": 0}

    last = {"detections": "unset"}

    def fake_pass(store, sup, **kw):
        calls["enforced"] += 1
        last["detections"] = kw.get("detections")
        return type("S", (), {"holding": False, "state": "degraded", "detail": "stub"})()

    monkeypatch.setattr(sluice_mod, "enforcement_pass", fake_pass)
    monkeypatch.setattr(sluice_mod, "SluiceSupervisor", lambda **kw: _Sup())
    monkeypatch.setattr(sluice_mod, "choose_backend", lambda name: object())
    monkeypatch.setattr(channel_mod, "detect", lambda *a, **k: _Channel())
    monkeypatch.setattr(
        worker, "current_detections_for_blocking",
        lambda client, **kw: (calls.__setitem__("detections_read", calls["detections_read"] + 1)
                              or [{"src_addr": "198.51.100.9", "severity": "high",
                                   "anomaly_score": 0.9}]),
    )
    worker._SLUICE["last_pass"] = 0.0

    settings = _settings()
    worker._sluice_maybe(settings, object(), derive=False)
    assert calls["enforced"] == 1, "the gate pass did not run"
    assert calls["detections_read"] == 0, (
        "a weirling gate read detections -- it must be a second ENFORCER, never a second writer")
    assert last["detections"] == []

    worker._SLUICE["last_pass"] = 0.0
    worker._sluice_maybe(settings, object())
    assert calls["detections_read"] == 1, (
        "the hub's pass stopped deriving: the shared rule set would never be written")


def test_only_an_explicit_gate_role_is_gate_only():
    from weirvern import worker

    assert worker._is_gate_only(_settings()) is False
    assert worker._is_gate_only(_settings(role="gate")) is True

    class _Older:
        """A settings object with no `role` at all -- an older ConfigMap."""

    assert worker._is_gate_only(_Older()) is False, (
        "a missing role must mean the hub: it is what every deployment was before the role existed")


def test_a_typo_in_the_role_refuses_to_start():
    import pytest

    from weirvern.config import get_settings

    with pytest.raises(ValueError) as excinfo:
        dataclasses.replace(get_settings(), role="gateway").validate()
    assert "WEIRVERN_ROLE" in str(excinfo.value)
    # The two real values pass.
    for role in ("full", "gate"):
        dataclasses.replace(get_settings(), role=role).validate()


def test_a_stale_gate_is_marked_stale_and_an_unknown_age_is_not_fresh():
    from weirvern.admin import web_api

    now = datetime(2026, 10, 16, 12, 0, tzinfo=UTC)

    def gate(sensor, age_s, **over):
        row = {"sensor": sensor, "state": "armed", "iface": "eth1", "rules_active": 2,
               "rules_total": 3, "packets_blocked": 10, "bytes_blocked": 100, "detail": "",
               "enforcement": "channel", "updated_at": None if age_s is None else
               (now - timedelta(seconds=age_s))}
        row.update(over)
        return row

    out = web_api.gates_payload(
        {"available": True, "reason": "", "gates": [
            gate("weirvern-dual", 20),
            gate("weirvern-eth2", 4000, enforcement="siphon"),
            gate("ghost", None),
        ]},
        "weirvern-dual", 240, now,
    )
    assert out["gates_available"] is True
    rows = {g["sensor"]: g for g in out["gates"]}
    assert rows["weirvern-dual"]["local"] is True and rows["weirvern-dual"]["stale"] is False
    assert rows["weirvern-eth2"]["local"] is False and rows["weirvern-eth2"]["stale"] is True
    assert rows["ghost"]["stale"] is True, (
        "an unreadable timestamp read as fresh: a gate that stopped would look armed")
    assert rows["weirvern-dual"]["age_s"] == 20
    assert all("updated_at" not in g for g in out["gates"]), (
        "the raw datetime leaked to the browser; the age in seconds is the contract")


def test_an_unreadable_fleet_says_so_rather_than_listing_nothing():
    from weirvern.admin import web_api

    out = web_api.gates_payload({"available": False, "reason": "Code: 47", "gates": []},
                                "hub", 240, datetime.now(UTC))
    assert out["gates_available"] is False and "47" in out["gates_reason"]
    assert out["gates"] == []


def test_the_gate_states_query_reads_every_sensor_and_reports_failures():
    from weirvern import sluice_store

    now = datetime(2026, 10, 16, 12, 0, tzinfo=UTC)

    class _Res:
        def __init__(self, rows):
            self.result_rows = rows

    class _C:
        def __init__(self, rows=None, exc=None):
            self.rows, self.exc = rows or [], exc
            self.sql = None

        def query(self, sql, parameters=None):
            self.sql = sql
            if self.exc:
                raise self.exc
            return _Res(self.rows)

    rows = [("weirvern-dual", now, "armed", "eth1", 2, 3, 100, 1000, "detail", "channel"),
            ("lab-west", now, "degraded", "eth1", 0, 3, 0, 0, "no verified path", "")]
    client = _C(rows=rows)
    out = sluice_store.load_gate_states(client)
    assert out["available"] is True and len(out["gates"]) == 2
    assert out["gates"][1]["sensor"] == "lab-west" and out["gates"][1]["state"] == "degraded"
    assert "FINAL" in client.sql and "sensor" in client.sql

    bad = sluice_store.load_gate_states(_C(exc=RuntimeError("Code: 47")))
    assert bad["available"] is False and "RuntimeError" in bad["reason"] and bad["gates"] == []


def test_the_deployment_surfaces_carry_the_gate_and_ship_it_disabled():
    """The capability has to be DELIVERABLE for the design to be real: the unit template must
    carry the gate container (and ship it off), the deploy script must offer it with the same
    refusals, and the worker must be the thing that runs it."""
    unit = (ROOT / "k8s/units/weirling-unit.yaml.template").read_text()
    assert "WEIRVERN_ROLE" in unit and 'value: "gate"' in unit
    assert "SLUICE_ENABLED" in unit and 'value: "0"' in unit, (
        "the unit must ship with its gate disabled; enabling it is the operator's decision")
    assert "NET_ADMIN" in unit, "a gate that cannot install a ruleset is decoration"

    script = (ROOT / "scripts/deploy-weirling.sh").read_text()
    assert "--gate" in script and "--gate-iface" in script
    assert "REFUSING to enforce on" in script, "the management NIC refusal must exist on this path too"

    worker = (ROOT / "weirvern/worker.py").read_text()
    assert "derive=False" in worker and "_is_gate_only(settings)" in worker


def test_permitting_capture_on_the_management_NIC_never_permits_ENFORCEMENT():
    """PREFER AN INDEPENDENT PORT, SUPPORT A SINGLE-NIC HOST -- without weakening the gate.

    `--allow-management-nic` exists because a laptop with one NIC otherwise cannot run a sensor
    at all. Capture on the management NIC is a READ: it misses most traffic, and the operator is
    told so. ENFORCEMENT there is the box's own uplink, so it takes the machine doing the
    blocking out of the network. The permission must therefore not reach the gate, and this test
    pins that at the only place it could leak -- the shell conditional that decides.

    It is a source test because the deploy script is shell, and the invariant is about which
    variable a refusal reads. A behavioural test would need a target host with one NIC, which is
    the situation being supported rather than the situation being tested.
    """
    script = (ROOT / "scripts/deploy-weirling.sh").read_text()

    # The permission exists, is parsed, and is documented.
    assert "--allow-management-nic" in script
    assert "ALLOW_MGMT=1" in script, "the flag must actually be parsed"

    # The gate's refusal must NOT consult the permission.
    gate_at = script.index("REFUSING to enforce on")
    gate_block = script[gate_at - 400:gate_at + 200]
    assert "ALLOW_MGMT" not in gate_block, (
        "the gate's management-NIC refusal now reads ALLOW_MGMT, so permitting capture has "
        "silently permitted enforcement on the box's own uplink"
    )

    # And the two together are refused outright, rather than left to the check above.
    assert "--gate cannot be combined with --allow-management-nic" in script, (
        "a single-NIC host must not be able to arm a gate on its management port"
    )
