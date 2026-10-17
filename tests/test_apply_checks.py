"""BF-14: the apply-time assertions -- named, blocking, and honest about skips."""
import datetime as dt
from types import SimpleNamespace

import pytest

from weirvern import apply_checks as ac
from weirvern import fleet as fleet_mod


class _CH:
    def __init__(self, *, count=None, raises=False):
        self.count = count
        self.raises = raises
        self.sql = []

    def query(self, sql, parameters=None):
        self.sql.append((sql, parameters or {}))
        if self.raises:
            raise RuntimeError("no store")
        return SimpleNamespace(result_rows=[(self.count,)]) if self.count is not None \
            else SimpleNamespace(result_rows=[])


def _names(out):
    return {r["name"]: r for r in out["results"]}


def test_a_change_that_does_not_touch_anything_is_all_skips():
    out = ac.run_apply_checks(changes={"RETRAIN_EVERY_H": "6"}, current={}, ch_client=_CH())
    assert out["blocked"] is False
    assert all(r["status"] == "skip" for r in out["results"])
    assert out["summary"] == "0 passed, 3 skipped"


def test_an_incomplete_siphon_plan_blocks_with_the_validators_own_words():
    # mode set, interface missing-but-valid -- make_plan refuses a half-armed plan only when
    # the pieces are wrong; here the interface is a bad name, which the real validator names.
    out = ac.run_apply_checks(changes={"INTERCEPT_IFACE": "not an iface"},
                              current={"INTERCEPT_MODE": "siphon"}, ch_client=_CH())
    r = _names(out)["the interconnect plan stays complete"]
    assert r["status"] == "fail"
    assert "not usable" in r["detail"]
    assert out["blocked"] is True


def test_a_valid_plan_passes_through_the_same_validator():
    out = ac.run_apply_checks(changes={"INTERCEPT_TARGETS": "192.0.2.0/28"},
                              current={"INTERCEPT_MODE": "loch", "INTERCEPT_IFACE": "eth1"},
                              ch_client=_CH())
    r = _names(out)["the interconnect plan stays complete"]
    assert r["status"] == "pass"


def test_an_interface_no_sensor_reports_blocks(monkeypatch):
    monkeypatch.setattr("weirvern.fleet_store.read_heartbeats",
                        lambda client: ([{"sensor_id": "weirvern", "interfaces": ["eth1", "eth2"]},
                                         {"sensor_id": "eth2-dk", "interfaces": ["eth0"]}], None))
    out = ac.run_apply_checks(changes={"INTERCEPT_IFACE": "eth9"}, current={}, ch_client=_CH())
    r = _names(out)["the capture interface is one the sensors report"]
    assert r["status"] == "fail"
    assert "eth9" in r["detail"] and "Heard" in r["detail"]
    assert out["blocked"] is True


def test_the_interface_check_skips_with_its_reason_when_heartbeats_are_down(monkeypatch):
    monkeypatch.setattr("weirvern.fleet_store.read_heartbeats",
                        lambda client: ([], "column missing"))
    out = ac.run_apply_checks(changes={"INTERCEPT_IFACE": "eth9"}, current={}, ch_client=_CH())
    r = _names(out)["the capture interface is one the sensors report"]
    assert r["status"] == "skip" and "column missing" in r["detail"]
    assert out["blocked"] is False


def test_a_threshold_over_the_days_budget_blocks_and_says_the_number():
    out = ac.run_apply_checks(changes={"BASE_THRESHOLD": "0.1"}, current={},
                              ch_client=_CH(count=999), now=dt.datetime(2026, 10, 17, 12, 0, 0))
    r = _names(out)["the threshold does not fire on yesterday's baseline"]
    assert r["status"] == "fail"
    assert "999" in r["detail"] and "50" in r["detail"]
    assert out["blocked"] is True


def test_a_threshold_within_budget_passes_and_states_the_count():
    out = ac.run_apply_checks(changes={"BASE_THRESHOLD": "0.35"}, current={},
                              ch_client=_CH(count=3), now=dt.datetime(2026, 10, 17, 12, 0, 0))
    r = _names(out)["the threshold does not fire on yesterday's baseline"]
    assert r["status"] == "pass" and "3" in r["detail"]


def test_the_count_query_window_matches_the_last_24h():
    ch = _CH(count=0)
    now = dt.datetime(2026, 10, 17, 12, 0, 0)
    ac.run_apply_checks(changes={"BASE_THRESHOLD": "0.35"}, current={}, ch_client=ch, now=now)
    sql, params = ch.sql[-1]
    assert params["since"] == (now - dt.timedelta(hours=24)).replace(tzinfo=None)
    assert "detected_at >=" in sql and "anomaly_score >=" in sql


def test_the_plan_validator_is_the_fleets_own():
    """The check and the sensor must never disagree about what a complete plan is."""
    with pytest.raises(fleet_mod.FleetError):
        fleet_mod.make_plan(mode="siphon", iface="not an iface")
