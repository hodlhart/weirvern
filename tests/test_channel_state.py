"""Mode is intent; the channel is evidence (WL-3, 2026-10-19).

Measured live before this existed: the fleet row said `siphon` while `mappings` was 0 and the
flows table had not seen a record for 24 hours. The mode came from configuration; the channel
had never come up. The row now states the evidence and the reason, not the intent alone.
"""
from weirvern.fleet import SensorHealth, channel_state
from weirvern.fleet_store import _health_to_json


def test_loch_has_no_channel():
    out = channel_state("loch", 0, True, True)
    assert out["state"] == "disabled"
    assert "passive" in out["why"]


def test_siphon_without_mappings_is_disabled_and_says_why():
    out = channel_state("siphon", 0, True, True)
    assert out["state"] == "disabled"
    assert "no intercept mappings" in out["why"]


def test_siphon_with_live_mappings_is_enabled():
    out = channel_state("siphon", 2, True, True)
    assert out["state"] == "enabled"
    assert out["mappings"] == 2


def test_a_stale_intercept_cannot_claim_a_live_channel():
    out = channel_state("siphon", 2, True, False)
    assert out["state"] == "disabled"
    assert "stale" in out["why"]


def test_the_row_carries_the_capture_path_and_channel_evidence():
    h = SensorHealth(sensor_id="s", state="alive", iface="eth1", mappings=2, running=True)
    out = _health_to_json(h)
    assert out["iface"] == "eth1"
    assert out["mappings"] == 2
    assert out["running"] is True
