"""Where an alert happened (operator, 2026-10-19).

Anomalies carry no sensor id; the location is resolved from the address against the fleet's
declared segments. The most specific network wins, and an address no weirling declares stays
unplaced rather than naming a sensor that cannot see it.
"""
from weirvern.admin.web import _attach_anomaly_locations


def test_most_specific_network_wins():
    rows = [{"src_addr": "192.0.2.5"}]
    _attach_anomaly_locations(rows, [
        {"sensor_id": "wide", "segment": "192.0.2.0/24"},
        {"sensor_id": "narrow", "segment": "192.0.2.0/28"},
    ])
    assert rows[0]["location"] == {"weirling": "narrow", "network": "192.0.2.0/28"}


def test_reported_segment_is_a_fallback():
    rows = [{"src_addr": "198.51.100.9"}]
    _attach_anomaly_locations(rows, [
        {"sensor_id": "edge", "segment": "", "reported_segment": "198.51.100.0/24"},
    ])
    assert rows[0]["location"]["weirling"] == "edge"


def test_an_address_outside_every_segment_is_unplaced():
    rows = [{"src_addr": "203.0.113.7"}]
    _attach_anomaly_locations(rows, [{"sensor_id": "edge", "segment": "192.0.2.0/24"}])
    assert "location" not in rows[0]


def test_ipv6_and_garbage_addresses_do_not_break_the_page():
    rows = [{"src_addr": "2001:db8::1"}, {"src_addr": "not-an-address"}]
    _attach_anomaly_locations(rows, [{"sensor_id": "edge", "segment": "192.0.2.0/24"}])
    assert "location" not in rows[0] and "location" not in rows[1]
