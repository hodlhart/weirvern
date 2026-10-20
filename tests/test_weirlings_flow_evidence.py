"""The fleet's flow evidence must query the exporter the hub actually uses.

WHY THIS FILE EXISTS. The local sensor's goflow2 exports from loopback. The payload built its
exporter list from `row.address` first, so once the hub registered with its management address
(192.0.2.176 in the fixture), it queried that address and never 127.0.0.1 -- while ClickHouse held
2,821 rows from 127.0.0.1 in two hours. The result was a lit-looking feed with `observed: false`,
`flows: 0`, no trend, and a Netflow tab full of data: three surfaces disagreeing about one fact.
"""
from __future__ import annotations

from weirvern.admin.web import _flow_exporters


def test_the_local_sensor_queries_loopback_even_when_it_reports_an_address():
    out = _flow_exporters([
        {"sensor_id": "weirvern", "local": True, "address": "192.0.2.176"},
        {"sensor_id": "remote", "local": False, "address": "198.51.100.20"},
    ])
    assert out["weirvern"] == ["192.0.2.176", "127.0.0.1", "::1"]
    assert out["remote"] == ["198.51.100.20"]


def test_a_local_sensor_with_no_address_still_queries_loopback():
    out = _flow_exporters([{"sensor_id": "weirvern", "local": True, "address": ""}])
    assert out["weirvern"] == ["127.0.0.1", "::1"]
