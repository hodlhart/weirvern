"""The fleet's flow evidence must query the exporter the hub actually uses.

WHY THIS FILE EXISTS. The local sensor's goflow2 exports from loopback. The payload built its
exporter list from `row.address` first, so once the hub registered with its management address
(192.0.2.176 in the fixture), it queried that address and never 127.0.0.1 -- while ClickHouse held
2,821 rows from 127.0.0.1 in two hours. The result was a lit-looking feed with `observed: false`,
`flows: 0`, no trend, and a Netflow tab full of data: three surfaces disagreeing about one fact.
"""
from __future__ import annotations

from types import SimpleNamespace

from weirvern.admin.web import _flow_exporters, _human_age
from weirvern.fleet_store import NETFLOW_STALE_S, flow_evidence


class FakeFlowClient:
    def __init__(self, rows):
        self.rows = rows

    def query(self, sql, parameters=None):
        assert "dateDiff" in sql, "the age must be computed by the database, not in Python"
        return SimpleNamespace(result_rows=list(self.rows))


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


def test_the_age_of_the_last_flow_comes_from_the_database():
    client = FakeFlowClient([("127.0.0.1", 9000, "2026-11-12 01:17:57", 7200)])
    evidence, err = flow_evidence(client, ["127.0.0.1"])
    assert err == ""
    assert evidence["127.0.0.1"]["age_s"] == 7200
    assert evidence["127.0.0.1"]["flows"] == 9000


def test_staleness_is_measured_in_minutes_not_days():
    # A 24-hour window kept a dead exporter looking healthy for a day; the threshold has to be
    # short enough that a stopped feed reads as stopped.
    assert NETFLOW_STALE_S <= 3600


def test_the_age_helper_reads_in_the_unit_a_person_uses():
    assert _human_age(45) == "45s"
    assert _human_age(13 * 60) == "13m"
    assert _human_age(3 * 3600) == "3h"
    assert _human_age(2 * 86400) == "2d"
    assert _human_age(None) == "an unknown time"
