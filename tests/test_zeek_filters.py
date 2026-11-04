"""The Zeek cross-filters are server-side and shared by every panel.

Clicking a log, service or DNS name is a HOST selection: the three charts read different
tables, so the common denominator is the hosts that match the selected value. A browser-side
filter would drop rows that were never fetched; a filter that only changes one chart would
leave the other panels answering a different question. These tests pin the SQL contract.
"""

from __future__ import annotations

import datetime

from weirvern.admin import soc


class _Result:
    def __init__(self, rows):
        self.result_rows = rows


class _Client:
    def __init__(self, by_table=None):
        self.by_table = by_table or {}
        self.seen: list[tuple[str, dict]] = []

    def query(self, sql, parameters=None):
        self.seen.append((sql, dict(parameters or {})))
        for table, rows in self.by_table.items():
            if f"weirvern.{table}" in sql:
                return _Result(rows)
        # Shapes that satisfy each consumer without pretending to be a real row.
        if "arrayJoin(splitByChar" in sql:
            return _Result([("http", 8)])
        if "uniqExact(src_addr)" in sql:
            return _Result([("example.test", 8, 2)])
        if "AS addr" in sql:
            return _Result([("198.51.100.7", 8)])
        return _Result([(0, 0, None)])


def _params(client):
    return client.seen[-1][1]


def test_a_log_filter_reads_only_that_log_and_scopes_it_to_its_hosts():
    client = _Client({"zeek_ssl": [(2, 71, datetime.datetime(2026, 1, 1, 0, 0))]})
    out = soc.zeek_counts(client, hours=24, filters={"log": "ssl"})
    assert [p["log"] for p in out["points"]] == ["ssl"]
    sql, params = client.seen[-1]
    assert "FROM weirvern.zeek_ssl" in sql
    assert "IN (SELECT DISTINCT toString(src_addr) FROM weirvern.zeek_ssl" in sql
    assert params["since"] and params["until"]


def test_an_unfiltered_count_has_no_in_subquery():
    client = _Client({"zeek_conn": [(4, 9, None)]})
    soc.zeek_counts(client, hours=24)
    assert len(client.seen) == len(soc.ZEEK_LOGS)
    assert all("IN (SELECT" not in sql for sql, _ in client.seen)


def test_service_filter_is_exact_and_binds_its_parameter():
    client = _Client()
    soc.zeek_services(client, hours=24, filters={"service": "http,ssl"})
    sql, params = client.seen[-1]
    assert "has(splitByChar(',', service), %(service)s)" in sql
    assert params["service"] == "http,ssl"
    assert "IN (SELECT DISTINCT src_addr FROM weirvern.zeek_conn" in sql


def test_dns_filter_is_exact_and_binds_its_parameter():
    client = _Client()
    soc.zeek_dns_names(client, hours=24, filters={"query": "ads.example.test"})
    sql, params = client.seen[-1]
    assert "query = %(query)s" in sql
    assert params["query"] == "ads.example.test"
    assert "IN (SELECT DISTINCT src_addr FROM weirvern.zeek_dns" in sql


def test_the_drill_down_accepts_the_same_host_scope():
    client = _Client({"zeek_conn": [("198.51.100.7", 3)]})
    out = soc.zeek_log_hosts(client, table="zeek_conn", label="conn", hours=24,
                             filters={"service": "http"})
    assert out["available"] is True
    assert [p["addr"] for p in out["points"]] == ["198.51.100.7"]
    sql, params = client.seen[-1]
    assert "IN (SELECT DISTINCT src_addr FROM weirvern.zeek_conn" in sql
    assert params["service"] == "http"


def test_an_unknown_log_is_refused_before_any_sql_runs():
    client = _Client()
    try:
        soc.zeek_counts(client, filters={"log": "not-a-log"})
    except ValueError as exc:
        assert "unknown Zeek log" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("an unknown log must not reach the query")
    assert client.seen == []


def test_a_host_filter_is_exact_and_binds_its_parameter():
    """A host-page service pivot must ask "this host", not "the whole fleet"."""
    client = _Client()
    soc.zeek_services(client, hours=24, filters={"host": "198.51.100.7"})
    sql, params = client.seen[-1]
    assert "src_addr = %(host)s" in sql
    assert params["host"] == "198.51.100.7"
