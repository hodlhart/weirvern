"""Assets and scan targets are limited to the networks the operator declares monitored.

WHY THIS EXISTS. The inventory was built from "every address that appeared on the wire", so it
filled with external peers -- CDN edges, torrent swarm members, resolvers -- and the Assets count
(562 on this box) described the internet as much as the LAN. Two things follow from that being
wrong: an inventory should be a list of things the operator is responsible for, and the same list
decides what nmap may touch. We only ever scan our own systems, so the scope rule has to be one
rule, in one place, enforced in SQL and again in Python.
"""
from __future__ import annotations

import ipaddress

from weirvern import monitored


class _Result:
    def __init__(self, rows):
        self.result_rows = rows


class _Client:
    def __init__(self, rows=None, exc=None):
        self._rows = rows or []
        self._exc = exc

    def query(self, _sql, *_a, **_kw):
        if self._exc:
            raise self._exc
        return _Result(self._rows)


def test_only_rows_flagged_monitored_are_our_networks():
    client = _Client([("192.168.3.0/24",), ("192.168.2.0/24",)])
    nets = monitored.networks(client)
    assert [str(n) for n in nets] == ["192.168.3.0/24", "192.168.2.0/24"]
    assert monitored.in_scope("192.168.3.58", nets)
    assert not monitored.in_scope("8.8.8.8", nets)
    assert not monitored.in_scope("192.168.5.20", nets)


def test_an_unreadable_scope_table_is_not_permission_to_scan_everything():
    """The dangerous default: a failed read must match NOTHING, not everything."""
    client = _Client(exc=RuntimeError("clickhouse unreachable"))
    nets = monitored.networks(client)
    assert nets == []
    assert monitored.sql_predicate("src_addr", nets) == "0"


def test_the_predicate_names_every_network_and_nothing_else():
    nets = [ipaddress.ip_network("192.168.3.0/24"), ipaddress.ip_network("10.0.0.0/8")]
    sql = monitored.sql_predicate("dst_addr", nets)
    assert sql.count("isIPAddressInRange(dst_addr") == 2
    assert "192.168.3.0/24" in sql and "10.0.0.0/8" in sql
    assert sql.startswith("(")


def test_a_junk_scope_row_is_skipped_rather_than_crashing_the_view():
    client = _Client([("192.168.3.0/24",), ("third floor IDF",), ("",)])
    assert [str(n) for n in monitored.networks(client)] == ["192.168.3.0/24"]


def test_ipv4_and_ipv6_are_judged_separately():
    nets = [ipaddress.ip_network("192.168.3.0/24"), ipaddress.ip_network("fd00::/8")]
    assert monitored.in_scope("fd00::1", nets)
    assert monitored.in_scope("192.168.3.10", nets)
    assert not monitored.in_scope("2001:db8::1", nets)


def test_the_summary_states_the_rule_so_the_panel_can_print_it():
    s = monitored.summary([ipaddress.ip_network("192.168.3.0/24")])
    assert s["enforced"] is True
    assert s["networks"] == ["192.168.3.0/24"]
    assert "peer" in s["rule"]
