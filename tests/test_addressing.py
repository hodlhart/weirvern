"""The addresses that appeared on a LIVE segment, and the rule that tells them from hosts.

This is a regression suite for a defect a human reported, not a hypothetical: the operator
opened the Netflow tab and said "the IPs in netflow look wrong". They were not wrong -- they
were frames from link-local, multicast and broadcast addresses, ranked as talkers.
"""

import ipaddress
from pathlib import Path

import pytest

from weirvern import addressing
from weirvern.admin import assets, soc, status

# EXACTLY the addresses observed, 2026-10-16, on the first real siphon session.
LIVE_NOISE = (
    "fe80::aa9c:6cff:fe96:b62d",   # the gateway's link-local (NDP)
    "ff02::fb",                    # mDNS, IPv6
    "ff02::2",                     # all-routers; the graph drew this as a host
    "224.0.0.251",                 # mDNS, IPv4
    "255.255.255.255",             # limited broadcast
    "192.168.3.255",               # subnet-directed broadcast
    "169.254.10.1",                # APIPA
    "127.0.0.1",
    "::1",
)
LIVE_HOSTS = (
    "192.168.3.194",               # the intercepted host
    "192.168.3.254",               # the sensor's own address on the segment
    "192.168.2.176", "192.168.3.1", "192.168.3.128",
    "10.42.0.1",
    "2606:4700::1111",
    # A documentation address is a HOST address by class. The test rows carrying 198.51.100.x
    # were a DATA problem (fixtures left in a live table, purged), not an addressing problem,
    # and this module must not hide them -- hiding the wrong thing is how a fix becomes a bug.
    "198.51.100.10",
)


@pytest.mark.parametrize("addr", LIVE_NOISE)
def test_addresses_that_actually_appeared_are_not_hosts(addr):
    assert addressing.is_noise(addr) is True


@pytest.mark.parametrize("addr", LIVE_HOSTS)
def test_real_unicast_addresses_are_hosts(addr):
    assert addressing.is_noise(addr) is False


def test_something_that_is_not_an_address_is_NOT_called_noise():
    """Unparseable is not evidence of noise. Filtering what we do not understand would hide
    real rows behind a parsing bug."""
    assert addressing.is_noise("not-an-address") is False
    assert addressing.is_noise("") is False
    assert addressing.is_noise(None) is False


def test_every_cidr_is_a_real_cidr():
    for cidr in addressing.NOISE_CIDRS:
        ipaddress.ip_network(cidr)  # raises if a typo ever lands in the list


def test_the_sql_fragment_asks_the_same_question_as_the_python():
    frag = addressing.sql_host("src_addr")
    for cidr in addressing.NOISE_CIDRS:
        assert cidr in frag, "the two languages must not drift apart in a list"
    assert "src_addr" in frag
    assert addressing.noise_sql("src_addr") == addressing.sql_host("src_addr").replace("= 0", "= 1")


class _Result:
    def __init__(self, rows):
        self.result_rows = rows


class _FakeClient:
    """Records every statement it is asked to run."""

    def __init__(self, rows=()):
        self.sql: list[str] = []
        self._rows = rows

    def query(self, sql, parameters=None, **_kw):
        self.sql.append(sql)
        return _Result(list(self._rows))


def test_every_panel_that_ranks_a_HOST_filters_by_the_same_rule():
    """The rule lives in one place and every host-ranking read carries it -- measured through
    the code paths themselves (fake client), not by grepping for a string."""
    client = _FakeClient()
    status.top_talkers(client, hours=6)
    soc.destination_spread(client, hours=6)
    assert any(addressing.sql_host("src_addr") in s for s in client.sql), client.sql

    client = _FakeClient()
    assets.connection_graph(client, hours=6)
    assert any(addressing.sql_host("src_addr") in s and addressing.sql_host("dst_addr") in s
               for s in client.sql), client.sql

    client = _FakeClient()
    assets.top_edges_for(client, ["192.168.3.194"], hours=6)
    assert any(addressing.sql_host("dst_addr") in s for s in client.sql), client.sql


def test_the_models_input_excludes_non_hosts_too():
    """The sweep's reads feed the detectors. A window keyed on a multicast group would train
    the baseline on something that is not a host."""
    src = (addressing.__file__.rsplit("weirvern/", 1)[0] + "weirvern/worker.py")
    text = Path(src).read_text()
    for table in ("flows_aggregated", "flows_aggregated_diversity", "flows_aggregated_temporal"):
        i = text.index(f"FROM weirvern.{table} WHERE window_start >= %(since)s AND")
        assert 'addressing.sql_host("src_addr")' in text[i:i + 500], table
