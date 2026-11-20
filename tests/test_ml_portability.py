"""Portability guards for the ML contract.

The product must learn a network it has never seen. Two properties make that possible and
are cheap to lose in a refactor:

  * the feature vector contains BEHAVIOUR, not identity -- no address, subnet, interface,
    hostname or VLAN id may enter it;
  * a new deployment reports warm-up honestly instead of treating "no data yet" as a quiet
    network and paging from a baseline it has not learned.
"""
from __future__ import annotations

from types import SimpleNamespace

from weirvern.features import CROSS_SECTIONAL_FEATURES, HOST_FEATURES, IF_FEATURES, extract_features
from weirvern.models import readiness


def test_feature_names_do_not_encode_network_identity():
    forbidden = (
        "src_addr", "dst_addr", "hostname", "subnet", "prefix", "vlan",
        "interface", "iface", "network_scope", "scope_id",
    )
    for name in HOST_FEATURES + IF_FEATURES + CROSS_SECTIONAL_FEATURES:
        assert not any(token in name for token in forbidden), (
            f"feature {name!r} encodes network identity; a model trained on it would learn "
            "the deployment, not the behaviour"
        )


def test_feature_vector_is_unchanged_by_address_or_scope_renaming():
    """The same behaviour under a different address plan must produce the same vector."""
    flow = {
        "src_addr": "198.51.100.5", "dst_addr": "198.51.100.9",
        "total_bytes": 12_000, "total_packets": 120,
        "unique_dst_ips": 4, "flow_count": 8,
        "window_start": "2026-01-01T12:00:00",
    }
    renamed = {
        **flow, "src_addr": "203.0.113.5", "dst_addr": "203.0.113.9",
        "network_scope": "a-different-network",
    }
    assert extract_features(flow) == extract_features(renamed)


class _Res:
    def __init__(self, rows):
        self.result_rows = rows


class _Client:
    def __init__(self, responses):
        self.responses = list(responses)
        self.queries: list[str] = []

    def query(self, sql):
        self.queries.append(sql)
        if not self.responses:
            raise RuntimeError("unexpected query")
        return self.responses.pop(0)


def _settings(**kw):
    base = {
        "ml_warmup_hours": 24, "ml_warmup_min_windows": 12, "ml_warmup_min_hosts": 1,
    }
    base.update(kw)
    return SimpleNamespace(**base)


def test_a_fresh_deployment_is_warming_and_does_not_page():
    client = _Client([_Res([(25, 5, 1, 1)]), _Res([(1,)])])
    state = readiness.assess(client, _settings())
    assert state.state == "warming"
    assert not state.ready
    assert any("distinct windows" in reason for reason in state.reasons)


def test_enough_local_windows_and_hosts_are_ready():
    client = _Client([_Res([(500, 48, 4, 6)]), _Res([(3,)])])
    state = readiness.assess(client, _settings())
    assert state.state == "ready"
    assert state.ready
    assert (state.windows, state.hosts, state.zeek_hosts) == (48, 4, 3)


def test_an_unreadable_baseline_does_not_masquerade_as_ready():
    class Broken:
        def query(self, sql):
            raise RuntimeError("clickhouse unavailable")

    state = readiness.assess(Broken(), _settings())
    assert state.state == "unknown"
    assert not state.ready
    assert "clickhouse unavailable" in " ".join(state.reasons)


def test_warmup_can_be_disabled_explicitly():
    client = _Client([])  # no query should be issued
    state = readiness.assess(client, _settings(ml_warmup_hours=0))
    assert state.state == "disabled"
    assert state.ready
    assert client.queries == []


def test_missing_zeek_is_reported_but_does_not_block_a_flow_only_network():
    client = _Client([_Res([(500, 48, 4, 6)]), _Res([])])
    state = readiness.assess(client, _settings())
    assert state.ready, "flow-only traffic must be able to complete warm-up"
    assert "Zeek coverage absent" in state.reasons
