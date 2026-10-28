"""External exposure is a peer dimension, never an alert entity."""
from __future__ import annotations

from weirvern import external, networks


def _scope(cidr: str, label: str, monitored: bool = True):
    return networks.normalize_scope(cidr, label=label, monitored=monitored, policy="full")


class _FakeClient:
    def __init__(self):
        self.calls: list[str] = []

    def query(self, sql: str, parameters=None, **_kw):
        self.calls.append(sql)
        if "GROUP BY prefix" in sql and "splitByChar('.', dst_addr)" in sql:
            rows = [("198.51.100", 3, 2000)]
        elif "GROUP BY prefix" in sql and "splitByChar('.', src_addr)" in sql:
            rows = [("203.0.113", 2, 1000)]
        elif "uniqExact(src_addr) AS peers" in sql:
            rows = [(2, 1000, 5)]
        elif "uniqExact(dst_addr) AS peers" in sql:
            rows = [(3, 2000, 7)]
        elif "max(peer_bytes)" in sql and "src_addr AS peer" in sql:
            rows = [(0.75,)]
        elif "max(peer_bytes)" in sql and "dst_addr AS peer" in sql:
            rows = [(0.25,)]
        else:
            rows = []
        return type("Result", (), {"result_rows": rows})()


def test_external_overview_counts_both_directions_without_creating_entities():
    client = _FakeClient()
    scopes = [_scope("192.0.2.0/24", "internal"), _scope("198.51.100.0/24", "vpn")]
    out = external.overview(client, scopes=scopes, hours=24)
    assert out["available"] is True
    assert out["observed_only"] is True
    assert out["inbound"]["peers"] == 2
    assert out["inbound"]["top_peer_share"] == 0.75
    assert out["inbound"]["top_prefixes"][0]["prefix"] == "203.0.113"
    assert out["outbound"]["peers"] == 3
    assert out["outbound"]["top_peer_share"] == 0.25
    assert out["outbound"]["top_prefixes"][0]["prefix"] == "198.51.100"


def test_external_overview_does_not_claim_a_reading_without_monitored_scopes():
    # A declaration set with only observed scopes has no internal endpoint to attribute
    # exposure to. That is a named state, not a calm zero.
    client = _FakeClient()
    scopes = [_scope("192.0.2.0/24", "internal", monitored=False)]
    out = external.overview(client, scopes=scopes, hours=24)
    assert out["available"] is False
    assert "no monitored scope" in out["note"].lower()


def test_external_prefix_is_a_presentation_key_not_a_replacement_for_the_address():
    # IPv4 is grouped to /24; IPv6 stays literal until an ASN/prefix source exists.
    assert "splitByChar" in external._prefix_expr("src_addr")
    assert "position(src_addr" in external._prefix_expr("src_addr")


def test_shadow_ranking_is_monotone_and_ties_share_a_position():
    from weirvern.models import external as shadow

    ranks = shadow._percentile([10.0, 10.0, 20.0, 30.0])
    assert ranks[0] == ranks[1]
    assert ranks[0] < ranks[2] < ranks[3]
    assert ranks[3] == 1.0
    assert all(0.0 <= value <= 1.0 for value in ranks)
