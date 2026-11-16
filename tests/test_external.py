"""External exposure is a peer dimension, never an alert entity."""
from __future__ import annotations

from weirvern import external, networks


def _scope(cidr: str, label: str, monitored: bool = True):
    return networks.normalize_scope(cidr, label=label, monitored=monitored, policy="full")


class _FakeClient:
    """Answers the ONE per-peer grouping the reader now issues, per direction.

    THE FIXTURE IS ROWS AT PEER GRAIN, NOT PRE-AGGREGATED ANSWERS. That is what the production query
    returns (`GROUP BY peer, prefix`), and it makes the test check the arithmetic the reader does --
    peers, totals, concentration, prefix rollup -- instead of restating constants the old three-query
    version returned from three different SQL shapes.
    """

    def __init__(self):
        self.calls: list[str] = []
        self.inbound = [
            # (peer, prefix, bytes, flows) -- the biggest peer carries three quarters of the bytes
            ("203.0.113.7", "203.0.113", 750, 4),
            ("203.0.113.9", "203.0.113", 150, 1),
            ("198.51.100.4", "198.51.100", 100, 2),
        ]
        self.outbound = [
            ("198.51.100.20", "198.51.100", 1400, 5),
            ("198.51.100.21", "198.51.100", 400, 1),
            ("203.0.113.30", "203.0.113", 200, 1),
        ]

    def query(self, sql: str, parameters=None, **_kw):
        self.calls.append(sql)
        if "src_addr AS peer" in sql:
            rows = self.inbound
        elif "dst_addr AS peer" in sql:
            rows = self.outbound
        else:
            rows = []
        return type("Result", (), {"result_rows": rows})()


def test_external_overview_counts_both_directions_without_creating_entities():
    client = _FakeClient()
    scopes = [_scope("192.0.2.0/24", "internal"), _scope("198.51.100.0/24", "vpn")]
    out = external.overview(client, scopes=scopes, hours=24)
    assert out["available"] is True
    assert out["observed_only"] is True
    assert out["inbound"]["peers"] == 3
    assert out["inbound"]["bytes"] == 1000
    assert out["inbound"]["flows"] == 7
    assert out["inbound"]["top_peer_share"] == 0.75
    assert out["inbound"]["top_prefixes"][0] == {"prefix": "203.0.113", "peers": 2, "bytes": 900}
    assert out["inbound"]["top_prefixes"][1] == {"prefix": "198.51.100", "peers": 1, "bytes": 100}
    assert out["outbound"]["peers"] == 3
    assert out["outbound"]["top_peer_share"] == 0.7
    assert out["outbound"]["top_prefixes"][0]["prefix"] == "198.51.100"
    assert out["outbound"]["top_prefixes"][0]["bytes"] == 1800
    # ONE SCAN PER DIRECTION, not three: the route held six full scans of a day of flows before.
    assert len(client.calls) == 2, client.calls


def test_an_empty_external_range_reads_as_zero_not_as_a_failure():
    """No peers is a measurement of zero; `None` is reserved for "could not read", which the UI
    renders as unavailable. The two must not share a shape."""
    class _Empty(_FakeClient):
        def query(self, sql, parameters=None, **_kw):
            self.calls.append(sql)
            return type("Result", (), {"result_rows": []})()

    scopes = [_scope("192.0.2.0/24", "internal")]
    out = external.overview(_Empty(), scopes=scopes, hours=24)
    assert out["inbound"] == {"peers": 0, "bytes": 0, "flows": 0, "top_peer_share": 0.0,
                              "top_prefixes": [], "error": ""}


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
