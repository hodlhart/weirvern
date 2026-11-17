"""The SEGMENT scope: the same merged rows, folded into the subnet that contains them.

Fixtures use RFC 5737 ranges so the tree carries no deployment addresses.
"""
from __future__ import annotations

from weirvern.models import scopes


class _R:
    def __init__(self, rows):
        self.result_rows = rows


class _C:
    """Answers the segment query, the scope, the era, and toHour(now())."""

    def __init__(self, rows, now_hour=3, scope_rows=None):
        self._rows, self._h = rows, now_hour
        self._s = scope_rows if scope_rows is not None else [("192.0.2.0/24",)]
        self.seen = {}

    def query(self, sql, *a, **kw):
        self.seen.setdefault("sql", []).append(sql)
        self.seen.setdefault("params", []).append(kw.get("parameters") or {})
        if "network_scopes" in sql:
            return _R(self._s)
        if "toString(now() - INTERVAL" in sql:
            return _R([("2026-01-01 00:00:00",)])
        if "toHour(now())" in sql:
            return _R([(self._h,)])
        return _R(self._rows)


def test_two_hosts_in_one_subnet_become_one_segment_with_SUMMED_bytes():
    rows = [
        ("192.0.2.10", "w1", 3, 1_000, 5, 1),
        ("192.0.2.20", "w1", 3, 2_000, 9, 1),
        ("198.51.100.7", "w1", 3, 7_000, 2, 1),
    ]
    profiles, recent = scopes.segment_hour_profiles(_C(rows))
    assert profiles["192.0.2.0/24"][3]["median_bytes"] == 3_000
    assert profiles["198.51.100.0/24"][3]["median_bytes"] == 7_000
    assert recent["192.0.2.0/24"]["bytes"] == 3_000


def test_peers_are_the_WIDEST_host_not_the_sum():
    """Distinct destinations cannot be added: three hosts each seeing the same gateway do not
    make three peers. The segment carries a floor, so it can never overstate diversity."""
    rows = [("192.0.2.10", "w1", 3, 1_000, 5, 1), ("192.0.2.20", "w1", 3, 2_000, 9, 1)]
    profiles, recent = scopes.segment_hour_profiles(_C(rows))
    assert profiles["192.0.2.0/24"][3]["median_peers"] == 9
    assert recent["192.0.2.0/24"]["peers"] == 9


def test_the_segment_query_MERGES_states_and_never_reads_the_fragmenting_table():
    client = _C([])
    scopes.segment_hour_profiles(client)
    sql = " ".join(client.seen["sql"])
    assert "sumMerge(total_bytes)" in sql and "uniqMerge(unique_dst_ips)" in sql, sql
    assert "flows_aggregated" not in sql


def test_the_recent_flag_is_computed_by_the_DATABASE_not_by_this_process():
    """The recurring defect in this repo is a Python clock compared with a ClickHouse timestamp.
    The split has to be a column the server computed."""
    client = _C([])
    scopes.segment_hour_profiles(client, recent_minutes=90)
    sql = " ".join(client.seen["sql"])
    assert "if(window_start >= now() - INTERVAL %(m)s MINUTE" in sql, sql
    # and the caller's window reached the query as a parameter, not baked into the text
    assert any(p.get("m") == 90 for p in client.seen["params"]), client.seen["params"]


def test_a_whole_segment_departing_OUTRANKS_a_quiet_one():
    # ten ordinary windows for this hour, then one hour in which the whole /24 sends 10x
    rows = []
    for w in range(10):
        rows += [("192.0.2.10", f"w{w}", 3, 400, 5, 0),
                 ("192.0.2.20", f"w{w}", 3, 600, 9, 0),
                 ("198.51.100.7", f"w{w}", 3, 50_000, 2, 0)]
    rows += [("192.0.2.10", "wR", 3, 4_000, 5, 1),
             ("192.0.2.20", "wR", 3, 6_000, 9, 1),
             ("198.51.100.7", "wR", 3, 50_000, 2, 1)]

    class _Rank(_C):
        def query(self, sql, *a, **kw):
            if "toHour(now())" in sql:
                self.seen.setdefault("sql", []).append(sql)
                return _R([(3,)])
            return super().query(sql, *a, **kw)

    rows_out = scopes.rank_segments(_Rank(rows))
    assert rows_out[0]["segment"] == "192.0.2.0/24", rows_out
    assert rows_out[0]["ratio"] == 10.0, rows_out[0]
    assert rows_out[0]["state"] == "scored"


def test_segment_of_parses_v4_and_v6_and_refuses_junk():
    assert scopes.segment_of("192.0.2.10") == "192.0.2.0/24"
    assert scopes.segment_of("2001:db8:1:2::5", bits=48) == "2001:db8:1::/48"
    assert scopes.segment_of("2001:db8::1", bits=64) == "2001:db8::/64"
    assert scopes.segment_of("not-an-address") is None


def test_the_summary_states_the_control_it_is_not():
    s = scopes.summarise_segments([{"ratio": 10.0}, {"ratio": 1.0}, {"ratio": None}])
    assert s["segments_scored"] == 2 and s["segments_without_history"] == 1
    assert "not a backup" in s["note"]
