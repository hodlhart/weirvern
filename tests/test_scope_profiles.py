"""The host scope: a host is compared with ITSELF at this hour, not with the fleet.

Fixtures use RFC 5737 ranges so the tree carries no deployment addresses.
"""
from __future__ import annotations

from weirvern.models import scopes


class _R:
    def __init__(self, rows):
        self.result_rows = rows


class _C:
    """Answers by fragment: scopes, the profile quantiles, toHour(now()), and the recent window."""

    def __init__(self, profile_rows, now_hour, recent_rows, scope_rows=None):
        self._p, self._h, self._r = profile_rows, now_hour, recent_rows
        self._s = scope_rows if scope_rows is not None else [("192.0.2.0/24",)]

    def query(self, sql, *a, **kw):
        if "network_scopes" in sql:
            return _R(self._s)
        if "quantile(0.5)(bytes)" in sql:
            return _R(self._p)
        if "toString(now() - INTERVAL" in sql:
            return _R([("2026-01-01 00:00:00",)])
        if "toHour(now())" in sql:
            return _R([(self._h,)])
        return _R(self._r)


def test_a_host_is_scored_against_its_own_p90_for_THIS_hour():
    client = _C([("192.0.2.58", 2, 10_000_000, 50_000_000, 1100)], 2,
                [("192.0.2.58", 40_000_000, 1050)])
    rows = scopes.rank_departures(client)
    assert rows[0]["ratio"] == 0.8, rows[0]


def test_a_sleeper_that_uploads_is_not_hidden_by_the_fleet():
    client = _C([("192.0.2.44", 13, 1_000, 5_000, 3)], 13, [("192.0.2.44", 500_000, 2)])
    assert scopes.rank_departures(client)[0]["ratio"] == 100.0


def test_a_host_with_no_history_for_this_hour_is_NOT_scored():
    client = _C([("192.0.2.9", 9, 1_000, 2_000, 4)], 3, [("192.0.2.9", 999_999, 4)])
    row = scopes.rank_departures(client)[0]
    assert row["state"] == "new_hour" and row["ratio"] is None, row


def test_the_query_MERGES_the_states_before_quantiles():
    """flows_window holds AggregateFunction states: summing them is illegal, and grouping without
    merging would quantile the fragments -- the defect the ratchet test exists to prevent."""
    seen = {}

    class _Rec(_C):
        def query(self, sql, *a, **kw):
            if "quantile" in sql:
                seen["sql"] = sql
            return super().query(sql, *a, **kw)

    scopes.host_hour_profiles(_Rec([], 0, []))
    sql = seen["sql"]
    for fn in ("sumMerge(total_bytes)", "uniqMerge(unique_dst_ips)"):
        assert fn in sql, fn
    assert "flows_aggregated" not in sql, "the profile went back to the fragmenting table"


def test_two_hosts_with_the_same_endpoints_are_a_class_even_if_one_is_chatty():
    sets = {
        "iphone-a": {"apple.com", "push.apple.com", "icloud.com"},
        "iphone-b": {"apple.com", "push.apple.com", "icloud.com"},
        "chatty": {"apple.com", "push.apple.com", "icloud.com",
                   *{f"peer{i}.net" for i in range(500)}},
        "laptop": {"github.com", "slack.com", "apple.com"},
    }
    members = sorted(m for g in scopes.class_profiles(sets) for m in g["members"])
    assert "iphone-a" in members and "iphone-b" in members
    assert "laptop" not in members


def test_a_peer_new_to_one_host_but_ROUTINE_FOR_ITS_CLASS_is_not_novelty():
    sets = {
        "iphone-a": {"apple.com", "icloud.com", "push.apple.com"},
        "iphone-b": {"apple.com", "icloud.com", "push.apple.com", "gateway.icloud.com"},
    }
    groups = scopes.class_profiles(sets)
    out = scopes.explain("iphone-a", {"apple.com", "icloud.com", "push.apple.com",
                                      "gateway.icloud.com"}, groups, sets)
    assert out["novel_count"] == 0 and out["explained"] == 4, out


def test_the_era_marker_is_a_timestamp_and_the_summary_states_the_control():
    client = _C([], 0, [])
    assert len(scopes.era_start(client, 6)) >= 19
    s = scopes.summarise([{"ratio": 1.1}, {"ratio": 3.0}, {"ratio": None}])
    assert s["hosts_scored"] == 2 and s["hosts_without_history"] == 1
    assert "thousands" in s["quiet_control"]
