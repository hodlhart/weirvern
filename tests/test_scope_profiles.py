"""The host scope: a host is compared with ITSELF at this hour, not with the fleet."""
from __future__ import annotations

from weirvern.models import scopes


class _R:
    def __init__(self, rows):
        self.result_rows = rows


class _C:
    def __init__(self, profile_rows, now_hour, recent_rows):
        self._p, self._h, self._r = profile_rows, now_hour, recent_rows

    def query(self, sql, *a, **kw):
        if "quantile(0.5)(total_bytes)" in sql:
            return _R(self._p)
        if "toHour(now())" in sql:
            return _R([(self._h,)])
        return _R(self._r)


def test_a_host_is_scored_against_its_own_p90_for_THIS_hour():
    # The torrent node: huge at 02:00 every night, and ordinary right now.
    client = _C([("192.168.3.58", 2, 10_000_000, 50_000_000, 1100)],
                now_hour=2, recent_rows=[("192.168.3.58", 40_000_000, 1050)])
    rows = scopes.rank_departures(client)
    assert rows[0]["host"] == "192.168.3.58"
    assert rows[0]["ratio"] == 0.8, rows[0]


def test_a_sleeper_that_uploads_is_NOT_hidden_by_the_fleet():
    client = _C([("192.168.3.44", 13, 1_000, 5_000, 3)],
                now_hour=13, recent_rows=[("192.168.3.44", 500_000, 2)])
    rows = scopes.rank_departures(client)
    assert rows[0]["ratio"] == 100.0, rows[0]


def test_a_host_with_no_history_for_this_hour_is_NOT_scored():
    """Inventing a profile for an unseen hour is the fleet-wide mistake in miniature."""
    client = _C([("192.168.3.9", 9, 1_000, 2_000, 4)], now_hour=3,
                recent_rows=[("192.168.3.9", 999_999, 4)])
    rows = scopes.rank_departures(client)
    assert rows[0]["state"] == "new_hour" and rows[0]["ratio"] is None, rows[0]


def test_the_summary_states_the_control():
    s = scopes.summarise([{"ratio": 1.1}, {"ratio": 3.0}, {"ratio": None}])
    assert s["hosts_scored"] == 2 and s["hosts_without_history"] == 1
    assert s["worst_ratio"] == 3.0
    assert "thousands" in s["quiet_control"]


def test_two_hosts_with_the_same_endpoints_are_a_class_even_if_one_is_chatty():
    """The iPhone case: size is irrelevant, OVERLAP is the test."""
    sets = {
        "iphone-a": {"apple.com", "push.apple.com", "icloud.com", "cdn.apple.com"},
        "iphone-b": {"apple.com", "push.apple.com", "icloud.com"},
        "chatty": {"apple.com", "push.apple.com", "icloud.com", "cdn.apple.com",
                   *{f"peer{i}.net" for i in range(500)}},
        "laptop": {"github.com", "slack.com", "apple.com"},
    }
    groups = scopes.class_profiles(sets)
    members = sorted(m for g in groups for m in g["members"])
    assert "iphone-a" in members and "iphone-b" in members, groups
    assert "laptop" not in members, groups


def test_a_peer_new_to_one_host_but_ROUTINE_FOR_ITS_CLASS_is_not_novelty():
    sets = {
        "iphone-a": {"apple.com", "icloud.com", "push.apple.com"},
        "iphone-b": {"apple.com", "icloud.com", "push.apple.com", "gateway.icloud.com"},
    }
    groups = scopes.class_profiles(sets)
    out = scopes.explain("iphone-a", {"apple.com", "icloud.com", "push.apple.com",
                                      "gateway.icloud.com"}, groups, sets)
    assert out["novel_count"] == 0, out          # the sibling's endpoint explains it
    assert out["explained"] == 4, out


def test_the_era_marker_exists_and_is_a_timestamp():
    assert len(scopes.era_start(6)) >= 19
