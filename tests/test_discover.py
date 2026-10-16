"""Discover: the raw-flow browser (Kibana's Discover over `weirvern.flows`).

The operator's ask, verbatim: "a discover like tab found in kibana. The ability to select flow
types or weirling and see all traffic". These tests pin the two properties that make it usable:
the filters land in the SQL as BOUND parameters, and the facets do not filter themselves out of
usefulness (the flow-type list must not be only the type already chosen).
"""

from pathlib import Path

import pytest

from weirvern.admin import soc


class _Result:
    def __init__(self, rows):
        self.result_rows = rows


class _Client:
    """Answers each query the discover path makes, recording every statement."""

    def __init__(self):
        self.sql: list[str] = []
        self.params: list[dict] = []
        self.registry = [("weirvern", ""), ("weirvern-eth2", "")]
        self.heartbeat = [("Weirvern",)]

    def query(self, sql, parameters=None, **_kw):
        self.sql.append(sql)
        self.params.append(dict(parameters or {}))
        if "FROM weirvern.weirlings" in sql:
            return _Result(self.registry)
        if "FROM weirvern.sensor_status" in sql:
            return _Result(self.heartbeat)
        # Order matters: the HISTOGRAM query also selects count(), so it must be matched first
        # or the histogram gets the scalar count's shape and the row builder indexes past it.
        if "toStartOfInterval" in sql:
            return _Result([])
        if sql.strip().startswith("SELECT count()"):
            return _Result([(7,)])
        if "GROUP BY proto" in sql:
            return _Result([(6, 5), (17, 2)])
        if "GROUP BY sampler_address" in sql:
            return _Result([("127.0.0.1", 7)])
        return _Result([("2026-10-16 06:00:00", "127.0.0.1", "198.51.100.20", 4444,
                         "198.51.100.77", 443, 6, 1234, 12, 0, 64, "", 0, 0)])


LIVE_TYPES = (("tcp", 6), ("udp", 17), ("icmp", 1), ("icmp6", 58), ("17", 17), ("6", 6))


@pytest.mark.parametrize("token,expect", LIVE_TYPES)
def test_flow_types_read_like_a_human_writes_them(token, expect):
    assert soc.proto_number(token) == expect


def test_an_unreadable_flow_type_is_a_sentence_not_a_silent_drop():
    """"silently dropped" would show MORE traffic than was asked for, which reads as working."""
    with pytest.raises(ValueError, match="not a flow type"):
        soc.proto_number("banana")


def test_no_flow_type_means_no_filter():
    assert soc.proto_number("") is None
    assert soc.proto_number(None) is None


def test_unknown_protocol_numbers_stay_numbers():
    assert soc.proto_label(250) == "proto 250"
    assert soc.proto_label(6) == "tcp"


def test_the_filters_land_in_the_sql_as_bound_parameters():
    c = _Client()
    out = soc.discover(c, hours=6, proto=6, addr="198.51.100.20", port=443, sensor="127.0.0.1")
    row_sql = next(s for s in c.sql if "ORDER BY timestamp DESC" in s)
    params = c.params[c.sql.index(row_sql)]
    assert "proto = %(proto)s" in row_sql and params["proto"] == 6
    assert "positionCaseInsensitive(src_addr, %(addr)s)" in row_sql
    assert "dst_port = %(port)s" in row_sql or "src_port = %(port)s" in row_sql
    assert "sampler_address = %(sensor)s" in row_sql and params["sensor"] == "127.0.0.1"
    assert "%(n)s" in row_sql and "%(o)s" in row_sql, "paging must reach the SQL"
    assert params["n"] == 100 and params["o"] == 0
    assert out["available"] is True and out["total"] == 7
    assert out["rows"][0]["proto_label"] == "tcp"
    assert out["rows"][0]["src_addr"] == "198.51.100.20"


def test_the_facets_do_not_filter_themselves_out_of_usefulness():
    """A flow-type list filtered by the chosen flow type answers "which types are there?" with
    "the one you already picked" -- which is how a filter bar becomes a dead end."""
    c = _Client()
    soc.discover(c, hours=6, proto=6, sensor="127.0.0.1")
    proto_sql = next(s for s in c.sql if "GROUP BY proto" in s)
    sensor_sql = next(s for s in c.sql if "GROUP BY sampler_address" in s)
    assert "proto = %(proto)s" not in proto_sql, "the flow-type facet filtered itself"
    assert "sampler_address = %(sensor)s" not in sensor_sql, "the sensor facet filtered itself"
    # ... but the OTHER filters still apply to both facets.
    assert "%(since)s" in proto_sql and "%(since)s" in sensor_sql


def test_a_clicked_value_becomes_an_exact_filter():
    """"Click a source and it is added to the filter" -- the operator's ask. The chip's field
    must land as an exact comparison, not a substring: clicking 198.51.100.1 must not also match
    198.51.100.11."""
    c = _Client()
    soc.discover(c, hours=6, src=["198.51.100.1"], dport=[443])
    row_sql = next(s for s in c.sql if "ORDER BY timestamp DESC" in s)
    params = c.params[c.sql.index(row_sql)]
    assert "src_addr IN %(src)s" in row_sql and params["src"] == ("198.51.100.1",)
    assert "dst_port IN %(dport)s" in row_sql and params["dport"] == (443,)


def test_same_field_chips_are_ORed_and_different_fields_ANDed():
    """Two sources clicked must show BOTH (IN), and a port on top must narrow them: that is the
    semantics of a filter bar, and the alternative -- ANDing two sources -- matches nothing."""
    c = _Client()
    soc.discover(c, hours=6, src=["198.51.100.1", "198.51.100.2"], dst=["198.51.100.9"])
    row_sql = next(s for s in c.sql if "ORDER BY timestamp DESC" in s)
    params = c.params[c.sql.index(row_sql)]
    assert params["src"] == ("198.51.100.1", "198.51.100.2")
    assert "src_addr IN %(src)s AND dst_addr IN %(dst)s" in row_sql, (
        "different fields must AND together in one WHERE clause")


def test_chips_apply_to_the_facets_too_so_the_counts_follow_the_filter():
    c = _Client()
    soc.discover(c, hours=6, src=["198.51.100.1"])
    proto_sql = next(s for s in c.sql if "GROUP BY proto" in s)
    assert "%(src)s" in proto_sql, "the facets ignored the chip filters"


def test_a_loopback_sampler_borrows_the_hubs_registered_name():
    """The operator: "its name, not its IP." The collector writes 127.0.0.1; the registry says
    "weirvern" -- and the two agree case aside (the heartbeat says "Weirvern")."""
    c = _Client()
    d = soc.discover(c, hours=6)
    assert d["rows"][0]["weirling"] == "weirvern"
    assert d["rows"][0]["sensor"] == "127.0.0.1", "the raw sampler must survive for filtering"
    facet = d["facets"]["weirlings"][0]
    assert facet["label"] == "weirvern" and facet["value"] == "127.0.0.1", (
        "the facet must show the name while still filtering on the address")


def test_an_unregistered_sampler_keeps_its_raw_value():
    """A guessed name is worse than an address: with nothing registered, show what we have."""
    c = _Client()
    c.registry = []
    c.heartbeat = []
    d = soc.discover(c, hours=6)
    assert d["rows"][0]["weirling"] == "127.0.0.1"


def test_a_window_is_still_a_window():
    c = _Client()
    soc.discover(c, hours=1)
    assert all("%(since)s" in s and "%(until)s" in s for s in c.sql if "weirvern.flows" in s)


def test_paging_is_clamped_so_a_url_cannot_ask_for_everything():
    c = _Client()
    out = soc.discover(c, hours=6, limit=99999, offset=-5)
    assert out["limit"] == 500 and out["offset"] == 0


def test_the_discover_route_and_script_are_served():
    """A route without a served script (or the reverse) is a tab that renders nothing."""
    web = (Path(soc.__file__).resolve().parents[1] / "admin" / "web.py").read_text()
    html = (Path(soc.__file__).resolve().parents[1] / "admin" / "web" / "index.html").read_text()
    assert '"/api/discover"' in web and "def _discover" in web
    assert '"/discover.js"' in web, "the file is not in STATIC_FILES: the tab would 404 its code"
    assert '<script src="/discover.js">' in html
    assert 'data-view="discover"' in html
