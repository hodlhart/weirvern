"""Discover: the raw-flow browser (Kibana's Discover over `weirvern.flows`).

The operator's ask, verbatim: "a discover like tab found in kibana. The ability to select flow
types or weirling and see all traffic". These tests pin the two properties that make it usable:
the filters land in the SQL as BOUND parameters, and the facets do not filter themselves out of
usefulness (the flow-type list must not be only the type already chosen).
"""

from pathlib import Path

import pytest

from tests.support_routes import routed
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

    def query(self, sql, parameters=None, **_kw):
        self.sql.append(sql)
        self.params.append(dict(parameters or {}))
        if "FROM weirvern.weirlings" in sql:
            return _Result(self.registry)
        # The direction evidence probe is a second flows query. This fake has no reverse
        # rows, which is the honest "no handshake captured" case; tests that need one use
        # _DirectionClient below.
        if "flow-direction reverse halves" in sql:
            return _Result([])
        if "flow-direction zeek conn" in sql:
            return _Result([])
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


def test_a_loopback_sampler_borrows_the_hubs_registered_name(monkeypatch):
    """The operator: "its name, not its IP." The collector writes 127.0.0.1; the hub's own id
    (SENSOR_ID, the same variable its heartbeat honours) says "weirvern"."""
    monkeypatch.setenv("SENSOR_ID", "weirvern")
    c = _Client()
    d = soc.discover(c, hours=6)
    assert d["rows"][0]["weirling"] == "weirvern"
    assert d["rows"][0]["sensor"] == "127.0.0.1", "the raw sampler must survive for filtering"
    facet = d["facets"]["weirlings"][0]
    assert facet["label"] == "weirvern" and facet["value"] == "127.0.0.1", (
        "the facet must show the name while still filtering on the address")


def test_the_local_name_never_comes_from_the_newest_heartbeat(monkeypatch):
    """REGRESSION, measured 2026-10-16: the first cut read the freshest sensor_status row, and
    on the live fleet that row belonged to a UNIT -- the local sampler showed "weirvern-dual".
    Every unit beats into that table; the resolver must not consult it at all."""
    monkeypatch.setenv("SENSOR_ID", "weirvern")
    c = _Client()
    soc.discover(c, hours=6)
    assert not any("sensor_status" in s for s in c.sql), (
        "the local weirling's name is being read from sensor_status -- whichever unit beat "
        "last would rename the hub")


def test_an_unregistered_sampler_keeps_its_raw_value(monkeypatch):
    """A guessed name is worse than an address: with nothing registered, show what we have."""
    monkeypatch.setenv("SENSOR_ID", "weirvern")
    c = _Client()
    c.registry = []
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
    assert routed("/api/discover") and "def _discover" in web
    assert '"/discover.js"' in web, "the file is not in STATIC_FILES: the tab would 404 its code"
    assert '<script src="/discover.js">' in html
    assert 'data-view="discover"' in html


# ── FLOW DIRECTION: PROOF, INFERENCE, OR UNKNOWN ────────────────────────────────────────────
# The Flows tab is a list of UNIDIRECTIONAL records. The reply half of an outbound HTTPS call
# has the remote service as its source; that is correct packet direction and a misleading
# "connection direction" unless the row says which half it is. These tests pin the evidence
# ladder: a bare SYN/SYN-ACK is proof, a reverse handshake is proof of the opposite role, a
# service port is only an inference, and no evidence stays unknown.

@pytest.mark.parametrize("flags,src_port,dst_port,expect", [
    (0x02, 51515, 443, ("request", "tcp-syn")),       # bare SYN: source opened
    (0x12, 443, 51515, ("reply", "tcp-syn-ack")),     # bare SYN-ACK: source answered
    (0x00, 51515, 443, ("request", "service-port")),  # request shape, no handshake
    (0x00, 443, 51515, ("reply", "service-port")),    # reply shape, no handshake
    (0x00, 10021, 28715, ("unknown", "")),            # two peers: no claim
    (0x1b, 10021, 28715, ("unknown", "")),            # cumulative SYN+ACK+FIN+PSH: no claim
    (0x1b, 51515, 443, ("request", "service-port")),  # aggregate does not override a port
    (0x00, 443, 8443, ("unknown", "")),               # both service ports: ambiguous
])
def test_flow_direction_never_turns_a_guess_into_a_fact(flags, src_port, dst_port, expect):
    row = {"proto": 6, "tcp_flags": flags, "src_port": src_port, "dst_port": dst_port,
           "src_addr": "198.51.100.20", "dst_addr": "203.0.113.10"}
    assert soc._flow_direction(row) == expect


def test_zeek_conn_originator_outranks_a_service_port_guess():
    row = {"proto": 6, "tcp_flags": 0, "src_addr": "198.51.100.20", "src_port": 51515,
           "dst_addr": "203.0.113.10", "dst_port": 443}
    assert soc._flow_direction(row, (), "reply") == ("reply", "zeek-conn")


def test_zeek_conn_lookup_matches_the_flow_tuple_and_its_reverse():
    from datetime import UTC, datetime

    class _ZeekClient:
        def query(self, sql, parameters=None, **_kw):
            class R:
                # A Zeek conn row is orig -> resp; this flow is the reverse half, so reply.
                result_rows = [
                    (datetime(2026, 10, 22, 12, 0, tzinfo=UTC).timestamp(),
                     "203.0.113.10", 443, "198.51.100.20", 51515, "tcp"),
                ]
            return R()

    row = {"timestamp": "2026-10-22T12:00:00+00:00",
           "src_addr": "198.51.100.20", "src_port": 51515,
           "dst_addr": "203.0.113.10", "dst_port": 443, "proto": 6}
    roles = soc._zeek_direction_roles(_ZeekClient(), [row], {"since": None, "until": None})
    assert roles[("198.51.100.20", 51515, "203.0.113.10", 443, 6)] == "reply"


def test_udp_dns_uses_the_service_port_without_pretending_it_is_a_handshake():
    row = {"proto": 17, "tcp_flags": 0, "src_port": 51515, "dst_port": 53,
           "src_addr": "198.51.100.20", "dst_addr": "198.51.100.1"}
    assert soc._flow_direction(row) == ("request", "service-port")
    row["src_port"], row["dst_port"] = 53, 51515
    assert soc._flow_direction(row) == ("reply", "service-port")


def test_the_reverse_halves_bare_syn_proves_this_half_is_the_reply():
    row = {"proto": 6, "tcp_flags": 0, "src_addr": "203.0.113.10", "src_port": 443,
           "dst_addr": "198.51.100.20", "dst_port": 51515}
    assert soc._flow_direction(row, [0x02]) == ("reply", "reverse-tcp-syn")


def test_the_reverse_halves_syn_ack_proves_this_half_is_the_request():
    row = {"proto": 6, "tcp_flags": 0, "src_addr": "198.51.100.20", "src_port": 51515,
           "dst_addr": "203.0.113.10", "dst_port": 443}
    assert soc._flow_direction(row, [0x12]) == ("request", "reverse-tcp-syn-ack")


def test_conflicting_reverse_handshakes_are_ambiguous_not_reversed():
    row = {"proto": 6, "tcp_flags": 0, "src_addr": "198.51.100.20", "src_port": 51515,
           "dst_addr": "203.0.113.10", "dst_port": 443}
    assert soc._flow_direction(row, [0x02, 0x12]) == ("request", "service-port")


class _DirectionClient(_Client):
    def __init__(self, row, reverse_rows):
        super().__init__()
        self.row = row
        self.reverse_rows = reverse_rows

    def query(self, sql, parameters=None, **kw):
        if "flow-direction reverse halves" in sql:
            self.sql.append(sql)
            self.params.append(dict(parameters or {}))
            return _Result(self.reverse_rows)
        if "ORDER BY timestamp DESC" in sql:
            self.sql.append(sql)
            self.params.append(dict(parameters or {}))
            return _Result([self.row])
        return super().query(sql, parameters=parameters, **kw)


def test_discover_puts_the_direction_and_opener_on_each_row():
    row = ("2026-10-16 06:00:00", "127.0.0.1", "203.0.113.10", 443,
           "198.51.100.20", 51515, 6, 900, 8, 0, 64, "", 0, 0)
    c = _DirectionClient(row, [("198.51.100.20", 51515, "203.0.113.10", 443, 6, [0x02])])
    out = soc.discover(c, hours=6)
    got = out["rows"][0]
    assert (got["direction"], got["direction_evidence"], got["direction_confidence"]) == (
        "reply", "reverse-tcp-syn", "proven")
    assert got["opened_by"] == "198.51.100.20:51515", (
        "the opener is the local ephemeral side, not the remote service that sent this half")
    reverse_sql = next(s for s in c.sql if "flow-direction reverse halves" in s)
    reverse_params = c.params[c.sql.index(reverse_sql)]
    assert "IN (" in reverse_sql and "203.0.113.10" not in reverse_sql
    assert reverse_params["d0a"] == "198.51.100.20", "the reverse key must be bound, not interpolated"

def test_the_reverse_direction_query_returns_one_row_per_key():
    """THE QUERY MUST NOT RETURN A ROW PER PACKET, and this pins the shape that makes it impossible.

    MEASURED ON THE LIVE DEPLOYMENT (2026-11-15): a page of 50 flows named a 5-tuple that appeared
    1,999,786 times in 24 hours, so the reverse-half probe materialised all of them, the GUI process
    reached ~730 MiB and was OOMKilled against its 512Mi limit. `/api/discover` answered nothing and
    the dashboard died mid-request.

    `_flow_direction` needs the SET of TCP roles the reverse half showed, not the packet count, so the
    distinct flags are aggregated server-side and the result is bounded by the page size.
    """
    row = ("2026-10-16 06:00:00", "127.0.0.1", "203.0.113.10", 443,
           "198.51.100.20", 51515, 6, 900, 8, 0, 64, "", 0, 0)
    c = _DirectionClient(row, [("198.51.100.20", 51515, "203.0.113.10", 443, 6, [0x02, 0x18])])
    out = soc.discover(c, hours=6)
    sql = next(s for s in c.sql if "flow-direction reverse halves" in s)
    assert "groupUniqArray(tcp_flags)" in sql, (
        "the reverse probe selects raw rows again, so a busy 5-tuple can return millions of them"
    )
    assert "GROUP BY src_addr, src_port, dst_addr, dst_port, proto" in sql, sql
    # The evidence still reaches the row: a reverse SYN proves this half is the reply.
    got = out["rows"][0]
    assert got["direction"] == "reply" and got["direction_evidence"] == "reverse-tcp-syn", got


def test_the_reverse_flags_accumulate_every_distinct_role():
    """Distinct flags, so a key that saw both a SYN and a SYN-ACK keeps BOTH roles.

    Collapsing them with a bitwise OR would turn 0x02|0x12 into 0x12 and silently lose the request
    half, which is why the query returns an array rather than one aggregated integer.
    """
    row = ("2026-10-16 06:00:00", "127.0.0.1", "203.0.113.10", 443,
           "198.51.100.20", 51515, 6, 900, 8, 0, 64, "", 0, 0)
    c = _DirectionClient(row, [("198.51.100.20", 51515, "203.0.113.10", 443, 6, [0x02, 0x12, 0x02])])
    out = soc.discover(c, hours=6)
    flags = soc._reverse_direction_flags(c, [{
        "src_addr": "203.0.113.10", "src_port": 443, "dst_addr": "198.51.100.20",
        "dst_port": 51515, "proto": 6}], {"since": "x", "until": "y"})
    key = ("198.51.100.20", 51515, "203.0.113.10", 443, 6)
    assert flags[key] == [0x02, 0x12, 0x02], flags
    assert out["rows"][0]["direction"] == "reply"
