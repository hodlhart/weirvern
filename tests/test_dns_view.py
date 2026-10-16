"""DNS view: port 53 made readable, and the reverse map's read path.

The operator's ask, verbatim: "for domain blocks can we view dns on port 53 and can we reverse
lookup ips with a small cache". These tests pin the two properties that make the view
trustworthy: filters land as BOUND parameters (a dropped filter shows MORE than was asked for,
which reads as working), and the answers parser accepts only tokens that PARSE as addresses --
the column mixes real answers with NSEC/TXT mDNS chatter (measured on the box).
"""

from weirvern.admin import soc


class _Result:
    def __init__(self, rows):
        self.result_rows = rows


class _Client:
    """Answers each query the DNS path makes, recording every statement."""

    def __init__(self):
        self.sql: list[str] = []
        self.params: list[dict] = []

    def query(self, sql, parameters=None, **_kw):
        self.sql.append(sql)
        self.params.append(dict(parameters or {}))
        if "toStartOfInterval" in sql:
            return _Result([("2026-10-16 06:00:00", 7)])
        if sql.strip().startswith("SELECT count()"):
            return _Result([(2,)])
        if "GROUP BY d" in sql:
            return _Result([("ads.example.com", 7)])
        if "GROUP BY src_addr" in sql:
            return _Result([("198.51.100.20", 12)])
        if "GROUP BY rcode" in sql:
            return _Result([(0, 9), (3, 3)])
        if "uniqExact" in sql:
            # the "top ten + others" total (2026-10-16); a distinct count, not another list
            return _Result([(7,)])
        if "FROM weirvern.dns_reverse_map" in sql:
            return _Result([("ads.example.com", "2026-10-16 06:00:00")])
        return _Result([("2026-10-16 06:00:00", "198.51.100.20", "ads.example.com", 1, 0,
                         "198.51.100.10,NSEC junk here,fd42::1")])


def test_answer_tokens_are_only_addresses():
    """The zeek answers column mixes addresses with NSEC/TXT chatter; only addresses survive."""
    assert soc.answer_ips("198.51.100.10,NSEC 70-35-60-63.1 living room.local ,fd42::1,") == [
        "198.51.100.10", "fd42::1"]


def test_filters_land_as_bound_parameters():
    c = _Client()
    soc.dns_rows(c, hours=6, domain="ads", client_ip="198.51", qtype=1, rcode=3)
    row_sql = next(s for s in c.sql if "ORDER BY ts DESC" in s)
    params = c.params[c.sql.index(row_sql)]
    assert "positionCaseInsensitive(query, %(domain)s) > 0" in row_sql
    assert params["domain"] == "ads" and params["qtype"] == 1 and params["rcode"] == 3
    assert "ts >= %(since)s AND ts <= %(until)s" in row_sql, "the view must be windowed"


def test_a_row_carries_its_labels_and_parsed_answers():
    c = _Client()
    d = soc.dns_rows(c, hours=6)
    row = d["rows"][0]
    assert row["qtype_label"] == "A" and row["rcode_label"] == "NOERROR"
    assert row["answer_ips"] == ["198.51.100.10", "fd42::1"], (
        "the display list must be parsed, not the raw string")


def test_the_facets_carry_the_distinct_total_for_others():
    """"Top ten and an others to click for more" needs a REAL total, or the chip lies."""
    c = _Client()
    d = soc.dns_rows(c, hours=6)
    assert d["facets"]["domains_total"] == 7
    sql = next(s for s in c.sql if "uniqExact" in s)
    assert "GROUP BY" not in sql.split("WHERE")[0], "the total is a distinct count, not a list"


def test_the_reverse_read_path_is_windowed_by_last_seen():
    c = _Client()
    d = soc.dns_reverse_for(c, "198.51.100.10", hours=6)
    sql = c.sql[-1]
    assert "ip = %(ip)s" in sql and "last_seen >= %(since)s" in sql, (
        "an address reassigned by DHCP must not keep naming a domain nobody uses")
    assert "AS last_seen" not in sql, (
        "REGRESSION: the aggregate alias collided with the WHERE column and ClickHouse refused "
        "the whole query (ILLEGAL_AGGREGATION) -- the endpoint 500'd while the SQL read fine")
    assert c.params[-1]["ip"] == "198.51.100.10"
    assert d["domains"][0]["domain"] == "ads.example.com"


def test_the_schema_ships_the_map_the_view_reads():
    """A view over a table nobody created is a 500. The schema file must define both halves."""
    from pathlib import Path

    text = (Path(soc.__file__).parent.parent / "schema" / "016_dns_reverse.sql").read_text()
    assert "CREATE TABLE IF NOT EXISTS weirvern.dns_reverse_map" in text
    assert "CREATE MATERIALIZED VIEW IF NOT EXISTS weirvern.dns_reverse_mv" in text
    assert "isIPv4String" in text, "the MV must filter answer tokens down to addresses"
