"""Blocklists: the import half of domain blocking (hagezi, custom lists, custom names).

The operator's ask named the source outright (github.com/hagezi/dns-blocklists) and sketched the
design. These tests pin the parts that fail silently: the parsers (the real dnsmasq shape is
`address=/domain/` -- the leading slash is syntax), the suffix walk that makes a list entry
cover its subdomains, the failure-is-a-state rule (a fetch error must never read as "zero
domains"), the cache that keeps matching cheap, and the custom-domain validation running
through the SAME rules as a domain rule.
"""

from datetime import UTC, datetime, timedelta

import pytest

from weirvern import blocklists
from weirvern.sluice import SluiceError


class _Result:
    def __init__(self, rows):
        self.result_rows = rows


class _Client:
    def __init__(self, rows=None):
        self.rows = rows or []
        self.sql: list[str] = []
        self.inserts: list[tuple] = []
        self.commands: list[str] = []

    def query(self, sql, parameters=None, **_kw):
        self.sql.append(sql)
        if "FROM weirvern.blocklist_sources" in sql:
            return _Result(self.rows)
        if "FROM weirvern.blocklist_domains" in sql:
            return _Result([("ads.example.com", "hagezi-light")])
        return _Result([])

    def insert(self, table, rows, column_names=None, **_kw):
        self.inserts.append((table, rows, list(column_names or [])))

    def command(self, sql, **_kw):
        self.commands.append(sql)


# ── parsers ───────────────────────────────────────────────────────────────────────────────────
def test_the_dnsmasq_shape_is_what_hagezi_actually_serves():
    """`address=/example.com/` -- and the first cut of this parser took split('/',1)[0] AFTER
    the '=', which is "" for every real line. The leading slash is part of the syntax."""
    parsed = blocklists.parse_list(
        "address=/ads.example.com/\n"
        "local=/track.example.net/\n"
        "*.wild.example.org\n"
        "0.0.0.0 hosts-style.example.io\n"
        "# comment\n"
        "1.2.3.4\n"
        "not_a_domain\n", "dnsmasq")
    assert "ads.example.com" in parsed and "track.example.net" in parsed
    assert "wild.example.org" in parsed, "the wildcard prefix must be normalized away"
    assert all("1.2.3.4" not in d for d in parsed), "an address is not a domain"


def test_hosts_and_plain_formats():
    hosts = blocklists.parse_list("0.0.0.0 a.example.com\n127.0.0.1 b.example.com\n", "hosts")
    assert hosts == {"a.example.com", "b.example.com"}
    plain = blocklists.parse_list("x.example.com\n! comment\njunk\n", "domains")
    assert plain == {"x.example.com"}


def test_matching_walks_parent_suffixes():
    listed = {"ads.example.com": "src"}
    assert blocklists.domain_in_set("ads.example.com", listed) == "ads.example.com"
    assert blocklists.domain_in_set("tracker.ads.example.com", listed) == "ads.example.com"
    assert blocklists.domain_in_set("example.com", listed) is None
    assert blocklists.domain_in_set("notads.example.com", listed) is None


# ── sync ──────────────────────────────────────────────────────────────────────────────────────
SRC = {"source_id": "hagezi-light", "name": "L", "url": "https://example.invalid/x",
       "format": "dnsmasq", "enabled": True, "domain_count": 0}


def test_a_successful_sync_replaces_and_records():
    c = _Client()
    out = blocklists.sync_source(c, SRC, fetch=lambda url: "address=/a.example.com/\naddress=/b.example.com/\n")
    assert out["ok"] and out["domains"] == 2
    assert any("DELETE WHERE source_id" in s for s in c.commands), (
        "a name removed upstream must stop matching: sync REPLACES the source's rows")
    domains = [row[0] for t, rows, cols in c.inserts if t.endswith("blocklist_domains") for row in rows]
    assert sorted(domains) == ["a.example.com", "b.example.com"]
    state = [row for t, rows, cols in c.inserts if t.endswith("blocklist_sources") for row in rows][0]
    cols = [cols for t, rows, cols in c.inserts if t.endswith("blocklist_sources")][0]
    assert state[cols.index("last_error")] == "" and state[cols.index("fetched_at")] is not None


def test_a_failed_fetch_is_a_recorded_state_not_zero_domains():
    c = _Client()
    def boom(url):
        raise OSError("no route to host")
    out = blocklists.sync_source(c, SRC, fetch=boom)
    assert out["ok"] is False and "no route" in out["error"]
    state_row = [row for t, rows, cols in c.inserts if t.endswith("blocklist_sources") for row in rows][0]
    cols = [cols for t, rows, cols in c.inserts if t.endswith("blocklist_sources")][0]
    assert "no route" in state_row[cols.index("last_error")], "the failure must be visible"
    assert state_row[cols.index("fetched_at")] is None, "a failure is not a fetch time"


def test_an_empty_parse_is_a_failure_not_a_silent_zero():
    c = _Client()
    out = blocklists.sync_source(c, SRC, fetch=lambda url: "# nothing but comments\n")
    assert out["ok"] is False and "zero domains" in out["error"]


def test_sync_due_respects_fetched_at():
    # datetime OBJECTS, like the driver returns (load_sources formats objects; a string from a
    # fake would slip through as "" and read as never-fetched -- which is what the first cut of
    # this test proved, the hard way).
    now = datetime.now(UTC)
    c = _Client(rows=[("s1", "a", "", "dnsmasq", True, now, 1, ""),
                      ("s2", "b", "", "dnsmasq", True, now - timedelta(hours=30), 1, ""),
                      ("s3", "c", "", "dnsmasq", True, None, 0, "")])
    due = {s["source_id"] for s in blocklists.sync_due(c)}
    assert due == {"s2", "s3"}, due


# ── custom names + the cache ──────────────────────────────────────────────────────────────────
def test_custom_domains_run_through_the_domain_rule_validation():
    c = _Client()
    assert blocklists.add_custom_domain(c, "Ads.Example.com") == "ads.example.com"
    with pytest.raises(SluiceError):
        blocklists.add_custom_domain(c, "bad_name.example.com")
    with pytest.raises(SluiceError):
        blocklists.add_custom_domain(c, "203.0.113.7")


def test_the_domain_cache_serves_repeat_reads():
    c = _Client()
    blocklists.load_domains(c, force=True)
    before = len(c.sql)
    blocklists.load_domains(c)   # within the TTL: no new query
    assert len(c.sql) == before, "the small cache must actually cache"
