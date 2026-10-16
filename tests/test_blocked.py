"""The Blocked ledger: recorded hits and the live rules split by what they do NOW.

The operator's ask, verbatim: "We need a blocked tab too." The pieces that fail silently and
are pinned here: the window and filters land as BOUND parameters (a dropped filter shows more
than was asked for), block-mode and alert-mode rules are SEPARATED (a hit is not a block and
the ledger must not imply one), and a domain rule carries the addresses it currently resolves
to -- the count is what makes "this rule blocks something" checkable rather than asserted.
"""

from datetime import UTC, datetime, timedelta

from weirvern.admin import soc
from weirvern.sluice import Rule


class _Result:
    def __init__(self, rows):
        self.result_rows = rows


class _Client:
    def __init__(self):
        self.sql: list[str] = []
        self.params: list[dict] = []

    def query(self, sql, parameters=None, **_kw):
        self.sql.append(sql)
        self.params.append(dict(parameters or {}))
        if "count()" in sql and "sluice_events" in sql:
            return _Result([(3,)])
        if "FROM weirvern.sluice_events" in sql:
            return _Result([(datetime(2026, 10, 16, 6, 2), "r1", "ads.example.com",
                             "ads.example.com", "198.51.100.20")])
        if "dns_reverse_map" in sql:
            return _Result([("203.0.113.7", datetime(2026, 10, 16, 6, 0)),
                            ("203.0.113.8", datetime(2026, 10, 16, 5, 0))])
        return _Result([])


class _StoreStub:
    def __init__(self, rules):
        self.rules = rules

    def load_all_rules(self, client, limit=500):
        return self.rules

    def resolve_domain_ips(self, client, domain, **kw):
        return ["203.0.113.7", "203.0.113.8"]


def test_the_window_and_filter_are_bound_parameters(monkeypatch):
    from weirvern import sluice_store

    monkeypatch.setattr(sluice_store, "load_all_rules", lambda client, limit=500: [])
    c = _Client()
    d = soc.blocked_view(c, hours=6, domain="ads")
    row_sql = next(s for s in c.sql if "ORDER BY ts DESC" in s)
    params = c.params[c.sql.index(row_sql)]
    assert "ts >= %(since)s AND ts <= %(until)s" in row_sql
    assert "positionCaseInsensitive(domain, %(domain)s) > 0" in row_sql
    assert params["domain"] == "ads" and d["total"] == 3


def test_blocks_and_alerts_are_separated_and_resolved(monkeypatch):
    from weirvern import sluice_store

    soon = datetime.now(UTC) + timedelta(minutes=30)
    rules = [
        Rule("r1", domain="ads.example.com", mode="block", expires_at=soon),
        Rule("r2", domain="track.example.net", mode="alert", expires_at=soon),
    ]
    monkeypatch.setattr(sluice_store, "load_all_rules", lambda client, limit=500: rules)
    monkeypatch.setattr(sluice_store, "resolve_domain_ips",
                        lambda client, domain, **kw: ["203.0.113.7", "203.0.113.8"])
    d = soc.blocked_view(_Client(), hours=6)
    assert [r["rule_id"] for r in d["blocks"]] == ["r1"]
    assert [r["rule_id"] for r in d["alerts"]] == ["r2"]
    assert d["blocks"][0]["resolved_count"] == 2, (
        "the addresses a name resolves to NOW are what the kernel enforces")
    assert d["blocks"][0]["resolved"][0] == "203.0.113.7"


def test_a_lapsed_rule_is_not_in_either_list(monkeypatch):
    from weirvern import sluice_store

    gone = datetime.now(UTC) - timedelta(minutes=1)
    monkeypatch.setattr(
        sluice_store, "load_all_rules",
        lambda client, limit=500: [Rule("r1", domain="ads.example.com", mode="block",
                                        expires_at=gone)])
    d = soc.blocked_view(_Client(), hours=6)
    assert d["blocks"] == [] and d["alerts"] == []


def test_the_dashboard_filter_binds_into_the_hits_query():
    """The operator, 2026-10-16: a click on a hit's client cell narrows the tab. The filter must
    land as a BOUND parameter in BOTH the hits and the count queries -- a count that ignored the
    filter would read as if nothing had been filtered at all."""
    from weirvern.admin.soc import blocked_view

    seen = []

    class _C:
        def query(self, sql, parameters=None, **_kw):
            seen.append((sql, dict(parameters or {})))
            class R:
                result_rows = [] if "SELECT ts," in sql else [(0,)]
            return R()

    blocked_view(_C(), hours=6, client_ip="198.51.100.7")
    hits_sql, hits_params = seen[0]
    assert "src_addr = %(client)s" in hits_sql, "the client filter must reach the hits query"
    assert hits_params["client"] == "198.51.100.7"
    count_sql, count_params = seen[1]
    assert "src_addr = %(client)s" in count_sql, "and the count, or the total lies"
    assert count_params["client"] == "198.51.100.7"
    assert "198.51.100.7" not in hits_sql, "bound, never interpolated"
