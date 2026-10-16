"""Domain rules: a name resolved through the reverse map, alert-first, and the refusals.

The operator's ask: "can we implement geo filters and what about blocks by domain? ... can we
reverse lookup ips with a small cache to also block traffic. That way we can even block DOH."
The kernel matches addresses, not names, so a domain rule is enforced through what the name
currently resolves to (schema/016) -- and these tests pin the properties that keep that honest:
an alert rule never reaches the kernel, a rule that resolved to NOTHING is refused rather than
installed as an empty shell (ARMED while blocking nothing is this project's named failure), and
the name's validation lives in one place.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from weirvern import sluice_store
from weirvern.sluice import NFT_SET_DOMAINS_V4, NftBackend, Rule, SluiceError

SOON = datetime.now(UTC) + timedelta(minutes=30)


class _Result:
    def __init__(self, rows):
        self.result_rows = rows


class _Client:
    def __init__(self):
        self.sql: list[str] = []
        self.params: list[dict] = []
        self.inserts: list[tuple] = []

    def query(self, sql, parameters=None, **_kw):
        self.sql.append(sql)
        self.params.append(dict(parameters or {}))
        if "dns_reverse_map" in sql:
            return _Result([("203.0.113.7", "2026-10-16 06:00:00"),
                            ("203.0.113.8", "2026-10-16 05:00:00")])
        return _Result([])

    def insert(self, table, rows, column_names=None, **_kw):
        self.inserts.append((table, rows, list(column_names or [])))


def _backend():
    return NftBackend()


# ── the rule's own semantics ──────────────────────────────────────────────────────────────────
def test_a_domain_rule_matches_its_resolved_addresses():
    r = Rule("r1", domain="ads.example.com", resolved_ips=["203.0.113.7"])
    assert r.matches("", "203.0.113.7", "tcp", 443) is True
    assert r.matches("", "203.0.113.9", "tcp", 443) is False


def test_alert_rules_do_not_enforce_and_say_so():
    r = Rule("r1", domain="ads.example.com", mode="alert", resolved_ips=["203.0.113.7"])
    assert r.enforcing is False
    assert "(alert)" in r.describes()


# ── the compiler ──────────────────────────────────────────────────────────────────────────────
def test_the_compiled_ruleset_installs_the_resolved_addresses():
    """The named historical bug is emitting the set declaration and not the elements; a domain
    rule must show BOTH the member and the drop that references the set."""
    r = Rule("r1", domain="ads.example.com", resolved_ips=["203.0.113.7"], expires_at=SOON)
    text = _backend()._base_ruleset([r], "eth0")
    assert NFT_SET_DOMAINS_V4 in text
    assert "203.0.113.7" in text
    assert f"ip daddr @{NFT_SET_DOMAINS_V4} counter drop" in text


def test_a_domain_rule_scoped_to_a_port_is_refused_not_ignored():
    """The kernel set matches addresses; a port on a domain rule would be silently dropped, so
    the compiler refuses rather than installing something narrower than it reads."""
    r = Rule("r1", domain="ads.example.com", resolved_ips=["203.0.113.7"], dst_port=443,
             protocol="tcp", expires_at=SOON)
    with pytest.raises(SluiceError, match="port-scoped"):
        _backend()._base_ruleset([r], "eth0")


def test_a_block_rule_that_resolved_to_nothing_cannot_be_armed():
    """Empty set + drop line = ARMED over work that does not happen. Refused at compile; the
    resolution step keeps these out of the list in the first place."""
    r = Rule("r1", domain="ads.example.com", resolved_ips=[], expires_at=SOON)
    with pytest.raises(SluiceError, match="no addresses"):
        _backend()._base_ruleset([r], "eth0")


def test_a_domain_rule_carrying_addresses_is_refused():
    r = Rule("r1", domain="ads.example.com", src_cidr="203.0.113.0/24", resolved_ips=["203.0.113.7"],
             expires_at=SOON)
    with pytest.raises(SluiceError, match="names a name"):
        _backend()._base_ruleset([r], "eth0")


# ── the store: validation, insertion, resolution ─────────────────────────────────────────────
def test_the_name_validation_is_one_place():
    assert sluice_store.validate_domain("Ads.Example.com.") == "ads.example.com"
    with pytest.raises(SluiceError, match="IP address"):
        sluice_store.validate_domain("203.0.113.7")
    with pytest.raises(SluiceError, match="no dot"):
        sluice_store.validate_domain("bad")
    with pytest.raises(SluiceError, match="cannot have"):
        sluice_store.validate_domain("bad_example.com")


def test_a_domain_rule_cannot_also_carry_addresses():
    with pytest.raises(SluiceError, match="names a domain, not addresses"):
        sluice_store.create_rule(_Client(), domain="ads.example.com", src_cidr="203.0.113.0/24")


def test_create_rule_records_domain_and_mode():
    c = _Client()
    rule = sluice_store.create_rule(c, domain="Ads.Example.com", mode="alert", ttl_minutes=30)
    table, rows, columns = c.inserts[0]
    assert table == "weirvern.sluice_rules"
    assert "domain" in columns and "mode" in columns
    assert rows[0][columns.index("domain")] == "ads.example.com"
    assert rows[0][columns.index("mode")] == "alert"
    assert rule.mode == "alert" and rule.domain == "ads.example.com"


def test_resolution_reads_the_reverse_map_with_suffix_and_window():
    c = _Client()
    ips = sluice_store.resolve_domain_ips(c, "example.com", window_h=6)
    assert ips == ["203.0.113.7", "203.0.113.8"]
    sql, params = c.sql[-1], c.params[-1]
    assert "endsWith(domain, %(suf)s)" in sql and "last_seen >= %(since)s" in sql
    assert params["d"] == "example.com" and params["suf"] == ".example.com"


def test_hits_are_recorded_with_kind_domain_and_query():
    c = _Client()
    n = sluice_store.write_events(c, [{
        "rule_id": "r1", "kind": "dns", "domain": "ads.example.com",
        "query": "ads.example.com", "src_addr": "203.0.113.20", "ts": datetime.now(UTC),
    }])
    assert n == 1
    table, rows, columns = c.inserts[0]
    assert table == "weirvern.sluice_events"
    for col in ("kind", "domain", "query"):
        assert col in columns
    assert rows[0][columns.index("kind")] == "dns"
    assert rows[0][columns.index("query")] == "ads.example.com"
