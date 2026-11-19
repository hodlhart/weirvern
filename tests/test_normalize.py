"""The Normalize tab: what a normalization is, and what it must never become.

The last test in this file is the important one. The operator's rule is that normalizing traffic
changes the baseline, not the alert path ("it would not alert on that activity and should not as
it's added to the host baseline so we don't have to silence alerts", 2026-11-19). A suppression list
is the obvious wrong way to implement this feature, so the code is read for the vocabulary of
suppression and the test fails if it appears.
"""
from __future__ import annotations

import math
import pathlib
import re

import pytest

from weirvern import normalize

ROOT = pathlib.Path(__file__).resolve().parents[1]
WEB = ROOT / "weirvern" / "admin" / "web"


def test_an_entry_needs_a_host_and_a_source():
    with pytest.raises(ValueError):
        normalize.new_entry(source="flow", src_addr="", dst_prefix="192.0.2.0/24")
    with pytest.raises(ValueError):
        normalize.new_entry(source="bogus", src_addr="192.0.2.10")
    with pytest.raises(ValueError):
        normalize.new_entry(source="dns", src_addr="192.0.2.10", dns_name="")


def test_a_dns_entry_carries_the_domain_and_not_a_port():
    e = normalize.new_entry(source="dns", src_addr="192.0.2.10", dns_name="updates.example.test",
                            dns_qtype=1, flows=40, samples=6, avg_bytes=31.0, var_bytes=4.0)
    assert e["status"] == "active"
    assert e["dns_name"] == "updates.example.test"
    assert e["dst_port"] == 0 and e["dst_prefix"] == ""


def test_removal_supersedes_the_entry_instead_of_deleting_it():
    e = normalize.new_entry(source="flow", src_addr="192.0.2.10",
                            dst_prefix="198.51.100.0/24", dst_port=443, proto=6)
    gone = normalize.removal(e, actor="sam")
    assert gone["entry_id"] == e["entry_id"]          # the same entry, superseded
    assert gone["status"] == "removed"
    assert gone["removed_by"] == "sam"
    assert gone["removed_at"] is not None


def test_pooling_adds_the_seed_and_keeps_both_samples():
    """Hand-computed: n1=3, m1=10, v1=4; n2=2, m2=20, v2=9."""
    out = normalize.pool({"samples": 3, "avg": 10.0, "var": 4.0},
                         {"samples": 2, "avg": 20.0, "var": 9.0})
    n1, n2, m1, m2, v1, v2 = 3.0, 2.0, 10.0, 20.0, 4.0, 9.0
    n = n1 + n2
    mean = (n1 * m1 + n2 * m2) / n
    var = ((n1 - 1) * v1 + (n2 - 1) * v2 + (n1 * n2 / n) * (m1 - m2) ** 2) / (n - 1)
    assert out["samples"] == pytest.approx(n)
    assert out["avg"] == pytest.approx(mean)
    assert out["var"] == pytest.approx(var)
    # The band widened: the pooled sigma is larger than either input's.
    assert normalize.sigma(out["avg"], out["var"]) > math.sqrt(v1)


def test_a_seed_with_no_samples_changes_nothing():
    host = {"samples": 5, "avg": 7.0, "var": 2.0}
    assert normalize.pool(host, {"samples": 0, "avg": 900.0, "var": 1.0}) == host


def test_a_percentile_only_moves_upward_and_only_with_enough_samples():
    assert normalize.widen(100.0, 500.0, samples=5) == 100.0      # too thin to trust
    assert normalize.widen(100.0, 500.0, samples=20) == 500.0
    assert normalize.widen(500.0, 100.0, samples=200) == 500.0    # never narrows a band


def test_the_tab_markup_exists_and_is_wired():
    html = (WEB / "index.html").read_text()
    js = (WEB / "normalize.js").read_text()
    assert 'data-view="normalize"' in html
    assert 'id="view-normalize"' in html
    assert '<script src="/normalize.js"></script>' in html
    for control in ("nz-hours", "nz-source", "nz-segment", "nz-port", "nz-minbytes", "nz-find",
                    "nz-feed", "nz-entries", "nz-apply"):
        assert f'id="{control}"' in html, f"the feed lost its {control} control"
    assert "loadNormalize" in js and "postJSON(\"/api/normalize\"" in js


def test_the_feed_reads_both_lanes_and_filters_server_side():
    from weirvern import normalize_store

    class FakeResult:
        column_names: list[str] = []
        result_rows: list[tuple] = []

    class FakeClient:
        def __init__(self):
            self.sql: list[str] = []

        def query(self, sql, **_kw):
            self.sql.append(sql)
            return FakeResult()

    c = FakeClient()
    normalize_store.feed(c, hours=24, source="", segment="192.0.2", port=443, min_bytes=1000,
                         query="example")
    feed_sql = c.sql[0]
    assert "UNION ALL" in feed_sql
    assert "'dns'" in feed_sql and "'flow'" in feed_sql
    assert "INTERVAL 24 HOUR" in feed_sql
    assert "dst_prefix LIKE '%192.0.2%'" in feed_sql
    assert "dst_port = 443" in feed_sql and "bytes_total >= 1000" in feed_sql
    assert "positionCaseInsensitive(dns_name, 'example')" in feed_sql


def test_the_feed_refuses_to_narrow_by_accident():
    """source=flow means FLOWS ONLY — a filter that silently widens would mislead the reader."""
    from weirvern import normalize_store

    class FakeResult:
        column_names: list[str] = []
        result_rows: list[tuple] = []

    class FakeClient:
        def __init__(self):
            self.sql: list[str] = []

        def query(self, sql, **_kw):
            self.sql.append(sql)
            return FakeResult()

    c = FakeClient()
    normalize_store.feed(c, hours=1, source="flow")
    assert "'dns'" not in c.sql[0]


def test_nothing_in_the_feature_suppresses_or_mutes_an_alert():
    """A suppression list is the obvious wrong implementation; this fails if one appears.

    Only the NORMALIZE markup is read, not the whole console: "blocklist" is a real DNS concept
    elsewhere in index.html, and the alert audit's own copy says "suppressed" about rate limits.
    """
    banned = re.compile(r"\b(suppress\w*|silenc(?!ed)\w*|mute|mutes|muting|allowlist\w*|whitelist\w*)\b",
                        re.IGNORECASE)
    html = (WEB / "index.html").read_text()
    view = html[html.index('<section id="view-normalize"'):
                html.index('<div class="info-text hidden" id="nz-info">')]
    blocks = {"normalize.js": (WEB / "normalize.js").read_text(), "index.html": view}
    for name, text in blocks.items():
        code = "\n".join(line for line in text.splitlines()
                         if not line.strip().startswith(("//", "*", "/*", "<!--")))
        assert not banned.search(code), f"{name} grew suppression vocabulary"


def test_a_scope_widens_or_narrows_the_destination():
    """The sheet's whole job: the same row claimed at three widths."""
    from weirvern.normalize import scope_prefix

    assert scope_prefix("198.51.100.17", "host") == "198.51.100.17/32"
    assert scope_prefix("198.51.100.17", "subnet") == "198.51.100.0/24"
    assert scope_prefix("198.51.100.17", "supernet") == "198.51.0.0/16"
    assert scope_prefix("198.51.100.17", "any") == ""
    assert scope_prefix("2001:db8::1", "subnet") == "2001:db8::/64"
    with pytest.raises(ValueError):
        scope_prefix("198.51.100.17", "galaxy")
    with pytest.raises(ValueError):
        scope_prefix("", "host")


def test_the_sheet_is_a_sheet_and_a_row_opens_it():
    html = (WEB / "index.html").read_text()
    js = (WEB / "normalize.js").read_text()
    assert 'id="nz-detail-card"' in html
    assert 'class="card sheet hidden"' in html
    assert "sheets.js" in html
    for control in ("nz-detail-body", "nz-detail-apply", "nz-detail-remove", "nz-detail-cancel",
                    "nz-detail-close"):
        assert f'id="{control}"' in html, f"the sheet lost {control}"
    # the row is the door, and the checkbox is not
    assert "openNormalizeSheet(r, tr)" in js
    assert 'if (ev.target.closest("input")) return;' in js
    assert 'openSheet(card, { scrimId: "nz-detail-scrim"' in js
    # broaden or reduce, both offered
    assert '"subnet"' in js and '"host"' in js and '"supernet"' in js and '"any"' in js
    assert "parentDomain" in js


def test_the_scope_reaches_the_written_prefix_not_just_the_wire():
    """A scope on the wire is only real if the row that lands has the derived prefix."""
    from weirvern import normalize

    e = normalize.new_entry(source="flow", src_addr="192.0.2.163",
                            dst_prefix=normalize.scope_prefix("198.51.100.17", "supernet"),
                            dst_port=2049, proto=6, flows=10, samples=10)
    assert e["dst_prefix"] == "198.51.0.0/16"


def test_the_feed_pages_backwards_in_time_and_says_so():
    """A long list needs the house pager pointed at time (operator, 2026-11-19)."""
    from weirvern import normalize_store

    class FakeResult:
        column_names: list[str] = []
        result_rows: list[tuple] = []

    class FakeClient:
        def __init__(self):
            self.sql: list[str] = []

        def query(self, sql, **_kw):
            self.sql.append(sql)
            return FakeResult()

    c = FakeClient()
    payload = normalize_store.feed(c, hours=24, offset=3)
    sql = c.sql[0]
    assert "INTERVAL 96 HOUR" in sql and "INTERVAL 72 HOUR" in sql, sql[:400]
    assert payload["window"]["offset"] == 3
    assert payload["window"]["hours"] == 24
    assert payload["window"]["older"] is False      # the probe returned nothing

    html = (WEB / "index.html").read_text()
    js = (WEB / "normalize.js").read_text()
    assert 'id="nz-pager" class="pager"' in html
    assert 'class: "pager-btn"' in js and 'class: "pager-info"' in js
    assert "\u2039" in js and "\u203a" in js
    assert "older traffic" in js and "newer traffic" in js
