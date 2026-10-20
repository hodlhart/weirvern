"""Discover reads three feeds (the operator, 2026-10-16): "flow type in discover should be DNS,
Zeek, or Netflow with the charts updating to reflect. This is our view to see the data feeds
being collected". These pin the routing, the wrappers' honesty, and the selector itself."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / "weirvern" / "admin" / "web"


def test_the_discover_route_refuses_an_unknown_feed_with_a_sentence():
    body = (ROOT / "weirvern" / "admin" / "web.py").read_text()
    assert "is not a feed this view reads" in body, "an unknown feed must be refused, not defaulted"


def test_the_route_branches_to_the_right_reader_per_feed():
    body = (ROOT / "weirvern" / "admin" / "web.py").read_text()
    assert "soc_mod.discover_dns(" in body and "soc_mod.discover_zeek(" in body
    assert 'feed == "dns"' in body and 'feed == "zeek"' in body


def test_discover_dns_wraps_the_dns_views_own_reader(monkeypatch):
    from weirvern.admin import soc

    captured = {}

    def fake_dns_rows(client, *, hours=24, client_ip="", limit=100, offset=0):
        captured.update({"hours": hours, "client_ip": client_ip, "limit": limit, "offset": offset})
        return {"available": True, "rows": [{"query": "example.org"}], "total": 1,
                "histogram": [{"t": "2026-10-16T07:00:00", "n": 3}], "bucket_s": 1440,
                "facets": {"clients": [{"value": "198.51.100.5", "count": 9}]}}

    monkeypatch.setattr(soc, "dns_rows", fake_dns_rows)
    out = soc.discover_dns(object(), hours=6, limit=50, offset=10, client_ip="198.51.100.5")
    assert captured == {"hours": 6, "client_ip": "198.51.100.5", "limit": 50, "offset": 10}
    assert out["feed"] == "dns" and out["total"] == 1
    assert out["rows"][0]["query"] == "example.org" and out["histogram"][0]["n"] == 3
    assert out["facets"]["clients"][0]["value"] == "198.51.100.5"


def test_discover_zeek_counts_every_log_and_sums_the_window(monkeypatch):
    from weirvern.admin import soc

    def fake_counts(client, hours=24):
        # The real payload files the per-log rows under "points" (verified live 2026-10-16).
        return {"available": True, "points": [
            {"log": "conn", "rows": 12, "total": 900, "last_ts": "2026-10-16T08:00:00"},
            {"log": "dns", "rows": 0, "total": 40, "last_ts": "2026-10-15T02:00:00"},
        ], "unreadable": ["capture_loss"]}

    monkeypatch.setattr(soc, "zeek_counts", fake_counts)
    out = soc.discover_zeek(object(), hours=24)
    assert out["feed"] == "zeek" and out["total"] == 12
    assert out["unreadable"] == ["capture_loss"]
    assert {row["log"] for row in out["logs"]} == {"conn", "dns"}


def test_the_flow_type_selector_offers_the_three_feeds():
    html = (WEB / "index.html").read_text()
    assert 'id="dc-feed"' in html
    for value in ("netflow", "dns", "zeek"):
        assert f'<option value="{value}">' in html, f"the selector must offer {value}"
    assert "flow type" in html


def test_discover_params_carry_the_chosen_feed():
    js = (WEB / "discover.js").read_text()
    assert '\"feed=\" + encodeURIComponent(feed)' in js
    assert "dcFeedColumns" in js and '"dns"' in js and '"zeek"' in js


def test_dns_and_zeek_accept_the_weirling_filter_and_name_the_remote_case(monkeypatch):
    from weirvern.admin import soc

    calls = {"dns": 0}

    def fake_dns_rows(client, *, hours=24, client_ip="", limit=100, offset=0):
        calls["dns"] += 1
        return {"available": True, "rows": [], "total": 0, "histogram": [], "bucket_s": 1440,
                "facets": {"clients": []}}

    monkeypatch.setattr(soc, "dns_rows", fake_dns_rows)
    monkeypatch.setattr(soc, "weirling_labels",
                        lambda client: {"127.0.0.1": "weirvern", "192.0.2.5": "edge"})
    local = soc.discover_dns(object(), sensor="127.0.0.1")
    assert local["available"] and calls["dns"] == 1
    assert local["facets"]["weirlings"][0]["label"] == "weirvern"

    remote = soc.discover_dns(object(), sensor="192.0.2.5")
    assert remote["available"] is True and remote["total"] == 0
    assert "captured by the hub's Zeek" in remote["reason"]
    assert calls["dns"] == 1, "the remote case must not read the hub's DNS rows as if filtered"


def test_the_weirling_selector_is_not_hidden_for_dns_or_zeek():
    js = (WEB / "discover.js").read_text()
    assert 'show("dc-lab-sensor", true)' in js, (
        "DNS and Zeek must expose the same weirling selector as NetFlow")
