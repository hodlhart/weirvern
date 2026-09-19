"""Reverse DNS must ADD a name, never replace the source IP.

The invariant these tests defend: every surface that displays an address shows the
IP, and shows a hostname only alongside it. The IP is the fact an operator acts on
-- it is what goes into a firewall rule, a DHCP lookup, or a grep of another log --
while a PTR record can be stale or map several addresses to one name.

This was a real defect: the TUI's helper shortened the address to its last octet
(`host-a (42)`) to save column width, which silently discarded the source IP on the
exact screen where an operator decides what to investigate.
"""
from __future__ import annotations

import pytest

from weirvern.admin import revdns
from weirvern.admin.tui import _host_label


@pytest.fixture(autouse=True)
def _clean_cache():
    revdns.clear_cache()
    yield
    revdns.clear_cache()


# --- the invariant ------------------------------------------------------------
def test_tui_label_keeps_the_full_address(monkeypatch):
    """A resolved name must appear WITH the complete address, not instead of it."""
    monkeypatch.setattr(revdns, "lookup", lambda addr, use_cache=True: "host-a.example")
    label = _host_label("203.0.113.42")
    assert "203.0.113.42" in label, (
        f"the source IP was dropped from {label!r}; an operator cannot act on a "
        f"hostname alone"
    )
    assert "host-a.example" in label


def test_tui_label_does_not_truncate_to_the_last_octet(monkeypatch):
    """The specific regression: `host-a (42)` is not an address."""
    monkeypatch.setattr(revdns, "lookup", lambda addr, use_cache=True: "host-a.example")
    label = _host_label("203.0.113.42")
    assert "(42)" not in label, f"address truncated: {label!r}"
    assert label.endswith("(203.0.113.42)")


def test_tui_label_falls_back_to_the_bare_address(monkeypatch):
    """No PTR record, or the resolver declined: show the address, unchanged."""
    monkeypatch.setattr(revdns, "lookup", lambda addr, use_cache=True: None)
    assert _host_label("192.0.2.11") == "192.0.2.11"


def test_tui_label_handles_a_name_equal_to_the_address(monkeypatch):
    """Some resolvers return the address itself. That must not become
    `1.2.3.4 (1.2.3.4)`."""
    monkeypatch.setattr(revdns, "lookup", lambda addr, use_cache=True: "1.2.3.4")
    assert _host_label("1.2.3.4") == "1.2.3.4"


def test_tui_label_survives_an_empty_address():
    assert _host_label("") == ""


def test_tui_label_survives_a_resolver_exception(monkeypatch):
    """A misbehaving resolver must not break the table."""
    def boom(addr, use_cache=True):
        raise OSError("resolver exploded")

    monkeypatch.setattr(revdns, "lookup", boom)
    assert _host_label("203.0.113.42") == "203.0.113.42"


# --- the web payloads ---------------------------------------------------------
def test_web_anomalies_keep_addr_and_add_hostname(monkeypatch):
    from weirvern.admin import web_api

    monkeypatch.setattr(web_api, "_hostname", lambda a: "host-a.example")
    rows = [{"src_addr": "203.0.113.42", "anomaly_score": 0.9,
             "feature_contributions": "{}"}]
    out = web_api.anomalies_payload(rows)
    assert out[0]["src_addr"] == "203.0.113.42", "src_addr must always be present"
    assert out[0]["hostname"] == "host-a.example"


def test_web_host_payload_keeps_addr_and_adds_hostname(monkeypatch):
    from weirvern.admin import web_api

    monkeypatch.setattr(web_api, "_hostname", lambda a: "host-a.example" if a else None)
    payload = web_api.host_payload({
        "src_addr": "203.0.113.42", "hours": 1, "totals": None,
        "top_destinations": [("203.0.113.200", 100, 2, 1)],
        "top_ports": [], "timeline": [], "anomalies": [], "zeek_services": [],
    })
    assert payload["src_addr"] == "203.0.113.42"
    assert payload["hostname"] == "host-a.example"
    assert payload["top_destinations"][0]["dst_addr"] == "203.0.113.200"
    assert "hostname" in payload["top_destinations"][0]


def test_web_overview_keeps_addr_and_adds_hostname(monkeypatch):
    from weirvern.admin import web_api

    monkeypatch.setattr(web_api, "_hostname", lambda a: "host-a.example")
    payload = web_api.overview_payload(
        services=[], report=None, anomalies=[],
        talkers=[("203.0.113.42", 1000, 5, 3)], caps=None,
    )
    assert payload["top_talkers"][0]["src_addr"] == "203.0.113.42"
    assert payload["top_talkers"][0]["hostname"] == "host-a.example"


# --- resolution policy --------------------------------------------------------
def test_private_addresses_are_resolved_by_default(monkeypatch):
    """The default mode must name the operator's own hosts -- that is the whole
    point -- while staying on the LAN."""
    monkeypatch.delenv("WEIRVERN_REVERSE_DNS", raising=False)
    assert revdns.current_mode() == "private"
    for addr in ("203.0.113.42", "198.51.100.5", "192.0.2.5", "100.64.0.11"):
        assert revdns.is_private(addr), f"{addr} should be treated as local"


def test_public_addresses_are_not_resolved_by_default(monkeypatch):
    """A privacy decision, not an optimisation: resolving a public address sends
    it to a resolver, which for many homelabs is an upstream provider. Doing that
    for every destination IP in flow data hands over derived traffic intelligence.
    """
    monkeypatch.delenv("WEIRVERN_REVERSE_DNS", raising=False)
    for addr in ("8.8.8.8", "1.2.3.4", "1.1.1.1"):
        assert not revdns.is_private(addr)
    assert revdns.lookup("8.8.8.8") is None, (
        "a public address must not be looked up in the default mode"
    )


def test_public_addresses_are_resolved_when_explicitly_enabled(monkeypatch):
    monkeypatch.setenv("WEIRVERN_REVERSE_DNS", "all")
    assert revdns.current_mode() == "all"
    # The lookup itself may fail in a sandbox; what matters is that it is ATTEMPTED
    # rather than declined, so patch the system call and assert it was reached.
    called = {}

    def fake_gethostbyaddr(addr):
        called["addr"] = addr
        return ("dns.google", [], [addr])

    monkeypatch.setattr(revdns.socket, "gethostbyaddr", fake_gethostbyaddr)
    assert revdns.lookup("8.8.8.8") == "dns.google"
    assert called["addr"] == "8.8.8.8"


def test_mode_off_disables_all_lookups(monkeypatch):
    monkeypatch.setenv("WEIRVERN_REVERSE_DNS", "off")
    assert revdns.current_mode() == "off"
    assert revdns.lookup("203.0.113.42") is None


@pytest.mark.parametrize("value,expected", [
    ("all", "all"), ("private", "private"), ("off", "off"),
    ("0", "off"), ("false", "off"), ("1", "all"), ("true", "all"), ("yes", "all"),
    ("nonsense", "private"),
])
def test_mode_parsing(monkeypatch, value, expected):
    monkeypatch.setenv("WEIRVERN_REVERSE_DNS", value)
    assert revdns.current_mode() == expected


# --- caching ------------------------------------------------------------------
def test_negative_results_are_cached(monkeypatch):
    """The negative case dominates real flow data: most destination addresses have
    no PTR record. Without negative caching the dashboard would pay the timeout for
    the same unresolvable address on every refresh."""
    calls = {"n": 0}

    def no_ptr(addr):
        calls["n"] += 1
        raise revdns.socket.herror("unknown host")

    monkeypatch.setattr(revdns.socket, "gethostbyaddr", no_ptr)
    monkeypatch.delenv("WEIRVERN_REVERSE_DNS", raising=False)

    assert revdns.lookup("203.0.113.99") is None
    assert revdns.lookup("203.0.113.99") is None
    assert calls["n"] == 1, "the failed lookup was repeated; negative results are not cached"


def test_positive_results_are_cached(monkeypatch):
    calls = {"n": 0}

    def one_ptr(addr):
        calls["n"] += 1
        return ("host-a.example", [], [addr])

    monkeypatch.setattr(revdns.socket, "gethostbyaddr", one_ptr)
    monkeypatch.delenv("WEIRVERN_REVERSE_DNS", raising=False)

    assert revdns.lookup("203.0.113.42") == "host-a.example"
    assert revdns.lookup("203.0.113.42") == "host-a.example"
    assert calls["n"] == 1


def test_trailing_dot_is_stripped(monkeypatch):
    """gethostbyaddr often returns a fully-qualified name with a trailing dot."""
    monkeypatch.setattr(revdns.socket, "gethostbyaddr",
                        lambda a: ("host-a.example.", [], [a]))
    monkeypatch.delenv("WEIRVERN_REVERSE_DNS", raising=False)
    assert revdns.lookup("203.0.113.42") == "host-a.example"


def test_lookup_never_raises_on_a_garbage_address():
    """A malformed address in flow data must not break a page render."""
    assert revdns.lookup("not-an-address") is None
    assert revdns.lookup("") is None
