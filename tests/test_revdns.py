"""Reverse DNS must ADD a name, never replace the source IP.

The invariant these tests defend: every surface that displays an address shows the
IP, and shows a hostname only alongside it. The IP is the fact an operator acts on
-- it is what goes into a firewall rule, a DHCP lookup, or a grep of another log --
while a PTR record can be stale or map several addresses to one name.

This was a real defect: a display helper shortened the address to its last octet
(`host-a (42)`) to save column width, which silently discarded the source IP on the
exact screen where an operator decides what to investigate. The CLI-side helper that
had the bug is gone, and the rule now lives at the payload boundary (web_api always
sends BOTH addr and hostname) plus the browser's hostCell, whose rendered output the
DOM harness pins -- so the tests here hold the server half and the harness holds the
rendering half.
"""
from __future__ import annotations

import pytest

from weirvern.admin import revdns


@pytest.fixture(autouse=True)
def _clean_cache():
    revdns.clear_cache()
    yield
    revdns.clear_cache()


# --- the web payloads ---------------------------------------------------------
def test_web_anomalies_keep_addr_and_add_hostname(monkeypatch):
    from weirvern.admin import web_api

    monkeypatch.setattr(web_api, "_hostname", lambda a: "host-a.example")
    rows = [{"src_addr": "203.0.113.42", "anomaly_score": 0.9,
             "feature_contributions": "{}"}]
    out = web_api.anomalies_payload(rows)["rows"]  # an object since 2026-10-16: rows + tiles
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
    # top_talkers now arrives in the standard {available, reason, points} shape (issue #13);
    # the overview payload still renders the rows, and still adds the name beside the address.
    payload = web_api.overview_payload(
        services=[], report=None, anomalies=[],
        talkers={"available": True, "reason": "", "points": [("203.0.113.42", 1000, 5, 3)]},
        caps=None,
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


# ── THE TIMEOUT THAT DID NOT BOUND ANYTHING, AND THE GLOBAL IT MUTATED (audit F088) ──────────────
#
# `revdns` called `socket.setdefaulttimeout(LOOKUP_TIMEOUT_S)` at import, with a comment claiming it
# was "the only portable way to bound" `gethostbyaddr`. Both halves were wrong:
#
#   * IT DID NOT BOUND THE LOOKUP. `setdefaulttimeout` applies to socket objects created by Python's
#     `socket` module; glibc's resolver inside `gethostbyaddr` creates none. MEASURED in an isolated
#     network namespace against a resolver that received queries and never answered:
#         QUERIES REACHED THE BLACKHOLE = 2
#         python sockets created        = 0
#         elapsed                       = 4.01s   with a 1.0s default set at import
#     (4.01s is glibc's own `timeout:2 attempts:2`.) My first measurement returned 0.01s and proved
#     nothing, because this host's nsswitch sends lookups to systemd-resolved over a varlink socket --
#     the query never reached DNS. Only after forcing `hosts: files dns` AND counting the queries the
#     blackhole received did the number mean anything.
#   * IT WAS A PROCESS-WIDE SIDE EFFECT. Importing revdns for a dashboard label silently reconfigured
#     every socket created later in the process -- including the GUI's `ThreadingHTTPServer` and the
#     AF_PACKET sockets the SIPHON intercept forges ARP with. revdns runs INSIDE the GUI process.


def test_importing_revdns_does_not_reconfigure_the_process_sockets():
    """THE GLOBAL HALF. A display concern must not change how the intercept's sockets behave."""
    import socket as _socket

    before = _socket.getdefaulttimeout()
    # The module is already imported, so re-executing it is what would re-set the global.
    import importlib

    importlib.reload(revdns)
    after = _socket.getdefaulttimeout()

    assert after == before, (
        f"importing revdns changed the process-wide socket default from {before!r} to {after!r}. "
        f"Every socket created afterwards inherits it, including the GUI's HTTP server and the SIPHON "
        f"intercept's AF_PACKET sockets (audit F088)"
    )
    # And the CALL must be gone, not merely moved somewhere harmless.
    #
    # Asserted with `ast`, not by searching the text: the module's own comment NAMES
    # setdefaulttimeout while explaining why it is not used, so a substring check flags the
    # explanation. My first version did exactly that and failed on the comment.
    import ast
    import pathlib as _p

    tree = ast.parse(_p.Path(revdns.__file__).read_text())
    calls = [
        ast.unparse(node.func)
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
    ]
    offenders = [c for c in calls if c.endswith("setdefaulttimeout")]
    assert not offenders, (
        f"revdns still CALLS {offenders}; it is process-global state, and it never bounded the "
        f"lookup it was added for (audit F088)"
    )


def test_a_resolver_that_never_answers_is_bounded_by_OUR_clock(monkeypatch):
    """THE BOUND HALF, and the case the old mechanism could never produce.

    A resolver that swallows the query is exactly what LOOKUP_TIMEOUT_S exists for. The old code
    returned None only when the resolver eventually GAVE UP (glibc's ~4s); it had no path that cut a
    quiet resolver off, because the default it set was never consulted.
    """
    import time as _time

    def _never_answers(addr):  # noqa: ANN001
        _time.sleep(3.0)
        raise AssertionError("should have been abandoned before this returned")

    monkeypatch.setattr(revdns.socket, "gethostbyaddr", _never_answers)
    revdns.clear_cache()

    t0 = _time.time()
    got = revdns.lookup("203.0.113.42")
    elapsed = _time.time() - t0

    assert got is None, f"a lookup that never answers returned {got!r} instead of None"
    assert elapsed < 2.5, (
        f"the lookup took {elapsed:.2f}s against a resolver that never answers. LOOKUP_TIMEOUT_S is "
        f"{revdns.LOOKUP_TIMEOUT_S}s, so the bound is not applying -- this is audit F088 exactly, "
        f"where setdefaulttimeout left glibc's own ~4s in charge"
    )


def test_the_bound_is_OURS_not_the_resolver_library(monkeypatch):
    """Pin the SHAPE too: our timeout must be shorter than any plausible resolver timeout, or the
    test above would pass on glibc's behaviour rather than on the fix."""
    assert revdns.LOOKUP_TIMEOUT_S <= 2.0, (
        f"LOOKUP_TIMEOUT_S is {revdns.LOOKUP_TIMEOUT_S}s, which is not meaningfully tighter than a "
        f"resolver's own give-up time -- the bound would be indistinguishable from no bound"
    )


def test_a_WORKING_resolver_still_returns_the_name(monkeypatch):
    """The other direction. A bound that returned None for everything would be a WORSE bug than the
    one being fixed: the UI would silently lose every hostname."""
    _clean = lambda a: ("host-a.example", [], [a])  # noqa: E731
    monkeypatch.setattr(revdns.socket, "gethostbyaddr", _clean)
    revdns.clear_cache()
    monkeypatch.setenv("WEIRVERN_REVERSE_DNS", "private")

    assert revdns.lookup("203.0.113.42") == "host-a.example"
    assert revdns.label("203.0.113.42") == "host-a.example (203.0.113.42)"


def test__resolve_bounded_absorbs_its_own_failures(monkeypatch):
    """`_resolve_bounded`'s OWN contract, tested directly.

    A mutation making it re-raise was MISSED when only `lookup` was tested, because `lookup` has a
    belt-and-braces `except Exception` of its own -- so the raise never reached the caller and the
    behaviour looked fine. That guard is worth keeping, but it hides this helper's contract, and a
    future caller that used the helper directly would get an exception a "never raises" resolver
    should not produce.
    """
    import socket as _socket

    for exc in (_socket.herror("no PTR"), _socket.gaierror("temp fail"), OSError("boom"),
                RuntimeError("something unexpected")):
        monkeypatch.setattr(revdns, "_LOOKUP_POOL", _RaisingPool(exc))
        assert revdns._resolve_bounded("203.0.113.42") is None, (
            f"{type(exc).__name__} escaped _resolve_bounded; a dashboard must render with addresses "
            f"even when lookup is broken"
        )


class _RaisingPool:
    """A pool whose work item raises the given exception, so the helper's guards can be exercised."""

    def __init__(self, exc):
        self._exc = exc

    def submit(self, fn, *a, **k):  # noqa: ANN001
        exc = self._exc

        class _Fut:
            def result(self, timeout=None):  # noqa: ANN001
                raise exc

        return _Fut()

def test_the_lookup_cache_is_BOUNDED():
    """Issue #29: per-entry TTLs alone left the map unbounded -- an entry that has not
    expired YET is never evicted, so a segment with many distinct addresses grows it without
    limit. Driven past the cap, the cache stays at MAX_ENTRIES and the most recent put
    survives with its value readable."""
    c = revdns._Cache()
    cap = revdns._Cache.MAX_ENTRIES
    assert cap > 0
    for i in range(cap + 500):
        # keys are opaque strings to the cache; the bound is the subject here
        c.put("addr-" + str(i), "host.example" if i % 2 else None)
    assert c.size() <= cap, "the cache grew past its stated bound: " + str(c.size())
    c.put("addr-fresh", "fresh.example")
    hit, val = c.get("addr-fresh")
    assert hit and val == "fresh.example", (hit, val)
