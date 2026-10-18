"""US-6 pins: arrive and return -- the return trip keeps filters, range, and scroll.

The failure these guard: navigation that silently resets context (the old host drill opened at
a hardcoded 24h, no way back), and shared links whose filters look like the screen's own
choices with no explanation for a short list.
"""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from weirvern.admin import status, web_api

ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / "weirvern" / "admin" / "web"


def test_the_host_drill_uses_the_global_window():
    src = (WEB / "app.js").read_text()
    seg = src.split("function openHost(addr) {", 1)[1].split("\n}", 1)[0]
    assert "trHours()" in seg, "openHost must ask the global range, not a hardcoded window"
    assert "loadHost(addr, 24)" not in src, \
        "the 24h hardcode is back (the audit: 'window = global range')"


def test_the_return_trip_restores_scroll_and_filters():
    src = (WEB / "app.js").read_text()
    assert "function returnWithScroll(" in src, "the return-trip helper vanished"
    seg = src.split("function returnWithScroll(", 1)[1].split("\n}", 1)[0]
    assert "window.scrollTo(0, PENDING_SCROLL)" in seg, "the return trip no longer scrolls back"
    assert "setTimeout(apply, 350)" in seg and "setTimeout(apply, 900)" in seg, \
        "the scroll must be applied AFTER the origin view re-renders (not against the outgoing page)"
    # both labeled exits route through it
    assert "returnWithScroll(fromView, EVIDENCE_SCROLL)" in src
    assert "returnWithScroll(HOST_RETURN.view, HOST_RETURN.scroll)" in src


def test_a_fresh_lookup_is_not_a_journey():
    """h-go (typed lookup) must NOT leave a crumb: you came from nowhere."""
    src = (WEB / "app.js").read_text()
    seg = src.split("function openHost(addr) {", 1)[1].split("\n}", 1)[0]
    assert 'CURRENT_VIEW !== "assets"' in seg, "a host->host hop is being treated as a journey"


def test_the_total_count_ignores_every_filter():
    captured = {}

    class C:
        def query(self, sql, parameters=None):
            captured["sql"] = sql
            captured["params"] = parameters
            return SimpleNamespace(result_rows=[[42]])

    assert status.anomalies_total_count(C(), min_score=0.4) == 42
    assert "count()" in captured["sql"]
    for clause in ("src_addr", "severity =", "splitByChar"):
        assert clause not in captured["sql"], (
            f"the 'of Y' number must be the UNFILTERED total; found {clause!r} in it")
    assert captured["params"] == {"s": 0.4}


def test_the_payload_carries_the_total_and_degrades_to_none():
    p = web_api.anomalies_payload([], total_unfiltered=7)
    assert p["total_unfiltered"] == 7
    p2 = web_api.anomalies_payload([])
    assert p2["total_unfiltered"] is None, "a failed read must omit Y, not invent a zero"


def test_copy_link_forces_the_state_before_copying():
    src = (WEB / "app.js").read_text()
    seg = src.split('const copyBtn = document.getElementById("copy-link");', 1)[1].split("});", 2)[0]
    assert "syncURL()" in seg, \
        "copying must WRITE the URL first (a debounced sync would copy the previous state)"
    assert "location.href" in seg


def test_the_arrival_chip_names_itself_and_offers_the_way_out():
    src = (WEB / "app.js").read_text()
    assert "ARRIVED_FROM_LINK" in src
    assert "arrived with filters" in src, "the arrival chip lost its explanation"
    seg = src.split("function anClearAllFilters() {", 1)[1].split("\n}", 1)[0]
    assert "ARRIVED_FROM_LINK = false" in seg, "clearing the filters must drop the arrival chip"
