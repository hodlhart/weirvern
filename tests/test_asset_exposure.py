"""The scanned-exposure reading is a STATE, and its states must not collapse.

The scanner can be absent, pending, mid-scan, failed, or done. Nmap measures services and
identity facts; it does NOT prove a host is patched, so the grammar no longer has a `clear`
verdict at all -- a finished scan reads `scanned`, and everything else stays visibly unknown or
not scanned. These tests pin that grammar, then pin the surfaces that consume it so a payload
rename cannot silently empty the column.
"""

from __future__ import annotations

from pathlib import Path

from weirvern.admin import assets

ROOT = Path(__file__).resolve().parents[1]
ASSETS_JS = (ROOT / "weirvern/admin/web/assets.js").read_text()
APP_JS = (ROOT / "weirvern/admin/web/app.js").read_text()
INDEX = (ROOT / "weirvern/admin/web/index.html").read_text()


def test_a_failed_scan_is_never_scanned():
    assert assets._scan_band("error") == "failed"


def test_not_scanned_is_distinct_from_scanned():
    assert assets._scan_band("pending") == "not scanned"
    assert assets._scan_band("known") == "not scanned"
    assert assets._scan_band("scanning") == "scanning"
    assert assets._scan_band("done") == "scanned"


def test_an_unknown_state_is_named_unknown_not_scanned():
    assert assets._scan_band("unknown") == "unknown"
    assert assets._scan_band("") == "not scanned"


def test_there_is_no_clear_verdict_to_mistake_for_patched():
    """`clear` claimed a check Nmap cannot perform. It must not come back."""
    for state in ("done", "error", "pending", "scanning", "unknown"):
        assert assets._scan_band(state) != "clear"
    source = (ROOT / "weirvern/admin/assets.py").read_text()
    assert '_scan_band(state, counts)' not in source
    assert "asset_findings" not in source


def test_the_inventory_ships_scan_and_exposure_fields_and_the_renderer_reads_them():
    # The bulk scan annotation is added in the function; source is the stable contract here.
    import inspect
    text = inspect.getsource(assets.asset_inventory)
    assert "_attach_scan_summaries" in text
    assert '"scan_available"' in text and '"scan_sources_failed"' in text
    for needle in ("h.scan", "scan.exposure", "scan.can_scan", "scan_sources_failed"):
        assert needle in ASSETS_JS, f"assets.js never reads {needle}"


def test_the_host_page_has_a_scanned_exposure_card_and_renderer():
    assert 'id="hp-scan-card"' in INDEX
    assert "Scanned exposure" in INDEX
    assert "hpRenderScanExposure" in APP_JS
    assert "not scanned" in APP_JS.lower()
