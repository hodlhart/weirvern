"""The scanned-exposure reading is a STATE, and its states must not collapse.

The scanner can be absent, pending, mid-scan, failed, or done. Only a done scan with a readable
findings table may say `clear`; everything else must remain visibly unknown or not scanned. These
tests pin that grammar, then pin the surfaces that consume it so a payload rename cannot silently
empty the column.
"""

from __future__ import annotations

from pathlib import Path

from weirvern.admin import assets

ROOT = Path(__file__).resolve().parents[1]
ASSETS_JS = (ROOT / "weirvern/admin/web/assets.js").read_text()
APP_JS = (ROOT / "weirvern/admin/web/app.js").read_text()
INDEX = (ROOT / "weirvern/admin/web/index.html").read_text()


def test_a_failed_scan_is_never_clear():
    assert assets._scan_band("error", None) == "failed"
    assert assets._scan_band("error", {"high": 0, "total": 0}) == "failed"


def test_not_scanned_is_distinct_from_clear():
    assert assets._scan_band("pending", None) == "not scanned"
    assert assets._scan_band("scanning", None) == "not scanned"
    assert assets._scan_band("done", {"critical": 0, "high": 0, "medium": 0,
                                      "low": 0, "info": 0, "total": 0}) == "clear"


def test_an_unreadable_findings_table_is_unknown_not_clear():
    assert assets._scan_band("done", None) == "unknown"
    assert assets._scan_band("unknown", None) == "unknown"


def test_the_highest_recorded_severity_wins():
    counts = {"critical": 0, "high": 2, "medium": 4, "low": 0, "info": 0, "total": 6}
    assert assets._scan_band("done", counts) == "high"


def test_the_inventory_ships_scan_and_exposure_fields_and_the_renderer_reads_them():
    # The bulk scan annotation is added in the function; source is the stable contract here.
    import inspect
    text = inspect.getsource(assets.asset_inventory)
    assert "_attach_scan_summaries" in text
    assert '"scan_available"' in text and '"scan_sources_failed"' in text
    for needle in ("h.scan", "scan.exposure", "with findings", "scan_sources_failed"):
        assert needle in ASSETS_JS, f"assets.js never reads {needle}"


def test_the_host_page_has_a_scanned_exposure_card_and_renderer():
    assert 'id="hp-scan-card"' in INDEX
    assert "Scanned exposure" in INDEX
    assert "hpRenderScanExposure" in APP_JS
    assert "not scanned" in APP_JS.lower()
