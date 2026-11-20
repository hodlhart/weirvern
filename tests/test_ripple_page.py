"""The Ripples page: the anomaly page is the ripples, and the seam that keeps it honest.

WHY THIS IS A TEST AND NOT A SCREENSHOT.

The phase-2 change is a READING contract, not a new detector: `/api/ripples` already returns the
ripple, its evidence rows and the baseline report; the page must render that, and the model's
fused score must sit under it as corroboration. The failures that matter here are structural and
invisible in a screenshot:

  * the page renders rows but drops the explanation sentence (the one thing an operator reads);
  * the empty state says "no results" instead of naming the scales and the baseline counts;
  * the view hardcodes a 24-hour window while the payload answered for a different one;
  * the ripple sheet shows the fused score first, or calls it the finding;
  * the model anomalies disappear from the console because the primary list moved.

`scripts/jsdom_render.js` executes the shipping JavaScript against the shipping HTML and proves
the render. These tests prove the other half of the seam: the payload carries the numbers the
empty state needs, and the static structure keeps the two layers in the right order.
"""
from __future__ import annotations

import re
from pathlib import Path
from types import SimpleNamespace

from weirvern.admin import payloads
from weirvern.models import ripple_evidence

ROOT = Path(__file__).resolve().parents[1]
HTML = (ROOT / "weirvern" / "admin" / "web" / "index.html").read_text()
APP = (ROOT / "weirvern" / "admin" / "web" / "app.js").read_text()


def _view_section(view_id: str) -> str:
    """The markup of one view, up to its closing tag (these views hold no nested <section>)."""
    start = HTML.index(f'<section id="view-{view_id}"')
    return HTML[start:HTML.index("</section>", start)]


def _between(source: str, start: str, end: str) -> str:
    return source[source.index(start):source.index(end)]


class _EmptyEvidenceClient:
    """A read that succeeds and holds no evidence rows: the common case today."""

    def query(self, sql, parameters=None):
        if "network_scopes" in sql:
            return SimpleNamespace(result_rows=[("198.51.100.0/24",)])
        return SimpleNamespace(result_rows=[])


def test_the_tab_says_ripples_and_keeps_the_stable_view_id():
    """The label is what the operator reads; the id is what every link and loader uses."""
    tabs = re.findall(r'<button class="tab[^"]*" data-view="([\w-]+)">([^<]+)</button>', HTML)
    labels = dict(tabs)
    assert labels.get("anomalies") == "Ripples", labels.get("anomalies")
    assert 'id="view-anomalies"' in HTML
    # The other views are untouched: this was a retitle, not a renumbering of the nav.
    assert labels.get("models") == "Models"
    assert labels.get("normalize") == "Normalize"


def test_ripples_are_primary_and_model_anomalies_are_still_on_the_same_page():
    view = _view_section("anomalies")

    assert 'id="ripples-table"' in view
    assert 'id="rp-empty"' in view
    assert 'id="rp-pager"' in view
    # Model anomalies did not disappear: the queue, its filters and its review table are here.
    assert 'id="anomalies-table"' in view
    assert 'id="f-queue-mode"' in view
    assert 'id="an-discipline"' in view
    assert 'id="detectors-table"' in view
    # And the order is the contract: the ripple list comes before the corroboration section.
    assert view.index('id="ripples-table"') < view.index('id="anomalies-table"')
    assert view.index("Ripple evidence") < view.index("Model anomalies")
    assert "corroboration, not the finding" in view


def test_the_empty_state_names_scales_and_baseline_counts_never_no_results():
    body = _between(APP, "function renderRippleEmpty(", "function renderRippleRows(")
    scale = _between(APP, "function rippleScaleSentence(", "function renderRippleEmpty(")

    for field in ("baseline_windows", "minimum_windows", "usable", "required_lookback_days",
                  "lookback_days"):
        assert field in body + scale, f"the empty state cannot state {field!r} without reading it"
    assert "needs ${minimum} baseline windows: ${windows} of ${minimum}" in scale
    assert "next scale to become available" in body
    assert not re.search(r"no results", body, re.IGNORECASE), (
        "an empty window is a measurement with named scales, never 'no results'"
    )
    # A failed read is a different statement from a quiet network, and it is named as one.
    assert "that is not the same as a quiet network" in APP


def test_the_page_and_the_payload_agree_on_the_window():
    """There must be one window on the page, and it must be the one `/api/ripples` read."""
    load_ripple = _between(APP, "async function loadRipplePage(", "/* ── THE RIPPLE SHEET")
    page = _between(APP, "async function loadAnomalies(", "/* THE INCIDENT QUEUE")

    assert '"/api/ripples?hours=" + encodeURIComponent(hours)' in load_ripple
    assert "rippleData.window_hours" in page, "the anomaly reads must use the payload's window"
    assert "API.anomalies(min, limit, unreviewedOnly, hours)" in page
    assert "loadEpisodeQueue(queueMode, hours)" in page
    # No hardcoded 24-hour window anywhere in the ripple page's reads.
    assert not re.search(r"hours\s*=\s*[\"']?24", load_ripple + page), (
        "the page carries its own 24h instead of the payload's window_hours"
    )


def test_a_ripple_row_opens_the_house_sheet_evidence_then_corroboration():
    sheet = _between(APP, "function openRippleSheet(", "async function loadAnomalies(")

    assert "openSheet(card, { scrimId: \"rp-detail-scrim\"" in sheet
    assert "wireRippleSheet()" in sheet
    assert 'wireSheet(card, { scrimId: "rp-detail-scrim" })' in APP
    # One evidence line per channel, with the scale, the p-value and the baseline behind it.
    for field in ('"Channel"', '"Family"', '"Scale"', '"Value"', '"Baseline median"',
                  '"p-value"', '"Baseline"'):
        assert field in APP, f"the evidence table does not name {field}"
    for field in ("p_value", "baseline_median", "sample_count", "scale", "family"):
        assert field in APP, f"the evidence row does not read {field}"
    # The fused score is corroboration and is placed after the evidence, never before it.
    assert "Model anomalies in this window" in sheet
    assert "corroboration, not the finding" in sheet
    assert "rippleEvidenceTable(ripple)" in sheet
    assert sheet.index("rippleEvidenceTable(ripple)") < sheet.index("Model anomalies in this window")
    assert "loadRippleCorroboration(ripple, corrNote, corrSlot)" in sheet
    assert "anomaly_score" in APP and "detected_by_models" in APP


def test_the_baseline_report_carries_the_numbers_the_empty_state_prints():
    """The empty state's words are the engine's numbers, not a second calculation."""
    one_hour = ripple_evidence.scale_report("1h")
    six_hours = ripple_evidence.scale_report("6h")
    day = ripple_evidence.scale_report("24h")

    assert one_hour["usable"] is True
    assert one_hour["scale_seconds"] == 3600
    assert six_hours["usable"] is False
    assert six_hours["baseline_windows"] == 27
    assert six_hours["minimum_windows"] == 30
    assert six_hours["required_lookback_days"] == 8
    assert six_hours["lookback_days"] == 7
    assert day["baseline_windows"] == 6
    assert day["required_lookback_days"] == 31
    assert "baseline too short" in six_hours["reason"]


def test_an_empty_window_keeps_the_payloads_window_and_the_scale_report():
    out = payloads.ripples(_EmptyEvidenceClient(), hours=6)

    assert out["available"] is True
    assert out["reason"] == ""
    assert out["window_hours"] == 6
    assert out["ripples"] == []
    assert out["count"] == 0
    assert out["baseline"]["1h"]["usable"] is True
    assert out["baseline"]["6h"]["baseline_windows"] == 27
    assert out["evidence"]["rows"] == 0
    assert out["monitored_networks"] == ["198.51.100.0/24"]
