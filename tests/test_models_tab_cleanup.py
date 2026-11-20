"""The Models tab's cleanup, pinned at the source and at the first-use wording.

The operator's rule (2026-11-20): a card survives only if it shows live data or an honest,
actionable state. Four paperwork cards and two duplicate Alerts panels were DELETED, not hidden,
so these checks fail if either the markup or the renderer comes back.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HTML = (ROOT / "weirvern" / "admin" / "web" / "index.html").read_text()
JS = (ROOT / "weirvern" / "admin" / "web" / "app.js").read_text()

REMOVED_IDS = (
    "m-verify",          # Verification coverage
    "m-eval",            # Evaluation history
    "m-review",          # Program review
    "m-ledger",          # Promotion policy and ledger
    "m-ripples",         # duplicate of the Alerts page's ripple table
    "m-ripples-note",
    "m-points",          # duplicate of the Alerts page's model anomalies table
)

REMOVED_RENDERERS = (
    "renderVerification",
    "renderEvalReport",
    "renderReview",
    "renderPromotionLedger",
    "renderRipples",
    "mKeepPoint",
)


def _models_section() -> str:
    start = HTML.index('<section id="view-models"')
    end = HTML.index("</section>", start)
    # Comments explain WHY a card left; they are not markup, so do not let the removal note
    # satisfy a check that the removed card is gone.
    return re.sub(r"<!--.*?-->", "", HTML[start:end], flags=re.S)


def test_the_removed_cards_are_absent_from_markup_and_javascript():
    models = _models_section()
    for element_id in REMOVED_IDS:
        assert element_id not in models, f"{element_id} is still in the Models markup"
        assert element_id not in JS, f"{element_id} is still referenced by app.js"
    for name in REMOVED_RENDERERS:
        assert name not in JS, f"{name} still exists; delete the renderer, not just the card"


def test_the_removed_card_titles_do_not_survive_in_the_models_section():
    models = _models_section()
    for title in ("Verification coverage", "Evaluation history", "Program review",
                  "Promotion policy and ledger"):
        assert title not in models, f"{title} is still a card on the Models tab"


def test_the_kept_surfaces_are_still_there():
    models = _models_section()
    for kept in ("Detectors", "Detection freshness", "Force retrain", "Source coverage",
                 "ML quality SLO", "Baseline deviations", "Near misses"):
        assert kept in models, f"{kept} was removed but is live or an honest state"


def test_the_alerts_page_is_where_the_removed_information_lives():
    # The duplicate cards were removed only because this page already carries the same rows.
    assert 'id="ripples-table"' in HTML
    assert 'id="anomalies-table"' in HTML
    assert "primary_deviation_feature" in JS  # the Alerts Why cell renders the feature
    assert "baseline_comparison" in JS        # ...and its measured magnitude


def test_knn_and_lof_are_spelled_out_at_first_use():
    # The sentence above the Detectors table names both in full, then uses the acronyms.
    assert "k-nearest neighbours (KNN distance)" in HTML
    assert "local outlier factor (LOF)" in HTML
    # The Detectors table itself expands each name on its first row (renderDetectors).
    assert 'return "k-nearest neighbours (KNN distance)";' in JS
    assert 'return "local outlier factor (LOF)";' in JS
    # ...and only there, so the table stays readable.
    assert JS.count('"k-nearest neighbours (KNN distance)"') == 1
    assert JS.count('"local outlier factor (LOF)"') == 1


def test_the_help_text_that_names_them_carries_the_expansion():
    # The training-history help is opened independently of the page order, so it may not use a
    # bare acronym the reader has not met yet.
    history_info = HTML[HTML.index('id="m-history-info"'):HTML.index("</div>", HTML.index('id="m-history-info"'))]
    assert "k-nearest neighbours (KNN distance)" in history_info
    assert "local outlier factor (LOF)" in history_info
