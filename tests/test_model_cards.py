"""PR-1: a model card is the identity behind a name in the fused score.

These are source and pure-logic tests; the live registry is exercised by `/api/models` and the
Models view after the migration is applied.
"""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from weirvern.models import cards

ROOT = Path(__file__).resolve().parents[1]


def test_a_missing_or_retired_card_is_not_production():
    allowed = cards.production_allowed({
        "Adaptive Baseline": "production",
        "Isolation Forest": "production",
        "Gradient Boosting": "shadow",
        "DBSCAN": "retired",
        "Old Model": "unknown",
    })
    assert allowed["Adaptive Baseline"] is True
    assert allowed["Isolation Forest"] is True
    assert allowed["Gradient Boosting"] is False
    assert allowed["DBSCAN"] is False
    assert allowed["Old Model"] is False
    assert cards.production_allowed({"DBSCAN": "retired"})["DBSCAN"] is False


def test_require_production_has_no_default_yes():
    class Empty:
        def query(self, _sql):
            return SimpleNamespace(result_rows=[])

    assert cards.require_production(Empty(), ["Isolation Forest", "DBSCAN"]) == {
        "Isolation Forest": False, "DBSCAN": False,
    }


def test_the_registry_migration_is_additive_and_seeds_every_live_family():
    src = (ROOT / "weirvern" / "schema" / "048_ml_model_cards.sql").read_text()
    assert "CREATE TABLE IF NOT EXISTS weirvern.ml_model_cards" in src
    assert "ReplacingMergeTree(updated_at)" in src
    for column in (
        "model_id", "model_name", "version", "artifact_hash", "training_window_start",
        "training_window_end", "feature_version", "calibration_version", "eval_report_id",
        "status", "owner", "approved_by", "approved_at", "rollback_ref", "intended_use",
        "out_of_scope", "known_limitations",
    ):
        assert column in src, column
    for family in ("Adaptive Baseline", "Isolation Forest", "Gradient Boosting", "DBSCAN"):
        assert family in src, family
    assert "'retired'" in src


def test_eligibility_is_card_gated_not_just_calibrated():
    src = (ROOT / "weirvern" / "models" / "calibration.py").read_text()
    assert "cards.registration(client)" in src or "_cards.registration(client)" in src
    assert "barred by model card" in src


def test_the_cards_panel_is_gone_but_the_payload_still_carries_the_registry():
    """The panel went; the registry did not (operator, 2026-11-19).

    "remove the Retraining and model cards registry from the models tab. we dont need them
    anymore" -- the VIEW is gone. Eligibility still reads the cards, so the payload must keep
    carrying them; deleting the backend too would quietly make every model card-gated-eligible.
    """
    api = (ROOT / "weirvern" / "admin" / "web_api.py").read_text()
    js = (ROOT / "weirvern" / "admin" / "web" / "app.js").read_text()
    html = (ROOT / "weirvern" / "admin" / "web" / "index.html").read_text()
    # the registry is still a fact the engine consults
    assert "model_cards" in api
    # the two panels are gone, markup and script both
    assert "renderModelCards" not in js and "m-cards" not in js
    assert "Model cards" not in html and "m-cards" not in html
    assert "Retraining <span" not in html and "mr-report" not in html
    # the one control they carried survives beside the truth it belongs to
    assert "Detection freshness" in html
    assert 'id="mr-force"' in html and 'id="mr-note"' in html
