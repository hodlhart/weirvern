"""The density detector is REMOVED, not retired: every place that could resurrect it is checked.

OPERATOR DECISION (2026-11-20): "Completely remove dbscan." The reason is measured -- 97.89% of
27,454 stored scores sat at 0.99 or above (p50 = p99 = max = 0.99), so no threshold could separate
anything from anything. A retired-but-present class is a name an old artifact, a log line or a stale
registry row can bring back; absence is the only state that cannot.

These tests are the four seams the task names, plus the source tree:
  * `build_detectors` (the engine's roster),
  * `MODEL_FAMILIES` and the weight mapping inside `detect_flows` (`NAME_TO_KEY`),
  * the Detectors payload,
  * the artifacts the engine can ask for on disk,
  * and the package source itself.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from types import SimpleNamespace

from weirvern.config import ModelConfig
from weirvern.ensemble import MODEL_FAMILIES
from weirvern.models.detector_status import detector_rows
from weirvern.models.detectors import DETECTOR_NAMES
from weirvern.worker import build_detectors

ROOT = Path(__file__).resolve().parents[1]
PKG = ROOT / "weirvern"
# "HDBSCAN" is a DIFFERENT algorithm (a shadow challenger), and its name contains the substring.
# The removed detector is the bare token, which is what every assertion below looks for.
_NAME = re.compile(r"(?<!H)DBSCAN")
_LOWER = re.compile(r"(?<!h)dbscan")


def test_build_detectors_returns_the_roster_and_no_density_detector(tmp_path):
    detectors = build_detectors(SimpleNamespace(model_dir=str(tmp_path)), ModelConfig())
    names = [d.name for d in detectors]
    assert names == ["Isolation Forest", "Gradient Boosting", "KNN distance", "LOF",
                     "Adaptive Baseline"]
    assert not any(_NAME.search(n) for n in names)


def test_no_family_and_no_weight_key_names_the_removed_detector():
    assert not any(_NAME.search(name) for name in MODEL_FAMILIES)
    # NAME_TO_KEY is local to `detect_flows`; its KEYS are the config weight names, and the config
    # no longer has one -- a weight with no model is a mapping entry nothing can reach.
    weights = ModelConfig().weights
    assert not any(_LOWER.search(key) for key in weights), sorted(weights)
    ensemble_src = (PKG / "ensemble.py").read_text(encoding="utf-8")
    assert not _LOWER.search(ensemble_src), (
        "ensemble.py still names the removed detector (a score key or a comment that would keep "
        "it in the fusion's vocabulary)")


def test_the_detectors_payload_has_no_row_for_it_even_with_history(tmp_path):
    training = {"DBSCAN": {"trained_at": "2026-11-19 08:21:17", "samples": 5000}}
    artifacts = {"DBSCAN": {"version": "v5", "written_at": "2026-11-19T08:22:00+00:00"}}
    calibration = {"DBSCAN": {"observed_far": 0.98, "target_far": 0.01, "coverage": 0.9,
                              "coverage_observed": 17, "coverage_expected": 19,
                              "age_hours": 0.5}}
    rows = detector_rows(training, artifacts, calibration, known_names=DETECTOR_NAMES)
    assert rows == []
    assert not _NAME.search(json.dumps(rows))
    # AND THE PAYLOAD ACTUALLY PASSES THE ROSTER. A filter the caller forgets is not a removal;
    # this is the seam, asserted in the source the route runs.
    payload_src = (PKG / "admin" / "payloads.py").read_text(encoding="utf-8")
    assert "known_names=DETECTOR_NAMES" in payload_src, (
        "payloads.models stopped filtering the Detectors table to the engine roster")


def test_the_engine_can_never_ask_for_an_artifact_of_that_name(tmp_path):
    """The artifact name is derived from the detector's own name, and no detector has it."""
    detectors = build_detectors(SimpleNamespace(model_dir=str(tmp_path)), ModelConfig())
    for detector in detectors:
        path = Path(detector.artifact_path())  # type: ignore[attr-defined]
        assert not _NAME.search(path.name), path.name
    # And nothing in the package resolves that file name any more.
    for source in PKG.rglob("*.py"):
        text = source.read_text(encoding="utf-8")
        assert not _NAME.search(text), f"{source.relative_to(ROOT)} still names the removed detector"


def test_the_frontend_and_the_schema_seed_do_not_name_it():
    for asset in (PKG / "admin" / "web").glob("*"):
        if asset.suffix in {".js", ".html"}:
            assert not _NAME.search(asset.read_text(encoding="utf-8")), asset.name
    seed = (PKG / "schema" / "048_ml_model_cards.sql").read_text(encoding="utf-8")
    assert not _NAME.search(seed), "a fresh install would seed a card for a model that is gone"
    # The removal migration exists and deletes the registry rows the live deployment may still hold.
    removal = (PKG / "schema" / "059_remove_dbscan.sql").read_text(encoding="utf-8")
    assert "ml_model_cards" in removal and "ml_models" in removal
