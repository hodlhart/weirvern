"""An artifact must not outlive the feature schema it was trained on.

WHY THIS FILE EXISTS (review round 2026-10-15). `artifact_path()` hardcoded `_v1.pkl` under
a comment claiming versioned filenames, so every retrain overwrote the only artifact; and
`load()` accepted any pickle, while `predict` rebuilds its vector from the CODE's current
feature list. Measured shape of the failure: an artifact trained on a different feature set
either raised inside predict (caught -> 0.0 for up to `retrain_every_h`, with `is_ready()`
still True) or -- same width -- silently reinterpreted every column after an edit.

The fix is a contract in three parts, each pinned here:
  * the artifact FILENAME carries the feature schema (`<name>_v<N>.pkl`);
  * `save()` stamps the schema into the metadata by the code doing the saving;
  * `load()` refuses a schema or column mismatch BEFORE adopting the artifact, so the
    detector stays untouched and `load_or_train`'s retrain path runs instead.
"""

from __future__ import annotations

import pickle

import pytest

from weirvern.features import FEATURE_SCHEMA_VERSION, IF_FEATURES
from weirvern.models.detectors import IsolationForestDetector


def _saved(tmp_path, columns=None):
    det = IsolationForestDetector(tmp_path)
    det.metadata.feature_columns = list(columns if columns is not None else IF_FEATURES)
    det.save()
    return det


def test_the_artifact_filename_carries_the_feature_schema(tmp_path):
    det = IsolationForestDetector(tmp_path)
    assert det.artifact_path().name == f"{det.name}_v{FEATURE_SCHEMA_VERSION}.pkl"


def test_save_stamps_the_schema_and_a_matching_artifact_loads(tmp_path):
    _saved(tmp_path)
    fresh = IsolationForestDetector(tmp_path)
    assert fresh.load() is True
    assert fresh.metadata.feature_schema == FEATURE_SCHEMA_VERSION
    assert list(fresh.metadata.feature_columns) == list(IF_FEATURES)


def test_load_refuses_an_artifact_trained_on_a_different_feature_set(tmp_path):
    _saved(tmp_path, columns=["totally", "different"])
    fresh = IsolationForestDetector(tmp_path)
    assert fresh.load() is False
    assert fresh.is_ready() is False, "a refused artifact must not read as ready"


def test_load_refuses_an_artifact_from_another_schema_version(tmp_path):
    det = _saved(tmp_path)
    path = det.artifact_path()
    with open(path, "rb") as fh:
        payload = pickle.load(fh)
    payload["metadata"].feature_schema = FEATURE_SCHEMA_VERSION + 7
    with open(path, "wb") as fh:
        pickle.dump(payload, fh)
    fresh = IsolationForestDetector(tmp_path)
    assert fresh.load() is False


def test_a_refused_load_leaves_the_detector_untouched(tmp_path):
    """No half-loaded state: the check runs BEFORE `__dict__.update`, so a refusal cannot
    leave the detector carrying a model it just decided it must not use."""
    _saved(tmp_path, columns=["wrong"])
    fresh = IsolationForestDetector(tmp_path)
    before = (fresh.model, fresh.preprocessor.fitted, fresh.metadata.feature_schema)
    assert fresh.load() is False
    assert (fresh.model, fresh.preprocessor.fitted, fresh.metadata.feature_schema) == before


def test_predict_errors_are_counted_and_not_logged_per_window(tmp_path, caplog):
    """A detector failing every window is a NUMBER, not one warning line per window."""
    det = IsolationForestDetector(tmp_path)
    det.model = object()  # predict will raise inside its try (unfitted preprocessor)
    with caplog.at_level("WARNING"):
        first = det.predict({})
        second = det.predict({})
    assert first == second == 0.0
    assert det.predict_errors == 2
    logged = [m for m in caplog.messages if "Prediction error" in m]
    assert len(logged) == 1, f"expected one warning for two failures, got {len(logged)}"


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
