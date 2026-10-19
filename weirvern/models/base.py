"""Detector base class with artifact persistence.

Lesson (v14–v19): models were trained in-memory and lost on pod restart; the
*deployed* version was unknowable. Every detector now:
  * persists itself to MODEL_DIR/<name>_v<N>.pkl after training,
  * records its training metadata to ClickHouse ml_models,
  * can be loaded back, so restarts are warm (and the running version is
    visible on disk and in the DB).
"""
from __future__ import annotations

import logging
import pickle  # noqa: S403 - trusted local MODEL_DIR artifacts only (never untrusted input)
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from weirvern.features import FEATURE_SCHEMA_VERSION

logger = logging.getLogger(__name__)


@dataclass
class ModelMetadata:
    """Everything a training run should record — written to ml_models."""

    model_type: str
    # A datetime, not a float epoch.
    #
    # THE BUG: this was `float = field(default_factory=time.time)` while the
    # ml_models.trained_at column is DateTime, so clickhouse-connect failed on
    # every insert with:
    #
    #   Error serializing column `trained_at` into data type `DateTime`
    #   AttributeError: 'float' object has no attribute 'timestamp'
    #
    # The insert is wrapped in a try/except that logs a warning, so training
    # "succeeded" and then silently recorded NOTHING about it: no model
    # provenance, no metrics history, and `weirvern status` unable to report the
    # last training run. Caught only by running against a real ClickHouse.
    trained_at: datetime = field(default_factory=datetime.now)
    duration_seconds: float = 0.0
    feature_columns: list[str] = field(default_factory=list)
    # The FEATURE SCHEMA this artifact was trained under (features.FEATURE_SCHEMA_VERSION),
    # stamped by save(). 0 means the artifact predates the field, and load() refuses it: an
    # artifact that cannot say what it was trained on is exactly the one that used to score
    # 0.0 for hours after a feature-set change (review round 2026-10-15).
    feature_schema: int = 0
    params: dict[str, Any] = field(default_factory=dict)
    metrics: dict[str, Any] = field(default_factory=dict)
    # datetimes, not strings: the schema declares these as DateTime and
    # clickhouse-connect serialises a DateTime column by calling .timestamp() on
    # each value, so a str raised
    #   AttributeError: 'str' object has no attribute 'timestamp'
    # and the whole metadata row was lost (the insert's except only warns). These
    # were populated with str(start_dt) / str(end_dt), so every model recorded
    # nothing about the window it trained on.
    #
    # NOT Optional, and this took two attempts to get right: None is ALSO
    # rejected, because clickhouse-connect calls .timestamp() on every value
    # before checking for nulls:
    #   AttributeError: 'NoneType' object has no attribute 'timestamp'
    # A DateTime column with no DEFAULT therefore needs a real datetime. `now` is
    # the honest fallback: a detector that did not report its window was trained
    # at approximately now, and recording that keeps the row rather than losing it.
    #
    # The schema would be better with these nullable (DateTime has no DEFAULT, so
    # the DDL already allows NULL) -- the limitation is in the client library, not
    # ClickHouse. If a future version fixes it, these can become Optional again.
    window_start: datetime = field(default_factory=datetime.now)
    window_end: datetime = field(default_factory=datetime.now)
    sample_count: int = 0

    def to_row(self) -> dict[str, Any]:
        import json

        return {
            "model_id": f"{self.model_type.lower().replace(' ', '_')}_{int(self.trained_at.timestamp())}",
            "model_type": self.model_type,
            "trained_at": self.trained_at,
            "training_duration_seconds": int(self.duration_seconds),
            "feature_columns": self.feature_columns,
            "model_params": json.dumps(self.params),
            "metrics": json.dumps(self.metrics),
            "training_window_start": self.window_start,
            "training_window_end": self.window_end,
            "training_sample_count": self.sample_count,
            "current_weight": 1.0,
        }


class BaseDetector(ABC):
    """Common persistence + metadata plumbing."""

    name = "base"

    def __init__(self, model_dir: str | Path):
        self.model_dir = Path(model_dir)
        self.model_dir.mkdir(parents=True, exist_ok=True)
        self.metadata = ModelMetadata(model_type=self.name)
        # Failed-prediction counter (see note_predict_error). Initialised so a diagnostic
        # surface can read it before the first failure has happened.
        self.predict_errors = 0

    # -- artifact paths. `<name>_v<schema>.pkl`: the on-disk version IS the running version.
    #
    # THE SCHEMA COMPONENT IS REAL NOW (review round 2026-10-15). It was a literal `_v1`
    # while this comment claimed old versions were never overwritten -- in practice every
    # retrain replaced the only artifact, and a feature-set change could keep loading the
    # incompatible file. FEATURE_SCHEMA_VERSION bumps move to a new filename, leaving the
    # old artifact on disk (revert the bump to roll back); WITHIN a version a retrain
    # replaces the model, which is the intended cadence.
    def artifact_path(self) -> Path:
        return self.model_dir / f"{self.name}_v{FEATURE_SCHEMA_VERSION}.pkl"

    def save(self) -> Path:
        # The schema stamp is written by the CODE doing the saving, so it cannot go stale:
        # whatever this process knows how to build vectors for is what the artifact claims.
        self.metadata.feature_schema = FEATURE_SCHEMA_VERSION
        path = self.artifact_path()
        tmp = path.with_suffix(".tmp")
        with open(tmp, "wb") as fh:
            pickle.dump({"detector": self, "metadata": self.metadata}, fh)
        tmp.replace(path)  # atomic-ish write, no partial artifact
        logger.info("💾 Persisted %s to %s", self.name, path)
        return path

    def load(self) -> bool:
        path = self.artifact_path()
        if not path.exists():
            return False
        try:
            with open(path, "rb") as fh:
                payload = pickle.load(fh)  # noqa: S301 - trusted local artifact dir
            det: BaseDetector = payload["detector"]
            meta: ModelMetadata = payload["metadata"]
            # ── AN ARTIFACT MUST SPEAK THE RUNNING SCHEMA (review round 2026-10-15) ───────
            #
            # The feature lists live in CODE; an artifact's predict rebuilt its vector from
            # whatever the code currently says, so one trained on a different feature set
            # either raised (width mismatch) and scored 0.0 for up to a full retrain
            # interval while is_ready() stayed True -- or, same width, silently
            # reinterpreted every column after an edit. Both are checked BEFORE the detector
            # adopts the artifact, so a refusal changes nothing and the caller's retrain
            # path runs instead.
            schema = int(getattr(meta, "feature_schema", 0) or 0)
            if schema != FEATURE_SCHEMA_VERSION:
                logger.warning(
                    "Refusing %s artifact: trained under feature schema %d, the running code "
                    "expects %d -- retraining instead of loading",
                    self.name, schema, FEATURE_SCHEMA_VERSION,
                )
                return False
            expected = self.expected_feature_columns()
            have = list(meta.feature_columns or [])
            if expected and have != expected:
                logger.warning(
                    "Refusing %s artifact: trained on %d feature column(s), the running code "
                    "expects %d -- retraining instead of loading",
                    self.name, len(have), len(expected),
                )
                return False
            # AN ARTIFACT CANNOT REDIRECT ITS OWNER. `det` was built in the candidate
            # directory, and its pickled `model_dir` says so; adopting the whole dict moved
            # the LIVE detector's home to a directory `apply_candidate` deletes moments
            # later (GitHub #59). The live object's home and its in-process error counter
            # are runtime state, not model state: preserve both across the load.
            home = self.model_dir
            errors = self.predict_errors
            self.__dict__.update(det.__dict__)
            self.model_dir = home
            # Legacy artifacts predate the counter; a diagnostic surface must still read it.
            # The LIVE counter wins over the artifact's snapshot -- it counts this process's
            # failed predictions, which is what the health surface is asking about.
            self.predict_errors = int(errors or 0)
            self.metadata = meta
            logger.info("📂 Loaded %s from disk (trained %s)", self.name, self.metadata.trained_at)
            return True
        except Exception as exc:  # noqa: BLE001
            logger.warning("Could not load %s artifact: %s", self.name, exc)
            return False

    @abstractmethod
    def train(self, *args: Any, **kwargs: Any) -> bool: ...

    @abstractmethod
    def predict(self, flow: dict[str, Any], features: dict[str, float] | None = None) -> float: ...

    def is_ready(self) -> bool:
        return False

    def expected_feature_columns(self) -> list[str]:
        """The feature list this detector builds its vectors from, for artifact validation.

        Empty (the default) means the detector declares no column contract; a subclass that
        builds vectors from a named feature list overrides this, so load() can refuse an
        artifact trained on a different set (see load)."""
        return []

    def note_predict_error(self, exc: Exception) -> float:
        """Count a failed prediction; log it WITHOUT one line per window; return 0.0.

        A detector that fails EVERY window (a stale artifact that escaped the load checks, a
        corrupt model) used to log a warning per window while scoring 0.0 -- unreadable noise
        at fleet scale, and never a number anyone could act on. The count is the number; it
        rides the detector so any diagnostic surface can read it."""
        n = int(getattr(self, "predict_errors", 0)) + 1
        self.predict_errors = n
        if n == 1 or n % 100 == 0:
            logger.warning("Prediction error in %s (%d so far): %s", self.name, n, exc)
        return 0.0
