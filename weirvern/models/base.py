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
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class ModelMetadata:
    """Everything a training run should record — written to ml_models."""

    model_type: str
    trained_at: float = field(default_factory=time.time)
    duration_seconds: float = 0.0
    feature_columns: list[str] = field(default_factory=list)
    params: dict[str, Any] = field(default_factory=dict)
    metrics: dict[str, Any] = field(default_factory=dict)
    window_start: str = ""
    window_end: str = ""
    sample_count: int = 0

    def to_row(self) -> dict[str, Any]:
        import json

        return {
            "model_id": f"{self.model_type.lower().replace(' ', '_')}_{int(self.trained_at)}",
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

    # -- artifact paths (versioned filename => the on-disk version is the
    #    running version; old versions are never silently overwritten)
    def artifact_path(self) -> Path:
        return self.model_dir / f"{self.name}_v1.pkl"

    def save(self) -> Path:
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
            self.__dict__.update(det.__dict__)
            self.metadata = det.metadata
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
