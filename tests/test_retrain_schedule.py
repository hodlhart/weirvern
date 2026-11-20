"""A restart must resume the retrain schedule, not reset it.

WHY THIS FILE EXISTS. `last_full_train` was stamped with `datetime.now()` whenever the detectors
were *usable* -- and a warm start is usable with no training having happened at all. So every
worker restart restarted the retrain clock, and the full-retrain branch correctly declined to
fire for another `retrain_every_h`.

MEASURED on the deployment before the fix: Isolation Forest, Gradient Boosting and the
density detector had
not retrained in 16 hours against a 6-hour interval, while the Adaptive Baseline trained 321
times in the same period because it has its own fast-refresh path. Nothing raised, the status
page showed all four detectors loaded, and the three stale models kept scoring against a baseline
trained on an older traffic mix. The only visible symptom was a number in `ml_models` that nobody
was comparing against the retrain interval.

The fix makes the age come from the ARTIFACT rather than from the process's uptime, which means
`load_or_train` returns a timestamp and three edge cases have to hold:

  * a fresh deployment (nothing trained) must still be DUE, or detection never starts;
  * a warm start with old artifacts must be DUE, or the staleness returns;
  * a NOT-ready detector must not count, because `ModelMetadata.trained_at` defaults to
    `datetime.now()` at construction -- including one would pin the clock to "just now" and
    suppress the retrain, arriving at the same never-retrain failure from the other direction.
"""

from __future__ import annotations

import pathlib
import re
import tempfile
from datetime import datetime, timedelta
from inspect import getsource

import pytest

from weirvern.config import ModelConfig
from weirvern.models.detectors import (
    AdaptiveBaselineDetector,
    GradientBoostingDetector,
    IsolationForestDetector,
    KNNDistanceDetector,
)
from weirvern.worker import _oldest_trained_at, load_or_train


@pytest.fixture
def detectors():
    cfg = ModelConfig()
    d = pathlib.Path(tempfile.mkdtemp())
    return [
        IsolationForestDetector(d, cfg),
        GradientBoostingDetector(d, cfg),
        KNNDistanceDetector(d, cfg),
        AdaptiveBaselineDetector(d, cfg),
    ]


def _ready(det, hours_ago: float) -> None:
    """Mark a detector ready with an artifact timestamp `hours_ago` old."""
    det.is_ready = lambda: True
    det.metadata.trained_at = datetime.now() - timedelta(hours=hours_ago)


# ── the helper's three cases ───────────────────────────────────────────────────────────────


def test_nothing_trained_means_due(detectors):
    """A fresh deployment must retrain, not wait out a cadence."""
    assert _oldest_trained_at(detectors) is None, (
        "with no trained detector the answer must be None, which the caller reads as 'due'. "
        "Returning a timestamp here would defer training on a fresh deployment."
    )


def test_a_warm_start_reports_the_artifact_age_not_now(detectors):
    """This is the regression: the age used to be `now`, i.e. the clock reset on every restart."""
    _ready(detectors[0], 16)
    _ready(detectors[1], 16)
    _ready(detectors[2], 15)
    oldest = _oldest_trained_at(detectors)
    assert oldest is not None, "a warm start with 15-16h-old artifacts must report an age"
    age_h = (datetime.now() - oldest).total_seconds() / 3600
    assert age_h > 15.9, (
        f"the reported age is {age_h:.1f}h; it must come from the artifact. Reporting ~0h is the "
        f"bug: it makes a 16-hour-stale model look freshly trained and suppresses the retrain."
    )


def test_the_oldest_full_detector_decides_not_the_newest(detectors):
    """One freshly-trained detector must not hold a retrain back for the stale ones."""
    _ready(detectors[0], 20)   # the stalest
    _ready(detectors[1], 1)
    _ready(detectors[2], 1)
    oldest = _oldest_trained_at(detectors)
    assert oldest is not None
    age_h = (datetime.now() - oldest).total_seconds() / 3600
    assert age_h > 19, f"the newest detector won: reported {age_h:.1f}h, expected ~20h"


def test_the_adaptive_baseline_is_excluded(detectors):
    """It refreshes on its own faster cadence, so including it would pin the clock to now."""
    _ready(detectors[0], 12)
    _ready(detectors[1], 12)
    _ready(detectors[2], 12)
    _ready(detectors[3], 0)   # the baseline, trained moments ago
    oldest = _oldest_trained_at(detectors)
    assert oldest is not None
    age_h = (datetime.now() - oldest).total_seconds() / 3600
    assert age_h > 11.9, (
        f"the baseline's fresh timestamp leaked in: reported {age_h:.1f}h instead of ~12h. "
        f"Including it would make the full retrain never become due."
    )


def test_a_not_ready_detector_does_not_count(detectors):
    """`trained_at` defaults to now() at construction, so an untrained detector must be skipped.

    This is the subtle one: including a constructed-but-untrained detector reports an age of
    zero and suppresses the retrain -- the same never-retrain failure from the other direction.
    """
    # Default construction already leaves metadata.trained_at at now().
    assert detectors[0].metadata.trained_at is not None, (
        "the default_factory changed; this test's premise needs re-checking"
    )
    assert _oldest_trained_at(detectors) is None, (
        "a detector that is not ready contributed a timestamp, so a deployment that has never "
        "trained would report 'freshly trained' and never retrain"
    )


# ── the contract with the caller ───────────────────────────────────────────────────────────


def test_load_or_train_returns_a_timestamp_alongside_usability():
    """The caller needs the age, so a bare bool cannot carry it."""
    src = getsource(load_or_train)
    assert "tuple[bool, datetime | None]" in src, (
        "load_or_train no longer returns the artifact timestamp, so the caller has nothing to "
        "base `last_full_train` on and will reach for now() again"
    )


def test_the_worker_does_not_stamp_now_on_a_warm_start():
    """The exact line that caused the staleness."""
    worker = pathlib.Path(__file__).resolve().parent.parent / "weirvern" / "worker.py"
    src = worker.read_text()
    # STRIP COMMENTS AND DOCSTRINGS FIRST. The fix's own comment QUOTES the old line while
    # explaining it, and a naive scan for that text matched the explanation -- the same
    # false-positive shape as a sibling test that matched a class name inside a comment.
    code = re.sub(r'""".*?"""', "", src, flags=re.S)      # docstrings
    code = re.sub(r"^\s*#.*$", "", code, flags=re.M)      # comments

    assert "last_full_train = as_aware(trained_at) if trained_at else utcnow()" in code, (
        "the worker does not use the artifact timestamp for last_full_train, so a warm start "
        "resets the retrain clock (measured: 16 hours without a retrain against a 6h interval)"
    )
    assert "last_full_train = datetime.now()" not in code, (
        "an unconditional now() stamp is still executed in the worker"
    )
