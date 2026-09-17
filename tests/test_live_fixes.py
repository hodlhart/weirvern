"""Regression tests for three bugs found only on a live cluster.

All three passed the entire suite, `ruff`, `mypy`, `kubeconform` and
`kustomize build`, and all three made the deployment quietly not work:

  1. ml_models.trained_at is DateTime but ModelMetadata held a float epoch, so
     every metadata insert failed and model provenance was silently lost.

  2. The ingest thread shared the detection loop's clickhouse-connect client, and
     the driver forbids concurrent queries on one session — so ingest passes
     failed intermittently under load.

  3. load_or_train() returned None whether it trained or found nothing, so the
     caller stamped "trained now" even on a cold start with zero data, deferring
     the next retrain by the full retrain_every_h window (6h). A fresh deployment
     therefore detected nothing for hours while every pod reported healthy.
"""
from __future__ import annotations

from datetime import datetime
from unittest.mock import MagicMock

import pytest

from weirvern.models.base import ModelMetadata
from weirvern.worker import load_or_train


# --- 1. metadata type ---------------------------------------------------------
def test_model_metadata_trained_at_is_a_datetime_not_a_float():
    """clickhouse-connect serialises DateTime columns by calling .timestamp() on
    each value, so a float raised:
        AttributeError: 'float' object has no attribute 'timestamp'
    and the insert (wrapped in a warning-only except) recorded nothing at all.
    """
    md = ModelMetadata(model_type="Isolation Forest")
    assert isinstance(md.trained_at, datetime), (
        f"trained_at must be a datetime for the DateTime column, got "
        f"{type(md.trained_at).__name__}"
    )


def test_model_metadata_row_serialises_for_a_datetime_column():
    """The row must survive the exact operation clickhouse-connect performs."""
    md = ModelMetadata(model_type="Adaptive Baseline", duration_seconds=1.5,
                       window_start="2026-09-17 10:00:00")
    row = md.to_row()
    assert isinstance(row["trained_at"], datetime)
    # This is the call that failed on a float.
    assert isinstance(row["trained_at"].timestamp(), float)
    # model_id must still be stable/int-based for the ReplacingMergeTree key.
    assert row["model_id"].startswith("adaptive_baseline_")
    assert row["model_id"].rsplit("_", 1)[1].isdigit()


def test_model_metadata_row_keys_match_the_schema_columns():
    """A rename on either side writes nothing. Pin the names."""
    row = ModelMetadata(model_type="DBSCAN").to_row()
    for col in ("model_id", "model_type", "trained_at", "training_duration_seconds",
                "feature_columns", "model_params", "metrics",
                "training_window_start", "training_window_end",
                "training_sample_count"):
        assert col in row, f"{col} missing from the row written to ml_models"


def test_all_datetime_columns_receive_datetimes_not_strings():
    """THE SECOND HALF OF THE SAME BUG, found only after fixing the first.

    training_window_start and training_window_end are DateTime columns, but the
    fields were typed `str` and populated with str(start_dt). Fixing trained_at
    alone therefore moved the failure along rather than resolving it:

        AttributeError: 'float' object has no attribute 'timestamp'
        ... became ...
        AttributeError: 'str' object has no attribute 'timestamp'

    Both columns must hold datetimes. This asserts the TYPE of every value whose
    schema column is a DateTime, so a third one cannot slip through.
    """
    from datetime import datetime

    md = ModelMetadata(
        model_type="Adaptive Baseline",
        window_start=datetime(2026, 9, 17, 10, 0, 0),
        window_end=datetime(2026, 9, 17, 16, 0, 0),
    )
    row = md.to_row()
    for col in ("trained_at", "training_window_start", "training_window_end"):
        assert isinstance(row[col], datetime), (
            f"{col} must be a datetime for its DateTime column, got "
            f"{type(row[col]).__name__} ({row[col]!r})"
        )
        # clickhouse-connect's exact serialisation step.
        assert isinstance(row[col].timestamp(), float)


def test_unknown_window_gets_a_real_datetime_not_none_or_empty():
    """A DateTime column needs a real datetime, and this took two attempts.

    `""` fails with "'str' object has no attribute 'timestamp'". `None` fails the
    SAME way, because clickhouse-connect calls .timestamp() on every value before
    considering nulls:

        AttributeError: 'NoneType' object has no attribute 'timestamp'

    So a detector that cannot report its training window must still supply a
    datetime. `now` is the honest choice and keeps the row instead of losing it --
    which matters, because the insert's except only logs a warning, so a failure
    here silently discards all model provenance.
    """
    md = ModelMetadata(model_type="Isolation Forest")
    assert isinstance(md.window_start, datetime)
    assert isinstance(md.window_end, datetime)
    row = md.to_row()
    for col in ("training_window_start", "training_window_end"):
        assert isinstance(row[col], datetime), (
            f"{col} must be a datetime; None and '' both fail clickhouse-connect"
        )
        assert isinstance(row[col].timestamp(), float)


def test_no_detector_passes_formatted_strings_into_metadata_windows():
    """Guard the call sites, not just the dataclass.

    The dataclass being correct is useless if a detector passes str(dt). This
    scans the detector source for the exact anti-pattern that caused the bug.
    """
    import inspect

    from weirvern.models import detectors

    src = inspect.getsource(detectors)
    offenders = [
        line.strip() for line in src.splitlines()
        if "window_start=str(" in line or "window_end=str(" in line
    ]
    assert not offenders, (
        "a detector is formatting a datetime into a string for a DateTime "
        f"column: {offenders}"
    )


# --- 3. cold-start retry ------------------------------------------------------
class _Detector:
    """A detector that reports whether training succeeded."""

    def __init__(self, name: str, trains: bool, has_scaled: bool = True):
        self.name = name
        self._trains = trains
        self.X_train_unscaled = [1, 2, 3] if has_scaled else None
        self.train_calls = 0

    def load(self) -> bool:
        return False

    def train(self, start, end, client) -> bool:  # noqa: ANN001
        self.train_calls += 1
        return self._trains

    def persist_history(self, client, hours) -> None:  # noqa: ANN001
        pass


def _stub_metadata(monkeypatch):
    import weirvern.worker as w

    monkeypatch.setattr(w, "_record_model_metadata", lambda client, dets: None)


def test_load_or_train_reports_failure_when_there_is_no_data(monkeypatch):
    """THE BUG: this returned None in both cases, so the caller could not tell a
    successful warm start from a cold start with nothing to train on."""
    _stub_metadata(monkeypatch)
    settings = MagicMock(retrain_window_h=72)
    dets = [_Detector("if", False, has_scaled=False), _Detector("gb", False),
            _Detector("db", False), _Detector("bl", False)]

    assert load_or_train(MagicMock(), dets, settings, MagicMock()) is False
    # The INDEPENDENT detectors must each have been attempted. `if` is asserted
    # separately below because Gradient Boosting is trained from Isolation
    # Forest's scaled output, so it is deliberately skipped when IF produced
    # nothing — that is correct behaviour, not a skipped attempt.
    _, gb, db, bl = dets
    assert db.train_calls == 1, "DBSCAN must be attempted"
    assert bl.train_calls == 1, "the baseline must be attempted"
    assert gb.train_calls == 0, (
        "GB trains on IF's output; with no IF there is nothing to learn from"
    )


def test_load_or_train_reports_success_when_any_detector_trains(monkeypatch):
    """At least one usable detector is enough to detect; the baseline alone can
    flag a bytes outlier, which is the most common real case."""
    _stub_metadata(monkeypatch)
    settings = MagicMock(retrain_window_h=72)
    dets = [_Detector("if", False, has_scaled=False), _Detector("gb", False),
            _Detector("db", False), _Detector("bl", True)]

    assert load_or_train(MagicMock(), dets, settings, MagicMock()) is True


def test_load_or_train_reports_success_on_a_warm_start(monkeypatch):
    """All detectors load from disk: no training needed, but it IS usable."""
    _stub_metadata(monkeypatch)
    dets = [_Detector("if", False), _Detector("gb", False),
            _Detector("db", False), _Detector("bl", False)]
    for d in dets:
        d.load = lambda: True  # type: ignore[method-assign]

    assert load_or_train(MagicMock(), dets, MagicMock(retrain_window_h=72),
                         MagicMock()) is True
    assert all(d.train_calls == 0 for d in dets), "warm start must not retrain"


def test_baseline_history_is_only_persisted_when_training_succeeded(monkeypatch):
    """persist_history mirrors baselines to ClickHouse. Calling it after a failed
    train would write an empty/garbage row for every host."""
    _stub_metadata(monkeypatch)
    settings = MagicMock(retrain_window_h=72)

    bl_fail = _Detector("bl", False)
    bl_fail.persist_history = MagicMock()  # type: ignore[method-assign]
    load_or_train(MagicMock(), [_Detector("if", False, has_scaled=False),
                                _Detector("gb", False), _Detector("db", False),
                                bl_fail], settings, MagicMock())
    assert bl_fail.persist_history.call_count == 0, (
        "baseline history must not be persisted when the baseline failed to train"
    )

    bl_ok = _Detector("bl", True)
    bl_ok.persist_history = MagicMock()  # type: ignore[method-assign]
    load_or_train(MagicMock(), [_Detector("if", False, has_scaled=False),
                                _Detector("gb", False), _Detector("db", False),
                                bl_ok], settings, MagicMock())
    assert bl_ok.persist_history.call_count == 1


def test_main_loop_retries_cold_start_instead_of_deferring_the_full_window(monkeypatch):
    """The consequence of bug 3, asserted at the source level.

    A cold start that finds no data must NOT latch trained_once, or the next
    full retrain is deferred by retrain_every_h (6h) while the pods look healthy.
    """
    import inspect

    import weirvern.worker as w

    src = inspect.getsource(w.main)
    # The latch must be conditional on the training result.
    assert "if load_or_train(" in src, (
        "main() must gate trained_once on load_or_train's result, not set it "
        "unconditionally"
    )
    assert src.count("trained_once = True") == 1, (
        "trained_once should be latched in exactly one place"
    )
    # And it must be inside the conditional, i.e. indented under it.
    for line in src.splitlines():
        if "if load_or_train(" in line:
            indent = len(line) - len(line.lstrip())
            break
    else:
        pytest.fail("could not locate the load_or_train call in main()")
    assert indent >= 16, f"the call is not inside the try/if block (indent {indent})"


# --- 2. one client per thread -------------------------------------------------
def test_ingest_thread_gets_its_own_client(monkeypatch):
    """clickhouse-connect refuses concurrent queries on one session:
        Attempt to execute concurrent queries within the same session.
        Please use a separate client instance per thread/process.
    The ingest thread must therefore NOT receive the detection loop's client.
    """
    import inspect

    import weirvern.worker as w

    src = inspect.getsource(w.main)
    assert "ingest_client = db.connect(" in src, (
        "the ingest thread must open its own ClickHouse client; sharing one "
        "across threads fails intermittently under load"
    )
    # And that client, not `client`, must be handed to the thread.
    assert "args=(ingest_client," in src, (
        "the ingest thread is being given the wrong client"
    )
    assert "args=(client, settings.tail_file" not in src, (
        "the ingest thread is still sharing the detection loop's client"
    )
