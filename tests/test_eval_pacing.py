"""One sweep covers one hour, so the eval must call it until the seed is drained.

THE DEFECT THIS PINS. `detection_sweep` caps a cycle at MAX_CATCHUP_BUCKETS (12) of AGG_BUCKET_S
(300), so it examines at most ONE HOUR per call. That cap is correct and deliberate: an uncapped
catch-up after a stalled cursor is what OOMed the worker, and a stuck cursor then never recovered.
But the eval seeds five hours and called the sweep exactly ONCE, so it scored the first hour, judged
windows that predate the attacks injected at minute 200, and reported detection as missing. The
instrument was measuring its own window rather than the engine.

A pass/fail on the CI job would not have caught that: the job failed, and the reason it failed was
the harness. These tests assert the drain, and the no-progress case, which is the one that would
otherwise hang or report a silent partial run as complete.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from scripts import eval_detection as ev
from weirvern.config import ModelConfig, Settings


@pytest.fixture
def rig(tmp_path, monkeypatch):
    """A console-free rig: fake rows, a fake sweep that advances the cursor, real loop."""
    # NOT stubbing _as_datetime: the cursor file holds an ISO string and the parser is what turns it
    # back into a datetime. Stubbing it made the comparison `str >= datetime` and the test failed for
    # a reason that had nothing to do with the loop.
    lo = datetime(2026, 11, 16, 0, 0, 0)
    hi = lo + timedelta(hours=5)

    def fetch_rows(client, sql):
        return [(lo, hi)]

    monkeypatch.setattr("weirvern.db.fetch_rows", fetch_rows)

    # Settings is FROZEN, so the cursor directory comes from the constructor. Assigning it after
    # construction raises FrozenInstanceError, which is the dataclass doing its job.
    settings = Settings(model_dir=str(tmp_path))
    cfg = ModelConfig()

    calls = {"n": 0}

    def fake_sweep(client, detectors, widened, cfg_):
        calls["n"] += 1
        covered = lo + timedelta(hours=calls["n"])
        (tmp_path / "detect_cursor.json").write_text(
            json.dumps({"covered_through": covered.isoformat()}))
        return [{"window_start": covered, "src_addr": f"192.0.2.{calls['n']}"}]

    monkeypatch.setattr("weirvern.worker.detection_sweep", fake_sweep)
    monkeypatch.setattr(ev, "train_detectors", lambda *a, **k: ([object()], None))
    return settings, cfg, calls, (lo, hi)


def test_the_sweep_is_called_until_the_seed_is_drained(rig):
    settings, cfg, calls, (lo, hi) = rig
    verdicts, err = ev.run_detection(object(), (settings, cfg), 300)

    assert err is None, err
    assert calls["n"] >= 5, (
        f"the sweep ran {calls['n']} time(s) for a 5-hour seed; one call covers one hour, so the "
        "rest of the seed was never examined"
    )
    assert len(verdicts) == calls["n"], "verdicts from later calls were dropped"


def test_a_sweep_that_stops_advancing_is_reported_not_silently_accepted(rig, monkeypatch):
    settings, cfg, _calls, (lo, _hi) = rig
    stuck = {"n": 0}

    def stuck_sweep(client, detectors, widened, cfg_):
        stuck["n"] += 1
        # writes the SAME boundary every time: coverage does not progress
        cursor = Path(settings.model_dir) / "detect_cursor.json"
        cursor.write_text(json.dumps({"covered_through": (lo + timedelta(hours=1)).isoformat()}))
        return []

    monkeypatch.setattr("weirvern.worker.detection_sweep", stuck_sweep)
    verdicts, err = ev.run_detection(object(), (settings, cfg), 300)

    assert err is not None, "a stalled sweep reported success"
    assert "stopped advancing" in err
    assert "NOT examined" in err, "the error must say the windows were unmeasured, not absent"
    assert verdicts == []
    assert stuck["n"] <= 2, f"it kept calling a stuck sweep {stuck['n']} times"


def test_reading_a_missing_cursor_is_none_rather_than_an_exception(tmp_path):
    assert ev._read_cursor(tmp_path / "nope.json") is None


def test_reading_a_corrupt_cursor_is_none_rather_than_an_exception(tmp_path):
    bad = tmp_path / "c.json"
    bad.write_text("{not json")
    assert ev._read_cursor(bad) is None
