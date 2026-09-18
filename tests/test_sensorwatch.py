"""Tests for observing the sensor's state from outside.

WHY THE WORKER OBSERVES RATHER THAN THE SENSOR SELF-REPORTING: the `zeek/zeek` image has no
python3 (busybox/ash, perl and Zeek only -- verified on the live pod), so nothing in that
container can write a row. More importantly, a self-reporting sensor can only say "my
heartbeat loop is alive"; it cannot say "my capture is broken". Reading the LOG FILES
answers the operator's actual question -- is the sensor producing data?

The specific lie these tests prevent: `stats.log` is written on a TIMER even when no packets
arrive, so using it as the liveness signal would report a dead sensor as healthy.
"""
from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from weirvern.admin import sensorwatch


@pytest.fixture
def logs(tmp_path, monkeypatch):
    monkeypatch.setattr(sensorwatch, "_log_dir", lambda: tmp_path)
    return tmp_path


def _write(d: Path, name: str, age_s: float, body: str = "") -> Path:
    p = d / name
    p.write_text(body)
    stamp = time.time() - age_s
    os.utime(p, (stamp, stamp))
    return p


# ── liveness ────────────────────────────────────────────────────────────────────


def test_a_recent_log_means_the_sensor_is_alive(logs):
    _write(logs, "conn.log", 2.0)
    assert sensorwatch.newest_activity()[1] < 5
    assert sensorwatch.observe()["running"] is True


def test_a_stale_log_means_capture_has_stopped(logs):
    _write(logs, "conn.log", sensorwatch.STALE_AFTER_S + 10)
    o = sensorwatch.observe()
    assert o["running"] is False
    assert any("capture has stopped" in f for f in o["failures"])


def test_stats_log_alone_does_NOT_count_as_alive(logs):
    """The trap: stats.log is written on a TIMER, even with no traffic.

    Using it as the liveness signal would report a dead sensor as healthy -- the same
    lie this whole feature exists to prevent.
    """
    _write(logs, "stats.log", 1.0)
    assert sensorwatch.newest_activity() is None
    o = sensorwatch.observe()
    assert o["running"] is False, "stats.log alone was treated as proof of capture"
    assert o["failures"]


def test_any_single_liveness_log_is_enough(logs):
    """A quiet segment with only DNS still means the sensor is capturing.

    Requiring conn.log specifically would report a healthy sensor as dead.
    """
    _write(logs, "dns.log", 1.0)
    assert sensorwatch.observe()["running"] is True


def test_the_newest_wins_across_log_types(logs):
    _write(logs, "conn.log", 300.0)
    _write(logs, "http.log", 3.0)
    name, age = sensorwatch.newest_activity()
    assert name == "http.log"
    assert age < 10


def test_a_missing_log_directory_is_reported_not_crashed(tmp_path, monkeypatch):
    monkeypatch.setattr(sensorwatch, "_log_dir", lambda: tmp_path / "nope")
    o = sensorwatch.observe()
    assert o["running"] is False
    assert any("not capturing" in f for f in o["failures"])


# ── capture loss ────────────────────────────────────────────────────────────────


def _loss_log(percent: float) -> str:
    return ("#separator \\x09\n"
            "#fields\tts\tts_delta\tpeer\tgaps\tacks\tpercent_lost\n"
            f"1789701537.0\t900.09\tzeek\t0\t0\t{percent}\n")


def test_capture_loss_is_read_from_the_column_named_percent_lost(logs):
    """Read by NAME, not position.

    Zeek field order is not fixed across versions and log types, so an index would silently
    read a different column after an upgrade -- reporting 0.0 loss forever.
    """
    _write(logs, "capture_loss.log", 1.0, _loss_log(62.5))
    assert sensorwatch.capture_loss() == pytest.approx(62.5)


def test_unavailable_loss_is_None_not_zero(logs):
    """"No loss data" and "no loss" are different facts.

    Reporting 0.0 for the first hides a broken sensor behind a healthy-looking number.
    """
    assert sensorwatch.capture_loss() is None
    assert sensorwatch.capture_loss() != 0.0


def test_high_loss_is_surfaced_as_a_failure_with_the_reason(logs):
    _write(logs, "conn.log", 1.0)
    _write(logs, "capture_loss.log", 1.0, _loss_log(62.0))
    o = sensorwatch.observe()
    assert any("capture loss" in f for f in o["failures"])
    # The explanation must name the actual cause, not just the symptom.
    msg = " ".join(o["failures"])
    assert "veth" in msg or "SPAN" in msg or "mirror" in msg


def test_low_loss_is_not_reported(logs):
    _write(logs, "conn.log", 1.0)
    _write(logs, "capture_loss.log", 1.0, _loss_log(0.0))
    assert not any("capture loss" in f for f in sensorwatch.observe()["failures"])


# ── the configured/observed distinction ─────────────────────────────────────────


def test_weir_is_reported_as_not_running_by_the_observer(logs):
    """The observer cannot see an intercept, so it must not claim one is active.

    A configured SENSOR_MODE=weir says what was INTENDED and survives the intercept dying.
    A real intercept publishes its own heartbeat with the authoritative values; this path
    reporting running=True from the config would be the configured-vs-actual error again.
    """
    _write(logs, "conn.log", 1.0)
    monkeypatch_env = pytest.MonkeyPatch()
    monkeypatch_env.setenv("SENSOR_MODE", "weir")
    try:
        o = sensorwatch.observe()
        assert o["mode"] == "weir"
        # The log files ARE fresh (Zeek is running), so running reflects capture -- but the
        # fields that only a real intercept can know must stay empty rather than invented.
        assert o["mappings"] == 0
        assert o["restores"] == 0
        assert o["segment"] == ""
    finally:
        monkeypatch_env.undo()


def test_the_mode_reported_is_the_configured_one(logs, monkeypatch):
    monkeypatch.setenv("SENSOR_MODE", "loch")
    assert sensorwatch.observe()["mode"] == "loch"


def test_observe_always_returns_every_field(logs):
    """So the payload shape never varies, matching sensor_status's contract."""
    o = sensorwatch.observe()
    for key in ("mode", "iface", "segment", "hosts", "mappings", "running",
                "uptime_s", "restores", "refreshes", "failures"):
        assert key in o, f"{key} missing -- a varying shape breaks a consumer"


def test_the_worker_publishes_the_heartbeat():
    """The wiring itself: an observation nothing writes is a feature nobody can see."""
    src = (Path(__file__).resolve().parents[1] / "weirvern" / "worker.py").read_text()
    assert "sensorwatch" in src, "the worker never observes the sensor"
    assert "status.heartbeat" in src, "the worker observes but never publishes"
    # It must be guarded: a monitoring failure must not stop detection.
    idx = src.index("status.heartbeat")
    window = src[max(0, idx - 900):idx + 400]
    assert "except Exception" in window, (
        "the heartbeat is not wrapped, so a monitoring failure would break the worker's "
        "detection loop"
    )


def test_the_heartbeat_interval_is_much_shorter_than_the_detection_interval():
    """Coupling them would make a healthy sensor look dead.

    sensor_status treats a heartbeat older than 45s as not-running, while detection runs
    every 300s. Publishing the heartbeat from the detection loop therefore meant a healthy
    sensor was reported as STOPPED for four and a half minutes out of every five -- a panel
    that is permanently wrong, which is worse than one that is empty.
    """
    from weirvern.admin import status
    from weirvern.config import Settings

    s = Settings()
    assert s.heartbeat_interval_s < status.HEARTBEAT_STALE_S, (
        f"the heartbeat interval ({s.heartbeat_interval_s}s) must be shorter than the "
        f"staleness threshold ({status.HEARTBEAT_STALE_S}s), or every beat arrives already "
        f"expired"
    )
    assert s.heartbeat_interval_s < s.detect_interval_s, (
        "the heartbeat must not be tied to the detection interval"
    )
    # Enough margin that one missed beat does not report a dead sensor.
    assert status.HEARTBEAT_STALE_S >= s.heartbeat_interval_s * 2, (
        "the staleness threshold must tolerate at least one missed heartbeat"
    )


def test_the_heartbeat_runs_in_its_own_thread():
    """Structural: it must not be inside the detection loop."""
    src = (Path(__file__).resolve().parents[1] / "weirvern" / "worker.py").read_text()
    assert "_heartbeat_thread" in src
    assert 'name="sensor-heartbeat"' in src, "the heartbeat thread is not started"
    # The detection loop must NOT call heartbeat directly any more.
    loop = src[src.index("while not _stop.is_set():"):]
    assert "status.heartbeat" not in loop, (
        "status.heartbeat is still called from the detection loop, so the heartbeat's "
        "interval is the detection interval and the sensor will look dead between cycles"
    )
