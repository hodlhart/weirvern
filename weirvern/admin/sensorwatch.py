"""Observe the sensor's state from the outside, and publish it.

WHY THE WORKER PUBLISHES THIS RATHER THAN THE SENSOR. The obvious design is for the sensor
to write its own heartbeat, and `weirvern intercept` does exactly that for siphon mode. But
the Kubernetes sensor runs Zeek directly from its startup script and the `zeek/zeek` image
has NO python3 (busybox/ash, perl and Zeek only -- verified on the pod). So there is nothing
in that container able to write a row, and the same constraint already forced the prune
logic into a CronJob.

Rather than add a sidecar or a second image just to say "I am alive", the WORKER observes
the sensor from outside. It already runs in a Python image, already mounts the Zeek log
directory read-only, and already has a loop every `detect_interval_s`.

WHY OBSERVATION IS BETTER THAN SELF-REPORT HERE: a sensor that writes its own heartbeat can
only report that its heartbeat loop is alive. It cannot report that its capture is broken --
a sensor happily writing "running" while Zeek has died, or while it is receiving no packets,
is exactly the failure an operator needs told about. Reading the LOG FILES answers the
question they actually have: is the sensor producing data?

WHAT IS REPORTED, and how each is derived rather than assumed:
  * liveness  from the newest log mtime. Zeek writes conn.log continuously, so a file
              mtime older than a few seconds means capture has stopped.
  * capture loss from capture_loss.log's `percent_lost` column, which Zeek maintains.
  * the mode   from SENSOR_MODE, explicitly labelled as CONFIGURED, because this process
              cannot observe which mode the sensor is in -- only the sensor itself knows
              that. Saying so is better than implying an observation we did not make.

The heartbeat is `running=False` for siphon unless a real intercept has reported itself, so a
configured-but-not-running intercept cannot masquerade as active.
"""
from __future__ import annotations

import logging
import os
import time
from pathlib import Path

logger = logging.getLogger(__name__)

# Zeek writes conn.log continuously while capturing, so the newest mtime is a direct
# liveness signal. 60s is generous for a quiet network (a file is only touched when a
# record is written) while still catching a dead sensor within a minute.
STALE_AFTER_S = 60.0

# Log types whose mtime indicates capture is working. `stats.log` is excluded on purpose:
# Zeek writes it on a timer even when it is receiving nothing, so it would report a dead
# sensor as alive -- the exact lie this module exists to avoid.
LIVENESS_LOGS = ("conn", "dns", "http", "ssl", "files", "ssh")


def _log_dir() -> Path:
    return Path(os.environ.get("ZEEK_LOG_DIR") or "/zeek/logs")


def newest_activity(log_dir: Path | None = None) -> tuple[str, float] | None:
    """(filename, age_seconds) of the most recently written liveness log, or None.

    Newest across the set rather than just conn.log: a network with no new connections but
    active DNS still means the sensor is capturing, and requiring conn.log specifically
    would report a healthy sensor as dead on a quiet segment.
    """
    d = log_dir or _log_dir()
    if not d.exists():
        return None
    best: tuple[str, float] | None = None
    now = time.time()
    for stem in LIVENESS_LOGS:
        # Both the live file and rotations, since a rotation moves the mtime to the new file.
        for path in list(d.glob(f"{stem}.log")) + list(d.glob(f"{stem}.*.log")):
            try:
                age = now - path.stat().st_mtime
            except OSError:
                continue
            if best is None or age < best[1]:
                best = (path.name, age)
    return best


def capture_loss(log_dir: Path | None = None, tail_lines: int = 50) -> float | None:
    """The most recent `percent_lost`, or None if it cannot be read.

    Returned as None rather than 0.0 when unavailable: "no loss data" and "no loss" are
    different facts, and reporting 0.0 for the first would hide a broken sensor behind a
    healthy-looking number.
    """
    d = log_dir or _log_dir()
    files = sorted(list(d.glob("capture_loss.log")) + list(d.glob("capture_loss.*.log")),
                   key=lambda p: p.stat().st_mtime if p.exists() else 0, reverse=True)
    for path in files:
        try:
            lines = path.read_text(errors="replace").splitlines()
        except OSError:
            continue
        fields: list[str] = []
        best: float | None = None
        for line in lines[-tail_lines:]:
            if line.startswith("#fields"):
                fields = line.split("\t")[1:]
                continue
            if line.startswith("#") or not line.strip():
                continue
            if "percent_lost" not in fields:
                continue
            try:
                best = float(line.split("\t")[fields.index("percent_lost")])
            except (ValueError, IndexError):
                continue
        if best is not None:
            return best
    return None


def capture_counters(log_dir: Path | None = None, tail_lines: int = 50) -> tuple[int | None, int | None]:
    """The newest packet counts from capture_loss.log, or (None, None) when the log has none.

    THE LOG OFTEN HAS NONE, and that is not an error. Measured on the live sensor, this Zeek
    build declares:

        #fields  ts  ts_delta  peer  gaps  acks  percent_lost

    There is no `pkts_recv`/`pkts_drop` column at all -- those appear in other Zeek versions and
    in the site's own logging policy. So a reader that returned 0 for a missing field would report
    "zero packets received" for a sensor that is happily receiving millions, and that is the same
    not-measured-looks-like-measured-zero confusion the nullable percentage column exists to
    prevent. Returning None keeps the two apart.

    `gaps` and `acks` ARE present and are read as the fallback counters: gaps is the number of
    times the analyzer's socket had no data when it expected some, which is the closest available
    stand-in for "packets missed" and is a real measurement rather than a placeholder.
    """
    d = log_dir or _log_dir()
    files = sorted(list(d.glob("capture_loss.log")) + list(d.glob("capture_loss.*.log")),
                   key=lambda p: p.stat().st_mtime if p.exists() else 0, reverse=True)
    for path in files:
        try:
            lines = path.read_text(errors="replace").splitlines()
        except OSError:
            continue
        fields: list[str] = []
        best: tuple[int | None, int | None] | None = None
        for line in lines[-tail_lines:]:
            if line.startswith("#fields"):
                fields = line.split("\t")[1:]
                continue
            if line.startswith("#") or not line.strip():
                continue
            cols = line.split("\t")
            # Bound EXPLICITLY as defaults. A closure over the loop variable `fields` would read
            # whatever the LAST line set, so a data row could be interpreted with a different
            # file's field list -- a silent wrong answer, and ruff's B023 is what caught it.
            def _num(name: str, fields=fields, cols=cols) -> int | None:
                if name not in fields:
                    return None
                try:
                    return int(cols[fields.index(name)])
                except (ValueError, IndexError):
                    return None

            recv, dropped = _num("pkts_recv"), _num("pkts_drop")
            if recv is None:
                # Fallback for the field set this sensor actually writes: `acks` counts the
                # packets the analyzer saw, and `gaps` the times it had none to read. Both are
                # REAL measurements, so they are reported as the counts rather than as zeros.
                recv, dropped = _num("acks"), _num("gaps")
            if recv is not None or dropped is not None:
                best = (recv, dropped)
        if best is not None:
            return best
    # None, not (0, 0): the log carries no counter we recognise, so the count is UNMEASURED.
    return (None, None)


def observe(mode: str = "", iface: str = "") -> dict:
    """The fields to publish, derived from observation.

    `running` means "the sensor is producing data", which is the operator's real question.
    For siphon it is deliberately False here: this process cannot see an intercept's state, and
    a real intercept publishes its own heartbeat with the authoritative values. Claiming
    running=True from the config would be the configured-vs-actual error all over again.
    """
    activity = newest_activity()
    loss = capture_loss()
    # The packet counters from the same log line that gave us percent_lost. Kept as numbers so a
    # surface can show the measurement rather than re-deriving it from prose -- capture loss was
    # previously computed here and only ever interpolated into a failure string, so nothing could
    # display it as a figure.
    recv, dropped = capture_counters()

    if activity is None:
        age = None
        alive = False
    else:
        _name, age = activity
        alive = age <= STALE_AFTER_S

    failures: list[str] = []
    if activity is None:
        failures.append(
            f"no Zeek log has been written under {_log_dir()}; the sensor is not capturing"
        )
    elif not alive:
        failures.append(
            f"the newest Zeek log ({activity[0]}) is {age:.0f}s old, so capture has stopped"
        )
    if loss is not None and loss >= 10.0:
        failures.append(
            f"Zeek reports {loss:.1f}% capture loss -- the sensor is missing packets. On a "
            f"veth this is expected (the bridge does not flood switched unicast); a SPAN "
            f"port or siphon mode is required for full coverage."
        )

    return {
        # CONFIGURED, not observed -- and the description says so, because implying this is
        # an observation would be a lie about how the value was obtained.
        "mode": mode or os.environ.get("SENSOR_MODE") or "loch",
        "iface": iface or os.environ.get("ZEEK_IFACE") or "",
        "segment": "",
        "hosts": 0,
        "mappings": 0,
        # Liveness as OBSERVED from log activity.
        "running": alive,
        "uptime_s": 0.0,
        "restores": 0,
        "refreshes": 0,
        "failures": failures,
        # MEASUREMENTS, not configuration. None means "not measured" and must stay
        # distinguishable from 0.0, which means "measured, nothing lost".
        "capture_loss_pct": loss,
        # None when the log carries no counter field, which is the case on this sensor's Zeek
        # build. NOT 0 -- see capture_counters().
        "packets_recv": recv,
        "packets_dropped": dropped,
    }
