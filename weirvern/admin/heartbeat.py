"""Sensor heartbeat: report what the sensor is actually doing.

WHY: the GUI runs in its own pod and cannot see the sensor's filesystem, so it could only
ever show the CONFIGURED mode from the ConfigMap -- a statement of intent, not of reality.
Those differ exactly when it matters: a siphon process that died, or was never started, still
has SENSOR_MODE=siphon in the ConfigMap, so a dashboard reading the config would show
"intercepting N hosts" for a sensor that is not running.

This runs as a small loop beside the capture, in its own thread so a slow ClickHouse never
delays forwarding -- in siphon mode Weirvern is a router, and a heartbeat is never worth a
packet.

EVERY FAILURE HERE IS NON-FATAL. A sensor that cannot report its status must still capture
traffic: the cost of a missing heartbeat is a dashboard saying "unknown", which is
recoverable, while the cost of an exception propagating is a dead sensor.
"""
from __future__ import annotations

import logging
import os
import socket
import threading

from weirvern.admin import status

logger = logging.getLogger(__name__)

DEFAULT_INTERVAL_S = 15


def sensor_id() -> str:
    """A stable name for this sensor. The pod name, which is unique per replica."""
    return (os.environ.get("HOSTNAME") or socket.gethostname() or "sensor")[:64]


class HeartbeatLoop:
    """Writes a heartbeat row every interval, in a background thread.

    `state` is a zero-argument callable returning the fields to publish, so the loop does
    not need to know about Intercept or Settings -- the caller decides what "current"
    means, and this stays testable without either.
    """

    def __init__(self, client, state, interval_s: float = DEFAULT_INTERVAL_S,
                 name: str | None = None) -> None:
        self.client = client
        self.state = state
        self.interval_s = interval_s
        self.sensor_id = name or sensor_id()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.writes = 0
        self.failures = 0

    def beat(self) -> bool:
        """Write one heartbeat. Returns whether it landed. Never raises."""
        try:
            fields = dict(self.state() or {})
        except Exception as exc:  # noqa: BLE001
            logger.debug("heartbeat state unavailable: %s", exc)
            self.failures += 1
            return False
        ok = status.heartbeat(self.client, sensor_id=self.sensor_id, **fields)
        if ok:
            self.writes += 1
        else:
            self.failures += 1
        return ok

    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(target=self._run, name="weirvern-heartbeat",
                                        daemon=True)
        self._thread.start()

    def _run(self) -> None:
        # Beat immediately, so a freshly started sensor appears without waiting an
        # interval -- otherwise a short-lived test run never reports at all and looks
        # like it never started.
        while not self._stop.is_set():
            self.beat()
            self._stop.wait(self.interval_s)

    def stop(self, final: bool = True) -> None:
        """Stop beating. Optionally write a last 'not running' beat.

        The final beat matters: it lets the dashboard distinguish "stopped cleanly a minute
        ago" from "vanished". Staleness would eventually say the same thing, but the
        operator gets the truth immediately rather than after three intervals.
        """
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None
        if final:
            try:
                fields = dict(self.state() or {})
                fields["running"] = False
                status.heartbeat(self.client, sensor_id=self.sensor_id, **fields)
            except Exception:  # noqa: BLE001
                pass
