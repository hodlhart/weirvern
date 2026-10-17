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


_INTERFACES_CACHE: list[str] | None = None
# Software interfaces are not "a sensor's NICs" to any operator: veth pairs, cni/flannel/docker
# plumbing and bridges are noise on every box that runs containers. Everything else is kept as
# reported -- the sensor's own network namespace is what it can actually see.
_SOFTWARE_IFACE_PREFIXES = ("veth", "cni", "flannel", "docker", "br-", "cali", "tunl", "virbr")


def _sensor_interfaces() -> list[str]:
    """The interfaces this process can see, cached. Never raises: a sensor that cannot
    report its NICs must still capture traffic."""
    global _INTERFACES_CACHE
    if _INTERFACES_CACHE is None:
        try:
            import socket
            names = {name for _, name in socket.if_nameindex()}
            _INTERFACES_CACHE = sorted(n for n in names
                                       if n != "lo" and not n.startswith(_SOFTWARE_IFACE_PREFIXES))
        except Exception:  # noqa: BLE001
            _INTERFACES_CACHE = []
    return _INTERFACES_CACHE


def sensor_id() -> str:
    """A stable name for this sensor -- the SAME precedence `worker._sensor_name` uses.

    MEASURED LIVE (2026-10-17): this read HOSTNAME / gethostname first, and on the deployed hub
    -- a hostNetwork pod -- that is the NODE's hostname, `Weirvern` (capital W: the LXC's own
    `hostname`). Every other writer (the worker's heartbeat, the GUI's gate name, the sluice
    state) derives from NODE_NAME, `weirvern`. One hub therefore produced TWO sensor ids
    differing only in case: fresh rows under `Weirvern` -- an UNDECLARED name, so the fleet
    view grew a phantom unregistered sensor -- while the REGISTERED `weirvern` row read STALE
    for as long as an intercept owned the heartbeat (the worker suppresses its own beat then).
    The operator sees a hub that looks dead beside its own fresh traffic.

    SENSOR_ID first (a deployment that names its sensors), then NODE_NAME (stable across pod
    restarts and equal in every pod on the node -- what the rest of the system uses), then the
    hostname (a non-cluster run, where it IS the box).
    """
    return (os.environ.get("SENSOR_ID") or os.environ.get("NODE_NAME")
            or os.environ.get("HOSTNAME") or socket.gethostname() or "sensor")[:64]


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
        ok = status.heartbeat(self.client, sensor_id=self.sensor_id,
                              interfaces=_sensor_interfaces(), **fields)
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
