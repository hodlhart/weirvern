"""THE SENSOR UNIT'S HEARTBEAT — one capture port, one identity, reportable.

WHAT THIS IS. A "sensor unit" runs beside a capture process (Zeek) on one NIC and reports what
it is doing into the hub's database under ITS OWN sensor id. It exists so a sensor can be RUN
MORE THAN ONCE — on another box, or twice on one box on two NICs — which the single-deployment
model could not express: a deployment's worker reports for exactly one sensor identity, and a
second sensor had nowhere to say "I am here, this is my port, this is my loss".

WHY IT OBSERVES RATHER THAN SELF-REPORTS. Same reasoning as `sensorwatch`'s docstring, and the
same code: the question an operator has is "is this sensor producing data", and the answer
lives in the log files, not in this loop's own aliveness. `sensorwatch.observe()` derives every
field from the logs (newest log mtime = capturing; Zeek's own `capture_loss.log` = loss and
packet counters); this module is the thin publisher around it, so the two cannot drift, and
`None` stays "not measured" rather than becoming a fake 0.0.

THE MANAGEMENT NIC IS NEVER A CAPTURE PORT (Samuel's standing rule, stated twice). A `ZEEK_IFACE`
equal to the default-route interface is a REFUSAL, not a warning: sensing on the management path
mixes the operator's own control traffic into the record and points the capture at the one NIC
whose loss nobody wants. The check reuses the product's own probe (`interfaces.probe_local()`
-- the same program `weirvern interfaces` runs) so what counts as an allowed capture port
cannot drift into a second opinion here.

ENV CONTRACT (set by the unit manifest, checked here):
  SENSOR_ID    required — the fleet identity. Explicit, because a unit's whole point is that
               several can exist; a default would silently collapse them into one row.
  ZEEK_IFACE   required — the capture port this unit owns.
  ZEEK_LOG_DIR the capture's log directory (default /zeek/logs), mounted read-only.
  CLICKHOUSE_* via the ordinary Settings env, so it reaches the hub database the same way
               every other component does.

ANY SENSOR CAN ALSO RECEIVE NETFLOW, if enabled:  WEIRLING_NETFLOW=1 starts a second thread that
tails what a LOCAL collector (goflow2, the same image and the same arguments the hub runs) wrote
and inserts it into the hub's `flows` table. WEIRLING_FLOW_FILE names that file (default
/flows/flows.jsonl); an exporter on that segment then has somewhere to send, without an exporter on
the hub's own segment and without a second transport to secure. See _flow_shipper.
"""
from __future__ import annotations

import logging
import os
import signal
import threading

from weirvern import db
from weirvern.config import get_settings

logger = logging.getLogger("weirvern.sensor_agent")

DEFAULT_INTERVAL_S = 15
FLOW_SHIP_INTERVAL_S = 5.0


def flow_shipping_enabled() -> bool:
    """Whether this unit should ship a local collector's records into the hub.

    ONE ENV VAR, because the alternative -- a second transport, a broker, an API key per sensor --
    would be a second thing to secure and a second definition of what a flow row is. The collector
    on this box speaks goflow2's JSON; the INGESTER already knows how to read it, keep a byte cursor
    across restarts, and drop the records the operator excluded. So the shipping half is that code
    run here, and a row written from a unit is the row the hub writes for its own collector.
    """
    return str(os.environ.get("WEIRLING_NETFLOW", "")).strip().lower() in ("1", "true", "yes", "on")


def flow_file() -> str:
    return os.environ.get("WEIRLING_FLOW_FILE", "/flows/flows.jsonl")


def ship_flows_once(client, *, path: str = "", state=None, allow: str = "") -> int:
    """One shipping pass. Returns the rows the collector wrote since the cursor.

    A missing file is NOT an error: a unit whose collector has never seen an exporter has nothing
    to ship, which is the normal state of a sensor nobody points NetFlow at yet.
    """
    from weirvern import ingester as ingester_mod  # noqa: PLC0415

    path = path or flow_file()
    if state is None:
        state = ingester_mod.load_tail_state(path)
    if not os.path.exists(path):
        return 0
    read, _offset, _inode = ingester_mod.tail_and_insert(client, path, state=state, allow=allow)
    ingester_mod.save_tail_state(path, state)
    return int(read or 0)


def _flow_shipper(settings, stop: threading.Event) -> None:
    """The thread: its OWN connection, its own retries, and no way to hurt the heartbeat.

    WHAT THIS MUST NEVER DO IS TAKE THE HEARTBEAT DOWN. The heartbeat is the unit's liveness -- it
    is how the fleet view knows this sensor exists. Flow shipping is a convenience on top, so it
    runs on a separate thread with its own client, and every failure is a log line and a retry.
    """
    client = None
    allow = str(getattr(settings, "exporter_allow", "") or "")
    logger.info("netflow: enabled -- shipping %s into the hub's flows table", flow_file())
    while not stop.is_set():
        try:
            if client is None:
                client = db.connect(settings, retries=1, delay_s=2)
            ship_flows_once(client, allow=allow)
        except Exception as exc:  # noqa: BLE001
            logger.warning("netflow: shipping pass failed: %s", exc)
            client = None
        stop.wait(FLOW_SHIP_INTERVAL_S)


def required_iface() -> str:
    """ZEEK_IFACE, or refuse: a unit without its capture port is a unit without a job."""
    iface = (os.environ.get("ZEEK_IFACE") or "").strip()
    if not iface:
        raise SystemExit(
            "sensor unit: ZEEK_IFACE is required -- which NIC does this unit capture?"
        )
    return iface


def capture_port_check(iface: str) -> str:
    """Prove the capture port exists and is NOT the management NIC. Returns the port.

    Raises SystemExit when the port cannot be used. Reuses `probe_local()` -- the product's
    own probe for this host, the same program `weirvern interfaces` runs -- so what counts as
    a capture port cannot drift into a second opinion here.

    WHY THE FULL VERDICT IS ADVISORY, NOT A SECOND REFUSAL: inside a container (this
    project's test box is an LXC) every port reads as 'virtual', and often as a bridge
    member -- the measured caveat the product's own interface guidance already documents --
    so the verdict is logged for the operator while the HARD rules stay: the port must
    exist, and it must never be the default-route (management) NIC.
    """
    from weirvern.admin.interfaces import probe_local, validate_capture_iface  # noqa: PLC0415

    probe = probe_local()
    if probe.error:
        # AN UNKNOWN refuses: a capture we cannot prove is off the management path must not
        # start; the operator can fix the probe or point the unit at another port.
        raise SystemExit(
            f"sensor unit: could not probe this host's interfaces ({probe.error}); refusing "
            f"to capture on {iface!r} without proving it is not the management port"
        )
    info = probe.by_name(iface)
    if info is None:
        names = ", ".join(sorted(i.name for i in probe.interfaces)) or "none"
        raise SystemExit(
            f"sensor unit: {iface!r} does not exist on this host; interfaces present: {names}"
        )
    if info.is_default_route:
        raise SystemExit(
            f"sensor unit: REFUSING to capture on {iface!r} -- it carries the default route, "
            f"which is the management path. Point the unit at a dedicated capture port."
        )
    try:
        verdict = validate_capture_iface(probe, iface, mgmt_iface=probe.default_route_iface)
        logger.info("capture port verdict: %s", verdict.summary())
        for msg in (verdict.fatal + verdict.warnings + verdict.notes):
            logger.info("  %s", msg)
    except Exception as exc:  # noqa: BLE001
        logger.info("capture port verdict unavailable: %s", exc)
    return iface


def sensor_identity() -> str:
    """SENSOR_ID, or refuse. Explicit because several units can exist; a fallback would
    collapse them into one fleet row."""
    sid = (os.environ.get("SENSOR_ID") or "").strip()
    if not sid:
        raise SystemExit(
            "sensor unit: SENSOR_ID is required -- it is what tells multiple sensors "
            "(and multiple units on one host) apart in the fleet."
        )
    return sid


def beat(client, sid: str, iface: str) -> bool:
    """One heartbeat from observation. Never raises; returns whether it landed."""
    from weirvern.admin import sensorwatch, status  # noqa: PLC0415

    fields = sensorwatch.observe(mode="loch", iface=iface)
    # THE WEIRLING AGENTS' OWN PATH (measured missing on the box, 2026-10-17: their rows
    # carried [] while the hub's carried its NICs -- this call site predated the column).
    fields.setdefault("interfaces", status.sensor_interfaces())
    return status.heartbeat(client, sensor_id=sid, **fields)


def _final_beat(client, sid: str, iface: str) -> None:
    """A last row saying running=False, so the fleet reads "stopped cleanly" immediately
    instead of "stale" minutes later. Best-effort: a kill -9 gets no such courtesy and
    staleness covers it."""
    try:
        from weirvern.admin import sensorwatch, status  # noqa: PLC0415

        fields = sensorwatch.observe(mode="loch", iface=iface)
        fields["running"] = False
        fields.setdefault("interfaces", status.sensor_interfaces())
        status.heartbeat(client, sensor_id=sid, **fields)
    except Exception:  # noqa: BLE001
        pass


def main() -> None:
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")
    iface = required_iface()
    capture_port_check(iface)
    sid = sensor_identity()
    settings = get_settings()
    interval = max(5, int(getattr(settings, "heartbeat_interval_s", DEFAULT_INTERVAL_S)))

    stop = threading.Event()

    def _term(_signum, _frame):
        stop.set()

    signal.signal(signal.SIGTERM, _term)
    signal.signal(signal.SIGINT, _term)

    logger.info("sensor unit %r: heartbeat every %ds, observing %s on %s",
                sid, interval, os.environ.get("ZEEK_LOG_DIR") or "/zeek/logs", iface)

    if flow_shipping_enabled():
        threading.Thread(target=_flow_shipper, args=(settings, stop), daemon=True,
                         name="netflow-shipper").start()
    else:
        logger.info("netflow: not enabled on this unit (WEIRLING_NETFLOW is unset) -- an exporter "
                    "here has nowhere to land")

    client = None
    while not stop.is_set():
        try:
            if client is None:
                client = db.connect(settings, retries=1, delay_s=2)
            if not beat(client, sid, iface):
                # The write failed; drop the client so the next cycle reconnects rather than
                # hammering a dead connection.
                logger.warning("heartbeat write failed; will reconnect and retry")
                client = None
        except Exception as exc:  # noqa: BLE001
            logger.warning("heartbeat cycle failed: %s", exc)
            client = None
        stop.wait(interval)

    try:
        if client is None:
            client = db.connect(settings, retries=1, delay_s=2)
        _final_beat(client, sid, iface)
    except Exception:  # noqa: BLE001
        pass
    logger.info("sensor unit %r: stopped", sid)


if __name__ == "__main__":
    main()
