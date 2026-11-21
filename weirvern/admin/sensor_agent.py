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

A UNIT CAN ALSO BE IN-PATH (siphon), SUPERVISED FROM ITS OWN DEPLOYMENT. Its mode and plan live in
ITS OWN registry row (see fleet.SensorPlan and 020_weirling_plan.sql): this loop reads its own row
and drives the SAME `SiphonSupervisor` the hub's worker runs -- same `weirvern intercept` child,
same fail-open watchdog, same bounded runs and self-destruct deadline, same capability gate -- so
the safety contract cannot fork between the hub's sensor and a weirling's. The mode this unit runs
is NEVER the hub's `SENSOR_MODE` (which describes the hub's own sensor): one plan per sensor is the
entire point, and an env var inherited through `envFrom` is exactly the leak that would defeat it.
"""
from __future__ import annotations

import contextlib
import json
import logging
import os
import signal
import threading
import time
from datetime import UTC, datetime
from functools import partial
from pathlib import Path
from typing import Any

from weirvern import db
from weirvern.config import get_settings

logger = logging.getLogger("weirvern.sensor_agent")

DEFAULT_INTERVAL_S = 15
FLOW_SHIP_INTERVAL_S = 5.0


def trunk_state_dir() -> str:
    return (os.environ.get("TRUNK_STATE_DIR") or "/run/weirvern/trunk").strip()


def host_stats() -> str:
    """A compact CPU/memory reading for the fleet row, or '' when this host cannot be read.

    The remote agent runs in its own container but hostNetwork; `/proc` is the node's view on
    this deployment, and the empty string is the honest "not measured" answer if it is not.
    The UI must render an empty value as a dash, never 0%.
    """
    try:
        from weirvern.admin import system_metrics  # noqa: PLC0415

        sample = system_metrics.sample()
        payload = {
            "cpu_pct": sample.get("cpu_percent"),
            "mem_pct": sample.get("memory_percent"),
            "mem_total_bytes": sample.get("memory_total_bytes"),
            "mem_used_bytes": sample.get("memory_used_bytes"),
            "scope": "sensor",
            "proc_root": str(system_metrics.proc_root()),
        }
        return json.dumps(payload, separators=(",", ":"))
    except Exception:  # noqa: BLE001 -- host stats are optional evidence
        return ""


def sync_trunk(iface: str) -> None:
    """Adapt this unit to an access port or a trunk, as the port actually is.

    THE DEFAULT IS THE ADAPTIVE PATH, NOT A MODE. Sonar's observation already records every
    802.1Q tag it sees; `trunk.sync` turns those tags into host VLAN devices when they exist,
    and records the parent alone when they do not. It never changes the configured parent:
    the heartbeat keeps naming the port the unit was installed on, while `interfaces` reports
    the real devices this process can see.
    """
    if str(os.environ.get("TRUNK_DISABLE", "")).strip().lower() in ("1", "true", "yes", "on"):
        logger.info("trunk: disabled on this unit (bridge/--no-trunk topology)")
        return
    try:
        from weirvern.admin import trunk  # noqa: PLC0415

        state = trunk.sync(iface, state_dir=trunk_state_dir(),
                           seconds=float(os.environ.get("TRUNK_DETECT_S", trunk.DEFAULT_WATCH_S)))
        if state.error:
            logger.warning("trunk: %s", state.error)
        elif state.vlans:
            logger.info("trunk: %s carries VLANs %s -> capture ports %s",
                        iface, ",".join(map(str, state.vlans)), ", ".join(state.ifaces))
        else:
            logger.info("trunk: no VLAN tags observed on %s; using the parent port", iface)
    except Exception as exc:  # noqa: BLE001 -- a trunk probe must not take the unit down
        logger.warning("trunk: probe failed on %s: %s", iface, exc)



def gateway_client():
    """The mTLS transport when this unit was adopted through the gateway, else None.

    THE ABSENCE OF THE URL IS THE SWITCH. Existing units keep their ClickHouse client
    untouched; a unit that has WEIRLING_GATEWAY_URL must have a certificate and key,
    because silently falling back to a database credential would defeat the adoption.
    """
    url = (os.environ.get("WEIRLING_GATEWAY_URL") or "").strip()
    if not url:
        return None
    cert = (os.environ.get("WEIRLING_CLIENT_CERT") or "").strip()
    key = (os.environ.get("WEIRLING_CLIENT_KEY") or "").strip()
    ca = (os.environ.get("WEIRLING_ROOT_CA") or "").strip()
    if not cert or not key or not ca:
        raise SystemExit(
            "sensor unit: WEIRLING_GATEWAY_URL is set but WEIRLING_CLIENT_CERT, "
            "WEIRLING_CLIENT_KEY or WEIRLING_ROOT_CA is missing -- refusing to fall "
            "back to a database credential"
        )
    from weirvern.weirling_client import GatewayClient  # noqa: PLC0415

    return GatewayClient(url, cert, key, ca)


class SensorTransportError(RuntimeError):
    """No authenticated transport to the hub: the unit has nothing it may talk to."""


def _no_transport_message() -> str:
    return (
        "sensor unit: no WEIRLING_GATEWAY_URL (or the certificate it names is missing), so this "
        "unit has no authenticated way to reach the hub. Every hub/weirling message crosses the "
        "mTLS gateway: enroll this sensor with "
        "`weirvern weirlings token --sensor-id <id>` on the hub and "
        "`python -m weirvern.weirling_client enroll --hub <gateway> --token <token> "
        "--sensor-id <id> --dir <pki>` on this box, then set WEIRLING_GATEWAY_URL, "
        "WEIRLING_CLIENT_CERT, WEIRLING_CLIENT_KEY and WEIRLING_ROOT_CA. A unit that cannot prove "
        "who it is does not report, and it does not fall back to the database."
    )


def _direct_clickhouse_allowed() -> bool:
    return str(os.environ.get("WEIRLING_ALLOW_DIRECT_CLICKHOUSE", "")).strip().lower() in (
        "1", "true", "yes", "on")


def require_transport() -> None:
    """Refuse to start a unit that cannot authenticate to the hub.

    Called once from `main` so the failure is immediate and legible, instead of a unit that runs
    forever and reports nothing because every write is refused.
    """
    if gateway_client() is not None:
        return
    if _direct_clickhouse_allowed():
        logger.warning(
            "heartbeat/netflow/zeek: talking to ClickHouse DIRECTLY because "
            "WEIRLING_ALLOW_DIRECT_CLICKHOUSE is set. This is the lab escape, not a deployment: "
            "the unit is holding the hub's database credential, which mTLS exists to avoid."
        )
        return
    raise SystemExit(_no_transport_message())


def connect(settings):
    """One transport for this unit: mTLS, always.

    ── EVERY HUB↔WEIRLING MESSAGE CROSSES THE mTLS GATEWAY (operator rule, 2026-11-17) ──────────

    "the hub is the command and control server, the weirling is the sensor" and "all communication
    between hub and weirling uses mtls". A sensor that holds the hub database's password is not a
    sensor, it is a database client that happens to capture: the credential outlives the sensor,
    every unit needs its own copy of it, and revoking a sensor means rotating a password for
    everything else. So the fallback to ClickHouse is GONE for units -- heartbeats, plans, flow
    records, Zeek records and gate rules all travel over the authenticated gateway under the unit's
    own certificate, which is revocable one unit at a time.

    THE ESCAPE IS DELIBERATELY UGLY AND OFF BY DEFAULT. `WEIRLING_ALLOW_DIRECT_CLICKHOUSE=1` exists
    for a lab box with no gateway running yet, prints a warning on every pass, and is never set by
    any manifest this repo ships. `deploy-weirling.sh --legacy-clickhouse` writes it into the same
    file that carries the credential it justifies.

    RAISES A RUNTIME ERROR, not SystemExit, so a caller with its own retry loop (the flow shipper)
    can log and try again without killing the heartbeat thread.
    """
    gateway = gateway_client()
    if gateway is not None:
        return gateway
    if _direct_clickhouse_allowed():
        logger.warning(
            "netflow/heartbeat: talking to ClickHouse DIRECTLY because "
            "WEIRLING_ALLOW_DIRECT_CLICKHOUSE is set. This is the lab escape, not a deployment: "
            "the unit is holding the hub's database credential, which mTLS exists to avoid."
        )
        return db.connect(settings, retries=1, delay_s=2)
    raise SensorTransportError(_no_transport_message())


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


def _ship_flows_gateway(client, *, path: str = "", state=None) -> int:
    """Read complete goflow2 JSONL lines and POST them to the gateway.

    The cursor is advanced only after the POST succeeds, so a failed upload retries the
    same records instead of losing them. The gateway maps and filters them exactly as the
    hub's own ingester does.
    """
    import json as _json  # noqa: PLC0415

    from weirvern import ingester as ingester_mod  # noqa: PLC0415

    path = path or flow_file()
    if state is None:
        state = ingester_mod.load_tail_state(path)
    if not os.path.exists(path):
        return 0
    st = os.stat(path)
    why = state.reset_reason(st, path)
    start = 0 if why else state.offset
    with open(path, "rb") as fh:
        fh.seek(start)
        raw = fh.read()
    end = start + len(raw)
    # A trailing line without a newline is a write in progress; leave it for the next pass.
    if raw and not raw.endswith(b"\n"):
        cut = raw.rfind(b"\n") + 1
        raw = raw[:cut]
        end = start + cut
    records = []
    for line in raw.decode("utf-8", "replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = _json.loads(line)
        except ValueError:
            continue
        if isinstance(row, dict):
            records.append(row)
    inserted = client.send_flows(records) if records else 0
    state.note_read(st, end)
    ingester_mod.save_tail_state(path, state)
    return int(inserted)


RENEW_CHECK_S = 6 * 3600.0
RENEW_BEFORE_DAYS = 30
ZEEK_SHIP_INTERVAL_S = 5.0
ZEEK_SHIP_BATCH = 500


def zeek_log_dir() -> str:
    return (os.environ.get("ZEEK_LOG_DIR") or "/zeek/logs").strip()


def zeek_ship_state_path() -> str:
    return (os.environ.get("WEIRLING_ZEEK_STATE")
            or os.path.join(trunk_state_dir(), "zeek-offsets.json"))


def _load_zeek_offsets(path: str) -> dict:
    try:
        data = json.loads(Path(path).read_text())
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _save_zeek_offsets(path: str, state: dict) -> None:
    try:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        tmp = Path(path).with_name(Path(path).name + ".tmp")
        tmp.write_text(json.dumps(state, sort_keys=True))
        os.replace(tmp, path)
    except OSError:
        pass


def _parse_zeek_chunk(path: str, *, offset: int, fields: list[str], separator: str,
                     limit: int = ZEEK_SHIP_BATCH) -> tuple[list[dict], int, list[str], str]:
    """Read complete records from a Zeek TSV log, preserving the header for a mid-file resume."""
    from weirvern import ingester  # noqa: PLC0415

    records: list[dict] = []
    consumed = offset
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            fh.seek(offset)
            while len(records) < limit:
                raw = fh.readline()
                if not raw:
                    break
                if not raw.endswith("\n"):
                    # An async writer is mid-line; leave it for the next pass.
                    break
                consumed = fh.tell()
                line = raw.rstrip("\n")
                if not line:
                    continue
                if line.startswith("#"):
                    sep, parsed = ingester.parse_zeek_header([line])
                    if parsed:
                        fields, separator = parsed, sep
                    elif line.startswith("#separator"):
                        separator = sep
                    continue
                if not fields:
                    # A data line without a header is not safe to interpret.
                    continue
                cols = line.split(separator)
                if len(cols) != len(fields):
                    continue
                records.append(dict(zip(fields, cols, strict=False)))
    except OSError:
        return [], offset, fields, separator
    return records, consumed, fields, separator


def _ship_zeek_once(client, *, root: str = "", state_path: str = "") -> int:
    """Ship new rows from every supported Zeek log, with a persisted byte cursor.

    The remote unit's own capture writes the same TSV logs the hub's local tailer understands.
    Sending parsed records (not a file copy) lets the gateway reuse `insert_zeek_records`, so
    a remote row is mapped and validated by the same code as a local one. Cursors advance only
    after a successful POST; a failure retries the same batch.
    """
    from weirvern import ingester  # noqa: PLC0415

    root = root or zeek_log_dir()
    state_path = state_path or zeek_ship_state_path()
    state = _load_zeek_offsets(state_path)
    total = 0
    base = Path(root)
    if not base.exists():
        return 0
    supported = set(ingester.ZEEK_MAPPERS)
    for path in sorted(base.rglob("*.log")):
        log_type = path.name.split(".", 1)[0]
        if log_type not in supported:
            continue
        key = str(path)
        old = state.get(key)
        if not isinstance(old, dict):
            old = {}
        try:
            st = path.stat()
        except OSError:
            continue
        offset = int(old.get("offset") or 0)
        inode = int(old.get("inode") or 0)
        fields = [str(f) for f in (old.get("fields") or [])]
        separator = str(old.get("separator") or "\t")
        if inode and inode != st.st_ino or st.st_size < offset:
            offset, fields, separator = 0, [], "\t"
        records, new_offset, fields, separator = _parse_zeek_chunk(
            key, offset=offset, fields=fields, separator=separator)
        if not records:
            # Still record a header-only read so a restart does not have to re-read it.
            if new_offset != offset:
                state[key] = {"offset": new_offset, "inode": st.st_ino,
                              "fields": fields, "separator": separator}
            continue
        inserted = client.send_zeek(log_type, records)
        # Only advance after the gateway accepted the batch. `inserted` may be less than the
        # record count when the mapper rejects a row; the bytes are still consumed because the
        # gateway has seen them and a retry cannot repair a malformed source row.
        del inserted
        state[key] = {"offset": new_offset, "inode": st.st_ino,
                      "fields": fields, "separator": separator}
        total += len(records)
    _save_zeek_offsets(state_path, state)
    return total


def _zeek_shipper(settings, stop: threading.Event) -> None:
    """A separate thread: a slow log upload must never take the heartbeat down."""
    client = None
    logger.info("zeek: shipping %s to the hub over the authenticated gateway", zeek_log_dir())
    while not stop.is_set():
        try:
            if client is None:
                client = connect(settings)
            if getattr(client, "is_gateway", False):
                _ship_zeek_once(client)
        except Exception as exc:  # noqa: BLE001
            logger.warning("zeek: shipping pass failed: %s", exc)
            client = None
        stop.wait(ZEEK_SHIP_INTERVAL_S)


def _maybe_renew_certificate(client) -> None:
    """Renew this unit's certificate before its 90-day life ends.

    The gateway's `/v1/renew` route existed but nothing called it, so a correctly enrolled
    sensor still went dark on day 90. This runs on the plan-refresh cadence (cheap local check,
    one request only when the leaf is inside the window) and writes the new chain atomically.
    A failed renewal is logged and retried; it does not stop capture or an intercept.
    """
    if not getattr(client, "is_gateway", False):
        return
    cert_path = str(getattr(client, "cert_path", "") or "")
    key_path = str(getattr(client, "key_path", "") or "")
    if not cert_path or not key_path:
        return
    try:
        from weirvern.weirling_client import certificate_expiry, renew_certificate  # noqa: PLC0415

        expires = certificate_expiry(cert_path)
        if expires is None:
            logger.warning("renew: could not read the certificate at %s", cert_path)
            return
        remaining = (expires - datetime.now(UTC)).total_seconds()
        if remaining > RENEW_BEFORE_DAYS * 86400:
            return
        renewed = renew_certificate(client, cert_path=cert_path, key_path=key_path)
        logger.info("renew: certificate replaced; now valid until %s", renewed)
    except Exception as exc:  # noqa: BLE001 -- a renewal failure must not kill the sensor
        logger.warning("renew: failed (will retry): %s", exc)


def _run_pending_sonar(client, default_iface: str) -> None:
    """Run one hub-requested survey on THIS unit and post the measured result.

    REMOTE, NOT A HUB JOB. The request arrived through the authenticated gateway; this
    process is on the sensor, with hostNetwork, so `sonar.survey()` sees the same NICs
    the capture does. NET_RAW is required for the ARP probe and is granted to this
    container by the deploy helper; without it the survey refuses with a reason and the
    refusal is posted rather than turned into a fake empty result.
    """
    if not getattr(client, "is_gateway", False):
        return
    try:
        request = client.sonar_next()
    except Exception as exc:  # noqa: BLE001
        logger.warning("sonar: could not claim a remote survey: %s", exc)
        return
    if not request:
        return
    from weirvern.admin import sonar as sonar_mod  # noqa: PLC0415

    request_id = str(request.get("request_id") or "")
    target = str(request.get("iface") or default_iface or "").strip()
    if not request_id or not target:
        return
    logger.info("sonar: surveying %s for a hub request", target)
    try:
        result = sonar_mod.survey(
            target, mgmt_iface=str(request.get("mgmt_iface") or os.environ.get("MGMT_IFACE") or ""),
            progress=lambda payload: logger.info("sonar: %s", payload.get("step") or payload),
        )
    except Exception as exc:  # noqa: BLE001 - a refusal is a result, not a crash
        logger.warning("sonar: survey failed: %s", exc)
        with contextlib.suppress(Exception):
            client.sonar_result(request_id, {"ok": False, "error": str(exc)})
        return
    try:
        client.sonar_result(request_id, result if isinstance(result, dict) else {"ok": False,
                          "error": "the survey returned a non-object result"})
    except Exception as exc:  # noqa: BLE001
        logger.warning("sonar: could not post the survey result: %s", exc)


_PROBE_LOCK = threading.Lock()


def _run_pending_probe(client, default_iface: str) -> None:
    """Claim one hub-requested CAPTURE probe and run it on a worker thread.

    The probe is read-only and takes up to `seconds`; it must not stall the heartbeat loop for
    the whole window. One probe at a time per unit: the lock is released by the worker's finally,
    including when it refuses before posting a result.
    """
    if not getattr(client, "is_gateway", False):
        return
    if not _PROBE_LOCK.acquire(blocking=False):
        return
    request = None
    try:
        request = client.probe_next()
    except Exception as exc:  # noqa: BLE001
        logger.warning("probe: could not claim a capture request: %s", exc)
    if not request:
        _PROBE_LOCK.release()
        return
    request_id = str(request.get("request_id") or "")
    target = str(request.get("iface") or default_iface or "").strip()
    try:
        seconds = int(request.get("seconds") or 30)
    except (TypeError, ValueError):
        seconds = 30
    if not request_id or not target:
        _PROBE_LOCK.release()
        if request_id:
            with contextlib.suppress(Exception):
                client.probe_result(request_id, {"ok": False, "error":
                                   "the probe request has no capture interface"})
        return

    def _work() -> None:
        from weirvern.admin import probe as probe_mod  # noqa: PLC0415

        try:
            result = probe_mod.run_capture_probe(target, seconds=seconds)
            error = "" if result.get("ok") else str(result.get("error") or "")
            with contextlib.suppress(Exception):
                client.probe_result(request_id, result, error=error)
        except Exception as exc:  # noqa: BLE001 -- a probe refusal is a result
            logger.warning("probe: capture window failed: %s", exc)
            with contextlib.suppress(Exception):
                client.probe_result(request_id, {"ok": False, "error": str(exc)}, error=str(exc))
        finally:
            _PROBE_LOCK.release()

    threading.Thread(target=_work, daemon=True, name="capture-probe").start()
    logger.info("probe: measuring %s for %ss for a hub request", target, seconds)


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
                client = connect(settings)
            if getattr(client, "is_gateway", False):
                _ship_flows_gateway(client)
            else:
                ship_flows_once(client, allow=allow)
        except Exception as exc:  # noqa: BLE001
            logger.warning("netflow: shipping pass failed: %s", exc)
            client = None
        stop.wait(FLOW_SHIP_INTERVAL_S)


def _report_scan_capability(client, sid: str, capability: dict) -> bool:
    """Publish this unit's measured Nmap/OS capability. Never raises.

    A capability report that fails is a log line, not a dead sensor: the hub will treat the
    unit as `unknown` and the Scan button will say so, which is the honest outcome.
    """
    from weirvern import scanner  # noqa: PLC0415

    try:
        if getattr(client, "is_gateway", False):
            return bool(client.scan_capability(capability))
        scanner.write_scanner_status(client, capability)
        return True
    except Exception as exc:  # noqa: BLE001
        logger.warning("scan: capability report failed: %s", exc)
        return False


SCAN_CAPABILITY_REPORT_S = 300


def _scan_worker(settings, sid: str, stop: threading.Event) -> None:
    """Claim and run manual scan jobs — ONLY when this unit can actually run one.

    THE LOCAL CHECK IS THE FIRST GATE. Nmap is measured at startup and re-measured on the
    report interval; a unit without it reports `nmap missing` with the exact install command
    and never asks the hub for work, so a queued job cannot be held by a node that cannot run
    it. The hub enforces the same capability rule AND the network scope at claim time.

    ONE JOB AT A TIME, in this thread: a scan is minutes of Nmap, and running two would make
    the lease the only thing bounding the unit's load.
    """
    from weirvern import scanner  # noqa: PLC0415

    interval = max(5, int(getattr(settings, "scan_claim_interval_s", 10)))
    lease_s = max(30, int(getattr(settings, "scan_job_lease_s", 900) or 900))
    capability = scanner.detect_scanner(settings, sid)
    if capability["nmap_available"]:
        logger.info("scan: this weirling can scan (%s; %s)", capability["nmap_version"],
                    scanner.scan_mode_sentence(capability.get("scan_mode", "connect")))
    else:
        install = scanner.nmap_install_command(capability["os_id"], capability["os_version"])
        logger.warning("scan: Nmap is not installed on this weirling; it will NOT claim manual "
                       "scans. Install it with: %s", install["command"])

    client = None
    last_report = 0.0
    while not stop.is_set():
        try:
            if client is None:
                client = connect(settings)
            now = time.monotonic()
            if last_report == 0.0 or now - last_report >= SCAN_CAPABILITY_REPORT_S:
                # RE-MEASURE, not just re-send: an operator who installs Nmap while the unit
                # runs should become claimable without a restart.
                capability = scanner.detect_scanner(settings, sid)
                _report_scan_capability(client, sid, capability)
                last_report = now
            if not capability["nmap_available"]:
                stop.wait(max(60, SCAN_CAPABILITY_REPORT_S))
                continue
            if getattr(client, "is_gateway", False):
                job, reason = client.scan_next()
                if job:
                    job_id = str(job.get("job_id") or "")
                    # THE HUB IS POLLED WHILE NMAP RUNS. Without this the operator's
                    # `cancel_requested` would only be noticed when the scan finished, which is
                    # a cancel that does not cancel -- the row would stay claimed and the probe
                    # would keep running until it was done anyway.
                    result = scanner.run_service_scan(
                        settings, str(job.get("ip") or ""),
                        raw=scanner.scan_mode_is_raw(capability.get("scan_mode")),
                        cancel_check=partial(client.scan_cancel, job_id))
                    client.scan_result(job_id, result)
                    logger.info("scan: job %s for %s -> %s", job.get("job_id"),
                                job.get("ip"), "done" if result.get("ok") else "error")
                elif reason:
                    logger.info("scan: no job for this weirling: %s", reason)
            else:
                from weirvern import scan_jobs  # noqa: PLC0415

                rows = client.query(
                    "SELECT networks, segment, plan_segment FROM weirvern.weirlings FINAL "
                    "WHERE sensor_id = %(s)s LIMIT 1", parameters={"s": sid},
                ).result_rows
                networks = scanner.declared_networks(
                    rows[0][0] if rows else [], rows[0][1] if rows else "",
                    rows[0][2] if rows else "") if rows else []
                job = scan_jobs.claim_next_job(client, owner=sid, lease_s=lease_s,
                                               networks=networks)
                if job:
                    scanner.run_claimed_job(
                        client, settings, job,
                        raw=scanner.scan_mode_is_raw(capability.get("scan_mode")),
                        # THE DATABASE IS THE HUB HERE: a claimer with a direct connection
                        # polls the same `cancel_requested` row the console wrote.
                        cancel_check=partial(scan_jobs.cancel_requested, client,
                                             str(job.get("job_id") or ""), sid))
        except Exception as exc:  # noqa: BLE001 — the heartbeat must survive a bad scan pass
            logger.warning("scan: claim/run pass failed: %s", exc)
            client = None
        stop.wait(interval)


def _install_worker(settings, sid: str, stop: threading.Event) -> None:
    """Run one-click Nmap install requests the hub delivers over this unit's mTLS channel.

    THE PASSWORD IS NEVER LOGGED, NEVER STORED AND NEVER RE-SENT: it arrives in the request,
    goes straight to sudo's stdin, and the buffer is overwritten afterwards. Only the outcome
    (exit code, redacted output) travels back.
    """
    from weirvern import install_requests  # noqa: PLC0415

    interval = max(5, int(getattr(settings, "scan_install_interval_s", 5)))
    client = None
    while not stop.is_set():
        try:
            if client is None:
                client = connect(settings)
            if getattr(client, "is_gateway", False):
                request = client.install_next()
                if request:
                    result = install_requests.run_local(settings, request)
                    client.install_result(str(request.get("request_id") or ""), result)
                    logger.info("install: request %s -> %s", request.get("request_id"),
                                "done" if result.get("ok") else "failed")
        except Exception as exc:  # noqa: BLE001 - the heartbeat must survive a bad install pass
            logger.warning("install: poll failed: %s", exc)
            client = None
        stop.wait(interval)


def required_iface() -> str:
    """ZEEK_IFACE, or refuse: a unit without its capture port is a unit without a job."""
    iface = (os.environ.get("ZEEK_IFACE") or "").strip()
    if not iface:
        raise SystemExit(
            "sensor unit: ZEEK_IFACE is required -- which NIC does this unit capture?"
        )
    return iface


def _truthy(raw: object) -> bool:
    return str(raw or "").strip().lower() in {"1", "true", "yes", "on"}


def capture_port_check(iface: str, *, allow_management: bool | None = None) -> str:
    """Prove the capture port exists, and decide what to do about the management NIC.

    PREFER AN INDEPENDENT PORT, SUPPORT A SINGLE-NIC HOST. The default-route interface is
    still the wrong place to capture, and it is still refused by default -- but a host with
    one NIC has no other port, and a sensor that will not start there is not a sensor. So the
    rule is now: refuse unless the operator says, explicitly and once, that this box has no
    second port (`--allow-management-nic` at deploy time, `ZEEK_ALLOW_MGMT_IFACE=1` at run
    time). When allowed, the cost is PRINTED, because a single-NIC sensor is a materially
    different instrument and the operator should not discover that from an empty dashboard.

    ENFORCEMENT IS EXEMPT AND MUST STAY THAT WAY. Capturing on the management NIC is a read.
    Blocking on it is the box's own uplink, so it is an outage of the machine doing the
    blocking. The gate refuses that unconditionally; see deploy-weirling.sh, where its refusal
    deliberately does not consult this flag.

    Raises SystemExit when the port cannot be used. Reuses `probe_local()` -- the product's
    own probe for this host, the same program `weirvern interfaces` runs -- so what counts as
    a capture port cannot drift into a second opinion here.

    WHY THE FULL VERDICT IS ADVISORY, NOT A SECOND REFUSAL: inside a container (this
    project's test box is an LXC) every port reads as 'virtual', and often as a bridge
    member -- the measured caveat the product's own interface guidance already documents --
    so the verdict is logged for the operator while the HARD rules stay: the port must
    exist, and the management NIC needs the explicit permission above.
    """
    if allow_management is None:
        allow_management = _truthy(os.environ.get("ZEEK_ALLOW_MGMT_IFACE"))
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
        if not allow_management:
            raise SystemExit(
                f"sensor unit: REFUSING to capture on {iface!r} -- it carries the default route, "
                f"which is the management path. Point the unit at a dedicated capture port, or, "
                f"if this host has only one NIC, deploy with --allow-management-nic (or set "
                f"ZEEK_ALLOW_MGMT_IFACE=1) to accept a degraded sensor."
            )
        # ALLOWED, AND IT MUST NOT BE QUIET. Every sentence below is a thing this sensor will
        # not do, stated where the operator will see it while the unit is starting rather than
        # inferring it later from a thin dashboard.
        logger.warning(
            "capture port %r is the MANAGEMENT NIC (default route). This sensor is DEGRADED and "
            "was accepted explicitly:",
            iface,
        )
        for line in (
            "it sees only traffic to and from THIS HOST, plus broadcast and multicast -- not the "
            "segment, and not other machines' traffic",
            "on a wireless port it does not even see other stations' unicast frames, because the "
            "access point does not forward them to the client",
            "it captures this host's OWN traffic, including the DNS names it resolves and the "
            "hosts it connects to -- treat this sensor's logs as host telemetry, not network "
            "telemetry",
            "do NOT add --gate to this unit: enforcement on the management NIC is the box's own "
            "uplink, and that refusal is not affected by this flag",
        ):
            logger.warning("  - %s", line)
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


# ── the intercept this unit runs, from ITS OWN plan ──────────────────────────────────────────
#
# HOW LONG BETWEEN PLAN READS. The plan is a database row the operator edits from the fleet
# view, so "picked up within half a minute" is the contract the GUI states. A tighter loop
# would be a second heartbeat's worth of queries for no operator-visible gain; a looser one
# makes a toggle feel broken.
PLAN_REFRESH_S = 30.0


def plan_for(client, sid: str) -> tuple[object | None, str]:
    """(plan, reason-it-could-not-be-read). The unit's OWN row, or None when unregistered.

    THE TWO EMPTY ANSWERS ARE DIFFERENT AND MUST NOT BE COLLAPSED. `(None, "")` means the
    registry was read and this sensor has no plan -- so `loch` is the truth and any running
    intercept should stop. `(None, reason)` means the read FAILED, which says nothing about
    the plan and must leave a running intercept alone: disarming a live intercept because
    ClickHouse blipped is the in-path equivalent of a self-inflicted outage.
    """
    from weirvern import fleet_store  # noqa: PLC0415

    if getattr(client, "is_gateway", False):
        try:
            return client.plan(), ""
        except Exception as exc:  # noqa: BLE001
            # A REVOKED IDENTITY IS A COMMAND, NOT A READ FAILURE. The gateway answers 403
            # when this certificate is no longer registered; keeping a live in-path intercept
            # would be the one case where fail-safe means fail-open forever. The caller stops
            # the intercept on this marker; every transport/5xx failure still preserves it.
            if int(getattr(exc, "status", 0) or 0) == 403:
                return None, f"REVOKED: {str(exc)[:180]}"
            return None, str(exc)[:200]
    try:
        for reg in fleet_store.read_registrations(client):
            if reg.sensor_id == sid:
                return reg.plan, ""
        return None, ""
    except Exception as exc:  # noqa: BLE001
        return None, str(exc)[:200]


class InterceptController:
    """Runs (or refuses to run) this unit's intercept, from its declared plan.

    THE SUPERVISOR IS THE HUB'S OWN, VERBATIM. `SiphonSupervisor` is imported and driven exactly
    as the worker drives it: a `weirvern intercept` child with a bounded `--seconds`, the
    fail-open watchdog that restores the forged mappings on any exit, the readiness gate that
    re-reads capabilities and sysctls before every spawn, and the shutdown path that SIGTERMs
    the child so the restore rides the ordinary signal contract. A second supervision scheme
    here would be a second safety contract, and the one nobody exercises is the one that fails.

    NO CAPABILITIES, NO ARMING -- SAID OUT LOUD. When this container has not been granted
    NET_ADMIN/NET_RAW (the unit manifest's opt-in patch does that), the supervisor refuses and
    its note rides this unit's heartbeat, so the fleet row explains why nothing is in-path
    instead of a toggle that appears to have worked.
    """

    def __init__(self, sid: str, *, supervisor_factory=None, group_factory=None) -> None:
        self.sid = sid
        self._factory = supervisor_factory or self._default_factory
        self._group_factory = group_factory or self._default_group_factory
        # `Any` on purpose: the factory is injectable (the tests build the REAL supervisor with
        # faked spawn/readiness hooks), so the attribute's type is "whatever the factory builds"
        # -- annotating it `SiphonSupervisor | None` would be a claim the injection point makes
        # false.
        self._supervisor: Any = None
        # The plan the current supervisor was built from. Rebuilding on an unchanged plan would
        # interrupt a healthy intercept for nothing (every rebuild is a restore/poison seam).
        self._built_from: dict | None = None
        # The mode this unit is RUNNING with, for the heartbeat. It follows the DECLARED plan
        # even while a refusal is outstanding -- which is exactly how the hub's worker reports a
        # configured-but-unarmed siphon sensor, and what lets the fleet view say "declared
        # siphon, reporting siphon, zero mappings".
        self.mode = "loch"

    @staticmethod
    def _default_factory(cfg):
        from weirvern.admin import siphon_supervisor  # noqa: PLC0415

        return siphon_supervisor.SiphonSupervisor(cfg)

    @staticmethod
    def _default_group_factory(configs):
        from weirvern.admin import siphon_supervisor  # noqa: PLC0415

        return siphon_supervisor.SiphonSupervisorGroup(configs)

    def apply(self, plan) -> None:
        """Make reality match the declared plan. Never raises."""
        configs = plan.to_intercept_configs() if plan is not None else []
        key = plan.as_dict() if plan is not None else None
        if key is not None:
            key = {**key, "nics": plan.nics}
        if not configs:
            self.stop(why="the plan does not ask for an intercept")
            self.mode = "loch"
            return
        if self._supervisor is not None and key == self._built_from:
            self.mode = "siphon"
            return
        self.stop(why="the plan changed")
        # THE REPORTED MODE FOLLOWS THE DECLARATION, EVEN IF ARMING FAILS (measured: a factory
        # that raised left the unit reporting `loch` while its plan said siphon -- which reads
        # as "this sensor is passive" instead of "this sensor is declared in-path and could not
        # arm", the same collapse the hub's worker avoids). The refusal itself rides `failures`.
        self.mode = "siphon"
        try:
            if len(configs) == 1:
                self._supervisor = self._factory(configs[0])
            else:
                self._supervisor = self._group_factory(configs)
            self._supervisor.start()
            self._built_from = key
            logger.info("intercept: supervising %d siphon NIC(s) from this unit's own plan",
                        len(configs))
        except Exception as exc:  # noqa: BLE001 -- a monitoring feature must not kill capture
            self._supervisor = None
            self._built_from = None
            logger.error("intercept: could not start the supervisor: %s", exc)

    @property
    def intercept_running(self) -> bool:
        return bool(self._supervisor is not None and self._supervisor.intercept_running)

    @property
    def should_publish(self) -> bool:
        """May THIS agent write its heartbeat row right now?

        THE SAME ONE-WRITER RULE THE WORKER FOLLOWS (`worker_should_publish`): `sensor_status`
        is keyed `(sensor_id, mode)`, and a live intercept child publishes its own row under
        this same id with the authoritative numbers. If the agent wrote too, the row would flip
        between "20 mappings" and "0 mappings" and the fleet would flicker between live and
        not-live. The rule lives on the supervisor -- it knows whether a child is running,
        whether one just crashed, and whether a clean re-arm is seconds away.
        """
        return self._supervisor is None or self._supervisor.worker_should_publish

    def failures(self) -> list[str]:
        """Supervision problems, for the heartbeat's `failures` -- never raises."""
        try:
            from weirvern.admin import siphon_supervisor  # noqa: PLC0415

            return list(siphon_supervisor.notes())
        except Exception:  # noqa: BLE001
            return []

    def stop(self, *, why: str = "") -> None:
        """Orderly shutdown: SIGTERM the child so it RESTORES, and wait for it.

        Called on every path that stops being in-path -- a plan that says loch, a plan change,
        and process shutdown. The child's fail-open watchdog would cover a SIGKILL too, but the
        signal path is the one that restores in milliseconds instead of on ARP expiry, so it is
        the path this always takes first.
        """
        if self._supervisor is None:
            return
        sup, self._supervisor, self._built_from = self._supervisor, None, None
        try:
            sup.stop()
        except Exception:  # noqa: BLE001
            logger.error("intercept: supervisor shutdown failed", exc_info=True)
        if why:
            logger.info("intercept: stopped (%s)", why)


def refresh_plan(client, sid: str, controller: InterceptController) -> None:
    """One plan refresh: this unit's row -> the controller. Never raises.

    A READ FAILURE CHANGES NOTHING. `plan_for` tells the two empty answers apart precisely so
    this can leave a running intercept alone when the registry is unreachable -- the failure
    direction here is "keep the current state", never "disarm because we could not ask".
    """
    plan, why = plan_for(client, sid)
    if why:
        if why.startswith("REVOKED:"):
            logger.error("intercept: this unit was revoked (%s); stopping any in-path intercept",
                         why)
            controller.stop(why="the hub revoked this unit")
            controller.mode = "loch"
            return
        logger.warning(
            "intercept: this unit's plan could not be read (%s); keeping the current "
            "intercept state until the registry is readable again", why)
        return
    controller.apply(plan)


def beat(client, sid: str, iface: str, *, mode: str = "loch",
         failures: list[str] | None = None) -> bool:
    """One heartbeat from observation. Never raises; returns whether it landed.

    `mode` is what this unit is RUNNING (its plan's mode, via the controller) -- never the
    hub's `SENSOR_MODE`: one plan per sensor is the point of the per-weirling plan. The
    supervisor's own refusal notes ride along in `failures`, so a unit that cannot arm says
    why on its own row rather than in a log nobody reads.
    """
    from weirvern.admin import sensorwatch, status  # noqa: PLC0415

    fields = sensorwatch.observe(mode=mode, iface=iface)
    if failures:
        fields["failures"] = list(fields.get("failures") or []) + list(failures)
    fields["host_stats"] = host_stats()
    # THE WEIRLING AGENTS' OWN PATH (measured missing on the box, 2026-10-17: their rows
    # carried [] while the hub's carried its NICs -- this call site predated the column).
    fields.setdefault("interfaces", status.sensor_interfaces())
    if getattr(client, "is_gateway", False):
        try:
            return bool(client.heartbeat(fields))
        except Exception as exc:  # noqa: BLE001
            logger.debug("gateway heartbeat failed: %s", exc)
            return False
    return status.heartbeat(client, sensor_id=sid, **fields)


def _final_beat(client, sid: str, iface: str, *, mode: str = "loch") -> None:
    """A last row saying running=False, so the fleet reads "stopped cleanly" immediately
    instead of "stale" minutes later. Best-effort: a kill -9 gets no such courtesy and
    staleness covers it."""
    try:
        from weirvern.admin import sensorwatch, status  # noqa: PLC0415

        fields = sensorwatch.observe(mode=mode, iface=iface)
        fields["running"] = False
        fields["host_stats"] = host_stats()
        fields.setdefault("interfaces", status.sensor_interfaces())
        if getattr(client, "is_gateway", False):
            client.heartbeat(fields)
        else:
            status.heartbeat(client, sensor_id=sid, **fields)
    except Exception:  # noqa: BLE001
        pass


def _tap_supervisor(settings, iface: str, controller, stop: threading.Event) -> None:
    """Meter this unit's own capture port, while the unit is asked to produce flow records.

    THE AGENT CONTAINER IS THE UNIT'S CAPTURE BOUNDARY. In a siphon unit it already holds
    NET_RAW + NET_ADMIN (the intercept runs there), and in a loch unit the base manifest grants
    NET_RAW for exactly this process; the capture container next door is the Zeek image, which
    has no python. So the tap runs HERE, using the hub's own `weirvern.tap` module rather than a
    second implementation that could drift.

    THE MODE IS THE UNIT'S, NEVER THE HUB'S. `controller.mode` is this unit's plan, read from its
    own registry row; `SENSOR_MODE` arrives through envFrom and describes the HUB's sensor, so it
    would be exactly the wrong input. `intercept_running` is direct evidence, which is stronger
    than the database liveness check the hub's sidecar has to ask for.

    OFF UNLESS THE UNIT SHIPS. `WEIRLING_NETFLOW` gates both halves: a collector whose file
    nothing ships is a file that grows forever, so a unit that is not shipping has no reason to
    spend CPU summarising packets. The thread exits immediately when the switch is off.
    """
    from weirvern import tap as tap_mod  # noqa: PLC0415

    supervisor = tap_mod.Supervisor()
    try:
        while not stop.wait(tap_mod.TICK_S):
            try:
                targets = tap_mod.select_from_settings(
                    settings,
                    # A unit has no channel of its own; its in-path mode is the intercept.
                    channel_active=False,
                    siphon_live=controller.intercept_running,
                    sensor_mode=controller.mode,
                    capture_iface=iface,
                    zeek_iface=iface,
                )
                supervisor.tick(targets)
                # Same evidence the hub's sidecar publishes, for the same reason: a file is the
                # only thing that crosses a container boundary, and this process has no database
                # client by design. ON A UNIT THIS IS LOCAL EVIDENCE -- the hub's health panel
                # reads the HUB's hostPath, so a weirling's tap state is not visible there yet;
                # making it visible belongs on the heartbeat (sensor_status), not on this file.
                tap_mod.publish_state(supervisor, targets, settings)
            except Exception as exc:  # noqa: BLE001 -- capture must not kill the heartbeat
                logger.warning("tap: tick failed (heartbeat continues): %s", exc)
    finally:
        # Orderly: SIGTERM tcpdump so it closes its last segment, and drop the ring.
        supervisor.stop("unit shutting down")


def main() -> None:
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")
    # BEFORE ANYTHING ELSE: a unit with no certificate has no hub to talk to, and must say so once
    # instead of running and reporting nothing.
    require_transport()
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

    # THE DEFAULT PORT ADAPTATION. An access port has no tags and this is a no-op; a trunk
    # gets one host VLAN device per observed tag before the heartbeat reports its interfaces.
    # The capture helper runs the same probe before starting Zeek, so both ends agree about
    # which ports exist. A unit that has not been granted NET_ADMIN records the reason.
    sync_trunk(iface)

    if flow_shipping_enabled():
        threading.Thread(target=_flow_shipper, args=(settings, stop), daemon=True,
                         name="netflow-shipper").start()
    else:
        logger.info("netflow: not enabled on this unit (WEIRLING_NETFLOW is unset) -- an exporter "
                    "here has nowhere to land")

    # REMOTE ZEEK SHIPPING. A gateway unit has no database credential, so its DNS/TLS/HTTP/
    # connection rows otherwise stay on the sensor and the hub's views are blind to that
    # segment. The shipper is mTLS-only and sends parsed records through the hub's own mapper.
    if ((os.environ.get("WEIRLING_GATEWAY_URL") or "").strip()
            and str(os.environ.get("WEIRLING_ZEEK", "1")).strip().lower()
            not in ("0", "false", "no", "off")):
        threading.Thread(target=_zeek_shipper, args=(settings, stop), daemon=True,
                         name="zeek-shipper").start()

    # SCANNING IS THIS UNIT'S JOB TOO (operator, 2026-11-20: "Any weirling should be able to
    # scan"). It has its OWN thread and connection so a minutes-long Nmap run cannot delay the
    # heartbeat, and it claims nothing unless its own Nmap measurement says it can.
    threading.Thread(target=_scan_worker, args=(settings, sid, stop), daemon=True,
                     name="scan-worker").start()

    # THE ONE-CLICK INSTALLER'S OTHER END. It polls the hub for an install request addressed
    # to THIS unit and runs only the allow-listed Nmap command; a password, when the host needs
    # one, arrives over the same mTLS channel and never touches disk or a log line.
    threading.Thread(target=_install_worker, args=(settings, sid, stop), daemon=True,
                     name="install-worker").start()

    # THE UNIT'S OWN INTERCEPT, FROM ITS OWN PLAN. Nothing is armed until a plan says so: this
    # object starts inert and `refresh_plan` (below, once per PLAN_REFRESH_S) is the only thing
    # that can change that. The mode it reports is the plan's, and it stays `loch` until a plan
    # declares otherwise -- the hub's SENSOR_MODE is deliberately not consulted (it describes
    # the HUB's sensor; the units inherit it through envFrom and must not obey it).
    controller = InterceptController(sid)
    last_plan_read = 0.0
    last_renew_check = 0.0

    # THE OTHER HALF OF THE FLOW SWITCH: a unit that ships flow records also PRODUCES them from
    # its own capture when its plan asks for active flow. Same module and same supervision as
    # the hub's tap sidecar, so the two capture paths cannot drift. Started after the controller
    # because the tap must read THIS unit's mode and intercept state, not the hub's SENSOR_MODE.
    if flow_shipping_enabled():
        threading.Thread(target=_tap_supervisor, args=(settings, iface, controller, stop),
                         daemon=True, name="tap").start()

    client = None
    while not stop.is_set():
        try:
            if client is None:
                client = connect(settings)
            now = time.monotonic()
            if now - last_renew_check >= RENEW_CHECK_S:
                last_renew_check = now
                _maybe_renew_certificate(client)
            if now - last_plan_read >= PLAN_REFRESH_S:
                last_plan_read = now
                refresh_plan(client, sid, controller)
                _run_pending_sonar(client, iface)
                _run_pending_probe(client, iface)
            if not controller.should_publish:
                # A live intercept child owns this sensor's `(sensor_id, 'siphon')` row with the
                # authoritative numbers (see `should_publish`); writing here would clobber it.
                stop.wait(interval)
                continue
            if not beat(client, sid, iface, mode=controller.mode,
                        failures=controller.failures()):
                # The write failed; drop the client so the next cycle reconnects rather than
                # hammering a dead connection.
                logger.warning("heartbeat write failed; will reconnect and retry")
                client = None
        except Exception as exc:  # noqa: BLE001
            logger.warning("heartbeat cycle failed: %s", exc)
            client = None
        stop.wait(interval)

    # ORDERLY SIPHON SHUTDOWN, BEFORE ANYTHING ELSE HERE. SIGTERM the supervised intercept while
    # this container still has a network stack to send the restore frames from: the unit's stop
    # would otherwise SIGKILL the child at the end of the grace period, and the forged mappings
    # would wait on ARP expiry instead. Same order as the worker's own shutdown.
    controller.stop(why="the unit is shutting down")

    try:
        if client is None:
            client = connect(settings)
        _final_beat(client, sid, iface, mode=controller.mode)
    except Exception:  # noqa: BLE001
        pass
    logger.info("sensor unit %r: stopped", sid)


if __name__ == "__main__":
    main()
