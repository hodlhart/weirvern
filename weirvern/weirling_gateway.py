"""The mTLS ingest gateway for remote weirlings.

WHY THIS EXISTS. A weirling used to write directly into the hub's ClickHouse over a
NodePort, authenticating with a per-sensor database password. That made the database
credential the sensor identity: it could be copied, it could write any sensor id, it
could not read the plan (the grant is INSERT-only), and no certificate proved which
box was reporting. This gateway gives a sensor one identity -- a client certificate
whose URI SAN is `spiffe://weirvern/sensor/<id>` -- and one outbound HTTPS door.

THE ENROLLMENT CONTRACT. An operator creates a one-time token for a sensor id. The
sensor generates its own key and CSR; it posts the token and CSR to `/v1/enroll`. The
gateway verifies the token and CSR, signs the certificate with the Weirling
intermediate CA, registers the sensor, consumes the token, and returns the leaf
certificate plus the root. The private key never reaches the hub. Subsequent calls
present the certificate; the gateway reads the URI SAN, checks the registry row's
enabled/revoked state, and writes ClickHouse with hub credentials.

WHAT IT DOES. The existing sensor_agent uses this gateway whenever WEIRLING_GATEWAY_URL is
set: enrollment, plan, heartbeat, flows, Zeek records, Sonar and probe results all travel
through the mTLS edge. The direct-ClickHouse path remains only for units explicitly deployed
with --legacy-clickhouse; it is not the default and cannot be entered by silently dropping a
gateway URL.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import logging
import os
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from weirvern import db, fleet, fleet_store, ingester, probe_store, sluice_store
from weirvern.admin import status as status_mod
from weirvern.config import get_settings
from weirvern.sluice import GateState

logger = logging.getLogger("weirvern.weirling_gateway")

ENROLLMENT_TABLE = "weirvern.weirling_enrollments"
SONAR_TABLE = "weirvern.weirling_sonar_requests"
CERT_DAYS = 90
MAX_BODY = 8 * 1024 * 1024
URI_PREFIX = "spiffe://weirvern/sensor/"
DEFAULT_TTL_S = 3600
# The fields status.heartbeat() actually accepts. A body is an untyped JSON object from a
# remote unit; passing an unknown key straight through raises TypeError inside a request
# thread, which closes the connection with no response (measured live: a stray "note" made a
# heartbeat return curl 56, not a 400). Keep the contract explicit so a version mismatch is a
# readable refusal rather than a dropped connection.
HEARTBEAT_FIELDS = frozenset({
    "mode", "iface", "segment", "hosts", "mappings", "running", "uptime_s",
    "restores", "refreshes", "failures", "capture_loss_pct", "packets_recv",
    "packets_dropped", "host_stats", "interfaces",
})


def heartbeat_fields(body: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """Return (accepted fields, unknown field names) without mutating the caller's body."""
    fields = dict(body or {})
    fields.pop("sensor_id", None)
    return fields, sorted(set(fields) - HEARTBEAT_FIELDS)


def token_hash(token: str) -> str:
    """The database stores the hash, never the token."""
    return hashlib.sha256((token or "").encode("utf-8")).hexdigest()


def _as_utc(value: Any) -> dt.datetime:
    if isinstance(value, dt.datetime):
        return value.replace(tzinfo=dt.UTC) if value.tzinfo is None else value.astimezone(dt.UTC)
    text = str(value or "").strip().replace(" ", "T")
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    return dt.datetime.fromisoformat(text).astimezone(dt.UTC)


def create_token(settings, sensor_id: str, *, ttl_s: int = DEFAULT_TTL_S,
                 address: str = "", segment: str = "", expected_mode: str = "loch") -> tuple[str, dt.datetime]:
    """Create a one-time enrollment token and store only its hash.

    Token issuance is the operator's adoption declaration: the token is bound to the
    sensor id, expires, and is consumed on first successful enrollment. A future
    pending/approve UI can split this into two clicks without changing the wire
    contract, but this first implementation deliberately keeps the operator in the
    loop at token creation rather than inventing a second credential store.
    """
    sid = fleet.validate_sensor_id(sensor_id)
    token = __import__("secrets").token_urlsafe(32)
    expires = dt.datetime.now(dt.UTC) + dt.timedelta(seconds=max(60, int(ttl_s)))
    client = db.connect(settings, retries=2, delay_s=1.0)
    try:
        client.insert(
            ENROLLMENT_TABLE,
            [[token_hash(token), sid, address.strip(), segment.strip(),
              expected_mode.strip() or "loch", expires, None, dt.datetime.now(dt.UTC)]],
            column_names=["token_hash", "sensor_id", "address", "segment",
                          "expected_mode", "expires_at", "used_at", "updated_at"],
        )
    finally:
        client.close()
    return token, expires


def _token_row(client, token: str) -> dict[str, Any] | None:
    rows = list(client.query(
        "SELECT token_hash, sensor_id, address, segment, expected_mode, expires_at, used_at "
        f"FROM {ENROLLMENT_TABLE} FINAL WHERE token_hash = %(h)s LIMIT 1",
        parameters={"h": token_hash(token)},
    ).named_results())
    return dict(rows[0]) if rows else None


def _consume(client, row: dict[str, Any]) -> None:
    """Write a newer ReplacingMergeTree version with used_at set."""
    client.insert(
        ENROLLMENT_TABLE,
        [[row["token_hash"], row["sensor_id"], row.get("address", ""), row.get("segment", ""),
          row.get("expected_mode", "loch"), row["expires_at"], dt.datetime.now(dt.UTC),
          dt.datetime.now(dt.UTC)]],
        column_names=["token_hash", "sensor_id", "address", "segment", "expected_mode",
                      "expires_at", "used_at", "updated_at"],
    )


class CertificateAuthority:
    """The Weirling intermediate, kept outside the application database."""

    def __init__(self, cert_path: str, key_path: str, root_path: str) -> None:
        self.cert = x509.load_pem_x509_certificate(Path(cert_path).read_bytes())
        # The CA is RSA or ECDSA; reject/typing-narrow the other key types that
        # `load_pem_private_key` can return but X.509 signing cannot use.
        self.key = cast(
            rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey,
            serialization.load_pem_private_key(Path(key_path).read_bytes(), password=None),
        )
        self.root_pem = Path(root_path).read_bytes()
        self.intermediate_pem = Path(cert_path).read_bytes()

    def sign_csr(self, csr_pem: bytes, sensor_id: str) -> tuple[bytes, dt.datetime]:
        csr = x509.load_pem_x509_csr(csr_pem)
        if not csr.is_signature_valid:
            raise ValueError("the CSR signature is not valid")
        now = dt.datetime.now(dt.UTC)
        serial = __import__("secrets").randbits(128)
        subject = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Weirvern"),
            x509.NameAttribute(NameOID.COMMON_NAME, f"weirling/{sensor_id}"),
        ])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self.cert.subject)
            .public_key(csr.public_key())
            .serial_number(serial)
            .not_valid_before(now - dt.timedelta(minutes=5))
            .not_valid_after(now + dt.timedelta(days=CERT_DAYS))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(digital_signature=True, content_commitment=False,
                              key_encipherment=True, data_encipherment=False,
                              key_agreement=False, key_cert_sign=False,
                              crl_sign=False, encipher_only=False, decipher_only=False),
                critical=True,
            )
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
            .add_extension(
                x509.SubjectAlternativeName([
                    x509.UniformResourceIdentifier(f"{URI_PREFIX}{sensor_id}")
                ]),
                critical=False,
            )
            .sign(self.key, hashes.SHA256())
        )
        return cert.public_bytes(serialization.Encoding.PEM), cert.not_valid_after_utc


def _peer_sensor_id(handler) -> str:
    """Read the URI SAN from the verified client certificate.

    The TLS stack has already validated the chain (ssl.CERT_OPTIONAL + root CA); this
    function only maps the verified identity to the registry key. A certificate whose
    URI SAN is not exactly one sensor id is rejected rather than searched loosely.
    """
    cert = handler.connection.getpeercert() or {}
    for kind, value in cert.get("subjectAltName", ()):
        if kind == "URI" and value.startswith(URI_PREFIX):
            sid = value[len(URI_PREFIX):].strip()
            if sid and "/" not in sid:
                try:
                    return fleet.validate_sensor_id(sid)
                except fleet_store.FleetError:
                    return ""
    return ""


def _sensor_registration(client, sensor_id: str):
    for reg in fleet_store.read_registrations(client, include_revoked=True):
        if reg.sensor_id == sensor_id:
            return reg
    return None


class Gateway:
    def __init__(self, settings, ca: CertificateAuthority) -> None:
        self.settings = settings
        self.ca = ca
        self._token_lock = threading.Lock()

    def client(self):
        return db.connect(self.settings, retries=2, delay_s=1.0)

    def enroll(self, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        token = str(body.get("token") or "").strip()
        sensor_id = str(body.get("sensor_id") or "").strip()
        csr_pem = str(body.get("csr") or "").encode("utf-8")
        if not token or not sensor_id or not csr_pem:
            return 400, {"error": "token, sensor_id and csr are required"}
        try:
            sid = fleet.validate_sensor_id(sensor_id)
        except fleet_store.FleetError as exc:
            return 400, {"error": str(exc)}
        client = self.client()
        try:
            row = _token_row(client, token)
            if row is None:
                return 401, {"error": "unknown enrollment token"}
            if row.get("used_at"):
                return 409, {"error": "enrollment token has already been used"}
            if _as_utc(row["expires_at"]) <= dt.datetime.now(dt.UTC):
                return 401, {"error": "enrollment token has expired"}
            if str(row.get("sensor_id")) != sid:
                return 403, {"error": "enrollment token is bound to a different sensor id"}
            try:
                certificate, expires = self.ca.sign_csr(csr_pem, sid)
            except Exception as exc:  # noqa: BLE001
                return 400, {"error": f"the CSR could not be signed: {exc}"}
            # REGISTER BEFORE CONSUMING THE TOKEN. A failed registration leaves the
            # token usable for a corrected retry, while a signed certificate that was
            # never delivered is harmless.
            try:
                fleet_store.register(
                    client, sid,
                    address=str(body.get("address") or row.get("address") or ""),
                    segment=str(body.get("segment") or row.get("segment") or ""),
                    expected_mode=str(body.get("expected_mode") or row.get("expected_mode") or "loch"),
                    note="adopted by mTLS enrollment",
                )
            except Exception as exc:  # noqa: BLE001
                return 503, {"error": f"the sensor could not be registered: {exc}"}
            with self._token_lock:
                _consume(client, row)
            return 201, {
                "sensor_id": sid,
                "certificate": certificate.decode("utf-8"),
                "ca": self.ca.root_pem.decode("utf-8"),
                "intermediate": self.ca.intermediate_pem.decode("utf-8"),
                "expires_at": expires.isoformat(),
            }
        finally:
            client.close()

    def _registered(self, client, sensor_id: str):
        reg = _sensor_registration(client, sensor_id)
        if reg is None:
            return None, (403, {"error": "sensor is not registered"})
        if reg.revoked_at is not None:
            return None, (403, {"error": "sensor is revoked"})
        if not reg.enabled:
            return None, (403, {"error": "sensor is disabled"})
        return reg, None

    def heartbeat(self, sensor_id: str, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        client = self.client()
        try:
            reg, err = self._registered(client, sensor_id)
            if err:
                return err
            fields, unknown = heartbeat_fields(body)
            if unknown:
                return 400, {"error": "unknown heartbeat field(s): " + ", ".join(unknown)}
            fields.setdefault("mode", reg.expected_mode or "loch")
            fields.setdefault("iface", reg.plan.iface if reg.plan else "")
            ok = status_mod.heartbeat(client, sensor_id=sensor_id, **fields)
            if not ok:
                return 503, {"error": "the heartbeat could not be stored"}
            return 200, {"ok": True, "sensor_id": sensor_id}
        finally:
            client.close()

    # ── FLEET SCANNING: capability, claim, result ────────────────────────────────────────────
    #
    # Scanning is executed by the weirlings themselves. Three calls, one contract:
    #   capability: what this unit measured about its own Nmap (and its OS, for the install line)
    #   next:       claim ONE job that is inside this unit's declared networks
    #   result:     the measured services/observations, written by the hub's own recorder
    #
    # THE SCOPE IS ENFORCED HERE, not on the unit: a compromised or misconfigured agent cannot
    # claim a segment it does not monitor, because the hub reads the registration and refuses.

    def scan_capability(self, sensor_id: str, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        client = self.client()
        try:
            _reg, err = self._registered(client, sensor_id)
            if err:
                return err
            from weirvern import scanner as scanner_mod  # noqa: PLC0415

            status = {
                "sensor_id": sensor_id,
                "profile": str(body.get("profile") or "basic")[:16],
                "nmap_available": bool(body.get("nmap_available")),
                "nmap_version": str(body.get("nmap_version") or "")[:300],
                "nmap_path": str(body.get("nmap_path") or "")[:300],
                "nse_available": bool(body.get("nse_available")),
                "os_id": str(body.get("os_id") or "")[:64],
                "os_version": str(body.get("os_version") or "")[:64],
                "os_label": str(body.get("os_label") or "")[:120],
                "os_family": str(body.get("os_family") or "")[:32],
                "detail": str(body.get("detail") or "")[:500],
                "privileged": bool(body.get("privileged")),
                "scan_mode": str(body.get("scan_mode") or "")[:16],
                "can_install": bool(body.get("can_install")),
                "sudo_state": str(body.get("sudo_state") or "")[:16],
            }
            scanner_mod.write_scanner_status(client, status)
            return 200, {"ok": True, "sensor_id": sensor_id,
                         "nmap_available": status["nmap_available"]}
        finally:
            client.close()

    def _scan_networks(self, client, sensor_id: str) -> list[str]:
        rows = client.query(
            "SELECT networks, segment, plan_segment FROM weirvern.weirlings FINAL "
            "WHERE sensor_id = %(s)s LIMIT 1",
            parameters={"s": sensor_id},
        ).result_rows
        if not rows:
            return []
        from weirvern import scanner as scanner_mod  # noqa: PLC0415

        row = rows[0]
        return scanner_mod.declared_networks(
            row[0], row[1] if len(row) > 1 else "", row[2] if len(row) > 2 else "")

    def scan_next(self, sensor_id: str) -> tuple[int, dict[str, Any]]:
        client = self.client()
        try:
            _reg, err = self._registered(client, sensor_id)
            if err:
                return err
            from weirvern import scan_jobs  # noqa: PLC0415
            from weirvern import scanner as scanner_mod

            capability = scanner_mod.fleet_capability(client, ip="")
            mine = next((item for item in capability["capable"]
                         if item["sensor_id"] == sensor_id), None)
            if mine is None:
                reason = next((item["reason"] for item in capability["unknown"]
                               + capability["incapable"] if item["sensor_id"] == sensor_id),
                              "this weirling has not reported a fresh Nmap capability")
                return 200, {"job": None, "reason": reason}
            networks = self._scan_networks(client, sensor_id)
            lease_s = int(getattr(self.settings, "scan_job_lease_s", 900) or 900)
            job = scan_jobs.claim_next_job(client, owner=sensor_id, lease_s=lease_s,
                                           networks=networks)
            if job is None:
                queued = client.query(
                    "SELECT count() FROM weirvern.scan_jobs FINAL WHERE state = 'queued'"
                ).result_rows
                waiting = int((queued[0][0] if queued else 0) or 0)
                reason = ("" if not waiting else
                          f"{waiting} queued job(s) are outside this weirling's declared "
                          "networks")
                return 200, {"job": None, "reason": reason}
            return 200, {"job": {
                "job_id": str(job["job_id"]), "ip": str(job["ip"]),
                "asset_key": str(job["asset_key"]),
                "requested_at": (job["requested_at"].isoformat()
                                 if hasattr(job.get("requested_at"), "isoformat") else ""),
            }}
        finally:
            client.close()

    def scan_cancel(self, sensor_id: str, job_id: str) -> tuple[int, dict[str, Any]]:
        """Has the hub asked THIS weirling to stop this job? Polled while Nmap runs."""
        client = self.client()
        try:
            _reg, err = self._registered(client, sensor_id)
            if err:
                return err
            from weirvern import scan_jobs  # noqa: PLC0415

            if not str(job_id or "").strip():
                return 400, {"error": "job_id is required"}
            return 200, {"cancel": scan_jobs.cancel_requested(client, job_id, sensor_id)}
        finally:
            client.close()

    def scan_result(self, sensor_id: str, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        client = self.client()
        try:
            _reg, err = self._registered(client, sensor_id)
            if err:
                return err
            import uuid as _uuid  # noqa: PLC0415

            from weirvern import scan_jobs  # noqa: PLC0415
            from weirvern import scanner as scanner_mod

            job_id = str(body.get("job_id") or "").strip()
            if not job_id:
                return 400, {"error": "job_id is required"}
            job = scan_jobs.get_job(client, job_id)
            if job is None:
                return 404, {"error": "unknown scan job"}
            if str(job.get("state") or "") not in ("claimed", "cancel_requested"):
                return 409, {"error": f"the job is {job.get('state') or 'unknown'}, not claimed"}
            if str(job.get("lease_owner") or "") != sensor_id:
                return 403, {"error": "the job is claimed by a different weirling"}
            result = body.get("result")
            if not isinstance(result, dict):
                return 400, {"error": "result must be a JSON object"}
            if bool(result.get("cancelled")):
                # THE WEIRLING CONFIRMED IT STOPPED. Only now is the row removed; the audit row
                # is the surviving record of the request and of the stop.
                from weirvern import fleet_store  # noqa: PLC0415

                fleet_store.write_audit(
                    client, scope="scan", action="scan_cancelled_confirmed",
                    target=f"{job.get('ip')} job {job_id}",
                    reason="the weirling confirmed it stopped the scan", actor=sensor_id)
                scan_jobs.delete_job(client, job_id)
                return 200, {"ok": True, "job_id": job_id, "state": "cancelled"}
            asset = scan_jobs.find_asset(client, str(job.get("ip") or ""))
            if asset is None:
                scan_jobs.finish_job(client, job, ok=False,
                                     error="the host is no longer in the asset registry")
                return 200, {"ok": True, "job_id": job_id, "state": "error"}
            ok = scanner_mod.record_scan_result(
                client, asset, result, scan_id=str(_uuid.uuid4()))
            error = ""
            if not ok:
                refreshed = scan_jobs.find_asset(client, str(job.get("ip") or ""))
                error = str((refreshed or {}).get("scan_error") or "the scan failed")
            scan_jobs.finish_job(client, job, ok=ok, error=error)
            return 200, {"ok": True, "job_id": job_id, "state": "done" if ok else "error"}
        finally:
            client.close()

    def plan(self, sensor_id: str) -> tuple[int, dict[str, Any]]:
        client = self.client()
        try:
            reg, err = self._registered(client, sensor_id)
            if err:
                return err
            return 200, {
                "sensor_id": sensor_id,
                "enabled": reg.enabled,
                "plan": ({**reg.plan.as_dict(), "nics": reg.plan.nics}
                         if reg.plan else None),
            }
        finally:
            client.close()

    def flows(self, sensor_id: str, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        records = body.get("records") if isinstance(body, dict) else None
        if not isinstance(records, list):
            return 400, {"error": "records must be a list"}
        if len(records) > 10000:
            return 413, {"error": "too many records in one request"}
        client = self.client()
        try:
            _reg, err = self._registered(client, sensor_id)
            if err:
                return err
            rows = [ingester.map_flow(r) for r in records if isinstance(r, dict)]
            inserted = ingester.insert_batch(client, rows)
            return 200, {"ok": True, "inserted": inserted}
        finally:
            client.close()

    def zeek(self, sensor_id: str, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        """Raw Zeek log records from a remote capture, mapped by the hub's own ingester."""
        log_type = str(body.get("log_type") or "").strip()
        records = body.get("records") if isinstance(body, dict) else None
        if not log_type:
            return 400, {"error": "log_type is required"}
        if not isinstance(records, list):
            return 400, {"error": "records must be a list"}
        if len(records) > 5000:
            return 413, {"error": "too many records in one request"}
        client = self.client()
        try:
            _reg, err = self._registered(client, sensor_id)
            if err:
                return err
            try:
                inserted = ingester.insert_zeek_records(client, log_type, records)
            except ValueError as exc:
                return 400, {"error": str(exc)}
            return 200, {"ok": True, "inserted": inserted}
        finally:
            client.close()

    def _sonar_row(self, client, request_id: str) -> dict[str, Any] | None:
        rows = list(client.query(
            "SELECT request_id, sensor_id, iface, mgmt_iface, status, result, error "
            f"FROM {SONAR_TABLE} FINAL WHERE request_id = %(id)s LIMIT 1",
            parameters={"id": request_id},
        ).named_results())
        return dict(rows[0]) if rows else None

    def _sonar_update(self, client, row: dict[str, Any], status: str,
                      result: str = "", error: str = "") -> None:
        now = dt.datetime.now(dt.UTC)
        client.insert(
            SONAR_TABLE,
            [[row["request_id"], row["sensor_id"], row.get("iface", ""),
              row.get("mgmt_iface", ""), status, result, error,
              row.get("requested_at") or now, now]],
            column_names=["request_id", "sensor_id", "iface", "mgmt_iface", "status",
                          "result", "error", "requested_at", "updated_at"],
        )

    def sonar_next(self, sensor_id: str) -> tuple[int, dict[str, Any]]:
        """Claim the oldest pending survey for this authenticated sensor.

        ONE REQUEST PER CLAIM, and the status changes to `running` before the reply is
        sent: a second poll cannot run the same survey twice. The caller's certificate
        already names the sensor, so a unit can never claim another unit's request.
        """
        client = self.client()
        try:
            _reg, err = self._registered(client, sensor_id)
            if err:
                return err
            rows = list(client.query(
                "SELECT request_id, sensor_id, iface, mgmt_iface, status, result, error, requested_at "
                f"FROM {SONAR_TABLE} FINAL WHERE sensor_id = %(s)s AND status = 'pending' "
                "ORDER BY requested_at ASC LIMIT 1",
                parameters={"s": sensor_id},
            ).named_results())
            if not rows:
                return 200, {"request": None}
            row = dict(rows[0])
            self._sonar_update(client, row, "running")
            return 200, {"request": {"request_id": row["request_id"],
                                     "iface": row.get("iface", ""),
                                     "mgmt_iface": row.get("mgmt_iface", "")}}
        finally:
            client.close()

    def sonar_result(self, sensor_id: str, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        client = self.client()
        try:
            _reg, err = self._registered(client, sensor_id)
            if err:
                return err
            request_id = str(body.get("request_id") or "").strip()
            if not request_id:
                return 400, {"error": "request_id is required"}
            row = self._sonar_row(client, request_id)
            if row is None:
                return 404, {"error": "unknown survey request"}
            if str(row.get("sensor_id")) != sensor_id:
                return 403, {"error": "survey request belongs to a different sensor"}
            result = body.get("result")
            error = str(body.get("error") or "").strip()
            if isinstance(result, dict) and result.get("ok") is False and not error:
                error = str(result.get("error") or "the sensor refused the survey")
            if error:
                self._sonar_update(client, row, "failed", "", error[:2000])
            else:
                if not isinstance(result, dict):
                    return 400, {"error": "result must be a JSON object"}
                self._sonar_update(client, row, "done", json.dumps(result), "")
            return 200, {"ok": True, "request_id": request_id}
        finally:
            client.close()

    def probe_next(self, sensor_id: str) -> tuple[int, dict[str, Any]]:
        """Claim the oldest pending CAPTURE probe for this authenticated sensor.

        The request changes to `running` before the reply is sent, so a second poll cannot run
        the same window twice. This is read-only on the sensor: no plan, mode or sysctl changes.
        """
        client = self.client()
        try:
            _reg, err = self._registered(client, sensor_id)
            if err:
                return err
            row = probe_store.claim_next(client, sensor_id)
            if row is None:
                return 200, {"request": None}
            return 200, {"request": {
                "request_id": row["request_id"],
                "iface": row.get("iface", ""),
                "seconds": int(row.get("seconds") or probe_store.DEFAULT_SECONDS),
            }}
        finally:
            client.close()

    def probe_result(self, sensor_id: str, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        """Record a capture probe's measured result (or the reason it could not run)."""
        client = self.client()
        try:
            _reg, err = self._registered(client, sensor_id)
            if err:
                return err
            request_id = str(body.get("request_id") or "").strip()
            if not request_id:
                return 400, {"error": "request_id is required"}
            row = probe_store.get_request(client, request_id)
            if row is None:
                return 404, {"error": "unknown capture probe request"}
            if str(row.get("sensor_id")) != sensor_id:
                return 403, {"error": "capture probe belongs to a different sensor"}
            result = body.get("result")
            error = str(body.get("error") or "").strip()
            if isinstance(result, dict) and result.get("ok") is False and not error:
                error = str(result.get("error") or "the sensor could not run the capture probe")
            if error:
                probe_store.finish(client, row, status="failed", error=error[:2000])
            else:
                if not isinstance(result, dict):
                    return 400, {"error": "result must be a JSON object"}
                probe_store.finish(client, row, status="done", result=result)
            return 200, {"ok": True, "request_id": request_id}
        finally:
            client.close()

    def gate_rules(self, sensor_id: str) -> tuple[int, dict[str, Any]]:
        """The live rule set and resolved domain addresses for a remote gate."""
        client = self.client()
        try:
            _reg, err = self._registered(client, sensor_id)
            if err:
                return err
            rules = sluice_store.load_live_rules(client)
            rules, problems = sluice_store.attach_resolved_ips(client, rules)
            return 200, {
                "rules": [sluice_store.rule_to_wire(rule) for rule in rules],
                "problems": list(problems),
            }
        except Exception as exc:  # noqa: BLE001
            return 503, {"error": f"the gate rules could not be read: {exc}"}
        finally:
            client.close()

    def gate_state(self, sensor_id: str) -> tuple[int, dict[str, Any]]:
        client = self.client()
        try:
            _reg, err = self._registered(client, sensor_id)
            if err:
                return err
            return 200, {"state": sluice_store.load_gate_state(client, sensor_id)}
        finally:
            client.close()

    def gate_write_state(self, sensor_id: str, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        client = self.client()
        try:
            _reg, err = self._registered(client, sensor_id)
            if err:
                return err
            # Only the known GateState fields are accepted; a gate cannot smuggle another
            # sensor's name or arbitrary columns into the store.
            try:
                state = GateState(
                    state=str(body.get("state") or "disarmed"),
                    iface=str(body.get("iface") or ""),
                    mgmt_iface=str(body.get("mgmt_iface") or ""),
                    rules_active=int(body.get("rules_active") or 0),
                    rules_total=int(body.get("rules_total") or 0),
                    packets_blocked=int(body.get("packets_blocked") or 0),
                    bytes_blocked=int(body.get("bytes_blocked") or 0),
                    detail=str(body.get("detail") or ""),
                    backend=str(body.get("backend") or ""),
                    backend_expected=str(body.get("backend_expected") or "nft"),
                    enforcement=str(body.get("enforcement") or ""),
                )
            except (TypeError, ValueError) as exc:
                return 400, {"error": f"invalid gate state: {exc}"}
            sluice_store.write_gate_state(client, sensor_id, state)
            return 200, {"ok": True}
        finally:
            client.close()

    def gate_write_events(self, sensor_id: str, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        client = self.client()
        try:
            _reg, err = self._registered(client, sensor_id)
            if err:
                return err
            events = body.get("events")
            if not isinstance(events, list):
                return 400, {"error": "events must be a list"}
            if len(events) > 10000:
                return 413, {"error": "too many events in one request"}
            clean = [e for e in events if isinstance(e, dict)]
            written = sluice_store.write_events(client, clean)
            return 200, {"ok": True, "written": written}
        finally:
            client.close()

    def install_create(self, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        """Create an in-memory install request for ONE registered weirling.

        THE HOST IS CHECKED, not trusted: an unknown, revoked or disabled registration is a
        403, and the request never exists. `sudo_password` is accepted only when the caller says
        the host needs one; it is stored as bytes, never echoed, and dropped on delivery.
        """
        from weirvern import install_requests  # noqa: PLC0415

        host_id = str(body.get("host_id") or "").strip()
        if not host_id:
            return 400, {"error": "host_id is required"}
        client = self.client()
        try:
            _reg, err = self._registered(client, host_id)
            if err:
                return err
        finally:
            client.close()
        try:
            request = install_requests.STORE.create(
                host_id=host_id,
                family=str(body.get("distro_family") or ""),
                version=str(body.get("distro_version") or ""),
                reason=str(body.get("reason") or ""),
                actor=str(body.get("actor") or "operator"),
                password=(str(body.get("sudo_password")) if body.get("sudo_password") else None),
            )
        except install_requests.InstallError as exc:
            return exc.code, {"ok": False, "error": str(exc)}
        logger.info("install: request %s for %s (%s)", request.request_id, host_id,
                    request.command)
        return 200, {"ok": True, **request.public()}

    def install_status(self, request_id: str) -> tuple[int, dict[str, Any]]:
        from weirvern import install_requests  # noqa: PLC0415

        try:
            return 200, install_requests.STORE.status(request_id).public()
        except install_requests.InstallError as exc:
            return exc.code, {"ok": False, "error": str(exc)}

    def install_next(self, sensor_id: str) -> tuple[int, dict[str, Any]]:
        """The weirling's own pickup: ONE pending request for THIS host, password delivered once."""
        from weirvern import install_requests  # noqa: PLC0415

        client = self.client()
        try:
            _reg, err = self._registered(client, sensor_id)
            if err:
                return err
        finally:
            client.close()
        request = install_requests.STORE.claim(sensor_id)
        return 200, {"request": request or None}

    def install_result(self, sensor_id: str, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        """Record the outcome and the FACT of the install; the secret was never part of it."""
        from weirvern import install_requests  # noqa: PLC0415

        request_id = str(body.get("request_id") or "").strip()
        if not request_id:
            return 400, {"error": "request_id is required"}
        ok = bool(body.get("ok"))
        exit_code = body.get("exit_code")
        try:
            request = install_requests.STORE.result(
                request_id, sensor_id, ok=ok,
                exit_code=(int(exit_code) if isinstance(exit_code, int) else None),
                output=str(body.get("output") or ""),
                nmap_version=str(body.get("nmap_version") or ""),
                scan_mode=str(body.get("scan_mode") or ""))
        except install_requests.InstallError as exc:
            return exc.code, {"ok": False, "error": str(exc)}
        client = self.client()
        try:
            # THE AUDIT SURVIVES THE REQUEST (which does not: it is in memory). It names the
            # actor, host, command and outcome, and THAT a password was used -- never the value.
            fleet_store.write_audit(
                client, scope="scan", action="nmap_install",
                target=f"{sensor_id} {request.command}"[:400],
                reason=(f"{request.reason}; exit {request.exit_code}"
                        f"{'; sudo password used' if request.password_used else ''}")[:400],
                actor=request.actor)
        finally:
            client.close()
        logger.info("install: %s on %s -> %s", request_id, sensor_id,
                    "done" if request.state == "done" else "failed")
        return 200, {"ok": True, "request_id": request_id, "state": request.state}

    def renew(self, sensor_id: str, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        client = self.client()
        try:
            _reg, err = self._registered(client, sensor_id)
            if err:
                return err
            csr_pem = str(body.get("csr") or "").encode("utf-8")
            if not csr_pem:
                return 400, {"error": "csr is required"}
            try:
                certificate, expires = self.ca.sign_csr(csr_pem, sensor_id)
            except Exception as exc:  # noqa: BLE001
                return 400, {"error": f"the CSR could not be signed: {exc}"}
            return 200, {"sensor_id": sensor_id, "certificate": certificate.decode("utf-8"),
                         "intermediate": self.ca.intermediate_pem.decode("utf-8"),
                         "expires_at": expires.isoformat()}
        finally:
            client.close()


def _make_handler(gateway: Gateway):
    class Handler(BaseHTTPRequestHandler):
        server_version = "Weirvern-Ingest"
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):  # noqa: A003
            logger.debug("%s - %s", self.address_string(), fmt % args)

        def _json(self, code: int, payload: dict[str, Any]) -> None:
            body = json.dumps(payload, default=str).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _body(self) -> dict[str, Any]:
            length = int(self.headers.get("Content-Length", "0") or 0)
            if length <= 0 or length > MAX_BODY:
                raise ValueError("request body is missing or too large")
            raw = self.rfile.read(length)
            try:
                parsed = json.loads(raw)
            except ValueError as exc:
                raise ValueError("request body is not JSON") from exc
            if not isinstance(parsed, dict):
                raise ValueError("request body must be a JSON object")
            return parsed

        def _sensor(self) -> str:
            sid = _peer_sensor_id(self)
            if not sid:
                self._json(401, {"error": "a valid weirling client certificate is required"})
            return sid

        def _service(self) -> bool:
            """THE INSTALL SERVICE CREDENTIAL: one bearer, one scope, compared in constant time.

            It is mounted only into the console and this gateway, and it opens exactly the
            install routes -- a bearer that leaked cannot read flows, write a heartbeat or
            claim a scan. An unset credential refuses rather than accepting everything.
            """
            configured = str(getattr(gateway.settings, "scan_install_token", "") or "")
            if not configured:
                self._json(503, {"error": "the install service credential is not configured "
                                          "on this gateway"})
                return False
            presented = self.headers.get("X-Weirvern-Scan-Install", "")
            from weirvern import install_requests  # noqa: PLC0415

            ok, code, message = install_requests.service_credential(gateway.settings, presented)
            if not ok:
                self._json(code, {"error": message})
            return ok

        def do_GET(self) -> None:  # noqa: N802
            path = urlparse(self.path).path.rstrip("/") or "/"
            if path == "/v1/healthz":
                return self._json(200, {"ok": True})
            if path == "/v1/plan":
                sid = self._sensor()
                if not sid:
                    return
                return self._json(*gateway.plan(sid))
            if path == "/v1/sonar/next":
                sid = self._sensor()
                if not sid:
                    return
                return self._json(*gateway.sonar_next(sid))
            if path == "/v1/probe/next":
                sid = self._sensor()
                if not sid:
                    return
                return self._json(*gateway.probe_next(sid))
            if path == "/v1/scan/next":
                sid = self._sensor()
                if not sid:
                    return
                return self._json(*gateway.scan_next(sid))
            if path == "/v1/scan/cancel":
                sid = self._sensor()
                if not sid:
                    return
                job_id = (urlparse(self.path).query.split("job_id=", 1)[1].split("&", 1)[0]
                          if "job_id=" in urlparse(self.path).query else "")
                from urllib.parse import unquote  # noqa: PLC0415

                return self._json(*gateway.scan_cancel(sid, unquote(job_id)))
            if path == "/v1/scan/install/next":
                sid = self._sensor()
                if not sid:
                    return
                return self._json(*gateway.install_next(sid))
            if path.startswith("/v1/scan/install/"):
                if not self._service():
                    return
                from urllib.parse import unquote  # noqa: PLC0415

                return self._json(*gateway.install_status(unquote(path.rsplit("/", 1)[-1])))
            if path == "/v1/gate/rules":
                sid = self._sensor()
                if not sid:
                    return
                return self._json(*gateway.gate_rules(sid))
            if path == "/v1/gate/state":
                sid = self._sensor()
                if not sid:
                    return
                return self._json(*gateway.gate_state(sid))
            return self._json(404, {"error": "no route"})

        def do_POST(self) -> None:  # noqa: N802
            path = urlparse(self.path).path.rstrip("/") or "/"
            if path == "/v1/enroll":
                try:
                    body = self._body()
                except ValueError as exc:
                    return self._json(400, {"error": str(exc)})
                return self._json(*gateway.enroll(body))
            if path == "/v1/scan/install":
                # SERVICE CREDENTIAL, NOT A SENSOR CERT: this is the console asking the hub to
                # deliver an install request to one weirling on its next poll.
                if not self._service():
                    return
                try:
                    body = self._body()
                except ValueError as exc:
                    return self._json(400, {"error": str(exc)})
                return self._json(*gateway.install_create(body))
            sid = self._sensor()
            if not sid:
                return
            try:
                body = self._body()
            except ValueError as exc:
                return self._json(400, {"error": str(exc)})
            if path == "/v1/heartbeat":
                return self._json(*gateway.heartbeat(sid, body))
            if path == "/v1/flows":
                return self._json(*gateway.flows(sid, body))
            if path == "/v1/zeek":
                return self._json(*gateway.zeek(sid, body))
            if path == "/v1/renew":
                return self._json(*gateway.renew(sid, body))
            if path == "/v1/sonar/result":
                return self._json(*gateway.sonar_result(sid, body))
            if path == "/v1/probe/result":
                return self._json(*gateway.probe_result(sid, body))
            if path == "/v1/scan/capability":
                return self._json(*gateway.scan_capability(sid, body))
            if path == "/v1/scan/result":
                return self._json(*gateway.scan_result(sid, body))
            if path == "/v1/scan/install/result":
                return self._json(*gateway.install_result(sid, body))
            if path == "/v1/gate/state":
                return self._json(*gateway.gate_write_state(sid, body))
            if path == "/v1/gate/events":
                return self._json(*gateway.gate_write_events(sid, body))
            return self._json(404, {"error": "no route"})

    return Handler


def make_server(host: str, port: int, *, ca_cert: str, ca_key: str, root_ca: str,
                server_cert: str, server_key: str, settings=None) -> ThreadingHTTPServer:
    ca = CertificateAuthority(ca_cert, ca_key, root_ca)
    gateway = Gateway(settings or get_settings(), ca)
    handler = _make_handler(gateway)
    httpd = ThreadingHTTPServer((host, port), handler)
    httpd.daemon_threads = True
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(server_cert, server_key)
    ctx.load_verify_locations(cafile=root_ca)
    # CERT_OPTIONAL lets /v1/enroll run without a client cert; every other route
    # rejects a missing certificate in _sensor(). A presented certificate is still
    # chain-verified by OpenSSL before the handler sees it.
    ctx.verify_mode = ssl.CERT_OPTIONAL
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    return httpd


def main() -> int:
    import argparse
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"),
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")
    ap = argparse.ArgumentParser(description="Weirvern mTLS weirling ingest gateway")
    ap.add_argument("--host", default=os.environ.get("WEIRLING_GATEWAY_HOST", "0.0.0.0"))
    ap.add_argument("--port", type=int, default=int(os.environ.get("WEIRLING_GATEWAY_PORT", "8443")))
    ap.add_argument("--ca-cert", default=os.environ.get("WEIRLING_CA_CERT", "/etc/weirling-ca/tls.crt"))
    ap.add_argument("--ca-key", default=os.environ.get("WEIRLING_CA_KEY", "/etc/weirling-ca/tls.key"))
    ap.add_argument("--root-ca", default=os.environ.get("WEIRLING_ROOT_CA", "/etc/weirling-root/root-ca.crt"))
    ap.add_argument("--server-cert", default=os.environ.get("WEIRLING_SERVER_CERT", "/etc/weirling-tls/tls.crt"))
    ap.add_argument("--server-key", default=os.environ.get("WEIRLING_SERVER_KEY", "/etc/weirling-tls/tls.key"))
    args = ap.parse_args()
    httpd = make_server(args.host, args.port, ca_cert=args.ca_cert, ca_key=args.ca_key,
                        root_ca=args.root_ca, server_cert=args.server_cert,
                        server_key=args.server_key)
    logger.info("weirling ingest gateway listening on %s:%s", args.host, args.port)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
