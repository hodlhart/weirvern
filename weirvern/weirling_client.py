"""The sensor side of the Weirling mTLS adoption contract.

WHAT THIS DOES. It generates a key and CSR on the sensor, sends the one-time enrollment
token to the hub, writes the issued certificate and the root chain beside the key, and
offers the authenticated calls the agent needs: heartbeat, plan and flow upload.

THE PRIVATE KEY NEVER LEAVES THE SENSOR. The gateway only ever sees the public CSR. The
certificate file contains the leaf plus the Weirling intermediate, because the server
trusts the root and a client that sends only the leaf cannot always build the chain.
"""
from __future__ import annotations

import argparse
import contextlib
import json
import os
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from weirvern.fleet import SensorPlan


class GatewayError(RuntimeError):
    """A gateway call failed. Callers decide whether that is retryable."""


@dataclass(frozen=True)
class Enrollment:
    sensor_id: str
    cert_path: str
    key_path: str
    ca_path: str
    expires_at: str


def _context(ca_path: str = "", cert_path: str = "", key_path: str = "") -> ssl.SSLContext:
    ctx = ssl.create_default_context(cafile=ca_path or None)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    if cert_path and key_path:
        ctx.load_cert_chain(cert_path, key_path)
    return ctx


def _open(request: urllib.request.Request, context: ssl.SSLContext, timeout: float = 15.0):
    try:
        return urllib.request.urlopen(request, timeout=timeout, context=context)
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:500]
        raise GatewayError(f"gateway returned HTTP {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise GatewayError(f"gateway is unreachable: {exc.reason}") from exc


def enroll(hub_url: str, token: str, sensor_id: str, out_dir: str,
           root_ca: str = "", *, address: str = "", segment: str = "",
           expected_mode: str = "loch") -> Enrollment:
    """Generate a key/CSR, redeem one token, write the chain. Returns the paths.

    The token is sent once. If the hub refuses it, no local file is written.
    """
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    with contextlib.suppress(OSError):
        os.chmod(out, 0o700)
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"weirling/{sensor_id}")]))
        .sign(key, hashes.SHA256())
    )
    body = json.dumps({
        "token": token,
        "sensor_id": sensor_id,
        "csr": csr.public_bytes(serialization.Encoding.PEM).decode("ascii"),
        "address": address,
        "segment": segment,
        "expected_mode": expected_mode,
    }).encode("utf-8")
    req = urllib.request.Request(
        f"{hub_url.rstrip('/')}/v1/enroll", data=body, method="POST",
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )
    ctx = _context(root_ca)
    with _open(req, ctx) as response:
        payload = json.loads(response.read().decode("utf-8"))
    if not payload.get("certificate"):
        raise GatewayError("the gateway returned no certificate")

    key_path = out / "weirling.key"
    cert_path = out / "weirling.crt"
    ca_path = out / "root-ca.crt"
    key_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    chain = payload["certificate"]
    if payload.get("intermediate"):
        chain += "\n" + payload["intermediate"]
    cert_path.write_text(chain)
    ca_path.write_text(payload.get("ca") or "")
    for path, mode in ((key_path, 0o600), (cert_path, 0o644), (ca_path, 0o644)):
        with contextlib.suppress(OSError):
            os.chmod(path, mode)
    return Enrollment(
        sensor_id=sensor_id, cert_path=str(cert_path), key_path=str(key_path),
        ca_path=str(ca_path), expires_at=str(payload.get("expires_at") or ""),
    )


class GatewayClient:
    """The authenticated sensor calls. `is_gateway` is the switch the agent reads."""

    is_gateway = True

    def __init__(self, base_url: str, cert_path: str, key_path: str, ca_path: str,
                 timeout: float = 15.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.cert_path = cert_path
        self.key_path = key_path
        self.ca_path = ca_path
        self.timeout = timeout
        self._ctx: ssl.SSLContext | None = None

    def _ssl(self) -> ssl.SSLContext:
        # Built lazily so constructing a client (and reading its configuration) does not
        # touch certificate files; the request path is where a missing credential belongs.
        if self._ctx is None:
            self._ctx = _context(self.ca_path, self.cert_path, self.key_path)
        return self._ctx

    def _request(self, method: str, path: str, payload: dict | None = None) -> dict:
        data = None
        headers = {"Accept": "application/json"}
        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(self.base_url + path, data=data, method=method,
                                     headers=headers)
        with _open(req, self._ssl(), self.timeout) as response:
            raw = response.read().decode("utf-8")
        try:
            parsed = json.loads(raw)
        except ValueError as exc:
            raise GatewayError("the gateway returned a non-JSON response") from exc
        if not isinstance(parsed, dict):
            raise GatewayError("the gateway returned a non-object response")
        return parsed

    def heartbeat(self, fields: dict) -> bool:
        return bool(self._request("POST", "/v1/heartbeat", fields).get("ok"))

    def plan(self) -> SensorPlan | None:
        payload = self._request("GET", "/v1/plan")
        plan = payload.get("plan")
        if not isinstance(plan, dict):
            return None
        return SensorPlan(
            mode=str(plan.get("mode") or ""),
            iface=str(plan.get("iface") or ""),
            segment=str(plan.get("segment") or ""),
            addr=str(plan.get("addr") or ""),
            gateway=str(plan.get("gateway") or ""),
            targets=str(plan.get("targets") or ""),
            nics=str(plan.get("nics") or ""),
        )

    def send_flows(self, records: list[dict]) -> int:
        if not records:
            return 0
        return int(self._request("POST", "/v1/flows", {"records": records}).get("inserted") or 0)

    def close(self) -> None:  # symmetry with the ClickHouse client; the transport owns no pool
        return None


def _main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="enroll a weirling with a one-time token")
    sub = ap.add_subparsers(dest="command", required=True)
    e = sub.add_parser("enroll")
    e.add_argument("--hub", required=True, help="gateway base URL, e.g. https://hub:30443")
    e.add_argument("--token", required=True, help="one-time enrollment token")
    e.add_argument("--sensor-id", required=True)
    e.add_argument("--dir", default="/etc/weirvern-weirling/pki")
    e.add_argument("--root-ca", default="", help="optional root CA used to verify the gateway")
    e.add_argument("--address", default="")
    e.add_argument("--segment", default="")
    e.add_argument("--mode", default="loch", choices=["loch", "siphon"])
    args = ap.parse_args(argv)
    result = enroll(args.hub, args.token, args.sensor_id, args.dir,
                    root_ca=args.root_ca, address=args.address, segment=args.segment,
                    expected_mode=args.mode)
    print(json.dumps(result.__dict__, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
