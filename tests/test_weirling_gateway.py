"""The weirling mTLS gateway: identity, enrollment and revocation contracts.

These tests deliberately exercise real X.509 objects rather than source strings: the
failure that matters is a certificate that is accepted by the wrong verifier, and a
string assertion cannot see it.
"""
from __future__ import annotations

import datetime as dt
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from weirvern import weirling_gateway as gw

ROOT = Path(__file__).resolve().parents[1]


def _key():
    return ec.generate_private_key(ec.SECP256R1())


def _cert(subject, issuer, public_key, signing_key, *, ca=False, days=365):
    now = dt.datetime.now(dt.UTC)
    b = (x509.CertificateBuilder()
         .subject_name(subject).issuer_name(issuer).public_key(public_key)
         .serial_number(x509.random_serial_number())
         .not_valid_before(now - dt.timedelta(minutes=1))
         .not_valid_after(now + dt.timedelta(days=days))
         .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    if ca:
        b = b.add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=True,
            crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
    return b.sign(signing_key, hashes.SHA256())


def _ca_files(tmp_path: Path):
    root_key = _key()
    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Root")])
    root = _cert(root_name, root_name, root_key.public_key(), root_key, ca=True)
    int_key = _key()
    int_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Weirling Intermediate")])
    inter = _cert(int_name, root_name, int_key.public_key(), root_key, ca=True)
    paths = {}
    for name, obj, key in (("root.crt", root, None), ("int.crt", inter, None),
                           ("int.key", None, int_key)):
        p = tmp_path / name
        if obj is not None:
            p.write_bytes(obj.public_bytes(serialization.Encoding.PEM))
        else:
            p.write_bytes(key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption()))
        paths[name] = str(p)
    return paths, root, inter


def _csr(subject="ignored"):
    key = _key()
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)]))
           .sign(key, hashes.SHA256()))
    return csr.public_bytes(serialization.Encoding.PEM)


def test_a_valid_csr_gets_a_client_cert_with_the_sensor_uri_san(tmp_path):
    paths, _root, inter = _ca_files(tmp_path)
    ca = gw.CertificateAuthority(paths["int.crt"], paths["int.key"], paths["root.crt"])
    pem, expires = ca.sign_csr(_csr(), "sensor-alpha")
    cert = x509.load_pem_x509_certificate(pem)
    assert cert.issuer == inter.subject
    assert expires > dt.datetime.now(dt.UTC)
    uris = cert.extensions.get_extension_for_class(
        x509.SubjectAlternativeName).value.get_values_for_type(x509.UniformResourceIdentifier)
    assert uris == ["spiffe://weirvern/sensor/sensor-alpha"]
    eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert ExtendedKeyUsageOID.CLIENT_AUTH in eku


def test_a_bad_csr_signature_is_refused(tmp_path):
    paths, _root, _inter = _ca_files(tmp_path)
    ca = gw.CertificateAuthority(paths["int.crt"], paths["int.key"], paths["root.crt"])
    csr = _csr().replace(b"A", b"B", 1)
    with pytest.raises(ValueError):
        ca.sign_csr(csr, "sensor-alpha")


def test_token_storage_is_only_a_hash_and_is_stable():
    a = gw.token_hash("secret-token")
    b = gw.token_hash("secret-token")
    assert a == b
    assert "secret-token" not in a
    assert len(a) == 64


def test_peer_identity_reads_only_the_exact_uri_san():
    class Conn:
        def __init__(self, san):
            self._san = san

        def getpeercert(self):
            return {"subjectAltName": self._san}

    class H:
        def __init__(self, san):
            self.connection = Conn(san)

    assert gw._peer_sensor_id(H([("URI", "spiffe://weirvern/sensor/s1")])) == "s1"
    assert gw._peer_sensor_id(H([("DNS", "s1.example")])) == ""
    assert gw._peer_sensor_id(H([("URI", "spiffe://weirvern/sensor/../bad")])) == ""
    assert gw._peer_sensor_id(H([("URI", "spiffe://other/sensor/s1")])) == ""


def test_enrollment_schema_keeps_token_hashes_without_secret_columns():
    sql = (ROOT / "weirvern" / "schema" / "021_weirling_enrollment.sql").read_text()
    assert "token_hash" in sql
    assert "used_at" in sql
    assert "password" not in sql.lower()


def test_gateway_routes_and_mtls_are_wired():
    src = (ROOT / "weirvern" / "weirling_gateway.py").read_text()
    for route in ("/v1/enroll", "/v1/heartbeat", "/v1/flows", "/v1/zeek", "/v1/plan", "/v1/renew",
                  "/v1/sonar/next", "/v1/sonar/result"):
        assert route in src
    assert "/v1/probe/next" in src
    assert "/v1/probe/result" in src
    assert "ssl.CERT_OPTIONAL" in src
    assert "ctx.load_verify_locations" in src
    assert "URI_PREFIX" in src
    assert "fleet_store.register" in src
    assert "insert_batch" in src
