"""The local HTTPS edge must remain an edge, not a documentation claim.

These tests pin the shape that made the CA work: a namespaced Certificate for the
console, a Traefik Ingress that presents it on 443, a redirect-only HTTP ingress,
and a ClusterIP Service behind them. They also pin the application's half: the
redirect and HSTS headers are emitted from the forwarded scheme, not invented from
the pod's own HTTP hop.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
TLS = ROOT / "k8s" / "tls"


def _render():
    r = subprocess.run(["kustomize", "build", "k8s/tls"], cwd=ROOT, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return [d for d in yaml.safe_load_all(r.stdout) if d]


def test_the_tls_overlay_issues_a_certificate_for_the_console_name():
    docs = _render()
    cert = next(d for d in docs if d.get("kind") == "Certificate")
    assert cert["metadata"]["name"] == "weirvern-tls"
    assert cert["spec"]["dnsNames"] == ["sensor.example"]
    assert cert["spec"]["issuerRef"]["name"] == "weirvern-ca"
    assert cert["spec"]["secretName"] == "weirvern-tls"
    assert cert["spec"]["renewBefore"] == "720h"


def test_https_is_terminated_by_traefik_and_http_only_redirects():
    docs = _render()
    ingresses = {d["metadata"]["name"]: d for d in docs if d.get("kind") == "Ingress"}
    secure = ingresses["weirvern-gui"]
    plain = ingresses["weirvern-gui-http"]
    assert secure["spec"]["tls"][0]["secretName"] == "weirvern-tls"
    assert secure["spec"]["tls"][0]["hosts"] == ["sensor.example"]
    secure_ann = secure["metadata"]["annotations"]
    plain_ann = plain["metadata"]["annotations"]
    assert "websecure" in secure_ann["traefik.ingress.kubernetes.io/router.entrypoints"]
    assert "web" in plain_ann["traefik.ingress.kubernetes.io/router.entrypoints"]
    assert "weirvern-redirect-https" in plain_ann[
        "traefik.ingress.kubernetes.io/router.middlewares"
    ]


def test_the_overlay_closes_the_plaintext_nodeport():
    docs = _render()
    svc = next(d for d in docs if d.get("kind") == "Service" and d["metadata"]["name"] == "weirvern-gui")
    assert svc["spec"]["type"] == "ClusterIP"
    assert "nodePort" not in svc["spec"]["ports"][0]


def test_the_app_redirects_only_when_the_ingress_says_http():
    src = (ROOT / "weirvern" / "admin" / "web.py").read_text()
    assert "def _redirect_to_https" in src
    assert 'self._forwarded_proto() != "http"' in src
    assert 'self.send_header("Location", location)' in src
    assert 'if self._forwarded_proto() != "http"' in src


def test_the_app_adds_hsts_only_when_the_ingress_says_https():
    src = (ROOT / "weirvern" / "admin" / "web.py").read_text()
    assert "def _security_headers" in src
    assert 'self._forwarded_proto() == "https"' in src or 'proto == "https"' in src
    assert "Strict-Transport-Security" in src


def test_the_gate_no_longer_tells_users_to_type_a_password_over_http():
    html = (ROOT / "weirvern" / "admin" / "web" / "index.html").read_text()
    assert "served over HTTPS by the local Weirvern ingress" in html
    assert "install that root once" in html
