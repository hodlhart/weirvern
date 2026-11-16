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
    """The redirect belongs to the application too, not only to the Traefik middleware: a request
    that reaches the pod over plain HTTP still leaves for https, and a request that arrives with no
    forwarded scheme (a probe, a port-forward) is never bounced to a name that may not resolve."""
    import sys

    sys.path.insert(0, str(ROOT))
    from tests.support_routes import _Ctx
    from weirvern.admin import flask_app

    client = flask_app.create_app(_Ctx(), secret_key="tls-edge").test_client()

    plain = client.get("/api/healthz", headers={"X-Forwarded-Proto": "http"})
    assert plain.status_code == 308, plain.status_code
    assert plain.headers["Location"].startswith("https://"), plain.headers["Location"]

    secure = client.get("/api/healthz", headers={"X-Forwarded-Proto": "https"})
    assert secure.status_code == 200, secure.status_code

    direct = client.get("/api/healthz")
    assert direct.status_code == 200, (
        "a request with no forwarded scheme was redirected; a probe or a port-forward would break")

    src = (ROOT / "weirvern" / "admin" / "flask_app.py").read_text()
    assert "def _redirect_to_https" in src
    assert 'if _forwarded_proto() != "http"' in src, (
        "the redirect is not conditional on the ingress reporting http")


def test_the_app_adds_hsts_only_when_the_ingress_says_https():
    import sys

    sys.path.insert(0, str(ROOT))
    from tests.support_routes import _Ctx
    from weirvern.admin import flask_app

    client = flask_app.create_app(_Ctx(), secret_key="tls-edge").test_client()

    secure = client.get("/api/healthz", headers={"X-Forwarded-Proto": "https"})
    assert secure.status_code == 200
    assert "Strict-Transport-Security" in secure.headers, (
        "no HSTS header on a request the ingress says arrived over https")

    plain = client.get("/api/healthz")
    assert "Strict-Transport-Security" not in plain.headers, (
        "HSTS over a connection that is not known to be https would poison the browser")

    src = (ROOT / "weirvern" / "admin" / "flask_app.py").read_text()
    assert "def _security_headers" in src
    assert '_forwarded_proto() == "https"' in src
    assert "Strict-Transport-Security" in src


def test_the_gate_no_longer_tells_users_to_type_a_password_over_http():
    html = (ROOT / "weirvern" / "admin" / "web" / "index.html").read_text()
    assert "served over HTTPS by the local Weirvern ingress" in html
    assert "install that root once" in html
