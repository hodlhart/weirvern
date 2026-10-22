"""mTLS is the default operating principle, not an operator-selected extra.

A hub install must create the CA/server certificate and run the ingest gateway without the
operator installing cert-manager or issuing certificates by hand. A weirling deploy must
adopt over mTLS unless the operator explicitly asks for the legacy database path.
"""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_the_gateway_is_part_of_the_base_install():
    kustomization = (ROOT / "k8s" / "kustomization.yaml").read_text()
    assert "mtls/gateway.yaml" in kustomization, (
        "the ingest gateway is not in the base install; a fresh hub would have no mTLS edge")
    assert "60-rbac.yaml" in kustomization


def test_the_installer_bootstraps_the_pki_before_applying_manifests():
    install = (ROOT / "install.sh").read_text()
    assert "bootstrap-mtls.sh" in install
    assert install.index("bootstrap-mtls.sh") < install.index("kubectl apply -k k8s/"), (
        "the gateway is applied before its CA/server secrets exist")


def test_the_bootstrap_script_creates_the_three_hub_secrets():
    script = (ROOT / "scripts" / "bootstrap-mtls.sh").read_text()
    for secret in ("weirling-root", "weirling-ca", "weirling-ingest-tls"):
        assert secret in script
    assert "openssl" in script
    assert "existing intermediate reused" in script, (
        "a re-run must not rotate the CA and invalidate enrolled sensors")


def test_weirling_deploy_defaults_to_mtls_with_an_explicit_legacy_opt_out():
    deploy = (ROOT / "scripts" / "deploy-weirling.sh").read_text()
    assert "MTLS=1" in deploy
    assert "--legacy-clickhouse" in deploy
    assert "MTLS=0" in deploy, "the legacy path must be explicitly selectable"
    assert "apply k8s/mtls first" not in deploy, (
        "the default deploy cannot tell the operator to apply an optional overlay first")


def test_the_gateway_is_the_shared_ingest_for_flows_and_zeek():
    gateway = (ROOT / "weirvern" / "weirling_gateway.py").read_text()
    assert "/v1/flows" in gateway
    assert "/v1/zeek" in gateway
    client = (ROOT / "weirvern" / "weirling_client.py").read_text()
    assert "def send_flows" in client and "def send_zeek" in client
