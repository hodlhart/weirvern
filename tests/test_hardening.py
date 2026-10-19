"""The hardening batch (GitHub #18, #22, #24, #25, #26, #27, #32).

Each test pins a fix that was verified against main on 2026-10-18 and imported from the GitHub
issues to the `weirvern-hardening` board. They are deliberately literal: these are claims to an
operator (images cannot drift, the installer's exit code is honest, credentials are per sensor,
the rollback contract is written down), so the text and the manifests are the artifact.
"""
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
K8S = ROOT / "k8s"


def _image_lines():
    files = list(K8S.rglob("*.yaml")) + list(K8S.rglob("*.template"))
    files += list((ROOT / "overlays").rglob("*.yaml"))
    files += [ROOT / "Containerfile", ROOT / "zeek" / "Containerfile"]
    for path in files:
        for i, line in enumerate(path.read_text().splitlines(), 1):
            if re.search(r"^\s*(image:|FROM)\s", line):
                yield path, i, line.strip()


def test_every_third_party_image_is_digest_pinned():
    third_party = ("busybox", "clickhouse/", "netsampler/", "python:", "zeek/zeek")
    offenders = []
    for path, line_no, line in _image_lines():
        if any(name in line for name in third_party) and "@sha256:" not in line:
            offenders.append(f"{path.relative_to(ROOT)}:{line_no}: {line}")
    assert not offenders, "unpinned third-party images: " + "; ".join(offenders)


def test_busybox_has_one_version():
    versions = {line.split("busybox:")[1].split("@")[0]
                for _, _, line in _image_lines() if "busybox:" in line}
    assert versions == {"1.37"}, f"busybox versions drifted: {sorted(versions)}"


def test_ci_pins_the_validator_and_reads_the_installer_kustomize_pin():
    ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text()
    assert "KUBECONFORM_VERSION: v0.8.0" in ci
    assert "CHECKSUMS" in ci and "sha256sum -c" in ci, "kubeconform is downloaded unverified"
    assert "releases/latest/download" not in ci
    assert 'sed -n \'s/^KUSTOMIZE_VERSION="\\(.*\\)"/\\1/p\' install.sh' in ci, \
        "CI keeps its own kustomize version instead of install.sh's"
    assert 'for d in overlays/*/' in ci, "overlays are not rendered in CI"


def test_the_prune_container_carries_the_same_hardening():
    docs = list(yaml.safe_load_all((K8S / "35-prune-cronjob.yaml").read_text()))
    cron = next(d for d in docs if d and d.get("kind") == "CronJob")
    pod = cron["spec"]["jobTemplate"]["spec"]["template"]["spec"]
    prune = next(c for c in pod["containers"] if c["name"] == "prune")
    sc = prune.get("securityContext") or {}
    assert sc.get("allowPrivilegeEscalation") is False
    assert sc.get("readOnlyRootFilesystem") is True
    assert sc.get("capabilities", {}).get("drop") == ["ALL"]
    mounts = {m["mountPath"]: m["name"] for m in prune["volumeMounts"]}
    assert "/tmp" in mounts, "read-only root without a writable /tmp"
    assert any(v.get("name") == mounts["/tmp"] and "emptyDir" in v for v in pod["volumes"])


def test_the_installer_is_honest_about_an_incomplete_deployment():
    sh = (ROOT / "install.sh").read_text()
    assert 'INSTALL_K3S_EXEC="server --secrets-encryption"' in sh
    assert "WITHOUT secrets encryption" in sh, "existing clusters get no warning"
    assert 'NOT_READY="$notready"' in sh
    block = sh[sh.index('if [ -n "${NOT_READY:-}" ]'):]
    assert "INCOMPLETE:" in block and "exit 1" in block, \
        "the installer still exits 0 after calling its own deployment incomplete"


def test_the_security_page_states_transport_secrets_and_credentials():
    sec = (ROOT / "docs" / "security.md").read_text()
    for heading in ("Transport and the trust boundary", "Secrets at rest",
                    "Per-weirling database credentials"):
        assert heading in sec, f"missing section: {heading}"
    assert "proxy_pass http://127.0.0.1:30088" in sec, "no worked TLS example"
    assert "port-forward" in sec and "ssh -L" in sec
    assert "k3s secrets-encrypt enable" in sec
    assert "DROP USER IF EXISTS" in sec


def test_the_rollback_contract_is_written_down():
    ops = (ROOT / "docs" / "operations.md").read_text()
    assert "### Upgrade and rollback" in ops
    assert "code\nrolls back, data does not" in ops
    assert "IfNotPresent" in ops and "sha-<previous>" in ops
    assert "superseded" in ops, "the model rollback path is missing"
    dep = (ROOT / "docs" / "deployment.md").read_text()
    assert "security.md#transport-and-the-trust-boundary" in dep


def test_deploy_weirling_issues_a_per_sensor_credential():
    sh = (ROOT / "scripts" / "deploy-weirling.sh").read_text()
    assert "WEIRVERN-SECRETS" not in sh.upper() or "CLICKHOUSE_PASSWORD" not in sh, \
        "the script still reads the hub's shared password"
    assert "CREATE USER IF NOT EXISTS" in sh and "ALTER USER" in sh
    assert "GRANT INSERT ON weirvern.*" in sh
    assert "sensor-credentials.tsv" in sh
    assert "DROP USER IF EXISTS" in sh, "removal does not revoke the credential"
    assert "CLICKHOUSE_USER=%s\\n' \"$CH_USER\"" in sh
