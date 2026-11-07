"""The siphon overlay must actually widen, and the BASE must not.

Two failure directions matter, and they are opposites:

  * the overlay stops granting NET_ADMIN or stops setting the sysctls -> siphon silently
    cannot work, and the symptom is a refused write to /proc/sys that reads like a file
    permission problem
  * the base starts granting them -> every passive (loch) deployment acquires the ability
    to change node routing, which is exactly the privilege it was designed not to have

Both are asserted from the RENDERED output rather than by reading the YAML, because a
strategic-merge patch can fail to apply in ways that still look correct in the source.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


def _render(target: str) -> list[dict]:
    try:
        out = subprocess.run(["kustomize", "build", target], cwd=ROOT,
                             capture_output=True, text=True, timeout=120)
    except FileNotFoundError:
        pytest.skip("kustomize not installed")
    if out.returncode != 0:
        pytest.fail(f"kustomize build {target} failed: {out.stderr[:400]}")
    return [d for d in yaml.safe_load_all(out.stdout) if d]


def _zeek(docs: list[dict]) -> dict:
    for d in docs:
        if d.get("kind") == "DaemonSet" and d["metadata"]["name"] == "zeek":
            return d
    pytest.fail("no zeek DaemonSet in the rendered output")


def _caps(ds: dict) -> list[str]:
    return ds["spec"]["template"]["spec"]["containers"][0]["securityContext"]["capabilities"]["add"]


@pytest.mark.parametrize("target", ["k8s/", "overlays/siphon/"])
def test_the_overlay_does_not_break_the_base(target):
    """Both must render 22 resources and keep the sensor's real arguments.

    22 since issue #16: the backup engine's allow-list ConfigMap joined the base (ClickHouse
    refuses BACKUP ... TO Disk without it). The overlay builds on that same base, so both
    render it -- the count is pinned to catch a resource disappearing or the overlay silently
    dropping one, and it must be updated in the same commit that adds one.
    """
    docs = _render(target)
    assert len(docs) == 23, f"{target} rendered {len(docs)} resources"
    ds = _zeek(docs)
    c = ds["spec"]["template"]["spec"]["containers"][0]
    assert c.get("args"), "the startup script was lost"
    assert c.get("env"), "the env block was lost"
    assert ds["spec"]["template"]["spec"].get("hostNetwork") is True, (
        "hostNetwork was lost; the sensor sees no traffic without it and the sysctls "
        "would no longer be the node's"
    )


def test_the_base_grants_only_NET_RAW():
    """loch must not be able to change node routing."""
    caps = _caps(_zeek(_render("k8s/")))
    assert caps == ["NET_RAW"], (
        f"the base grants {caps}. It must stay NET_RAW only: NET_ADMIN lets the container "
        f"change IP forwarding and interface parameters on the NODE, and the passive "
        f"deployment is designed not to have that."
    )


def test_the_base_declares_no_sysctls():
    spec = _zeek(_render("k8s/"))["spec"]["template"]["spec"]
    assert not spec.get("securityContext", {}).get("sysctls"), (
        "the base sets sysctls; with hostNetwork those are the node's, so a passive "
        "deployment would be reconfiguring the host's routing"
    )


def test_the_overlay_grants_NET_ADMIN():
    caps = _caps(_zeek(_render("overlays/siphon/")))
    assert "NET_ADMIN" in caps, (
        "the overlay does not grant NET_ADMIN, so siphon cannot write the forwarding "
        "sysctls and cannot work at all"
    )
    assert "NET_RAW" in caps, "the overlay dropped NET_RAW, so capture stops working"


def test_the_overlay_does_NOT_declare_pod_sysctls():
    """Pod-level sysctls are REJECTED when hostNetwork is true.

    Verified against the live cluster -- the API server refuses the DaemonSet outright:

        spec.template.spec.securityContext.sysctls[0].name: Invalid value:
        "net.ipv4.ip_forward": may not be specified when 'hostNetwork' is true

    An earlier version of the overlay declared them, on the reasoning that `net.*` sysctls
    are namespaced and hostNetwork makes them the node's. The reasoning about the namespace
    was right; the conclusion about where to set them was not. The overlay therefore must
    NOT contain them, or `kubectl apply` fails and siphon cannot be deployed at all.
    """
    spec = _zeek(_render("overlays/siphon/"))["spec"]["template"]["spec"]
    declared = (spec.get("securityContext") or {}).get("sysctls")
    assert not declared, (
        f"the overlay declares pod sysctls {declared}, which Kubernetes rejects for a "
        f"hostNetwork pod. They belong on the node; the container inherits them."
    )


def test_the_overlay_documents_where_the_sysctls_go():
    """The requirement must still be discoverable from the overlay itself.

    Removing the declaration is correct, but the operator still needs to know the three
    settings and their symptoms -- otherwise the removal looks like the requirement was
    dropped rather than relocated.
    """
    text = (ROOT / "overlays" / "siphon" / "zeek-siphon-patch.yaml").read_text()
    for setting in ("net.ipv4.ip_forward", "rp_filter", "send_redirects"):
        assert setting in text, f"{setting} is no longer mentioned in the overlay"
    assert "may not be specified" in text or "rejects" in text.lower(), (
        "the overlay does not explain WHY the sysctls are absent, so a future reader is "
        "likely to re-add them and break the apply"
    )


def test_neither_manifest_weakened_the_rest_of_the_security_context():
    """Widening two capabilities must not quietly drop the other protections."""
    for target in ("k8s/", "overlays/siphon/"):
        c = _zeek(_render(target))["spec"]["template"]["spec"]["containers"][0]
        sc = c["securityContext"]
        assert sc["allowPrivilegeEscalation"] is False, f"{target}: privilege escalation"
        assert "ALL" in sc["capabilities"]["drop"], f"{target}: capabilities not dropped"
        assert sc["runAsUser"] == 0, (
            f"{target}: not uid 0. Kubernetes drops added capabilities for non-root "
            f"containers, so the grants would be decorative and capture would fail."
        )
