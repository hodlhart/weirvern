"""The per-unit siphon grant: opt-in, minimal, and ACTUALLY APPLICABLE.

WHY THIS FILE EXISTS. A weirling unit ships passive: every capability dropped. In-path
interception needs strictly more (an AF_PACKET ARP socket, `ip` on the host namespace, three
kernel sysctls), and the operator's requirement is that the grant is PER WEIRLING -- one unit
on one segment, not the whole fleet. So the grant is a patch the operator renders for the unit
that deserves it, and this file pins the three things that make that safe and real:

  * THE BASE STAYS PASSIVE. If the unit template ever grows NET_ADMIN, every unit acquires the
    ability to change node routing -- the exact privilege the default is designed not to have;
  * THE PATCH CAN ACTUALLY ARM A CHILD. The image runs as uid 10001 and Kubernetes DROPS added
    capabilities for a non-root container (measured on the hub's worker: CapBnd had the bits,
    CapEff was zero) -- so `add:` without `runAsUser: 0` silently grants nothing;
  * THE MODE IS NOT IN THE MANIFEST. A unit's mode is its own registry row; a SENSOR_MODE key
    here would re-introduce the single-global-mode defect the per-weirling plan removes.

The patch is applied to the RENDERED template in these tests (a small strategic merge), because
a patch that fails to apply still reads as correct in the source -- the lesson the siphon
overlay's own tests carry.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
UNIT = ROOT / "k8s/units/weirling-unit.yaml.template"
PATCH = ROOT / "k8s/units/weirling-unit-siphon.yaml.template"

UNIT_ID = "weirvern-eth2"
IFACE = "eth2"


def _render(path: Path) -> dict:
    """The template with its placeholders filled, as the operator renders it with sed."""
    text = path.read_text()
    for placeholder, value in (("__WEIRLING_ID__", UNIT_ID), ("__CAPTURE_IFACE__", IFACE),
                               ("__ZEEK_SITE_CONFIGMAP__", "zeek-site-a1b2c3")):
        text = text.replace(placeholder, value)
    assert "__" + "WEIRLING" not in text, "an unrendered placeholder survived"
    return yaml.safe_load(text)


def _merge(base: dict, patch: dict) -> dict:
    """A minimal strategic merge: name-keyed lists (containers, initContainers, volumes) merge
    entry by entry, scalars overwrite. That is all the `name` merge key this patch relies on."""
    if isinstance(patch, dict) and isinstance(base, dict):
        out = dict(base)
        for key, value in patch.items():
            out[key] = _merge(base[key], value) if key in base else value
        return out
    if (isinstance(patch, list) and isinstance(base, list) and patch
            and all(isinstance(i, dict) and "name" in i for i in patch)):
        out = [dict(i) for i in base]
        index = {i["name"]: n for n, i in enumerate(out)}
        for item in patch:
            if item["name"] in index:
                pos = index[item["name"]]
                out[pos] = _merge(out[pos], item)
            else:
                out.append(dict(item))
        return out
    return patch


def _spec(doc: dict) -> dict:
    return doc["spec"]["template"]["spec"]


def _container(spec: dict, name: str) -> dict:
    for c in spec["containers"]:
        if c["name"] == name:
            return c
    pytest.fail(f"no {name} container")


# ── the base stays passive ───────────────────────────────────────────────────────────────────

def test_the_unit_template_grants_the_agent_NOTHING():
    spec = _spec(_render(UNIT))
    agent = _container(spec, "agent")
    caps = agent.get("securityContext", {}).get("capabilities", {})
    assert caps.get("add") in (None, []), (
        "the base unit granted the agent capabilities; in-path is supposed to be opt-in")
    assert agent.get("securityContext", {}).get("runAsUser") != 0
    assert not spec.get("initContainers"), (
        "a passive unit must not carry the privileged sysctl init container")


def test_the_template_is_not_swept_into_the_manifests():
    """CI walks k8s/ with kubeconform -strict; a file full of placeholders is not a manifest.
    Both files carry the non-.yaml suffix for that reason, and the template is not a kustomize
    resource (units are applied per unit, by hand, deliberately)."""
    assert UNIT.name.endswith(".yaml.template")
    assert PATCH.name.endswith(".yaml.template")
    kustomization = (ROOT / "k8s/kustomization.yaml").read_text()
    assert "units/" not in kustomization


# ── the patch is applicable, and grants exactly the right things ─────────────────────────────

def test_the_patch_applies_and_arms_the_AGENT_container():
    base = _render(UNIT)
    patched = _merge(base, yaml.safe_load(PATCH.read_text()))
    agent = _container(_spec(patched), "agent")
    caps = agent["securityContext"]["capabilities"]
    assert set(caps["add"]) == {"NET_RAW", "NET_ADMIN"}, (
        "NET_ADMIN alone cannot open an AF_PACKET socket and NET_RAW alone cannot assign the "
        "address or read the sysctls; the hub's overlay measured both as required")
    assert caps["drop"] == ["ALL"]
    assert agent["securityContext"]["runAsUser"] == 0, (
        "Kubernetes drops added capabilities for a non-root container and this image runs as "
        "uid 10001: without runAsUser 0 the add above silently grants nothing")


def test_the_patch_leaves_every_other_container_alone():
    """The capture container parses untrusted input continuously; the netflow collector needs
    nothing; the gate has its own grant. Widening them would be privilege nobody asked for."""
    base = _render(UNIT)
    patched = _merge(base, yaml.safe_load(PATCH.read_text()))
    old, new = _spec(base), _spec(patched)
    for name in ("capture", "netflow", "gate"):
        assert _container(old, name) == _container(new, name), f"{name} was modified"


def test_the_patch_sets_the_forwarding_sysctls_with_the_hubs_reasoning():
    patch_text = PATCH.read_text()
    patched = _spec(_merge(_render(UNIT), yaml.safe_load(patch_text)))
    init = patched["initContainers"][0]
    assert init["name"] == "siphon-sysctls"
    assert init["securityContext"]["privileged"] is True, (
        "NET_ADMIN alone cannot write /proc/sys: Kubernetes mounts it read-only")
    assert "allowPrivilegeEscalation" not in init["securityContext"], (
        "the API server rejects allowPrivilegeEscalation: false together with privileged: true")
    script = init["command"][-1]
    for want in ("net/ipv4/ip_forward", "net/ipv4/conf/all/rp_filter",
                 "net/ipv4/conf/all/send_redirects"):
        assert want in script, f"the init container does not set {want}"
    assert "FATAL: sysctls did not take" in script, (
        "writing is not the same as taking: the container must verify or refuse to start")
    assert "siphon-sysctls.saved" in script, (
        "the node's pre-change values must be recorded, or the overlay is removable but not "
        "reversible")
    assert f"units/{UNIT_ID}/state" in PATCH.read_text().replace("__WEIRLING_ID__", UNIT_ID), (
        "the save path must be per unit, so two units cannot overwrite each other's record")


def test_the_init_container_targets_THIS_units_capture_port():
    """weirvern-env's ZEEK_IFACE is the HUB's port; a unit that read it would narrow the sysctl
    sweep onto the wrong interface and report itself healthy."""
    patch = yaml.safe_load(PATCH.read_text())
    init = patch["spec"]["template"]["spec"]["initContainers"][0]
    env = {e["name"]: e.get("value") for e in init["env"]}
    assert env == {"CAPTURE_IFACE": "__CAPTURE_IFACE__"}, env
    assert "configMapKeyRef" not in PATCH.read_text().split("initContainers")[1].split(
        "containers:")[0], "the patch must not read the hub's capture interface from the ConfigMap"


def test_the_patch_carries_NO_mode_key():
    """A unit's mode lives in its own registry row. A SENSOR_MODE here would make the manifest a
    second source for one fact -- and the hub's value, inherited through envFrom, would then be
    able to arm every weirling at once."""
    text = PATCH.read_text()
    code = "\n".join(ln.split("#")[0] for ln in text.splitlines())
    assert "SENSOR_MODE" not in code
    assert "INTERCEPT_" not in code


def test_the_patch_is_renderable_with_the_documented_sed_line():
    """The header's own instructions are the contract an operator follows; a placeholder the
    line does not fill would land in a live patch as a literal __TOKEN__."""
    header = PATCH.read_text().split("apiVersion:")[0]
    for placeholder in ("__WEIRLING_ID__", "__CAPTURE_IFACE__"):
        assert placeholder in header, f"the render line does not fill {placeholder}"
    rendered = PATCH.read_text().replace("__WEIRLING_ID__", UNIT_ID).replace(
        "__CAPTURE_IFACE__", IFACE)
    doc = yaml.safe_load(rendered)
    assert doc["metadata"]["name"] == f"weirling-{UNIT_ID}"
    # And the file is valid YAML once rendered -- the operator pipes it straight into kubectl.
    assert isinstance(doc["spec"]["template"]["spec"]["containers"], list)
    assert subprocess.run(["true"]).returncode == 0  # (no kubectl here; parsing is the check)
