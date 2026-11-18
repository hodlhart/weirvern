"""The GUI's own RBAC must not be a path to the node filesystem.

── WHY THIS FILE EXISTS (audit F017, CONFIRMED AGAINST A LIVE CLUSTER) ──────────────────────────

`k8s/60-rbac.yaml` granted the GUI's ServiceAccount `patch`/`update` on the WHOLE `daemonsets`
resource. `ds/zeek` is `privileged: true`, holds `CAP_NET_RAW`, and mounts host paths -- and it has
to be, because a capture sensor needs those capabilities. So the operator role could rewrite it.
Measured with a server-side dry run, which validates the request fully without writing it:

    kubectl patch ds/zeek --as=system:serviceaccount:<ns>:weirvern-operator \\
      -p '{"spec":{"template":{"spec":{"volumes":[{"name":"host-root",
           "hostPath":{"path":"/"}}]}}}}' --dry-run=server
    -> daemonset.apps/zeek patched

The only objection was a PodSecurity WARNING. The namespace is labelled
`pod-security.kubernetes.io/enforce: privileged`, deliberately, because the sensor needs those
capabilities -- so nothing enforced it. A compromised GUI pod could mount the node filesystem on
every node, and the GUI is a NodePort HTTP service with password auth, which makes "a compromised
GUI pod" a realistic assumption rather than a hypothetical.

WHAT THESE TESTS PIN, and why they are structural rather than behavioural:

`resourceNames` CANNOT BE TESTED BY RUNNING THE PRODUCT. A test can assert that the manifest uses
it; only the API server can confirm the resulting grant, which is why the verification for this fix
was `kubectl auth can-i` and a dry-run patch against the live cluster. What a test CAN do is hold
the line: the escalation came from a broad verb list, and the cheapest way to reintroduce it is a
careless edit that widens `names:` back to nothing. Each assertion below names the specific way that
could happen.
"""

from __future__ import annotations

import pathlib

import pytest
import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
RBAC = ROOT / "k8s" / "60-rbac.yaml"


def _docs() -> list[dict]:
    return [d for d in yaml.safe_load_all(RBAC.read_text()) if d]


def _role(name: str) -> dict:
    for d in _docs():
        if d.get("kind") == "Role" and d["metadata"]["name"] == name:
            return d
    pytest.fail(f"no Role named {name!r} in {RBAC.name}")


def _rules_for(role: dict, resource: str) -> list[dict]:
    return [r for r in role.get("rules", []) if resource in (r.get("resources") or [])]


def _scoped_names(role: dict, resource: str, verb: str) -> set[str] | None:
    """The resourceNames covering `verb` on `resource`, or None if that VERB is unscoped.

    ASKED PER VERB, which the first version of this helper got wrong. It looked at every rule
    mentioning the resource and returned None if any of them lacked `resourceNames` -- but a rule
    granting `get`/`list` on all daemonsets is correct and expected (the GUI lists workloads to
    display them), so that check failed on the manifest being RIGHT. What matters is whether the
    WRITE verb is scoped, since reading a workload does not change it.

    None is still the dangerous answer for a write verb: Kubernetes grants are the UNION of rules,
    so a second, unscoped rule granting the same verb is exactly how a scoped grant gets widened.
    """
    write_rules = [
        r for r in _rules_for(role, resource)
        if verb in (r.get("verbs") or [])
    ]
    if not write_rules:
        return set()
    names: set[str] = set()
    for r in write_rules:
        rn = r.get("resourceNames")
        if not rn:
            return None
        names |= set(rn)
    return names


# ── the escalation path itself ───────────────────────────────────────────────────────────────

def test_the_operator_role_cannot_patch_EVERY_daemonset():
    """THE FINDING. `ds/zeek` is privileged and host-mounting, so an unscoped patch on daemonsets
    is a route to root on every node."""
    names = _scoped_names(_role("weirvern-operator"), "daemonsets", "patch")
    assert names is not None, (
        "the operator role can patch daemonsets WITHOUT a resourceNames restriction. ds/zeek is "
        "privileged and mounts host paths, so this is a path to the node filesystem (audit F017)"
    )
    assert names <= {"zeek"}, (
        f"the operator role may patch daemonsets it has no reason to touch: {sorted(names - {'zeek'})}"
    )


def test_the_operator_role_cannot_patch_EVERY_deployment():
    """The same shape on deployments. Less severe than daemonsets only because a Deployment is not
    privileged here -- but `update` on it would strip securityContext from the worker, and the
    grant is not needed either way.

    goflow2 joined the list with 0.23.72: its launcher reads NETFLOW_IFACE at start, so a NIC
    added in the console takes effect only by restarting the collector. The allowlist is
    extended here, deliberately, rather than by removing the restriction."""
    names = _scoped_names(_role("weirvern-operator"), "deployments", "patch")
    assert names is not None, (
        "the operator role can patch deployments without a resourceNames restriction"
    )
    assert names <= {"weirvern-worker", "weirvern-gui", "goflow2"}, (
        f"the operator role may patch deployments it has no reason to touch: "
        f"{sorted(names - {'weirvern-worker', 'weirvern-gui', 'goflow2'})}"
    )


def test_the_three_restart_targets_are_exactly_what_the_settings_path_needs():
    """The grant is derived from `_RESTART_FOR`, so if that table grows a target, this test fails
    and the reviewer has to decide whether the RBAC should grow with it.

    Asserted by READING the table rather than restating it: a hardcoded list here would drift out
    of step with the code that actually restarts things, and the failure would be a settings change
    that silently does not take effect.
    """
    from weirvern.admin import cluster_config as cc

    needed: set[str] = set()
    for targets, _blast in cc._RESTART_FOR.values():
        for t in targets:
            kind, _, name = t.partition("/")
            needed.add({"ds": "daemonsets", "deploy": "deployments"}.get(kind, kind) + ":" + name)

    role = _role("weirvern-operator")
    granted: set[str] = set()
    for resource in ("daemonsets", "deployments"):
        names = _scoped_names(role, resource, "patch")
        for n in names or set():
            granted.add(f"{resource}:{n}")

    missing = needed - granted
    assert not missing, (
        f"the settings path restarts {sorted(missing)} but the operator role may not patch them, so "
        f"those settings would save and never take effect"
    )


def test_the_operator_role_cannot_UPDATE_any_workload():
    """`update` is a full replace. A PATCH with a merge is bounded by what the caller sends; a PUT
    replaces the whole object, so one malformed request can strip a workload's securityContext --
    on a Deployment that is a soft failure, and on the privileged capture DaemonSet it is not.
    Nothing in the product needs `update` on a workload: restarts PATCH and stop/start scales."""
    for resource in ("daemonsets", "deployments", "statefulsets", "replicasets"):
        for r in _rules_for(_role("weirvern-operator"), resource):
            assert "update" not in (r.get("verbs") or []), (
                f"the operator role may UPDATE {resource}, which replaces the entire object: {r}"
            )


def test_the_operator_role_cannot_reach_SECRETS():
    """The GUI authenticates with its own store and never reads the cluster Secret; the worker gets
    its values through envFrom at container start."""
    for r in _role("weirvern-operator").get("rules", []):
        assert "secrets" not in (r.get("resources") or []), (
            f"the operator role can reach secrets, which the GUI has never needed: {r}"
        )


# ── and it must still be able to do its job ──────────────────────────────────────────────────

def test_the_operator_role_keeps_the_grants_the_product_uses():
    """A security fix that removes a needed permission produces a broken product, and the failure
    surfaces later as an unrelated-looking error. Each entry is a call the code actually makes."""
    role = _role("weirvern-operator")

    def verbs_for(resource: str) -> set[str]:
        out: set[str] = set()
        for r in _rules_for(role, resource):
            out |= set(r.get("verbs") or [])
        return out

    assert {"get", "list"} <= verbs_for("pods"), "the GUI lists and reads pods"
    assert {"get", "create"} <= verbs_for("pods/log") | verbs_for("pods"), (
        "the GUI streams pod logs (and the tunnel needs the portforward subresource)"
    )
    assert "create" in verbs_for("jobs"), (
        "the Sonar survey CREATES a Job; without this the survey fails at request time"
    )
    assert "patch" in verbs_for("configmaps"), (
        "the settings path patches weirvern-env"
    )
    scale_verbs = set()
    for r in _rules_for(role, "deployments/scale"):
        scale_verbs |= set(r.get("verbs") or [])
    assert "patch" in scale_verbs, "`weirvern stop`/`start` scales deployments"


def test_the_VIEWER_role_is_still_read_only():
    """The viewer is a separate account for read-only access, and the whole point of it is that it
    cannot change anything. A widened operator role is a nuisance; a widened viewer is a hole.

    ONE SUBRESOURCE IS EXEMPT, and the exemption is the assertion's point. `create` on
    `pods/portforward` is a POST, but it does not write anything: it opens a tunnel to a container's
    network, which is how `weirvern status` reaches ClickHouse without publishing a port (see
    admin/tunnel.py for why that trade was made). Treating it as a write verb would force the
    viewer's own tunnel path to be either broken or silently privileged.
    """
    exempt = {("create", "pods/portforward")}
    role = _role("weirvern-viewer")
    for r in role.get("rules", []):
        verbs = set(r.get("verbs") or [])
        resources = set(r.get("resources") or [])
        for verb in verbs - {"get", "list"}:
            assert all((verb, res) in exempt for res in resources), (
                f"the viewer role has a write verb not on the exemption list: {verb} on "
                f"{sorted(resources)}"
            )
