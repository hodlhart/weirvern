"""The plan the operator chose decides the capabilities the worker is granted.

The bug these pin: an applied plan came up unable to open a capture socket because the
Deployment still dropped every capability, and the operator had no way to know from the UI
that a second, invisible step was required.
"""
from __future__ import annotations

from weirvern.admin import cluster_config as cc


def test_a_passive_sensor_gets_nothing():
    caps = cc.required_capabilities({"SENSOR_MODE": "loch", "NETFLOW_MODE": "auto",
                                     "SIPHON_NETFLOW": "0", "CHANNEL_NETFLOW": "off"})
    assert caps == set()


def test_an_active_tap_is_not_the_WORKERS_grant():
    """THE MEASURED BUG THIS PINS. The worker used to be granted NET_RAW for an active tap, and
    the grant was inert: it runs as uid 10001, and Kubernetes drops added capabilities for a
    non-root container (CapEff read 0000000000000000 in the live pod). The tap now runs in the
    Zeek sidecar, which is root; granting the worker again would recreate the false assurance."""
    caps = cc.required_capabilities({"SENSOR_MODE": "loch", "NETFLOW_MODE": "active"})
    assert caps == set()


def test_a_siphon_needs_both_and_that_is_strictly_more():
    siphon = cc.required_capabilities({"SENSOR_MODE": "siphon"})
    active = cc.required_capabilities({"NETFLOW_MODE": "active"})
    assert siphon == {"NET_RAW", "NET_ADMIN"}
    assert siphon > active


def test_the_legacy_siphon_flag_implies_siphon():
    assert cc.required_capabilities({"SENSOR_MODE": "loch", "SIPHON_NETFLOW": "1"}) == {
        "NET_RAW", "NET_ADMIN"}


def test_a_channel_selection_is_not_the_WORKERS_grant_either():
    assert cc.required_capabilities({"CHANNEL_NETFLOW": "upstream"}) == set()


def test_the_patch_is_surgical_and_refuses_the_wrong_container():
    ops = cc.capability_patch(0, "worker", {"NET_RAW"}, has_capabilities=True)
    assert ops[0] == {"op": "test", "path": "/spec/template/spec/containers/0/name",
                      "value": "worker"}
    assert ops[1]["op"] == "replace"
    assert ops[1]["value"] == {"drop": ["ALL"], "add": ["NET_RAW"]}


def test_a_container_with_no_capability_block_gets_one_added():
    ops = cc.capability_patch(2, "worker", set(), has_capabilities=False)
    assert ops[1]["op"] == "add"
    assert ops[1]["value"] == {"drop": ["ALL"]}


def test_passive_patch_drops_everything_and_adds_nothing():
    ops = cc.capability_patch(0, "worker", set(), has_capabilities=True)
    assert ops[1]["value"] == {"drop": ["ALL"]}


# ── the POSTURE, without which the grant is inert (measured 2026-11-17) ────────────────────────
#
# The live worker ran as uid 10001 with runAsNonRoot:true, so CapEff read 0000000000000000 even
# with NET_ADMIN and NET_RAW in the bounding set, and it did not run hostNetwork, so it saw only
# lo and eth0. A capability add alone therefore produced a deployment that read as configured and
# could do neither of the two things siphon needs.

class _FakeWorkload(cc.ClusterConfig):
    def __init__(self, workload, config):
        self._workload = workload
        self._config = config
        self.patched = None
        # The real constructor reads the in-cluster token and CA; this fake never makes a call,
        # but `reconcile_capabilities` builds the URL from these two attributes before patching.
        self.api_host = "https://cluster.invalid"
        self.namespace = "weirvern"

    def read(self):
        return dict(self._config)

    def _request_url(self, method, url):  # noqa: ARG002 - signature matches the base
        return self._workload

    def _patch_json(self, url, ops):  # noqa: ARG002
        self.patched = ops


def _workload(host_network=False, pod_sc=None, container_sc=None):
    return {"spec": {"template": {"spec": {
        "hostNetwork": host_network,
        "dnsPolicy": "ClusterFirst" if not host_network else "ClusterFirstWithHostNet",
        "securityContext": pod_sc if pod_sc is not None else {
            "runAsUser": 10001, "runAsGroup": 10001, "runAsNonRoot": True,
            "fsGroup": 10001, "seccompProfile": {"type": "RuntimeDefault"}},
        "containers": [{"name": "worker", "securityContext": container_sc or {
            "allowPrivilegeEscalation": False,
            "capabilities": {"drop": ["ALL"]}}}],
    }}}}


def test_a_siphon_plan_grants_the_WHOLE_POSTURE_not_only_the_capabilities():
    client = _FakeWorkload(_workload(), {"SENSOR_MODE": "siphon"})
    result = client.reconcile_capabilities("weirvern-worker")
    assert result["changed"] is True and result["posture"] == "siphon"
    paths = {op["path"]: op.get("value") for op in client.patched if op["op"] != "test"}
    assert paths["/spec/template/spec/hostNetwork"] is True
    assert paths["/spec/template/spec/dnsPolicy"] == "ClusterFirstWithHostNet"
    assert paths["/spec/template/spec/securityContext"]["runAsNonRoot"] is False
    assert paths["/spec/template/spec/securityContext"]["runAsUser"] == 0
    assert paths["/spec/template/spec/containers/0/securityContext/runAsUser"] == 0
    caps = paths["/spec/template/spec/containers/0/securityContext/capabilities"]
    assert caps["add"] == ["NET_ADMIN", "NET_RAW"]


def test_a_passive_plan_puts_the_posture_BACK():
    client = _FakeWorkload(
        _workload(host_network=True,
                  pod_sc={"runAsUser": 0, "runAsGroup": 0, "runAsNonRoot": False},
                  container_sc={"runAsUser": 0, "runAsGroup": 0,
                                "capabilities": {"drop": ["ALL"],
                                                 "add": ["NET_ADMIN", "NET_RAW"]}}),
        {"SENSOR_MODE": "loch"})
    result = client.reconcile_capabilities("weirvern-worker")
    assert result["changed"] is True and result["posture"] == "passive"
    paths = {op["path"]: op for op in client.patched if op["op"] == "add"}
    assert paths["/spec/template/spec/hostNetwork"]["value"] is False
    assert paths["/spec/template/spec/securityContext"]["value"]["runAsNonRoot"] is True
    assert paths["/spec/template/spec/securityContext"]["value"]["runAsUser"] == 10001


def test_a_deployment_already_in_siphon_posture_is_left_alone():
    """Idempotence: the five-minute restart must not re-patch a worker that is already right."""
    client = _FakeWorkload(
        _workload(host_network=True,
                  pod_sc={"runAsUser": 0, "runAsGroup": 0, "runAsNonRoot": False},
                  container_sc={"runAsUser": 0, "runAsGroup": 0,
                                "capabilities": {"drop": ["ALL"],
                                                 "add": ["NET_ADMIN", "NET_RAW"]}}),
        {"SENSOR_MODE": "siphon"})
    assert client.reconcile_capabilities("weirvern-worker")["changed"] is False
    assert client.patched is None, "an already-correct worker was patched again"

