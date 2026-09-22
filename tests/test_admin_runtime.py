"""Admin layer tests: project discovery, cluster capability detection, and the
kubectl command construction the control plane depends on.

These lock in the behaviour that makes the control plane safe to hand to an
operator: it must work from any cwd, must not invent a cluster that isn't there,
and must never run a destructive command that could delete data or hang waiting
for input.
"""
import json
import re
from pathlib import Path

import pytest

from weirvern.admin import runtime as rt


# --- project discovery -------------------------------------------------------
def test_find_project_dir_from_nested_path(tmp_path):
    (tmp_path / ".env.example").write_text("X=1\n")
    nested = tmp_path / "a" / "b" / "c"
    nested.mkdir(parents=True)
    assert rt.find_project_dir(nested) == tmp_path


def test_find_project_dir_uses_env_home(tmp_path, monkeypatch):
    k8s = tmp_path / "k8s"
    k8s.mkdir()
    (k8s / "kustomization.yaml").write_text("resources: []\n")
    monkeypatch.setenv("WEIRVERN_HOME", str(tmp_path))
    other = tmp_path / "elsewhere"
    other.mkdir()
    assert rt.find_project_dir(other) == tmp_path


def test_find_project_dir_rejects_bogus_env_home(tmp_path, monkeypatch):
    """A bad WEIRVERN_HOME must fail loudly rather than silently operating on
    some other directory the user did not intend."""
    empty = tmp_path / "empty"
    empty.mkdir()
    monkeypatch.setenv("WEIRVERN_HOME", str(empty))
    with pytest.raises(FileNotFoundError, match="WEIRVERN_HOME"):
        rt.find_project_dir(tmp_path)


def test_find_project_dir_raises_when_nothing_matches(tmp_path, monkeypatch):
    monkeypatch.delenv("WEIRVERN_HOME", raising=False)
    monkeypatch.setattr(rt, "__file__", str(tmp_path / "x" / "y" / "z" / "runtime.py"))
    with pytest.raises(FileNotFoundError, match="WEIRVERN_HOME|locate"):
        rt.find_project_dir(tmp_path)


# --- capability detection ----------------------------------------------------
def _fake_run(monkeypatch, results, calls=None):
    """Install a fake _run. `results` maps a substring of the command to
    (ok, stdout). Anything unmatched is treated as a failure."""
    def fake(args, cwd, timeout=None):
        if calls is not None:
            calls.append(args)
        joined = " ".join(args)
        for needle, (ok, out) in results.items():
            if needle in joined:
                return rt.CommandResult(ok=ok, stdout=out, code=0 if ok else 1)
        return rt.CommandResult(ok=False, stderr="unexpected command", code=1)

    monkeypatch.setattr(rt, "_run", fake)


def test_capabilities_reports_missing_kubectl(monkeypatch, tmp_path):
    monkeypatch.setattr(rt.shutil, "which", lambda _n: None)
    caps = rt.detect_capabilities(tmp_path)
    assert caps.kubectl is False
    assert caps.cluster_available is False
    assert "kubectl" in caps.reason.lower()


def test_capabilities_reports_unreachable_cluster(monkeypatch, tmp_path):
    """kubectl present but pointing nowhere is a distinct state from 'not
    installed' — the operator's fix is different."""
    monkeypatch.setattr(rt.shutil, "which", lambda _n: "/usr/bin/kubectl")
    _fake_run(monkeypatch, {"version": (False, "")})
    caps = rt.detect_capabilities(tmp_path)
    assert caps.kubectl is True
    assert caps.kubeconfig is False
    assert caps.cluster_available is False
    assert "kubeconfig" in caps.reason.lower() or "cluster" in caps.reason.lower()


def test_capabilities_reports_missing_namespace(monkeypatch, tmp_path):
    """Cluster reachable but the manifests never applied: the reason must say so,
    because that is exactly the first-run state."""
    monkeypatch.setattr(rt.shutil, "which", lambda _n: "/usr/bin/kubectl")
    _fake_run(monkeypatch, {
        "version": (True, '{"clientVersion":{}}'),
        "get namespace": (False, ""),
    })
    caps = rt.detect_capabilities(tmp_path)
    assert caps.kubeconfig is True
    assert caps.namespace is False
    assert "namespace" in caps.reason.lower()


def test_capabilities_full_when_everything_present(monkeypatch, tmp_path):
    k8s = tmp_path / "k8s"
    k8s.mkdir()
    (k8s / "kustomization.yaml").write_text("resources: []\n")
    monkeypatch.setattr(rt.shutil, "which", lambda _n: "/usr/bin/kubectl")
    _fake_run(monkeypatch, {
        "version": (True, "{}"),
        "get namespace": (True, "namespace/weirvern"),
    })
    caps = rt.detect_capabilities(tmp_path)
    assert caps.cluster_available is True
    assert caps.namespace is True
    assert caps.manifests is True


def test_kustomize_is_optional(monkeypatch, tmp_path):
    """kubectl has kustomize built in (-k), so a missing binary must not make
    the deployment un-deployable."""
    monkeypatch.setattr(rt.shutil, "which", lambda n: None if n == "kustomize" else "/usr/bin/kubectl")
    _fake_run(monkeypatch, {
        "version": (True, "{}"),
        "get namespace": (True, "namespace/weirvern"),
    })
    caps = rt.detect_capabilities(tmp_path)
    assert caps.kustomize is False
    assert caps.cluster_available is True  # still deployable


# --- backend selection -------------------------------------------------------
def test_get_backend_is_local_without_cluster(monkeypatch, tmp_path):
    monkeypatch.setattr(rt.shutil, "which", lambda _n: None)
    caps = rt.detect_capabilities(tmp_path)
    backend = rt.get_backend(tmp_path, caps)
    assert isinstance(backend, rt.LocalBackend)
    assert backend.ps() == []  # must not crash without kubectl


def test_local_backend_is_honest_about_unavailability(monkeypatch, tmp_path):
    """It must not pretend to do anything — and must point at the next action."""
    monkeypatch.setattr(rt.shutil, "which", lambda _n: None)
    caps = rt.detect_capabilities(tmp_path)
    backend = rt.LocalBackend(tmp_path, caps)
    for result in (backend.start(), backend.stop(), backend.restart(),
                   backend.down(), backend.pull(), backend.apply(), backend.wait_ready()):
        assert result.ok is False
        assert result.text, "an unavailable action must explain itself"
    logs = backend.logs()
    assert logs and "kubectl" in logs.lower()
    assert "README" in logs, "must point somewhere actionable"


def test_k8s_backend_refuses_to_construct_without_cluster(tmp_path):
    """Constructing a cluster backend with no cluster would create an object
    whose every method fails; refuse up front instead."""
    caps = rt.Capabilities(kubectl=False, reason="kubectl not found on PATH")
    with pytest.raises(RuntimeError, match="unavailable"):
        rt.K8sBackend(tmp_path, caps)


# --- kubectl command construction --------------------------------------------
def _backend(tmp_path):
    caps = rt.Capabilities(kubectl=True, kubeconfig=True, namespace=True)
    return rt.K8sBackend(tmp_path, caps)


def _capture(monkeypatch, ok=True, stdout=""):
    seen = []

    def fake_run(args, cwd, timeout=None):
        seen.append({"args": args, "cwd": cwd, "timeout": timeout})
        return rt.CommandResult(ok=ok, stdout=stdout, code=0 if ok else 1)

    monkeypatch.setattr(rt, "_run", fake_run)
    return seen


def test_namespace_is_always_pinned(tmp_path, monkeypatch):
    """Every call must target the weirvern namespace explicitly, or the CLI
    would act on whatever the kubeconfig's default namespace happens to be."""
    b = _backend(tmp_path)
    seen = _capture(monkeypatch)
    b.ps()
    assert seen, "expected kubectl invocations"
    for call in seen:
        assert call["args"][:3] == ["kubectl", "-n", rt.NAMESPACE]


def test_kubectl_run_never_uses_a_shell(tmp_path, monkeypatch):
    """A shell would make resource names (which can come from config) an
    injection surface."""
    b = _backend(tmp_path)
    seen = _capture(monkeypatch)
    b.logs("zeek")
    assert isinstance(seen[0]["args"], list)
    assert "shell" not in str(seen[0]["args"])


def test_restart_uses_rollout_not_pod_delete(tmp_path, monkeypatch):
    """`rollout restart` is the supported equivalent of a restart; deleting pods
    would bypass the Deployment's rolling-update guarantees."""
    b = _backend(tmp_path)
    seen = _capture(monkeypatch)
    b.restart(["weirvern-worker"])
    args = seen[0]["args"]
    assert args[3:5] == ["rollout", "restart"]
    assert "deployment/weirvern-worker" in args


def test_restart_targets_the_right_kind_per_workload(tmp_path, monkeypatch):
    """A StatefulSet and a DaemonSet are not Deployments; using the wrong kind
    would silently fail."""
    b = _backend(tmp_path)
    seen = _capture(monkeypatch)
    b.restart()
    kinds = {a for call in seen for a in call["args"] if "/" in a}
    assert "statefulset/clickhouse" in kinds
    assert "daemonset/zeek" in kinds
    assert "deployment/goflow2" in kinds


def test_start_scales_back_up(tmp_path, monkeypatch):
    b = _backend(tmp_path)
    seen = _capture(monkeypatch)
    b.start(["weirvern-worker"])
    assert "scale" in seen[0]["args"]
    assert "--replicas=1" in seen[0]["args"]


def test_stop_scales_to_zero(tmp_path, monkeypatch):
    b = _backend(tmp_path)
    seen = _capture(monkeypatch)
    b.stop(["weirvern-worker"])
    assert "--replicas=0" in seen[0]["args"]


def test_start_reports_that_build_is_meaningless(tmp_path, monkeypatch):
    """Silently ignoring --build would let an operator believe a new image was
    rolled out when it was not."""
    b = _backend(tmp_path)
    _capture(monkeypatch)
    result = b.start(build=True)
    assert "--build" in result.text or "registry" in result.text


def test_unknown_service_is_rejected_with_the_valid_list(tmp_path):
    b = _backend(tmp_path)
    with pytest.raises(ValueError, match="unknown service"):
        b.start(["not-a-service"])


# --- DaemonSet suspension ----------------------------------------------------
def test_daemonset_cannot_be_scaled_to_zero(tmp_path, monkeypatch):
    """Kubernetes rejects replicas:0 on a DaemonSet. If this ever regresses to a
    `scale` call, stop would fail at runtime against a real cluster."""
    b = _backend(tmp_path)

    # stop() now READS the DaemonSet first and decides from its state, so the
    # stub must answer the get with a real object (no nodeSelector, matching the
    # shipped manifest) rather than blanket-failing every call.
    calls = []

    def fake_run(args, cwd, timeout=None):
        calls.append(args)
        joined = " ".join(args)
        if " get " in joined or args[3:4] == ["get"]:
            if "jsonpath" in joined:
                return rt.CommandResult(ok=True, stdout="", code=0)
            return rt.CommandResult(ok=True, stdout='{"spec":{"template":{"spec":{}}}}', code=0)
        return rt.CommandResult(ok=True, stdout="", code=0)

    monkeypatch.setattr(rt, "_run", fake_run)
    b.stop(["zeek"])
    patch_calls = [c for c in calls if "patch" in c]
    assert patch_calls, "stop should patch the DaemonSet"
    joined = " ".join(patch_calls[0])
    assert "scale" not in joined
    assert "daemonset" in joined


def test_suspend_creates_the_missing_nodeSelector_parent(tmp_path, monkeypatch):
    """THE BUG: RFC 6902 requires a JSON-patch path's PARENT to exist, and the
    shipped manifest has NO nodeSelector (it ships commented out). A single
    `add` on /spec/template/spec/nodeSelector/<key> therefore failed with a
    "missing path" error against every default deployment, so `weirvern stop`
    reported FAILED for the sensor.

    The patch must create nodeSelector first, then add the suspension key.
    """
    b = _backend(tmp_path)
    calls = []

    def fake_run(args, cwd, timeout=None):
        calls.append(args)
        if "jsonpath" in " ".join(args):
            return rt.CommandResult(ok=True, stdout="", code=0)  # no selector yet
        return rt.CommandResult(ok=True, stdout='{"spec":{"template":{"spec":{}}}}', code=0)

    monkeypatch.setattr(rt, "_run", fake_run)
    b.stop(["zeek"])

    patch_calls = [c for c in calls if "patch" in c]
    assert patch_calls, "expected a patch call"
    patch = json.loads(patch_calls[0][patch_calls[0].index("-p") + 1])
    ops = {op["op"]: op for op in patch}
    assert "add" in ops
    # The parent must be created before the key can be added to it.
    paths = [op["path"] for op in patch]
    assert "/spec/template/spec/nodeSelector" in paths, (
        f"the parent nodeSelector is not created, so the child add fails: {paths}"
    )
    assert paths.index("/spec/template/spec/nodeSelector") < paths.index(
        b._SUSPEND_KEY_PATH), "parent must be added before the child"
    assert patch[-1]["value"] == "true"


def test_suspend_does_not_recreate_an_existing_nodeSelector(tmp_path, monkeypatch):
    """When a nodeSelector IS present (the documented sensor-node label), adding
    the parent again would wipe any other selector keys."""
    b = _backend(tmp_path)
    calls = []

    def fake_run(args, cwd, timeout=None):
        calls.append(args)
        if "jsonpath" in " ".join(args):
            return rt.CommandResult(
                ok=True, stdout='{"weirvern.io/sensor-node":"true"}', code=0)
        return rt.CommandResult(
            ok=True,
            stdout='{"spec":{"template":{"spec":{"nodeSelector":{"weirvern.io/sensor-node":"true"}}}}}',
            code=0)

    monkeypatch.setattr(rt, "_run", fake_run)
    b.stop(["zeek"])
    patch = json.loads(
        [c for c in calls if "patch" in c][0][
            [c for c in calls if "patch" in c][0].index("-p") + 1])
    paths = [op["path"] for op in patch]
    assert paths == [b._SUSPEND_KEY_PATH], (
        f"an existing nodeSelector must not be re-added (it would drop its keys): {paths}"
    )


def test_resume_removes_only_the_suspension_key(tmp_path, monkeypatch):
    """`start` must REMOVE the suspension key, never overwrite the whole
    selector — that would discard the sensor-node label and break scheduling."""
    b = _backend(tmp_path)
    calls = []

    def fake_run(args, cwd, timeout=None):
        calls.append(args)
        return rt.CommandResult(
            ok=True,
            stdout='{"spec":{"template":{"spec":{"nodeSelector":{"weirvern.io/suspended":"true","weirvern.io/sensor-node":"true"}}}}}',
            code=0)

    monkeypatch.setattr(rt, "_run", fake_run)
    b.start(["zeek"])
    patch = json.loads(
        [c for c in calls if "patch" in c][0][
            [c for c in calls if "patch" in c][0].index("-p") + 1])
    assert patch == [{"op": "remove", "path": b._SUSPEND_KEY_PATH}], (
        f"resume must remove exactly one key, got: {patch}"
    )


def test_start_reports_failure_for_a_missing_daemonset(tmp_path, monkeypatch):
    """THE BUG: start() treated any error containing the substring "not found"
    as 'already running', so a DaemonSet that does not exist was reported as a
    success. An operator who deleted the sensor was told it was running."""
    b = _backend(tmp_path)
    monkeypatch.setattr(rt, "_run", lambda *a, **k: rt.CommandResult(
        ok=False,
        stderr='Error from server (NotFound): daemonsets.apps "zeek" not found',
        code=1))
    result = b.start(["zeek"])
    assert result.ok is False, "a missing DaemonSet must be a failure"
    assert "FAILED" in result.text
    assert "already running" not in result.text


def test_start_is_idempotent_when_not_suspended(tmp_path, monkeypatch):
    """When the sensor is already capturing, start is a no-op SUCCESS (the
    desired end state holds) — but it must say so from the object's state, not
    from guessing at an error string."""
    b = _backend(tmp_path)
    calls = []

    def fake_run(args, cwd, timeout=None):
        calls.append(args)
        return rt.CommandResult(
            ok=True, stdout='{"spec":{"template":{"spec":{"nodeSelector":{}}}}}', code=0)

    monkeypatch.setattr(rt, "_run", fake_run)
    result = b.start(["zeek"])
    assert result.ok is True
    assert "already running" in result.text
    assert not [c for c in calls if "patch" in c], "no patch needed when already running"


def test_stop_of_zeek_says_it_is_suspended_not_stopped(tmp_path, monkeypatch):
    """An operator who thinks the sensor is off when it is only suspended would
    misread their own network coverage."""
    b = _backend(tmp_path)

    def fake_run(args, cwd, timeout=None):
        if "jsonpath" in " ".join(args):
            return rt.CommandResult(ok=True, stdout="", code=0)
        if " get " in " ".join(args):
            return rt.CommandResult(ok=True, stdout='{"spec":{"template":{"spec":{}}}}', code=0)
        return rt.CommandResult(ok=True, stdout="", code=0)

    monkeypatch.setattr(rt, "_run", fake_run)
    result = b.stop(["zeek"])
    assert "SUSPEND" in result.text.upper()
    assert "cannot be scaled to zero" in result.text


def test_suspended_daemonset_is_distinguishable_from_unmatched(tmp_path):
    """Both states report desiredNumberScheduled == 0, so they must be told
    apart by the suspension key, not by the count."""
    b = _backend(tmp_path)
    suspended = {
        "spec": {"template": {"spec": {"nodeSelector": {"weirvern.io/suspended": "true"}}}},
        "status": {"desiredNumberScheduled": 0, "numberReady": 0},
    }
    st = b._state_from_object("zeek", "daemonset", suspended)
    assert st.state == "suspended"
    assert st.dot == "‖"

    unlabelled = {
        "spec": {"template": {"spec": {}}},
        "status": {"desiredNumberScheduled": 0, "numberReady": 0},
    }
    st2 = b._state_from_object("zeek", "daemonset", unlabelled)
    assert st2.state == "pending"
    assert "nodeSelector" in st2.detail or "sensor node" in st2.detail


# --- destructive operations --------------------------------------------------
def test_down_does_not_delete_data_by_default(tmp_path, monkeypatch):
    """The PVCs hold all collected flow history and every trained model. It must
    never be implicit: a stray keypress would destroy the dataset."""
    b = _backend(tmp_path)
    seen = _capture(monkeypatch)
    b.down()
    joined = " ".join(" ".join(c["args"]) for c in seen)
    assert "pvc" not in joined


def test_down_with_volumes_says_what_was_lost(tmp_path, monkeypatch):
    b = _backend(tmp_path)
    _capture(monkeypatch)
    result = b.down(volumes=True)
    assert "claims deleted" in result.text.lower() or "gone" in result.text.lower()


# --- observation -------------------------------------------------------------
def test_ps_reports_missing_workload_without_crashing(tmp_path, monkeypatch):
    """An absent object is reported as missing — but ONLY when the error really
    says it is absent.

    This test previously stubbed a blanket failure for every call and asserted
    every state was 'missing', which pinned the bug where an RBAC denial or an
    unreachable API server was also reported as a missing deployment.
    """
    b = _backend(tmp_path)
    monkeypatch.setattr(rt, "_run", lambda *a, **k: rt.CommandResult(
        ok=False, stderr='Error from server (NotFound): deployments.apps "x" not found',
        code=1))
    states = b.ps()
    assert len(states) == len(rt.WORKLOADS)
    assert all(s.state == "missing" for s in states)


def test_ps_distinguishes_rbac_denial_from_missing(tmp_path, monkeypatch):
    """A permission problem must NOT look like 'not applied' — otherwise the
    operator re-applies correct manifests and stays stuck."""
    b = _backend(tmp_path)
    monkeypatch.setattr(rt, "_run", lambda *a, **k: rt.CommandResult(
        ok=False,
        stderr='Error from server (Forbidden): deployments.apps "goflow2" is forbidden: '
               'User "system:serviceaccount:weirvern:weirvern-viewer" cannot get resource "deployments"',
        code=1))
    states = {s.name: s for s in b.ps()}
    assert states["goflow2"].state == "forbidden"
    assert "permission denied" in states["goflow2"].detail.lower()
    assert "not found" not in states["goflow2"].detail.lower()


def test_ps_distinguishes_unreachable_api_server(tmp_path, monkeypatch):
    """A cluster that cannot be reached is a different problem from a missing
    deployment, and needs a different fix."""
    b = _backend(tmp_path)
    monkeypatch.setattr(rt, "_run", lambda *a, **k: rt.CommandResult(
        ok=False,
        stderr="Unable to connect to the server: dial tcp 198.51.100.1:6443: i/o timeout",
        code=1))
    states = {s.name: s for s in b.ps()}
    assert states["goflow2"].state == "unreachable"
    assert "unreachable" in states["goflow2"].detail.lower()


def test_ps_parses_workload_ready_replicas(tmp_path, monkeypatch):
    """Status must come from the workload object (what an operator controls),
    not from a pod listing that changes on every rollout."""
    b = _backend(tmp_path)
    fake = {
        "statefulset clickhouse": (True, '{"spec":{"replicas":1},"status":{"readyReplicas":1}}'),
        "deployment goflow2": (True, '{"spec":{"replicas":1},"status":{"readyReplicas":1}}'),
        "daemonset zeek": (True, '{"spec":{},"status":{"desiredNumberScheduled":1,"numberReady":1}}'),
        "deployment weirvern-worker": (True, '{"spec":{"replicas":1},"status":{"readyReplicas":0}}'),
    }

    def fake_run(args, cwd, timeout=None):
        # Shape: kubectl -n <ns> get <kind> <name> -o json
        kind = args[4]
        name = args[5]
        for key, (ok, out) in fake.items():
            if key.startswith(kind) and key.endswith(name):
                return rt.CommandResult(ok=ok, stdout=out, code=0)
        return rt.CommandResult(ok=False, stderr="nf", code=1)

    monkeypatch.setattr(rt, "_run", fake_run)
    states = {s.name: s for s in b.ps()}
    assert states["clickhouse"].state == "running"
    assert states["zeek"].state == "running"
    assert states["weirvern-worker"].state == "starting"
    assert states["weirvern-worker"].health == "unhealthy"
    assert "0/1" in states["weirvern-worker"].detail


def test_ps_shows_scaled_to_zero_as_stopped(tmp_path, monkeypatch):
    b = _backend(tmp_path)
    monkeypatch.setattr(rt, "_run", lambda *a, **k: rt.CommandResult(
        ok=True, stdout='{"spec":{"replicas":0},"status":{}}', code=0))
    states = {s.name: s for s in b.ps()}
    assert states["goflow2"].state == "stopped"
    assert states["goflow2"].running is False


def test_logs_are_bounded_and_colourless(tmp_path, monkeypatch):
    """Unbounded logs would flood a terminal pane; ANSI codes would corrupt it."""
    b = _backend(tmp_path)
    seen = _capture(monkeypatch, stdout="line")
    b.logs(service="zeek", tail=50)
    args = seen[0]["args"]
    assert "--tail" in args and "50" in args
    assert "--no-color=true" in args
    assert "app.kubernetes.io/name=zeek" in args


def test_logs_selects_by_label_not_pod_name(tmp_path, monkeypatch):
    """Pod names change on every rollout; a label selector keeps the log view
    working across deploys."""
    b = _backend(tmp_path)
    seen = _capture(monkeypatch, stdout="x")
    b.logs()
    for call in seen:
        assert "-l" in call["args"], "log queries must use a label selector"


def test_logs_of_unknown_service_explains(tmp_path):
    b = _backend(tmp_path)
    out = b.logs("nope")
    assert "unknown service" in out
    assert "zeek" in out  # lists the valid options


def test_pull_explains_instead_of_faking(tmp_path):
    """There is no client-side pull on Kubernetes, but nothing is broken either."""
    b = _backend(tmp_path)
    result = b.pull()
    assert result.ok is True
    assert "kubelet" in result.text
    assert "registry" in result.text


def test_wait_ready_names_the_failing_workload(tmp_path, monkeypatch):
    """A bare timeout is useless; the operator needs to know which workload."""
    b = _backend(tmp_path)

    def fake_run(args, cwd, timeout=None):
        ok = "zeek" not in " ".join(args)
        return rt.CommandResult(ok=ok, stdout="" if ok else "Waiting for daemonset",
                                stderr="not ready", code=0 if ok else 1)

    monkeypatch.setattr(rt, "_run", fake_run)
    result = b.wait_ready(timeout_s=5)
    assert result.ok is False
    assert "zeek" in result.text
    assert "NOT ready" in result.text


def test_apply_uses_kustomize_directory(tmp_path, monkeypatch):
    b = _backend(tmp_path)
    seen = _capture(monkeypatch)
    b.apply()
    args = seen[0]["args"]
    assert "apply" in args and "-k" in args
    assert str(tmp_path / "k8s") in args


def test_apply_dry_run_changes_nothing(tmp_path, monkeypatch):
    b = _backend(tmp_path)
    seen = _capture(monkeypatch)
    b.apply(dry_run=True)
    assert "--dry-run=client" in seen[0]["args"]


# --- display helpers ---------------------------------------------------------
def test_workload_labels_cover_every_workload():
    """A missing label means logs and status silently skip that workload."""
    assert {name for name, _ in rt.WORKLOADS} == set(rt.WORKLOAD_LABELS)
    for label in rt.WORKLOAD_LABELS.values():
        assert "app.kubernetes.io/name=" in label


def test_service_order_matches_workloads():
    """runtime.WORKLOADS is the single workload list the CLI and manifests agree on."""
    import weirvern.admin.runtime as rt2

    assert {name for name, _ in rt2.WORKLOADS} == set(rt2.WORKLOAD_LABELS)


def test_condense_strips_driver_noise():
    from weirvern.admin.runtime import _condense

    raw = ("Could not connect to ClickHouse at http://clickhouse:8123: Error "
           "HTTPConnectionPool(host='clickhouse', port=8123): Max retries exceeded "
           "with url: /?query_id=ead8ab")
    out = _condense(raw)
    assert "query_id" not in out
    assert len(out) <= 91
    assert "clickhouse:8123" in out, "must keep the host an operator needs"


def test_condense_passes_short_text_through():
    from weirvern.admin.runtime import _condense

    assert _condense("kubectl not found on PATH") == "kubectl not found on PATH"
    assert _condense("") == ""


# --- manifest/README consistency ---------------------------------------------
def test_manifests_declare_every_workload_the_backend_drives():
    """The control plane drives workload names; if a manifest is renamed the tool
    would report 'missing' forever. Catch that here instead of on a cluster."""
    root = Path(__file__).resolve().parents[1]
    text = "\n".join(p.read_text() for p in sorted((root / "k8s").glob("*.yaml")))
    for name, kind in rt.WORKLOADS:
        assert re.search(rf"kind:\s*{kind.title() if kind != 'daemonset' else 'DaemonSet'}"
                         rf"[\s\S]{{0,200}}?name:\s*{re.escape(name)}", text) or \
               re.search(rf"name:\s*{re.escape(name)}", text), \
            f"{kind}/{name} not found in k8s/*.yaml"
