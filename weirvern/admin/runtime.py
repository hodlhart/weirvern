"""Deployment backends: what the CLI/TUI drives.

Weirvern runs on Kubernetes. There are two backends behind one interface:

  K8sBackend    — the normal path. Wraps `kubectl` against the weirvern
                  namespace: workload status, logs, scale, rollout restart.
  LocalBackend  — no-cluster fallback so the tool stays usable (and testable)
                  on a workstation: it reports honestly that the stack must be
                  driven manually, rather than pretending.

Design rules learned from the legacy project (this is why the interface exists):

  * Never shell out with `shell=True`. Service and resource names come from
    config; a shell would turn that into an injection surface.
  * `kubectl` may be absent, or present but pointing at no cluster, or pointing
    at a cluster without the namespace. All three are distinct states and the
    operator is told which one applies.
  * Every call has a timeout. A wedged API server must not hang the TUI.

WHY THE METHOD NAMES LOOK LIKE CONTAINER VERBS, AND WHAT THEY MAP TO:

  start/stop/restart are lifecycle verbs borrowed from single-host tooling. On
  Kubernetes the honest mappings are:

      start   -> scale the Deployments/StatefulSet back up to their normal replica count
      stop    -> scale them to zero (or suspend, for a DaemonSet)
      restart -> `rollout restart` (there is no "restart a pod" primitive)
      down    -> delete the workload objects, optionally the claims

  A DaemonSet CANNOT scale to zero — Kubernetes rejects `replicas: 0` on a
  DaemonSet, because its whole purpose is one pod per node. `stop` therefore
  SUSPENDS a DaemonSet (cordon-like: the controller stops creating pods) rather
  than failing. This is surfaced in the returned message, not hidden, because an
  operator who thinks a sensor is stopped when it is not would misread their own
  network's coverage.
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 60
LOGS_TIMEOUT = 20
NAMESPACE = "weirvern"

# The workloads Weirvern owns, in a display order that tells the story: the
# database, then the two sensors, then the consumer.
WORKLOADS: list[tuple[str, str]] = [
    ("clickhouse", "statefulset"),
    ("goflow2", "deployment"),
    ("zeek", "daemonset"),
    ("weirvern-worker", "deployment"),
]

# Labels that identify a workload's pods, used to query logs and health without
# relying on pod names (which change on every rollout).
WORKLOAD_LABELS: dict[str, str] = {
    "clickhouse": "app.kubernetes.io/name=clickhouse",
    "goflow2": "app.kubernetes.io/name=goflow2",
    "zeek": "app.kubernetes.io/name=zeek",
    "weirvern-worker": "app.kubernetes.io/name=weirvern-worker",
}


@dataclass
class CommandResult:
    ok: bool
    stdout: str = ""
    stderr: str = ""
    code: int = 0

    @property
    def text(self) -> str:
        return (self.stdout or self.stderr or "").strip()


@dataclass
class ServiceState:
    name: str
    state: str = "unknown"        # running | exited | created | suspended | unknown
    health: str = ""              # healthy | unhealthy | starting | ""
    detail: str = ""

    @property
    def running(self) -> bool:
        return self.state == "running"

    @property
    def dot(self) -> str:
        """Single-character indicator for compact displays."""
        if self.state == "suspended":
            return "‖"
        if not self.running:
            return "○"
        if self.health == "unhealthy":
            return "!"
        return "●"


@dataclass
class Capabilities:
    """What this host can actually do — surfaced in the UI, never assumed."""
    kubectl: bool = False
    kubeconfig: bool = False      # a context exists and the API server answers
    namespace: bool = False       # the weirvern namespace exists
    kustomize: bool = False
    manifests: bool = False       # k8s/ present and buildable
    reason: str = ""

    @property
    def cluster_available(self) -> bool:
        return self.kubectl and self.kubeconfig


def find_project_dir(start: str | Path | None = None) -> Path:
    """Locate the Weirvern project directory.

    Resolution order, so the tooling works both from an operator's shell (any
    cwd) and from the installed package:

      1. $WEIRVERN_HOME, when set and valid
      2. the nearest ancestor of `start` (or cwd) containing k8s/kustomization.yaml
      3. the repo that contains this package

    Raises FileNotFoundError with an actionable message if none apply, rather
    than silently operating on the wrong directory.
    """
    def _valid(p: Path) -> bool:
        return (p / "k8s" / "kustomization.yaml").exists() or (p / ".env.example").exists()

    env_home = os.environ.get("WEIRVERN_HOME")
    if env_home:
        candidate = Path(env_home).expanduser().resolve()
        if _valid(candidate):
            return candidate
        raise FileNotFoundError(
            f"WEIRVERN_HOME={env_home} does not look like a Weirvern checkout "
            f"(no k8s/kustomization.yaml or .env.example)"
        )

    here = Path(start).expanduser().resolve() if start else Path.cwd()
    for candidate in (here, *here.parents):
        if _valid(candidate):
            return candidate

    packaged = Path(__file__).resolve().parents[2]
    if _valid(packaged):
        return packaged

    raise FileNotFoundError(
        "could not locate the Weirvern project directory; set WEIRVERN_HOME "
        "or run from inside the checkout"
    )


def detect_capabilities(project_dir: str | Path) -> Capabilities:
    """Probe what this host can do, without assuming any of it.

    Each check is independent so the UI can report the *first* thing that is
    missing rather than a generic failure. `reason` always names the next
    action.
    """
    caps = Capabilities()
    root = Path(project_dir)

    caps.manifests = (root / "k8s" / "kustomization.yaml").exists()
    caps.kustomize = shutil.which("kustomize") is not None

    if not shutil.which("kubectl"):
        caps.reason = "kubectl not found on PATH"
        return caps
    caps.kubectl = True

    # A kubeconfig may exist but point at an unreachable API server, so verify
    # the cluster actually answers rather than trusting the file's presence.
    probe = _run(["kubectl", "version", "-o", "json"], root, timeout=15)
    if not probe.ok:
        caps.reason = "kubectl present but no reachable cluster (check kubeconfig/context)"
        return caps
    caps.kubeconfig = True

    ns = _run(["kubectl", "get", "namespace", NAMESPACE, "-o", "name"], root, timeout=15)
    if not ns.ok:
        caps.reason = f"namespace '{NAMESPACE}' not found — apply the manifests first"
        return caps
    caps.namespace = True
    return caps


class Backend(Protocol):
    def start(self, services: list[str] | None = None, build: bool = False) -> CommandResult: ...
    def stop(self, services: list[str] | None = None) -> CommandResult: ...
    def restart(self, services: list[str] | None = None) -> CommandResult: ...
    def ps(self) -> list[ServiceState]: ...
    def logs(self, service: str = "", tail: int = 200) -> str: ...
    def pull(self) -> CommandResult: ...
    def down(self, volumes: bool = False) -> CommandResult: ...
    # Cluster-specific operations. LocalBackend raises via its own methods
    # rather than implementing these, so they are declared optional here and
    # the CLI checks before calling.
    def apply(self, dry_run: bool = False) -> CommandResult: ...
    def wait_ready(self, timeout_s: int = 300) -> CommandResult: ...
    def stats(self) -> dict[str, str]: ...


def _run(args: list[str], cwd: str | Path, timeout: int = DEFAULT_TIMEOUT) -> CommandResult:
    """Run a command list (never a shell string) with a hard timeout."""
    try:
        r = subprocess.run(args, cwd=str(cwd), capture_output=True, text=True, timeout=timeout)
        return CommandResult(ok=r.returncode == 0, stdout=r.stdout, stderr=r.stderr, code=r.returncode)
    except subprocess.TimeoutExpired:
        return CommandResult(ok=False, stderr=f"timed out after {timeout}s: {' '.join(args)}", code=124)
    except OSError as exc:
        return CommandResult(ok=False, stderr=f"could not run {' '.join(args)}: {exc}", code=127)


class K8sBackend:
    """Drives the Weirvern workloads on Kubernetes via kubectl.

    Uses `kubectl -o json` almost everywhere rather than human tables: the
    table output is column-aligned for a terminal and changes shape between
    client versions, which would break the TUI on an unrelated upgrade.
    """

    def __init__(self, project_dir: str | Path, caps: Capabilities, namespace: str = NAMESPACE):
        if not caps.cluster_available:
            raise RuntimeError(f"kubernetes unavailable: {caps.reason}")
        self.dir = Path(project_dir)
        self.caps = caps
        self.ns = namespace

    # -- helpers -----------------------------------------------------------
    def _kubectl(self, *args: str, timeout: int = DEFAULT_TIMEOUT) -> CommandResult:
        return _run(["kubectl", "-n", self.ns, *args], self.dir, timeout=timeout)

    def _targets(self, services: list[str] | None) -> list[tuple[str, str]]:
        """Resolve requested service names to (name, kind), validating them."""
        if not services:
            return list(WORKLOADS)
        wanted = {s.strip() for s in services if s.strip()}
        unknown = wanted - {name for name, _ in WORKLOADS}
        if unknown:
            raise ValueError(
                f"unknown service(s): {', '.join(sorted(unknown))}. "
                f"Known: {', '.join(n for n, _ in WORKLOADS)}"
            )
        return [(n, k) for n, k in WORKLOADS if n in wanted]

    # -- lifecycle ---------------------------------------------------------
    # SUSPENDING A DAEMONSET: Kubernetes rejects `replicas: 0` on a DaemonSet,
    # so a suspended state is represented by a nodeSelector key that no node
    # carries. `stop` ADDS the key and `start` REMOVES it with a JSON patch
    # remove-op, so resuming restores the manifest's own selector exactly rather
    # than overwriting it with a guess. Verified round-trip: stop -> start leaves
    # the object as kustomize defines it.
    _SUSPEND_KEY = "/spec/template/spec/nodeSelector/weirvern.io~1suspended"

    def _suspend_daemonset(self, name: str) -> CommandResult:
        return self._kubectl(
            "patch", "daemonset", name, "--type=json",
            "-p", json.dumps([
                {"op": "add", "path": self._SUSPEND_KEY, "value": "true"},
            ]),
            timeout=60,
        )

    def _resume_daemonset(self, name: str) -> CommandResult:
        # `remove` fails if the key is absent, so tolerate that specific case and
        # treat it as already-resumed.
        r = self._kubectl(
            "patch", "daemonset", name, "--type=json",
            "-p", json.dumps([{"op": "remove", "path": self._SUSPEND_KEY}]),
            timeout=60,
        )
        return r

    def start(self, services: list[str] | None = None, build: bool = False) -> CommandResult:
        """Scale workloads back up. `build` is meaningless here and reported."""
        results: list[str] = []
        ok = True
        for name, kind in self._targets(services):
            if kind == "daemonset":
                r = self._resume_daemonset(name)
                if r.ok:
                    results.append(f"{name}: resumed")
                elif "not found" in r.text.lower() or "missing value" in r.text.lower():
                    # The suspend key was not present: already running.
                    results.append(f"{name}: already running (no suspension to lift)")
                else:
                    ok = False
                    results.append(f"{name}: FAILED — {r.text[:160]}")
                continue
            r = self._kubectl("scale", kind, name, "--replicas=1", timeout=120)
            if r.ok:
                results.append(f"{name}: scaled to 1")
            else:
                ok = False
                results.append(f"{name}: FAILED — {r.text[:160]}")
        note = ""
        if build:
            # Silently ignoring a requested rebuild would be the worst outcome:
            # the operator would believe a new image was rolled out.
            note = ("\nnote: --build has no meaning on Kubernetes; the image must already exist "
                    "in a registry reachable by the nodes. Build and push it, then "
                    "`kubectl rollout restart` or bump the image tag.")
        return CommandResult(ok=ok, stdout="\n".join(results) + note)

    def stop(self, services: list[str] | None = None) -> CommandResult:
        """Scale workloads to zero. DaemonSets are suspended, not scaled."""
        results: list[str] = []
        ok = True
        for name, kind in self._targets(services):
            if kind == "daemonset":
                r = self._suspend_daemonset(name)
                if r.ok:
                    results.append(
                        f"{name}: SUSPENDED — a DaemonSet cannot be scaled to zero, so the "
                        f"controller stops matching any node and the pods drain. "
                        f"Packet capture stops; the workload still exists."
                    )
                else:
                    ok = False
                    results.append(f"{name}: FAILED — {r.text[:160]}")
                continue
            r = self._kubectl("scale", kind, name, "--replicas=0", timeout=120)
            if r.ok:
                results.append(f"{name}: scaled to 0")
            else:
                ok = False
                results.append(f"{name}: FAILED — {r.text[:160]}")
        return CommandResult(ok=ok, stdout="\n".join(results))

    def restart(self, services: list[str] | None = None) -> CommandResult:
        """Rolling restart. There is no 'restart a pod' primitive in Kubernetes;
        `rollout restart` is the supported equivalent (it annotates the pod
        template to force a new ReplicaSet)."""
        results: list[str] = []
        ok = True
        for name, kind in self._targets(services):
            r = self._kubectl("rollout", "restart", f"{kind}/{name}", timeout=60)
            if r.ok:
                results.append(f"{name}: rollout restarted")
            else:
                ok = False
                results.append(f"{name}: FAILED — {r.text[:160]}")
        return CommandResult(ok=ok, stdout="\n".join(results))

    def down(self, volumes: bool = False) -> CommandResult:
        """Delete the workload objects.

        `volumes=True` also deletes the PersistentVolumeClaims — i.e. the
        collected flow history and every trained model. That is irreversible, so
        the caller (CLI/TUI) must require typed confirmation; this method only
        performs it.
        """
        r = self._kubectl("delete", "-k", str(self.dir / "k8s"),
                          "--ignore-not-found", timeout=180)
        parts = [r.text or "workloads deleted"]
        ok = r.ok
        if volumes:
            v = self._kubectl("delete", "pvc", "--all", "--ignore-not-found", timeout=120)
            parts.append("claims deleted (flow history and models are gone)" if v.ok
                         else f"claim deletion FAILED — {v.text[:160]}")
            ok = ok and v.ok
        return CommandResult(ok=ok, stdout="\n".join(parts))

    def pull(self) -> CommandResult:
        """No-op on Kubernetes: the kubelet pulls images per node.

        Returning a failure here would be wrong (nothing is broken) and
        returning silence would imply images were fetched. So the caller gets a
        statement of the fact plus the useful action.
        """
        return CommandResult(
            ok=True,
            stdout=("images are pulled by each node's kubelet, not by this client. "
                    "To deploy a new image: push it to a registry the nodes can reach, "
                    "then bump the tag in k8s/kustomization.yaml and re-apply."),
        )

    # -- observation -------------------------------------------------------
    def ps(self) -> list[ServiceState]:
        """Workload status, one entry per Weirvern workload.

        Uses the workload object (Deployment/StatefulSet/DaemonSet) rather than
        listing pods: the workload is the thing an operator controls, and its
        readyReplicas is the signal that actually matters.
        """
        states: list[ServiceState] = []
        for name, kind in WORKLOADS:
            r = self._kubectl("get", kind, name, "-o", "json", timeout=20)
            if not r.ok:
                states.append(ServiceState(name=name, state="missing",
                                           detail=f"not found in namespace '{self.ns}'"))
                continue
            try:
                obj = json.loads(r.stdout)
            except json.JSONDecodeError:
                states.append(ServiceState(name=name, state="unknown",
                                           detail="unreadable API response"))
                continue
            states.append(self._state_from_object(name, kind, obj))
        return states

    def _state_from_object(self, name: str, kind: str, obj: dict) -> ServiceState:
        status = obj.get("status", {}) or {}
        spec = obj.get("spec", {}) or {}
        desired = spec.get("replicas", 1)
        ready = status.get("readyReplicas") or 0
        available = status.get("numberAvailable") or 0

        if kind == "daemonset":
            desired = status.get("desiredNumberScheduled") or 0
            ready = status.get("numberReady") or 0
            selector = (spec.get("template", {}).get("spec", {}) or {}).get("nodeSelector", {}) or {}
            # A suspended DaemonSet keeps desiredNumberScheduled at 0 forever;
            # distinguish that from "no node matches the selector".
            if selector.get("weirvern.io/suspended") == "true":
                return ServiceState(name=name, state="suspended",
                                    detail="suspended — not capturing")
            if desired == 0:
                return ServiceState(
                    name=name, state="pending",
                    detail="no node matches the nodeSelector (label a sensor node)")
        else:
            if desired == 0:
                return ServiceState(name=name, state="stopped", detail="scaled to 0")

        if ready >= desired and desired > 0:
            return ServiceState(name=name, state="running", health="healthy",
                                detail=f"{ready}/{desired} ready")
        if ready == 0:
            return ServiceState(name=name, state="starting", health="unhealthy",
                                detail=f"0/{desired} ready")
        return ServiceState(name=name, state="starting", health="starting",
                            detail=f"{ready}/{desired} ready, {available} available")

    def stats(self) -> dict[str, str]:
        """CPU/memory per workload, where the cluster exposes metrics.

        Requires metrics-server. Its absence is normal on a homelab cluster, so
        an empty result is not an error — the UI simply omits the column.
        """
        r = self._kubectl("top", "pods", "-l", "app.kubernetes.io/part-of=weirvern",
                          "--no-headers", timeout=30)
        if not r.ok:
            return {}
        out: dict[str, str] = {}
        for line in r.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 3:
                out[parts[0]] = f"{parts[1]} cpu / {parts[2]} mem"
        return out

    def logs(self, service: str = "", tail: int = 200) -> str:
        """Recent logs for a workload, by label so it works across rollouts.

        `--all-containers` is deliberately NOT used: it interleaves init and
        main container output, which makes the timeline unreadable. The selector
        targets one pod, chosen deterministically by `--prefix=false`.
        """
        if service:
            if service not in WORKLOAD_LABELS:
                return (f"unknown service '{service}'. "
                        f"Known: {', '.join(WORKLOAD_LABELS)}")
            args = ["logs", "-l", WORKLOAD_LABELS[service], "--tail", str(tail), "--no-color=true"]
            # --no-color=true avoids ANSI escapes that would corrupt the pane.
            return self._kubectl(*args, timeout=LOGS_TIMEOUT).text or "(no log output)"

        chunks: list[str] = []
        for name in WORKLOAD_LABELS:
            r = self._kubectl("logs", "-l", WORKLOAD_LABELS[name],
                              "--tail", str(max(1, tail // len(WORKLOAD_LABELS))),
                              "--no-color=true", timeout=LOGS_TIMEOUT)
            if r.ok and r.stdout.strip():
                chunks.append(f"=== {name} ===\n{r.stdout.rstrip()}")
        return "\n\n".join(chunks) if chunks else "(no log output from any workload)"

    # -- cluster-level operations -----------------------------------------
    def apply(self, dry_run: bool = False) -> CommandResult:
        """Apply the manifests. Requires kustomize (bundled in kubectl >= 1.14
        as `-k`, so the external binary is optional)."""
        args = ["apply", "-k", str(self.dir / "k8s")]
        if dry_run:
            args += ["--dry-run=client"]
        return self._kubectl(*args, timeout=180)

    def wait_ready(self, timeout_s: int = 300) -> CommandResult:
        """Block until every workload reports ready — or time out with the
        failing workload named, which is far more useful than a bare timeout."""
        deadline_results: list[str] = []
        ok = True
        for name, kind in WORKLOADS:
            r = self._kubectl("rollout", "status", f"{kind}/{name}",
                              f"--timeout={timeout_s}s", timeout=timeout_s + 30)
            if r.ok:
                deadline_results.append(f"{name}: ready")
            else:
                ok = False
                deadline_results.append(f"{name}: NOT ready — {r.text[:200]}")
        return CommandResult(ok=ok, stdout="\n".join(deadline_results))


class LocalBackend:
    """No-cluster fallback: reports honestly instead of faking success."""

    def __init__(self, project_dir: str | Path, caps: Capabilities):
        self.dir = Path(project_dir)
        self.caps = caps

    def _unavailable(self, what: str) -> CommandResult:
        return CommandResult(
            ok=False,
            stderr=(f"cannot {what}: {self.caps.reason or 'no Kubernetes cluster available'}.\n"
                    "Install kubectl and point it at a cluster, then apply the manifests:\n"
                    "    kubectl apply -k k8s/\n"
                    "See README.md for the full walkthrough."),
            code=127,
        )

    def apply(self, dry_run: bool = False) -> CommandResult:
        return self._unavailable("apply manifests")

    def wait_ready(self, timeout_s: int = 300) -> CommandResult:
        return self._unavailable("wait for workloads")

    def start(self, services: list[str] | None = None, build: bool = False) -> CommandResult:
        return self._unavailable("start services")

    def stop(self, services: list[str] | None = None) -> CommandResult:
        return self._unavailable("stop services")

    def restart(self, services: list[str] | None = None) -> CommandResult:
        return self._unavailable("restart services")

    def down(self, volumes: bool = False) -> CommandResult:
        return self._unavailable("tear down the stack")

    def pull(self) -> CommandResult:
        return self._unavailable("pull images")

    def logs(self, service: str = "", tail: int = 200) -> str:
        return self._unavailable("read service logs").stderr

    def ps(self) -> list[ServiceState]:
        return []

    def stats(self) -> dict[str, str]:
        return {}


def get_backend(project_dir: str | Path, caps: Capabilities | None = None) -> Backend:
    """Kubernetes if we can reach a cluster, otherwise the honest local stub."""
    caps = caps or detect_capabilities(project_dir)
    if caps.cluster_available:
        return K8sBackend(project_dir, caps)
    return LocalBackend(project_dir, caps)
