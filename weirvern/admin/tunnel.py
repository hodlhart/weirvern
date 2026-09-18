"""Reach the in-cluster ClickHouse from the operator's workstation.

THE PROBLEM THIS SOLVES, found by running the TUI on a real host:

    Could not connect to ClickHouse at http://clickhouse:8123:
    HTTPConnectionPool(host='clickhouse', ...)

`clickhouse` is a cluster-internal DNS name. The control plane (CLI, TUI) runs on
an operator's machine, OUTSIDE the cluster, so it can never resolve it — and the
`clickhouse-external` Service ships as ClusterIP with its NodePort commented out,
so there is no route from the host either. The result was a TUI that showed every
workload running while its Health and Anomalies panels reported a connection
error, which reads like a broken deployment rather than an unreachable one.

WHY A PORT-FORWARD RATHER THAN A NODEPORT:

`k8s/60-rbac.yaml` already grants `pods/portforward` to both the viewer and
operator roles, so the intended design was clearly a tunnel — nothing had
implemented it. A tunnel is also the better answer on its own merits:

  * It needs NO exposed port. Publishing a database to the LAN is a decision with
    security consequences, and `weirvern status` should not force it.
  * It uses the operator's existing kubeconfig and RBAC, so access is governed by
    the same controls as every other action rather than by network reachability.
  * It works unchanged against a remote cluster behind a bastion, which a NodePort
    to a private subnet would not.

The tunnel is a short-lived child process, started on demand and torn down with
the client. It is deliberately NOT a background daemon: a stale forwarding process
holding a port is a confusing failure mode, and the tooling is interactive.
"""
from __future__ import annotations

import logging
import socket
import subprocess
import time
from collections.abc import Iterator
from contextlib import contextmanager

logger = logging.getLogger(__name__)

# The Service to forward through, and the port ClickHouse's HTTP interface
# listens on inside the cluster.
DEFAULT_SERVICE = "svc/clickhouse"
DEFAULT_REMOTE_PORT = 8123

# How long to wait for the forward to become usable. `kubectl port-forward` prints
# "Forwarding from ..." once the listener is up, so this is an upper bound rather
# than a delay that is always paid.
READY_TIMEOUT_S = 15.0


def _pick_local_port() -> int:
    """A free local port, chosen by the OS.

    Binding port 0 and reading back what we got avoids colliding with whatever the
    operator already has on 8123 — which is common, because a developer testing
    locally will often be running a ClickHouse or another tunnel on exactly that
    port. A hardcoded local port fails in that case with a confusing "address
    already in use" from kubectl.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _port_is_open(port: int, timeout: float = 0.5) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        return s.connect_ex(("127.0.0.1", port)) == 0


@contextmanager
def clickhouse_tunnel(namespace: str, service: str = DEFAULT_SERVICE,
                      remote_port: int = DEFAULT_REMOTE_PORT,
                      local_port: int | None = None) -> Iterator[int]:
    """Yield a local port forwarding to ClickHouse. Raises RuntimeError on failure.

    Use as a context manager so the child process cannot outlive the client:

        with clickhouse_tunnel("weirvern") as port:
            settings = replace(settings, clickhouse_host="127.0.0.1",
                               clickhouse_port=port)

    Raises rather than returning None so a caller cannot silently proceed with an
    unreachable host and then report a misleading connection error.
    """
    local = local_port or _pick_local_port()
    cmd = [
        "kubectl", "-n", namespace, "port-forward", service,
        f"{local}:{remote_port}",
        # Keep kubectl from prompting on a stale/expired credential: in an
        # interactive TUI a prompt would appear where there is no stdin.
        "--request-timeout=10s",
    ]
    proc = subprocess.Popen(  # noqa: S603 - fixed argv, no shell
        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    try:
        deadline = time.time() + READY_TIMEOUT_S
        output: list[str] = []
        while time.time() < deadline:
            if proc.poll() is not None:
                # kubectl exited: surface WHY rather than timing out vaguely.
                rest = proc.stdout.read() if proc.stdout else ""
                output.append(rest)
                detail = " ".join("".join(output).split())[:300]
                raise RuntimeError(
                    f"kubectl port-forward exited early (code {proc.returncode}): "
                    f"{detail or 'no output'}"
                )
            if _port_is_open(local):
                break
            time.sleep(0.2)
        else:
            raise RuntimeError(
                f"port-forward to {service}:{remote_port} did not become ready "
                f"within {READY_TIMEOUT_S:.0f}s"
            )
        logger.debug("ClickHouse tunnel ready on 127.0.0.1:%d", local)
        yield local
    finally:
        # terminate() then kill(): kubectl traps SIGTERM and closes the listener,
        # but a wedged one would otherwise hold the port and make the next run
        # fail for no visible reason.
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
        if proc.stdout:
            proc.stdout.close()


def _detect_in_cluster() -> bool:
    """Are we executing INSIDE a pod?

    THE SIGNAL IS THE SERVICE-ACCOUNT TOKEN DIRECTORY, which Kubernetes mounts into
    every container by default. KUBERNETES_SERVICE_HOST is checked too because it
    is set even in pods with the token disabled (this project sets
    automountServiceAccountToken: false on most workloads), and either signal is
    sufficient.

    WHY THIS CHECK IS ESSENTIAL rather than a nicety: the tunnel decision keys off
    "does the configured host look cluster-internal", and `clickhouse` looks
    internal from BOTH sides. From a workstation that means "tunnel", but from
    inside a pod it is simply the Service DNS name and resolves natively. Without
    this, the in-cluster GUI tried to shell out to kubectl -- which the image does
    not contain -- and every data panel silently rendered empty while the page
    itself loaded fine. The failure was invisible because the exception was caught
    and logged at debug level.
    """
    import os
    from pathlib import Path

    if os.environ.get("KUBERNETES_SERVICE_HOST"):
        return True
    return Path("/var/run/secrets/kubernetes.io/serviceaccount").is_dir()


def is_running_in_cluster() -> bool:
    """Public wrapper around _detect_in_cluster().

    Split so tests can assert the DETECTION (by calling _detect_in_cluster) and the
    DECISION (by patching this one) independently. A single function would force
    every decision test to fake the environment instead.
    """
    return _detect_in_cluster()


def is_cluster_internal_host(host: str) -> bool:
    """Does this hostname look cluster-internal (and therefore unresolvable here)?

    Used to decide whether a tunnel is needed at all. A deployment that has
    deliberately exposed ClickHouse (or an operator pointing at 127.0.0.1 through
    their own tunnel) must not have one forced on them.

    Returns False when running IN a pod: cluster DNS resolves the name directly, and
    tunnelling would require kubectl, which the runtime image does not ship.
    """
    if not host:
        return False
    if host in ("localhost", "127.0.0.1", "::1"):
        return False
    if is_running_in_cluster():
        return False
    # A single-label name like `clickhouse` is cluster DNS. A FQDN or an IP is
    # something the operator aimed at deliberately.
    return "." not in host and host != "localhost"
