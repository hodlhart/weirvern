"""The tunnel decision must be correct on BOTH sides of the cluster boundary.

`clickhouse` is a cluster-internal DNS name that looks identical from a
workstation and from inside a pod, but the correct action is opposite:

  * on a workstation  -> open a `kubectl port-forward`, because the name will not
    resolve and the operator has kubectl and credentials
  * inside a pod      -> connect directly, because the name DOES resolve and the
    runtime image ships no kubectl at all

Getting this wrong is not loud. An earlier version tunnelled in both cases, so the
in-cluster GUI shelled out to a binary that did not exist, caught the failure, and
logged it at DEBUG level. The page loaded, every panel was empty, and nothing said
why — it looked exactly like a deployment with no traffic.
"""
from __future__ import annotations

import pytest

from weirvern.admin import tunnel


@pytest.fixture(autouse=True)
def _not_in_cluster(monkeypatch):
    """Default to 'on a workstation' so pod-specific tests opt in explicitly.

    Only patches the DECISION function. The detector's own tests call
    `_detect_in_cluster()` directly, which is the unpatched implementation, so they
    exercise real logic rather than this stub.
    """
    monkeypatch.delenv("KUBERNETES_SERVICE_HOST", raising=False)
    monkeypatch.setattr(tunnel, "is_running_in_cluster", lambda: False)


def test_single_label_host_tunnels_from_a_workstation():
    assert tunnel.is_cluster_internal_host("clickhouse") is True


def test_single_label_host_does_not_tunnel_inside_a_pod(monkeypatch):
    """The bug: tunnelling here means shelling out to a missing kubectl."""
    monkeypatch.setattr(tunnel, "is_running_in_cluster", lambda: True)
    assert tunnel.is_cluster_internal_host("clickhouse") is False, (
        "cluster DNS resolves natively inside a pod; a tunnel would require "
        "kubectl, which the runtime image does not ship"
    )


@pytest.mark.parametrize("host", ["localhost", "127.0.0.1", "::1", ""])
def test_loopback_never_tunnels(host):
    assert tunnel.is_cluster_internal_host(host) is False


@pytest.mark.parametrize("host", [
    "clickhouse.weirvern.svc.cluster.local",
    "clickhouse.example.com",
    "203.0.113.159",
    "198.51.100.5",
])
def test_explicit_targets_never_tunnel(host):
    """An FQDN or an IP is something an operator aimed at deliberately, so the
    tooling must not second-guess it by inserting a tunnel."""
    assert tunnel.is_cluster_internal_host(host) is False


def test_detects_a_pod_by_the_service_account_mount(monkeypatch, tmp_path):
    """The primary signal: Kubernetes mounts the SA token dir into every pod."""
    monkeypatch.delenv("KUBERNETES_SERVICE_HOST", raising=False)
    real_is_dir = type(tmp_path).is_dir
    import pathlib

    def fake_is_dir(self):
        if str(self) == "/var/run/secrets/kubernetes.io/serviceaccount":
            return True
        return real_is_dir(self)

    monkeypatch.setattr(pathlib.Path, "is_dir", fake_is_dir)
    assert tunnel._detect_in_cluster() is True


def test_detects_a_pod_by_the_service_host_env(monkeypatch):
    """The fallback signal. Needed because this project sets
    automountServiceAccountToken: false on most workloads, so the token directory
    may be absent while KUBERNETES_SERVICE_HOST is still set."""
    monkeypatch.setenv("KUBERNETES_SERVICE_HOST", "198.51.100.1")
    assert tunnel._detect_in_cluster() is True


def test_a_workstation_looks_like_a_workstation(monkeypatch, tmp_path):
    monkeypatch.delenv("KUBERNETES_SERVICE_HOST", raising=False)
    import pathlib

    real_is_dir = pathlib.Path.is_dir
    monkeypatch.setattr(
        pathlib.Path, "is_dir",
        lambda self: False if str(self) == "/var/run/secrets/kubernetes.io/serviceaccount"
        else real_is_dir(self),
    )
    assert tunnel._detect_in_cluster() is False


# --- the admin_client wiring --------------------------------------------------
def test_admin_client_skips_the_tunnel_when_not_needed(monkeypatch):
    """It must pass the settings through unchanged rather than rewriting the host,
    or an operator pointing at an exposed ClickHouse would be redirected."""
    from weirvern.admin import cli as cli_mod

    captured = {}

    def fake_connect(settings, retries=2, delay_s=1):
        captured["settings"] = settings
        return "client"

    monkeypatch.setattr(cli_mod, "admin_client", cli_mod.admin_client, raising=False)
    import weirvern.db as db
    monkeypatch.setattr(db, "connect", fake_connect)
    monkeypatch.setattr(tunnel, "is_cluster_internal_host", lambda h: False)

    class S:
        clickhouse_host = "clickhouse.example.com"
        clickhouse_port = 8123

    with cli_mod.admin_client(S()) as client:
        assert client == "client"
    assert captured["settings"].clickhouse_host == "clickhouse.example.com", (
        "the host was rewritten even though no tunnel was needed"
    )


def test_admin_client_rewrites_the_host_when_tunnelling(monkeypatch):
    """When a tunnel IS used, the client must be pointed at the local port while
    every other setting (credentials, database) is preserved."""
    from contextlib import contextmanager

    from weirvern.admin import cli as cli_mod

    @contextmanager
    def fake_tunnel(namespace, service=None, remote_port=None, local_port=None):
        yield 45678

    monkeypatch.setattr(tunnel, "clickhouse_tunnel", fake_tunnel)
    monkeypatch.setattr(tunnel, "is_cluster_internal_host", lambda h: True)

    captured = {}

    def fake_connect(settings, retries=2, delay_s=1):
        captured["settings"] = settings
        return "client"

    import weirvern.db as db
    monkeypatch.setattr(db, "connect", fake_connect)

    from dataclasses import dataclass

    @dataclass
    class S:
        clickhouse_host: str = "clickhouse"
        clickhouse_port: int = 8123
        clickhouse_db: str = "weirvern"
        clickhouse_user: str = "weirvern"
        clickhouse_password: str = "secret"

    with cli_mod.admin_client(S()) as client:
        assert client == "client"
    s = captured["settings"]
    assert s.clickhouse_host == "127.0.0.1", "the client was not pointed at the tunnel"
    assert s.clickhouse_port == 45678
    assert s.clickhouse_user == "weirvern", "credentials must survive the rewrite"
    assert s.clickhouse_db == "weirvern"
    assert s.clickhouse_password == "secret"
