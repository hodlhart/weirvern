"""The install-time in-cluster DNS probe.

WHY THIS EXISTS AT ALL: the failure it detects is invisible from the symptom. With
`net.bridge.bridge-nf-call-iptables=0` on a node, bridged traffic bypasses iptables, so
the Service ClusterIP is never reverse-translated and CoreDNS answers from its POD
address. A raw UDP query accepts that reply happily (DNS content is fine), but glibc's
resolver uses connect() and the kernel drops a reply from an unexpected source — so
every getaddrinfo in every pod times out with "Temporary failure in name resolution".

Everything downstream then reports "cannot reach ClickHouse at http://clickhouse:8123",
which sends an operator to debug ClickHouse, the password, the Service and the network
policy before anyone suspects DNS. That cost real time on the test cluster, so it earns
one cheap probe at install time.

The probe's hard cases are the ones tested here: it must not claim DNS is broken when it
simply could not look.
"""
from __future__ import annotations

import inspect

from weirvern.admin import cli


class FakeResult:
    def __init__(self, stdout="", stderr="", ok=True):
        self.stdout = stdout
        self.stderr = stderr
        self.ok = ok
        self.returncode = 0 if ok else 1


def test_a_healthy_cluster_reports_success(monkeypatch):
    """The happy path, with the argv captured so we know kubectl was really invoked."""
    import weirvern.admin.cli as c

    calls: list[list[str]] = []

    def runner(args, cwd, timeout=60):
        calls.append(list(args))
        return FakeResult(
            stdout="Server:\t\t198.51.100.10\nAddress:\t198.51.100.10:53\n\n"
                   "Name:\tkubernetes.default\nAddress: 198.51.100.1\n")

    monkeypatch.setattr(c, "_run", runner)
    ok, detail = c._probe_cluster_dns()
    assert ok, detail
    assert calls, "kubectl was never invoked"
    assert calls[0][:2] == ["kubectl", "run"]


def test_the_probe_asks_for_a_name_that_always_exists():
    """Resolving a Weirvern Service would confuse 'DNS broken' with 'not deployed yet'.
    kubernetes.default exists in any healthy cluster."""
    src = inspect.getsource(cli._probe_cluster_dns)
    assert "kubernetes.default" in src
    assert "nslookup" in src


def test_temporary_failure_is_reported_as_broken(monkeypatch):
    """How glibc words it (EAI_AGAIN). Both wordings must be caught, because the probe
    image may use either resolver."""
    import weirvern.admin.cli as c
    monkeypatch.setattr(c, "_run", lambda *a, **k: FakeResult(
        stderr="nslookup: can't resolve 'kubernetes.default': "
               "Temporary failure in name resolution", ok=False))
    ok, _ = c._probe_cluster_dns()
    assert not ok


def test_missing_permission_is_unverifiable_not_a_failure(monkeypatch):
    """A viewer without pod-create rights must not be told the cluster's DNS is broken.
    Reporting a permission problem as a broken dependency is the misreporting class this
    project keeps fixing."""
    import weirvern.admin.cli as c
    monkeypatch.setattr(c, "_run", lambda *a, **k: FakeResult(
        stderr='Error from server (Forbidden): pods "weirvern-dnscheck" is forbidden', ok=False))
    ok, detail = c._probe_cluster_dns()
    assert ok, "a permission error must not be reported as a DNS failure"
    assert "could not verify" in detail
    assert "permission" in detail


def test_a_missing_nslookup_in_the_probe_image_is_unverifiable(monkeypatch):
    """The probe image is configurable; if it lacks nslookup that is our limitation, not
    a cluster fault."""
    import weirvern.admin.cli as c
    monkeypatch.setattr(c, "_run", lambda *a, **k: FakeResult(
        stderr='exec: "nslookup": executable file not found in $PATH', ok=False))
    ok, detail = c._probe_cluster_dns()
    assert ok
    assert "could not verify" in detail


def test_an_unexpected_failure_does_not_cry_wolf(monkeypatch):
    """Anything we do not recognise is reported as unverifiable. A false alarm at
    install time would train operators to ignore the check."""
    import weirvern.admin.cli as c
    monkeypatch.setattr(c, "_run", lambda *a, **k: FakeResult(
        stderr="something entirely unexpected happened", ok=False))
    ok, _detail = c._probe_cluster_dns()
    assert ok, "an unrecognised error must not be reported as broken DNS"


def test_install_wires_the_probe_in_and_explains_the_fix():
    """The check must be CALLED by install, and must print the remediation. A check that
    detects a problem but does not say how to fix it just adds a step to the hunt."""
    src = inspect.getsource(cli.cmd_install)
    assert "_probe_cluster_dns()" in src, "install never runs the DNS probe"
    assert "bridge-nf-call-iptables" in src, "the fix is not stated"
    assert "ready = False" in src[src.find("_probe_cluster_dns()"):], (
        "a broken DNS result must mark the environment not-ready, not warn and continue"
    )


def test_the_probe_uses_an_optional_probe_image_with_no_service_account():
    """It runs a pod, so it must not mount a service-account token: the probe needs no
    API access and the project sets automountServiceAccountToken:false elsewhere."""
    src = inspect.getsource(cli._probe_cluster_dns)
    assert "PROBE_IMAGE" in src, "the probe image should be configurable"
    assert "automountServiceAccountToken" in src
    assert "False" in src


# --- the diagnostic must not crash on a missing optional dependency -------------
def test_install_does_not_import_the_clickhouse_driver():
    """THE BUG: the schema-presence check imported `weirvern.db`, which imports
    clickhouse_connect at module level. On a box without that driver the whole install
    report died partway through with "No module named 'clickhouse_connect'", hiding
    every check after it.

    A prerequisite check exists to diagnose a broken environment, so it must survive the
    most likely broken thing. The schema path resolves relative to the package and needs
    no driver at all.
    """
    import inspect

    from weirvern.admin import cli

    src = inspect.getsource(cli.cmd_install)
    assert "from weirvern import db" not in src, (
        "install imports weirvern.db, which drags in clickhouse_connect and crashes the "
        "diagnostic when the driver is absent"
    )
    # The driver, where it IS needed, must be guarded.
    assert "import clickhouse_connect" in src
    assert "except ImportError" in src, (
        "the local driver import is unguarded; a missing driver would crash install"
    )
    assert "schema" in src, "the schema check disappeared"


def test_install_finds_the_schema_without_the_driver():
    """The replacement path must actually resolve. Checked in this environment, where
    the driver IS installed -- so what is verified is the path, not the absence."""
    from pathlib import Path

    sql_dir = Path(__file__).resolve().parent.parent / "weirvern" / "schema"
    assert sql_dir.is_dir(), f"schema directory not found at {sql_dir}"
    assert sorted(sql_dir.glob("*.sql")), "no schema .sql files"


def test_nxdomain_is_not_reported_as_a_dns_failure(monkeypatch):
    """REGRESSION: the first version accepted any output containing 'Address' as success
    -- and nslookup echoes its Server/Address header even on failure. A reply of

        Server:  198.51.100.10
        Address: 198.51.100.10:53
        ** server can't find kubernetes.default: NXDOMAIN

    was therefore reported as "in-cluster DNS resolves". The header must not be
    mistaken for an answer, and NXDOMAIN means the transport WORKED (the resolver
    replied) so it is not the fault this check hunts for.
    """
    from weirvern.admin import cli

    text = ("Server:\t\t198.51.100.10\nAddress:\t198.51.100.10:53\n\n"
            "** server can't find kubernetes.default: NXDOMAIN\n")
    ok, detail = cli._interpret_dns_probe(text, ok=True)
    assert ok, detail
    assert "answered" in detail, (
        f"an NXDOMAIN must be described as a transport success, got: {detail}"
    )


def test_a_timeout_from_the_resolver_is_a_failure():
    """The actual bridge-nf symptom, which is a TIMEOUT rather than an answer."""
    from weirvern.admin import cli

    ok, detail = cli._interpret_dns_probe(
        ";; connection timed out; no servers could be reached", ok=False)
    assert not ok
    assert "cannot reach" in detail or "cannot resolve" in detail


def test_the_probe_name_is_fully_qualified():
    """`kubernetes.default` relies on the search list, which is itself suspect when DNS
    is broken. The FQDN avoids the search path entirely, so a failure means the
    resolver answered badly rather than that the search list is wrong."""
    import inspect

    from weirvern.admin import cli

    assert "kubernetes.default.svc.cluster.local" in inspect.getsource(cli._probe_cluster_dns)
