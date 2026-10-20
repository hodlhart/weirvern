"""Weirvern control CLI — install, configure, run, and monitor the stack.

Design intent: a single entry point an operator can learn in a minute, that
works everywhere, and that never lies about state. Every command either does
the thing or explains precisely why it cannot.

    weirvern install     # create .env from template, detect runtime, first checks
    weirvern init-db     # apply the ClickHouse schema
    weirvern start/stop/restart [service...]
    weirvern status      # health probes + service table
    weirvern logs [service]
    weirvern config      # list / get / set / validate .env keys
    weirvern tune        # interactive threshold editing

Exit codes: 0 ok, 1 failure, 2 usage error, 3 environment not ready.
"""
from __future__ import annotations

import argparse
import contextlib
import json
import logging
import os
import re
import sys
from contextlib import contextmanager
from pathlib import Path

from weirvern.admin import config_io
from weirvern.admin import status as status_mod
from weirvern.admin.runtime import (
    NAMESPACE,
    WORKLOADS,
    _condense,
    _run,
    detect_capabilities,
    find_project_dir,
    get_backend,
)

# The project directory is resolved LAZILY, not at import time.
#
# Resolving it here crashed the `weirvern init-db` entry point inside the
# container image: the Containerfile copies only pyproject/README/LICENSE and the
# package, so the image has neither k8s/ nor .env.example, and find_project_dir()
# raised at IMPORT — before argparse could run. The schema Job runs the exact
# command `weirvern init-db`, so it died instantly, retried, and the deployment
# created ZERO TABLES while the README said the schema was applied automatically.
#
# Only commands that genuinely need a checkout (install, apply, down, tune)
# pay for resolution, and only when they run. `init-db` needs a database, not a
# checkout.
_CACHED_PROJECT_DIR: Path | None = None


def project_dir() -> Path:
    """Resolve the project directory on first use (see the note above)."""
    global _CACHED_PROJECT_DIR
    if _CACHED_PROJECT_DIR is None:
        _CACHED_PROJECT_DIR = find_project_dir()
    return _CACHED_PROJECT_DIR


EXIT_OK, EXIT_FAIL, EXIT_USAGE, EXIT_NOTREADY = 0, 1, 2, 3


def _c(color: str, text: str) -> str:
    """ANSI colour, disabled when not a TTY or NO_COLOR is set."""
    if not sys.stdout.isatty() or os.environ.get("NO_COLOR"):
        return text
    codes = {"red": "31", "green": "32", "yellow": "33", "blue": "34", "dim": "2", "bold": "1"}
    return f"\033[{codes.get(color, '0')}m{text}\033[0m"


def _ok(msg: str) -> None:
    print(f"{_c('green', '✓')} {msg}")


def _bad(msg: str) -> None:
    print(f"{_c('red', '✗')} {msg}")


def _warn(msg: str) -> None:
    print(f"{_c('yellow', '!')} {msg}")


def _probe_cluster_dns(timeout: int = 45) -> tuple[bool, str]:
    """Can pods resolve Service names?

    Runs a throwaway pod and asks it to resolve a name that ALWAYS exists in a healthy
    cluster (`kubernetes.default`), so a failure means DNS is broken rather than that a
    particular Service is missing.

    WHY THIS IS WORTH A PROBE: the underlying fault
    (`net.bridge.bridge-nf-call-iptables=0` on a node) makes DNS *content* look fine --
    a raw query to the CoreDNS ClusterIP answers immediately -- while glibc's connect()
    based resolver silently drops the mismatched source address. Everything downstream
    then reports "cannot reach ClickHouse", so an operator debugs ClickHouse. One cheap
    probe at install time replaces that whole hunt.

    Returns (ok, detail). A cluster with no cluster-admin cannot run the probe pod, and
    that is reported as unverifiable rather than as a failure: claiming DNS is broken
    when we simply could not look would be its own misdiagnosis.
    """
    r = _run(["kubectl", "run", "weirvern-dnscheck", "-n", NAMESPACE,
              "--rm", "-i", "--restart=Never", "--quiet",
              "--image", PROBE_IMAGE,
              "--overrides", json.dumps({"spec": {"dnsPolicy": "ClusterFirst",
                                                  "automountServiceAccountToken": False}}),
              "--", "nslookup", "kubernetes.default.svc.cluster.local"],
             project_dir(), timeout=timeout)
    return _interpret_dns_probe(f"{r.stdout or ''}\n{r.stderr or ''}", r.ok)


def _interpret_dns_probe(text: str, ok: bool) -> tuple[bool, str]:
    """Judge a probe result. Split out so the wordings are testable.

    ORDER MATTERS, and an earlier version got it wrong: it accepted any output
    containing "Address" as success, so a reply reading
    `Server: 198.51.100.10 Address: 198.51.100.10:53` followed by
    `** server can't find kubernetes.default: NXDOMAIN` was reported as
    "DNS resolves". The Server/Address header is echoed even on failure, so the
    FAILURE wordings must be checked first.

    NXDOMAIN also tells us something useful: the resolver ANSWERED, so the transport is
    fine and only the name is missing -- a different problem from DNS being unreachable.
    """
    low = text.lower()

    # 1. Failures first. These are the signals that the transport is broken, which is the
    #    bridge-nf fault.
    if "temporary failure in name resolution" in low:
        return False, "pods cannot resolve Service names (resolver timed out)"
    if "no servers could be reached" in low or "connection timed out" in low:
        return False, "pods cannot reach the cluster DNS service at all"
    # 2. The resolver answered but has no such name. Transport is healthy; this is a
    #    cluster-content problem, not DNS reachability, so it must NOT be reported as a
    #    DNS failure.
    if "nxdomain" in low or "can't find" in low or "servfail" in low:
        return True, "cluster DNS answered (name not found, transport is healthy)"
    # 3. Our own limitations.
    if "forbidden" in low or "cannot create" in low or "unauthorized" in low:
        return True, "could not verify (no permission to run a probe pod)"
    if "executable file not found" in low or "command not found" in low:
        return True, "could not verify (probe image has no nslookup)"
    # 4. A real answer, with an address that is not just the server's own.
    if ok and re.search(r"name:\s*\S+", low):
        return True, "kubernetes.default resolves"
    return True, "could not verify"


def env_path() -> Path:
    """`<project>/.env`, or a path that does not exist when there is no checkout.

    WHY THIS TOLERATES A MISSING PROJECT DIRECTORY.

    `project_dir()` raises when it cannot find a checkout, and the container image deliberately
    ships only the package -- so no k8s/ and no .env.example. Every command that reads
    configuration was therefore CRASHING inside the cluster, including `weirvern intercept`:

        ✗ unexpected error: could not locate the Weirvern project directory. Looked for a
          directory containing k8s/kustomization.yaml or .env.example, in: $WEIRVERN_HOME, the
          ancestors of the current directory, and the repository containing this package.

    That is the same defect this module already documents for `init-db` (see the note on
    `project_dir` below), reached by a different route: a command that needs CONFIGURATION does
    not need a CHECKOUT, and in-cluster the configuration comes from the environment and the
    ConfigMap, never from a `.env` file.

    Returning a non-existent path under the current directory preserves the calling convention
    exactly -- callers already do `env_path().exists()` or `EnvFile.load(...) if ... .exists()` --
    without inventing a file that is not there. A deployment with a real checkout is unaffected:
    `find_project_dir()` succeeds and this returns the same path as before.
    """
    try:
        return project_dir() / ".env"
    except Exception:  # noqa: BLE001 - ProjectDirNotFound and anything similar
        return Path(".env")


# The image used for one-shot utility pods (the interface probe). Deliberately a
# tiny base rather than the application image: the probe reads /sys and /proc only,
# so pulling a 15 MB+ worker image to answer a question about NICs would be slow and
# pointless. Overridable for an air-gapped registry.
PROBE_IMAGE = os.environ.get("WEIRVERN_PROBE_IMAGE", "busybox:1.37")


def _cluster_config() -> dict[str, str]:
    """Read the live cluster ConfigMap, as a flat dict.

    Returns {} on any failure rather than raising: callers use this to enrich a
    check, and a missing ConfigMap must not abort a diagnostic that is otherwise
    useful (the whole point of these commands is to work when something is wrong).
    """
    r = _run(["kubectl", "-n", NAMESPACE, "get", "configmap", "weirvern-env",
              "-o", "jsonpath={.data}"], project_dir(), timeout=20)
    if not r.ok or not (r.stdout or "").strip():
        return {}
    try:
        data = json.loads(r.stdout)
    except (ValueError, TypeError):
        return {}
    return data if isinstance(data, dict) else {}


def _sensor_image() -> str:
    """The image to run the interface probe in.

    The probe is a stdlib Python program, but the images in this project do not all
    ship Python (the worker does, busybox does not). Resolving that here rather than
    hardcoding one image means the command keeps working if a deployment swaps the
    base: prefer the worker image, which is known to have Python, and fall back to
    the busybox probe image only if asked.
    """
    for kind, name in (("deployment", "weirvern-worker"), ("daemonset", "zeek")):
        r = _run(["kubectl", "-n", NAMESPACE, "get", kind, name,
                  "-o", "jsonpath={.spec.template.spec.containers[0].image}"],
                 project_dir(), timeout=15)
        img = (r.stdout or "").strip()
        if r.ok and img:
            return img
    return PROBE_IMAGE


def _connect(settings):
    from weirvern import db
    return db.connect(settings, retries=2, delay_s=1)


@contextmanager
def admin_client(settings):
    """A ClickHouse client for control-plane commands, tunnelling if needed.

    WHY THIS EXISTS: `weirvern status` runs on the OPERATOR's machine,
    but CLICKHOUSE_HOST defaults to `clickhouse` — a cluster-internal name that
    cannot resolve outside the cluster, and the `clickhouse-external` Service ships
    as ClusterIP with its NodePort commented out. So there was no route from the
    host at all, and `weirvern status` showed every workload healthy while its Health
    and Anomalies panels reported a connection error. That reads like a broken
    deployment rather than an unreachable one.

    The tunnel opens only when the configured host actually looks cluster-internal,
    so a deployment that deliberately exposed ClickHouse — or an operator already
    running their own port-forward — is never second-guessed.
    """
    from dataclasses import replace

    from weirvern import db
    from weirvern.admin import tunnel

    if not tunnel.is_cluster_internal_host(settings.clickhouse_host):
        yield db.connect(settings, retries=2, delay_s=1)
        return

    with tunnel.clickhouse_tunnel(NAMESPACE) as local_port:
        # Point the client at the tunnel. `replace` keeps every other setting
        # (credentials, database) exactly as configured.
        tunnelled = replace(settings, clickhouse_host="127.0.0.1",
                            clickhouse_port=local_port)
        yield db.connect(tunnelled, retries=2, delay_s=1)


# ---------------------------------------------------------------------------
# install
# ---------------------------------------------------------------------------
def cmd_install(args: argparse.Namespace) -> int:
    """Prerequisite check.

    Returns EXIT_NOTREADY (3) when the environment cannot deploy yet, distinct
    from EXIT_FAIL (1) for a real error. Without that distinction a script or CI
    step cannot tell "prerequisites missing" from "something broke" — both
    exited 0 previously.
    """
    ready = True
    print(_c("bold", "Weirvern install check"))
    print()

    # 1. .env — used for LOCAL runs (the CLI itself, `init-db`, `tune`). The
    #    cluster takes its configuration from k8s/20-configmap-env.yaml, so this
    #    step is about making the local tooling work, not about the deployment.
    target = env_path()
    if target.exists() and not args.force:
        _ok(f".env already exists ({target})")
    else:
        if target.exists():
            backup = config_io.EnvFile.load(target).backup(".bak")
            _warn(f"overwriting existing .env (backup: {backup})")
        try:
            env = config_io.EnvFile.from_example(project_dir() / ".env.example", target)
            env.save()
            _ok(f"created {target} from .env.example")
        except FileNotFoundError as exc:
            _bad(str(exc))
            return EXIT_FAIL

    env = config_io.EnvFile.load(target)
    if env.duplicates():
        _warn(f"duplicate keys in .env (last wins): {', '.join(env.duplicates())}")

    # 2. Kubernetes tooling.
    caps = detect_capabilities(project_dir())
    if caps.kubectl:
        _ok("kubectl found")
    else:
        _bad(f"kubectl unavailable: {caps.reason}")
        ready = False
    if caps.cluster_available:
        _ok("cluster reachable")
    else:
        _warn(caps.reason or "no reachable cluster")
        ready = False
    # In-cluster DNS. This is checked because its failure is SILENT and looks like
    # something else entirely: with net.bridge.bridge-nf-call-iptables unset on the
    # node, bridged traffic bypasses iptables, the Service ClusterIP is never
    # reverse-translated, and CoreDNS answers from its POD address instead of the
    # service address -- so every getaddrinfo in every pod times out with
    # "Temporary failure in name resolution" while DNS content itself looks healthy.
    # The symptom appears as "the GUI cannot reach ClickHouse", which sends you looking
    # in entirely the wrong place, so it is worth one cheap probe at install time.
    if caps.cluster_available:
        dns_ok, dns_detail = _probe_cluster_dns()
        if dns_ok:
            _ok(f"in-cluster DNS resolves ({dns_detail})")
        else:
            _bad(f"in-cluster DNS is NOT working: {dns_detail}")
            print(_c("dim", "    Pods will fail to resolve Service names, which shows up as"))
            print(_c("dim", "    'cannot reach ClickHouse' in the GUI or worker logs."))
            print(_c("dim", "    Fix on every node, then reboot or re-apply:"))
            print(_c("dim", "      sysctl -w net.bridge.bridge-nf-call-iptables=1"))
            print(_c("dim", "      echo 'net.bridge.bridge-nf-call-iptables = 1' "
                            "> /etc/sysctl.d/99-k3s-bridge-nf.conf"))
            ready = False
    if caps.namespace:
        _ok(f"namespace '{NAMESPACE}' exists")
    else:
        _warn(f"namespace '{NAMESPACE}' not found yet")
    if caps.kustomize:
        _ok("kustomize found (kustomize build k8s/ works standalone)")
    else:
        # kubectl has built-in kustomize support via -k, so this is not a blocker.
        print(_c("dim", "    kustomize binary not found — `kubectl apply -k` still works "
                        "(kubectl has kustomize built in)"))

    # 3. Manifests present and buildable.
    if caps.manifests:
        _ok("k8s/kustomization.yaml present")
    else:
        _bad("k8s/kustomization.yaml missing — cannot deploy")
        return EXIT_FAIL

    # 4. Schema file present INSIDE THE PACKAGE. The schema Job applies it
    #    in-cluster using this same file, resolved relative to the installed
    #    package, so its absence is fatal rather than cosmetic — and a repo-level
    #    copy would not fix a real install (verified: the path resolved outside
    #    the package and the job applied nothing while reporting success).
    #
    #    Resolved WITHOUT importing weirvern.db, because that module imports
    #    clickhouse_connect at the top level. A prerequisite CHECK must not crash on a
    #    driver that is not installed here -- on the test box this raised
    #    "No module named 'clickhouse_connect'" and killed the whole install report
    #    partway through, hiding every check after it. The schema directory resolves the
    #    same way (relative to the package) without pulling in the driver.
    sql_dir = Path(__file__).resolve().parent.parent / "schema"
    sql_files = sorted(sql_dir.glob("*.sql")) if sql_dir.is_dir() else []
    if sql_files:
        _ok(f"ClickHouse schema present in the package "
            f"({', '.join(p.name for p in sql_files)})")
    else:
        _bad(f"no schema .sql files in {sql_dir} — cannot create tables")
        return EXIT_FAIL
    # The local driver is only needed for LOCAL database commands. Report it as a note
    # rather than a failure: a cluster deployment applies the schema in-cluster, where
    # the image has the driver.
    try:
        import clickhouse_connect  # noqa: F401
        _ok("clickhouse-driver available locally (needed for init-db/tune)")
    except ImportError:
        print(_c("dim", "    clickhouse-connect not installed locally — `weirvern init-db` "
                        "and `weirvern tune` need it; the cluster applies the schema "
                        "itself and does not"))

    # 5. Secrets. Checked against the CLUSTER secret (that is what the pod reads),
    #    falling back to reporting that it cannot be verified.
    #
    #    NOTE ON RBAC: this check reads the Secret, so it needs `get` on `secrets`
    #    in this namespace. The shipped weirvern-viewer Role deliberately does NOT
    #    grant that (so an identity that displays health cannot exfiltrate the
    #    alert credentials), which means under the viewer role this check cannot
    #    complete. That is handled honestly below: a 403 is reported as "cannot
    #    read", which is a different statement from "not set". Reporting a
    #    permission error as a missing credential would send an operator hunting
    #    for a Pushover problem that does not exist.
    print()
    alerts_on = (env.get("PUSHOVER_ENABLED") or "0") in {"1", "true", "yes"}
    if caps.cluster_available:
        for key in ("PUSHOVER_USER_KEY", "PUSHOVER_API_TOKEN"):
            r = _run(["kubectl", "-n", NAMESPACE, "get", "secret", "weirvern-secrets",
                      "-o", f"jsonpath={{.data.{key}}}"], project_dir(), timeout=20)
            value = (r.stdout or "").strip()
            err = (r.stderr or "").lower()
            # Distinguish three states, because they collapse into one warning
            # here and that is the misreporting class this project keeps finding:
            # a permission failure then looks like a configuration failure.
            #   set              -> ok
            #   readable, empty  -> genuinely not set
            #   not readable     -> RBAC; say so, do not imply the key is missing
            if r.ok and value and value != '""':
                _ok(f"{key} is set in the cluster secret")
            elif r.ok:
                _warn(f"{key} is NOT set in the cluster secret"
                      + (" — alerts will fail" if alerts_on else " (fine while disabled)"))
            elif "forbidden" in err or "cannot get" in err or "access denied" in err:
                print(_c("dim", f"    {key}: cannot read the secret with these "
                                f"credentials (RBAC). The shipped viewer role has no "
                                f"secret access by design; use the operator kubeconfig "
                                f"or check it with kubectl directly."))
            elif "not found" in err:
                _warn("secret weirvern-secrets not found — create it (README step 4)"
                      + ("; alerts will FAIL" if alerts_on else ""))
            else:
                _warn(f"could not verify {key}: {_condense(r.text)}")
    else:
        _warn("cannot verify Pushover credentials without a cluster connection")
    if alerts_on:
        _ok("PUSHOVER_ENABLED is reported on in .env (the cluster value is in the ConfigMap)")
    else:
        _warn("PUSHOVER_ENABLED=0 in .env — alerts are log-only (fine for a first run)")

    print()
    print(_c("bold", "Next steps"))
    steps = []
    if not caps.kubectl:
        steps.append("install kubectl and a kubeconfig (see README.md)")
    if not caps.cluster_available:
        steps.append("point kubectl at your cluster, then re-run: weirvern install")
    # The sensor needs a labelled node; say so up front because it is the single
    # most common reason a first deployment captures nothing.
    steps.append("label the sensor node:  kubectl label node <node> weirvern.io/sensor-node=true")
    steps.append(
        "review k8s/20-configmap-env.yaml (ZEEK_IFACE, TZ), then create the "
        "weirvern-secrets Secret (see README step 4)"
    )
    steps.append("deploy:  weirvern apply")
    steps.append("verify:  weirvern status")
    for i, text in enumerate(steps, start=1):
        print(f"  {i}. {text}")

    if ready and caps.cluster_available:
        print()
        _ok("environment is ready to deploy")
        return EXIT_OK
    print()
    _warn("environment is not ready yet — see the steps above")
    return EXIT_NOTREADY


# ---------------------------------------------------------------------------
# schema
# ---------------------------------------------------------------------------
def cmd_init_db(args: argparse.Namespace) -> int:
    from weirvern import db
    from weirvern.config import get_settings

    settings = get_settings()
    print(f"applying schema to {settings.http_url} (db: {settings.clickhouse_db})")
    try:
        client = db.connect(settings, retries=args.retries, delay_s=2)
    except Exception as exc:  # noqa: BLE001
        _bad(f"cannot connect: {exc}")
        return EXIT_NOTREADY
    db.apply_schema(client, settings)
    rows = sorted(r[0] for r in client.query(f"SHOW TABLES FROM {settings.clickhouse_db}").result_rows)
    _ok(f"schema applied — {len(rows)} objects")
    for r in rows:
        print(f"    {r}")
    client.close()
    return EXIT_OK


# ---------------------------------------------------------------------------
# lifecycle
# ---------------------------------------------------------------------------
def _backend():
    caps = detect_capabilities(project_dir())
    return get_backend(project_dir(), caps), caps


def _lifecycle(action: str, args: argparse.Namespace) -> int:
    backend, caps = _backend()
    services = args.services or None
    if action == "start":
        result = backend.start(services, build=getattr(args, "build", False))
    elif action == "stop":
        result = backend.stop(services)
    elif action == "restart":
        result = backend.restart(services)
    elif action == "apply":
        result = backend.apply(dry_run=getattr(args, "dry_run", False))
    elif action == "down":
        result = backend.down(volumes=getattr(args, "volumes", False))
    elif action == "pull":
        result = backend.pull()
    else:
        _bad(f"unknown action {action}")
        return EXIT_USAGE

    if result.ok:
        _ok(f"{action}: ok" + (f" ({', '.join(services)})" if services else ""))
        if result.text:
            print(_c("dim", result.text[-2000:]))
        return EXIT_OK
    _bad(f"{action} failed")
    if result.text:
        print(result.text[-2000:])
    # Distinguish "the cluster refused" from "there is no cluster": the second is
    # an environment problem the operator fixes once, not a command failure.
    return EXIT_FAIL if caps.cluster_available else EXIT_NOTREADY


def cmd_logs(args: argparse.Namespace) -> int:
    backend, caps = _backend()
    # Base the exit code on whether the fetch SUCCEEDED, not on whether a string
    # came back: a failed kubectl returns its error text, so `out` was always
    # truthy and this command exited 0 even with no cluster at all — unusable as a
    # script or CI check.
    if hasattr(backend, "logs_result"):
        out, ok = backend.logs_result(args.service or "", tail=args.tail)
    else:
        out = backend.logs(args.service or "", tail=args.tail)
        ok = bool(out)
    print(out or _c("dim", "(no log output)"))
    if ok:
        return EXIT_OK
    return EXIT_FAIL if caps.cluster_available else EXIT_NOTREADY


def cmd_wait(args: argparse.Namespace) -> int:
    """"Block until every workload reports ready — the useful thing to run after
    `weirvern apply`, because `apply` returns as soon as the API accepts the
    objects, long before any pod is serving."""
    backend, caps = _backend()
    if not caps.cluster_available:
        _bad(caps.reason or "no cluster available")
        return EXIT_NOTREADY
    print(f"waiting up to {args.timeout}s for all workloads to become ready...")
    result = backend.wait_ready(timeout_s=args.timeout)
    print(result.text)
    if result.ok:
        _ok("all workloads ready")
        return EXIT_OK
    _bad("not all workloads became ready")
    print(_c("dim", "  inspect with: weirvern status ; weirvern logs <service>"))
    return EXIT_FAIL


# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------
def cmd_status(args: argparse.Namespace) -> int:
    backend, caps = _backend()
    print(_c("bold", f"Workloads (namespace: {NAMESPACE})"))
    states = backend.ps()
    if states:
        for s in states:
            health = f" [{s.health}]" if s.health else ""
            detail = f"  {_c('dim', s.detail)}" if s.detail else ""
            print(f"  {s.dot} {s.name:<18} {s.state}{health}{detail}")
    else:
        if caps.cluster_available:
            _warn("no workloads reported — are the manifests applied?")
            print(_c("dim", "    deploy with: weirvern apply"))
        else:
            _warn(f"cannot inspect workloads: {caps.reason}")

    # Metrics are optional (they need metrics-server); omitted rather than shown
    # as an error when unavailable.
    try:
        stats = backend.stats()
    except Exception:  # noqa: BLE001
        stats = {}
    if stats:
        print()
        print(_c("bold", "Resource use"))
        for name, value in sorted(stats.items()):
            print(f"    {name:<34} {value}")

    print()
    print(_c("bold", "Health"))
    from weirvern.config import get_settings
    settings = get_settings()
    try:
        # `admin_client` opens a port-forward automatically when the configured
        # host is cluster-internal (the default), so `weirvern status` works from
        # a workstation without the operator setting one up by hand.
        with admin_client(settings) as client:
            report = status_mod.collect_health(client, settings)
            # SIPHON-1 LOUD CHECK: a siphon-CONFIGURED sensor with no live intercept is the
            # state where every config-derived surface says "in-path" while nothing is
            # redirected. Read the CONFIGURED mode from the cluster (where the sensor
            # actually gets it), falling back to this environment.
            configured_mode = (
                _cluster_config().get("SENSOR_MODE") or settings.sensor_mode or ""
            )
            liveness = status_mod.siphon_liveness(configured_mode, client)
    except Exception as exc:  # noqa: BLE001
        _bad(f"cannot reach ClickHouse: {_condense(str(exc), 160)}")
        print(_c("dim", "    Tried to tunnel to svc/clickhouse automatically. "
                        "If that failed, check:"))
        print(_c("dim", "      kubectl -n weirvern get pods -l app.kubernetes.io/name=clickhouse"))
        print(_c("dim", "      kubectl -n weirvern port-forward svc/clickhouse 8123:8123"))
        return EXIT_NOTREADY

    for p in report.probes:
        marker = _c("green", "✓") if p.ok else _c("red", "✗")
        print(f"  {marker} {p.name:<18} {p.detail}")

    # The mode row, then the liveness verdict. Order matters: the mode line states what
    # is CONFIGURED, and the verdict states whether that is actually true -- printing the
    # config first and the reality second is the only order in which the pair is honest.
    if liveness.get("applicable"):
        print()
        if liveness.get("live"):
            _ok(f"siphon intercept LIVE — {liveness['hosts']} host(s), "
                f"{liveness['mappings']} mapping(s), heartbeat {liveness['age_s']}s old")
        else:
            _bad("SENSOR_MODE=siphon is configured but no intercept is live:")
            for line in _wrap(str(liveness.get("error") or ""), 74):
                print(f"    {line}")
            return EXIT_FAIL
    return EXIT_OK if report.ok else EXIT_FAIL


def _wrap(text: str, width: int) -> list[str]:
    """Soft-wrap for the status output's indented blocks. textwrap keeps the code short
    at the call site and the width consistent with the probe lines above."""
    import textwrap
    return textwrap.wrap(text, width=width) or [""]


# ---------------------------------------------------------------------------
# config
# ---------------------------------------------------------------------------
CONFIG_HELP = {
    "PUSHOVER_USER_KEY": "Pushover account user key (secret)",
    "PUSHOVER_API_TOKEN": "Pushover application token (secret)",
    "PUSHOVER_ENABLED": "1 to actually send pushes, 0 for log-only",
    "PUSHOVER_COOLDOWN_S": "per-source alert cooldown, seconds",
    "PUSHOVER_MAX_PER_HOUR": "global alert cap per hour",
    "BASE_THRESHOLD": "ensemble score floor for alerting (0-1)",
    "MIN_AGREEMENT": "fraction of detectors that must fire",
    "DETECT_INTERVAL_S": "detection sweep cadence, seconds",
    "RETRAIN_EVERY_H": "full retrain cadence, hours",
    "ZEEK_IFACE": "interface the Zeek sensor sniffs (the capture port)",
    "MGMT_IFACE": "management port (default route, SSH, API) — not sniffed",
    "SENSOR_MODE": "loch = passive capture, siphon = in-path intercept",
    "ZEEK_MAX_MB": "cap on rotated Zeek logs (MB); see `weirvern disk`",
    "NETFLOW_MAX_MB": "cap on the raw flow sink (MB)",
    "ML_MAX_MB": "cap on ClickHouse table data (MB)",
    "INTERCEPT_TARGETS": "siphon mode: who to intercept (empty = nobody)",
    "CLICKHOUSE_HOST": "ClickHouse hostname",
    "CLICKHOUSE_PORT": "ClickHouse HTTP port",
    "CLICKHOUSE_DB": "ClickHouse database name",
    "TZ": "timezone for windows and logs",
}


def cmd_config(args: argparse.Namespace) -> int:
    env = config_io.EnvFile.load(env_path())
    if not env.lines:
        _bad(f"{env_path()} not found — run `weirvern install`")
        return EXIT_NOTREADY

    if args.action == "list":
        for key in env.keys():  # noqa: SIM118 - EnvFile is not a dict
            val = env.get(key) or ""
            shown = config_io.mask(val) if config_io.is_secret(key) else val
            help_text = CONFIG_HELP.get(key, "")
            pad = 24
            print(f"  {key:<{pad}} {shown:<28} {_c('dim', help_text)}")
        dups = env.duplicates()
        if dups:
            _warn(f"duplicate keys: {', '.join(dups)}")
        return EXIT_OK

    if args.action == "get":
        if args.key is None or args.key not in env.keys():  # noqa: SIM118 - not a dict
            _bad(f"unknown key: {args.key}")
            return EXIT_USAGE
        val = env.get(args.key) or ""
        print(config_io.mask(val) if config_io.is_secret(args.key) else val)
        return EXIT_OK

    if args.action == "set":
        if not args.key or args.value is None:
            _bad("set requires KEY VALUE")
            return EXIT_USAGE
        env.backup(".bak")
        env.set(args.key, args.value)
        env.save()
        _ok(f"{args.key} updated (backup written)")
        return EXIT_OK

    if args.action == "validate":
        return _validate_env(env)

    _bad(f"unknown config action: {args.action}")
    return EXIT_USAGE


def _validate_env(env: config_io.EnvFile) -> int:
    problems: list[str] = []
    dupes = env.duplicates()
    if dupes:
        problems.append(f"duplicate keys (ambiguous): {', '.join(dupes)}")

    for key, checker, msg in (
        ("BASE_THRESHOLD", lambda v: _in_range(v, 0.0, 1.0), "must be in (0, 1]"),
        ("MIN_AGREEMENT", lambda v: _in_range(v, 0.0, 1.0), "must be in (0, 1]"),
        ("DETECT_INTERVAL_S", lambda v: _is_int(v) and int(v) >= 10, "must be an integer >= 10"),
        ("RETRAIN_EVERY_H", lambda v: _is_int(v) and int(v) >= 1, "must be an integer >= 1"),
        ("PUSHOVER_COOLDOWN_S", lambda v: _is_int(v) and int(v) >= 0, "must be an integer >= 0"),
    ):
        raw = env.get(key)
        if raw is None or raw == "":
            continue
        if not checker(raw):
            problems.append(f"{key}={raw!r} {msg}")

    if (env.get("PUSHOVER_ENABLED", "0") or "0").lower() in {"1", "true", "yes"}:
        for k in ("PUSHOVER_USER_KEY", "PUSHOVER_API_TOKEN"):
            if not env.get(k):
                problems.append(f"PUSHOVER_ENABLED=1 but {k} is empty")

    mode = env_path().stat().st_mode & 0o777 if env_path().exists() else None
    if mode is not None and mode & 0o077:
        problems.append(f".env permissions are {oct(mode)} — secrets are world/group readable (chmod 600)")

    if problems:
        for p in problems:
            _bad(p)
        return EXIT_FAIL
    _ok("configuration looks valid")
    return EXIT_OK


def _is_int(v: str) -> bool:
    try:
        int(v)
        return True
    except ValueError:
        return False


def _in_range(v: str, lo: float, hi: float) -> bool:
    try:
        return lo < float(v) <= hi
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# tune (interactive thresholds)
# ---------------------------------------------------------------------------
def cmd_tune(args: argparse.Namespace) -> int:
    """Guided editing of the detection thresholds, with live feedback."""
    env = config_io.EnvFile.load(env_path())
    if not env.lines:
        _bad("no .env — run `weirvern install` first")
        return EXIT_NOTREADY

    knobs = [
        ("BASE_THRESHOLD", "score floor for alerting", "higher = fewer alerts"),
        ("MIN_AGREEMENT", "detectors that must fire", "higher = fewer alerts"),
        ("DETECT_INTERVAL_S", "sweep cadence (sec)", "lower = faster, more CPU"),
        ("RETRAIN_EVERY_H", "full retrain cadence (h)", "lower = adapts faster"),
        ("PUSHOVER_COOLDOWN_S", "per-source cooldown (sec)", "higher = quieter"),
        ("PUSHOVER_MAX_PER_HOUR", "hourly alert cap", "higher = chattier"),
    ]
    print(_c("bold", "Detection tuning"))
    print(_c("dim", "Enter to keep the current value. Settings save to .env."))
    print()
    changed = 0
    for key, label, hint in knobs:
        current = env.get(key, "")
        try:
            new = input(f"  {key} [{current}] ({hint})\n    {label}: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if new and new != current:
            env.set(key, new)
            changed += 1

    # Show the resulting alert-rate implication before saving.
    print()
    thr_raw = env.get("BASE_THRESHOLD") or "0.35"
    print(f"  resulting configuration: {changed} change(s), BASE_THRESHOLD={thr_raw}")

    # Optionally preview against real data.
    try:
        threshold = float(thr_raw)
    except ValueError:
        threshold = None

    if threshold is not None:
        try:
            from weirvern.config import get_settings
            settings = get_settings()
            client = _connect(settings)
            rows = client.query(
                "SELECT countIf(anomaly_score >= %(t)s) AS above, count() AS total "
                "FROM weirvern.netflow_anomalies WHERE detected_at >= now() - INTERVAL 7 DAY",
                parameters={"t": threshold},
            ).result_rows
            if rows and rows[0][1]:
                above, total = rows[0]
                print(_c("dim", f"  last 7 days: {above}/{total} recorded anomalies are at/above {thr_raw}"))
            client.close()
        except Exception:  # noqa: BLE001
            print(_c("dim", "  (live preview unavailable — database not reachable)"))

    if changed:
        env.backup(".bak")
        env.save()
        _ok(f"saved {changed} setting(s) (backup written)")
        print(_c("dim", "  restart the worker for changes to take effect:"))
        print(_c("dim", "    weirvern restart weirvern-worker"))
    else:
        print(_c("dim", "  nothing changed"))
    return EXIT_OK


def cmd_gui(args: argparse.Namespace) -> int:
    """Serve the web dashboard.

    Accounts and roles: reads require a signed-in account, settings writes require an
    admin (or the break-glass operator token). There is still no lifecycle control --
    start, stop and apply stay in the CLI. See weirvern/admin/web.py for the
    reasoning.

    ON THE PROJECT DIRECTORY: `project_dir()` used to be called unconditionally
    here, and it RAISES inside the container image -- the Containerfile copies only
    pyproject/README/LICENSE plus the package, so the image has neither k8s/ nor
    .env.example for find_project_dir to recognise. That made the GUI pod
    CrashLoopBackOff with

        could not locate the Weirvern project directory; set WEIRVERN_HOME

    which is the same defect class as the schema Job's import-time crash. The
    project directory is only needed to locate the CLUSTER (for the Workloads
    panel), so its absence is now tolerated: the GUI serves every data panel from
    ClickHouse alone.
    """
    from weirvern.admin import web
    from weirvern.config import get_settings

    # AUDIT LINES AT INFO ARE THE POINT. Without this, Python's last-resort handler prints only
    # WARNING and above -- so a deployment's log showed the bootstrap password and rejected
    # sign-ins but NOT one successful sign-in, password change, role change or account
    # creation. Diagnosing "I can't sign in" needs exactly those lines, and the worker and
    # ingester already configure the same level: a service that logs its failures but not its
    # successes cannot be read.
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

    settings = get_settings()
    host = args.host or os.environ.get("GUI_HOST", web.DEFAULT_HOST)
    port = args.port or int(os.environ.get("GUI_PORT", str(web.DEFAULT_PORT)))
    shown = "127.0.0.1" if host in ("0.0.0.0", "::") else host
    print(_c("bold", f"Weirvern GUI on http://{shown}:{port}"))
    if host in ("0.0.0.0", "::"):
        print(_c("dim", "    bound to all interfaces; anyone who can reach this "
                        "port can read your flow data once signed in"))
    print(_c("dim", "    accounts: reads need a sign-in; settings changes need an admin"))
    print(_c("dim", "    no start/stop/apply actions are exposed"))

    try:
        pdir = project_dir()
    except Exception:  # noqa: BLE001
        # Running from an installed package with no checkout. Data panels are
        # unaffected; only the workload list needs kubectl, which is discovered
        # separately and reported in the UI when missing.
        pdir = Path.cwd()
        print(_c("dim", "    no project checkout found; the Workloads panel will "
                        "report cluster access as unavailable"))

    try:
        return web.run(admin_client, settings, pdir, NAMESPACE, host=host, port=port)
    except OSError as exc:
        # The common case is a port already in use, and saying which port is far
        # more useful than the bare errno.
        _bad(f"cannot bind {host}:{port}: {exc}")
        print(_c("dim", "    pick another with: weirvern gui --port 8090"))
        return EXIT_FAIL


def cmd_interfaces(args: argparse.Namespace) -> int:
    """List a sensor node's interfaces and judge which one can capture.

    WHY A COMMAND rather than documenting `ip link`: the choice is not obvious from
    interface names, and getting it wrong fails SILENTLY. Pointing the sensor at the
    management port produces a capture full of broadcast noise, which reads as a busy
    network; pointing it at a bridge member inside a container produces 73% noise and
    no unicast. Both look healthy in Zeek's logs. So this prints the verdict, not just
    the list.

    Probes the NODE by default (a throwaway hostNetwork pod), because that is what
    Zeek sees. `--local` asks the machine the CLI is running on instead, which is
    right on a single-host install and wrong on a cluster.
    """
    from weirvern.admin import interfaces as if_mod

    iface_env = {}
    # A missing or unreadable .env must not stop a diagnostic that is otherwise
    # useful -- this command exists partly to help when the setup is wrong.
    with contextlib.suppress(Exception):
        iface_env = config_io.EnvFile.load(env_path()).as_dict()
    configured = args.capture_iface or iface_env.get("ZEEK_IFACE", "")
    mgmt = args.mgmt_iface or iface_env.get("MGMT_IFACE", "")
    # Fall back to the cluster ConfigMap, which is what the deployment actually uses.
    if not configured:
        configured = _cluster_config().get("ZEEK_IFACE", "")
    if not mgmt:
        mgmt = _cluster_config().get("MGMT_IFACE", "")

    if args.local:
        probe = if_mod.probe_local()
    else:
        caps = detect_capabilities(project_dir())
        if not (caps.kubectl and caps.cluster_available):
            _warn(f"no cluster ({caps.reason or 'kubectl unavailable'}) — probing this host instead")
            probe = if_mod.probe_local()
        else:
            image = _sensor_image()
            print(_c("dim", f"    probing node via a hostNetwork pod ({image})…"))
            probe = if_mod.probe_node(NAMESPACE, node=args.node, image=image)

    if probe.error:
        _bad(probe.error)
        print()
        print("  If the probe pod could not start, re-run with --local to inspect this")
        print("  host, or run this command ON the sensor node.")
        return EXIT_FAIL

    where = "this host" if probe.source == "local" else f"node {probe.source}"
    print(_c("bold", f"Interfaces on {where}"))
    if probe.hostname and probe.hostname != probe.source:
        print(_c("dim", f"    hostname {probe.hostname}"))
    print()

    rows = if_mod.describe(probe)
    if not rows:
        print("  no usable interfaces found")
        return EXIT_FAIL
    width = max(len(r[0]) for r in rows) + 2
    print(f"  {'iface'.ljust(width)} {'role':<9} detail")
    for name, role, detail in rows:
        colour = "bold" if role in ("mgmt", "CAPTURE?") else "dim"
        print(f"  {name.ljust(width)} {_c(colour, role.ljust(9))} {detail}")

    print()
    if configured:
        v = if_mod.validate_capture_iface(probe, configured, mgmt)
        head = _c("bold", f"Capture interface (ZEEK_IFACE={configured})")
        print(head)
        if v.fatal:
            _bad(v.summary())
            for f in v.fatal:
                print(f"    {f}")
        else:
            _ok(v.summary())
        for w in v.warnings:
            _warn(w)
        for n in v.notes:
            print(_c("dim", f"    {n}"))
    else:
        _warn("ZEEK_IFACE is not set — the sensor will fall back to eth0")

    if mgmt:
        m = probe.by_name(mgmt)
        if m is None:
            _warn(f"MGMT_IFACE='{mgmt}' does not exist on {where}")
        # The same-interface case is already reported inside the verdict above, so it
        # is deliberately NOT repeated here -- two identical warnings read as a bug.

    suggestion = if_mod.recommend(probe, mgmt)
    print()
    if suggestion:
        print(_c("bold", "Suggested capture port: ") + suggestion)
        if configured and suggestion != configured:
            print(f"  ZEEK_IFACE is '{configured}'. To use '{suggestion}':")
            print(f"    weirvern config set ZEEK_IFACE={suggestion}")
            print(f"    edit k8s/20-configmap-env.yaml ZEEK_IFACE: \"{suggestion}\"")
            print("    weirvern apply")
    else:
        print(_c("bold", "No valid capture port found."))
        print("  Every interface is a bridge member, virtual, or the management port.")
        print("  A mirror/SPAN port has to exist as a PHYSICAL interface on the sensor")
        print("  node. On a virtualised host (Proxmox, ESXi, Hyper-V) a VM cannot be")
        print("  handed a SPAN feed through its normal paravirtual NIC: the switch")
        print("  mirrors to a physical port, and the hypervisor's bridge delivers only")
        print("  flooded traffic to a virtual port. Give the sensor VM/LXC a dedicated")
        print("  physical NIC (PCI passthrough or a second, unbridged NIC) and mirror")
        print("  the switch port to that cable.")
    return EXIT_OK


def cmd_mode(args: argparse.Namespace) -> int:
    """Inspect or set the sensor mode.

    WHY THIS IS ITS OWN COMMAND: the mode decides whether Weirvern is a passive
    observer or a router, and those have different requirements and radically different
    failure modes. Burying that in a config value an operator has to know to look for
    would mean discovering the blast radius after a deployment, so the mode gets a
    first-class command that states the requirements and the consequence.

    With no argument it reports the current mode. `weirvern mode siphon` checks whether
    siphon mode CAN be enabled here before writing anything, and refuses when it cannot.
    """
    from weirvern.admin import mode as mode_mod

    env = config_io.EnvFile.load(env_path())
    current = env.get("SENSOR_MODE") or mode_mod.DEFAULT_MODE
    mgmt_iface = env.get("MGMT_IFACE") or ""
    capture_iface = env.get("ZEEK_IFACE") or ""

    if not args.mode:
        # Report only.
        print(_c("bold", "Sensor mode"))
        print(f"  {mode_mod.describe(current)}")
        print()
        v = mode_mod.validate(current)
        if not v.ok:
            _warn(v.summary())
            for b in v.blockers:
                print(f"    {b}")
        else:
            _ok(v.summary())
        print()
        print(_c("dim", "  switch with: weirvern mode loch   |   weirvern mode siphon"))
        return EXIT_OK

    wanted = mode_mod.normalise(args.mode)
    print(_c("bold", f"Sensor mode: {current} -> {wanted}"))
    print(f"  {mode_mod.SUMMARY.get(wanted, 'unknown mode')}")
    print(f"  impact: {mode_mod.IMPACT.get(wanted, '?')}")
    print()

    if wanted == current and not args.force:
        _ok(f"already in {wanted} mode — nothing to change")
        return EXIT_OK

    # Gather the facts the gates depend on, from the cluster the sensor runs in.
    # Unknown is treated as absent: claiming a capability we could not confirm would
    # defeat the point of gating.
    has_net_admin = has_net_raw = False
    watchdog_ok = True          # ships with Weirvern; absence would be a code fault
    if wanted == mode_mod.MODE_SIPHON:
        caps = detect_capabilities(project_dir())
        if caps.kubectl and caps.cluster_available:
            # The WORKER runs the intercept; its capabilities are what siphon needs. The
            # zeek container keeps its narrow NET_RAW capture posture.
            r = _run(["kubectl", "-n", NAMESPACE, "get", "deploy", "weirvern-worker", "-o",
                      "jsonpath={.spec.template.spec.containers[0].securityContext.capabilities.add}"],
                     project_dir(), timeout=20)
            adds = (r.stdout or "") if r.ok else ""
            has_net_admin = "NET_ADMIN" in adds
            has_net_raw = "NET_RAW" in adds
        else:
            _warn("no cluster reachable — cannot confirm the sensor's capabilities")
        print(_c("bold", "Prerequisites"))
        _ok_or_bad("CAP_NET_RAW", has_net_raw, "needed to send forged ARP frames")
        _ok_or_bad("CAP_NET_ADMIN", has_net_admin,
                   "needed to configure forwarding; the passive sensor does NOT have it")
        _ok_or_bad("fail-open watchdog", watchdog_ok, "withdraws the poisoned ARP entries")
        print()
        print(_c("bold", "Node sysctls siphon mode depends on"))
        from weirvern.admin.watchdog import preflight_sysctls
        for name, cur, want in preflight_sysctls():
            if args.local and cur != "?":
                mark = "ok" if cur == want else "MISMATCH"
                print(f"  [{mark}] {name} = {cur} (want {want})")
            else:
                print(_c("dim", f"  [node] {name} must be {want}"))
        print()

    v = mode_mod.validate(wanted, has_net_admin=has_net_admin,
                          has_net_raw=has_net_raw, watchdog_available=watchdog_ok)

    # In siphon mode the CAPTURE interface is the one that gets spoofed and relayed, so
    # it must not be the management port: intercepting your own management path would
    # cut the sensor off from the cluster that manages it. loch mode does not care,
    # which is exactly why this check lives here rather than in validate().
    if wanted == mode_mod.MODE_SIPHON and capture_iface and mgmt_iface:
        if capture_iface == mgmt_iface:
            v.ok = False
            v.blockers.append(
                f"ZEEK_IFACE and MGMT_IFACE are both '{capture_iface}'. Siphon mode "
                f"relays traffic on the capture interface, so using the management "
                f"port would intercept the sensor's own cluster API traffic and can "
                f"cut it off from the deployment that manages it"
            )
    elif wanted == mode_mod.MODE_SIPHON and capture_iface and not mgmt_iface:
        v.warnings.append(
            "MGMT_IFACE is not set, so Weirvern cannot verify the capture interface is "
            "separate from the management path. Set it before enabling siphon mode."
        )

    if not v.ok and not args.force:
        _bad(f"cannot enable {wanted} mode:")
        for b in v.blockers:
            print(f"    {b}")
        print()
        print(_c("dim", "  --force writes it anyway. Do not use it to skip the watchdog: "
                        "in siphon mode a sensor that stops relaying takes the LAN down."))
        return EXIT_NOTREADY

    for w in v.warnings:
        _warn(w)

    # Write it. .env is the local view; the cluster reads the ConfigMap, so both are
    # updated and the operator is told which one matters at runtime.
    try:
        env.set("SENSOR_MODE", mode_mod.env_value(wanted))
        env.save()
        _ok(f"{env_path()} updated (SENSOR_MODE={mode_mod.env_value(wanted)})")
    except Exception as exc:  # noqa: BLE001
        _bad(f"could not update {env_path()}: {exc}")
        return EXIT_FAIL

    if wanted == mode_mod.MODE_SIPHON:
        print()
        _warn("the CLUSTER mode lives in k8s/20-configmap-env.yaml — set it there too:")
        print(f'    SENSOR_MODE: "{mode_mod.env_value(wanted)}"')
        print("  then:  weirvern apply")
        print()
        _warn("set INTERCEPT_TARGETS before traffic is actually diverted. The mode "
              "alone intercepts nothing.")
    return EXIT_OK


def _ok_or_bad(label: str, ok: bool, why: str) -> None:
    if ok:
        _ok(f"{label} — {why}")
    else:
        _bad(f"{label} MISSING — {why}")


def cmd_disk(args: argparse.Namespace) -> int:
    """Show disk usage and the per-component caps, and recommend values from the disk.

    WHY THIS IS A COMMAND: Zeek rotates by TIME but deletes nothing, so a sensor on a
    40 GB disk reaches 87 rotated files / 11 MB in a few hours of light traffic and keeps
    growing -- measured, at roughly 7 MB/hour. Nothing bounded it. A sensor that fills its
    disk stops capturing, and it takes ClickHouse down with it, which presents as a
    database fault rather than a capacity one.

    Set a cap with:  weirvern config set ZEEK_MAX_MB=2048
    """
    from weirvern.admin import diskplan as dp

    env = config_io.EnvFile.load(env_path()) if env_path().exists() else None
    current = {}
    if env is not None:
        for key, comp in (("ZEEK_MAX_MB", "zeek"), ("NETFLOW_MAX_MB", "netflow"),
                          ("ML_MAX_MB", "ml")):
            raw = (env.get(key) or "").strip()
            if raw.isdigit() and int(raw) > 0:
                current[comp] = int(raw)

    target = args.path or env_path().parent
    total, used, avail, mount = dp.probe_disk(str(target))
    if not total:
        _bad(f"could not read disk usage for {target}")
        return EXIT_FAIL

    print(_c("bold", f"Disk ({mount or target})"))
    print(f"  total {dp.human_mb(total)}   used {dp.human_mb(used)}   "
          f"free {dp.human_mb(avail)}")
    print()

    report = dp.plan(avail, total, current)
    print(_c("bold", "Component caps"))
    print(f"  {'component':<9} {'cap':<10} {'holds':<12} source")
    for name in ("zeek", "netflow", "ml"):
        b = report.budgets[name]
        cap = dp.human_mb(b.cap_mb)
        print(f"  {name:<9} {cap:<10} ~{b.human_history:<11} {b.reason}")
    print()
    print(f"  allocated {dp.human_mb(report.allocated_mb)} of "
          f"{dp.human_mb(avail)} free ({report.allocated_mb / max(avail, 1):.0%}), "
          f"leaving {dp.human_mb(report.headroom_mb)} for merges and the runtime")

    if report.warnings:
        print()
        for w in report.warnings:
            _warn(w)

    # The Zeek file-count translation, because Zeek cannot cap by size and the integer
    # rounding can push real usage above the requested cap.
    z = report.budgets["zeek"]
    pol = dp.rotation_policy("zeek", z.cap_mb)
    print()
    print(_c("bold", "How Zeek's cap is enforced"))
    print(f"  Zeek rotates every {pol.rotation_interval_s // 60} min and keeps a FILE "
          f"COUNT, not a byte total.")
    print(f"  {dp.human_mb(z.cap_mb)} becomes {pol.keep} files at an estimated "
          f"{pol.mb_per_rotation:.1f} MB each = {dp.human_mb(pol.actual_cap_mb)} actual.")
    print(_c("dim", "  The estimate uses the observed rate on this deployment. Re-run "
                    "after a day of traffic for a tighter figure."))

    if not current:
        print()
        print(_c("bold", "To apply the recommendation:"))
        for name in ("zeek", "netflow", "ml"):
            b = report.budgets[name]
            print(f"  weirvern config set {name.upper()}_MAX_MB={b.recommended_mb}")
    return EXIT_OK


def cmd_version(args: argparse.Namespace) -> int:
    from weirvern import __version__
    print(f"weirvern {__version__}")
    print(f"project: {project_dir()}")
    caps = detect_capabilities(project_dir())
    if caps.cluster_available:
        ctx = _run(["kubectl", "config", "current-context"], project_dir(), timeout=15).text
        print(f"cluster: {ctx or '(context name unavailable)'}  namespace: {NAMESPACE}")
    else:
        print(f"cluster: unavailable — {caps.reason or 'unknown'}")
    print(f"manifests: {'present (k8s/kustomization.yaml)' if caps.manifests else 'MISSING'}")
    return EXIT_OK


def cmd_exporters(args: argparse.Namespace) -> int:
    """Report which devices are sending flow records, so an allow-list can be written from fact.

    WHY THIS COMMAND EXISTS BEFORE THE FILTER IS ENFORCED ANYWHERE. The collector accepts
    unauthenticated UDP on the node's own interfaces (hostNetwork, so an exporter targeting either
    the conventional port or the NodePort works). NetFlow carries no authentication and no source
    verification, the NetworkPolicy deliberately exempts this collector, and goflow2 has no
    accept-list -- so any device that can reach the node can add records attributed to any address,
    and those records feed the anomaly models and the charts.

    The fix is WEIRVERN_FLOW_EXPORTER_ALLOW, and it cannot be written from documentation: an
    operator needs to know WHICH addresses their exporters use. Asking them to grep ClickHouse for
    that is asking them not to do it. This command answers the question directly.

    A SINGLE EXPORTER IS NORMAL. Most deployments have one router or one collector; seeing one
    address here is not a sign the view is broken.
    """
    from weirvern import db
    from weirvern.config import get_settings

    settings = get_settings()
    allow = settings.flow_exporter_allow.strip()
    print(_c("dim", "  Exporters seen in the flows table (newest first):"))
    try:
        with db.connect(settings, retries=3) as client:
            rows = client.query(
                "SELECT sampler_address, count() AS n, max(timestamp) AS last "
                "FROM weirvern.flows GROUP BY sampler_address ORDER BY n DESC LIMIT 25"
            ).result_rows
    except Exception as exc:  # noqa: BLE001
        _bad(f"cannot read the flows table: {_condense(str(exc), 160)}")
        return EXIT_NOTREADY

    if not rows:
        print(_c("dim", "    (none yet — no flow records have been ingested)"))
        return EXIT_OK

    print(f"    {'ADDRESS':<44} {'RECORDS':>12}  LAST SEEN")
    for addr, n, last in rows:
        mark = ""
        if allow:
            # Show whether the CURRENT allow-list would accept this address, so the command also
            # answers "did I write the list correctly" rather than only "who is talking".
            try:
                from weirvern.ingester import _exporter_networks, _exporter_permitted

                nets = _exporter_networks(allow)
                # ── THE VERDICT IS A REASON, NOT A BOOL (glm-5.3 review) ──────────────────────────
                #
                # This was `if _exporter_permitted(...)` on a bool. The function now returns WHY, and
                # every non-empty string is truthy -- so testing it directly would have marked every
                # address "accepted", including the rejected ones, which is the display this command
                # exists to get right. Branch on the verdict instead, and show the two admissions the
                # list cannot check rather than flattening them into "accepted": an operator reading
                # this to decide "did I write the list correctly" needs to know that one of these
                # addresses was never actually checked.
                verdict = _exporter_permitted(addr, nets)
                mark = {
                    "allowed": "  accepted",
                    "rejected": "  REJECTED",
                    "no-address": "  admitted (no address to check)",
                    "unparsable": "  admitted (address will not parse)",
                    "ungated": "  (no allow-list)",
                }.get(verdict, f"  {verdict}")
            except Exception:  # noqa: BLE001
                mark = ""
        print(f"    {str(addr)[:44]:<44} {int(n):>12}  {last}{mark}")

    print()
    if allow:
        print(f"  Filter is ON: WEIRVERN_FLOW_EXPORTER_ALLOW={allow!r}")
        print("  Records from any other address are rejected and counted in the worker log.")
    else:
        print(_c("warn", "  Filter is OFF: every sender is accepted."))
        print("  To restrict it to the addresses above:")
        addrs = ",".join(str(a) for a, _n, _l in rows if str(a))
        print(f"      WEIRVERN_FLOW_EXPORTER_ALLOW={addrs}")
        print("  then restart the worker. A sender not in the list is rejected AND logged, so a")
        print("  device you forgot shows up as a warning rather than as missing data.")
    return EXIT_OK


# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="weirvern",
        description="Weirvern control CLI — install, configure, run, monitor.",
        epilog="Run `weirvern <command> -h` for command-specific help.",
    )
    p.add_argument("-V", "--version", action="version", version="weirvern (see `weirvern version`)")
    sub = p.add_subparsers(dest="command", metavar="<command>")

    s = sub.add_parser("install", help="check prerequisites (kubectl, cluster, manifests) and create .env")
    s.add_argument("--force", action="store_true", help="overwrite an existing .env (backs it up)")
    s.set_defaults(func=cmd_install)

    s = sub.add_parser("apply", help="deploy the manifests to the cluster (kubectl apply -k k8s/)")
    s.add_argument("--dry-run", action="store_true", help="client-side validation only, changes nothing")
    s.set_defaults(func=lambda a: _lifecycle("apply", a))

    s = sub.add_parser("init-db", help="apply the ClickHouse schema to a reachable database")
    s.add_argument("--retries", type=int, default=30)
    s.set_defaults(func=cmd_init_db)

    s = sub.add_parser("wait", help="block until every workload reports ready")
    s.add_argument("--timeout", type=int, default=300, help="seconds to wait (default 300)")
    s.set_defaults(func=cmd_wait)

    for name, help_text in (("start", "scale workloads back up"),
                            ("stop", "scale workloads down (suspends the Zeek DaemonSet)"),
                            ("restart", "rolling restart (kubectl rollout restart)")):
        s = sub.add_parser(name, help=help_text)
        s.add_argument("services", nargs="*", help=f"optional subset: {', '.join(n for n, _ in WORKLOADS)}")
        if name == "start":
            s.add_argument("--build", action="store_true",
                           help="accepted for compatibility; has no effect on Kubernetes (reported)")
        s.set_defaults(func=lambda a, _n=name: _lifecycle(_n, a))

    s = sub.add_parser("down", help="delete the workloads (and optionally the persistent data)")
    s.add_argument("--volumes", action="store_true",
                   help="ALSO DELETE the data claims — destroys all flow history and trained models")
    s.set_defaults(func=lambda a: _lifecycle("down", a))

    s = sub.add_parser("pull", help="explain how images reach the nodes (no client-side pull on Kubernetes)")
    s.set_defaults(func=lambda a: _lifecycle("pull", a))

    s = sub.add_parser("status", help="workload state + database health")
    s.set_defaults(func=cmd_status)

    s = sub.add_parser("logs", help="show workload logs")
    s.add_argument("service", nargs="?", help=f"one of: {', '.join(n for n, _ in WORKLOADS)} (default: all)")
    s.add_argument("--tail", type=int, default=200)
    s.set_defaults(func=cmd_logs)

    s = sub.add_parser("config", help="inspect or edit .env")
    s.add_argument("action", choices=["list", "get", "set", "validate"])
    s.add_argument("key", nargs="?")
    s.add_argument("value", nargs="?")
    s.set_defaults(func=cmd_config)

    s = sub.add_parser("tune", help="guided threshold tuning")
    s.set_defaults(func=cmd_tune)

    s = sub.add_parser(
        "exporters",
        help="list the devices sending flow records, and whether the allow-list accepts them",
    )
    s.set_defaults(func=cmd_exporters)

    s = sub.add_parser(
        "disk",
        help="disk usage, per-component log caps, and a recommendation from disk size",
    )
    s.add_argument("--path", default="",
                   help="measure this path's filesystem (default: the project dir)")
    s.set_defaults(func=cmd_disk)

    s = sub.add_parser(
        "mode",
        help="inspect or set the sensor mode (loch = passive, siphon = in-path intercept)",
    )
    s.add_argument("mode", nargs="?", default="",
                   help="'loch' or 'siphon'; omit to report the current mode")
    s.add_argument("--force", action="store_true",
                   help="write the mode even if prerequisites are missing (not advised)")
    s.add_argument("--local", action="store_true",
                   help="also read the sysctls from this host")
    s.set_defaults(func=cmd_mode)

    s = sub.add_parser(
        "interfaces",
        help="list a sensor node's NICs and judge which can capture (mirror/SPAN)",
    )
    s.add_argument("--node", default="", help="probe this node (default: any node)")
    s.add_argument("--local", action="store_true",
                   help="probe this host instead of a cluster node")
    s.add_argument("--capture-iface", default="",
                   help="check this interface as the capture port instead of the configured one")
    s.add_argument("--mgmt-iface", default="",
                   help="check this interface as the management port")
    s.set_defaults(func=cmd_interfaces)

    s = sub.add_parser("gui", help="serve the read-only web dashboard")
    s.add_argument("--host", default=None,
                   help="bind address (default 127.0.0.1, or $GUI_HOST)")
    s.add_argument("--port", type=int, default=None,
                   help="port (default 8088, or $GUI_PORT)")
    s.set_defaults(func=cmd_gui)

    s = sub.add_parser("prune", help="apply the per-component disk caps")
    s.add_argument("--dry-run", action="store_true",
                   help="report what would be freed without deleting")
    s.add_argument("--cap", help="override the cap in MB for one component")
    s.add_argument("--component", choices=["zeek", "netflow", "ml"], default="zeek",
                   help="which component --cap applies to (default: zeek)")
    s.add_argument("--grace", type=int, default=3600,
                   help="never delete files newer than this many seconds (default 3600)")
    s.set_defaults(func=cmd_prune)

    s = sub.add_parser("intercept", help="run in-path intercept (siphon mode)")
    s.add_argument("--iface", help="capture NIC with L2 reachability to the segment")
    s.add_argument("--segment", help="CIDR to intercept, e.g. 198.51.100.0/24")
    s.add_argument("--our-ip", dest="our_ip", help="this sensor's address on that segment")
    s.add_argument("--gateway", help="the gateway whose traffic to relay")
    s.add_argument("--policy-table", type=int, default=0,
                   help="routing table for this interface's relay (default: 100; the "
                        "supervisor gives each interface its own)")
    s.add_argument("--dry-run", action="store_true",
                   help="show the plan and preflight results, change nothing")
    s.add_argument("--hosts", action="append",
                   help="intercept ONLY this host (repeatable). Strongly advised for a "
                        "first run: a whole segment makes every device depend on this "
                        "process, so a crash is an outage for all of them")
    s.add_argument("--all", action="store_true", dest="all_hosts",
                   help="intercept EVERY host the sweep finds on the segment. Requires "
                        "--seconds or a hard timeout, and refuses a segment larger than /22: "
                        "this process becomes the path for everything it intercepts, so a "
                        "crash is an outage for all of it. Use when the segment has no "
                        "interactive users (servers only), where a brief loss is tolerable")
    s.add_argument("--seconds", type=int,
                   help="intercept for this long, then restore (default: until Ctrl-C; "
                        "required when stdin is not a terminal)")
    s.add_argument("--max-runtime", type=int, metavar="S", dest="max_runtime",
                   help="self-destruct deadline: restore and exit after S seconds even if "
                        "no signal ever arrives (covers a killed kubectl exec client; "
                        "default: --seconds + 120 when --seconds is given, else off)")
    s.add_argument("--force-unsafe", action="store_true",
                   help="override a refusal to intercept a host holding a never-intercept "
                        "role (the sensor's resolver, management address, or the cluster "
                        "API). The sensor's own address and the gateway remain refused "
                        "regardless: forging them cannot relay anything")
    s.set_defaults(func=cmd_intercept)

    s = sub.add_parser("version", help="show version and detected runtime")
    s.set_defaults(func=cmd_version)

    return p



def cmd_prune(args: argparse.Namespace) -> int:
    """Apply the per-component disk caps. Safe to run repeatedly.

    This is BOTH the manual command and the body of the prune CronJob, deliberately: a cap
    is only worth having if the scheduled path and the path an operator runs by hand are
    the same code. A divergence between them stays invisible until a disk fills.

    Reads ZEEK_MAX_MB / NETFLOW_MAX_MB / ML_MAX_MB. A component with no cap is reported as
    unset rather than assumed fine -- "no cap" and "under cap" look identical on a
    healthy-looking disk and only one of them is safe.
    """
    from weirvern import enforce

    caps = {c: 0 for c in ("zeek", "netflow", "ml")}
    for key, comp in (("ZEEK_MAX_MB", "zeek"), ("NETFLOW_MAX_MB", "netflow"),
                      ("ML_MAX_MB", "ml")):
        raw = (os.environ.get(key) or "").strip()
        if raw.isdigit() and int(raw) > 0:
            caps[comp] = int(raw)

    if args.cap:
        try:
            caps[args.component] = int(args.cap)
        except ValueError:
            _bad(f"--cap must be a whole number of MB, got {args.cap!r}")
            return EXIT_FAIL

    if not any(caps.values()):
        print("No caps are set, so nothing is enforced: rotated logs and flow data will")
        print("grow until the disk fills. Run `weirvern disk` for recommended values, then")
        print("for example:  weirvern config set ZEEK_MAX_MB=2048")
        return EXIT_NOTREADY

    if args.dry_run:
        print(_c("bold", "Dry run: nothing will be deleted"))
        total = 0.0
        for comp in ("zeek", "netflow", "ml"):
            cap = caps[comp]
            if cap <= 0:
                print(f"  {comp:<8} {'no cap set':>16}")
                continue
            if comp == "zeek":
                from weirvern import prune as _prune
                before = _prune.total_bytes(enforce.ZEEK_DIR)
                # plan_prune returns the doomed-file LIST; the preview sums it. (It used to
                # getattr `planned_freed_mb`/`to_delete` -- attributes that exist on no
                # version of the return value -- so the operator's only preview read
                # "would free 0.0 MB (0 file(s))" unconditionally, on any directory.)
                # grace_s matches the real pass below, so preview and enforcement agree.
                res = _prune.plan_prune(enforce.ZEEK_DIR, cap, grace_s=args.grace)
                freed = sum(c.size_bytes for c in res) / 1048576.0
                n = len(res)
                print(f"  {comp:<8} {enforce._mb(before):8.1f} MB / cap {cap:<6} MB"
                      f"  would free {freed:.1f} MB ({n} file(s))")
            else:
                d = enforce.NETFLOW_DIR if comp == "netflow" else enforce.ML_DIR
                before = enforce._total_bytes(d)
                freed = max(0.0, enforce._mb(before) - cap)
                print(f"  {comp:<8} {enforce._mb(before):8.1f} MB / cap {cap:<6} MB"
                      f"  would free {freed:.1f} MB")
            total += freed
        print(f"\n  total reclaimable: {total:.1f} MB")
        return EXIT_OK

    results = enforce.enforce(caps, grace_s=args.grace)
    print(enforce.render(results))

    if any(r.errors for r in results):
        _bad("at least one component reported errors; the disk may still be over cap")
        return EXIT_FAIL

    # Exit non-zero when a component is STILL over cap after a real prune pass. This is what
    # makes the CronJob's failure state meaningful: a Job that "succeeded" while the disk is
    # over budget would hide the exact condition worth alerting on.
    stuck = [r for r in results if r.cap_mb > 0 and r.after_mb > r.cap_mb]
    if stuck:
        _bad("still over cap after pruning: " + ", ".join(r.component for r in stuck))
        return EXIT_FAIL
    return EXIT_OK



def _resolve_host_scope(args: argparse.Namespace) -> tuple[set[str], str | None]:
    """Which hosts to intercept: a named set, an explicit "all", or a refusal to explain.

    Returns (only, refusal). `refusal` is None when the combination is valid.

    WHY THIS IS A FUNCTION RATHER THAN A FEW LINES INSIDE cmd_intercept: it is a SAFETY gate. It
    is what stops an unbounded whole-segment intercept -- where every host on the VLAN has this
    process in its path and nothing ends the run except someone remembering to stop it. A gate
    that can only be exercised with a live NIC is a gate that does not get tested, and this one
    used to sit after interface resolution, so a missing interface masked it entirely.

    The two rules:

      * `--all` and `--hosts` are contradictory. One says "only these", the other "all of them";
        silently honouring either leaves the operator believing the other took effect.
      * `--all` REQUIRES `--seconds`. Without a bound, every intercepted host stays dependent on
        this process until the session ends.
    """
    only = {h.strip() for h in (args.hosts or []) if h.strip()}
    if not getattr(args, "all_hosts", False):
        return only, None

    if only:
        return set(), "  --all intercepts every host; --hosts names specific ones. Pick one."
    if not args.seconds:
        return set(), (
            "  --all requires --seconds N: intercepting a whole segment without an\n"
            "  automatic end means every host stays dependent on this process until\n"
            "  someone stops it. Give it a bound."
        )
    return set(), None


def cmd_intercept(args: argparse.Namespace) -> int:
    """Run in-path intercept (siphon mode): ARP-forge the path, relay in the kernel.

    WHY THIS IS GATED AND LOVES --dry-run: in siphon mode Weirvern is a ROUTER. Every host
    whose ARP cache is forged loses the network if this process stops without restoring,
    which is why the watchdog is armed before the first poison frame. A whole-segment
    intercept can take an entire VLAN off the air, so the plan is inspectable first.

    This is an L2/L3 redirect, NOT a TLS intercept: nothing is decrypted, no certificate
    is substituted, and no payload is inspected or stored.
    """
    from weirvern.admin import intercept as ic_mod
    from weirvern.admin import mode as mode_mod
    from weirvern.admin import siphonnet

    env = config_io.EnvFile.load(env_path()) if env_path().exists() else None

    def _get(k, d=""):
        """Env file wins, then the process environment, then the default.

        The file wins because `.env` is what the operator edited; the process environment
        only matters for the flags Kubernetes injects.
        """
        value = env.get(k) if env is not None else None
        return str(value or os.environ.get(k) or d)

    iface = args.iface or _get("CAPTURE_IFACE") or _get("ZEEK_IFACE")
    segment = args.segment or _get("INTERCEPT_SEGMENT")
    our_ip = args.our_ip or _get("INTERCEPT_ADDR") or _get("MGMT_ADDR")
    gateway = args.gateway or _get("INTERCEPT_GATEWAY")

    missing = [n for n, v in (("interface", iface), ("segment", segment),
                              ("our address", our_ip), ("gateway", gateway)) if not v]
    if missing:
        _bad("missing: " + ", ".join(missing))
        print("\n  Required for an intercept:")
        print("    --iface    the capture NIC with L2 reachability to the segment")
        print("    --segment  the CIDR to intercept, e.g. 198.51.100.0/24")
        print("    --our-ip   this sensor's address on that segment")
        print("    --gateway  the gateway whose traffic to relay")
        print("\n  Or set CAPTURE_IFACE / INTERCEPT_SEGMENT / INTERCEPT_ADDR /")
        print("  INTERCEPT_GATEWAY in .env")
        return EXIT_USAGE

    # Mode gate first: refuse before probing anything, so a misconfigured mode cannot
    # half-build a plan and leave the operator wondering which step failed.
    # Signature is validate(mode, *, ...) returning ModeVerdict(mode, ok, blockers,
    # warnings) -- verified against mode.py rather than assumed. The watchdog ships with
    # Weirvern, so its availability is a code fact, not a probe.
    verdict = mode_mod.validate(
        mode_mod.MODE_SIPHON,
        has_net_admin=_has_cap("net_admin"),
        has_net_raw=_has_cap("net_raw"),
        watchdog_available=True,
    )
    if not verdict.ok:
        _bad(f"siphon mode is not permitted on this host: {verdict.summary()}")
        for reason in verdict.blockers:
            print(f"    - {reason}")
        for warn in verdict.warnings:
            print(f"    ! {warn}")
        return EXIT_NOTREADY

    # Show the segment and offer free addresses, BEFORE building the plan.
    #
    # WHY THE OPERATOR CHOOSES: intercept needs an address on the segment to relay from,
    # and silently picking one risks an address conflict on their network -- a worse
    # outcome than not testing at all. DHCP is not an option here: a lease can change or be
    # withdrawn mid-intercept, and that is the one failure the watchdog cannot distinguish
    # from idleness (the forwarding counter simply stops advancing), so poisoned hosts
    # would keep believing we are the gateway while we can no longer forward for them.
    used, err = siphonnet.describe_segment(iface, segment, our_ip or gateway)
    if err:
        _warn(f"could not survey {segment}: {err}")
    else:
        print(_c("bold", f"Segment {segment} on {iface}"))
        if not used:
            print("  nothing answered ARP — either the segment is empty, or this "
                  "interface cannot reach it")
            print("  (intercepting it would affect nobody, which is safe but pointless)")
        else:
            print(f"  {len(used)} host(s) in reach — this is the blast radius, since")
            print("  every one of them would have its ARP cache forged:")
            for ip, mac in sorted(used.items(),
                                  key=lambda kv: tuple(int(x) for x in kv[0].split(".")))[:20]:
                print(f"      {ip:<16} {mac}")
            if len(used) > 20:
                print(f"      ... and {len(used) - 20} more")
        print()
        if not args.our_ip:
            free = siphonnet.find_free_addresses(iface, segment, our_ip or gateway,
                                               exclude=set(used) | {gateway})
            if free:
                print(_c("bold", "  free addresses you could use for --our-ip:"))
                for f_ in free:
                    print(f"      {f_}")
                print("  These answered no ARP. Confirm against your own records before")
                print("  using one — a host that is simply powered off would also be free.")
            else:
                print("  no obviously free address found; choose --our-ip deliberately")
        print()

    only, refusal = _resolve_host_scope(args)
    if refusal is not None:
        print(refusal)
        return EXIT_FAIL

    # REQUIRE --seconds WHEN STDIN IS NOT A TERMINAL (siphon-2). A non-interactive run -- the
    # documented in-cluster pattern is `kubectl exec` without a TTY, and a scripted run is
    # the same shape -- has no Ctrl-C path a human can press, and if the client is killed
    # no signal may reach this process at all. The protections that survive that case are
    # the --seconds bound and ARP expiry; making the bound mandatory here is what turns
    # "the session might be orphaned" into "the run ends by itself". Interactive runs keep
    # the unbounded form because the operator is present to stop it.
    if not args.seconds and not args.dry_run and not sys.stdin.isatty():
        _bad("stdin is not a terminal, so there is no Ctrl-C path: an unbounded run could "
             "be orphaned when the client or connection goes away, leaving poisoned ARP "
             "caches until they expire.")
        print("  Give it a bound:  --seconds 300")
        return EXIT_USAGE

    plan = ic_mod.build_plan(iface=iface, segment=segment, our_ip=our_ip,
                             gateway_ip=gateway, only=only or None,
                             force_unsafe=bool(getattr(args, "force_unsafe", False)),
                             policy_table=getattr(args, "policy_table", 0) or None)
    if plan is None:
        return EXIT_FAIL

    # THE SELF-DESTRUCT DEADLINE (siphon-2, part 3). --seconds bounds the WAIT loop; this
    # bounds the mappings' lifetime when no signal can reach the process at all (a
    # SIGKILLed kubectl-exec client leaves the in-pod process alive and unreachable, and
    # no handler runs). Default: --seconds + 120s grace, so the normal path always wins
    # and the deadline only fires when something went wrong. Explicit --max-runtime wins;
    # without --seconds there is no default deadline (nobody asked for a bound).
    max_runtime_s = _effective_max_runtime(args)

    print(_c("bold", "Intercept plan"))
    print(plan.describe())
    if max_runtime_s:
        print(f"  self-destruct deadline: restore and exit after {max_runtime_s}s "
              f"regardless of signals")
    print()

    runner = ic_mod.Intercept(plan, max_runtime_s=max_runtime_s)
    problems = runner.preflight()

    if args.dry_run:
        print(_c("bold", "Preflight"))
        if problems:
            for p_ in problems:
                print(f"  {_c('bad', 'BLOCKED')} {p_}")
            print()
            print(siphonnet.SYSCTL_WRITE_HINT)
            return EXIT_NOTREADY
        print("  all checks passed")
        print()
        print(f"  would install {plan.host_count * 2} mapping(s): "
              f"{plan.host_count} host(s) x 2 directions")
        print("  (each host: its gateway entry, and the gateway's entry for it)")
        print()
        print("  Nothing was changed. Remove --dry-run to apply.")
        return EXIT_OK

    if problems:
        _bad("preflight failed, nothing was changed")
        for p_ in problems:
            print(f"    - {p_}")
        print()
        print(siphonnet.SYSCTL_WRITE_HINT)
        return EXIT_NOTREADY

    # ASSIGN THE ADDRESS, which is the step this command was missing entirely.
    #
    # Without an address on the capture interface the kernel has no route on that interface,
    # so it CANNOT forward relayed traffic, and every neighbour lookup on the segment fails.
    # Measured live: the plan refused to build with "cannot resolve the gateway" purely
    # because the interface had no address, while the gateway was answering ARP the whole
    # time. Poisoning without an address would take hosts OFF the network instead of relaying
    # them -- the exact failure siphon mode exists to avoid.
    #
    # Placed HERE, after the mode gate and the survey and immediately before the try, so
    # every return below it is covered by the finally and no path can leak the address.
    addr_added = False
    if not _iface_has_address(iface, our_ip):
        rc, out = siphonnet.add_address(iface, our_ip, segment)
        if rc != 0:
            _bad(f"could not assign {our_ip} to {iface}: {out}")
            return EXIT_NOTREADY
        addr_added = True
        print(f"  assigned {our_ip} to {iface} for the duration of this intercept")
        print("  (withdrawn on exit, including on failure and on Ctrl-C)")
        print()
    else:
        print(f"  {iface} already carries {our_ip}; it will be left in place")
        print()

    try:
        return _run_intercept(args, runner, plan, ic_mod)
    finally:
        # EVERY exit path, including the failure returns inside. An address left on the
        # capture interface keeps a route and keeps accepting traffic for a segment the
        # operator never asked to be involved in.
        if addr_added:
            siphonnet.remove_address(iface, our_ip, segment)
            print(f"  withdrew {our_ip} from {iface}")


def _effective_max_runtime(args: argparse.Namespace) -> int | None:
    """The self-destruct deadline for this run, or None for no deadline.

    Default policy (siphon-2): a bounded run (--seconds) gets --seconds + 120s of grace, so
    the normal restore path always wins and the deadline exists purely for the case where
    that path never got to run (a SIGKILLed kubectl-exec client leaves the in-pod process
    alive and unsignalable). An unbounded interactive run gets NO default deadline --
    nobody asked for a bound, and Ctrl-C is present. Explicit --max-runtime always wins;
    a non-positive value disables it.

    A separate function so the policy is testable without mocking a live intercept.
    """
    explicit = getattr(args, "max_runtime", None)
    if explicit is not None:
        return explicit if explicit > 0 else None
    if getattr(args, "seconds", None):
        return int(args.seconds) + 120
    return None


def _run_intercept(args: argparse.Namespace, runner, plan, ic_mod) -> int:
    """Start the intercept, wait, and restore. Split out so the address teardown can wrap
    the whole thing in one finally block rather than being repeated on each return path."""
    runner.start()

    # Publish a heartbeat so the GUI can see this intercept running. Without it
    # the only thing a remote reader has is SENSOR_MODE in the ConfigMap, which says what
    # was INTENDED and survives this process dying -- so the dashboard would show
    # "intercepting" for a sensor that had stopped.
    # The heartbeat needs a LIVE connection for the whole intercept, so the client is
    # opened into an ExitStack rather than closed after starting the loop -- a closed
    # client would make every subsequent beat fail silently and the GUI would show
    # nothing while the intercept ran.
    beat = None
    stack = contextlib.ExitStack()
    try:
        from weirvern.admin import heartbeat as hb_mod
        _hc = stack.enter_context(admin_client(_settings()))
        beat = hb_mod.HeartbeatLoop(_hc, state=lambda: _intercept_state(runner))
        beat.start()
    except Exception as exc:  # noqa: BLE001
        # Non-fatal by design: a sensor that cannot report must still intercept. The cost
        # of no heartbeat is a dashboard showing "unknown", which is recoverable; the cost
        # of aborting is no interception at all.
        print(f"  note: no status heartbeat ({exc}) -- the GUI will not show this "
              f"intercept, but it is running")

    failure: str | None = None
    try:
        if args.seconds:
            runner.wait(stop_after_s=args.seconds)
        else:
            print("  intercepting; Ctrl-C to stop and restore")
            runner.wait()
    except KeyboardInterrupt:
        print("\n  interrupted")
    except Exception as exc:  # noqa: BLE001
        # Recorded, not swallowed, and the restore below still runs. An exception here
        # means the intercept loop broke, which is exactly when the mappings most need
        # withdrawing.
        failure = f"{type(exc).__name__}: {exc}"
    finally:
        if beat is not None:
            beat.stop()
        runner.stop()
        stack.close()

    st = runner.status()
    print(f"\n  restored. watchdog: {st['watchdog_restores']} restore(s), "
          f"{st['watchdog_refreshes']} refresh(es)")
    # The deadline firing is the orphaned-session case: no signal arrived, no caller asked
    # for the stop, and the mappings were withdrawn anyway. It must not read like a normal end.
    if st.get("deadline_reached"):
        _warn("the self-destruct deadline fired: no signal or caller stopped this "
              "intercept, so it restored itself. Check whether the session that "
              "started it died without delivering a signal.")
    # "Quiet" and "broken" are different answers to the same silent counter, so the count
    # of never-observed ticks is reported rather than left in the object. A run that ended
    # with forwarding never seen has an ambiguous record; a run that saw it working and
    # then stopped is a real finding, and the two must not read the same.
    quiet = int(st.get("quiet_samples") or 0)
    if quiet and not st.get("forwarding_observed"):
        print(f"  note: forwarding was NEVER observed working during this run "
              f"({quiet} quiet sample(s)) -- on an idle segment that is expected; on a "
              f"busy one it means the relay never carried traffic.")
    if failure:
        _bad(f"the intercept loop failed: {failure}")
        return EXIT_FAIL
    if st["watchdog_failures"]:
        _bad("watchdog reported failures:")
        for f in list(st["watchdog_failures"]):  # type: ignore[call-overload]
            print(f"    - {f}")
        overflow = int(st.get("watchdog_failures_overflow") or 0)
        if overflow:
            print(f"    ... and {overflow} more (list capped): the same failure repeated")
        return EXIT_FAIL
    return EXIT_OK



def _iface_has_address(iface: str, address: str) -> bool:
    """Whether `iface` already carries `address` (with any prefix).

    Checked so a re-run does not add a duplicate, and so the message can say whether the
    address was ours to add -- which decides whether we withdraw it on exit. Removing an
    address the operator had already configured would be a real network change made by
    teardown, exactly the kind of thing this command must never do.
    """
    import subprocess as _sp

    # A raw `ip` ARGV CALL, so the name must not be able to become part of the command (F091).
    # argv (not a shell) means this is not command injection -- but an unvalidated name here still
    # reaches a privileged binary's argument list, and the fix is one call.
    from weirvern.admin import siphonnet as _sn

    try:
        _sn.require_iface_name(iface, what="interface")
    except ValueError:
        return False
    try:
        out = _sp.run(["ip", "-o", "addr", "show", "dev", iface],
                      capture_output=True, text=True).stdout
    except OSError:
        return False
    return address in out

def _has_cap(name: str) -> bool:
    """Whether this process holds a Linux capability, read from CapEff.

    Read from /proc rather than inferred from uid: a container may run as root with
    capabilities DROPPED (which is exactly what the zeek manifest does with
    `drop: [ALL]`), so root does not imply NET_ADMIN.
    """
    try:
        with open("/proc/self/status") as fh:
            line = next(ln for ln in fh if ln.startswith("CapEff:"))
        bits = int(line.split()[1], 16)
    except (OSError, StopIteration, ValueError):
        return False
    # Capability numbers: NET_ADMIN = 12, NET_RAW = 13.
    number = {"net_admin": 12, "net_raw": 13}.get(name)
    if number is None:
        return False
    return bool(bits & (1 << number))


def _intercept_state(runner) -> dict:
    """The fields to publish for a running intercept.

    Reports the mode the process is ACTUALLY in -- "siphon" here, because this only runs
    while intercepting -- rather than reading SENSOR_MODE. That distinction is the point
    of the heartbeat: an observed fact beats a configured one.
    """
    st = runner.status()
    return {
        "mode": "siphon",
        "iface": str(st.get("iface") or ""),
        "segment": str(st.get("segment") or ""),
        "hosts": int(st.get("hosts") or 0),
        "mappings": int(st.get("mappings") or 0),
        "running": bool(st.get("running")),
        "uptime_s": float(st.get("uptime_s") or 0.0),
        "restores": int(st.get("watchdog_restores") or 0),
        "refreshes": int(st.get("watchdog_refreshes") or 0),
        "failures": [str(f) for f in (st.get("watchdog_failures") or [])],
    }


def _settings():
    """Settings from the environment, for the control-plane commands here."""
    from weirvern import config
    return config.Settings.from_env() if hasattr(config.Settings, "from_env") \
        else config.Settings()


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return EXIT_USAGE
    try:
        return int(args.func(args))
    except KeyboardInterrupt:
        print()
        return 130
    except Exception as exc:  # noqa: BLE001
        _bad(f"unexpected error: {exc}")
        return EXIT_FAIL


if __name__ == "__main__":
    sys.exit(main())
