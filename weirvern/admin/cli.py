"""Weirvern control CLI — install, configure, run, and monitor the stack.

Design intent: a single entry point an operator can learn in a minute, that
works with or without the TUI, and that never lies about state. Every command
either does the thing or explains precisely why it cannot.

    weirvern install     # create .env from template, detect runtime, first checks
    weirvern init-db     # apply the ClickHouse schema
    weirvern start/stop/restart [service...]
    weirvern status      # health probes + service table
    weirvern logs [service]
    weirvern config      # list / get / set / validate .env keys
    weirvern tune        # interactive threshold editing
    weirvern tui         # full control-panel TUI

Exit codes: 0 ok, 1 failure, 2 usage error, 3 environment not ready.
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from weirvern.admin import config_io
from weirvern.admin import status as status_mod
from weirvern.admin.runtime import (
    NAMESPACE,
    WORKLOADS,
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
# Only commands that genuinely need a checkout (install, apply, down, tune, tui)
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


def env_path() -> Path:
    return project_dir() / ".env"


def _connect(settings):
    from weirvern import db
    return db.connect(settings, retries=2, delay_s=1)


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
    from weirvern import db as db_mod
    sql_files = sorted(db_mod.SCHEMA_DIR.glob("*.sql")) if db_mod.SCHEMA_DIR.is_dir() else []
    if sql_files:
        _ok(f"ClickHouse schema present in the package "
            f"({', '.join(p.name for p in sql_files)})")
    else:
        _bad(f"no schema .sql files in {db_mod.SCHEMA_DIR} — cannot create tables")
        return EXIT_FAIL

    # 5. Secrets. Checked against the CLUSTER secret (that is what the pod reads),
    #    falling back to reporting that it cannot be verified.
    print()
    alerts_on = (env.get("PUSHOVER_ENABLED") or "0") in {"1", "true", "yes"}
    if caps.cluster_available:
        for key in ("PUSHOVER_USER_KEY", "PUSHOVER_API_TOKEN"):
            r = _run(["kubectl", "-n", NAMESPACE, "get", "secret", "weirvern-secrets",
                      "-o", f"jsonpath={{.data.{key}}}"], project_dir(), timeout=20)
            value = (r.stdout or "").strip()
            # A base64-encoded empty string is ""; anything else is a real value.
            if r.ok and value and value != '""':
                _ok(f"{key} is set in the cluster secret")
            else:
                _warn(f"{key} is NOT set in the cluster secret"
                      + (" — alerts will fail" if alerts_on else " (fine while disabled)"))
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
    steps.append("review k8s/20-configmap-env.yaml (ZEEK_IFACE, TZ) and k8s/21-secrets.yaml")
    steps.append("deploy:  weirvern apply")
    steps.append("verify:  weirvern status")
    steps.append("control panel:  weirvern tui")
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
    try:
        from weirvern.config import get_settings
        settings = get_settings()
        client = _connect(settings)
    except Exception as exc:  # noqa: BLE001
        _bad(f"cannot reach ClickHouse: {str(exc)[:120]}")
        print(_c("dim", "    Inside the cluster the database is reachable at "
                        "clickhouse.weirvern.svc:8123; from a workstation, "
                        "port-forward it:"))
        print(_c("dim", "      kubectl -n weirvern port-forward svc/clickhouse 8123:8123"))
        return EXIT_NOTREADY

    report = status_mod.collect_health(client, settings)
    for p in report.probes:
        marker = _c("green", "✓") if p.ok else _c("red", "✗")
        print(f"  {marker} {p.name:<18} {p.detail}")
    client.close()
    return EXIT_OK if report.ok else EXIT_FAIL


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
    "ZEEK_IFACE": "interface the Zeek sensor sniffs",
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


# ---------------------------------------------------------------------------
# tui
# ---------------------------------------------------------------------------
def cmd_tui(args: argparse.Namespace) -> int:
    try:
        from weirvern.admin.tui import run_tui
    except ImportError as exc:
        _bad(f"TUI unavailable: {exc}")
        print(_c("dim", "  install the optional extra: pip install 'weirvern[admin]'"))
        return EXIT_FAIL
    return run_tui(project_dir(), refresh_s=args.refresh)


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

    s = sub.add_parser("tui", help="launch the control-panel TUI")
    s.add_argument("--refresh", type=int, default=5, help="refresh interval, seconds")
    s.set_defaults(func=cmd_tui)

    s = sub.add_parser("version", help="show version and detected runtime")
    s.set_defaults(func=cmd_version)

    return p


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
