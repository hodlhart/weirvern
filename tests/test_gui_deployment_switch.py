"""The deployment switch: the dashboard runs the Flask surface, and nothing is quietly proxied.

WHY THESE ARE DEPLOYMENT TESTS rather than route tests. The port moved 83 API paths onto Flask, one at
a time, while the console kept answering behind it. A green suite proves the routes answer; it says
nothing about what the CLUSTER runs, and the console's own `gui --flask` docstring was already stale by
a hundred routes when the port finished. These checks are the ones a roll depends on:

  * the GUI Deployment's command actually starts the Flask surface,
  * the signing key is DECLARED, so a cluster without it refuses the container instead of serving a
    login page that says the rendered UI is disabled while the pod reports Ready,
  * the installer creates that key, including on an install that predates the switch,
  * and the passthrough is OFF by default, so a route this app does not serve is a 404 rather than a
    second implementation answering it.
"""

from __future__ import annotations

import importlib
import json
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
GUI_MANIFEST = ROOT / "k8s" / "34-gui.yaml"


def _gui_container() -> dict:
    docs = [d for d in yaml.safe_load_all(GUI_MANIFEST.read_text()) if d]
    dep = next(d for d in docs if d.get("kind") == "Deployment")
    return dep["spec"]["template"]["spec"]["containers"][0]


def test_the_gui_deployment_starts_the_flask_surface():
    """THE COMMAND IS THE SWITCH. An image can contain the whole app and still serve the old server."""
    command = _gui_container()["command"]
    assert command[-1] == "--flask", (
        "the GUI Deployment does not pass --flask, so the image's ported routes are dormant and the "
        "dashboard answers from the legacy handler"
    )
    assert "--proxy-legacy" not in command, (
        "the deployment asks for a passthrough that no longer exists"
    )


def test_the_deployment_declares_the_flask_signing_key():
    """DECLARED, not merely available through envFrom.

    A key that arrives only via envFrom is absent rather than wrong when the Secret lacks it, and the
    app then serves a login page reading "the rendered UI is disabled" while the pod is Ready. The
    explicit secretKeyRef makes a missing key a refusal at container start.
    """
    env = _gui_container()["env"]
    names = [e["name"] for e in env]
    assert len(names) == len(set(names)), f"duplicate env names in the manifest: {names}"
    entry = next((e for e in env if e["name"] == "WEIRVERN_FLASK_SECRET"), None)
    assert entry is not None, "the signing key is not declared on the container"
    ref = (entry.get("valueFrom") or {}).get("secretKeyRef") or {}
    assert ref.get("name") == "weirvern-secrets", ref
    assert ref.get("key") == "WEIRVERN_FLASK_SECRET", ref
    assert ref.get("optional") is not True, (
        "an optional secretKeyRef resolves to an empty string, which is the degradation this "
        "declaration exists to prevent"
    )


def test_no_other_key_is_pinned_over_the_configmap():
    """A pod-level `env:` entry SHADOWS envFrom, which is how a Settings write became inert once.

    Measured live: the ConfigMap said 'all' and the GUI pod still read 'private'. Anything the Settings
    tab can write must arrive through envFrom, so pinning one of those keys here would silently make
    that control a no-op again.
    """
    from weirvern.admin import cluster_config as cc

    env = _gui_container()["env"]
    pinned = {e["name"] for e in env if "value" in e}
    overrides = {k for k in pinned
                 if k in cc.EDITABLE_KEYS or cc.to_configmap_key(k) in cc.EDITABLE_KEYS}
    assert overrides == set(), (
        f"these keys are pinned in the manifest, so a Settings write for them never reaches the pod: "
        f"{sorted(overrides)}"
    )


def test_the_installer_creates_the_signing_key_on_a_fresh_and_an_existing_secret():
    """A fresh install generates it; an install from BEFORE the switch backfills it.

    Without the second half, the re-apply that follows would roll a pod whose declared key does not
    exist, and the GUI would refuse to start on every upgraded deployment.
    """
    src = (ROOT / "install.sh").read_text()
    assert "WEIRVERN_FLASK_SECRET" in src, "the installer never creates the signing key"
    block = src.split("# ── THE FLASK SIGNING KEY", 1)[1].split("\nfi\n", 1)[0]
    assert "patch secret weirvern-secrets" in block, (
        "the key is only created with the Secret, so an existing install cannot get it"
    )
    assert "--type merge" in block, (
        "a full replace would wipe the ClickHouse password and the operator token"
    )
    assert "openssl rand" in block, "the key is not random"


def test_the_flask_entry_point_does_not_start_the_console_at_all():
    """THE PASSTHROUGH IS GONE, not switched off. Reading this from the source is deliberate: the
    defect it prevents is a second surface answering a route nobody tested, and a fallback kept "just
    in case" is exactly the dead path that makes an unported route look served."""
    src = (ROOT / "weirvern" / "admin" / "cli.py").read_text()
    body = src.split("def _run_flask(", 1)[1].split("\n\ndef ", 1)[0]
    assert "GuiServer(" not in body, "the entry point still starts the console on loopback"
    assert "proxy_to" not in body, "the entry point still configures a passthrough"
    assert "waitress" in body, (
        "the deployment serves with Werkzeug's development server, which is single-process and "
        "documented as not for production"
    )


def test_an_unrouted_path_is_a_404_when_no_passthrough_is_configured():
    """The behavioural half: with no proxy the app says 404 for an unknown API path, and with one it
    forwards. That is what makes `--proxy-legacy` a decision rather than a default."""
    from weirvern.admin import flask_app

    class _Ctx:
        settings = None
        backend = None
        config_client = None
        user_store = None
        sessions = None
        throttle = None
        accounts_note = ""
        auth = None
        connect_factory = staticmethod(lambda settings: None)

    app = flask_app.create_app(_Ctx(), secret_key="deployment-test")
    app.config.update(TESTING=True)
    app.config["PROPAGATE_EXCEPTIONS"] = False

    response = app.test_client().get("/api/there-is-no-such-endpoint")
    assert response.status_code == 404, response.status_code
    body = json.loads(response.data)
    assert body["error"] == "no such endpoint: /api/there-is-no-such-endpoint", body
    assert body["code"] == 404, body

    proxied = flask_app.create_app(_Ctx(), secret_key="deployment-test",
                                   proxy_to="http://127.0.0.1:1")
    proxied.config.update(TESTING=True)
    proxied.config["PROPAGATE_EXCEPTIONS"] = False
    answered = proxied.test_client().get("/api/there-is-no-such-endpoint")
    assert answered.status_code == 502, (
        "with a passthrough configured, an unrouted path must be forwarded (and here the backend is "
        f"absent), not 404. Got {answered.status_code}"
    )
    assert json.loads(answered.data)["code"] == 502


def test_the_documented_entry_points_still_import():
    """A module a deployment invokes by name must import on its own, without the console's help."""
    for dotted in ("weirvern.admin.cli", "weirvern.admin.flask_app", "weirvern.admin.payloads"):
        assert importlib.import_module(dotted), dotted

def test_the_cli_parser_builds_and_every_command_has_a_handler():
    """MEASURED DEFECT, and the reason this test exists: a refactor of `_run_flask` deleted `cmd_gui`,
    so `python -m weirvern.admin.cli --help` died with a NameError BEFORE parsing anything. The suite
    stayed green because nothing built the parser, and the entry point the deployment invokes is
    exactly that module. Building it is the whole check, because `set_defaults(func=...)` resolves the
    handler's name at build time -- a deleted handler crashes here rather than in a pod.
    """
    from weirvern.admin import cli

    parser = cli.build_parser()
    assert parser is not None
    ns = parser.parse_args(["status"])
    assert callable(ns.func), "the status subcommand carries no callable"
    gui = parser.parse_args(["gui", "--flask"])
    assert callable(gui.func) and gui.flask is True, gui
