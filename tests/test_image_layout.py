"""Commands must survive running from an installed package with no checkout.

THE DEFECT CLASS, WHICH HAS NOW HAPPENED THREE TIMES:

The Containerfile copies only pyproject/README/LICENSE plus the `weirvern` package,
so the image contains neither `k8s/` nor `.env.example`. `find_project_dir()`
recognises a project directory by exactly those two files, so it RAISES inside the
image. Anything that depends on it therefore works in a checkout and breaks in the
deployed container -- the worst possible split, because the developer path is the
one that feels tested.

Occurrences:
  1. `weirvern init-db` resolved PROJECT_DIR at IMPORT time, so the schema Job
     crashed before argparse ran and a fresh deployment created ZERO tables.
  2. The same, rediscovered during the fresh-clone walk.
  3. `weirvern gui` called project_dir() unconditionally, so the GUI pod went
     CrashLoopBackOff with "could not locate the Weirvern project directory".

These tests assert the invariant rather than the three individual fixes: the
project directory may only be resolved by commands that genuinely need a checkout,
and resolving it must never be fatal for a command that can work without one.
"""
from __future__ import annotations

import inspect
import subprocess
import sys
from pathlib import Path

import pytest

from weirvern.admin import cli


# --- the invariant ------------------------------------------------------------
def test_importing_the_cli_does_not_resolve_the_project_dir():
    """Import-time resolution is what made the schema Job crash before it could
    even print an error. It must not come back.

    Uses the AST rather than string matching: an earlier version of this test
    matched the function's own `def project_dir()` line and failed on correct code,
    which is how a guard ends up being weakened until it means nothing.
    """
    import ast

    tree = ast.parse(inspect.getsource(cli))
    offenders: list[str] = []

    def calls_project_dir(node: ast.AST) -> bool:
        for sub in ast.walk(node):
            if (isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name)
                    and sub.func.id == "project_dir"):
                return True
        return False

    # Module scope, excluding function/class bodies: this is exactly the set of
    # statements that execute on import.
    for stmt in tree.body:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        if calls_project_dir(stmt):
            offenders.append(ast.unparse(stmt)[:80])

    assert not offenders, (
        f"project_dir() is called at module scope: {offenders}. That runs on "
        f"import, so it crashes every command in an image with no checkout."
    )


def test_gui_tolerates_a_missing_project_dir(monkeypatch, tmp_path):
    """The GUI must start where there is no checkout.

    This is the exact deployed condition: /app in the container has the package and
    nothing else. Calling project_dir() there raises FileNotFoundError.
    """
    from weirvern.admin import cli as cli_mod

    def boom():
        raise FileNotFoundError(
            "could not locate the Weirvern project directory; set WEIRVERN_HOME"
        )

    monkeypatch.setattr(cli_mod, "project_dir", boom)
    # The fallback is Path.cwd(); chdir to a bare temp dir to make the point.
    monkeypatch.chdir(tmp_path)

    captured = {}

    # web.run is the only thing after project_dir(); intercept it so the test does
    # not actually bind a port.
    def fake_run(connect_factory, settings, project_dir, namespace, host=None, port=None):
        captured["project_dir"] = project_dir
        return 0

    # The legacy `web.run` entry point is retired; `cmd_gui` always starts the Flask surface now, so
    # that is the function to intercept if the test is not to bind a port.
    monkeypatch.setattr(cli_mod, "_run_flask", fake_run)

    code = cli_mod.cmd_gui(_gui_args())
    assert code == 0, "cmd_gui must not fail when there is no project checkout"
    assert captured["project_dir"] == tmp_path


def test_project_dir_raises_with_an_actionable_message(tmp_path, monkeypatch):
    """When it DOES fail, the message must say how to fix it.

    Simulating the real failure rather than assuming a bare directory is enough:
    resolution step 3 is "the repo containing this package", so from a source
    checkout find_project_dir NEVER fails, no matter the cwd (verified: from /tmp it
    still resolved to the dev checkout). It only raises in an installed image, where
    the package sits in site-packages with no checkout above it. Both fallbacks are
    neutralised here to reproduce that condition.
    """
    from weirvern.admin import runtime

    monkeypatch.delenv("WEIRVERN_HOME", raising=False)
    monkeypatch.chdir(tmp_path)
    # Neutralise step 3: no ancestor of the package location is valid.
    monkeypatch.setattr(Path, "exists", lambda self: False, raising=False)

    with pytest.raises(FileNotFoundError) as exc:
        runtime.find_project_dir(tmp_path)
    message = str(exc.value)
    assert "WEIRVERN_HOME" in message, "the message must name the variable to set"
    # A user reading this needs to know what makes a directory valid.
    assert "kustomization" in message or "env.example" in message, (
        f"the message does not explain what a valid directory contains: {message}"
    )


def test_find_project_dir_accepts_either_marker(tmp_path, monkeypatch):
    """A directory counts as the project if it has EITHER k8s/kustomization.yaml
    OR .env.example -- matching _valid() in the implementation, so a deployment
    that ships only one of them still resolves."""
    from weirvern.admin import runtime

    monkeypatch.delenv("WEIRVERN_HOME", raising=False)

    a = tmp_path / "with_kustomization"
    (a / "k8s").mkdir(parents=True)
    (a / "k8s" / "kustomization.yaml").write_text("resources: []\n")
    assert runtime.find_project_dir(a) == a

    b = tmp_path / "with_env_example"
    b.mkdir()
    (b / ".env.example").write_text("CLICKHOUSE_HOST=clickhouse\n")
    assert runtime.find_project_dir(b) == b


def test_weirvern_home_is_honoured(tmp_path, monkeypatch):
    from weirvern.admin import runtime

    home = tmp_path / "explicit"
    home.mkdir()
    (home / ".env.example").write_text("X=1\n")
    monkeypatch.setenv("WEIRVERN_HOME", str(home))
    assert runtime.find_project_dir(tmp_path) == home


# --- the same invariant, checked against the real container layout ------------
def test_cli_subcommands_run_from_a_bare_directory(tmp_path):
    """Run the CLI's help from an empty directory, as the container image would.

    A subprocess rather than a direct call, because an import-time failure only
    manifests when the module is actually imported fresh.
    """
    result = subprocess.run(
        [sys.executable, "-c",
         "import weirvern.admin.cli as c; print('imported ok')"],
        capture_output=True, text=True, cwd=tmp_path,
        env={**__import__("os").environ, "WEIRVERN_HOME": ""},
    )
    assert result.returncode == 0, (
        f"importing the CLI failed from {tmp_path}:\n{result.stderr[-1500:]}"
    )
    assert "imported ok" in result.stdout


def _gui_args():
    import argparse

    return argparse.Namespace(host="127.0.0.1", port=0)


# --- the web handler's own robustness ----------------------------------------
def test_missing_gui_assets_produce_an_explanatory_500(monkeypatch, tmp_path):
    """A packaging bug must name itself rather than serving an empty 200.

    The same shape as the schema-path bug: the asset is present in a checkout and
    absent from an installed wheel unless package-data declares it.

    An earlier version of this test HUNG rather than failing, for two reasons worth
    recording: it opened the request on the main thread with no read timeout, and it
    tore the server down while the connection was still live. The assertions below
    use a bounded timeout and stop the server in a finally block, so a regression
    reports as a failure instead of wedging the suite -- a hanging test is worse
    than a failing one, because CI times out with no message.
    """
    import weirvern.admin.web as web

    monkeypatch.setattr(web, "STATIC_DIR", tmp_path / "nonexistent")

    # DRIVEN THROUGH THE SURVIVING SURFACE. This test used to start the legacy HTTP server and fetch
    # "/" over a socket. That server is retired, and the behaviour under test -- a missing asset
    # directory must be a loud 500 naming the fix, not a 200 and not a hang -- belongs to whichever
    # surface serves the console, so it now asks Flask the same question.
    class _CM:
        def __enter__(self):
            return None

        def __exit__(self, *_a):
            return False

    class _Ctx:
        settings = None
        backend = None
        config_client = None
        user_store = None
        sessions = None
        throttle = None
        accounts_note = ""
        connect_factory = staticmethod(lambda settings: _CM())

        class auth:
            enabled = False
            reason = ""

            @staticmethod
            def check(presented, client=""):
                return False

    from weirvern.admin import flask_app

    app = flask_app.create_app(_Ctx(), secret_key="image-layout")
    app.config.update(TESTING=True)
    resp = app.test_client().get("/")

    assert resp.status_code != 200, "a missing asset must not return 200"
    assert resp.status_code == 500, f"expected 500, got {resp.status_code}"
    body = resp.get_data(as_text=True)
    assert "missing from the package" in body
    assert "package-data" in body, (
        "the error must name the FIX, not just the symptom"
    )
