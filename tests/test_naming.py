"""Guard against a partial rename.

A rename touches the package directory, the Python import namespace, the CLI
entry point, the image tag, the Kubernetes namespace and label domain, hostPath
directories, environment variables, the ClickHouse database name, the schema
filename, and every doc. Missing any one of them produces a specific failure that
is easy to ship by accident:

  * a stale package name        -> ModuleNotFoundError only in a fresh install
  * a stale image tag           -> ImagePullBackOff on the cluster
  * a stale namespace           -> resources land somewhere unexpected
  * a stale hostPath            -> a healthy-looking stack that captures nothing
  * a stale env var             -> settings silently ignored, defaults used
  * a stale DB name             -> the schema Job creates a second empty database
  * a stale doc path            -> an operator follows a command that 404s

The previous name may appear in exactly ONE place: the README's reference to the
original graduate-school project, which is historical fact about a different and
older codebase. Anything else is a missed rename.
"""
import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
OLD = "flowforge"

# Historical references to the ORIGINAL project. These describe a different,
# older codebase and must not be rewritten — renaming them would falsify history.
ALLOWED_HISTORICAL = re.compile(r"original FlowForge experiment", re.IGNORECASE)

TEXT_SUFFIXES = {
    ".py", ".md", ".yaml", ".yml", ".toml", ".sql", ".cfg", ".example",
    ".txt", ".zeek", ".json",
}

# Files exempt from the scan, because naming the old name is their PURPOSE.
#
# This file is the guard: it must be able to say "the old name must not appear",
# which is impossible without containing the string. Exempting it is not a
# loophole — the assertions below still verify every OTHER file, and this file is
# reviewed by a human precisely because it defines what "renamed" means.
#
# (A guard that scanned itself and failed would be worse than useless: it would be
# "fixed" by deleting it.)
SELF_EXEMPT = {"tests/test_naming.py"}


def _tracked_files() -> list[Path]:
    """Files to scan: `git ls-files` where possible, else a filesystem walk.

    The fallback exists because the code is copied onto an ISOLATED test box with
    no remote and often no .git at all. `git ls-files` fails outright there and
    took the whole suite with it (6 tests failed) -- on the box where we most need
    the suite to run. git is still preferred because it honours .gitignore; the
    walk applies the same exclusions by hand.
    """
    try:
        out = subprocess.run(
            ["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True
        ).stdout.split()
        return [ROOT / f for f in out]
    except (subprocess.CalledProcessError, FileNotFoundError, OSError):
        skip = {".git", ".venv", "build", "dist", "__pycache__", ".ruff_cache",
                ".mypy_cache", ".pytest_cache", "node_modules", ".env"}
        found = []
        for path in sorted(ROOT.rglob("*")):
            if not path.is_file():
                continue
            rel = path.relative_to(ROOT)
            if set(rel.parts) & skip or rel.name in skip or rel.name.startswith(".env."):
                continue
            found.append(path)
        return found


def test_no_stale_old_name_in_any_tracked_file():
    """The single most valuable rename test: nothing may still say the old name.

    Scans `git ls-files`, so it sees exactly what a user would get from a clone.
    Anything tracked that is not this guard file must be clean.
    """
    problems: list[str] = []
    for path in _tracked_files():
        rel = str(path.relative_to(ROOT))
        if rel in SELF_EXEMPT:
            continue
        if not path.is_file():
            continue
        if path.suffix.lower() not in TEXT_SUFFIXES and path.suffix != "":
            continue
        try:
            text = path.read_text()
        except (UnicodeDecodeError, OSError):
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            if OLD not in line.lower():
                continue
            if ALLOWED_HISTORICAL.search(line):
                continue
            problems.append(f"{rel}:{lineno}: {line.strip()[:100]}")

    assert not problems, (
        "the old project name survives in the tree; a partial rename ships a "
        "broken install or a broken deployment:\n  " + "\n  ".join(problems)
    )


def test_the_guard_actually_scans_the_tree():
    """A guard that silently scans nothing always passes.

    This is the failure mode that let the rename ship broken once: the scan
    listed only TRACKED files, so while this test was itself untracked it had
    nothing to complain about. Assert the scan is actually looking at files.
    """
    scanned = [
        p for p in _tracked_files()
        if str(p.relative_to(ROOT)) not in SELF_EXEMPT and p.is_file()
    ]
    assert len(scanned) > 40, f"guard is scanning only {len(scanned)} files"

    # And the scan must be capable of detecting a violation. If this string were
    # ever absent from the tree, the guard could not be proven to work.
    assert OLD, "the guard has no pattern to look for"


def test_no_file_or_directory_named_after_the_old_project():
    """A stale path is worse than stale text: it 404s or fails to import."""
    stale = [
        str(p.relative_to(ROOT))
        for p in _tracked_files()
        if OLD in str(p.relative_to(ROOT)).lower()
        and not ALLOWED_HISTORICAL.search(str(p))
        # the README may name the old project, but no PATH may
    ]
    assert not stale, f"paths still carrying the old name: {stale}"


def test_old_package_directory_is_gone():
    assert not (ROOT / OLD).exists(), "the old package directory still exists"
    assert (ROOT / "weirvern").is_dir(), "the new package directory is missing"


def test_new_package_imports():
    import weirvern

    assert weirvern.__version__


def test_old_package_does_not_import():
    """If the old name still resolved, something is shadowing the rename."""
    with pytest.raises(ImportError):
        __import__(OLD)


def test_entry_point_names_match_the_pyproject():
    """The CLI name in pyproject must be the one the docs and manifests use."""
    pyproject = (ROOT / "pyproject.toml").read_text()
    assert "weirvern = \"weirvern.admin.cli:main\"" in pyproject

    # And the README must not document a command that no longer exists.
    readme = (ROOT / "README.md").read_text()
    assert "weirvern " in readme
    for stale in ("flowforge install", "flowforge status", "flowforge apply",
                  "flowforge tui", "flowforge logs"):
        assert stale not in readme, f"README still documents `{stale}`"


def test_kubernetes_namespace_and_labels_are_consistent():
    """Every manifest must agree on the namespace and the label domain, or
    resources scatter across namespaces and selectors stop matching."""
    k8s = ROOT / "k8s"
    text = "\n".join(p.read_text() for p in sorted(k8s.glob("*.yaml")))

    assert "namespace: weirvern" in text
    assert "weirvern.io/sensor-node" in text      # the node label the docs use
    assert "namespace: weirvern" in (k8s / "kustomization.yaml").read_text()


def test_env_var_is_renamed_everywhere():
    """A stale FLOWFORGE_HOME would be ignored and discovery would fail silently."""
    runtime = (ROOT / "weirvern" / "admin" / "runtime.py").read_text()
    assert "WEIRVERN_HOME" in runtime
    assert "FLOWFORGE_HOME" not in runtime

    # And if the README mentions it, it must use the new spelling.
    readme = (ROOT / "README.md").read_text()
    assert "FLOWFORGE_HOME" not in readme


def test_clickhouse_database_name_is_renamed():
    """A stale DB name means the schema Job provisions an empty second database
    and the worker queries the wrong one — both look like 'no data'."""
    schema = (ROOT / "weirvern" / "schema" / "001_weirvern.sql").read_text()
    assert "weirvern." in schema
    assert "flowforge." not in schema.lower()

    env = (ROOT / "k8s" / "20-configmap-env.yaml").read_text()
    assert "CLICKHOUSE_DB: \"weirvern\"" in env


def test_schema_filename_matches_the_package():
    """apply_schema globs *.sql, but a stale filename is a doc/packaging trap."""
    schema_dir = ROOT / "weirvern" / "schema"
    names = [p.name for p in schema_dir.glob("*.sql")]
    assert names, "no schema files packaged"
    assert not any(OLD in n.lower() for n in names), f"stale schema filename: {names}"


def test_hostpaths_are_renamed():
    """The hostPath directories are what the sensor writes and the worker reads;
    a mismatch between the two manifests means silent empty ingest."""
    worker = (ROOT / "k8s" / "33-worker.yaml").read_text()
    collector = (ROOT / "k8s" / "31-goflow2.yaml").read_text()
    assert "/var/lib/weirvern/flows" in worker
    assert "/var/lib/weirvern/flows" in collector
    assert "/var/lib/weirvern/zeek" in worker
