"""The tree must not reference files that do not exist.

WHY THIS TEST EXISTS: this class of defect recurred four separate times and was
never caught by anything else. `k8s/21-secrets.yaml` was deleted for a good reason
(it silently wiped real secrets on every apply), and after the deletion five
tracked files still told the reader to go and edit it: the CLI's post-install
checklist, the README's configuration table, the CHANGELOG, and the kustomization.
A dangling reference is worse than a missing feature: the reader believes the file
is there and concludes they have misconfigured something.

The same pattern appeared with `k8s/secrets.env.example` and with
`k8s/zeek/zeekctl.cfg`. Each was found by accident, while doing something else.
This test makes it deliberate.

Deliberately NOT checked: CHANGELOG.md, whose whole purpose is to describe what a
release contained. Naming a file that has since been removed is correct there, and
excluding the file is more honest than adding a growing allow-list of historical
mentions.
"""
from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

# Paths that legitimately do not exist in the tree. Keep this list SHORT and
# always with a reason; every entry is a hole in the check.
ALLOWED_MISSING = {
    # Created by the operator at deploy time, deliberately not a manifest.
    ".env",
}

# Files whose CONTENT is legitimately about paths that do not exist.
#
# CHANGELOG.md narrates history, including removals, so naming a since-deleted
# file is correct there.
#
# this test file itself holds fixtures: paths planted specifically to be absent,
# and docstring narration of files that were removed. It cannot pass its own check
# without exempting itself, which is exactly the self-exemption pattern that
# produced a useless guard earlier in this project (a rename guard that exempted
# itself and then scanned nothing while reporting success).
#
# So the exemption is bounded two ways, and both are asserted below:
#   * test_check_is_not_accidentally_empty asserts the scan covers >25 files, so
#     the exemption cannot grow into "everything is skipped"
#   * test_skip_list_is_exactly_these_two_files fails if a third entry is added
#     without a decision being recorded here
SKIP_FILES = {"CHANGELOG.md", "test_references.py"}

# Extensions that mean "this is a file path worth resolving".
PATH_RE = re.compile(
    # Directory-prefixed paths: k8s/foo.yaml, weirvern/worker.py
    # `(?:\.template)?` because the tree has REAL files like
    # k8s/units/weirling-unit.yaml.template: without it the pattern stopped at `.yaml`, so a
    # reference to the template was checked against a name that does not exist -- a false
    # positive that would train a reader to ignore this guard.
    r"(?<![\w/.-])(?:k8s|weirvern|tests|docs|\.github)/[\w./-]+\.(?:ya?ml|py|md|sql|toml|sh|json)(?:\.template)?"
    r"|"
    # Bare root-level names, but ONLY with an extension or a known extensionless
    # filename. Matching the bare word "README" flagged prose like "see the README"
    # in 16 files. The lookahead requires end-of-token so "README.md" still matches.
    r"(?<![\w/.-])(?:Containerfile|pyproject\.toml|\.gitignore|"
    r"(?:README|SECURITY|NOTICE|USAGE_POLICY|CHANGELOG)\.md)(?=[\s,;:)]|$)"
)

CHECKED_SUFFIXES = {".py", ".md", ".yaml", ".yml", ".toml", ".sh", ".example"}
SKIP_DIRS = {".git", ".venv", "build", "dist", "__pycache__", ".ruff_cache",
             ".mypy_cache", ".pytest_cache", "node_modules", "site-packages"}



def _tracked_files(root: Path) -> list[str]:
    """Files to scan: `git ls-files` where possible, else a filesystem walk.

    WHY THE FALLBACK EXISTS: the code is copied onto an isolated test box with no
    git remote (and often no .git at all), and `git ls-files` then fails outright,
    taking the whole suite with it. Six tests failed that way before this was added.
    `git ls-files` is still preferred because it respects .gitignore, which a walk
    cannot: the walk must therefore apply the same exclusions by hand.
    """
    try:
        out = subprocess.run(["git", "ls-files"], capture_output=True, text=True,
                             cwd=root, check=True).stdout
        return out.split()
    except (subprocess.CalledProcessError, FileNotFoundError, OSError):
        found: list[str] = []
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            rel = path.relative_to(root)
            if set(rel.parts) & SKIP_DIRS:
                continue
            found.append(str(rel))
        return found


def find_dangling_references(root: Path) -> list[str]:
    """Every reference to a repository path that does not exist.

    Split out from the test so the test can feed it a planted file and prove it
    actually detects one. A guard that cannot be shown to fail is not a guard.
    """
    problems: list[str] = []

    for rel in _tracked_files(root):
        path = Path(rel)
        if path.name in SKIP_FILES:
            continue
        if path.suffix not in CHECKED_SUFFIXES or set(path.parts) & SKIP_DIRS:
            continue
        try:
            text = (root / path).read_text()
        except (UnicodeDecodeError, OSError):
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            for m in PATH_RE.finditer(line):
                # group(0), NOT group(1): the extension sits outside the capture
                # group in the pattern, so group(1) yields 'k8s/kustomization' and
                # every real file then looks missing. That mistake produced 30
                # lines of false positives the first time this ran.
                ref = m.group(0)
                if ref in ALLOWED_MISSING:
                    continue
                # Resolve against the repo root, and also against the referencing
                # file's own directory: k8s/README.md legitimately writes
                # "10-storage.yaml" meaning k8s/10-storage.yaml.
                if (root / ref).exists() or (root / path.parent / ref).exists():
                    continue
                problems.append(f"{path}:{lineno}: '{ref}' does not exist")
    return problems


def test_no_reference_to_a_nonexistent_file():
    problems = find_dangling_references(Path.cwd())
    assert not problems, (
        "the tree references files that do not exist; a reader will look for them "
        "and conclude they misconfigured something:\n  " + "\n  ".join(problems)
    )


def test_the_dangling_reference_check_detects_a_planted_reference(tmp_path):
    """A guard that scans nothing always passes.

    The rename guard in this project shipped once with no test that IT could fail,
    and it silently scanned nothing while reporting success. So: build a real git
    tree containing one reference to a file that certainly does not exist, and
    assert the check reports exactly that.
    """
    (tmp_path / "k8s").mkdir()
    (tmp_path / "k8s" / "real.yaml").write_text("kind: Namespace\n")
    (tmp_path / "README.md").write_text(
        "See k8s/definitely-not-a-real-file-9f3a.yaml for details.\n"
        "See k8s/real.yaml for the real thing.\n"
    )
    # No git init: _tracked_files falls back to a walk, which is what the
    # isolated test box does, so these exercise that path too.

    problems = find_dangling_references(tmp_path)

    assert len(problems) == 1, f"expected exactly the planted reference, got {problems}"
    assert "definitely-not-a-real-file-9f3a.yaml" in problems[0]
    # And it must NOT flag the file that really exists, or the check is noise.
    assert "k8s/real.yaml" not in problems[0]


def test_the_check_reports_a_real_reference_as_present(tmp_path):
    """The complement: a valid reference must produce no problem at all. Without
    this, a check that flags everything would pass the test above."""
    for name in ("k8s/20-configmap-env.yaml", "weirvern/worker.py", "README.md",
                 "SECURITY.md", ".env.example"):
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("x\n")
    (tmp_path / "docs.md").write_text(
        "Edit k8s/20-configmap-env.yaml and weirvern/worker.py.\n"
        "Read README.md, SECURITY.md and .env.example.\n"
    )
    # No git init: _tracked_files falls back to a walk, which is what the
    # isolated test box does, so these exercise that path too.

    assert find_dangling_references(tmp_path) == []


def test_allowed_missing_entries_are_still_absent():
    """`.env` is the only dangling-reference exemption, and it is exempt because the
    CLI GENERATES it from .env.example rather than committing it.

    The real risk is a COMMITTED .env, which would carry Pushover tokens and
    database passwords. Checked two ways, because neither alone is sufficient:

      * git says whether it is tracked -- authoritative, but git is absent on the
        isolated test box, where this check was crashing with CalledProcessError.
      * in a tree with no repository, the equivalent statement is that .env is not
        part of the shipped source, so its presence is checked against the
        filesystem-walk exclusion list instead.
    """
    try:
        tracked = subprocess.run(["git", "ls-files", ".env"], capture_output=True,
                                 text=True, check=True).stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError, OSError):
        # No repository (the isolated test box). The equivalent guarantee there is
        # that .env is NOT part of the scanned source set, so the exemption cannot
        # be hiding a shipped secrets file. Without this branch the exemption would
        # go unverified exactly where the tree is about to be copied somewhere new.
        scanned = [Path(p).name for p in _tracked_files(Path.cwd())]
        assert ".env" not in scanned, (
            ".env is included in the scanned set on a box with no git, so the "
            "dangling-reference exemption is hiding a secrets file"
        )
        return
    assert not tracked, (
        ".env is TRACKED and is exempt from the dangling-reference check, so the "
        "check is blind to a committed environment file (which would carry "
        "Pushover tokens and database passwords)"
    )


def test_the_check_skips_the_changelog():
    """Assert the exclusion rather than leaving it implicit: if CHANGELOG.md were
    ever dropped from SKIP_FILES, its historical mentions would fail CI and the
    likely 'fix' would be to delete accurate history."""
    assert "CHANGELOG.md" in SKIP_FILES


def test_skip_list_is_exactly_these_two_files():
    """Bound the self-exemption.

    This file must skip itself (it holds deliberately-absent fixture paths), and
    CHANGELOG.md must be skipped (it narrates removals). Those are the only two
    reasons, so the set is pinned. A third entry silently narrows the check, and
    the whole point of this file is that a narrowing check still passes.

    To add a third: change this assertion deliberately, and record why in the
    SKIP_FILES comment above.
    """
    # Membership + cardinality rather than a set comparison: the comparison form
    # trips ruff's SIM300 (constant on one side), and its suggested rewrite is a
    # Yoda condition that reads worse than either.
    assert len(SKIP_FILES) == 2, (
        f"the skip list changed to {sorted(SKIP_FILES)}; every entry is a hole in "
        f"the dangling-reference check"
    )
    assert "CHANGELOG.md" in SKIP_FILES
    assert "test_references.py" in SKIP_FILES


def test_the_fixtures_are_still_exercised_despite_the_self_exemption():
    """The self-exemption means the REAL tree is not scanned for this file's
    fixture paths. That must not hide a broken check: the planted-reference and
    valid-reference tests build their own trees, so they exercise the same code
    the real scan uses without depending on this file being scanned.
    """
    import inspect

    src = inspect.getsource(find_dangling_references)
    assert "_tracked_files" in src, (
        "find_dangling_references no longer goes through _tracked_files, so the "
        "synthetic-tree tests are no longer testing the same path the real scan does"
    )
    # _tracked_files must still PREFER git (it respects .gitignore, which a walk
    # cannot) while falling back to a walk on a box with no repository. Asserting
    # both halves: dropping the git path would silently change what "tracked"
    # means in CI, and dropping the fallback breaks the isolated test box.
    tsrc = inspect.getsource(_tracked_files)
    assert "ls-files" in tsrc, "the git path was dropped; .gitignore is no longer honoured"
    assert "rglob" in tsrc, "the filesystem fallback was dropped; a box with no .git will fail"

    # Both synthetic tests must exist, or the exemption above is unbounded in
    # practice (nothing would prove the checker can fail).
    names = {n for n in globals() if n.startswith("test_")}
    assert "test_the_dangling_reference_check_detects_a_planted_reference" in names
    assert "test_the_check_reports_a_real_reference_as_present" in names


def test_check_is_not_accidentally_empty():
    """A scan that finds no files always passes. Assert it actually walks the
    tree, the same way test_naming.py guards its own scan."""
    out = _tracked_files(Path.cwd())
    scanned = [p for p in out
               if Path(p).suffix in CHECKED_SUFFIXES
               and not set(Path(p).parts) & SKIP_DIRS
               and Path(p).name not in SKIP_FILES]
    assert len(scanned) > 25, (
        f"only {len(scanned)} files are being scanned; the check has silently "
        f"narrowed and is no longer covering the tree"
    )
    assert os.path.exists("README.md")
