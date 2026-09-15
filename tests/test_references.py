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

# The CHANGELOG narrates history, including removals, so a reference to something
# that no longer exists is the intended content rather than a defect.
SKIP_FILES = {"CHANGELOG.md"}

# Extensions that mean "this is a file path worth resolving".
PATH_RE = re.compile(
    # Directory-prefixed paths: k8s/foo.yaml, weirvern/worker.py
    r"(?<![\w/.-])(?:k8s|weirvern|tests|docs|\.github)/[\w./-]+\.(?:ya?ml|py|md|sql|toml|sh|json)"
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


def find_dangling_references(root: Path) -> list[str]:
    """Every reference to a repository path that does not exist.

    Split out from the test so the test can feed it a planted file and prove it
    actually detects one. A guard that cannot be shown to fail is not a guard.
    """
    out = subprocess.run(["git", "ls-files"], capture_output=True, text=True,
                         cwd=root, check=True).stdout
    problems: list[str] = []

    for rel in out.split():
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
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(["git", "add", "-A"], cwd=tmp_path, check=True)

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
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(["git", "add", "-A"], cwd=tmp_path, check=True)

    assert find_dangling_references(tmp_path) == []


def test_allowed_missing_entries_are_still_absent():
    """The allow-list must not rot.

    `.env` is the only exemption, and it is exempt because the CLI GENERATES it
    from .env.example rather than committing it. If it ever appears in the tree,
    the exemption hides a real problem (a committed environment file).
    """
    tracked = subprocess.run(["git", "ls-files", ".env"], capture_output=True,
                             text=True, check=True).stdout.strip()
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


def test_check_is_not_accidentally_empty():
    """A scan that finds no files always passes. Assert it actually walks the
    tree, the same way test_naming.py guards its own scan."""
    out = subprocess.run(["git", "ls-files"], capture_output=True, text=True,
                         check=True).stdout.split()
    scanned = [p for p in out
               if Path(p).suffix in CHECKED_SUFFIXES
               and not set(Path(p).parts) & SKIP_DIRS
               and Path(p).name not in SKIP_FILES]
    assert len(scanned) > 25, (
        f"only {len(scanned)} files are being scanned; the check has silently "
        f"narrowed and is no longer covering the tree"
    )
    assert os.path.exists("README.md")
