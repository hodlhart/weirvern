"""Guard against the in-path mode's old name creeping back.

The mode was renamed `weir` -> `siphon`. The old spelling survives in exactly two
PLACES ON PURPOSE, both of them input acceptance so a deployment configured before the
rename keeps working:

  * `mode.normalise` accepts it and stores `siphon`
  * the sensor's startup `case` accepts it and announces the new name

Everything else -- config values, module names, the overlay directory, docs, scripts --
must use `siphon`. The subtlety that makes a naive scan wrong: `weir` is a PREFIX of the
product name (`weirvern`) and of `weirnet`'s replacement (`siphonnet`), so only the
whole word is flagged, matched with non-letter boundaries.
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# The old name, as a word: `weir` not followed by a letter (`weirvern`, `weirnet`) and
# not preceded by one. Plus the two identifier forms that underscore-boundaries hide.
OLD = re.compile(r"(?<![A-Za-z])weir(?![A-Za-z])|MODE_WEIR\b|(?<![A-Za-z])weirnet(?![A-Za-z])")

# A line is allowed to name the old spelling when it is ABOUT the old spelling: an
# acceptance construct (it also names `siphon`), a migration note, or the changelog entry
# that records the rename itself. Anything else is a stale rename.
ALLOWED = re.compile(r"former|legacy|renam|siphon", re.IGNORECASE)

# This file necessarily contains the thing it forbids.
SELF_EXEMPT = {"tests/test_mode_naming.py"}

TEXT_SUFFIXES = {
    ".py", ".md", ".yaml", ".yml", ".toml", ".sql", ".cfg", ".example",
    ".txt", ".zeek", ".json", ".js", ".html", ".css", ".sh",
}


def _tracked_files() -> list[Path]:
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


def test_no_stale_old_mode_name_in_any_tracked_file():
    """The single most valuable rename test: only the acceptance constructs may keep it."""
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
            if not OLD.search(line):
                continue
            if ALLOWED.search(line):
                continue
            problems.append(f"{rel}:{lineno}: {line.strip()[:110]}")

    assert not problems, (
        "the old mode name survives outside the documented acceptance points; a partial "
        "rename ships a config value the sensor refuses or a doc that contradicts the "
        "code:\n  " + "\n  ".join(problems)
    )


def test_the_guard_actually_scans_the_tree():
    """A guard that silently scans nothing always passes. (The product rename shipped
    broken exactly that way once, and the fix was this assertion.)"""
    scanned = [
        p for p in _tracked_files()
        if str(p.relative_to(ROOT)) not in SELF_EXEMPT and p.is_file()
    ]
    assert len(scanned) > 40, f"guard is scanning only {len(scanned)} files"


def test_the_old_name_is_still_ACCEPTED_on_input():
    """The acceptance is the reason the guard has exemptions -- verify it end to end, so
    the exemptions describe a real behaviour rather than a permission."""
    from weirvern.admin import mode as mode_mod

    assert mode_mod.normalise("weir") == mode_mod.MODE_SIPHON
    assert mode_mod.normalise("WEIR") == mode_mod.MODE_SIPHON
    # And a pre-rename ConfigMap value validates as a live, capable mode.
    v = mode_mod.validate("weir", has_net_admin=True, has_net_raw=True, watchdog_available=True)
    assert v.ok and v.mode == mode_mod.MODE_SIPHON


def test_the_sensor_startup_accepts_the_old_name():
    """The startup script must not crash-loop a pre-rename deployment: `weir` reaches the
    in-path branch, announces the NEW name, and says why the old spelling is tolerated."""
    script = (ROOT / "k8s" / "32-zeek.yaml").read_text()
    assert "siphon|weir)" in script, "the startup case does not accept the former name"
    assert "former name" in script, "the acceptance does not say why it exists"
