#!/usr/bin/env python3
"""Prove the new Zeek-summary guards actually fail on the defects they describe.

A guard that cannot fail is not a guard. This reintroduces each shipping defect -- one at a time,
on a copy restored between runs -- and confirms the matching test goes red. Anything reported
MISSED is a test that would have let the bug back in.

Runs offline against the local file; no database needed. Restores the file from the copy it made,
so a crash mid-run cannot leave the source mutated.
"""
from __future__ import annotations

import pathlib
import shutil
import subprocess
import sys
import tempfile

# Derived from this file's own location, never hardcoded: an absolute path to a working
# directory is both a portability bug and a leak of the local directory name (which still
# carries the pre-rename project name).
ROOT = pathlib.Path(__file__).resolve().parent.parent
SRC = ROOT / "weirvern" / "zeek_features.py"
TEST = "tests/test_zeek_summary_runnable.py"

CAST = "                toString(src_addr) AS src_addr,"
BARE = "                src_addr,"
DHCP_FIXED = "                toString(client_addr) AS src_addr,"
DHCP_BROKEN = "                src_addr,"

original = SRC.read_text()
if original.count(CAST) != 3:
    sys.exit(f"expected 3 Tier-3 casts, found {original.count(CAST)} -- update this probe")

backup = pathlib.Path(tempfile.mkdtemp()) / "zeek_features.py"
shutil.copy2(SRC, backup)


def run_tests() -> tuple[bool, list[str]]:
    """True if the suite FAILED (the guard bit), plus the names of the failing tests."""
    proc = subprocess.run(
        [".venv/bin/pytest", TEST, "-q", "--no-header", "-p", "no:cacheprovider"],
        cwd=ROOT, capture_output=True, text=True, timeout=300,
    )
    out = proc.stdout + proc.stderr
    caught = proc.returncode != 0
    names = [
        line.split("::")[-1].split()[0]
        for line in out.splitlines()
        if line.strip().startswith("FAILED")
    ]
    if caught and not names:
        names = ["<suite failed without naming a test>"]
    return caught, names


def check(label: str, mutated: str) -> bool:
    SRC.write_text(mutated)
    caught, names = run_tests()
    print(f"  {'CAUGHT' if caught else 'MISSED':7s} {label}")
    for name in names:
        print(f"             -> {name}")
    return caught


results = {}

# 1. Revert the dhcp fix: the wrong column that made the whole summary raise Code 47.
results["dhcp"] = check(
    "dhcp_agg reads `src_addr` (the Code 47 defect)",
    original.replace(DHCP_FIXED, DHCP_BROKEN, 1),
)

# 2. Drop each Tier-3 toString() cast, one at a time: the mixed IPv4/String union -> Variant
#    -> Code 44. Each removal must be caught on its own, not only in combination.
for which in ("tunnel", "quic", "ldap"):
    parts = original.split(CAST)
    degraded = parts[0] + BARE + CAST.join(parts[1:])
    assert degraded.count(CAST) == 2, "the mutation did not remove exactly one cast"
    assert degraded != original, "the mutation changed nothing"
    results[which] = check(f"{which}_agg loses its toString() cast (the Code 44 defect)", degraded)

# Restore and confirm green.
SRC.write_text(original)
assert SRC.read_text() == original, "restore failed -- the source is still mutated"
caught, names = run_tests()
print(f"\n  restored: suite {'STILL RED (restore is wrong!)' if caught else 'green again'}")

# The probe is only meaningful if every mutation was caught.
uncaught = [k for k, v in results.items() if not v]
if uncaught:
    print(f"\n  RESULT: {len(uncaught)} mutation(s) MISSED: {', '.join(uncaught)}")
    print("  A test that does not fail on its own defect is not yet a guard.")
    sys.exit(1)
print(f"\n  RESULT: all {len(results)} mutations caught, and the file is restored.")
