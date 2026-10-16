#!/usr/bin/env python3
"""Prove the JA4 guards fail on the three defects they describe.

A guard that cannot fail is not a guard. Each defect is reintroduced on a copy of the shipping
file, one at a time, and the matching test must go red. Anything reported MISSED is a test that
would have let the bug back in.

The three defects, all of which produced a plausible number for something never measured:

  1. `zeek_value()` normalising only the `-` sentinel, so the literal string "(empty)" was stored
     as a TLS fingerprint and `zeek_ja4_count` reported 1 on hosts with no fingerprint at all.
  2. The baseline query LEFT JOINing zeek_ssl onto zeek_conn, so `baseline_conn_count` counted
     conn x ssl pairs (measured: 64,319 rows -> 93,048) instead of connections.
  3. A feature in ZEEK_FEATURES whose summary column is a CONSTANT rather than a measurement.
     It shipped first as a missing column (51 names against 49 aliases, which breaks every
     training query outright); its quieter successor is a column that exists, holds `0` for
     every row, and teaches the models nothing -- the shape the JA4 novelty feature wore until
     it was wired to a real history window. The mutation below reintroduces THAT: novelty stops
     comparing against the host's history and reports `1.0` for every TLS window.

Offline: reads the generated SQL, needs no database. Restores every file it touches.
"""
from __future__ import annotations

import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
INGESTER = ROOT / "weirvern" / "ingester.py"
FEATURES = ROOT / "weirvern" / "zeek_features.py"
TEST = "tests/test_ja4_fingerprint_integrity.py"


def run_tests() -> tuple[bool, list[str]]:
    proc = subprocess.run(
        [".venv/bin/pytest", TEST, "-q", "--no-header", "-p", "no:cacheprovider"],
        cwd=ROOT, capture_output=True, text=True, timeout=300,
    )
    out = proc.stdout + proc.stderr
    names = [
        line.split("::")[-1].split()[0]
        for line in out.splitlines() if line.strip().startswith("FAILED")
    ]
    if proc.returncode != 0 and not names:
        # A collection error is also a failure, and reporting it as "caught" is correct: the
        # mutation made the module unimportable, which the suite notices.
        names = ["<collection error>"]
    return proc.returncode != 0, names


# A SKIP IS NOT A PASS, and this function returning True for one was a real defect.
#
# The old version returned True -- success -- when its anchor text was not found, with the comment
# "not a failure of the guards; the probe is stale". The reasoning is sound about the GUARDS and
# wrong about the PROBE: if the anchor no longer exists, the mutation was never applied, no test
# was ever expected to fail, and the proof demonstrated NOTHING. It printed SKIP and the gate read
# a pass -- so a guard proof that had silently stopped proving anything looked exactly like one
# that worked. That is the failure mode this project names most often, in the script whose entire
# job is to detect it.
#
# A stale anchor is now a MISPROBE: reported as such, and it fails the run. The fix for a stale
# anchor is to update the anchor, not to keep certifying.
MISPROBE = False


def mutate(path: pathlib.Path, old: str, new: str, label: str) -> bool:
    global MISPROBE
    original = path.read_text()
    if old not in original:
        print(f"  MISPROBE {label}: the anchor is gone, so this mutation proved NOTHING.")
        print(f"           looked for: {old[:70]!r}")
        print("           Update the anchor in this script to match the current code.")
        MISPROBE = True
        return False
    path.write_text(original.replace(old, new, 1))
    caught, names = run_tests()
    path.write_text(original)
    print(f"  {'CAUGHT' if caught else 'MISSED':7s} {label}")
    for n in names:
        print(f"             -> {n}")
    return caught


results = []

# 1. The sentinel: stop normalising `(empty)`, exactly as it shipped.
results.append(mutate(
    INGESTER,
    'if val == "" or val in (ZEEK_NULL, ZEEK_EMPTY):',
    'if val == "" or val == ZEEK_NULL:',
    "zeek_value() ignores the (empty) sentinel (defect 1)",
))

# 2. The inflated baseline: put the fan-out join back.
results.append(mutate(
    FEATURES,
    """        FROM weirvern.zeek_conn
        WHERE ts BETWEEN '{start}' AND '{end}' AND src_addr != ''
        GROUP BY src_addr
    \"\"\"


def zeek_baseline_ja4_sql""",
    """        FROM weirvern.zeek_conn
        LEFT JOIN (SELECT src_addr AS f_addr, ja4 FROM weirvern.zeek_ssl
                   WHERE ts BETWEEN '{start}' AND '{end}') fp
               ON fp.f_addr = src_addr
        WHERE ts BETWEEN '{start}' AND '{end}'
        GROUP BY src_addr
    \"\"\"


def zeek_baseline_ja4_sql""",
    "the connection baseline joins zeek_ssl again (defect 2)",
))

# 3. The inert constant: novelty stops comparing against the history -- "entirely novel" for
#    every TLS window, which is what the placeholder era actually produced at scoring time.
results.append(mutate(
    FEATURES,
    "                - arrayCount(x -> has(ifNull(hj.hist_set, []), x), ifNull(s.ja4_set, [])))",
    "                - 0)",
    "zeek_ja4_novelty stops comparing against its history (defect 3)",
))

# 4. The predicate: accept `(empty)` as a real fingerprint again.
results.append(mutate(
    FEATURES,
    'JA4_REAL = "ja4 != \'\' AND ja4 != \'-\' AND ja4 != \'(empty)\'"',
    'JA4_REAL = "ja4 != \'\'"',
    "the JA4 predicate accepts the (empty) sentinel again",
))

# 5. The set: ship only the count, so novelty has to guess.
results.append(mutate(
    FEATURES,
    "arraySlice(arrayDistinct(arrayFilter(x -> {JA4_REAL_ARRAY},",
    "arraySlice(arrayDistinct(arrayFilter(x -> x != '',",
    "the baseline fingerprint set loses its sentinel guard",
))

# Confirm the clean tree is green again.
caught, names = run_tests()

# The probe is only meaningful if it ran mutations at all.
assert results, "no mutation was attempted -- the anchors have drifted"
missed = results.count(False)
print()
if missed:
    print(f"  RESULT: {missed} of {len(results)} mutations MISSED.")
    print("  A test that does not fail on its own defect is not yet a guard.")
    sys.exit(1)
print(f"  RESULT: all {len(results)} mutations caught.")
print(f"  restored tree: {'STILL RED (restore is wrong!)' if caught else 'green'}")
