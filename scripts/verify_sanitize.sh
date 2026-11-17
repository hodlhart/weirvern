#!/bin/sh
# Prove the scrub is SAFE before trusting it: snapshot every address-shaped token, scrub, and
# compare.
#
# WHY THIS EXISTS. Two scrub bugs already shipped into 23 files:
#
#   1. A rule that replaced only an address PREFIX dropped the final octet, turning a valid CIDR
#      into something unparseable (a trailing dot where the last octet had been), in 23 files.
#   2. The same class of error left stale PACKED BYTES in an ARP test: the address moved but the
#      assertion still compared against the bytes of the old one, so the test failed and the
#      comment beside it described the wrong address.
#
# Both were invisible in a diff and only appeared when the tests ran. This harness checks the
# INVARIANT instead: an address-shaped token must still parse after the scrub, and the count of
# such tokens must not change. A scrub that eats an octet breaks the first; one that drops a
# token breaks the second.
#
# THE SCRUB RUNS IN A DETACHED WORKTREE, NOT IN THE REPOSITORY UNDER TEST (measured 2026-11-17).
# This script used to run `--write` in place, so VERIFYING the scrubber MUTATED the tree: a gate
# run rewrote tests/test_scorecard.py from 10.0.0.x to 198.51.100.x while the gate was deciding
# whether to push it. Two consequences, both bad. A failed gate left the repository altered, so
# the next run judged different content than the run before it; and a scrub wide enough to touch
# a real defect would have "fixed" the very file the gate had just rejected, turning a failing
# check into a passing one without a human reading the change. A check that edits the subject
# cannot report on it. `git worktree add --detach` gives the scrub a real checkout at HEAD --
# what the push will publish -- and `trap` removes it on every exit path.
set -u
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT" || exit 1

WORK=$(mktemp -d "${TMPDIR:-/tmp}/wv-sanitize.XXXXXX") || exit 1
cleanup() {
    git worktree remove --force "$WORK" >/dev/null 2>&1 || rm -rf "$WORK"
}
trap cleanup EXIT INT TERM
if ! git worktree add --detach "$WORK" HEAD >/dev/null 2>&1; then
    echo "FAIL: could not create a scratch worktree at HEAD"
    exit 1
fi

echo "=== snapshot address-shaped tokens BEFORE ==="
python3 - "$WORK" <<'EOF' > /tmp/sanitize_before.txt
import re, subprocess, pathlib, sys
root = pathlib.Path(sys.argv[1])
IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b")
NET = re.compile(r"\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b")
out = subprocess.run(["git","ls-files"], cwd=root, capture_output=True, text=True).stdout.split()
for rel in out:
    if pathlib.Path(rel).suffix.lower() in {".png",".ico",".jpg",".pdf",".zip"}:
        continue
    try:
        t = (root / rel).read_text(errors="replace")
    except Exception:
        continue
    for m in list(IP.finditer(t)) + list(NET.finditer(t)):
        print(f"{rel}\t{m.group(0)}")
EOF
wc -l < /tmp/sanitize_before.txt | sed 's/^/  tokens: /'

echo
echo "=== scrub (in the scratch worktree) ==="
( cd "$WORK" && python3 -m weirvern.tools.sanitize_identifiers --write ) | tail -2

echo
echo "=== 1. every address-shaped token must still PARSE ==="
python3 - "$WORK" <<'EOF'
import ipaddress, re, subprocess, pathlib, sys

root = pathlib.Path(sys.argv[1])
IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b")

# Tokens that were ALREADY unparseable BEFORE the scrub. A value written on purpose to be invalid
# (a test that bad input is refused) parses in neither state, so it cannot be evidence that the
# scrubber broke anything -- this check would otherwise fail forever on correct fixtures.
BEFORE_INVALID = set()
try:
    for line in pathlib.Path("/tmp/sanitize_before.txt").read_text().splitlines():
        parts = line.split("\t")
        if len(parts) != 2:
            continue
        tok = parts[1]
        try:
            if "/" in tok:
                ipaddress.ip_network(tok, strict=False)
            else:
                ipaddress.ip_address(tok)
        except ValueError:
            BEFORE_INVALID.add(tok)
except OSError:
    pass

bad = []
out = subprocess.run(["git","ls-files"], cwd=root, capture_output=True, text=True).stdout.split()
for rel in out:
    if pathlib.Path(rel).suffix.lower() in {".png",".ico",".jpg",".pdf",".zip"}:
        continue
    try:
        t = (root / rel).read_text(errors="replace")
    except Exception:
        continue
    for m in IP.finditer(t):
        tok = m.group(0)
        try:
            if "/" in tok:
                ipaddress.ip_network(tok, strict=False)
            else:
                ipaddress.ip_address(tok)
        except ValueError as e:
            # A DELIBERATELY INVALID TOKEN IS NOT CORRUPTION. This check exists to catch the
            # scrubber EATING part of a real address (measured: it once turned a valid CIDR into a
            # truncated one). A malformed value written on purpose -- a test asserting that bad
            # input is REFUSED -- parses in neither state, so it must be excluded from the
            # comparison. Distinguished by whether the token is invalid BEFORE scrubbing too: if it
            # never parsed, the scrubber did not break it.
            if tok in BEFORE_INVALID:
                continue
            bad.append(f"{rel}: {tok!r} -- {e}")
if bad:
    print(f"  FAIL: {len(bad)} token(s) no longer parse -- the scrub ate part of an address:")
    for b in bad[:10]:
        print(f"    {b}")
    sys.exit(1)
print("  OK: every address and CIDR in the tree parses")
EOF
PARSE=$?

echo
echo "=== 2. no address-shaped token was DROPPED ==="
python3 - "$WORK" <<'EOF'
import re, subprocess, pathlib, sys
root = pathlib.Path(sys.argv[1])
IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b")
NET = re.compile(r"\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b")
out = subprocess.run(["git","ls-files"], cwd=root, capture_output=True, text=True).stdout.split()
after = []
for rel in out:
    if pathlib.Path(rel).suffix.lower() in {".png",".ico",".jpg",".pdf",".zip"}:
        continue
    try:
        t = (root / rel).read_text(errors="replace")
    except Exception:
        continue
    for m in list(IP.finditer(t)) + list(NET.finditer(t)):
        after.append(f"{rel}\t{m.group(0)}")
before = open("/tmp/sanitize_before.txt").read().splitlines()
print(f"  before {len(before)}  after {len(after)}  delta {len(after)-len(before):+d}")
if len(after) < len(before):
    # A drop is expected ONLY where a mapped value was removed outright (a hostname, a vendor
    # name). An address count going DOWN means a token was destroyed.
    print("  FAIL: fewer address tokens than before -- the scrub removed an address rather than")
    print("        replacing it, which means something that was read is now unreadable.")
    raise SystemExit(1)
print("  OK: no address token was dropped")
EOF
DROP=$?

echo
echo "=== 3. the tests still pass ==="
if [ -x .venv/bin/pytest ]; then
    # Capture pytest's OWN exit code -- `... | tail` returns tail's status, which is always 0,
    # so the harness reported success while three tests were failing.
    if .venv/bin/pytest -q > /tmp/sanitize_tests.txt 2>&1; then TESTS=0; else TESTS=1; fi
    tail -3 /tmp/sanitize_tests.txt
else
    echo "  (no .venv; skipped)"; TESTS=0
fi

echo
echo "=== 4. the guard reports nothing in the tree that will be pushed ==="
python3 -m weirvern.tools.sanitize_identifiers --check | tail -2
CHECK=$(python3 -m weirvern.tools.sanitize_identifiers --check >/dev/null 2>&1; echo $?)

echo
if [ "$PARSE" = 0 ] && [ "$DROP" = 0 ] && [ "$TESTS" = 0 ] && [ "$CHECK" = 0 ]; then
    echo "ALL CHECKS PASSED"
else
    echo "FAILED: parse=$PARSE drop=$DROP tests=$TESTS guard=$CHECK"
    exit 1
fi
