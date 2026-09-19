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
set -u
cd "$(dirname "$0")/.." || exit 1

echo "=== snapshot address-shaped tokens BEFORE ==="
python3 - <<'EOF' > /tmp/sanitize_before.txt
import re, subprocess, pathlib
IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b")
NET = re.compile(r"\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b")
out = subprocess.run(["git","ls-files"],capture_output=True,text=True).stdout.split()
for rel in out:
    if pathlib.Path(rel).suffix.lower() in {".png",".ico",".jpg",".pdf",".zip"}:
        continue
    try:
        t = pathlib.Path(rel).read_text(errors="replace")
    except Exception:
        continue
    for m in list(IP.finditer(t)) + list(NET.finditer(t)):
        print(f"{rel}\t{m.group(0)}")
EOF
wc -l < /tmp/sanitize_before.txt | sed 's/^/  tokens: /'

echo
echo "=== scrub ==="
python3 -m weirvern.tools.sanitize_identifiers --write | tail -2

echo
echo "=== 1. every address-shaped token must still PARSE ==="
python3 - <<'EOF'
import ipaddress, re, subprocess, pathlib, sys
IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b")
bad = []
out = subprocess.run(["git","ls-files"],capture_output=True,text=True).stdout.split()
for rel in out:
    if pathlib.Path(rel).suffix.lower() in {".png",".ico",".jpg",".pdf",".zip"}:
        continue
    try:
        t = pathlib.Path(rel).read_text(errors="replace")
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
python3 - <<'EOF'
import re, subprocess, pathlib
IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b")
NET = re.compile(r"\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b")
out = subprocess.run(["git","ls-files"],capture_output=True,text=True).stdout.split()
after = []
for rel in out:
    if pathlib.Path(rel).suffix.lower() in {".png",".ico",".jpg",".pdf",".zip"}:
        continue
    try:
        t = pathlib.Path(rel).read_text(errors="replace")
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
echo "=== 4. the guard reports nothing ==="
python3 -m weirvern.tools.sanitize_identifiers --check | tail -2
CHECK=$(python3 -m weirvern.tools.sanitize_identifiers --check >/dev/null 2>&1; echo $?)

echo
if [ "$PARSE" = 0 ] && [ "$DROP" = 0 ] && [ "$TESTS" = 0 ] && [ "$CHECK" = 0 ]; then
    echo "ALL CHECKS PASSED"
else
    echo "FAILED: parse=$PARSE drop=$DROP tests=$TESTS guard=$CHECK"
    exit 1
fi
