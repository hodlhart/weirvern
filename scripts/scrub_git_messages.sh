#!/bin/sh
# Rewrite commit MESSAGES to remove deployment identifiers, keeping every file and tree intact.
#
# WHY THE MESSAGES ARE PUBLISHED SURFACE. GitHub renders them on the commit list, in blame, in
# the PR view and in the RSS feed. Nine commits here described the lab -- a gateway MAC, segment
# addresses, a monitored host -- so "the identifiers are out of the files" was not the same claim
# as "the identifiers are out of the repository".
#
# WHY MESSAGES AND NOT THE TREES. The file contents are already clean (a scrub plus a test that
# fails if they drift). Rewriting trees would change every object hash in the repository for no
# additional privacy, and would make the history unverifiable against the backups. Message-only
# rewriting keeps the tree hashes IDENTICAL, so `git diff` between old and new is empty for every
# commit -- which is the property this script verifies at the end.
#
# A bundle backup is taken first, because this is destructive and must be recoverable:
#     git bundle create <backup>.bundle --all
#
# The rewrite uses `--msg-filter`, which receives the message on stdin. python3 is called rather
# than sed so the same MAPPING table is used as the file scrubber -- the alternative is a second,
# hand-written list of identifiers, which is exactly the drift this project has already been
# bitten by. (It cannot import the module: `git filter-branch` runs the filter with a working
# directory that is not guaranteed to be the repo root. The table is therefore inlined here, and
# `scripts/verify_sanitize.sh` checks the two agree.)
set -eu
cd "$(dirname "$0")/.." || exit 1

if [ "${1:-}" != "--yes" ]; then
    echo "This rewrites git history and requires a force-push. Re-run with --yes"
    echo
    echo "It will:"
    echo "  * rewrite commit MESSAGES only -- file contents and tree hashes are unchanged"
    echo "  * create a bundle backup in /home/hart/flowforge-backups/ BEFORE touching anything"
    echo "  * leave the remote alone; force-pushing is a separate, explicit step"
    exit 1
fi

BACKUP="/home/hart/flowforge-backups/weirvern-premessage-scrub-$(date +%Y%m%d-%H%M).bundle"
mkdir -p "$(dirname "$BACKUP")"
echo "=== backup ==="
git bundle create "$BACKUP" --all 2>&1 | tail -2 | sed 's/^/  /'
echo "  $BACKUP"

BEFORE=$(git rev-parse HEAD)
TREES_BEFORE=$(git log --all --format='%T' | sort | md5sum | cut -c1-12)

echo
echo "=== rewriting messages ==="
FILTER_BRANCH_SQUELCH_WARNING=1 git filter-branch -f --msg-filter '
python3 - <<'"'"'PYEOF'"'"'
import re, sys
msg = sys.stdin.read()
MAPPING = [
    (r"192\.168\.3\.(\d+)", r"198.51.100.\1"),
    (r"192\.168\.2\.(\d+)", r"203.0.113.\1"),
    (r"192\.168\.1\.(\d+)", r"192.0.2.\1"),
    (r"100\.98\.39\.(\d+)", r"100.64.0.\1"),
    (r"162\.248\.221\.(\d+)", "1.2.3.4"),
    (r"10\.0\.0\.(\d+)", r"198.51.100.\1"),
    (r"10\.0\.5\.(\d+)", r"198.51.100.\1"),
    (r"10\.9\.9\.(\d+)", r"203.0.113.\1"),
    (r"10\.20\.30\.(\d+)", r"192.0.2.\1"),
    (r"10\.43\.0\.(\d+)", r"198.51.100.\1"),
    (r"172\.16\.5\.(\d+)", r"192.0.2.\1"),
    (r"a8:9c:6c:96:b6:2d", "00:00:5e:00:53:01"),
    (r"bc:24:11:53:ca:66", "00:00:5e:00:53:02"),
    (r"bc:24:11:f6:ab:f1", "00:00:5e:00:53:03"),
    (r"Weirvern\.home", "sensor.example"),
    (r"spyro\.home", "host-a.example"),
    (r"\bspyro\b", "host-a"),
    (r"\bunifi\b", "gateway"),
    (r"derp\d+[a-z]*\.tailscale\.com", "relay.example.net"),
]
for pat, repl in MAPPING:
    msg = re.sub(pat, repl, msg, flags=re.IGNORECASE)
sys.stdout.write(msg)
PYEOF
' -- --all 2>&1 | tail -4 | sed 's/^/  /'

AFTER=$(git rev-parse HEAD)
TREES_AFTER=$(git log --all --format='%T' | sort | md5sum | cut -c1-12)

echo
echo "=== VERIFY: tree hashes unchanged (file contents were not touched) ==="
if [ "$TREES_BEFORE" = "$TREES_AFTER" ]; then
    echo "  OK: every tree hash is identical ($TREES_AFTER)"
    echo "      the rewrite changed messages only, so no file content moved"
else
    echo "  FAIL: tree hashes differ ($TREES_BEFORE -> $TREES_AFTER)"
    echo "        file contents changed. Restore from $BACKUP before continuing."
    exit 1
fi

echo
echo "=== VERIFY: no identifiers remain in any message ==="
python3 -m weirvern.tools.sanitize_identifiers --check --history 2>&1 | tail -6 | sed 's/^/  /'

echo
echo "=== VERIFY: the working tree is still clean ==="
python3 -m weirvern.tools.sanitize_identifiers --check 2>&1 | tail -2 | sed 's/^/  /'

echo
echo "HEAD moved $BEFORE -> $AFTER"
echo "The remote still has the OLD history. To publish the rewrite:"
echo "    git push --force-with-lease origin main"
echo "--force-with-lease, not --force: it refuses if the remote moved since this backup, which"
echo "prevents overwriting work that arrived while this ran."
