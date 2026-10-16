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
# The rewrite uses `--msg-filter`, which receives the message on stdin, and pipes it through the
# SAME module the file scrubber uses (`--filter` mode). One MAPPING table, two consumers.
#
# An earlier version inlined a copy of the table here, because `git filter-branch` runs the filter
# from a working directory that is not guaranteed to be the repo root. That copy was the drift
# this project keeps finding: it would have been scrubbed by a stale list while the file scrubber
# moved on, silently, with nothing to notice. The path is made absolute instead.
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

ROOT=$(git rev-parse --show-toplevel)
# `git filter-branch` runs the filter with a working directory that is not guaranteed to be the
# repo root, so the module is invoked by ABSOLUTE path with PYTHONPATH set. The alternative --
# inlining a second copy of MAPPING in this script -- is the drift this project keeps finding:
# a stale table would scrub messages while the file scrubber moved on, silently.
REPO_PYTHON="$ROOT/.venv/bin/python"
[ -x "$REPO_PYTHON" ] || REPO_PYTHON=python3
export PYTHONPATH="$ROOT"

# THE BACKUP PATH MOVED WITH THE HOST (2026-10-16). The original path (/home/hart/...) was where
# this script was first written; the machine this repo actually publishes from has no /home/hart
# and no passwordless root to create one. A backup path that cannot be created is a backup that
# does not happen -- and "backup first" is this script's entire contract, so it must not be the
# step that silently fails. $HOME, overridable.
BACKUP="${WEIRVERN_BACKUP_DIR:-$HOME/weirvern-backups}/weirvern-premessage-scrub-$(date +%Y%m%d-%H%M).bundle"
mkdir -p "$(dirname "$BACKUP")"
echo "=== backup ==="
git bundle create "$BACKUP" --all 2>&1 | tail -2 | sed 's/^/  /'
echo "  $BACKUP"

BEFORE=$(git rev-parse HEAD)
TREES_BEFORE=$(git rev-parse "$BEFORE^{tree}")

echo
echo "=== rewriting messages ==="
FILTER_BRANCH_SQUELCH_WARNING=1 git filter-branch -f --msg-filter "
    '"$REPO_PYTHON"' -m weirvern.tools.sanitize_identifiers --filter
" -- --all 2>&1 | tail -4 | sed 's/^/  /'

AFTER=$(git rev-parse HEAD)
TREES_AFTER=$(git rev-parse "$AFTER^{tree}")

echo
echo "=== VERIFY: the tip TREE is unchanged (file contents were not touched) ==="
# Compared tip-to-tip. An earlier version used `git log --all --format=%T`, which swept in
# refs/original/* -- filter-branch's own local backup of the PRE-rewrite state -- so the two
# lists could never match and the check reported failure for a correct rewrite.
if [ "$TREES_BEFORE" = "$TREES_AFTER" ]; then
    echo "  OK: the tree is identical ($TREES_AFTER)"
    echo "      the rewrite changed messages only, so no file content moved"
else
    echo "  FAIL: tree hashes differ ($TREES_BEFORE -> $TREES_AFTER)"
    echo "        file contents changed. Restore from $BACKUP before continuing."
    exit 1
fi

echo
echo "=== VERIFY: the messages still EXIST (an empty rewrite passes every other check) ==="
if [ -z "$(git log --format=%s -1)" ]; then
    echo "  FAIL: the newest commit subject is EMPTY. The filter produced no output and the"
    echo "        history now has blank messages. Restore from $BACKUP immediately:"
    echo "            git fetch \"$BACKUP\" 'refs/heads/main:refs/heads/restored'"
    echo "            git update-ref refs/heads/main refs/heads/restored"
    exit 1
fi
EMPTY_COUNT=$(git log --format=%s | grep -c '^$' || true)
echo "  subjects: $(git log --oneline | wc -l) commits, $EMPTY_COUNT empty"
[ "$EMPTY_COUNT" = "0" ] || { echo "  FAIL: $EMPTY_COUNT commit(s) have no subject"; exit 1; }
echo "  OK: every commit still has a message"

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
