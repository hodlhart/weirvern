#!/bin/sh
# Correct a wrong figure in one already-published commit message.
#
# WHY. The message for 51969bf claims "1014 passed, 3 skipped". That figure was never measured --
# it was carried forward from an earlier run and incremented by hand. Measured at that commit:
# 928 passed, 4 skipped. A wrong number in a committed message is the failure this project keeps
# guarding against ("a plausible number for something never measured"), and it is worse in a
# message than in a log because it is permanent and published.
#
# The rewrite is SAFE-OR-ABORT, in three places:
#   1. it refuses to run on a dirty tree;
#   2. it refuses to run unless the exact wrong text is present in the target message;
#   3. the filter asserts the text matched, so a no-op rewrite fails instead of reporting success.
#
# Only the message changes. The tree at each commit is untouched, and commits AFTER the target in
# the range keep their content.
set -eu

TARGET=51969bf
WRONG='1014 passed, 3 skipped. Gate green, now 11 checks.'
RIGHT='928 passed, 4 skipped (MEASURED at this commit by checking it out into a worktree and
running the suite -- an earlier draft of this message said 1014, a hand-incremented figure that
no run ever produced). Gate green, now 11 checks.'

cd "$(dirname "$0")/.."

if [ -n "$(git status --porcelain)" ]; then
    echo "  refusing: the working tree is dirty. Commit or stash first."
    exit 1
fi

if ! git log --format=%B -1 "$TARGET" | grep -qF "$WRONG"; then
    echo "  refusing: $TARGET's message does not contain the text to replace."
    echo "  Looking for: $WRONG"
    echo "  The rewrite would change nothing while reporting success."
    exit 1
fi
echo "  found the wrong figure in $TARGET"

# The message filter reads the message on stdin and writes the new one to stdout. It ASSERTS the
# target text is present, so a silent no-op aborts the whole rewrite.
# The filter is a FILE, not an inline string: the commit message contains apostrophes, which
# terminate a single-quoted argument and make the shell try to execute the following words
# (observed as "sh: line 3: these: command not found" plus a fatal syntax error). A file has no
# quoting problem.
# An ABSOLUTE path: git filter-branch runs the filter via the shell but does not resolve a
# relative one against the repository root, failing with "No such file or directory" even when
# the file exists (observed). $PWD here is already the repo root because of the `cd` above.
MSG_FILTER="$PWD/scripts/msgfix_test_count.sh"

if [ ! -x "$MSG_FILTER" ]; then
    echo "  refusing: the message filter is not executable at $MSG_FILTER"
    exit 1
fi

FILTER_BRANCH_SQUELCH_WARNING=1 \
    git filter-branch -f --msg-filter "$MSG_FILTER" "$TARGET^..HEAD" >/dev/null 2>&1 || {
    echo "  filter-branch failed; the tree is unchanged."
    exit 1
}

# VERIFY BY SUBJECT, NOT BY THE OLD SHA. A rewrite produces a NEW commit id, so looking up
# $TARGET afterwards reads the BACKUP ref (refs/original/...), which by definition still holds the
# old message -- the first version of this check did exactly that and reported "the wrong figure
# is still present" while the rewrite had in fact succeeded. The subject is the stable handle.
NEW_SHA=$(git log --format='%H %s' --all \
    | grep -F "threat hunt team" \
    | grep -v "^$(git rev-parse refs/original/refs/heads/main 2>/dev/null)" \
    | head -1 | cut -d' ' -f1)

if [ -z "$NEW_SHA" ]; then
    echo "  FAILED: could not find the rewritten commit by subject."
    exit 1
fi

echo
echo "  after the rewrite ($NEW_SHA):"
git log --format=%B -1 "$NEW_SHA" | tail -4 | sed 's/^/    /'

if git log --format=%B -1 "$NEW_SHA" | grep -qF "$WRONG"; then
    echo "  FAILED: the wrong figure is still present."
    exit 1
fi
if ! git log --format=%B -1 "$NEW_SHA" | grep -qF "928 passed"; then
    echo "  FAILED: the corrected figure is not present."
    exit 1
fi

echo
echo "  corrected. The tree is unchanged; only the message differs."
echo "  Verify the range still has its content, then: git push --force-with-lease"
