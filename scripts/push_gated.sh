#!/bin/sh
# Gate, then push -- as ONE command, so a failed gate cannot be routed around.
#
# WHY THIS EXISTS, AND WHAT IT PREVENTS. `git push` used to be typed after `sh scripts/gate.sh`
# on the same line, separated by `;`. Shell `;` runs the next command whatever the last one did,
# so a FAILING gate did not stop a push. Measured twice in one session: the gate reported FAIL
# and the push went through anyway, putting a commit that violated a sanitation invariant on
# GitHub. The gate itself was correct both times. The invocation defeated it.
#
# That is the same defect class this project names most often, one level up: the check was right
# and the thing around the check was wrong. A verdict nothing acts on is decoration.
#
# SO THE ONLY SUPPORTED WAY TO PUBLISH IS THIS SCRIPT. It runs the gate, and it pushes ONLY on a
# zero exit. `&&` in a shell line is the equivalent, and it is exactly the sort of thing somebody
# forgets under time pressure -- which is why the ordering lives in a file that is read rather
# than remembered.
#
# Usage:
#   scripts/push_gated.sh            gate, then push the current branch
#   scripts/push_gated.sh --force-with-lease   gate, then push (history rewrite)
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"

echo "=== gate ==="
if ! sh scripts/gate.sh; then
    echo
    echo "GATE FAILED -- NOT PUSHING. Nothing was published, and nothing needs undoing."
    echo "Fix the failure above and run this again."
    exit 1
fi

echo
echo "=== gate passed, pushing ==="
if [ "${1:-}" = "--force-with-lease" ]; then
    git push --force-with-lease
else
    git push
fi
git fetch -q origin 2>/dev/null || true
echo "  local  $(git rev-parse --short HEAD)"
echo "  origin $(git rev-parse --short origin/"$(git rev-parse --abbrev-ref HEAD)" 2>/dev/null || echo '?')"
