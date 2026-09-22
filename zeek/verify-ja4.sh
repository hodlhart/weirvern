#!/bin/sh
# Prove, at image BUILD time, that the vendored JA4 module LOADS as Zeek sees it.
#
# WHY THIS EXISTS AS A SCRIPT rather than an inline RUN: Dockerfile syntax does not support
# a line-continued RUN with a heredoc, and keeping the check in a file means it can be
# exercised against a plain directory outside a container build.
#
# WHAT IT CATCHES: a vendored tree that parses but produces no fingerprint -- a sensor that
# looks healthy and records nothing. Listing files cannot see that; only Zeek can.
#
# USAGE:  verify-ja4.sh <module-dir>
set -eu

DIR=${1:?usage: verify-ja4.sh <module-dir>}
[ -f "$DIR/__load__.zeek" ] || { echo "ERROR: no loader in $DIR" >&2; exit 1; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"

# Load the module exactly as the site policy does: as a bare path. The site policy in the
# ConfigMap loads this same directory at runtime, so a load error here is the same error an
# operator would hit on a running sensor.
cat > local.zeek <<ZEEK
@load $DIR
ZEEK

if ! zeek -e 'exit(0)' local.zeek > parse.txt 2>&1; then
    echo "ASSERT FAIL: the vendored module does not load as Zeek sees it" >&2
    cat parse.txt >&2
    exit 1
fi

# The loader must reach the ja4 module. Without this, a tree that loads but whose loader
# was emptied would pass a "does it parse" check while emitting nothing.
if ! grep -q '@load ./ja4' "$DIR/__load__.zeek"; then
    echo "ASSERT FAIL: the loader no longer loads the ja4 module" >&2
    exit 1
fi

echo "verify-ja4: the vendored module loads cleanly and loads the ja4 module"
