#!/bin/sh
# Prove, at image BUILD time, that the pruned ja4 package still LOADS.
#
# WHY THIS EXISTS AS A SCRIPT rather than an inline RUN. The first version wrote a local.zeek
# with `cat > file <<'ZEEK'` inside a line-continued Dockerfile RUN, and Dockerfile syntax
# does not support that -- the build failed with "unterminated heredoc". Keeping it in a file
# also means it can be exercised without a container, which is the same reason the prune
# itself lives in prune-ja4plus.sh.
#
# WHAT IT CATCHES: a prune that left a package which parses but produces no fingerprint. The
# assertions in prune-ja4plus.sh check that the licensed code is GONE and that JA4's options
# SURVIVED; this checks the stronger, end-to-end property that Zeek can actually LOAD what
# remains. A sensor whose policy fails to load at startup takes the whole sensor down, and one
# that loads but emits no ja4 is silently useless -- neither is caught by inspecting files.
#
# USAGE:  verify-ja4.sh <package-dir>
set -eu

DIR=${1:?usage: verify-ja4.sh <package-dir>}
[ -f "$DIR/__load__.zeek" ] || { echo "ERROR: no loader in $DIR" >&2; exit 1; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"

# Load the package exactly as the site policy does: as a bare path. The site policy in the
# ConfigMap loads this same directory at runtime, so a load error here is the same error an
# operator would hit on a running sensor.
cat > local.zeek <<ZEEK
@load $DIR
ZEEK

if ! zeek -e 'exit(0)' local.zeek > parse.txt 2>&1; then
    echo "ASSERT FAIL: the pruned package no longer loads as Zeek sees it" >&2
    cat parse.txt >&2
    exit 1
fi

# The loader must still reach the BSD module. Without this, a prune that emptied __load__.zeek
# would pass a "does it parse" check while emitting nothing.
if ! grep -q '@load ./ja4' "$DIR/__load__.zeek"; then
    echo "ASSERT FAIL: the loader no longer loads the ja4 module" >&2
    exit 1
fi

# And it must not mention a FoxIO module. Belt and braces with the prune's own assertions:
# those run before this, and this runs against the file as it will actually be loaded.
for sub in ja4s ja4h ja4ssh ja4x ja4l ja4t ja4d; do
    if grep -q "\./$sub\b" "$DIR/__load__.zeek"; then
        echo "ASSERT FAIL: the loader still references ./$sub" >&2
        exit 1
    fi
done

echo "verify-ja4: the pruned package loads cleanly and still loads the BSD ja4 module"
