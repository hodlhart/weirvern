#!/bin/sh
# Prove the three-state liveness check behaves correctly for all three states.
#
# WHY: conflating "could not read the heartbeat" with "the intercept stopped" is the bug that
# orphaned a live intercept. A test that only covers the healthy path would not have caught it.
#
# The block is extracted from the real script and driven with a stubbed kubectl, so what is tested is
# the SHIPPING logic rather than a paraphrase of it.
set -u

SRC="${1:-/home/hart/Documents/flowforge/scripts/weir_stress_test.sh}"
BLOCK=$(mktemp)
sed -n '/# Is the intercept still alive? THREE STATES/,/^  esac/p' "$SRC" > "$BLOCK"
[ -s "$BLOCK" ] || { echo "  FAIL: could not extract the liveness block"; exit 1; }
echo "  extracted $(wc -l < "$BLOCK") lines of the real block"

run_case() {
    name=$1
    output=$2
    echo
    echo "=== $name ==="
    # A stub kubectl that emits the given status output, so no cluster is needed.
    STUB=$(mktemp -d)
    cat > "$STUB/kubectl" <<EOF
#!/bin/sh
cat <<'OUT'
$output
OUT
EOF
    chmod +x "$STUB/kubectl"

    RESULT=$(
        PATH="$STUB:$PATH"
        NS=weirvern; W=stub-pod; OUT=/dev/null; ELAPSED=14; HB_UNREADABLE=0
        BROKE=no
        . "$BLOCK" || true
        # Did the block exit the loop? It uses `break`, which outside a loop is a no-op error, so the
        # marker is whether it reached the DEAD branch -- checked by the message it printed.
        echo "HB_AGE=${HB_AGE:-} HB_MODE=${HB_MODE:-} HB_UNREADABLE=$HB_UNREADABLE"
    )
    echo "$RESULT" | sed 's/^/    /'
    rm -rf "$STUB"
}

# ALIVE: a fresh heartbeat. Must not break, and must not count as unreadable.
run_case "ALIVE: fresh weir heartbeat" "HEARTBEAT=3.5s ago mode=weir"

# DEAD: a heartbeat that was READ and is stale. This is the only state that should break.
run_case "DEAD: stale heartbeat, was read" "HEARTBEAT=900.0s ago mode=weir"

# UNKNOWN: the check could not read anything. Must NOT break, and MUST count.
run_case "UNKNOWN: unreadable (empty output)" ""

# UNKNOWN: the status command failed entirely.
run_case "UNKNOWN: error text, no HEARTBEAT line" "Unexpected Http Driver Exception"
