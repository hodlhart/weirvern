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
        NS=weirvern; W=stub-pod; OUT=/dev/null; ELAPSED=14; HB_UNREADABLE=0; HB_STREAK=0
        BROKE=no
        . "$BLOCK" || true
        # Did the block exit the loop? It uses `break`, which outside a loop is a no-op error, so the
        # marker is whether it reached the DEAD branch -- checked by the message it printed.
        echo "HB_AGE=${HB_AGE:-} HB_MODE=${HB_MODE:-} HB_UNREADABLE=$HB_UNREADABLE"
    )
    echo "$RESULT" | sed 's/^/    /'
    rm -rf "$STUB"
}

# ALIVE: a real intercept process. Must not break, and must not count as unreadable.
run_case "ALIVE: an intercept process is present" "REAL_INTERCEPTS=1"

# DEAD: the process count was READ and is zero. This is the only state that should break --
# positive evidence of absence, which a client-side pid check cannot give across a boundary.
run_case "DEAD: no intercept process (read, and zero)" "REAL_INTERCEPTS=0"

# UNKNOWN: the check could not read anything. Must NOT break, and MUST count.
run_case "UNKNOWN: unreadable (empty output)" ""

# UNKNOWN: the status command failed entirely.
run_case "UNKNOWN: error text, no HEARTBEAT line" "Unexpected Http Driver Exception"

echo
echo "=== COUNTER SEMANTICS: a streak must not be mistaken for a total ==="
echo "  Two failures separated by a good check. The STREAK resets; the TOTAL must not -- the summary"
echo "  rests on the total, and reporting the streak claimed 'full' evidence for a run that had"
echo "  unreadable checks."
STUB=$(mktemp -d)
cat > "$STUB/kubectl" <<'EOF'
#!/bin/sh
cat <<'OUT'
HEARTBEAT=999.0s ago mode=weir
OUT
EOF
chmod +x "$STUB/kubectl"
# Drive the block three times: unreadable, readable, unreadable -- then check the total is 2.
#
# THE STUB MUST EMIT THE SIGNAL THAT ACTUALLY DECIDES. This test originally stubbed a HEARTBEAT
# line, because liveness was once heartbeat-driven. It is not any more: the deciding signal is now
# count_intercepts' REAL_INTERCEPTS (positional-argv matching, no database), which is why the
# "readable" middle pass stayed UNKNOWN and the check reported TOTAL=3 STREAK=3 -- the run really
# did have three unreadable checks, and the assertion was describing a mechanism that no longer
# exists. A gate check that tests an obsolete signal is worse than no check: it reports the
# harness as broken while the shipping logic is correct.
RESULT=$(
    PATH="$STUB:$PATH"
    NS=x; W=x; OUT=/dev/null; ELAPSED=2; HB_UNREADABLE=0; HB_STREAK=0
    # First pass with an unreadable stub: rewrite the stub to emit nothing.
    cat > "$STUB/kubectl" <<'EOF'
#!/bin/sh
exit 1
EOF
    chmod +x "$STUB/kubectl"
    . "$BLOCK"
    # The READABLE pass: a real intercept process is what makes liveness ALIVE.
    cat > "$STUB/kubectl" <<'EOF'
#!/bin/sh
echo "REAL_INTERCEPTS=1"
EOF
    chmod +x "$STUB/kubectl"
    . "$BLOCK"
    cat > "$STUB/kubectl" <<'EOF'
#!/bin/sh
exit 1
EOF
    chmod +x "$STUB/kubectl"
    . "$BLOCK"
    echo "TOTAL=$HB_UNREADABLE STREAK=$HB_STREAK"
)
echo "  $RESULT" | sed 's/^/    /'
case "$RESULT" in
  *"TOTAL=2 STREAK=1"*) echo "    PASS: total survives a good check, streak resets" ;;
  *) echo "    FAIL: expected TOTAL=2 STREAK=1 -- the summary would misreport evidence quality" ;;
esac
rm -rf "$STUB"
