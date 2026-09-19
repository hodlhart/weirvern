#!/bin/sh
# THE FULL GATE, in one command, so it is cheap enough to actually run before every push.
#
# WHY THIS EXISTS. I pushed a commit whose CI failed, and the failure was a deployment address in
# `scripts/` that the sanitation guard had already flagged LOCALLY. The gate existed and would have
# caught it in two seconds; I pushed without running it and reported CI as green from a stale check.
#
# The lesson is not "the guard was wrong" -- it worked, in CI, exactly as designed. The lesson is
# that a gate which is not a single obvious command does not get run. So this is one command, and it
# prints a single verdict.
#
# ORDER MATTERS: the cheapest checks first, so a failure is found before spending time on the suite.
# Sanitation is first because that is the one that leaked.
set -u
cd "$(dirname "$0")/.." || exit 1

PY=.venv/bin/python
[ -x "$PY" ] || PY=python3
FAIL=0

step() {
    printf '\n=== %s ===\n' "$1"
}

run() {
    label=$1
    shift
    step "$label"
    if "$@"; then
        echo "  PASS"
    else
        echo "  FAIL"
        FAIL=1
    fi
}

# 1. No deployment identifiers anywhere in the tracked tree. This is the check that was skipped.
step "sanitation: no deployment identifiers in any tracked file"
if "$PY" -m weirvern.tools.sanitize_identifiers --check; then
    echo "  PASS"
else
    echo "  FAIL -- the repository describes a real network"
    FAIL=1
fi

# 2. No identifiers in commit messages either: GitHub renders those.
step "sanitation: no deployment identifiers in commit messages"
if "$PY" -m weirvern.tools.sanitize_identifiers --check --history | grep -q "^  clean"; then
    echo "  PASS"
else
    echo "  FAIL -- commit messages are published surface"
    FAIL=1
fi

run "lint (ruff, pinned)" .venv/bin/ruff check weirvern tests scripts 2>/dev/null || \
    run "lint (ruff, pinned)" ruff check weirvern tests
run "types (mypy)" .venv/bin/mypy weirvern --ignore-missing-imports
run "schema audit" "$PY" scripts/audit_schema.py
run "shell syntax" sh -n scripts/weir_stress_test.sh
run "stress-harness liveness (3 states)" sh scripts/verify_liveness.sh

# The suite last: it is the slowest, and everything above is a precondition for trusting it.
step "tests"
if .venv/bin/pytest -q > /tmp/weirvern_gate_tests.txt 2>&1; then
    tail -1 /tmp/weirvern_gate_tests.txt | sed 's/^/  /'
    echo "  PASS"
else
    tail -20 /tmp/weirvern_gate_tests.txt | sed 's/^/  /'
    echo "  FAIL"
    FAIL=1
fi

# The invariants that two real bugs violated: a scrub must not eat part of an address, and must not
# drop one.
step "sanitation invariants (parse + count)"
if sh scripts/verify_sanitize.sh > /tmp/weirvern_gate_sanitize.txt 2>&1; then
    grep -E "OK:|ALL CHECKS" /tmp/weirvern_gate_sanitize.txt | sed 's/^/  /'
    echo "  PASS"
else
    tail -20 /tmp/weirvern_gate_sanitize.txt | sed 's/^/  /'
    echo "  FAIL"
    FAIL=1
fi

echo
if [ "$FAIL" = "0" ]; then
    echo "GATE PASSED -- safe to push"
else
    echo "GATE FAILED -- do not push. CI will fail for the same reason."
fi
exit "$FAIL"
