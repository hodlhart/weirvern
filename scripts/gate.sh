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
run "shell syntax" sh -n scripts/siphon_stress_test.sh
run "stress-harness liveness (3 states)" sh scripts/verify_liveness.sh
run "policy-rule cleanup (all forms)" sh scripts/verify_rule_cleanup.sh

# The guard proofs: each reintroduces a real defect and requires the suite to go RED. A test
# that cannot fail on its own defect is not a guard, and these two are the ones where a silent
# pass is most costly -- the Zeek feature query returning nothing, and a sentinel counted as a
# real TLS fingerprint.
run "guard proof: zeek summary (4 defects)" .venv/bin/python scripts/prove_zeek_summary_guards.py
run "guard proof: JA4 integrity (5 defects)" .venv/bin/python scripts/prove_ja4_guards.py

# The frontend only, and only the part that can be checked without a browser: `node --check`
# catches a syntax error in a view file, which otherwise shows up as a tab that does nothing.
# The DOM-level check (scripts/jsdom_render.js) needs a server and an npm install, so it is run
# by hand rather than in the gate -- it is documented in the README's development section.
step "frontend syntax (node --check)"
JS_OK=1
for js in weirvern/admin/web/app.js weirvern/admin/web/soc.js weirvern/admin/web/assets.js; do
    if command -v node >/dev/null 2>&1; then
        if ! node --check "$js" 2>/tmp/weirvern_gate_js.txt; then
            echo "  $js: $(head -3 /tmp/weirvern_gate_js.txt | tr '\n' ' ')"
            JS_OK=0
        fi
    else
        echo "  node not installed -- skipping (install node to check the frontend)"
        break
    fi
done
if [ "$JS_OK" = "1" ]; then echo "  PASS"; else echo "  FAIL"; FAIL=1; fi


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
