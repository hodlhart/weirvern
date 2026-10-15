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
SKIPPED=0

step() {
    printf '\n=== %s ===\n' "$1"
}

run() {
    label=$1
    shift
    step "$label"
    if "$@"; then
        echo "  PASS"
        return 0
    else
        echo "  FAIL"
        FAIL=1
        # ── RETURN NON-ZERO, OR `run A || run B` CAN NEVER FIRE B (audit F106) ───────────────────
        #
        # This used to end at `FAIL=1`, so the function's status was 0 even on failure. The final
        # `exit "$FAIL"` still refused the push, so the gate was not silent -- but any caller
        # composing it with `||` was dead code. That was exactly the ruff situation below: the
        # pinned binary is tried first and a fallback to a PATH ruff was written for the case where
        # it is missing, and the fallback could never run because the failure it responds to
        # reported success.
        #
        # MEASURED before the fix: `run "x" false` printed FAIL and returned 0; so did a
        # nonexistent binary. After: both return 1 and the fallback fires.
        return 1
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

# RUFF: TRIED FROM THE PINNED VENV, THEN FROM PATH. The fallback was DEAD CODE until F106 was fixed
# (`run` always returned 0, so `||` never fired), and it was also wrong in a second way: it re-ran the
# SAME `.venv/bin/ruff`-less command shape, so even when it fired it linted only `weirvern tests` and
# silently skipped `scripts/` -- the exact directory whose unlinted state this gate was written to
# catch. Both are fixed: the fallback uses `ruff` from PATH and lints the same three trees.
#
# A missing linter must FAIL rather than skip. `command -v` is the test, so a machine with no ruff at
# all refuses the push instead of reporting lint as clean.
if [ -x .venv/bin/ruff ]; then
    run "lint (ruff, pinned venv)" .venv/bin/ruff check weirvern tests scripts
elif command -v ruff >/dev/null 2>&1; then
    run "lint (ruff, from PATH -- the pinned venv has none)" ruff check weirvern tests scripts
else
    step "lint (ruff)"
    echo "  FAIL -- no ruff available (tried .venv/bin/ruff and PATH)."
    echo "          The pinned version is in pyproject.toml; install it with:"
    echo "              .venv/bin/pip install -e '.[dev]'"
    echo "          Refusing rather than reporting lint as clean."
    FAIL=1
fi
# MYPY: same shape as ruff above -- pinned venv first, PATH second, and a loud refusal when neither
# exists. It was hardcoded to `.venv/bin/mypy` with a `command not found` -> FAIL, which is safe but
# leaves no working path on a machine that has mypy elsewhere (F106's tests-step complaint).
if [ -x .venv/bin/mypy ]; then
    run "types (mypy, pinned venv)" .venv/bin/mypy weirvern --ignore-missing-imports
elif command -v mypy >/dev/null 2>&1; then
    run "types (mypy, from PATH)" mypy weirvern --ignore-missing-imports
else
    step "types (mypy)"
    echo "  FAIL -- no mypy available (tried .venv/bin/mypy and PATH); refusing rather than"
    echo "          reporting types as clean."
    FAIL=1
fi
run "schema audit" "$PY" scripts/audit_schema.py
run "README claims vs the code" "$PY" scripts/audit_readme.py
run "version agreement (code, kustomize, README)" sh scripts/verify_versions.sh
# 3. EVERY shell script, under the interpreter ITS SHEBANG NAMES (review round 2026-10-15):
# this checked ONE file (`sh -n scripts/siphon_stress_test.sh`) while the gate and the suite
# invoke many scripts, and the class that actually shipped -- bash-isms in a script run under
# dash (see the installer-harness fix) -- lives in all of them. `install.sh` names bash and
# uses arrays, so `sh -n` is not ITS check; the rule is the interpreter the file itself
# declares, and a failure names the file.
step "shell syntax (every script, its own shebang)"
SH_SYNTAX_OK=1
for f in scripts/*.sh install.sh; do
    [ -e "$f" ] || continue
    case "$(head -1 "$f")" in
        *bash*) CHECKER=bash ;;
        *) CHECKER=sh ;;
    esac
    if ! command -v "$CHECKER" >/dev/null 2>&1; then
        echo "  SKIP  $f: $CHECKER is not installed, so this file was NOT syntax-checked."
        SKIPPED=$((SKIPPED + 1))
        continue
    fi
    if ! "$CHECKER" -n "$f" 2>/tmp/weirvern_gate_sh.txt; then
        echo "  $f: $(head -3 /tmp/weirvern_gate_sh.txt | tr '\n' ' ')"
        SH_SYNTAX_OK=0
    fi
done
if [ "$SH_SYNTAX_OK" = "1" ]; then
    echo "  PASS"
else
    echo "  FAIL"
    FAIL=1
fi
run "installer interface logic (simulated machines)" sh scripts/verify_installer.sh
run "stress-harness liveness (3 states)" sh scripts/verify_liveness.sh
run "policy-rule cleanup (all forms)" sh scripts/verify_rule_cleanup.sh

# The guard proofs: each reintroduces a real defect and requires the suite to go RED. A test
# that cannot fail on its own defect is not a guard, and these two are the ones where a silent
# pass is most costly -- the Zeek feature query returning nothing, and a sentinel counted as a
# real TLS fingerprint.
run "guard proof: zeek summary (4 defects)" .venv/bin/python scripts/prove_zeek_summary_guards.py
run "guard proof: JA4 integrity (5 defects)" .venv/bin/python scripts/prove_ja4_guards.py

# The frontend, and only the part that can be checked without a browser: `node --check`
# catches a syntax error in a view file, which otherwise shows up as a tab that does nothing.
# The DOM-level check (scripts/jsdom_render.js) is executed by CI now (node + `npm ci`; it
# stubs fetch and reads the files from disk, so it needs no server); the gate keeps the fast
# parse check so every push stays cheap and a missing node is a loud SKIP, never a pass.
step "frontend syntax (node --check)"
# THREE STATES, NOT TWO. A check that cannot run is NOT a check that passed.
#
# The old version initialised JS_OK=1, printed "node not installed -- skipping", and then fell
# through to `if [ "$JS_OK" = "1" ]; then echo PASS`. So on a machine without node -- a CI runner
# that did not install it, a fresh clone -- the gate reported PASS for a syntax check it never
# performed. That is this project's named failure mode ("a green reading over work that did not
# happen") in the one place it is most costly, because the gate is what decides whether code ships.
#
# SKIP now reads as SKIP, and a skip is reported in the summary line so it cannot be overlooked.
JS_STATE=PASS
for js in weirvern/admin/web/app.js weirvern/admin/web/soc.js weirvern/admin/web/assets.js \
          weirvern/admin/web/sluice.js weirvern/admin/web/weirlings.js scripts/jsdom_render.js; do
    if ! command -v node >/dev/null 2>&1; then
        JS_STATE=SKIP
        echo "  SKIP  node is not installed, so the frontend was NOT syntax-checked."
        echo "        Install node to have this check performed."
        break
    fi
    if ! node --check "$js" 2>/tmp/weirvern_gate_js.txt; then
        echo "  $js: $(head -3 /tmp/weirvern_gate_js.txt | tr '\n' ' ')"
        JS_STATE=FAIL
    fi
done
case "$JS_STATE" in
    PASS) echo "  PASS" ;;
    FAIL) echo "  FAIL"; FAIL=1 ;;
    SKIP) echo "  SKIP -- not a pass: this check did not run"; SKIPPED=$((SKIPPED + 1)) ;;
esac


# The suite last: it is the slowest, and everything above is a precondition for trusting it.
step "tests"
# `$PY -m pytest` rather than `.venv/bin/pytest`: the interpreter was already resolved above (with a
# python3 fallback), and hardcoding the venv path here meant the ONE step that decides whether the
# suite passes ignored that resolution (audit F106).
if "$PY" -m pytest -q > /tmp/weirvern_gate_tests.txt 2>&1; then
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
if [ "$FAIL" = "0" ] && [ "$SKIPPED" = "0" ]; then
    echo "GATE PASSED -- safe to push (every check ran)"
elif [ "$FAIL" = "0" ]; then
    echo "GATE PASSED WITH $SKIPPED SKIPPED CHECK(S) -- the skipped ones did not run."
    echo "  Install the missing tools (node, kustomize, tcpdump) for a complete verdict."
else
    echo "GATE FAILED -- do not push. CI will fail for the same reason."
fi
exit "$FAIL"
