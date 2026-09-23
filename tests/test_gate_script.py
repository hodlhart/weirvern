"""The gate must be able to FAIL, and its composition must work (audit F106).

THE GATE IS THE ONLY PUSH PATH, so a defect in it is a defect in every assurance this project
relies on. `scripts/gate.sh`'s `run()` set `FAIL=1` and then fell off the end, so the function
returned 0 even when the command it ran failed. The final `exit "$FAIL"` still refused the push --
so the gate was NOT silent, and that distinction matters -- but every `run A || run B` composition
was dead code, which is exactly what the ruff fallback was.

These drive the REAL function out of the REAL script, rather than a copy of it: the failure mode of
a copy is that it cannot fail on a change to the thing it copies (which is what F112 found in the
sanitation guard).
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GATE = ROOT / "scripts" / "gate.sh"


def _run_helper() -> str:
    """Extract the `run()` function's source from the shipping script."""
    src = GATE.read_text()
    m = re.search(r"^run\(\) \{.*?^\}", src, re.S | re.M)
    assert m, "could not find run() in scripts/gate.sh -- this test cannot verify anything"
    return m.group(0)


def _drive(body: str) -> subprocess.CompletedProcess:
    """Execute `body` with the SHIPPING run() definitions loaded, and report what happened."""
    helper = _run_helper()
    script = f"""set -u
FAIL=0
SKIPPED=0
step() {{ printf '\n=== %s ===\n' "$1"; }}
{helper}
{body}
"""
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True, cwd=ROOT)


def test_run_RETURNS_NONZERO_when_its_command_fails():
    """THE DEFECT. A failing command must give run() a failing status."""
    r = _drive('run "failing" false\necho "STATUS=$?"')
    assert "FAIL" in r.stdout, r.stdout
    assert "STATUS=0" not in r.stdout, (
        "run() returned 0 after its command failed, so any `run A || run B` composition is dead "
        "code and the fallback it guards can never fire (audit F106)"
    )
    assert "STATUS=1" in r.stdout, f"run() returned something other than 1: {r.stdout}"


def test_run_RETURNS_ZERO_when_its_command_succeeds():
    """The other direction, so the fix cannot be "always fail"."""
    r = _drive('run "passing" true\necho "STATUS=$?"')
    assert "STATUS=0" in r.stdout, r.stdout


def test_the_FALLBACK_composition_actually_fires():
    """The concrete composition that was dead: the second command must run when the first fails."""
    r = _drive('run "first" false || run "fallback" true')
    assert "fallback" in r.stdout, (
        "the fallback branch did not execute, so a missing pinned binary still cannot fall through "
        "to another one (audit F106)"
    )


def test_a_failure_still_sets_the_FAIL_flag():
    """The status and the flag must agree; either alone is an incomplete signal."""
    r = _drive('run "failing" false\necho "FAIL=$FAIL"')
    assert "FAIL=1" in r.stdout, r.stdout


def test_no_gate_step_still_hardcodes_the_venv_interpreter():
    """`$PY` carries a python3 fallback; a step that bypasses it ignores that resolution.

    The tests step -- the one step that decides whether the suite passes -- used `.venv/bin/pytest`
    directly, so a machine without the author's venv could not run the suite through the gate.
    """
    src = GATE.read_text()
    offenders = [
        ln.strip() for ln in src.splitlines()
        if ".venv/bin/pytest" in ln and not ln.strip().startswith("#")
    ]
    assert not offenders, (
        f"a gate step still invokes the venv interpreter directly instead of $PY: {offenders}"
    )


def test_a_MISSING_linter_is_a_failure_not_a_skip():
    """Reporting lint as clean because no linter exists is the silent-pass shape this gate exists
    to prevent."""
    src = GATE.read_text()
    assert "no ruff available" in src, (
        "the gate no longer refuses when no ruff exists; it would report lint as clean on a machine "
        "that has none"
    )
    assert "command -v ruff" in src, "the gate does not probe PATH for a ruff fallback"
