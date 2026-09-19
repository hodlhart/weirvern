"""An intercept must not survive the death of the client that started it.

THE BUG THIS FILE EXISTS FOR, found on a live segment.

`Intercept.wait()` caught `KeyboardInterrupt` -- Ctrl-C in a terminal, which is NOT how this runs
in a cluster. `kubectl exec` is a CLIENT: when that client is disconnected (the terminal closes,
the SSH session drops, the runner script is killed), the signal goes to the client, and the in-pod
process keeps running.

It happened. An intercept from an earlier run was found still alive inside the pod while the
capture address and policy-routing rules had already been removed by a later cleanup:

    pid 41  python -m weirvern.admin.cli intercept --iface eth1 --segment ... --our-ip ...

The segment looked clean -- no address, no rule, no table -- and yet a process was sitting there
with an intercept active and its watchdog armed. That is the worst possible state for this
component: a sensor that thinks it is relaying, whose next refresh can re-poison every ARP cache
it remembers, on a segment where nothing is in place to restore them. A failed `weir` sensor must
fail OPEN, and an orphan is a failure that never completes.

So SIGTERM and SIGHUP now mean the same thing as Ctrl-C: unwind through the `finally` that
restores every forged mapping.

WHY THIS IS TESTED BY SENDING A REAL SIGNAL.

Asserting that the handler is installed would pass while the restore never ran. The property that
matters is "the process stops AND the restore path executes", so the test starts a real subprocess,
sends a real SIGTERM, and checks the process is gone and the cleanup ran.
"""

from __future__ import annotations

import signal
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent

# A child that installs the same handlers via Intercept.wait() and records whether it unwound.
CHILD = textwrap.dedent(
    '''
    import sys, time, types
    from weirvern.admin.intercept import Intercept

    # `wait()` is called on a real Intercept, which needs a plan. A stub avoids building one while
    # still exercising the handler installation and the loop that reads the flag.
    class Fake:
        stopped = False
        def stop(self):
            Fake.stopped = True

    ic = Intercept.__new__(Intercept)
    ic.__dict__.update({"_started": False, "watchdog": None, "plan": None})

    try:
        ic.wait()
    finally:
        # This stands in for the `finally` that restores the ARP mappings.
        open(sys.argv[1], "w").write("unwound")
    '''
)


def _wait_for_file(path: Path, timeout: float = 8.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        if path.exists():
            return True
        time.sleep(0.1)
    return False


def test_sigterm_stops_the_wait_and_runs_the_restore_path(tmp_path: Path):
    """THE REGRESSION. A real SIGTERM must end the process and reach the cleanup.

    Before the fix this child ignored SIGTERM entirely: `git`-era behaviour, where the process
    blocks forever on `time.sleep(0.5)` and nothing unwinds. The segment stays poisoned and the
    only trace is a stray pid.
    """
    marker = tmp_path / "unwound"
    child = subprocess.Popen(
        [sys.executable, "-c", CHILD, str(marker)],
        cwd=str(ROOT),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    try:
        time.sleep(1.5)  # let it install handlers and enter the loop
        assert child.poll() is None, "the child exited before the signal; test is not exercising it"

        child.send_signal(signal.SIGTERM)
        try:
            child.wait(timeout=8)
        except subprocess.TimeoutExpired:
            child.kill()
            pytest.fail(
                "SIGTERM did not stop the intercept. In a cluster the client is `kubectl exec`, "
                "so a disconnected client leaves this process orphaned with an armed watchdog and "
                "a poisoned segment."
            )
    finally:
        if child.poll() is None:
            child.kill()

    assert marker.exists(), (
        "the process stopped but the restore path never ran -- the ARP mappings would be left "
        "forged on every host the intercept touched"
    )


def test_sighup_is_also_survivable(tmp_path: Path):
    """An SSH session dropping sends SIGHUP, which is the commonest way this is orphaned."""
    marker = tmp_path / "unwound"
    child = subprocess.Popen(
        [sys.executable, "-c", CHILD, str(marker)],
        cwd=str(ROOT),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    try:
        time.sleep(1.5)
        child.send_signal(signal.SIGHUP)
        try:
            child.wait(timeout=8)
        except subprocess.TimeoutExpired:
            child.kill()
            pytest.fail("SIGHUP did not stop the intercept, so a dropped SSH session orphans it")
    finally:
        if child.poll() is None:
            child.kill()
    assert marker.exists(), "SIGHUP stopped the process without unwinding"


def test_the_intercept_module_installs_handlers_rather_than_catching_only_keyboardinterrupt():
    """A structural check, so the fix cannot be quietly reverted to `except KeyboardInterrupt`.

    The behavioural tests above would catch it, but this names the property directly: the code must
    mention the signals it handles.
    """
    src = (ROOT / "weirvern" / "admin" / "intercept.py").read_text()
    assert "signal.SIGTERM" in src, (
        "the intercept no longer handles SIGTERM. In a cluster the client is `kubectl exec`, so "
        "this is the signal a disconnected client produces -- and without a handler the process "
        "is orphaned with an armed watchdog."
    )
    assert "signal.SIGHUP" in src, "SIGHUP (a dropped SSH session) is no longer handled"
    assert "KeyboardInterrupt" in src, "Ctrl-C handling was removed; terminals still matter"
