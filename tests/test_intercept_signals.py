"""Signals: what is actually protected, and what is not.

CORRECTION TO AN EARLIER CLAIM IN THIS FILE. It asserted that no signal handler existed. That was
WRONG -- `WeirWatchdog._install_signal_handlers` installs a SIGTERM/SIGINT handler that restores
the ARP mappings, and it is visible in real runs as "signal 2 received -- restoring ARP mappings".
An earlier version of this file also asserted that `wait()` must handle SIGTERM, which would have
meant installing a second handler OVER the working one, replacing a restore path with a flag that
merely stops a loop. That is a downgrade dressed as a fix.

What is true, and what these tests assert:

  * SIGTERM/SIGINT restore, via the watchdog's handler. Already worked.
  * SIGHUP does not, and did not. A dropped SSH session is the commonest way a long-running
    in-cluster process is left behind, so `wait()` handles it -- and does NOT shadow SIGTERM.
  * A SIGKILLed client, or a connection that vanishes without a signal, may deliver NOTHING to the
    in-pod process. No handler can run if no signal arrives. The protections that hold there are
    `--seconds` and the forged ARP entries EXPIRING.
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

# A child that exercises `Intercept.wait()` for real: it installs the handlers and blocks, then
# writes a marker when it unwinds. The marker stands in for the `finally` that restores mappings.
CHILD = textwrap.dedent(
    """
    import sys
    from weirvern.admin.intercept import Intercept

    ic = Intercept.__new__(Intercept)
    ic.__dict__.update({"_started": False, "watchdog": None, "plan": None})

    try:
        ic.wait()
    finally:
        open(sys.argv[1], "w").write("unwound")
    """
)


def _spawn(tmp_path: Path) -> tuple[subprocess.Popen, Path]:
    marker = tmp_path / "unwound"
    child = subprocess.Popen(
        [sys.executable, "-c", CHILD, str(marker)],
        cwd=str(ROOT),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    time.sleep(1.5)  # let it install handlers and enter the loop
    assert child.poll() is None, "the child exited before the signal; it is not under test"
    return child, marker


def _stop(child: subprocess.Popen, sig: int, label: str) -> None:
    child.send_signal(sig)
    try:
        child.wait(timeout=8)
    except subprocess.TimeoutExpired:
        child.kill()
        pytest.fail(
            f"{label} did not stop the intercept, so the process is left orphaned with its "
            f"watchdog armed and the segment poisoned"
        )
    finally:
        if child.poll() is None:
            child.kill()


# ── the gap that was real ─────────────────────────────────────────────────────────────────────

def test_sighup_stops_the_wait_and_unwinds(tmp_path: Path):
    """THE REGRESSION. A dropped SSH session sends SIGHUP, which nothing handled.

    This is the commonest way an in-cluster process is left behind: the terminal or tunnel goes
    away and the remote process carries on. `wait()` now stops on SIGHUP so the caller's `finally`
    runs the restore.
    """
    child, marker = _spawn(tmp_path)
    _stop(child, signal.SIGHUP, "SIGHUP")
    assert marker.exists(), (
        "the process stopped on SIGHUP but never unwound, so the ARP mappings would be left forged"
    )


def test_the_wait_loop_stops_on_a_plain_flag_not_just_keyboardinterrupt():
    """The loop must read a flag, not only catch an exception.

    `KeyboardInterrupt` is raised inside the loop, so catching it works -- but a signal handler
    cannot raise into the loop safely, and a flag is how a handler asks for the same stop. Asserted
    structurally because the behaviour needs a real signal, which the test above provides.
    """
    src = (ROOT / "weirvern" / "admin" / "intercept.py").read_text()
    start = src.index("def wait(self")
    body = src[start:src.index("def __enter__", start)]
    assert "while not stop" in body, (
        "the wait loop no longer reads a stop flag, so a signal handler has no way to end it"
    )
    assert "signal.SIGHUP" in body, "SIGHUP is no longer handled"


# ── the protection that already worked, asserted where it lives ───────────────────────────────

def test_sigterm_restore_is_the_watchdog_job_and_still_present():
    """SIGTERM restore is the WATCHDOG's job, and it already existed.

    An earlier version of this file asserted that `wait()` handled SIGTERM. That was wrong twice
    over: it did not, and adding one there would have shadowed the handler that actually restores
    the mappings -- leaving them forged until the entries expired.
    """
    src = (ROOT / "weirvern" / "admin" / "watchdog.py").read_text()
    assert "signal.SIGTERM" in src, (
        "the watchdog no longer handles SIGTERM. It is what restores the ARP mappings, so losing "
        "it means a SIGTERM leaves every forged entry in place."
    )
    assert "signal.SIGINT" in src, "the watchdog no longer handles SIGINT (Ctrl-C)"
    assert "_install_signal_handlers" in src, "the handler installer was renamed or removed"


def test_the_wait_loop_does_not_shadow_the_watchdog_handler():
    """`wait()` must NOT install a SIGTERM handler -- the inverse of the usual check.

    Installing one would REPLACE the watchdog's restore path with a flag that only breaks a sleep
    loop, so the mappings would stay forged until they expired. Asserted because the earlier
    version of this file demanded exactly that mistake.
    """
    src = (ROOT / "weirvern" / "admin" / "intercept.py").read_text()
    start = src.index("def wait(self")
    body = src[start:src.index("def __enter__", start)]
    assert "signal.SIGTERM" not in body, (
        "wait() installs a SIGTERM handler, shadowing the watchdog's restore path"
    )


# ── the honest limit ──────────────────────────────────────────────────────────────────────────

def test_the_limit_is_documented_next_to_the_handler():
    """The code must SAY what it cannot protect against, or the next reader assumes it is covered.

    A SIGKILLed client may deliver no signal at all, in which case no handler runs. That limit
    belongs beside the handler rather than in a commit message nobody will read.
    """
    src = (ROOT / "weirvern" / "admin" / "intercept.py").read_text()
    start = src.index("def wait(self")
    body = src[start:src.index("def __enter__", start)].lower()
    assert "sigkill" in body or "no signal" in body, (
        "the signal handling no longer documents that a killed client may deliver nothing, so a "
        "reader will assume an orphan is impossible"
    )
    assert "expir" in body or "seconds" in body, (
        "the docstring does not name what actually protects when no signal arrives"
    )
