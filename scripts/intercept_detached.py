"""Run a long intercept in the pod, detached from any kubectl exec stream.

WHY THIS EXISTS -- THE ROOT CAUSE OF EVERY FAILED HOUR-LONG RUN.

The stress test launched the intercept like this:

    kubectl -n weirvern exec "$W" -c worker -- python -m weirvern.admin.cli intercept ... &
    INTERCEPT_PID=$!

`INTERCEPT_PID` is the LOCAL `kubectl` client, not the remote process. The exec connection is a
stream to the API server, and it does not survive an hour:

    E0919 02:17:04 v2.go:168] "Copying stderr failed" err="next reader: read tcp
    127.0.0.1:55636->127.0.0.1:6443: i/o timeout"

Measured: the stream dies after roughly four minutes of an idle-but-alive remote process. Three
separate runs died at 4m for this reason, and because the harness then checked `kill -0` on the
client pid it reported "intercept exited early" -- which was true of the CLIENT and told us nothing
about the intercept.

That is also the likely explanation for the orphaned intercept found earlier: a stream that times
out leaves the remote process running, and the old teardown then reported the segment clean while a
process with an armed watchdog was still in it.

TWO FIXES, BOTH NEEDED:

  1. LAUNCH DETACHED, inside the pod, with its output in a file there. `nohup ... &` under `setsid`
     so the process is not in the exec session's process group and never receives its hangup.
     Nothing about the run then depends on a client staying connected.

  2. CHECK LIVENESS FROM THE SENSOR'S OWN HEARTBEAT, not from a local pid. The intercept writes
     `sensor_status` every 15s, and that survives the client entirely -- it is the same signal the
     GUI uses. A local pid is the wrong question: it says whether OUR client is alive, which is
     not what an hour-long test needs to know.

USAGE (inside the pod):

    python /tmp/intercept_detached.py --seconds 3600
    python /tmp/intercept_detached.py --status
    python /tmp/intercept_detached.py --stop
"""

from __future__ import annotations

import argparse
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

PID_FILE = Path("/tmp/weir_intercept.pid")
LOG_FILE = Path("/tmp/weir_intercept_detached.log")


def process_state(pid: int) -> str:
    """The single-letter state from /proc/<pid>/stat, or "" if there is no such process.

    WHY NOT `/proc/<pid>` EXISTING. A ZOMBIE keeps its /proc entry: the process has exited, its
    mappings are restored, and the kernel is holding the exit status until someone reaps it. An
    existence check therefore reports a finished process as running. Measured live: pid 754 was
    state `Z` with an empty cmdline, and `--stop` waited 30 seconds for it to die.
    """
    try:
        stat = Path(f"/proc/{pid}/stat").read_text()
    except OSError:
        return ""
    # `comm` is parenthesised and may contain spaces, so the state is the field AFTER the last ')'.
    after = stat.rsplit(")", 1)[-1].split()
    return after[0] if after else ""


def is_running(pid: int) -> bool:
    """Alive and not a zombie."""
    return process_state(pid) not in ("", "Z", "X", "x")


def _argv_for(args: argparse.Namespace) -> list[str]:
    argv = [
        sys.executable, "-m", "weirvern.admin.cli", "intercept",
        "--iface", args.iface,
        "--segment", args.segment,
        "--our-ip", args.our_ip,
        "--gateway", args.gateway,
    ]
    if args.all_hosts:
        argv.append("--all")
    elif args.hosts:
        for host in args.hosts:
            argv += ["--hosts", host]
    argv += ["--seconds", str(args.seconds)]
    return argv


def start(args: argparse.Namespace) -> int:
    if PID_FILE.exists():
        pid = int(PID_FILE.read_text().strip() or 0)
        if pid and is_running(pid):
            print(f"already running as pid {pid}; stop it first", file=sys.stderr)
            return 1
        if pid:
            # A stale or zombie entry is cleared rather than treated as running -- otherwise a
            # finished run blocks the next one forever.
            print(f"clearing a finished entry for pid {pid} (state {process_state(pid)!r})")
    if args.seconds is None:
        # Refused deliberately: a detached intercept with no deadline cannot be waited for, and
        # nothing bounds it if the machine is unattended.
        print("--seconds is required when detaching", file=sys.stderr)
        return 1

    # Kept open for the child's whole life -- the subprocess writes its output here -- so it is
    # intentionally not closed in this function. Closing it would silence the run.
    log = open(LOG_FILE, "ab")  # noqa: SIM115
    # setsid detaches from the controlling terminal AND puts the child in its own session, so a
    # hangup on our side is not delivered to it. Without setsid, `nohup` alone still leaves it in
    # our process group receiving our signals.
    proc = subprocess.Popen(
        _argv_for(args),
        stdout=log,
        stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL,
        start_new_session=True,
    )
    PID_FILE.write_text(str(proc.pid))
    print(f"started pid {proc.pid}; log {LOG_FILE}")
    return 0


def status(args: argparse.Namespace) -> int:
    pid = 0
    state = ""
    if PID_FILE.exists():
        pid = int(PID_FILE.read_text().strip() or 0)
        state = process_state(pid)
    alive = is_running(pid)

    # THE HEARTBEAT IS THE REAL ANSWER, and it is reported ALONGSIDE the pid rather than instead of
    # it: the two disagreeing is itself the interesting case (a pid with no heartbeat means the
    # process is stuck before it started serving; a heartbeat with no pid means it is running but
    # we lost the pid file).
    print(f"PID={pid}", flush=True)
    print(f"PID_STATE={state or 'gone'}", flush=True)
    print(f"PID_ALIVE={int(alive)}", flush=True)

    beat = "unknown"
    mode = ""
    try:
        from weirvern.config import Settings
        from weirvern.db import connect

        client = connect(Settings())
        rows = list(client.query(
            "SELECT mode, ts, running FROM weirvern.sensor_status FINAL ORDER BY ts DESC LIMIT 5"
        ).named_results())
        newest = None
        for row in rows:
            age = time.time() - row["ts"].timestamp()
            if newest is None or age < newest[1]:
                newest = (row, age)
        if newest is not None:
            row, age = newest
            mode = str(row["mode"])
            beat = f"{age:.1f}s ago mode={mode}"
    except Exception as exc:  # noqa: BLE001
        beat = f"unavailable: {type(exc).__name__}"
    print(f"HEARTBEAT={beat}", flush=True)
    print(f"MODE={mode}", flush=True)

    if LOG_FILE.exists():
        tail = LOG_FILE.read_text(errors="replace").splitlines()[-6:]
        print("LOG_TAIL:")
        for line in tail:
            print(f"  {line}", flush=True)
    return 0


def stop(args: argparse.Namespace) -> int:
    if not PID_FILE.exists():
        print("no pid file; nothing recorded to stop")
        return 0
    pid = int(PID_FILE.read_text().strip() or 0)
    if not is_running(pid):
        # Covers a zombie, which is already finished: its restore ran and the kernel is only
        # holding the exit status.
        print(f"pid {pid} is not running (state {process_state(pid) or 'gone'})")
        PID_FILE.unlink(missing_ok=True)
        return 0
    # SIGINT, so the intercept's own restore path runs -- the watchdog's handler catches it and
    # withdraws every forged ARP mapping. SIGTERM would work too; SIGKILL would NOT, and that is
    # why it is never used here.
    os.kill(pid, signal.SIGINT)
    for _ in range(30):
        time.sleep(1)
        if not is_running(pid):
            # Report WHAT state it reached, because `Z` and `gone` mean different things: a zombie
            # means the process exited but the container's PID 1 did not reap it, which is a fact
            # about the container rather than about the intercept.
            print(f"pid {pid} stopped (state {process_state(pid) or 'gone'}) and restored")
            PID_FILE.unlink(missing_ok=True)
            return 0
    print(f"pid {pid} still running after 30s of SIGINT (state {process_state(pid)})",
          file=sys.stderr)
    return 1


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=(__doc__ or "").strip().split("\n\n")[0])
    ap.add_argument("--status", action="store_true")
    ap.add_argument("--stop", action="store_true")
    ap.add_argument("--iface", default=os.environ.get("ZEEK_IFACE") or "eth1")
    ap.add_argument("--segment", default=os.environ.get("INTERCEPT_SEGMENT") or "")
    ap.add_argument("--our-ip", default=os.environ.get("INTERCEPT_ADDR") or "")
    ap.add_argument("--gateway", default=os.environ.get("INTERCEPT_GATEWAY") or "")
    ap.add_argument("--all", action="store_true", dest="all_hosts")
    ap.add_argument("--hosts", action="append")
    ap.add_argument("--seconds", type=int)
    args = ap.parse_args(argv)

    if args.status:
        return status(args)
    if args.stop:
        return stop(args)
    return start(args)


if __name__ == "__main__":
    sys.exit(main())
