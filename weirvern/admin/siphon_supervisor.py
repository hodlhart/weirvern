"""Supervise the in-path intercept when siphon mode is CONFIGURED.

WHY THIS MODULE EXISTS (WEIR-1, fixed in 0.8.0). Setting SENSOR_MODE=siphon used to
configure an INTENT and nothing else: the intercept was operator-triggered --
`weirvern intercept ...` run by hand, or detached inside the pod -- so a deployment
could read "in-path" on every configuration surface while redirecting zero hosts.
`siphon_liveness` (status.py) reports that state loudly, and this module makes it
STOP happening: when siphon mode is configured WITH a complete intercept plan, the
worker starts and supervises the intercept for as long as the pod lives.

DESIGN: a SUPERVISED CHILD PROCESS, not an in-process intercept.
  * signals. The intercept's fail-open watchdog installs SIGTERM/SIGINT handlers
    that restore the forged ARP mappings AND end the process. Installed in the
    worker's main process they would REPLACE the worker's own graceful-shutdown
    handler, and a pod termination while intercepting would tear down the ingest
    and detection loops as a side effect of a restore. As a child process, the
    intercept owns its signals, and the mapping-restore contract is exactly the one
    the CLI already proves in the field.
  * crash isolation. An intercept fault must not stop ingest/detection, and a
    worker restart must not silently drop supervision -- the child either exits
    (bounded) or dies with its container, and the ARP-expiry backstop covers the
    rest, as documented in watchdog.py.
  * one code path. The child IS `weirvern intercept`: the same command an operator
    runs by hand. This module adds supervision, not a second dataplane.

FAIL-OPEN BY CONSTRUCTION. Each child run is BOUNDED (`--seconds`, default one
hour). When the bound is reached the child restores every mapping and exits
cleanly, and the supervisor starts a fresh run. So the steady state is a series of
self-restoring runs -- every seam is a proof that restore works -- and a crash ends
a run the same way (watchdog restore, or ARP expiry as the last resort). A crash
loop backs off exponentially instead of hot-restarting.

READINESS IS RECHECKED, NOT ASSUMED ONCE. The intercept needs the worker's
effective capabilities (NET_RAW + NET_ADMIN, from the siphon overlay) and three
node sysctls (set by the overlay's privileged init container). Both are read from
/proc -- the same sources mode.validate and the watchdog preflight use -- before
every spawn attempt, so a pod that starts a moment before the overlay finishes
self-heals on the next attempt instead of refusing forever.

INCOMPLETE PLAN = NO INTERCEPT, WITH A STATED REASON. Missing segment/address/
gateway, or an empty target list, means nothing is diverted (the safe direction,
same as the CLI), and the reason is written to the log AND surfaced in the health
payload through `notes()`.

WEIRLINGS. One supervisor belongs to one worker pod, which is one sensor node;
sensor identity comes from the pod name (the child publishes its heartbeat under
the same sensor_id the worker uses). Nothing here is global or singleton -- a fleet
of workers is a fleet of independent supervisors, which is the shape the
multi-sensor ("weirlings") direction builds on. Keep it that way: no shared state
outside this pod, no assumptions that this is the only sensor.
"""
from __future__ import annotations

import ipaddress
import logging
import os
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Mapping
from contextlib import suppress
from dataclasses import dataclass
from typing import Protocol

from weirvern.admin import mode as mode_mod

logger = logging.getLogger("weirvern.siphon")

# One hour per child run. The seams are cheap (a few seconds of non-intercepted
# traffic while the child restores and the next one re-poisons) and every seam is a
# working restore -- which is the property the whole design leans on.
DEFAULT_RUN_S = 3600
BASE_RESTART_DELAY_S = 10.0
MAX_RESTART_DELAY_S = 120.0
# Gap between a CLEAN bounded run and the next one. Short: the child already
# restored on its way out, so this seam is just the cost of proving the restore
# path over and over.
CLEAN_REARM_S = 2.0
# After a clean exit with no child running for this long, the worker resumes publishing
# its own heartbeat row (see worker_should_publish). Mirrors status.HEARTBEAT_STALE_S:
# past the staleness horizon the last live row reads as "stopped", so the supervisor's
# explanation must take its place. Kept as its own constant so the coupling is explicit.
PUBLISH_AFTER_QUIET_S = 45.0
# A run shorter than this counts as a failure for backoff purposes: something is
# wrong with the environment, not with the schedule.
MIN_HEALTHY_RUN_S = 60.0
READINESS_RETRY_S = 30.0
STOP_TIMEOUT_S = 15.0
# The most target addresses one INTERCEPT_TARGETS list may name. Matches the segment
# cap in intercept.parse_cidr: every named host becomes the blast radius, so a list
# this size is almost certainly a mistake rather than an intention.
MAX_TARGET_ADDRESSES = 1024


@dataclass
class InterceptConfig:
    """The intercept plan, as the operator set it (Settings / ConfigMap / env)."""

    mode: str = ""
    iface: str = ""
    segment: str = ""
    our_ip: str = ""
    gateway: str = ""
    targets: str = ""

    @property
    def enabled(self) -> bool:
        return self.mode == mode_mod.MODE_SIPHON

    def missing(self) -> list[str]:
        """Required values that are empty, named for an operator rather than a key."""
        out: list[str] = []
        for label, value in (
            ("intercept segment (INTERCEPT_SEGMENT)", self.segment),
            ("intercept address (INTERCEPT_ADDR)", self.our_ip),
            ("intercept gateway (INTERCEPT_GATEWAY)", self.gateway),
        ):
            if not (value or "").strip():
                out.append(label)
        return out

    def target_args(self) -> list[str]:
        """`intercept` CLI arguments for INTERCEPT_TARGETS.

        Contract, matching the ConfigMap help: comma-separated addresses or CIDRs,
        or '*' for every host the segment sweep finds. A CIDR EXPANDS to its host
        addresses (bounded by MAX_TARGET_ADDRESSES), because `intercept --hosts`
        names literal hosts -- passing a CIDR through unconverted would silently
        intercept nothing while reading as configured. Empty -> [] and NOTHING is
        intercepted, deliberately: enabling the mode diverts no traffic by itself.

        Lists that cannot be honoured are refused with a reason by
        `target_problems()`, which `start()` checks before spawning.
        """
        raw = (self.targets or "").strip()
        if not raw:
            return []
        if raw.lower() in ("*", "all"):
            return ["--all"]
        args: list[str] = []
        for item in raw.split(","):
            item = item.strip()
            if not item:
                continue
            net = _network_literal(item)
            if net is None or net.version != 4 or net.num_addresses > MAX_TARGET_ADDRESSES:
                # Not something this list can expand. Passed through unchanged so the
                # CLI names it when nothing answers, and refused up front by
                # target_problems() when it is a network we cannot honour.
                args += ["--hosts", item]
                continue
            for host in (net.hosts() or [net.network_address]):
                args += ["--hosts", str(host)]
        return args

    def target_problems(self) -> list[str]:
        """Targets that cannot be honoured as given. [] when the list is workable.

        Separate from `target_args` so the supervisor can REFUSE, with a reason on
        the heartbeat, instead of spawning a child that would intercept less than
        asked -- the silent-subset shape this project refuses to ship.
        """
        raw = (self.targets or "").strip()
        if not raw or raw.lower() in ("*", "all"):
            return []
        problems: list[str] = []
        for item in raw.split(","):
            item = item.strip()
            if not item:
                continue
            net = _network_literal(item)
            if net is None:
                # Not an address or CIDR at all. The CLI reports it as a host that
                # did not answer, which names the token in the log.
                continue
            if net.version != 4:
                problems.append(
                    f"'{item}' is IPv6; siphon mode is IPv4-only (the ARP frames and "
                    f"the forwarding sysctls are v4), so it can never match"
                )
            elif net.num_addresses > MAX_TARGET_ADDRESSES:
                problems.append(
                    f"'{item}' names {net.num_addresses} addresses; more than "
                    f"{MAX_TARGET_ADDRESSES} targets at once is refused (every named "
                    f"host becomes the blast radius)"
                )
        return problems


def _network_literal(token: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    """The `ip_network` a token names, or None when it is not one.

    A BARE address parses to a /32, which is what lets 'name a few hosts' and
    'name a CIDR' flow through the same expansion path in target_args().
    """
    try:
        return ipaddress.ip_network(token, strict=False)
    except ValueError:
        return None


def config_from_env(env: Mapping[str, str] | None = None) -> InterceptConfig:
    """The plan as this process can see it. Normalised through mode.normalise so
    the former name ('weir') and mechanism words keep working."""
    e = os.environ if env is None else env

    def first(*names: str) -> str:
        for name in names:
            value = (e.get(name) or "").strip()
            if value:
                return value
        return ""

    return InterceptConfig(
        mode=mode_mod.normalise(e.get("SENSOR_MODE") or ""),
        # CAPTURE_IFACE wins when set: the CLI documents it as the explicit override
        # for the interface an intercept runs on.
        iface=first("CAPTURE_IFACE", "ZEEK_IFACE"),
        segment=first("INTERCEPT_SEGMENT"),
        our_ip=first("INTERCEPT_ADDR"),
        gateway=first("INTERCEPT_GATEWAY"),
        targets=e.get("INTERCEPT_TARGETS") or "",
    )


def build_child_argv(cfg: InterceptConfig, *, python_exe: str | None = None,
                     run_seconds: int = DEFAULT_RUN_S) -> list[str]:
    """The exact `weirvern intercept` command the supervisor runs.

    --seconds is REQUIRED for this shape: the child's stdin is not a terminal, and
    the CLI refuses an unbounded run with no Ctrl-C path -- which is the siphon-2
    safety rule, and it stays enforced here rather than bypassed with --max-runtime.
    """
    return [
        python_exe or sys.executable, "-m", "weirvern.admin.cli", "intercept",
        "--iface", cfg.iface,
        "--segment", cfg.segment,
        "--our-ip", cfg.our_ip,
        "--gateway", cfg.gateway,
        *cfg.target_args(),
        "--seconds", str(int(run_seconds)),
    ]


# ── supervision notes, surfaced in the worker's health payload ─────────────────
#
# WHY A MODULE-LEVEL NOTE INSTEAD OF A RETURN VALUE: the heartbeat thread
# (worker._heartbeat_thread -> sensorwatch.observe) is the surface an operator
# actually reads, and it has no reference to this object. One note, owned by the
# supervisor in THIS process, read by the heartbeat in the same process -- no
# cross-process state, no DB table, nothing to leak between sensors.
_notes: list[str] = []
_notes_lock = threading.Lock()


def _set_note(text: str) -> None:
    with _notes_lock:
        _notes[:] = [text] if text else []


def notes() -> list[str]:
    """Current supervision problems, for the heartbeat's `failures` list.

    Empty when the supervisor is idle (passive deployments) or healthy. Never
    raises: a monitoring detail must not be able to break the heartbeat.
    """
    try:
        with _notes_lock:
            return list(_notes)
    except Exception:  # noqa: BLE001
        return []


# ── readiness (capabilities + sysctls), read from /proc each attempt ──────────


def _process_caps() -> tuple[bool, bool]:
    """(has_net_admin, has_net_raw) for THIS process, from CapEff."""
    try:
        with open("/proc/self/status") as fh:
            line = next(ln for ln in fh if ln.startswith("CapEff:"))
        bits = int(line.split()[1], 16)
    except (OSError, StopIteration, ValueError):
        return (False, False)
    # Capability numbers: NET_ADMIN = 12, NET_RAW = 13. Read from /proc rather than
    # inferred from uid: the siphon overlay runs the worker as root WITH a scoped
    # capability set, and root alone does not imply either bit.
    return (bool(bits & (1 << 12)), bool(bits & (1 << 13)))


def readiness_problems() -> list[str]:
    """What would stop an intercept right now, as plain sentences. [] == ready.

    The same two facts `mode.validate` and the watchdog preflight check, read
    directly so the SUPERVISOR can say why it will not spawn a child -- otherwise
    a misconfigured overlay turns into an invisible crash-restart loop.
    """
    problems: list[str] = []
    net_admin, net_raw = _process_caps()
    missing = [n for n, ok in (("CAP_NET_RAW", net_raw), ("CAP_NET_ADMIN", net_admin)) if not ok]
    if missing:
        problems.append(
            "the worker lacks " + " and ".join(missing) +
            " -- apply overlays/siphon/ (`kubectl apply -k overlays/siphon/`), which is "
            "what grants the intercept its capabilities"
        )
    try:
        from weirvern.admin.watchdog import preflight_sysctls

        for name, current, want in preflight_sysctls():
            if current != "?" and current != want:
                problems.append(
                    f"{name}={current} but siphon needs {want} -- the siphon overlay's "
                    f"init container sets this when the sensor starts"
                )
    except Exception as exc:  # noqa: BLE001
        problems.append(f"could not read the node's forwarding sysctls: {exc}")
    return problems


# ── the child handle protocol (Popen satisfies it; tests supply fakes) ────────


class ChildProcess(Protocol):
    pid: int

    def poll(self) -> int | None: ...
    def terminate(self) -> None: ...


def _spawn(argv: list[str]) -> subprocess.Popen:
    """Start one intercept run, detached from a terminal but in this container.

    stdin=DEVNULL because there is no operator here -- which is exactly why the
    command carries --seconds (see build_child_argv). Output is piped and re-logged
    so the run is readable with `kubectl logs deploy/weirvern-worker`; a piped child
    whose output nobody drained would block on a full pipe, so _pump() always runs.
    """
    return subprocess.Popen(  # noqa: S603 - fixed argv, our own interpreter
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        env={**os.environ, "PYTHONUNBUFFERED": "1"},
        start_new_session=True,
    )


class SiphonSupervisor:
    """Runs the intercept as a supervised child while siphon mode is configured.

    start() is cheap and safe on any deployment: in loch mode, or with an
    incomplete plan, it states why it will not run and returns; nothing is spawned.
    stop() is the orderly path that must run before the pod exits -- the worker
    calls it after its main loop -- and it SIGTERMs the child, which is how the
    watchdog's restore-on-signal contract gets exercised on every pod restart.
    """

    def __init__(self, cfg: InterceptConfig, *,
                 run_seconds: int = DEFAULT_RUN_S,
                 spawn: Callable[[list[str]], ChildProcess] | None = None,
                 readiness: Callable[[], list[str]] | None = None,
                 python_exe: str | None = None,
                 poll_s: float = 0.5,
                 base_delay_s: float = BASE_RESTART_DELAY_S,
                 max_delay_s: float = MAX_RESTART_DELAY_S,
                 clean_rearm_s: float = CLEAN_REARM_S,
                 publish_after_quiet_s: float = PUBLISH_AFTER_QUIET_S,
                 stop_timeout_s: float = STOP_TIMEOUT_S) -> None:
        self.cfg = cfg
        self.run_seconds = int(run_seconds)
        self._spawn = spawn or _spawn
        self._readiness = readiness or readiness_problems
        self._python_exe = python_exe
        self._poll_s = poll_s
        self.base_delay_s = base_delay_s
        self.max_delay_s = max_delay_s
        self.clean_rearm_s = clean_rearm_s
        self.publish_after_quiet_s = publish_after_quiet_s
        self.stop_timeout_s = stop_timeout_s

        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._child: ChildProcess | None = None
        self._child_lock = threading.Lock()
        # Counts child runs that ENDED (any exit). Readable for status/tests.
        self.restarts = 0
        self.last_exit_code: int | None = None
        # When the last child run ended; decides when the worker may publish again after
        # a clean exit (see worker_should_publish).
        self._last_run_end: float | None = None

    # -- state -------------------------------------------------------------

    @property
    def intercept_running(self) -> bool:
        """Is a supervised intercept child alive RIGHT NOW?"""
        with self._child_lock:
            child = self._child
        if child is None:
            return False
        try:
            return child.poll() is None
        except Exception:  # noqa: BLE001
            return False

    @property
    def worker_should_publish(self) -> bool:
        """May the WORKER write its own `(sensor_id, 'siphon')` heartbeat row?

        THE TWO-WRITERS PROBLEM this solves: `sensor_status` is keyed
        `(sensor_id, mode)`, and the worker and an intercept child share both -- same
        pod name, same mode. If both write, the row becomes whichever version the merge
        keeps, the liveness check flips between "20 mappings" and "0 mappings", and the
        panel flickers between live and not-live. The reader cannot fix this; the
        writers have to agree on one owner.

        THE RULE, and why each branch:
          * not supervising (loch, or a refused plan) -> the worker IS the story: it
            publishes, carrying the supervisor's refusal note in `failures`.
          * a child is running -> the CHILD owns the row (it has the real numbers).
          * no child, nothing ever ran (readiness retry) -> worker publishes the note.
          * no child after a CRASH -> worker publishes: the backoff is long and the
            crash reason must be visible.
          * no child briefly after a CLEAN exit -> stay silent: the child restored on
            its way out and the next run re-arms within seconds, so the last live row
            (still well inside the staleness window) is the truth. Publishing a
            mappings=0 row here would make a healthy hourly re-arm read as a fault.
            Silent only until the row would go stale anyway, then publish the note --
            after the staleness horizon the supervisor's explanation is all that is
            left to show.
        """
        if self._thread is None or not self._thread.is_alive():
            return True
        if self.intercept_running:
            return False
        if self.restarts == 0:
            return True
        if self.last_exit_code not in (0, None):
            return True
        return (time.time() - (self._last_run_end or 0.0)) > self.publish_after_quiet_s

    def status(self) -> dict:
        """A small snapshot for logs and tests. Never raises."""
        return {
            "configured": self.cfg.enabled,
            "supervising": self._thread is not None and self._thread.is_alive(),
            "intercept_running": self.intercept_running,
            "restarts": self.restarts,
            "last_exit_code": self.last_exit_code,
            "note": (notes() or [""])[0],
        }

    # -- lifecycle -------------------------------------------------------------

    def start(self) -> None:
        """Begin supervision, or explain why there is nothing to supervise."""
        if not self.cfg.enabled:
            logger.debug("siphon supervisor: mode is not siphon; nothing to supervise")
            return
        missing = self.cfg.missing()
        if missing:
            note = (
                "siphon supervisor: the intercept plan is incomplete (missing: "
                + "; ".join(missing)
                + "). Nothing will be intercepted until segment, address and gateway "
                "are all set (Settings, or INTERCEPT_SEGMENT / INTERCEPT_ADDR / "
                "INTERCEPT_GATEWAY in the ConfigMap)."
            )
            logger.error(note)
            _set_note(note)
            return
        problems = self.cfg.target_problems()
        if problems:
            note = ("siphon supervisor: INTERCEPT_TARGETS cannot be used as given -- "
                    + "; ".join(problems))
            logger.error(note)
            _set_note(note)
            return
        if not self.cfg.target_args():
            note = (
                "siphon supervisor: INTERCEPT_TARGETS is empty, so there is nothing to "
                "intercept -- enabling siphon mode diverts no traffic by itself. Name "
                "hosts (comma-separated), or '*' for the whole segment, in Settings."
            )
            logger.warning(note)
            _set_note(note)
            return
        self._thread = threading.Thread(target=self._run, name="siphon-supervisor",
                                        daemon=True)
        self._thread.start()

    def stop(self, timeout_s: float | None = None) -> None:
        """Orderly shutdown: SIGTERM the child (it restores), and wait for it.

        Bounded: restore takes well under a second in measured runs, so the wait
        exists for the pathological case, and a child that outlives it is covered
        by its own self-destruct deadline (--seconds + 120s) plus ARP expiry.
        Idempotent, so the worker can call it unconditionally on every exit path.
        """
        self._stop.set()
        with self._child_lock:
            child = self._child
        if child is not None:
            try:
                child.terminate()
            except Exception:  # noqa: BLE001
                logger.debug("siphon supervisor: could not signal the child", exc_info=True)
            deadline = time.time() + (timeout_s if timeout_s is not None
                                      else self.stop_timeout_s)
            while time.time() < deadline and child.poll() is None:
                time.sleep(0.1)
            if child.poll() is None:
                logger.warning(
                    "siphon supervisor: the intercept did not exit after SIGTERM; its "
                    "own self-destruct deadline will restore the mappings"
                )
        if self._thread is not None and self._thread is not threading.current_thread():
            self._thread.join(timeout=2.0)
        self._thread = None
        _set_note("")

    # -- the loop --------------------------------------------------------------

    def _run(self) -> None:
        argv = build_child_argv(self.cfg, python_exe=self._python_exe,
                                run_seconds=self.run_seconds)
        logger.info("siphon supervisor: in-path intercept will run as: %s", " ".join(argv))
        delay = self.base_delay_s
        last_problems: list[str] = []

        while not self._stop.is_set():
            # READINESS FIRST, EVERY ATTEMPT. A pod that starts a moment before the
            # overlay's init container finishes would otherwise refuse forever; here
            # it simply retries and heals.
            problems = self._readiness()
            if problems:
                if problems != last_problems:
                    logger.error("siphon supervisor: not starting the intercept yet -- %s",
                                 "; ".join(problems))
                    last_problems = list(problems)
                _set_note("siphon supervisor: cannot start the intercept -- "
                          + "; ".join(problems))
                self._stop.wait(READINESS_RETRY_S)
                continue
            last_problems = []

            started = time.time()
            try:
                child = self._spawn(argv)
            except Exception as exc:  # noqa: BLE001
                note = f"siphon supervisor: could not start the intercept: {exc}"
                logger.error(note)
                _set_note(note)
                self._stop.wait(delay)
                continue

            with self._child_lock:
                self._child = child
            _set_note("")  # a run is in flight; any earlier failure note is stale
            pump = getattr(child, "stdout", None)
            if pump is not None:
                threading.Thread(target=self._pump, args=(pump,), daemon=True,
                                 name="siphon-child-log").start()
            logger.info("siphon supervisor: intercept running (pid %s), bounded to %ds",
                        getattr(child, "pid", "?"), self.run_seconds)

            rc: int | None = None
            while not self._stop.is_set():
                rc = child.poll()
                if rc is not None:
                    break
                self._stop.wait(self._poll_s)
            if self._stop.is_set():
                # stop() owns the teardown and signalling; fall through and end.
                break

            ran_for = time.time() - started
            with self._child_lock:
                self._child = None
            self.restarts += 1
            self.last_exit_code = rc
            self._last_run_end = time.time()
            if rc == 0:
                # A bounded run ended: the child restored its mappings on the way out.
                # Re-arm quickly -- the restore/poison seam is the only interruption,
                # and every seam is a working proof of the restore path.
                logger.info("siphon supervisor: bounded run ended (mappings restored "
                            "by the child); re-arming in %ds", int(self.clean_rearm_s))
                delay = self.clean_rearm_s
            else:
                if ran_for >= MIN_HEALTHY_RUN_S:
                    delay = self.base_delay_s
                else:
                    delay = min(self.max_delay_s, max(self.base_delay_s, delay * 2))
                note = (f"siphon supervisor: the intercept exited with code {rc} after "
                        f"{int(ran_for)}s; re-arming in {int(delay)}s")
                logger.error(note)
                _set_note(note)
            self._stop.wait(delay)

        logger.info("siphon supervisor: stopped")

    def _pump(self, stream) -> None:
        """Re-log the child's output so `kubectl logs` shows the whole run.

        Also the drain: a piped child whose pipe fills would block mid-restore.
        """
        try:
            for line in iter(stream.readline, ""):
                text = line.rstrip() if isinstance(line, str) else str(line).rstrip()
                if text:
                    logger.info("siphon: %s", text)
        except Exception:  # noqa: BLE001
            logger.debug("siphon supervisor: log pump ended", exc_info=True)
        finally:
            with suppress(Exception):
                stream.close()
