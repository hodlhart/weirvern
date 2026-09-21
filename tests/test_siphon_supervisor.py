"""The siphon supervisor: WEIR-1 closed, and the properties that keep it safe.

THE GAP THIS FILE PINS SHUT. SENSOR_MODE=siphon used to configure an INTENT and
nothing else: the intercept was operator-triggered, so a deployment could read
"in-path" on every config surface while redirecting zero hosts. 0.8.0 gives the
worker a supervisor (weirvern/admin/siphon_supervisor.py) that runs the intercept
as a supervised child whenever the mode is configured WITH a complete plan.

WHAT THESE TESTS ARE ABOUT, in order of what would hurt most if it broke:
  * nothing is spawned in loch mode, or with an incomplete plan (the safe direction)
  * the child command is EXACTLY `weirvern intercept` with --seconds (the CLI's own
    non-TTY safety rule is not bypassed by using a different invocation shape)
  * one owner per heartbeat row: the worker must not fight the child for
    (sensor_id, 'siphon') -- two writers would make the liveness check flap
  * crashes back off and are REPORTED (a note on the heartbeat), never silent
  * a clean bounded run re-arms quickly, because its restore was just proven
  * stop() signals the child, which is how the restore-on-signal path runs on
    every pod restart

No process is spawned for real: `spawn` and `readiness` are injected, which is what
lets the loop be driven deterministically here.
"""
from __future__ import annotations

import time

from weirvern.admin import siphon_supervisor as sup


class FakeChild:
    """A stand-in for subprocess.Popen with scriptable death."""

    def __init__(self, argv, exit_after_polls: int | None = None, exit_code: int = 0):
        self.argv = argv
        self.pid = 4242
        self.terminated = False
        self._exit_after = exit_after_polls
        self._exit_code = exit_code
        self._polls = 0
        self.stdout = None

    def poll(self):
        self._polls += 1
        if self.terminated:
            return 0
        if self._exit_after is not None and self._polls >= self._exit_after:
            return self._exit_code
        return None

    def terminate(self):
        self.terminated = True


def _cfg(**over):
    base = {
        "mode": "siphon",
        "iface": "eth1",
        "segment": "198.51.100.0/24",
        "our_ip": "198.51.100.250",
        "gateway": "198.51.100.1",
        "targets": "198.51.100.10,198.51.100.11",
    }
    base.update(over)
    return sup.InterceptConfig(**base)


def _ready():
    return []


# ── config_from_env ─────────────────────────────────────────────────────────────


def test_config_normalises_the_former_mode_name():
    """'weir' was the name before 0.7.0; the supervisor must accept it like every
    other surface does (mode.normalise), or a pre-rename ConfigMap loses siphon."""
    cfg = sup.config_from_env({"SENSOR_MODE": "weir", "ZEEK_IFACE": "eth1"})
    assert cfg.mode == "siphon"
    assert cfg.enabled is True


def test_config_prefers_capture_iface_over_zeek_iface():
    """The CLI documents CAPTURE_IFACE as the explicit override for the interface an
    intercept runs on; the supervisor must use the same precedence."""
    cfg = sup.config_from_env({"SENSOR_MODE": "siphon", "CAPTURE_IFACE": "eth9",
                               "ZEEK_IFACE": "eth1"})
    assert cfg.iface == "eth9"


def test_targets_wildcard_and_lists_and_empty():
    assert _cfg(targets="*").target_args() == ["--all"]
    assert _cfg(targets="all").target_args() == ["--all"]
    assert _cfg(targets="198.51.100.10, 198.51.100.11").target_args() == [
        "--hosts", "198.51.100.10", "--hosts", "198.51.100.11"]
    # EMPTY MEANS NOTHING IS INTERCEPTED, deliberately -- enabling the mode diverts
    # no traffic by itself.
    assert _cfg(targets="").target_args() == []


def test_a_cidr_target_expands_to_the_host_addresses_it_names():
    """`intercept --hosts` names literal hosts, so a CIDR must be expanded before it
    is passed -- a CIDR forwarded unconverted would match nothing while reading as
    configured, which is the silent-empty shape this project keeps refusing."""
    assert _cfg(targets="198.51.100.4/30").target_args() == [
        "--hosts", "198.51.100.5", "--hosts", "198.51.100.6"]
    # a bare address goes through the same path as a /32
    assert _cfg(targets="198.51.100.10").target_args() == ["--hosts", "198.51.100.10"]
    # and a mixed list keeps both forms
    assert _cfg(targets="198.51.100.10,192.0.2.0/30").target_args() == [
        "--hosts", "198.51.100.10", "--hosts", "192.0.2.1", "--hosts", "192.0.2.2"]


def test_an_oversized_or_ipv6_cidr_is_refused_not_truncated():
    """Refused, with the reason reachable: silently intercepting a subset of what was
    asked would look like success while testing less than the operator thinks."""
    big = _cfg(targets="10.0.0.0/8")
    assert big.target_problems() and "10.0.0.0/8" in big.target_problems()[0]
    six = _cfg(targets="2001:db8::/64")
    assert six.target_problems() and "IPv6" in six.target_problems()[0]
    assert _cfg(targets="198.51.100.4/30").target_problems() == []


def test_an_unworkable_target_list_spawns_nothing_and_says_why():
    spawned = []
    s = sup.SiphonSupervisor(_cfg(targets="10.0.0.0/8"),
                             spawn=lambda a: spawned.append(a) or FakeChild(a),
                             readiness=_ready)
    s.start()
    note = sup.notes()
    s.stop()
    assert spawned == []
    assert note and "INTERCEPT_TARGETS" in note[0] and "10.0.0.0/8" in note[0]


def test_missing_names_what_an_operator_must_set():
    missing = _cfg(segment="", our_ip="", gateway="").missing()
    assert len(missing) == 3
    assert any("INTERCEPT_SEGMENT" in m for m in missing)
    assert any("INTERCEPT_ADDR" in m for m in missing)
    assert any("INTERCEPT_GATEWAY" in m for m in missing)
    assert _cfg().missing() == []


# ── the child command ───────────────────────────────────────────────────────────


def test_the_child_is_the_same_command_an_operator_runs_by_hand():
    """ONE code path: supervision must not fork the dataplane into a second shape."""
    argv = sup.build_child_argv(_cfg(), python_exe="/py", run_seconds=60)
    assert argv[:4] == ["/py", "-m", "weirvern.admin.cli", "intercept"]
    for flag, value in (("--iface", "eth1"), ("--segment", "198.51.100.0/24"),
                        ("--our-ip", "198.51.100.250"), ("--gateway", "198.51.100.1")):
        i = argv.index(flag)
        assert argv[i + 1] == value


def test_the_child_is_ALWAYS_bounded():
    """The CLI refuses an unbounded run when stdin is not a terminal -- and the child's
    stdin is DEVNULL. --seconds is what makes each run self-restoring, so its presence
    is a safety property, not a scheduling preference."""
    argv = sup.build_child_argv(_cfg())
    assert "--seconds" in argv
    assert argv[argv.index("--seconds") + 1] == str(sup.DEFAULT_RUN_S)
    # And the CLI's own refusal would catch it if this regressed; assert the shape.
    assert "--max-runtime" not in argv, (
        "the supervisor bypasses the CLI's non-TTY rule via --max-runtime instead of "
        "--seconds; the run would then have no orderly bound"
    )


# ── nothing is spawned when it should not be ────────────────────────────────────


def test_loch_mode_spawns_nothing():
    spawned = []
    s = sup.SiphonSupervisor(_cfg(mode="loch"), spawn=lambda a: spawned.append(a) or FakeChild(a),
                             readiness=_ready)
    s.start()
    s.stop()
    assert spawned == []
    assert s.status()["supervising"] is False


def test_an_incomplete_plan_spawns_nothing_and_says_why():
    """Missing segment/address/gateway -> nothing diverted (the safe direction), with
    the reason ON THE HEARTBEAT so the operator is not left reading a healthy panel."""
    spawned = []
    s = sup.SiphonSupervisor(_cfg(segment=""), spawn=lambda a: spawned.append(a) or FakeChild(a),
                             readiness=_ready)
    s.start()
    note = sup.notes()
    s.stop()
    assert spawned == []
    assert note and "incomplete" in note[0]
    assert "INTERCEPT_SEGMENT" in note[0]


def test_empty_targets_spawn_nothing_and_say_why():
    spawned = []
    s = sup.SiphonSupervisor(_cfg(targets=""), spawn=lambda a: spawned.append(a) or FakeChild(a),
                             readiness=_ready)
    s.start()
    note = sup.notes()
    s.stop()
    assert spawned == []
    assert note and "INTERCEPT_TARGETS" in note[0]


def test_readiness_failure_is_reported_and_retried_not_a_spawn():
    """The pod can start a moment before the overlay's init container finishes. The
    supervisor must retry readiness rather than refuse forever -- and must say so
    while it waits."""
    spawned = []
    # The message shape readiness_problems() actually produces (asserted below).
    said = ["the worker lacks CAP_NET_ADMIN -- apply overlays/siphon/ "
            "(`kubectl apply -k overlays/siphon/`), which is what grants the intercept "
            "its capabilities"]
    s = sup.SiphonSupervisor(_cfg(), spawn=lambda a: spawned.append(a) or FakeChild(a),
                             readiness=lambda: list(said),
                             poll_s=0.01)
    s.start()
    time.sleep(0.1)
    note = sup.notes()
    s.stop()
    assert spawned == [], "a child was spawned without the intercept's capabilities"
    assert note and "CAP_NET_ADMIN" in note[0]
    assert "overlays/siphon" in note[0], (
        "the note does not tell the operator what to DO about the missing capability"
    )


def test_the_real_readiness_message_names_the_remedy():
    """The text an operator actually gets must name the fix, not just the symptom."""
    # Drive the real function through a monkeypatched capability read so the message
    # construction is what is tested -- no /proc dependence.
    from unittest import mock

    with mock.patch.object(sup, "_process_caps", return_value=(False, False)):
        problems = sup.readiness_problems()
    text = "; ".join(problems)
    assert "CAP_NET_RAW" in text and "CAP_NET_ADMIN" in text
    assert "overlays/siphon" in text, (
        "the readiness message does not name the overlay that grants the capabilities"
    )


# ── the loop, with a live child ─────────────────────────────────────────────────


def _running_supervisor(children, **over):
    """Start a supervisor whose spawn returns scripted children, and wait for the
    first spawn. Returns (supervisor, spawned)."""
    spawned: list[FakeChild] = []

    def spawn(argv):
        child = FakeChild(argv, **over)
        spawned.append(child)
        children.append(child)
        return child

    s = sup.SiphonSupervisor(_cfg(), spawn=spawn, readiness=_ready, poll_s=0.01,
                             base_delay_s=0.01, max_delay_s=0.02,
                             clean_rearm_s=0.01, publish_after_quiet_s=0.05)
    s.start()
    deadline = time.time() + 2.0
    while not spawned and time.time() < deadline:
        time.sleep(0.005)
    assert spawned, "the supervisor never spawned the intercept"
    return s, spawned


def test_a_live_child_owns_the_heartbeat_row():
    s, spawned = _running_supervisor([])
    try:
        assert s.intercept_running is True
        assert s.worker_should_publish is False, (
            "the worker would write its own mappings=0 siphon row while the child is "
            "live; two writers on one key make the liveness check flap"
        )
    finally:
        s.stop()


def test_a_clean_bounded_run_re_arms_and_the_worker_stays_quiet_briefly():
    """A bounded run ending with code 0 is the DESIGNED seam: the child restored on
    its way out. Re-arm fast; the worker must not publish a mappings=0 row during
    the seam (that would make a healthy hourly re-arm read as a fault), but must
    take over once the seam would go stale."""
    children: list[FakeChild] = []
    s, spawned = _running_supervisor(children, exit_after_polls=3, exit_code=0)
    deadline = time.time() + 2.0
    while len(spawned) < 2 and time.time() < deadline:
        time.sleep(0.005)
    try:
        assert len(spawned) >= 2, "a clean exit did not re-arm"
        assert s.restarts >= 1
        assert s.last_exit_code == 0
        # The seam: worker_should_publish is False until publish_after_quiet_s passes
        # (0.05s in this test). Right AFTER an exit it must be False -- publishing
        # would show a healthy re-arm as a fault.
        s._last_run_end = time.time()
        assert s.worker_should_publish is False, (
            "the worker publishes during a clean seam, which would show a healthy "
            "re-arm as a fault"
        )
        # ...and after the quiet window it takes over, so a supervisor that died
        # silently still gets its last word shown.
        s._last_run_end = time.time() - 10.0
        assert s.worker_should_publish is True, (
            "after a clean exit the worker never publishes again, so a supervisor "
            "that stopped for good leaves a stale 'live' row instead of the story"
        )
    finally:
        s.stop()


def test_a_crash_is_reported_on_the_heartbeat():
    """A crash note must be visible in the window BETWEEN the crash and the re-arm.
    (Once a new child spawns the note is cleared -- a run is in flight, so the old
    failure is stale; the worker publishes during the backoff window, which is when
    the note must exist.)"""
    children: list[FakeChild] = []
    spawned: list[FakeChild] = []

    def spawn(argv):
        child = FakeChild(argv, exit_after_polls=2, exit_code=7)
        spawned.append(child)
        children.append(child)
        return child

    s = sup.SiphonSupervisor(_cfg(), spawn=spawn, readiness=_ready, poll_s=0.01,
                             # A LONG backoff makes the crash window wide enough to
                             # observe deterministically; real backoff starts at 10s.
                             base_delay_s=30.0, max_delay_s=30.0)
    s.start()
    # Wait for the NOTE, not just for the restart counter: the counter is bumped a few
    # statements before the note is written, so polling the counter alone is racy.
    deadline = time.time() + 2.0
    note: list[str] = []
    while time.time() < deadline:
        note = sup.notes()
        if note:
            break
        time.sleep(0.005)
    try:
        assert s.last_exit_code == 7
        assert note and "code 7" in note[0], (
            "a crashing intercept is not reported anywhere an operator can see"
        )
        assert s.worker_should_publish is True, (
            "after a crash the worker must publish, or the crash is invisible"
        )
    finally:
        s.stop()


def test_stop_signals_the_child_so_the_restore_path_runs():
    """stop() must SIGTERM the child: that is the handler the watchdog uses to restore
    every forged mapping, so this is the ordinary pod-restart path to a clean segment."""
    s, spawned = _running_supervisor([])
    child = spawned[0]
    s.stop()
    assert child.terminated, (
        "the supervisor exited without signalling the child, so a pod restart would "
        "leave the restore to ARP expiry instead of the watchdog"
    )
    assert s.intercept_running is False


def test_notes_are_cleared_on_stop():
    """A stale refusal note must not keep riding the heartbeat after shutdown."""
    s = sup.SiphonSupervisor(_cfg(segment=""), spawn=lambda a: FakeChild(a), readiness=_ready)
    s.start()
    assert sup.notes()
    s.stop()
    assert sup.notes() == []


def test_status_is_readable_without_raising():
    s = sup.SiphonSupervisor(_cfg(mode="loch"), spawn=lambda a: FakeChild(a), readiness=_ready)
    s.start()
    st = s.status()
    s.stop()
    for key in ("configured", "supervising", "intercept_running", "restarts",
                "last_exit_code", "note"):
        assert key in st
