"""The siphon test run: bounded probe, reverted on every path.

WHAT IS PINNED HERE. The button's promise is "runs siphon for 30 seconds and then reverts
to loch". The interesting failure is not the 30 seconds -- it is the ENDING, because
leaving a sensor in siphon mode puts it in the traffic path with nothing stopping the
intercept. So the tests drive the sequencing with injectable sleep/monotonic/liveness and
assert:

  * a usable plan -> mode flipped to siphon, worker restarted, then ALWAYS a revert write
    back to loch and a second restart (which is what stops the supervised child);
  * an unusable plan -> refused BEFORE anything is written (a test must not start a run it
    knows will intercept nobody);
  * a window that dies mid-run -> the revert still runs and the result still reports it;
  * a revert that fails -> reported as such, loudly, never folded into success;
  * the backstop timer -> exists, and re-reverts if the probe thread never got there.

The probe's contract is deliberately about the ConfigMap + restart (it drives the real
supervision), so the fake client records the exact write/restart sequence.
"""
from __future__ import annotations

import importlib

probe = importlib.import_module("weirvern.admin.siphon_probe")


class _FakeClient:
    """Records the exact apply/restart sequence; read() serves a plan."""

    def __init__(self, configmap, fail_revert=False):
        self.configmap = dict(configmap)
        self.fail_revert = fail_revert
        self.applies: list[dict] = []
        self.restarts: list[str] = []
        self._reverts_seen = 0

    def read(self):
        return dict(self.configmap)

    def apply(self, changes):
        # The revert is the second write of SENSOR_MODE=loch; let a test make it fail.
        if changes.get("SENSOR_MODE") == "loch":
            self._reverts_seen += 1
            if self.fail_revert:
                raise RuntimeError("the cluster refused the revert (403)")
        self.applies.append(dict(changes))
        self.configmap.update(changes)
        return dict(changes)

    def restart(self, target):
        self.restarts.append(target)


PLAN = {
    "SENSOR_MODE": "loch",
    "ZEEK_IFACE": "eth1",
    "INTERCEPT_SEGMENT": "198.51.100.0/24",
    "INTERCEPT_ADDR": "198.51.100.250",
    "INTERCEPT_GATEWAY": "198.51.100.1",
    "INTERCEPT_TARGETS": "*",
}


def _run(client, *, evidence=None, fail_at=None, **kw):
    """Run the probe with a fake clock. `evidence` is what liveness reports."""
    calls = {"n": 0}

    def sleep(_n):
        calls["n"] += 1
        if fail_at is not None and calls["n"] >= fail_at:
            raise RuntimeError("injected failure mid-window")

    def monotonic():
        # One "second" per poll keeps the window short and deterministic.
        return calls["n"] * 1.0

    def liveness():
        return evidence or {"live": False, "error": None}

    kw.setdefault("seconds", 3.0)
    kw.setdefault("poll_s", 1.0)
    kw.setdefault("backstop", False)
    rc = probe.run_probe(client, liveness=liveness, sleep=sleep, monotonic=monotonic, **kw)
    return rc, calls


# ── the happy path, asserted step by step ──────────────────────────────────────────────

def test_the_probe_turns_siphon_on_then_always_back_off():
    client = _FakeClient(PLAN)
    rc, _ = _run(client)
    assert rc["ok"] is True
    assert rc["reverted"] is True
    assert rc["mode_after"] == "loch"
    # The exact sequence: siphon on, worker restart, loch back, worker restart again.
    assert client.applies[0] == {"SENSOR_MODE": "siphon"}
    assert client.applies[-1] == {"SENSOR_MODE": "loch"}
    assert client.restarts == [probe.WORKER, probe.WORKER], (
        "the worker must restart on BOTH ends: the first starts the supervised intercept, "
        "the second stops it through its orderly shutdown (which restores the mappings)"
    )
    # And the cluster really ends in loch -- the promise, asserted on the fake's state.
    assert client.configmap["SENSOR_MODE"] == "loch"


def test_evidence_observed_during_the_window_is_reported():
    client = _FakeClient(PLAN)
    rc, _ = _run(client, evidence={"live": True, "hosts": 4, "mappings": 8, "age_s": 5})
    assert rc["observed"] == {"hosts": 4, "mappings": 8, "age_s": 5}
    assert rc["observed_s"] is not None


def test_no_evidence_is_stated_with_the_next_step_not_hidden():
    client = _FakeClient(PLAN)
    rc, _ = _run(client, evidence={"live": False, "error": None})
    assert rc["ok"] is True and rc["observed"] is None
    assert any("no intercept evidence" in n for n in rc["notes"])
    assert any("siphon overlay" in n for n in rc["notes"])


# ── refusals: before anything is written ───────────────────────────────────────────────

def test_an_incomplete_plan_is_refused_with_nothing_written():
    incomplete = {k: v for k, v in PLAN.items() if k != "INTERCEPT_ADDR"}
    client = _FakeClient(incomplete)
    rc, _ = _run(client)
    assert rc["ok"] is False
    assert "INTERCEPT_ADDR" in rc["error"]
    assert client.applies == [], "a refusal must not write siphon mode first"
    assert client.restarts == []


def test_empty_targets_is_refused_because_the_run_would_intercept_nobody():
    no_targets = dict(PLAN, INTERCEPT_TARGETS="")
    client = _FakeClient(no_targets)
    rc, _ = _run(client)
    assert rc["ok"] is False
    assert "targets" in rc["error"].lower() or "INTERCEPT_TARGETS" in rc["error"]
    assert client.applies == []


def test_target_problems_are_refused_by_the_same_check_the_supervisor_uses():
    bad = dict(PLAN, INTERCEPT_TARGETS="2001:db8::/64")  # IPv6: v4-only dataplane
    client = _FakeClient(bad)
    rc, _ = _run(client)
    assert rc["ok"] is False
    assert "IPv6" in rc["error"]
    assert client.applies == []


def test_an_unreadable_configmap_is_a_stated_refusal():
    class _Unreadable(_FakeClient):
        def read(self):
            return {}

    rc, _ = _run(_Unreadable(PLAN))
    assert rc["ok"] is False
    assert "ConfigMap" in rc["error"]


# ── the failure paths that must still revert ───────────────────────────────────────────

def test_a_window_that_dies_mid_run_still_reverts_and_reports_it():
    client = _FakeClient(PLAN)
    rc, _ = _run(client, fail_at=2)
    assert client.applies[-1] == {"SENSOR_MODE": "loch"}, (
        "an exception during the window must not skip the revert"
    )
    assert rc["reverted"] is True
    assert any("ended early" in n for n in rc["notes"])


def test_a_failed_revert_is_reported_loudly_never_as_success():
    client = _FakeClient(PLAN, fail_revert=True)
    rc, _ = _run(client)
    assert rc["reverted"] is False
    assert "revert FAILED" in rc["mode_after"] or "siphon" in rc["mode_after"]
    assert rc["error"], "the revert failure must carry the cluster's reason"


def test_the_backstop_reverts_when_the_foreground_never_did():
    """The timer exists for a request thread that died mid-run: mode flipped, no revert
    sent. Driven directly, so no 30-second wait is needed."""
    client = _FakeClient(dict(PLAN, SENSOR_MODE="siphon"))
    state = {"reverted": False}
    probe._revert_quietly(client, state)
    assert state["reverted"] is True
    assert client.applies[-1] == {"SENSOR_MODE": "loch"}
    assert client.restarts[-1] == probe.WORKER


def test_the_backstop_does_nothing_when_the_probe_already_reverted():
    client = _FakeClient(PLAN)
    state = {"reverted": True}
    probe._revert_quietly(client, state)
    assert client.applies == [], "the backstop must not write when the revert already ran"


def test_a_prior_siphon_state_is_disclosed_not_hidden():
    already = dict(PLAN, SENSOR_MODE="siphon")
    client = _FakeClient(already)
    rc, _ = _run(client)
    assert rc["mode_before"] == "siphon"
    assert any("ALREADY in siphon" in n for n in rc["notes"])
    # ...and it still ends in loch: the button's contract is absolute.
    assert client.configmap["SENSOR_MODE"] == "loch"


def test_the_backstop_timer_is_armed_and_cancelled():
    """With backstop=True the timer thread must be created and, on success, cancelled -- a
    live timer firing after a clean revert would write loch over a deliberate later apply."""
    import threading

    armed = {}

    class _Timer(threading.Timer):
        def __init__(self, interval, function, args=()):
            super().__init__(interval, function, args)
            armed["created"] = interval
            armed["cancelled"] = False

        def cancel(self):
            armed["cancelled"] = True
            super().cancel()

    real = threading.Timer
    threading.Timer = _Timer  # type: ignore[misc]
    try:
        client = _FakeClient(PLAN)
        rc, _ = _run(client, backstop=True)
    finally:
        threading.Timer = real  # type: ignore[misc]
    assert rc["reverted"] is True
    assert "created" in armed, "no backstop timer was armed"
    assert armed["cancelled"] is True, "the backstop was not cancelled after a clean revert"
    assert armed["created"] >= 30, "the backstop must outlive the probe window"
