"""Run the siphon intercept for a bounded TEST, then put the mode back.

WHAT THIS IS FOR. Switching a sensor to siphon mode is the one action in this project
that changes the failure mode of the network: the box becomes a router for every host it
intercepts. The Settings tab can survey the segment (Sonar) and apply a plan, but until
this module existed there was no way to SEE the intercept run without committing to it --
an operator had to apply siphon, watch, and remember to switch back.

So: a probe, not a mode change. It runs the REAL intercept through the REAL supervision
path for `seconds` (default 30), then writes the mode back to loch and lets the worker
stop the child through its own orderly shutdown -- the same restore path every production
run uses. The word "test" is not a euphemism for a stub: the ARP mappings are real and
the traffic really relays while it runs. What it protects is the ENDING: the revert runs
in a `finally`, and a timer backstop re-reverts if this process dies mid-probe.

WHY IT DRIVES THE CONFIGMAP RATHER THAN SPAWNING ITS OWN INTERCEPT. `weirvern intercept`
executed from the GUI pod would run in the WRONG NETWORK NAMESPACE with none of the
capabilities (the same reason the Sonar survey is a Job), and it would bypass the
supervisor -- the one component whose restart/restore contract makes siphon mode
defensible. The worker already supervises: flipping the mode and restarting the worker
means the probe exercises exactly what a real deployment does.

WHAT "REVERTED" MEANS, precisely: the ConfigMap's SENSOR_MODE is back to `loch` and the
worker has been restarted, so its shutdown SIGTERMs the intercept child, whose watchdog
restores every forged ARP mapping. The result reports both halves (`reverted`, and the
observed live evidence) rather than one summary boolean, because "the config says loch"
and "an intercept was actually seen" are different facts -- and collapsing them is the
failure class this project keeps naming.

THE REVERT TARGET IS ALWAYS `loch`, deliberately, even when the sensor was already in
siphon before the test. That is the button's stated contract ("runs siphon for 30 seconds
and then reverts to loch"), and a test that silently left the box in the traffic path
would be the worst possible reading of "test". `mode_before` is reported so nothing about
the prior state is hidden.
"""
from __future__ import annotations

import logging
import threading
import time
from typing import Any

from weirvern.admin.siphon_supervisor import config_from_env

logger = logging.getLogger(__name__)

DEFAULT_PROBE_S = 30.0
DEFAULT_POLL_S = 2.0
# Grace on the backstop reverter: the probe's own window plus room for one slow API call.
BACKSTOP_GRACE_S = 120.0
# The workload whose restart starts (and later stops) the supervised intercept.
WORKER = "deploy/weirvern-worker"
MODE_KEY = "SENSOR_MODE"


def run_probe(client, *, seconds: float | None = None, poll_s: float | None = None,
              liveness=None, sleep=time.sleep, monotonic=time.monotonic,
              backstop: bool = True) -> dict:
    """Run the intercept for `seconds`, then revert the mode to loch. Never leaves it on.

    `client` is a ClusterConfig-shaped object (read/apply/restart). `liveness` is a
    callable returning a status.siphon_liveness-shaped dict (or None when the caller
    cannot reach the database -- the probe still runs, and the result says evidence was
    unavailable rather than inventing some). `sleep`/`monotonic`/`backstop` are injectable
    so the sequencing is testable without a 30-second wall-clock or a real cluster.

    Returns a dict. A refusal (no usable plan) returns {"ok": False, "error": ...} and
    touches nothing; a run returns {"ok": True, ..., "reverted": bool, "observed": ...}.
    """
    seconds = DEFAULT_PROBE_S if seconds is None else float(seconds)
    poll_s = DEFAULT_POLL_S if poll_s is None else float(poll_s)

    current = client.read()
    if not current:
        return {"ok": False,
                "error": ("could not read the weirvern-env ConfigMap, so there is no plan to "
                          "test. Check the GUI's cluster access (and its ServiceAccount).")}

    plan = config_from_env(current)
    mode_before = str(current.get(MODE_KEY) or "").strip()

    # THE SAME PREFLIGHT THE SUPERVISOR USES. A test that ran with half a plan would
    # intercept nobody while looking like it worked -- the silent-subset shape this
    # project refuses to ship. Refusing here names exactly what is missing, and the fix
    # is the operator's own next click (fill it in, Apply, test again).
    missing = plan.missing()
    if not (plan.targets or "").strip():
        missing.append("intercept targets (INTERCEPT_TARGETS)")
    missing += plan.target_problems()
    if missing:
        return {"ok": False,
                "error": ("the intercept plan in the cluster is not usable yet, so there is "
                          "nothing to test: " + "; ".join(missing)
                          + ". Fill it in on this page and press Apply first.")}

    notes: list[str] = []
    if mode_before == "siphon":
        notes.append("the sensor was ALREADY in siphon mode before this test; the probe still "
                     "runs its window and then reverts the mode to loch.")

    state = {"reverted": False}
    timer: threading.Timer | None = None
    if backstop:
        timer = threading.Timer(seconds + BACKSTOP_GRACE_S, _revert_quietly,
                                args=(client, state))
        timer.daemon = True
        timer.start()

    started = monotonic()
    evidence: dict[str, Any] | None = None
    observed_s: float | None = None
    revert_error = ""
    try:
        # MERGE-PATCH + READ-BACK. `apply` verifies the write landed, so a patch that
        # matched nothing raises here rather than at the point where 30 seconds later the
        # result would claim a run that never happened.
        client.apply({MODE_KEY: "siphon"})
        client.restart(WORKER)
        while monotonic() - started < seconds:
            if liveness is not None:
                try:
                    st = liveness() or {}
                except Exception as exc:  # noqa: BLE001 - evidence is best-effort
                    st = {"live": False, "error": str(exc)}
                if st.get("live"):
                    evidence = {"hosts": int(st.get("hosts") or 0),
                                "mappings": int(st.get("mappings") or 0),
                                "age_s": st.get("age_s")}
                    observed_s = monotonic() - started
                elif st.get("error") and not any("could not confirm" in n for n in notes):
                    # ONE note for the window, not one per poll.
                    notes.append(f"could not confirm the intercept while it ran: {st['error']}")
            sleep(poll_s)
    except Exception as exc:  # noqa: BLE001
        # THE WINDOW CAN END EARLY; THE REPORT MUST NOT. An exception here (an API blip
        # during the interval, an injected failure in tests) is recorded as a note rather
        # than thrown, because the finally clause below still has to run the revert and
        # the caller still needs the revert's outcome -- discarding it would leave the
        # operator with a 500 and no statement about whether the mode went back.
        notes.append(f"the test window ended early: {exc}")
    finally:
        # THE REVERT IS THE FEATURE. Every path out of the loop above -- normal end, an
        # exception, even a caller cancellation surfacing as an error -- arrives here, and
        # leaving siphon mode configured is the one outcome the button promises never
        # happens.
        try:
            client.apply({MODE_KEY: "loch"})
            client.restart(WORKER)
        except Exception as exc:  # noqa: BLE001
            revert_error = str(exc)
            logger.error("siphon probe: REVERT FAILED, mode may still be siphon: %s", exc)
        else:
            state["reverted"] = True
            if timer is not None:
                timer.cancel()

    result: dict[str, Any] = {
        "ok": True,
        "seconds": seconds,
        "mode_before": mode_before,
        "mode_after": "loch" if state["reverted"] else "siphon (revert FAILED)",
        "reverted": state["reverted"],
        "observed": evidence,
        "observed_s": observed_s,
        "plan": {"iface": plan.iface, "segment": plan.segment, "addr": plan.our_ip,
                 "gateway": plan.gateway, "targets": plan.targets},
        "notes": notes,
        "error": revert_error,
    }
    if evidence is None and not revert_error:
        notes.append(
            "no intercept evidence arrived during the window -- check that the siphon "
            "overlay is applied (the worker needs NET_ADMIN + NET_RAW) and read "
            "`kubectl -n weirvern logs deploy/weirvern-worker` for the supervisor's refusal."
        )
    return result


def _revert_quietly(client, state) -> None:
    """The backstop: put the mode back if the probe never got to (process died mid-run).

    A daemon timer owned by the GUI process. It cannot cover the GUI pod itself being
    deleted mid-test, and that limit is stated rather than papered over -- the belt it
    adds is for the common case (a request thread that died after the mode was flipped).
    """
    if state.get("reverted"):
        return
    try:
        client.apply({MODE_KEY: "loch"})
        client.restart(WORKER)
        state["reverted"] = True
        logger.warning("siphon probe backstop: reverted the mode after the probe itself "
                       "did not (its request thread likely died mid-run)")
    except Exception:  # noqa: BLE001
        logger.error("siphon probe backstop could NOT revert the mode", exc_info=True)
