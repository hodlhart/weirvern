"""Run the detection pipeline once over a freshly seeded demo.

WHY THIS EXISTS. `demo-seed` can fill tables with plausible rows, and a console full of rows
that no model ever scored is a screenshot of a database, not of the product. The ML surfaces
(Alerts, Evidence, Models, the fused Ripples card) are only honest if the real pipeline ran:
the detectors trained on the seeded windows, the sweep scored them, the calibration measured a
false-alarm rate, and the shadow specialists produced their own answers.

So this module drives the WORKER'S OWN functions, in the worker's own order, for a bounded
span and then stops. It is not a second implementation and it does not invent a verdict: every
row it leaves behind was produced by the code the deployment runs.

WHAT IT DOES NOT DO. It does not alert anyone (`ALERT_DELIVERY=record` writes the decision to
`alert_events` and sends nothing), it does not page, and it does not touch a model artifact
outside the demo's own subdirectory of MODEL_DIR. The demo can be run beside a real deployment
without loading or overwriting its models.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

#: How far back the demo scores. Long enough to cover the seeded ripple and a full working day,
#: short enough that a test drive finishes while someone is watching it.
DEFAULT_HOURS = 8
#: The sweep drains in bounded chunks, so a span needs several cycles. This is the stop, not the
#: plan: the loop exits as soon as the cursor reaches the present.
MAX_SWEEPS = 24


def _specialists(client, settings) -> dict[str, str]:
    """Run the shadow specialists the worker runs hourly, isolated from each other.

    Each one is a separate model with its own table. One refusing its data must not stop the
    others, which is the same rule the worker applies; the result records what happened rather
    than pretending every specialist answered.
    """
    out: dict[str, str] = {}

    def attempt(name: str, fn) -> None:
        try:
            result = fn()
        except Exception as exc:  # noqa: BLE001 - a demo pass must finish
            logger.warning("demo ML: %s failed: %s", name, exc)
            out[name] = f"failed: {exc}"[:160]
            return
        out[name] = str(result)[:160]

    from weirvern.models import (  # noqa: PLC0415
        beacon_specialist,
        candidates,
        changepoints,
        dns_specialist,
        drift,
        flow_specialist,
        graph_specialist,
        roles,
        temporal,
        tls_specialist,
    )

    attempt("roles", lambda: len(roles.run(client, settings)))
    attempt("candidates", lambda: candidates.run(client))
    attempt("temporal", lambda: temporal.run(client))
    attempt("changepoints", lambda: changepoints.run(client))
    attempt("drift", lambda: drift.run(client))
    attempt("beacon", lambda: beacon_specialist.run(client, minutes=60 * DEFAULT_HOURS))
    attempt("dns", lambda: dns_specialist.run(client, minutes=60 * DEFAULT_HOURS))
    attempt("flow", lambda: flow_specialist.run(client, minutes=60 * DEFAULT_HOURS))
    attempt("graph", lambda: graph_specialist.run(client, minutes=60 * DEFAULT_HOURS))
    attempt("tls", lambda: tls_specialist.run(client, minutes=60 * DEFAULT_HOURS))
    return out


def run(client, settings, *, hours: int = DEFAULT_HOURS,
        max_sweeps: int = MAX_SWEEPS) -> dict[str, Any]:
    """Train, sweep, fuse and calibrate over the last `hours` of seeded data.

    Returns a summary of what was actually produced, which is what the seeder prints and what a
    test asserts against.
    """
    from dataclasses import replace  # noqa: PLC0415

    from weirvern import alerts, episodes, worker  # noqa: PLC0415
    from weirvern.models import calibration, host_hour, ripple_shadow  # noqa: PLC0415

    # THE DEMO'S MODELS LIVE IN THEIR OWN DIRECTORY. A test drive must not load, retrain or
    # overwrite the artifacts of a deployment that shares MODEL_DIR, and the cursor is part of
    # that state. Settings is frozen, so this is a copy rather than an assignment to the caller's
    # object (measured: assigning raised "cannot assign to field 'model_dir'").
    demo_settings = replace(settings, model_dir=str(Path(settings.model_dir) / "demo"))
    Path(demo_settings.model_dir).mkdir(parents=True, exist_ok=True)

    # THE MODEL WINDOW IS THE COVERAGE CEILING. `detection_sweep` clamps its cursor to
    # `retrain_window_h`, so asking for 144 hours scored at most 72 and the summary still said
    # 144. Report the requested and the effective span; never advertise hours the cursor cannot
    # reach.
    requested_hours = max(1, int(hours))
    hours = min(requested_hours, max(1, int(demo_settings.retrain_window_h)))

    summary: dict[str, Any] = {"hours": hours, "hours_requested": requested_hours,
                              "model_dir": demo_settings.model_dir}
    cfg = worker.model_config(demo_settings)
    detectors = worker.build_detectors(demo_settings, cfg, model_dir=demo_settings.model_dir)
    usable, trained_at = worker.load_or_train(client, detectors, demo_settings, cfg)
    summary["trained"] = usable
    summary["trained_at"] = trained_at.isoformat() if trained_at else None
    if not usable:
        summary["reason"] = "no data to train on"
        return summary

    # A WARM-UP DRAIN BEFORE CALIBRATION. Calibration reads `ml_window_scores`; on a fresh seed
    # that table is empty until the sweep has scored something, so calibrating first produced 0
    # rows, every detector stayed barred, and the scoring pass returned no verdicts. Measured:
    # calibration on an empty score table = 0 rows and 0 anomalies; after one drain = 28 rows.
    worker._save_detect_cursor(demo_settings, datetime.now(UTC) - timedelta(hours=hours))
    for _ in range(max_sweeps):
        worker.detection_sweep(client, detectors, demo_settings, cfg)
        after = worker._load_detect_cursor(demo_settings)
        if after is None or after >= datetime.now(UTC) - timedelta(minutes=10):
            break

    # CALIBRATION BEFORE THE SCORING PASS, and the order is the whole point. The eligibility gate
    # reads the calibration table; a sweep that runs first finds every detector uncalibrated,
    # bars all five from the fused score, and correctly returns zero verdicts. Measured on a
    # seeded box: sweeps first produced 0 anomalies, calibration first produced 24.
    try:
        summary["calibration"] = len(calibration.run(client, demo_settings))
    except Exception as exc:  # noqa: BLE001
        summary["calibration"] = f"failed: {exc}"[:120]

    # START THE CURSOR AT THE FRONT OF THE SPAN WE WANT SCORED. Without this the sweep starts
    # from its own lookback and the seeded past is never examined, which is exactly how a
    # demo ends up with a full database and empty Alerts.
    worker._save_detect_cursor(demo_settings, datetime.now(UTC) - timedelta(hours=hours))
    total = 0
    sweeps = 0
    state = alerts.AlertState()
    for i in range(max_sweeps):
        verdicts = worker.detection_sweep(client, detectors, demo_settings, cfg)
        sweeps = i + 1
        total += len(verdicts)
        try:
            episodes.refresh(client, demo_settings)
        except Exception as exc:  # noqa: BLE001 - a review view, never a prerequisite
            logger.warning("demo ML: episode refresh failed: %s", exc)
        for verdict in verdicts:
            try:
                verdict["_pageable"] = episodes.claim(client, verdict, demo_settings)
            except Exception:  # noqa: BLE001
                verdict["_pageable"] = True
            try:
                alerts.push_alert(verdict, demo_settings, state, client)
            except Exception as exc:  # noqa: BLE001
                logger.warning("demo ML: alert record failed: %s", exc)
        after = worker._load_detect_cursor(demo_settings)
        if after is None or after >= datetime.now(UTC) - timedelta(minutes=10):
            break

    summary["sweeps"] = sweeps
    summary["anomalies"] = total

    try:
        summary["host_hour"] = host_hour.run(client)
    except Exception as exc:  # noqa: BLE001
        summary["host_hour"] = f"failed: {exc}"[:120]

    try:
        summary["ripples"] = ripple_shadow.run(client)
    except Exception as exc:  # noqa: BLE001
        summary["ripples"] = f"failed: {exc}"[:120]

    summary["specialists"] = _specialists(client, demo_settings)
    return summary
