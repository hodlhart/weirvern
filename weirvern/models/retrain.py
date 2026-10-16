"""Force a retrain, then keep or trash the result -- the operator's check that ML is working.

THE QUESTION THIS ANSWERS IS "IS ANY OF THIS ACTUALLY WORKING?", asked by the person who owns the
network and cannot see inside a model. The honest answer is not a green dot; it is: train the
same detectors again on the traffic you have NOW, show what they learned, and let the operator
decide whether that is what they want watching their segment.

TWO RULES MAKE THE ANSWER TRUSTWORTHY, and both exist because the alternative fails quietly:

  * A FORCED RETRAIN NEVER TOUCHES THE LIVE ARTIFACTS. It trains into `<MODEL_DIR>/candidate`,
    reports what it built, and stops. Nothing the running pipeline uses changes until the
    operator says keep. So "was that a good idea?" is answered BEFORE the model that is scoring
    traffic is replaced, not after -- and a retrain that turns out to be wrong costs one button
    press, not the detection baseline.
  * THE REPORT SAYS WHAT THE WINDOW CONTAINED. A retrain learns from whatever it is shown. A
    window holding an attack teaches the new model that the attack is normal -- that is exactly
    what a model is for and exactly the wrong thing here. The worker cannot know whether the
    traffic was friendly; the operator can. So the count of detections already recorded inside
    the window is computed and put in the report, in one sentence, next to the Keep button.

The candidate trains through the SAME detector classes and the same window as the cadence path
(`train_if_due`), so a forced retrain is a real rehearsal of what the pipeline will do on its own
-- not a special path that could pass while the scheduled one is broken.
"""

from __future__ import annotations

import json
import logging
import shutil
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from clickhouse_connect.driver.client import Client

logger = logging.getLogger(__name__)

CANDIDATE_DIR = "candidate"
SUPERSEDED_DIR = "superseded"


def candidate_dir(model_dir: str | Path) -> Path:
    return Path(model_dir) / CANDIDATE_DIR


def candidate_files(model_dir: str | Path) -> list[str]:
    """The candidate artifacts on disk right now, by filename -- what a keep would install."""
    path = candidate_dir(model_dir)
    if not path.is_dir():
        return []
    return sorted(p.name for p in path.glob("*.pkl"))


def _json_window(value):
    """A detector's window comes off its metadata as a DATETIME; the report must be JSON by
    construction (issue #5, 2026-10-16): `actions.finish` writes `json.dumps(report)` for the
    DONE state, and a raw datetime made that write raise TypeError -- the row stayed in
    RUNNING forever, a retrain that trained fine never finished. ISO strings are what this
    same report already uses for `built_at`/`window_start`, so the stored column stays valid
    JSON and `report_summary` keeps reading it. None passes through untouched."""
    return value.isoformat() if hasattr(value, "isoformat") else value


def _detector_report(det, *, trained: bool) -> dict[str, Any]:
    meta = getattr(det, "metadata", None)
    return {
        "name": str(getattr(det, "name", "?")),
        "trained": bool(trained),
        # Host-windows, from the detector's own metadata -- named as the metadata and the
        # `ml_models` column name it, so a reader (and the schema audit) can trace it. A model
        # trained on 12 windows and one trained on 12000 score very differently, and
        # "trained: true" alone hides which one this is.
        "sample_count": int(getattr(meta, "sample_count", 0) or 0),
        "window_start": _json_window(getattr(meta, "window_start", None)),
        "window_end": _json_window(getattr(meta, "window_end", None)),
        "metrics": getattr(meta, "metrics", {}) or {},
    }


def contamination(client: Client, start: datetime, end: datetime) -> dict[str, Any]:
    """How many detections the system ALREADY recorded inside this training window.

    Not a veto and not a count of attacks: a detection is a model's opinion, and the window may
    hold detections that are noise. It is the one fact the operator needs beside the Keep button
    that the machine cannot supply: if this window contains things this deployment already
    flagged, retraining on it teaches the new model to see them as normal.
    """
    try:
        rows = client.query(
            """
            SELECT count() AS n, min(window_start) AS first_seen, max(window_start) AS last_seen
            FROM weirvern.netflow_anomalies
            WHERE window_start >= %(a)s AND window_start <= %(b)s
            """,
            parameters={"a": start, "b": end},
        ).result_rows
    except Exception as exc:  # noqa: BLE001
        logger.warning("could not count detections in the training window: %s", exc)
        return {"available": False, "reason": f"{type(exc).__name__}: {exc}"}
    n, first_seen, last_seen = rows[0] if rows else (0, None, None)
    return {"available": True, "detections": int(n or 0),
            "first": first_seen, "last": last_seen}


def run_candidate(
    client: Client,
    settings,
    cfg,
    *,
    build: Callable[[str], list] | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Train a CANDIDATE set of detectors and report what it produced. Changes nothing live.

    `build` is injectable so this path can be tested without ClickHouse or sklearn; production
    passes nothing and gets the real detectors aimed at the candidate directory.
    """
    builder = build
    if builder is None:
        from weirvern.worker import build_detectors  # noqa: PLC0415

        def builder(model_dir: str) -> list:  # type: ignore[misc]  # noqa: ANN001
            return build_detectors(settings, cfg, model_dir=model_dir)

    now = now or datetime.now(UTC)
    start = now - timedelta(hours=settings.retrain_window_h)
    target = candidate_dir(settings.model_dir)
    detectors = builder(str(target))

    if_det, gb_det, db_det, bl_det = detectors
    reports: list[dict[str, Any]] = []

    trained = if_det.train(start, now, client)
    reports.append(_detector_report(if_det, trained=trained))
    if trained and getattr(if_det, "X_train_unscaled", None) is not None:
        # The student trains on the teacher's matrix, exactly as the cadence path does -- a
        # student trained on a different matrix would make the rehearsal a different experiment.
        gb_ok = bool(gb_det.train(if_det, if_det.X_train_unscaled, start, now, client))
        reports.append(_detector_report(gb_det, trained=gb_ok))
        if gb_ok:
            gb_det.save()
    else:
        reports.append(_detector_report(gb_det, trained=False))
    if trained:
        if_det.save()

    for det in (db_det, bl_det):
        ok = bool(det.train(start, now, client))
        reports.append(_detector_report(det, trained=ok))
        if ok:
            det.save()

    files = candidate_files(settings.model_dir)
    report = {
        "built_at": now.isoformat(),
        "window_start": start.isoformat(),
        "window_end": now.isoformat(),
        "window_hours": int(settings.retrain_window_h),
        "detectors": reports,
        "trained_any": any(r["trained"] for r in reports),
        "contamination": contamination(client, start, now),
        "files": files,
    }
    logger.info("candidate retrain built: %d of %d detector(s) trained, %d file(s)",
                sum(1 for r in reports if r["trained"]), len(reports), len(files))
    return report


def apply_candidate(client: Client, settings, detectors) -> dict[str, Any]:
    """Keep: install the candidate artifacts over the live ones, ARCHIVING what they replace.

    The archive is not sentiment. A retrain that turns out worse is discovered in a day, and
    "put back what was working" has to be possible without a re-run of anything -- so the file
    that was in place is kept, named for the moment it was retired.

    The live detectors are reloaded straight after the swap, in this process, so the pod that
    just installed them starts scoring with them instead of waiting for its next restart.
    """
    target = candidate_dir(settings.model_dir)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S")
    archive = Path(settings.model_dir) / SUPERSEDED_DIR / stamp
    installed: list[str] = []
    archived: list[str] = []
    for det in detectors:
        name = det.artifact_path().name
        src = target / name
        if not src.exists():
            continue
        live = Path(settings.model_dir) / name
        if live.exists():
            archive.mkdir(parents=True, exist_ok=True)
            shutil.copy2(live, archive / name)
            archived.append(str(archive / name))
        src.replace(live)
        installed.append(name)
        # Reload IN PLACE: the same object the cycle holds now carries the candidate's weights.
        det.load()
    # Anything left in the candidate directory would be installed by the NEXT keep as if it had
    # just been built -- a stale artifact wearing a fresh date.
    shutil.rmtree(target, ignore_errors=True)
    logger.info("candidate kept: %s installed, %s archived", len(installed), len(archived))
    return {"installed": installed, "archived": archived, "archived_to": str(archive)}


def discard_candidate(settings) -> dict[str, Any]:
    """Trash: remove the candidate artifacts. The live models were never touched."""
    target = candidate_dir(settings.model_dir)
    removed = candidate_files(settings.model_dir)
    shutil.rmtree(target, ignore_errors=True)
    logger.info("candidate discarded: %d file(s) removed", len(removed))
    return {"removed": removed}


def report_summary(report: dict[str, Any]) -> str:
    """One sentence for the GUI header -- the same facts the report carries, in the order an
    operator asks them: did it train, on how much, and was the window clean."""
    if not report:
        return ""
    dets = [d for d in (report.get("detectors") or []) if isinstance(d, dict)]
    trained = [d for d in dets if "trained" in d and d["trained"]]
    parts = [f"{len(trained)} of {len(dets)} detector(s) trained"]
    rows = 0
    for d in trained:
        try:
            rows += int(d.get("sample_count") or 0)
        except (TypeError, ValueError):
            continue
    parts.append(f"on {rows} host-window(s)")
    cont = report.get("contamination") or {}
    if cont.get("available") and int(cont.get("detections") or 0) > 0:
        parts.append(
            f"WARNING: {int(cont['detections'])} detection(s) already recorded inside this "
            f"window -- keeping it teaches the new model to treat that traffic as normal"
        )
    elif cont.get("available"):
        parts.append("no detections were recorded inside the window")
    return "; ".join(parts)


def parse_report(row_report: str) -> dict[str, Any]:
    try:
        return json.loads(row_report) if row_report else {}
    except (TypeError, ValueError):
        return {}
