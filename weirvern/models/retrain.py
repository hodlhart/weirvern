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
    # "TRAINED" AND "USABLE" ARE DIFFERENT FACTS (GitHub #60). A centreless DBSCAN completes
    # a run, saves its diagnostic artifact and cannot score; a report that says only
    # "trained" makes that invisible. The cluster count is already in metrics; this word
    # states the consequence.
    try:
        usable = bool(getattr(det, "is_ready", lambda: False)())
    except Exception:  # noqa: BLE001 - a broken detector must not break the report
        usable = False
    return {
        "name": str(getattr(det, "name", "?")),
        "trained": bool(trained),
        "usable": usable,
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

    THE RELOAD IS THE VERIFICATION (GitHub #59). A candidate that cannot load is not installed:
    the bytes that were live are put back, the detector is named in `failed`, and the caller
    can report a refusal instead of a success it did not get.
    """
    target = candidate_dir(settings.model_dir)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S")
    archive = Path(settings.model_dir) / SUPERSEDED_DIR / stamp
    installed: list[str] = []
    archived: list[str] = []
    failed: list[dict[str, str]] = []
    for det in detectors:
        name = det.artifact_path().name
        src = target / name
        if not src.exists():
            continue
        live = Path(settings.model_dir) / name
        kept: Path | None = None
        if live.exists():
            archive.mkdir(parents=True, exist_ok=True)
            kept = archive / name
            shutil.copy2(live, kept)
            archived.append(str(kept))
        src.replace(live)
        # A KEEP IS A VERIFIED SWAP (GitHub #59). The old code discarded this bool, so an
        # unreadable candidate was reported as installed while the live file on disk was the
        # new, unusable one. Reload IN PLACE: the same object the cycle holds should carry the
        # candidate's weights -- but only after it has proved it can.
        try:
            loaded = bool(det.load())
            reason = "" if loaded else "the artifact did not load"
        except Exception as exc:  # noqa: BLE001
            loaded = False
            reason = f"the artifact did not load: {exc}"
        if not loaded:
            # Put back exactly what was there. With no old artifact, remove the new one:
            # leaving it would make the next restart adopt the candidate we just refused.
            if kept is not None:
                shutil.copy2(kept, live)
            else:
                live.unlink(missing_ok=True)
            failed.append({"name": name, "reason": reason})
            logger.error("candidate %s was NOT installed: %s", name, reason)
            continue
        installed.append(name)
    # Anything left in the candidate directory would be installed by the NEXT keep as if it had
    # just been built -- a stale artifact wearing a fresh date.
    shutil.rmtree(target, ignore_errors=True)
    logger.info("candidate kept: %s installed, %s archived, %s failed",
                len(installed), len(archived), len(failed))
    return {"installed": installed, "archived": archived, "archived_to": str(archive),
            "failed": failed}


def discard_candidate(settings) -> dict[str, Any]:
    """Trash: remove the candidate artifacts. The live models were never touched."""
    target = candidate_dir(settings.model_dir)
    removed = candidate_files(settings.model_dir)
    shutil.rmtree(target, ignore_errors=True)
    logger.info("candidate discarded: %d file(s) removed", len(removed))
    return {"removed": removed}


def report_summary(report: dict[str, Any]) -> str:
    """One sentence for the GUI header: did it train, on how much, and was the window clean.

    EVERY DETECTOR COUNTS A DIFFERENT THING, AND SAYS SO (operator, 2026-11-19: "in models this
    doesn't add up"). The panel prints each detector's own `sample_count` beside it, so a header
    that quotes ONE of those numbers as the run's basis contradicts the table under it -- the
    screenshot that prompted this read "trained on 9,520 host-windows" above an Isolation Forest
    row that said 11,900. The header now carries each trained detector's count with its own unit,
    which is the same thing the table says, in one line.
    """
    if not report:
        return ""
    dets = [d for d in (report.get("detectors") or []) if isinstance(d, dict)]
    trained = [d for d in dets if "trained" in d and d["trained"]]

    def _count(d: dict) -> int:
        try:
            return int(d.get("sample_count") or 0)
        except (TypeError, ValueError):
            return 0

    # The unit belongs to the detector: a model trains on windows, DBSCAN on a sample of them,
    # the baseline on HOSts. Printing them in one list with no units is how they got summed.
    units = {"Gradient Boosting": "windows", "Isolation Forest": "windows",
             "DBSCAN": "window sample", "Adaptive Baseline": "hosts"}
    parts = [f"{len(trained)} of {len(dets)} detector(s) trained"]
    detail = [f"{d.get('name') or 'detector'} {_count(d):,} "
              f"{units.get(str(d.get('name')), 'samples')}"
              for d in trained if _count(d)]
    if detail:
        parts.append("each on its own matrix: " + " · ".join(detail))
    cont = report.get("contamination") or {}
    if cont.get("available") and int(cont.get("detections") or 0) == 0:
        parts.append("no detections were recorded inside the window")
    if cont.get("available") and int(cont.get("detections") or 0) > 0:
        parts.append(
            f"WARNING: {int(cont['detections']):,} detection(s) already recorded inside this "
            "window -- keeping it teaches the new model to treat that traffic as normal")
    return "; ".join(parts) + "."


def parse_report(row_report: str) -> dict[str, Any]:
    try:
        return json.loads(row_report) if row_report else {}
    except (TypeError, ValueError):
        return {}
