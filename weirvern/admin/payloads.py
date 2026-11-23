"""Fetchers that return a finished payload, for any surface to call.

WHY THIS MODULE EXISTS. `web_api` formats and knows nothing about HTTP; the handler in `web.py` both
fetches AND routes, so a second surface had no way to reach the data without copying the fetch. That
copy is what I had already started doing in the Flask route for episodes, and a copy is exactly what
this codebase spends its time removing: two readers, two ideas of what the payload means, drifting
apart with each copy looking correct alone.

SO THE SEAM MOVES ONE LAYER DOWN. A function here takes a ClickHouse client and the request's
arguments and returns the SAME payload the console returns. A surface then does only two things:
parse arguments, and turn the result into a response. Neither surface knows how the data is read.

THE ERROR SHAPE IS PART OF THE CONTRACT. Every fetcher raises on a failed read and leaves the wording
to the caller through `read_failure`, which is the one place a failure is described by what was
OBSERVED rather than by the layer assumed to have broken (WV1-20). A fetcher that swallowed the
exception and returned an empty payload would be the "absence reads as healthy" defect at the source.

MIGRATION IS INCREMENTAL, DELIBERATELY. Only routes that have been moved here appear, and each one is
deleted from the handler as it lands so there is never a second implementation lying around. The
console keeps serving everything not yet moved.
"""

from __future__ import annotations

import datetime
import json
import logging
import math
from typing import Any

from clickhouse_connect.driver.client import Client

from weirvern.admin import status as status_mod
from weirvern.admin import web_api
from weirvern.config import FUSED_MODEL

logger = logging.getLogger(__name__)


def episodes(client: Client, *, hours: int, limit: int) -> dict[str, Any]:
    """One row per incident, with the hostname resolved the same way everywhere.

    The queue's Host column is the fact (the address); the hostname is the convenience, resolved
    through the same cached reverse-DNS path the anomaly route uses, so the two tables cannot
    disagree about a name. A missing name is an empty cell, never an invented label.
    """
    payload = status_mod.episodes_recent(client, hours=hours, limit=limit)
    for row in payload.get("episodes", []):
        row["hostname"] = web_api._hostname(row.get("src_addr"))
    return payload


def baselines(client: Client) -> dict[str, Any]:
    """The per-host baseline snapshot: latest row per host, when it refreshed, what fired lately.

    `available`/`reason` pass through intact, because "the store could not be read" and "no host has a
    baseline yet" need different words on screen and only the server knows which is true.

    A FAILED read is a 200 carrying `available: false`, NOT a 503: the card sits beside others, and an
    error page for one of them would take down the views around it. The console words it the same way,
    through `baselines_failure`, so the two surfaces cannot drift on it.
    """
    return web_api.baselines_payload(status_mod.baselines_overview(client))


def baselines_failure(exc: BaseException) -> dict[str, Any]:
    """The console's own failure shape for /api/baselines, shared so both surfaces cannot drift."""
    from weirvern.admin.web import read_failure  # noqa: PLC0415

    logger.warning("baselines unavailable: %s", exc)
    return {"available": False, "reason": read_failure(exc)}


def detectors(client: Client) -> dict[str, Any]:
    """The detector registry with its catch counts: who owns what, who may page."""
    return status_mod.detectors_overview(client)


def models_calibration(client: Client, settings: Any) -> dict[str, Any]:
    """Shadow calibration readout. A FAILED read is a 200 with `available: false` and the reason."""
    from weirvern.admin.web import read_failure  # noqa: PLC0415

    try:
        return web_api.calibration_payload(status_mod.calibration_overview(client, settings))
    except Exception as exc:  # noqa: BLE001
        return {"available": False, "reason": read_failure(exc), "rows": []}


def models_shadow(client: Client) -> dict[str, Any]:
    """Shadow ML channel counts. A failed read is a state, not an empty success."""
    from weirvern.admin.web import read_failure  # noqa: PLC0415

    try:
        return status_mod.shadow_overview(client)
    except Exception as exc:  # noqa: BLE001
        return {"available": False, "reason": read_failure(exc), "rows": []}


def ml_slo(client: Client) -> dict[str, Any]:
    """The operating numbers, with window/source and explicit not-measured states."""
    try:
        from weirvern.models import quality  # noqa: PLC0415

        return quality.report(client)
    except Exception as exc:  # noqa: BLE001
        return {"available": False, "reason": f"cannot read the ML SLO report: {exc}",
                "windows": [], "live_precision": "not measured"}


def ml_coverage(client: Client) -> dict[str, Any]:
    """The source and role truth report; explicitly unavailable rather than empty on failure."""
    try:
        from weirvern.models import source_coverage  # noqa: PLC0415

        return source_coverage.collect(client)
    except Exception as exc:  # noqa: BLE001
        return {"available": False, "reason": f"cannot read source coverage: {exc}",
                "sources": [], "roles": {}, "models": [], "promotion_ok": False}


# ── reads that come from a FILE, not from ClickHouse ─────────────────────────────────────────
#
# These take no client at all, which is why the fetcher signature differs. `_package_root()` matches
# the path the console computes (`Path(__file__).resolve().parents[2]` from weirvern/admin/web.py) --
# both modules sit in weirvern/admin, so parents[2] is the checkout root for either.

def _package_root() -> Any:
    from pathlib import Path  # noqa: PLC0415

    return Path(__file__).resolve().parents[2]


def ml_ledger() -> dict[str, Any]:
    """The append-only decision trail, read-only."""
    try:
        from weirvern.models import ledger  # noqa: PLC0415

        path = _package_root() / "docs" / "ledger" / "ml-decisions.jsonl"
        rows = ledger.read(path)
        return {"available": bool(rows), "path": str(path), "rows": rows[-20:]}
    except Exception as exc:  # noqa: BLE001
        return {"available": False, "reason": f"cannot read the decision ledger: {exc}"}


def ml_eval_report() -> dict[str, Any]:
    """The archived fixed-budget report, read-only."""
    try:
        from weirvern.models import eval_report  # noqa: PLC0415

        return eval_report.latest_report(_package_root())
    except Exception as exc:  # noqa: BLE001
        return {"available": False, "reason": f"cannot read the evaluation report: {exc}"}


def ml_review() -> dict[str, Any]:
    """The archived review, read from disk, never recomputed in the GUI."""
    try:
        from weirvern.models import review  # noqa: PLC0415

        return review.latest_report(_package_root())
    except Exception as exc:  # noqa: BLE001
        return {"available": False, "reason": f"cannot read the archived review: {exc}"}


# ── the pipeline's own health and audit views ───────────────────────────────────────────────
#
# Three different failure shapes live in this block, and each is preserved exactly. `audit` raises so
# the route answers 503; `sluice_state` and `asset_posture` answer 200 with `available: false` so a
# partial page still draws. Collapsing them into one shape would change what an operator sees.

def audit(client: Client) -> dict[str, Any]:
    """The pipeline's self-audit read. Raises, so the caller answers 503."""
    return status_mod.pipeline_audit(client)


def sluice_state(client: Client) -> dict[str, Any]:
    """Just the gate's state, for a cheap poll on a short interval."""
    from weirvern import sluice_store  # noqa: PLC0415
    from weirvern.admin.web import _gate_sensor_name  # noqa: PLC0415

    try:
        return sluice_store.load_gate_state(client, sensor=_gate_sensor_name())
    except Exception as exc:  # noqa: BLE001
        # The exception TYPE, not its message: this payload is polled every few seconds and a raw
        # message would put a stack fragment on the wire repeatedly.
        return {"available": False, "reason": f"cannot read the gate: {type(exc).__name__}"}


def asset_posture(client: Client) -> dict[str, Any]:
    """The shadow asset-posture scorer's state. Advisory, and a fixed shape when it cannot read."""
    import logging  # noqa: PLC0415

    from weirvern.admin import assets as assets_mod  # noqa: PLC0415

    logger = logging.getLogger(__name__)
    try:
        return assets_mod.asset_posture_overview(client)
    except Exception as exc:  # noqa: BLE001
        logger.warning("asset posture unavailable: %s", exc)
        return {"available": False, "reason": "the data could not be read",
                "model_version": "asset-posture-1", "scored": 0, "total_changes": 0,
                "bands": {}, "last_scored": ""}


def ml_ripple(client: Client) -> dict[str, Any]:
    """The latest fused ripple evaluation; unavailable is a named state, never an empty list."""
    from weirvern.admin.web import read_failure  # noqa: PLC0415

    try:
        return status_mod.ripple_overview(client)
    except Exception as exc:  # noqa: BLE001
        return {"available": False, "reason": read_failure(exc), "rows": [], "pageable": False,
                "counts": {}, "contributors": [], "scales": [], "families": [], "unknown": []}


def ripples(client: Client, *, hours: int) -> dict[str, Any]:
    """Phase-1 ripples plus the evidence they were grouped from. Read-only, never pages.

    The failure shape is built HERE rather than left to the route: the Models card has to tell
    "the evidence could not be read" apart from "no ripple formed", and both must be a 200 with
    an empty list rather than an error page.
    """
    from weirvern.models import ripple_evidence  # noqa: PLC0415

    try:
        return ripple_evidence.overview(client, hours=hours)
    except Exception as exc:  # noqa: BLE001 - a read failure is a state, not a crash
        return ripples_failure(exc, hours=hours)


def ripples_failure(exc: BaseException | None = None, *, hours: int = 0) -> dict[str, Any]:
    """The console's own empty-and-named shape for `/api/ripples`."""
    from weirvern.admin.web import read_failure  # noqa: PLC0415
    from weirvern.models import ripple_evidence  # noqa: PLC0415

    logger.warning("ripple evidence unavailable: %s", exc)
    return {"available": False, "reason": read_failure(exc), "ripples": [], "count": 0,
            "window_hours": int(hours), "model_version": ripple_evidence.MODEL_VERSION,
            "severity_bands": ripple_evidence.severity_bands()}


def ml_data_contract(client: Client) -> dict[str, Any]:
    """What 'covered' means, measured against the live tables."""
    try:
        from weirvern.models import data_contract  # noqa: PLC0415

        return data_contract.inventory(client)
    except Exception as exc:  # noqa: BLE001
        return {"available": False, "reason": f"cannot read the data contract: {exc}",
                "sources": [], "families": [], "gaps": [], "hosts": [],
                "population": {}, "promotion_ok": False}


# ── inventory reads: one fetch, one shape, and a failure the panel can draw around ──────────

def assets(client: Client, *, hours: int, scope: str = "all") -> dict[str, Any]:
    """The asset inventory: every host seen, with a per-host summary.

    `hours` bounds the TRAFFIC columns only. A host whose last packet was days ago is still an asset,
    so it appears with zeroed counters rather than being dropped.

    `scope` is the reading the caller asked for, resolved HERE rather than by silently ignoring
    the parameter. The inventory is monitored-only by construction (an external peer is not an
    asset we are responsible for), so `all` and `monitored` return the same monitored set -- but
    the counts below are COUNTED from the rows, not aliased from one number, and an unsupported
    scope is rejected by the route instead of being answered with the full set.

    THE SCAN AFFORDANCE TRAVELS WITH THE ROWS. One fleet-capability read annotates every host
    with whether a weirling that can scan also DECLARES its network, so the Assets table can
    disable "Scan now" per row with the reason instead of offering work nothing can claim.
    """
    from weirvern import scan_jobs as scan_jobs_mod  # noqa: PLC0415
    from weirvern import scanner as scanner_mod  # noqa: PLC0415
    from weirvern.admin import assets as assets_mod  # noqa: PLC0415

    payload = assets_mod.asset_inventory(client, hours=hours)
    hosts = payload.get("hosts") or []
    # COMPUTED, NOT COPIED. `all` is every row this inventory can return; `monitored` counts the
    # rows whose own scope says monitored; `external` is counted too, and is zero because the
    # inventory never emits one.
    payload["scope"] = scope
    payload["scope_counts"] = {
        "all": len(hosts),
        "monitored": sum(1 for h in hosts if str(h.get("scope") or "") == "monitored"),
        "external": sum(1 for h in hosts if str(h.get("scope") or "") == "external"),
    }
    try:
        capability = scanner_mod.fleet_capability(client)
    except Exception as exc:  # noqa: BLE001 - the inventory must not fail with the annotation
        logger.warning("asset scan capability unavailable: %s", exc)
        capability = scanner_mod.capability_failure(exc)
    for host in hosts:
        scan = host.get("scan") or {}
        addr = str(host.get("addr") or "")
        reach = [item["sensor_id"] for item in capability.get("capable") or []
                 if scan_jobs_mod.ip_allowed(addr, item.get("networks") or [])]
        scan["can_scan"] = bool(reach)
        scan["scan_weirlings"] = reach
        scan["scan_refusal"] = "" if reach else (
            capability.get("reason_unavailable")
            or "no weirling that can scan declares this host's network")
        host["scan"] = scan
    payload["scan_capability"] = {
        "enabled": capability.get("enabled", False),
        "sentence": capability.get("sentence", ""),
        "reason_unavailable": capability.get("reason_unavailable", ""),
        "count": capability.get("count", 0),
        "capable_count": capability.get("capable_count", 0),
        "available": capability.get("available", False),
    }
    return payload


def assets_failure(exc: BaseException) -> dict[str, Any]:
    """The console's own failure shape for /api/assets, shared so both surfaces cannot drift."""
    from weirvern.admin.web import read_failure  # noqa: PLC0415

    logger.warning("asset inventory unavailable: %s", exc)
    return {"available": False, "hosts": [], "reason": read_failure(exc), "data_error": str(exc)}


def asset_changes(client: Client, *, hours: int) -> dict[str, Any]:
    """Recent service changes and their shadow posture score. Hours bounds the window only."""
    from weirvern.admin import assets as assets_mod  # noqa: PLC0415

    return assets_mod.asset_changes(client, hours=hours)


def asset_changes_failure(exc: BaseException) -> dict[str, Any]:
    """The console's own failure shape for /api/asset-changes, shared between the surfaces."""
    from weirvern.admin.web import read_failure  # noqa: PLC0415

    logger.warning("asset changes unavailable: %s", exc)
    return {"available": False, "changes": [], "count": 0, "reason": read_failure(exc),
            "data_error": str(exc)}


def scan_readiness(client: Client, *, ip: str = "", lease_s: int = 900) -> dict[str, Any]:
    """Whether the FLEET can execute a manual scan, and who can reach this target.

    THE FACT IS CAPABILITY, NOT CONFIGURATION. A weirling's own agent measures Nmap and reports
    it; the hub counts only fresh, registered, capable rows, and (for one address) only the
    weirlings whose declared networks contain it. The Scan button, the refusal and the claim all
    read this one shape, so the console cannot promise a scan no node can claim.
    """
    from weirvern import scanner as scanner_mod  # noqa: PLC0415

    payload = scanner_mod.fleet_capability(client, ip=ip)
    payload["lease_s"] = max(30, int(lease_s or 900))
    payload["docs_url"] = "docs/deployment.md#asset-scanning-and-nmap"
    return payload


def scan_readiness_failure(exc: BaseException) -> dict[str, Any]:
    """A failed capability read is an UNKNOWN answer, never "nobody can scan"."""
    from weirvern import scanner as scanner_mod  # noqa: PLC0415

    return scanner_mod.capability_failure(exc)


def scan_jobs(client: Client, *, ip: str, job: str = "", lease_s: int = 900,
              scanning_enabled: bool = True, unavailable_reason: str = "") -> dict[str, Any]:
    """The manual-scan queue: recent requests, optionally for one address or one job.

    The row timestamps are serialised here, through the console's own `_iso`, so a job's
    `requested_at` is the same string on both surfaces. `job` is the sheet's subject: a URL
    that names one job reads that job even after it has left the 20-row recent list. An
    unknown id is an empty list, never a fabricated row.

    `derived_state`/`abandoned`/`state_reason` are computed from the lease and the claim by
    `scan_jobs.derive` BEFORE serialisation -- the lease math needs datetimes, and `_iso`
    would turn them into strings the comparison cannot read. The row's own `state` stays
    exactly what the scanner wrote.
    """
    from weirvern import scan_jobs as scan_jobs_mod  # noqa: PLC0415
    from weirvern.admin.web import _iso  # noqa: PLC0415

    if job:
        one = scan_jobs_mod.get_job(client, job)
        rows = [one] if one is not None else []
    else:
        rows = scan_jobs_mod.list_jobs(client, ip=ip, limit=20)
    out = []
    for row in rows:
        item = scan_jobs_mod.derive(
            dict(row), lease_s=lease_s, scanning_enabled=scanning_enabled,
            unavailable_reason=unavailable_reason)
        for key in ("requested_at", "lease_until", "started_at", "finished_at"):
            item[key] = _iso(item.get(key))
        out.append(item)
    return {"available": True, "reason": "", "jobs": out, "count": len(out)}


def scan_jobs_failure(exc: BaseException) -> dict[str, Any]:
    """The console's own failure shape for /api/scan-jobs.

    A FIXED SENTENCE, not `read_failure`: the queue is not a monitoring read and the operator is told
    which table is unreadable. Reproduced exactly rather than tidied into the house wording.
    """
    logger.warning("scan jobs unavailable: %s", exc)
    return {"available": False, "reason": "the scan-job table is not readable",
            "jobs": [], "count": 0}


def host_identity(client: Client) -> dict[str, Any]:
    """What each host IS, from traffic already seen. Nothing is sent, so this is a pure read."""
    return status_mod.host_identity_view(client)


def host_identity_failure(exc: BaseException) -> dict[str, Any]:
    """The console's own failure shape for /api/identity, shared between the surfaces."""
    from weirvern.admin.web import read_failure  # noqa: PLC0415

    logger.warning("host identity unavailable: %s", exc)
    return {"available": False, "hosts": [], "count": 0, "coverage": None,
            "reason": read_failure(exc)}


def networks_overview(client: Client, *, hours: int) -> dict[str, Any]:
    """Read-only network coverage for Settings and the Warden tab.

    The suggestion block is part of the payload: with no declared scopes the pane offers starting
    points, and deriving them here means both surfaces offer the same ones.
    """
    from weirvern import networks as networks_mod  # noqa: PLC0415

    payload = networks_mod.overview(client, hours=hours)
    if not payload.get("scopes"):
        payload["suggested_scopes"] = [
            scope.public() for scope in networks_mod.suggested_monitored_scopes()
        ]
    return payload


def networks_failure(exc: BaseException) -> dict[str, Any]:
    """The console's own failure shape for /api/networks: the exception TYPE, never its message."""
    logger.warning("network scope read failed: %s", exc)
    return {"available": False,
            "reason": f"could not read network scopes: {type(exc).__name__}",
            "scopes": [], "summary": {}, "counts_available": False}


# ── panel reads: one fetch each, with the console's own failure shape ───────────────────────

def write_trail(client: Client, *, scope: str, action: str, target: str,
                limit: int) -> dict[str, Any]:
    """The write trail, newest first, with its filter menus derived from the table itself.

    NO failure dict: the console has no try around `read_audit`, so an exception becomes the server's
    own 500 with `internal error: ...`. That shape is preserved by leaving this raising and letting
    each surface's global handler answer, rather than inventing a 200 the operator never saw.
    """
    from weirvern import fleet_store  # noqa: PLC0415

    rows, reason = fleet_store.read_audit(client, scope=scope, action=action, target=target,
                                         limit=limit)
    facets: dict[str, list[str]] = {"scopes": [], "actions": []}
    if not reason:
        try:
            facets["scopes"] = sorted({
                str(r[0]) for r in client.query(
                    "SELECT DISTINCT scope FROM weirvern.fleet_audit"
                ).result_rows})
            facets["actions"] = sorted({
                str(r[0]) for r in client.query(
                    "SELECT DISTINCT action FROM weirvern.fleet_audit"
                ).result_rows})
        except Exception:  # noqa: BLE001
            facets = {"scopes": [], "actions": []}
    return {"available": not reason, "reason": reason, "rows": rows,
            "scopes": facets["scopes"], "actions": facets["actions"]}


def blocklists(client: Client) -> dict[str, Any]:
    """The blocklist pane: every source with its state, plus the custom names.

    Custom names ride along so the pane shows the whole watch set in one place, wherever it lives in
    the page.
    """
    from weirvern import blocklists as blocklists_mod  # noqa: PLC0415

    sources = blocklists_mod.load_sources(client)
    custom_rows = client.query(
        "SELECT domain FROM weirvern.blocklist_domains "
        "WHERE source_id = 'custom' GROUP BY domain ORDER BY domain "
        "LIMIT 500").result_rows
    return {"available": True, "reason": "", "sources": sources,
            "custom": [str(r[0]) for r in custom_rows]}


def blocklists_failure(exc: BaseException) -> dict[str, Any]:
    """The console's own failure shape for /api/blocklists."""
    from weirvern.admin.web import read_failure  # noqa: PLC0415

    logger.warning("blocklists unavailable: %s", exc)
    return {"available": False, "sources": [], "custom": [], "reason": read_failure(exc)}


def models(client: Client, *, hours: int, settings: Any) -> dict[str, Any]:
    """Model overview: training history, score spread, agreement, deviations.

    THE MODEL REGISTRY IS ITS OWN READ. A broken card query must not hide the training history, and a
    broken history must not make the cards look absent, so the registry failure is carried in the
    payload as `model_cards_available: false` with its own reason instead of taking the route down.

    THE DETECTORS TABLE IS DERIVED, NOT CURATED. Its status comes from the engine's own
    training log, the artifacts on disk, the measured false-alarm rate with its coverage, and the
    promotion guard's measured budget decision. A model card is documentation of intent and is
    never consulted for a verdict. Each source is read independently, so a card table that cannot
    be read no longer changes any detector's status -- and the table says which panel is missing
    rather than converting a read failure into a veto.
    """
    from weirvern.models import cards as cards_mod  # noqa: PLC0415
    from weirvern.models import eligibility as eligibility_mod  # noqa: PLC0415
    from weirvern.models.detector_status import detector_rows  # noqa: PLC0415
    from weirvern.models.detectors import DETECTOR_NAMES  # noqa: PLC0415

    data = status_mod.model_overview(client, hours=hours, settings=settings)
    # WHAT THE ENGINE ACTUALLY DID, not only what an operator approved (2026-11-19: "in models
    # this still looks wrong: the card says retired and the retraining says october 14"). The
    # registry is a curation snapshot; ml_models is the engine's own log, one row per training.
    data["model_training"] = model_training(client)
    # WHAT IS INSTALLED is a file read, so a broken card query cannot hide it either.
    data["model_artifacts"] = cards_mod.artifact_inventory(getattr(settings, "model_dir", ""))
    data["normalized"] = normalized_seeds(client)

    try:
        data["model_cards"] = cards_mod.current_cards(client)
        data["model_cards_available"] = True
        data["model_cards_behind"] = [
            c["model_name"] for c in data["model_cards"]
            if str(c.get("version") or "") !=
            str((data["model_artifacts"].get(str(c.get("model_name") or "")) or {})
                .get("version") or "")]
    except Exception as card_exc:  # noqa: BLE001
        data["model_cards"] = []
        data["model_cards_available"] = False
        data["model_cards_reason"] = f"cannot read the model registry: {card_exc}"
        data["model_cards_behind"] = []

    calibration = calibration_latest(client)
    # THE PROMOTION GUARD IS MEASURED, NOT STORED. Asking it here keeps the table honest between
    # worker sweeps (a held detector is held because its rate is over budget NOW, not because a
    # file says so yesterday); the worker's recorded state is what keeps the SET stable. A failed
    # measurement falls back to the evidence-only row and says so in `detector_budget.reason`.
    report = None
    budget_error = ""
    try:
        report = eligibility_mod.evaluate(client, settings, names=DETECTOR_NAMES, persist=False)
    except Exception as exc:  # noqa: BLE001 - a measurement failure must not hide the table
        budget_error = f"the promotion budget could not be measured: {exc}"
        logger.warning("models: %s", budget_error)
    data["detector_budget"] = {
        "budget": float(getattr(report, "budget", 0.0) or 0.0),
        "bar": float(getattr(report, "bar", 0.0) or 0.0),
        "windows": int(getattr(report, "windows", 0) or 0),
        "reason": budget_error,
    }
    data["detectors"] = detector_rows(
        data["model_training"], data["model_artifacts"], calibration,
        target_far=float(getattr(settings, "ml_target_far", 0.01) or 0.01),
        multiple=float(getattr(settings, "ml_eligibility_multiple", 3.0) or 3.0),
        min_coverage=float(getattr(settings, "ml_min_feature_coverage", 0.15)),
        retrain_every_h=float(getattr(settings, "retrain_every_h", 6) or 6),
        grace_h=float(getattr(settings, "ml_calibration_grace_h", 1.0) or 0.0),
        min_validation_windows=int(getattr(settings, "ml_eligibility_min_windows", 300) or 300),
        # The engine's roster: a name that is no longer built has no row at all.
        known_names=DETECTOR_NAMES,
        decisions=(report.decisions if report is not None else None),
        # The last training OUTCOME per model, so a REFUSED fit renders as
        # "not trained: degenerate reference" instead of as an ordinary absence.
        outcomes={name: str((row or {}).get("outcome") or "")
                  for name, row in data["model_training"].items()})
    data["detector_summary"] = detector_summary_for(
        data, calibration, report, settings, client)
    return web_api.models_payload(data)


def models_failure(exc: BaseException) -> dict[str, Any]:
    """The console's own failure shape for /api/models: 200 with the reason, never a 503."""
    from weirvern.admin.web import read_failure  # noqa: PLC0415

    logger.warning("model overview unavailable: %s", exc)
    return {"available": False, "reason": read_failure(exc)}


def scanner(client: Client) -> dict[str, Any]:
    """Scanner readiness for every REGISTERED weirling, plus the fleet's one-line verdict.

    A SENSOR WITH NO ROW IS NOT "basic". It is "not_reported", which is a different fact and
    needs the setup sheet rather than a clean-looking profile, so the missing rows are filled
    with that state and the install command for the OS the weirling reported.

    ONLY REGISTERED, ENABLED WEIRLINGS ARE THE FLEET. A status row left behind by a removed
    workload is not a scanner the operator can use, and listing it would inflate the count.
    """
    from weirvern import scanner as scanner_mod  # noqa: PLC0415
    from weirvern.admin.web import _gate_sensor_name  # noqa: PLC0415

    status_rows = client.query(
        "SELECT sensor_id, profile, nmap_available, nmap_version, nmap_path, "
        "       nse_available, os_id, os_version, detail, last_check, "
        "       privileged, scan_mode, can_install, sudo_state, os_label, os_family "
        "FROM weirvern.scanner_status FINAL ORDER BY sensor_id"
    ).result_rows
    registered = client.query(
        "SELECT sensor_id FROM weirvern.weirlings FINAL "
        "WHERE revoked_at IS NULL AND enabled = 1 ORDER BY sensor_id"
    ).result_rows

    status: dict[str, dict[str, Any]] = {}
    now = datetime.datetime.now(datetime.UTC)
    for row in status_rows:
        sid = str(row[0] or "").strip().lower()
        if not sid or sid in status:
            continue
        # A ROW IS A REPORT, NOT A VERDICT. `last_check` ages; when it is past the same window
        # `fleet_capability` uses, the row is marked `stale` and carries its age, so no surface
        # can read an old measurement as this weirling's current state.
        when = scanner_mod.checked_at(row[9])
        is_fresh, age_s = scanner_mod.freshness(when, now=now)
        status[sid] = {
            "sensor_id": sid,
            "profile": str(row[1] or "basic"),
            "nmap_available": bool(row[2]),
            "nmap_version": str(row[3] or ""),
            "nmap_path": str(row[4] or ""),
            "nse_available": bool(row[5]),
            "os_id": str(row[6] or ""),
            "os_version": str(row[7] or ""),
            "detail": str(row[8] or ""),
            "last_check": when.isoformat() if when is not None else "",
            "privileged": bool(row[10]) if len(row) > 10 else False,
            "scan_mode": scanner_mod.normalise_scan_mode(
                str(row[11] if len(row) > 11 else "")
                or ("syn/udp" if bool(row[2]) else "none")),
            "can_install": bool(row[12]) if len(row) > 12 else False,
            "sudo_state": str(row[13]) if len(row) > 13 else "",
            # THE LABEL IS THE DISTRO; THE FAMILY PICKS THE COMMAND. A row written before the
            # columns existed falls back to ID + version and derives the family from that.
            "os_label": str(row[14]) if len(row) > 14 else "",
            "os_family": str(row[15]) if len(row) > 15 else "",
            "state": "reported" if is_fresh else "stale",
            "fresh": is_fresh,
            "age_s": int(age_s) if age_s is not None else None,
            "age": scanner_mod.ago(age_s),
        }

    sensors: list[dict[str, Any]] = []
    for row in registered:
        sid = str(row[0] or "").strip().lower()
        item = status.get(sid)
        if item is None:
            item = {
                "sensor_id": sid, "profile": "unknown", "nmap_available": False,
                "nmap_version": "", "nmap_path": "", "nse_available": False,
                "os_id": "", "os_version": "", "os_label": "", "os_family": "",
                "detail": "no scanner status reported yet",
                "last_check": "", "privileged": False, "scan_mode": "unknown",
                "can_install": False, "sudo_state": "unknown", "state": "not_reported",
            }
        # THE COMMAND COMES FROM THE ID FIRST, THEN THE FAMILY -- the same order the agent uses.
        install = scanner_mod.nmap_install_command(
            item.get("os_id", ""), item.get("os_version", ""))
        if not install.get("known") and item.get("os_family"):
            install = scanner_mod.nmap_install_command(
                item.get("os_family", ""), item.get("os_version", ""))
        if not item.get("os_label"):
            name = str(item.get("os_id") or "").strip()
            version = str(item.get("os_version") or "").strip()
            item["os_label"] = " ".join(part for part in (name.title(), version) if part)
        item["install_command"] = install["command"]
        item["install_manager"] = install["manager"]
        item["install_known"] = install["known"]
        item["setcap_command"] = "sudo setcap cap_net_raw,cap_net_admin+eip /usr/bin/nmap"
        item["scan_mode_sentence"] = scanner_mod.scan_mode_sentence(item["scan_mode"])
        # THE ANSWER TO "CAN WEIRVERN INSTALL IT?" IS THE AGENT'S OWN MEASUREMENT, never a
        # hopeful assumption at the hub. Root, or the one scoped sudoers entry the installer
        # created, makes it yes; everything else is copy-and-instruct with the reason.
        # A STALE ROW'S PRIVILEGE FACTS ARE AS OLD AS THE ROW. Offering a one-click install from
        # a measurement that may predate the host's current state is the same unearned verdict
        # the card must not print, one layer down.
        if item.get("state") == "stale":
            item["install_privileged"] = False
            item["can_install"] = False
            item["install_answer"] = (
                f"No report from this weirling in {item.get('age') or 'the freshness window'}; "
                "its last report is too old to act on.")
        elif item.get("nmap_available"):
            # NOTHING TO INSTALL. The containerised agent ships Nmap, and a host-installed unit
            # that already has it needs no click either. Offering Install here would run a
            # package manager for a binary that is present (and, in a container, an install that
            # vanishes on the next recreate).
            item["install_privileged"] = False
            item["install_answer"] = (
                "Nmap is already installed on this weirling — nothing to install.")
        else:
            item["install_privileged"] = bool(item.get("can_install"))
            sudo_state = str(item.get("sudo_state") or "unknown")
            if item.get("can_install"):
                item["install_answer"] = "Weirvern can install nmap here (privileged installer path)"
            elif sudo_state == "password":
                item["install_answer"] = (
                    "Weirvern cannot install nmap here — the weirling's user has a sudo password, "
                    "but this build has no secret channel from the console to an agent. Run the "
                    "command below as root, or create the scoped sudoers entry.")
            elif sudo_state == "none":
                item["install_answer"] = (
                    "Weirvern cannot install nmap here — the weirling's user is not in sudoers; "
                    "run the command below as root")
            else:
                item["install_answer"] = (
                    "Weirvern cannot install nmap here — run this as root")
        item["install_url"] = "https://nmap.org/download.html"
        item["docs_url"] = "docs/deployment.md#asset-scanning-and-nmap"
        sensors.append(item)

    capability = scanner_mod.fleet_capability(client)
    return {
        "available": True, "reason": "", "sensors": sensors, "count": len(sensors),
        "local_sensor": _gate_sensor_name(),
        "capability": {
            "enabled": capability["enabled"],
            "sentence": capability["sentence"],
            "count": capability["count"],
            "capable_count": capability["capable_count"],
        },
    }


def scanner_failure(exc: BaseException) -> dict[str, Any]:
    """The console's own failure shape for /api/scanner, including its truncated message."""
    logger.warning("scanner readiness unavailable: %s", exc)
    return {"available": False,
            "reason": f"scanner readiness could not be read: {str(exc)[:200]}",
            "sensors": [], "count": 0}


def system_payload(*, sensor: str) -> dict[str, Any]:
    """The sensor host's CPU, memory and interface counters, read from procfs.

    A process-level read, not a database query, so an unavailable database cannot make the system
    cards disappear. A remote sensor has not reported host counters, and saying so is better than
    presenting the hub's numbers under another sensor's name.
    """
    from weirvern.admin import system_metrics  # noqa: PLC0415
    from weirvern.admin.web import _gate_sensor_name  # noqa: PLC0415

    if sensor and sensor != _gate_sensor_name():
        return {
            "available": False, "sensor": sensor,
            "reason": f"{sensor} has not reported host CPU, memory or interface counters",
            "history": [], "interfaces": [],
        }
    payload = system_metrics.sample()
    if sensor:
        payload["sensor"] = sensor
    return payload


# ── windowed reads: the arguments are part of the contract ──────────────────────────────────

def netflow(client: Client, *, hours: int, filters: dict) -> dict[str, Any]:
    """Netflow shape: volume trend, protocols, ports, fan-out, talkers.

    EVERY SUB-QUERY REPORTS ITS OWN STATE and a failure in one does not take the others down, so the
    charts beside a missing one still render. That is why the failure payload keeps a full shape
    rather than collapsing to a single reason.
    """
    from weirvern.admin import soc as soc_mod  # noqa: PLC0415

    try:
        volume = soc_mod.flow_volume_series(client, hours=hours, filters=filters)
        proto = soc_mod.protocol_mix(client, hours=hours, filters=filters)
        ports = soc_mod.top_ports(client, hours=hours, filters=filters)
        spread = soc_mod.destination_spread(client, hours=hours, filters=filters)
        # WHICH NIC EACH FLOW CAME THROUGH (0.23.70): its own read, so a failure here still
        # leaves the volume, protocol and port charts standing.
        interfaces = soc_mod.interface_mix(client, hours=hours, filters=filters)
        # THE TREND IS A SECOND READ, so a failure in it cannot blank the mix beside it.
        try:
            interfaces = {**interfaces,
                          "timeline": soc_mod.interface_series(client, hours=hours, filters=filters)}
        except Exception as exc:  # noqa: BLE001
            logger.warning("interface series unavailable: %s", exc)
            interfaces = {**interfaces,
                          "timeline": {"available": False, "reason": "the series read failed",
                                       "series": {}, "bucket_s": 0}}
        talkers = status_mod.top_talkers(client, hours=hours, limit=12, filters=filters)
        # The host lists are filtered; this says by how much, so a reader can tell "a quiet segment"
        # from "a noisy one with the noise hidden".
        noise = status_mod.noise_flows(client, hours=hours)
    except Exception as exc:  # noqa: BLE001
        return netflow_failure(exc)
    return web_api.netflow_payload(volume, proto, ports, spread, talkers, noise=noise,
                                   interfaces=interfaces)


def netflow_failure(exc: BaseException) -> dict[str, Any]:
    """The console's own failure shape for /api/netflow."""
    from weirvern.admin.web import read_failure  # noqa: PLC0415

    logger.warning("netflow view unavailable: %s", exc)
    empty = {"available": False, "reason": "the data could not be read", "points": []}
    return {"volume": dict(empty), "protocols": dict(empty), "ports": dict(empty),
            "spread": dict(empty),
            "talkers": {"available": False, "points": [], "reason": read_failure(exc)},
            "noise": {}, "data_error": read_failure(exc)}


def zeek(client: Client, *, hours: int, filters: dict) -> dict[str, Any]:
    """Zeek shape: per-log counts, protocol timeline, services, DNS names.

    The counts helper reports a table it could not count SEPARATELY from a table with no rows,
    because those are different facts and conflating them is how an empty panel comes to look like a
    quiet network.
    """
    from weirvern.admin import soc as soc_mod  # noqa: PLC0415

    try:
        counts = soc_mod.zeek_counts(client, hours=hours, filters=filters)
        timeline = soc_mod.zeek_timeline(client, hours=hours, filters=filters)
        services = soc_mod.zeek_services(client, hours=hours, filters=filters)
        dns = soc_mod.zeek_dns_names(client, hours=hours, filters=filters)
    except Exception as exc:  # noqa: BLE001
        return zeek_failure(exc)
    payload = web_api.zeek_payload(counts, timeline, services, dns)
    payload["filters"] = filters
    return payload


def zeek_failure(exc: BaseException, *, filters: dict | None = None) -> dict[str, Any]:
    """The console's own failure shape for /api/zeek, filters included.

    THE FILTERS ARE PART OF THE FAILURE PAYLOAD: the panel still shows what was asked for, so the
    reader can tell a bad window from a bad filter. The builder takes them because `_soft_route` can
    only pass the exception; the route binds them with `functools.partial`.
    """
    from weirvern.admin.web import read_failure  # noqa: PLC0415

    logger.warning("zeek view unavailable: %s", exc)
    empty = {"available": False, "reason": "the data could not be read", "points": []}
    return {"counts": dict(empty), "timeline": dict(empty), "services": dict(empty),
            "dns": dict(empty), "filters": filters or {}, "data_error": read_failure(exc)}


def flows(client: Client, *, hours: int, port: int | None, proto: int | None,
          src: str, dst: str) -> dict[str, Any]:
    """The hosts behind one destination port, one IP protocol, or one address."""
    from weirvern.admin import soc as soc_mod  # noqa: PLC0415

    try:
        return soc_mod.flows_matching(client, port=port, proto=proto, src=src, dst=dst,
                                      hours=hours)
    except Exception as exc:  # noqa: BLE001
        return flows_failure(exc)


def flows_failure(exc: BaseException) -> dict[str, Any]:
    """The console's own failure shape for /api/flows."""
    from weirvern.admin.web import read_failure  # noqa: PLC0415

    logger.warning("flow drill-down unavailable: %s", exc)
    return {"available": False, "points": [], "reason": read_failure(exc),
            "data_error": str(exc)}


def dns(client: Client, *, hours: int, domain: str, client_ip: str, qtype: int | None,
        rcode: int | None, limit: int, offset: int) -> dict[str, Any]:
    """The DNS view: Q/A rows, filters, histogram and facets."""
    from weirvern.admin import soc as soc_mod  # noqa: PLC0415

    try:
        return soc_mod.dns_rows(client, hours=hours, domain=domain, client_ip=client_ip,
                                qtype=qtype, rcode=rcode, limit=limit, offset=offset)
    except Exception as exc:  # noqa: BLE001
        return dns_failure(exc)


def dns_failure(exc: BaseException) -> dict[str, Any]:
    """The console's own failure shape for /api/dns."""
    from weirvern.admin.web import read_failure  # noqa: PLC0415

    logger.warning("dns view unavailable: %s", exc)
    return {"available": False, "rows": [], "reason": read_failure(exc),
            "data_error": str(exc)}


# ── the address-validated detail reads: a 503 on failure, by design ─────────────────────────
#
# These four RAISE and the surface answers 503, which is different from the panels above: a detail
# page has nothing to draw without its subject, so an error page is the honest answer rather than a
# card-shaped 200 saying "unavailable". The difference is the console's and it is preserved.

def host(client: Client, *, addr: str, hours: int) -> dict[str, Any]:
    """One host's detail, with the scanner exposure as an ANNOTATION.

    A missing exposure table is reported inside `exposure.available` and rendered as "unavailable",
    never as a reason to fail the page -- the host detail is the load-bearing read, the scanner is
    the extra.
    """
    from weirvern.admin import assets as assets_mod  # noqa: PLC0415

    detail = status_mod.host_detail(client, addr, hours=hours)
    try:
        exposure = assets_mod.asset_exposure(client, addr)
    except Exception as exc:  # noqa: BLE001
        logger.warning("host exposure unavailable for %s: %s", addr, exc)
        exposure = {"available": False, "reason": "the scanner exposure read failed",
                    "registered": False, "state": "unknown", "exposure": "unknown",
                    "services": [], "findings": [], "counts": {}}
    payload = web_api.host_payload(detail)
    payload["exposure"] = exposure
    return payload


def evidence(client: Client, *, addr: str, start: str, end: str | None) -> dict[str, Any]:
    """The alert-evidence pivot: the RAW records inside one detection window."""
    return web_api.evidence_payload(status_mod.alert_evidence(client, addr, start, end))


def incident(client: Client, *, addr: str, start: str) -> dict[str, Any]:
    """One incident object: actor, asset, window, evidence and review provenance."""
    return web_api.incident_payload(status_mod.incident_detail(client, addr, start))


def fingerprints(client: Client, *, ja4: str) -> dict[str, Any]:
    """Which hosts have presented a given JA4 fingerprint -- the hunting pivot."""
    return status_mod.fingerprint_hosts(client, ja4)


def normalized_seeds(client: Client) -> dict[str, Any]:
    """What the baseline has learned from the Normalize tab, by lane.

    THE ML TAB HAS TO SAY THIS (operator, 2026-11-19: "look at our newest ML engine and all the
    work we have been doing. then update the ml tab"). Normalizing traffic changes what the
    Adaptive Baseline considers normal, and nothing on the Models tab mentioned it -- so the tab
    described a pipeline with a whole input missing.
    """
    try:
        res = client.query(
            "SELECT source, count() FROM weirvern.normal_traffic FINAL "
            "WHERE status != 'removed' GROUP BY source ORDER BY source")
    except Exception as exc:  # noqa: BLE001 - a panel, not a page
        logger.warning("normalized pattern count unavailable: %s", exc)
        return {"available": False, "total": 0, "by_source": {}}
    by_source = {str(r[0]): int(r[1]) for r in (getattr(res, "result_rows", None) or [])}
    return {"available": True, "total": sum(by_source.values()), "by_source": by_source}


def model_training(client: Client) -> dict[str, dict[str, Any]]:
    """The newest training run per model, from the engine's own table.

    The Models tab used to read only the curated card registry (frozen at its approval date) and
    the last OPERATOR-requested retrain (an action row). Neither says what the engine has been
    doing, so a month-old operator candidate and an eight-day-old registry looked like the present
    while every detector retrained that morning.
    """
    try:
        res = client.query(
            # ALIASES MUST NOT SHARE A COLUMN'S NAME (ClickHouse Code 184): `AS trained_at`
            # made the alias visible inside `max(trained_at)`, which the engine refuses as
            # "aggregate function found inside another aggregate". Same class as bytes_total.
            #
            # `last_metrics` carries the REFUSAL record: a cross-sectional detector whose
            # reference was degenerate writes a row with `{"refused": true}` and no artifact.
            # Without reading it here the Detectors table cannot say "not trained: degenerate
            # reference" and would render the refusal as an ordinary training run.
            "SELECT model_type, toString(max(trained_at)) AS last_trained, "
            "toString(max(training_window_end)) AS last_window_end, "
            "argMax(training_sample_count, trained_at) AS samples, "
            "argMax(metrics, trained_at) AS last_metrics "
            "FROM weirvern.ml_models GROUP BY model_type")
    except Exception as exc:  # noqa: BLE001 - a missing table is a panel, not a page
        logger.warning("model training history unavailable: %s", exc)
        return {}
    out: dict[str, dict[str, Any]] = {}
    for row in (getattr(res, "result_rows", None) or []):
        name, trained_at, window_end, samples, metrics = (list(row) + ["", "", "", 0, ""])[:5]
        outcome = ""
        refused = False
        try:
            parsed = json.loads(metrics) if metrics else {}
        except (TypeError, ValueError):
            parsed = {}
        if isinstance(parsed, dict):
            outcome = str(parsed.get("outcome") or "")
            refused = bool(parsed.get("refused", False))
        out[str(name)] = {"trained_at": str(trained_at), "window_end": str(window_end),
                          "samples": int(samples or 0), "outcome": outcome, "refused": refused}
    return out


def calibration_latest(client: Client) -> dict[str, dict[str, Any]]:
    """The newest calibration row per model, with the fused score under its own name.

    ONE ROW PER NAME. `ml_calibration` is a ReplacingMergeTree keyed by
    (model_name, scope, subject, statistic), so FINAL can still leave several rows for one model
    when a scope or subject changed; argMax takes the newest measurement rather than whichever row
    the engine happened to return first.

    A FAILED READ IS AN EMPTY MAPPING, and the detector summary then says nothing is measured. The
    table is a panel, not a page: the rest of the Models view still has to draw.
    """
    try:
        res = client.query(
            "SELECT model_name, argMax(observed_far, computed_at), "
            "argMax(target_far, computed_at), argMax(coverage, computed_at), "
            "argMax(excluded_windows, computed_at), argMax(coverage_detail, computed_at), "
            "argMax(coverage_observed, computed_at), argMax(coverage_expected, computed_at), "
            "argMax(missing_mode, computed_at), argMax(validation_count, computed_at), "
            "argMax(threshold, computed_at), argMax(far_lower, computed_at), "
            "argMax(far_upper, computed_at), argMax(model_version, computed_at), "
            "argMax(computed_at, computed_at) "
            "FROM weirvern.ml_calibration FINAL WHERE scope = 'global' GROUP BY model_name")
    except Exception as exc:  # noqa: BLE001 - a missing table is a panel, not a page
        # THE COVERAGE COLUMNS ARRIVED IN 056 AND THE COUNTS IN 058. A deployment still on an
        # older schema must not lose the whole Detectors table to a field only the missing-data
        # path writes, so the read falls back through the column sets it has. The row then says
        # `coverage not recorded` -- which is the truth about that deployment, not a default.
        logger.warning("calibration coverage columns unavailable (%s); detector coverage will "
                       "read as not measured", exc)
        res = None
        try:
            res = client.query(
                "SELECT model_name, argMax(observed_far, computed_at), "
                "argMax(target_far, computed_at), argMax(coverage, computed_at), "
                "argMax(excluded_windows, computed_at) "
                "FROM weirvern.ml_calibration FINAL WHERE scope = 'global' GROUP BY model_name")
        except Exception as exc2:  # noqa: BLE001
            logger.warning("calibration coverage columns unavailable (%s); falling back to the "
                           "pre-056 shape", exc2)
            try:
                res = client.query(
                    "SELECT model_name, argMax(observed_far, computed_at), "
                    "argMax(target_far, computed_at) "
                    "FROM weirvern.ml_calibration FINAL WHERE scope = 'global' "
                    "GROUP BY model_name")
            except Exception as exc3:  # noqa: BLE001
                logger.warning("model calibration rows unavailable: %s", exc3)
                return {}
    out: dict[str, dict[str, Any]] = {}
    for row in (getattr(res, "result_rows", None) or []):
        values = list(row) + [None] * 15
        out[str(values[0])] = {
            "observed_far": values[1],
            "target_far": values[2],
            "coverage": values[3],
            "excluded_windows": values[4],
            "coverage_detail": values[5] or "",
            "coverage_observed": values[6],
            "coverage_expected": values[7],
            "missing_mode": values[8] or "",
            # THE SAMPLE AND THE INTERVAL: a FAR without them is the reading this release fixes.
            "validation_count": values[9],
            "threshold": values[10],
            "far_lower": values[11],
            "far_upper": values[12],
            # THE VERSION AND THE INSTANT make the rate reproducible: the report measures the
            # decision-bar rate over the same population (same engine version, same window).
            "model_version": str(values[13] or ""),
            "computed_at": values[14],
        }
    return out


def _number(value: Any) -> float | None:
    """A finite float, or None. A blank/garbage cell is absence, never zero."""
    try:
        out = float(value)
    except (TypeError, ValueError):
        return None
    return out if math.isfinite(out) else None


def fused_far_counts(client: Client, thresholds: list[float], *, model_version: str = "",
                     days: int = 7) -> tuple[int, list[int]] | None:
    """Count the fused population at each threshold, in ONE read.

    The report must compare two thresholds on the SAME windows. Counting them in one aggregate
    over `ml_window_scores` (the population the ensemble scored before any alert gate) makes the
    two rates directly comparable and avoids shipping every score into Python.

    `model_version` is the version the calibration row was measured under. A reference that
    straddles a model change is the mixture `calibration._population_scores` already refuses, and
    the report must not reintroduce it through a different query.
    """
    bars = [float(t) for t in thresholds if math.isfinite(float(t))]
    if not bars:
        return None
    columns = ", ".join(f"countIf(score >= {bar:.10g})" for bar in bars)
    sql = ("SELECT count(), " + columns + " FROM weirvern.ml_window_scores FINAL "
           "WHERE model_name = %(name)s AND computed_at >= now() - INTERVAL %(days)s DAY")
    params: dict[str, Any] = {"name": FUSED_MODEL, "days": int(days)}
    if model_version:
        sql += " AND model_version = %(version)s"
        params["version"] = str(model_version)
    try:
        rows = client.query(sql, parameters=params).result_rows
    except Exception as exc:  # noqa: BLE001 - a panel, not a page
        logger.warning("fused false-alarm population unavailable: %s", exc)
        return None
    if not rows:
        return None
    values = list(rows[0])
    if not values or values[0] is None:
        return None
    try:
        windows = int(values[0])
        hits = [int(value or 0) for value in values[1:]]
    except (TypeError, ValueError):
        return None
    return windows, hits


def detector_summary_for(data: dict[str, Any], calibration: dict[str, dict[str, Any]],
                          report: Any, settings: Any, client: Client) -> str:
    """The Models card's headline, measured at the bar the running decision uses.

    WHICH BAR THAT IS. `ensemble.detect_flows` compares the fused score against
    `settings.base_threshold` when every active member has a calibrated threshold (the per-detector
    scale is active); otherwise it compares against the fused calibration's own conformal
    threshold. The report must name the one in force, and show the other beside it, or the number
    and the behaviour disagree.
    """
    from weirvern.models.detector_status import (  # noqa: PLC0415
        detector_summary,
        far_reading_from_counts,
    )

    fused = calibration.get(FUSED_MODEL)
    if fused is None:
        return detector_summary(data.get("detectors") or [], None)
    calibration_threshold = _number(fused.get("threshold"))
    if report is None and bool(getattr(settings, "ml_calibrated_threshold", True)):
        # THE MEMBERSHIP COULD NOT BE MEASURED, so the bar in force is unknown. Do not let the
        # calibration threshold stand in for it: say the decision bar was not measured.
        return detector_summary(
            data.get("detectors") or [], fused,
            decision_threshold=float(getattr(settings, "base_threshold", 0.35) or 0.35))
    members = [decision for decision in (getattr(report, "decisions", {}) or {}).values()
               if getattr(decision, "contributing", False)]
    scaled = (bool(getattr(settings, "ml_calibrated_threshold", True))
              and bool(members) and all(
                  getattr(getattr(decision, "evidence", None), "threshold", None) is not None
                  for decision in members))
    decision_threshold = (float(getattr(settings, "base_threshold", 0.35) or 0.35)
                          if scaled else calibration_threshold)
    if decision_threshold is None:
        return detector_summary(data.get("detectors") or [], fused)

    wanted = [decision_threshold]
    if calibration_threshold is not None and abs(calibration_threshold - decision_threshold) > 1e-12:
        wanted.append(calibration_threshold)
    days = int(getattr(settings, "ml_calibration_days", 7) or 7)
    counts = fused_far_counts(client, wanted, model_version=str(fused.get("model_version") or ""),
                              days=days)
    if counts is None:
        return detector_summary(data.get("detectors") or [], fused,
                                decision_threshold=decision_threshold)
    windows, hits = counts
    decision = far_reading_from_counts(decision_threshold, hits[0], windows)
    calibration_reading = None
    if len(wanted) > 1 and len(hits) > 1:
        calibration_reading = far_reading_from_counts(wanted[1], hits[1], windows)
    return detector_summary(data.get("detectors") or [], fused,
                            decision=decision, calibration=calibration_reading)


def model_retrain(client: Client) -> dict[str, Any]:
    """The last forced retrain: what state it is in, and what it produced.

    A FAILED read is a 200 with `available: false` and the reason, like every other panel: an error
    page for one card would take down the views around it, and an empty report would read as
    "nothing has been trained".
    """
    from weirvern.models import actions  # noqa: PLC0415

    try:
        row = actions.latest(client, actions.RETRAIN)
        decision = (actions.latest(client, actions.KEEP)
                    or actions.latest(client, actions.TRASH))
    except Exception as exc:  # noqa: BLE001
        return model_retrain_failure(exc)
    return web_api.retrain_payload(row, decision, training=model_training(client))


def model_retrain_failure(exc: BaseException) -> dict[str, Any]:
    """The console's own failure shape for /api/models/retrain."""
    from weirvern.admin.web import read_failure  # noqa: PLC0415

    logger.warning("model retrain state unavailable: %s", exc)
    return web_api.retrain_payload(None, None, available=False, reason=read_failure(exc))


def _annotate_ripple_signals(payload: dict[str, Any], rows: list[dict[str, Any]]) -> None:
    """Put each host's ripple count/band on the node and both ends of every edge.

    THE SERVER COMPUTES THE BAND ONCE. The browser renders `ripple_worst`; a second mapping in
    JavaScript would drift from the Alerts tab the day the bands move. `ripple_count` is the
    number of ripple WINDOWS in this range (a host can ripple in several hours), so the host
    table's "ripples N" is a count of findings, not a boolean.
    """
    ranks = {"low": 1, "medium": 2, "high": 3}
    summary: dict[str, dict[str, Any]] = {}
    for row in rows or []:
        host = str(row.get("host") or "")
        if not host:
            continue
        item = summary.setdefault(host, {"count": 0, "worst": "", "families": set()})
        item["count"] += 1
        band = str(row.get("severity") or "").lower()
        if ranks.get(band, 0) > ranks.get(item["worst"], 0):
            item["worst"] = band
        item["families"].update(str(f) for f in (row.get("families") or []))
    for node in payload.get("nodes") or []:
        hit: dict[str, Any] | None = summary.get(str(node.get("id") or ""))
        node["ripple_count"] = int(hit["count"]) if hit else 0
        node["ripple_worst"] = hit["worst"] if hit else ""
        node["ripple_families"] = sorted(hit["families"]) if hit else []
    for edge in payload.get("edges") or []:
        for side in ("source", "target"):
            hit = summary.get(str(edge.get(side) or ""))
            edge[f"{side}_ripple_count"] = int(hit["count"]) if hit else 0
            edge[f"{side}_ripple_worst"] = hit["worst"] if hit else ""


def _attach_ripples(client: Client, payload: dict[str, Any], *, hours: int) -> dict[str, Any]:
    """Attach the window's ripples (and the ONE band table) to a graph payload.

    THE NETWORK TAB MUST NOT READ A SECOND MAPPING. `/api/ripples` groups the evidence; this
    reuses that exact read at the graph's EFFECTIVE window (`payload["hours"]`, which the graph
    may have narrowed), so a ring/chip on the map and a row on the Ripples tab are the same
    ripple with the same server-computed `severity`. A failed ripple read is named in the
    payload rather than drawn as "no ripples".

    THE COVERAGE TRAVELS WITH THE ROWS. `ml_ripple_evidence` on this deployment began
    2026-11-19 14:00 -- one day, not seven. A 7d request therefore has a one-day ripple reading,
    and the payload says so (`ripple_coverage`) instead of letting the empty older hours read as
    a quiet network.
    """
    from weirvern.models import ripple_evidence  # noqa: PLC0415

    effective = int(payload.get("hours") or hours)
    coverage: dict[str, Any] = {"from": "", "to": "", "available": False, "reason": ""}
    try:
        cov = client.query(
            "SELECT min(window_start), max(window_end) FROM weirvern.ml_ripple_evidence")
        row = (getattr(cov, "result_rows", None) or [None])[0]
        if row and row[0] is not None:
            coverage = {"from": row[0].isoformat(), "to": row[1].isoformat(),
                        "available": True, "reason": ""}
        else:
            coverage.update({"available": True, "reason": "no ripple evidence stored yet"})
    except Exception as exc:  # noqa: BLE001 - coverage is an annotation, not the graph
        logger.warning("graph ripple coverage unavailable: %s", exc)
        coverage["reason"] = f"{type(exc).__name__}: {str(exc)[:120]}"

    try:
        data = ripple_evidence.overview(client, hours=effective)
    except Exception as exc:  # noqa: BLE001 - the graph still stands without ripple presence
        logger.warning("graph ripple presence unavailable: %s", exc)
        payload.update({"ripples": [], "ripple_available": False,
                        "ripple_reason": f"{type(exc).__name__}: {str(exc)[:160]}",
                        "ripple_window_hours": effective,
                        "ripple_coverage": coverage,
                        "severity_bands": ripple_evidence.severity_bands()})
        _annotate_ripple_signals(payload, [])
        return payload
    rows = data.get("ripples") or []
    payload.update({
        "ripples": rows,
        "ripple_available": bool(data.get("available")),
        "ripple_reason": data.get("reason") or "",
        "ripple_window_hours": int(data.get("window_hours") or effective),
        "ripple_coverage": coverage,
        "severity_bands": data.get("severity_bands") or ripple_evidence.severity_bands(),
    })
    # WHICH CHANNELS THIS DEPLOYMENT CAN NAME A VALUE ON. The signature capability is computed
    # from the specs server-side; the sheet must not keep a second list.
    payload["signature_channels"] = data.get("signature_channels") or []
    _annotate_ripple_signals(payload, rows)
    return payload


def _attach_normalized(client: Client, payload: dict[str, Any]) -> dict[str, Any]:
    """Mark hosts whose traffic has a normalized baseline pattern.

    `normal_ripple_signatures` is EMPTY on this deployment today, and that is a measured zero:
    the table read succeeded and holds no active rows. A failed read is `normalized_available:
    false`, never "nothing is normalized" -- the two must not look alike on the map.
    """
    try:
        res = client.query(
            "SELECT host_addr, count() FROM weirvern.normal_ripple_signatures FINAL "
            "WHERE removed_at IS NULL GROUP BY host_addr")
        counts = {str(r[0]): int(r[1] or 0) for r in (getattr(res, "result_rows", None) or [])}
        payload["normalized_available"] = True
        payload["normalized_reason"] = ""
        for node in payload.get("nodes") or []:
            node["normalized_count"] = counts.get(str(node.get("id") or ""), 0)
    except Exception as exc:  # noqa: BLE001 - the graph draws without this annotation
        logger.warning("graph normalized presence unavailable: %s", exc)
        payload["normalized_available"] = False
        payload["normalized_reason"] = f"{type(exc).__name__}: {str(exc)[:120]}"
        for node in payload.get("nodes") or []:
            node.pop("normalized_count", None)
    return payload


def graph(client: Client, *, hours: int, tracked: list[str], sensor: str = "") -> dict[str, Any]:
    """The connection graph, optionally restricted to tracked hosts and to one weirling's segment.

    AN EMPTY SELECTION MEANS NO RESTRICTION and returns the whole graph, which is what an operator
    expects from a cleared multi-select. `sensor` narrows the map to one sensor's segment plus the
    peers its hosts talk to, so a deployment with several locations can read one at a time instead
    of one hairball.

    RIPPLE PRESENCE RIDES THE SAME PAYLOAD. A host node and every edge it touches can then show
    the severity the Ripples page shows, without the Network view re-deriving a bar it does not own.
    """
    from weirvern.admin import assets as assets_mod  # noqa: PLC0415

    try:
        if tracked:
            payload = assets_mod.top_edges_for(client, tracked, hours=hours)
            payload.setdefault("tracked", tracked)
            payload = _attach_normalized(client, _attach_ripples(client, payload, hours=hours))
        else:
            payload = _attach_normalized(
                client, _attach_ripples(client, assets_mod.connection_graph(client, hours=hours),
                                        hours=hours))
        if sensor:
            payload = _restrict_to_sensor(client, payload, sensor)
        return payload
    except Exception as exc:  # noqa: BLE001
        return graph_failure(exc)


def _restrict_to_sensor(client: Client, payload: dict[str, Any], sensor_id: str) -> dict[str, Any]:
    """Keep the sensor's own segment and one hop of peers, and say what was applied.

    THE PEERS ARE THE POINT. A site map that dropped the web and the DMZ would show a cluster of
    clients talking to nothing; the interesting question is what this location reaches. Nodes
    inside the segment are kept, plus every node on an edge touching one of them.
    """
    import ipaddress  # noqa: PLC0415

    try:
        rows = client.query(
            "SELECT segment FROM weirvern.weirlings WHERE sensor_id = %(s)s "
            "ORDER BY updated_at DESC LIMIT 1",
            parameters={"s": sensor_id},
        ).result_rows
    except Exception:  # noqa: BLE001
        rows = []
    segment = str(rows[0][0]) if rows else ""
    if not segment:
        payload["sensor"] = {"id": sensor_id, "available": False,
                             "reason": f"no weirling named {sensor_id!r} has a segment"}
        return payload
    try:
        net = ipaddress.ip_network(segment, strict=False)
    except ValueError:
        payload["sensor"] = {"id": sensor_id, "available": False,
                             "reason": f"the segment {segment!r} is not a network"}
        return payload

    def inside(addr: str) -> bool:
        try:
            return ipaddress.ip_address(str(addr)) in net
        except ValueError:
            return False

    nodes = payload.get("nodes") or []
    edges = payload.get("edges") or []
    own = {n.get("id") for n in nodes if inside(n.get("id"))}
    keep = set(own)
    for edge in edges:
        if edge.get("source") in own:
            keep.add(edge.get("target"))
        if edge.get("target") in own:
            keep.add(edge.get("source"))
    payload["nodes"] = [n for n in nodes if n.get("id") in keep]
    payload["edges"] = [e for e in edges
                        if e.get("source") in keep and e.get("target") in keep]
    payload["sensor"] = {"id": sensor_id, "segment": segment, "hosts": len(own),
                         "available": True}
    return payload


def network_host(client: Client, *, addr: str, hours: int) -> dict[str, Any]:
    """One host's investigation sheet for the Network tab.

    It reads the SAME ripple grouping `/api/ripples` renders and the same anomaly table the
    Alerts queue reads; it is a second VIEW of those facts, never a second definition.
    """
    from weirvern.admin import network_host as host_mod  # noqa: PLC0415

    try:
        return host_mod.host_sheet(client, addr, hours=hours)
    except Exception as exc:  # noqa: BLE001
        return host_mod.host_sheet_failure(exc, addr=addr, hours=hours)


def network_host_failure(exc: BaseException, *, addr: str = "", hours: int = 24) -> dict[str, Any]:
    from weirvern.admin import network_host as host_mod  # noqa: PLC0415

    return host_mod.host_sheet_failure(exc, addr=addr, hours=hours)


def graph_failure(exc: BaseException) -> dict[str, Any]:
    """The console's own failure shape for /api/graph."""
    from weirvern.admin.web import read_failure  # noqa: PLC0415
    from weirvern.models import ripple_evidence  # noqa: PLC0415

    logger.warning("graph unavailable: %s", exc)
    return {"available": False, "nodes": [], "edges": [], "ripples": [],
            "ripple_available": False, "ripple_reason": read_failure(exc),
            "ripple_coverage": {"from": "", "to": "", "available": False,
                                "reason": "the graph did not load"},
            "normalized_available": False, "normalized_reason": read_failure(exc),
            "severity_bands": ripple_evidence.severity_bands(),
            "reason": read_failure(exc), "data_error": str(exc)}


def blocked(client: Client, *, hours: int, domain: str, client_ip: str, limit: int,
            offset: int) -> dict[str, Any]:
    """The Blocked tab: hits, live blocks, live alerts and the gate state, in one read."""
    from weirvern import sluice_store  # noqa: PLC0415
    from weirvern.admin import soc as soc_mod  # noqa: PLC0415
    from weirvern.admin.web import _gate_sensor_name  # noqa: PLC0415

    try:
        gate = sluice_store.load_gate_state(client, sensor=_gate_sensor_name())
        return soc_mod.blocked_view(
            client, hours=hours, domain=domain, client_ip=client_ip,
            limit=limit, offset=offset, gate=gate,
        )
    except Exception as exc:  # noqa: BLE001
        return blocked_failure(exc)


def blocked_failure(exc: BaseException) -> dict[str, Any]:
    """The console's own failure shape for /api/blocked."""
    from weirvern.admin.web import read_failure  # noqa: PLC0415

    logger.warning("blocked view unavailable: %s", exc)
    return {"available": False, "hits": [], "reason": read_failure(exc),
            "data_error": str(exc)}


def zeeklog(client: Client, *, hours: int, table: str, label: str,
            filters: dict) -> dict[str, Any]:
    """Per-log detail for ONE Zeek log, for click-through from the Zeek view.

    `table` is resolved from the label ALLOW-LIST before it ever reaches the SQL text, which is why
    the parser returns both: the table name is never interpolated from the request.
    """
    from weirvern.admin import soc as soc_mod  # noqa: PLC0415

    try:
        return soc_mod.zeek_log_hosts(client, table=table, label=label, hours=hours,
                                      filters=filters)
    except Exception as exc:  # noqa: BLE001
        return zeeklog_failure(exc, label=label)


def zeeklog_failure(exc: BaseException, *, label: str = "") -> dict[str, Any]:
    """The console's own failure shape for /api/zeeklog, naming the log that was asked for."""
    from weirvern.admin.web import read_failure  # noqa: PLC0415

    logger.warning("zeek log detail unavailable: %s", exc)
    return {"available": False, "points": [], "log": label,
            "reason": read_failure(exc), "data_error": str(exc)}


def update_meta(backend: Any, *, refresh: bool) -> dict[str, Any]:
    """Release metadata for Settings -> Software update.

    READ-ONLY: this answers "is there a newer release" and never changes the running deployment.
    Applying an update remains a pipeline operation, not an HTTP verb. A backend that cannot report
    its version falls back to the package version rather than failing the card.
    """
    from weirvern.admin import update as update_mod  # noqa: PLC0415

    try:
        current = status_mod._running_version(backend)
    except Exception:  # noqa: BLE001
        from weirvern import __version__  # noqa: PLC0415

        current = __version__
    return update_mod.check(current, refresh=refresh)


def health_deep(client: Client, *, settings: Any, user_store: Any, hours: int) -> dict[str, Any]:
    """DEEP health: the checks, the ingestion trend, table sizes, the sensor, and the alert audit.

    NOT the liveness probe. /api/healthz answers without touching the database so a slow database
    cannot restart the GUI; this one reads it, because "is data still arriving" cannot be answered
    otherwise.
    """
    from weirvern.admin import soc as soc_mod  # noqa: PLC0415

    try:
        report = status_mod.collect_health(client, settings, user_store=user_store)
        sensor = status_mod.sensor_status(client)
        ingest = soc_mod.ingestion_series(client, hours=hours)
        sizes = soc_mod.table_sizes(client)
        # SOC-8: the alert audit rides on the health payload. It answers the same question ("is the
        # system doing what it should") and does not deserve a route nobody would look at.
        audit = soc_mod.alert_audit(client, hours=hours)
    except Exception as exc:  # noqa: BLE001
        return health_deep_failure(exc)
    return web_api.health_deep_payload(report, ingest, sizes, sensor, audit)


def health_deep_failure(exc: BaseException) -> dict[str, Any]:
    """The console's own failure shape for /api/health: a full shape, with `health: null`."""
    from weirvern.admin.web import read_failure  # noqa: PLC0415

    logger.warning("health view unavailable: %s", exc)
    empty = {"available": False, "reason": "the data could not be read", "points": []}
    audit = {"available": False, "reason": "the data could not be read", "by_reason": [],
             "recent": [], "suppressed": 0, "total": 0, "truncated": False, "names": {}}
    return {"health": None, "ingest": dict(empty), "tables": dict(empty), "sensor": {},
            "alerts": audit, "data_error": read_failure(exc)}


def overview(with_client: Any, *, backend: Any, settings: Any, user_store: Any,
             capabilities: Any) -> dict[str, Any]:
    """The landing payload: services, health report, recent anomalies, talkers and the sensor.

    TAKES A CONNECTION FACTORY, NOT A CLIENT, and that is deliberate: the service list comes from
    the backend and is read BEFORE the database is touched, so a database that will not connect
    still leaves the page with something true to say. A fetcher handed an open client would lose
    that half the moment the connect failed.
    """
    services: list = []
    if backend is not None:
        try:
            services = backend.ps()
        except Exception as exc:  # noqa: BLE001
            logger.debug("backend.ps failed: %s", exc)

    report = None
    anomalies: list = []
    # A STATE, NOT AN EMPTY LIST (issue #13): if the read below fails, the payload says so; an
    # empty list would render as a quiet network.
    talkers: dict = {"available": False, "reason": "the overview read did not run", "points": []}
    sensor: dict = {}
    data_error = None
    try:
        with with_client() as client:
            report = status_mod.collect_health(client, settings, user_store=user_store)
            anomalies = status_mod.anomalies_detailed(client, limit=25)
            talkers = status_mod.top_talkers(client, limit=10)
            # What the sensor reports about itself: separate from the health checks above, which
            # answer "is data flowing", not "what is the sensor doing".
            sensor = status_mod.sensor_status(client)
    except Exception as exc:  # noqa: BLE001
        # WARNING, not debug, and surfaced in the payload. This was debug once, and the effect was
        # a page that rendered every panel empty with no explanation anywhere.
        data_error = str(exc)[:300]
        logger.warning("overview data unavailable: %s", exc)

    payload = web_api.overview_payload(
        services, report, anomalies, talkers, capabilities, sensor=sensor)
    payload["data_error"] = data_error
    return payload


def weirlings_detail(client: Client, *, sensor_id: str) -> dict[str, Any]:
    """One sensor, for the drill-down, through the same classifier the list uses."""
    from weirvern import fleet_store  # noqa: PLC0415
    from weirvern.admin.web import _gate_sensor_name  # noqa: PLC0415

    try:
        row = fleet_store.classify_one(client, sensor_id)
    except Exception as exc:  # noqa: BLE001
        return weirlings_detail_failure(exc)
    if row is None:
        # DELIBERATELY A 200 with `available: true` and a null sensor: "there is no such sensor" is
        # an ANSWER, not a failure, and an error would send the operator looking for an outage.
        return {
            "available": True, "reason": None, "sensor": None,
            "note": (f"no sensor named {sensor_id!r} is registered or reporting. It may "
                     f"have been revoked, or the spelling may differ."),
        }
    # Same local marker as the list, from the same source: the drill-down decides from it whether
    # to mount the sensor's settings or the note saying where they are.
    row["local"] = (row.get("sensor_id") == _gate_sensor_name())
    return {"available": True, "reason": None, "sensor": row}


def weirlings_detail_failure(exc: BaseException) -> dict[str, Any]:
    """The console's own failure shape for /api/weirlings/detail."""
    logger.warning("weirlings detail unavailable: %s", exc)
    return {"available": False,
            "reason": f"the sensor could not be read: {str(exc)[:200]}",
            "sensor": None}


def weirlings_probe(client: Client, *, request_id: str) -> tuple[int, dict[str, Any]]:
    """Read one queued or complete capture probe.

    RETURNS (STATUS, PAYLOAD), because this route's contract is not one status: a missing request is
    a 404 with its own body, a failed read a 503, and a found one a 200. Collapsing that into one
    code would tell the operator the wrong thing about which of the three happened.
    """
    from weirvern import probe_store  # noqa: PLC0415

    try:
        row = probe_store.get_request(client, request_id)
    except Exception as exc:  # noqa: BLE001
        return weirlings_probe_failure(exc)
    if row is None:
        return 404, {"ok": False, "error": "no such capture probe"}
    result = None
    if row.get("result"):
        try:
            result = json.loads(str(row["result"]))
        except ValueError:
            result = None
    return 200, {
        "ok": True,
        "request_id": row["request_id"],
        "sensor_id": row["sensor_id"],
        "iface": row.get("iface", ""),
        "seconds": int(row.get("seconds") or 0),
        "status": row.get("status", ""),
        "result": result,
        "error": row.get("error", ""),
    }


def weirlings_probe_failure(exc: BaseException) -> tuple[int, dict[str, Any]]:
    """The console's own failure for a probe read: 503 with its own body, not the house error shape."""
    logger.warning("capture probe read failed: %s", exc)
    return 503, {"ok": False, "error": f"the probe could not be read: {str(exc)[:200]}"}


def users_list(*, store: Any, accounts_on: bool, note: str) -> dict[str, Any]:
    """Every account, for an admin. Reads are admin-only: the account list is not monitoring data.

    The ROLE GATE lives in the caller, not here: this function answers "what are the accounts", and
    both surfaces check the role before calling it.
    """
    from weirvern.admin import users as users_mod  # noqa: PLC0415

    if store is None or not accounts_on:
        return {"available": False, "users": [],
                "reason": note or "no accounts provisioned"}
    return {"available": True, "users": store.public_users(),
            "roles": list(users_mod.ROLES)}


ACCOUNTS_UNAVAILABLE = "the account store is not available on this GUI"
TOKENS_UNAVAILABLE = "the token store is not available on this GUI"


def tokens_list(*, store: Any) -> dict[str, Any]:
    """Every token record, revoked ones included, with the digest removed.

    REVOKED ROWS ARE KEPT. A revoke disappears from the live credential set but not from the
    operator's view of what happened; hiding it would make "did I revoke the right one?" a question
    the GUI cannot answer. `public()` carries `revoked` so the row can say which state it is in.

    NO PLAINTEXT AND NO DIGEST EVER APPEARS HERE. The only credential-shaped field is `prefix`, the
    eight-character display label.
    """
    from weirvern.admin import users as users_mod  # noqa: PLC0415

    if store is None:
        return {"available": False, "tokens": [], "roles": list(users_mod.ROLES),
                "reason": TOKENS_UNAVAILABLE}
    return {"available": True, "tokens": store.public_tokens(), "roles": list(users_mod.ROLES)}


def token_create(store: Any, *, name: str, role: str,
                 created_by: str) -> tuple[int, dict[str, Any]]:
    """Mint a token and return its plaintext ONCE.

    THE ONLY RESPONSE THAT EVER CARRIES THE SECRET. The store keeps a digest and a display prefix;
    the audit row records the name and role; a log line records the name and prefix. Nothing else
    has the value, which is why the UI says "shown once" rather than pretending it can be recovered.
    """
    from weirvern.admin import tokens as tokens_mod  # noqa: PLC0415

    try:
        record, plaintext = store.create_token(name, role, created_by=created_by)
    except tokens_mod.TokenError as exc:
        return 400, {"ok": False, "error": str(exc)}
    except Exception as exc:  # noqa: BLE001
        return 502, {"error": f"could not create the token: {exc}", "code": 502}
    return 200, {"ok": True, "token": plaintext, "record": record.public()}


def token_revoke(store: Any, *, token_id: str, revoked_by: str) -> tuple[int, dict[str, Any]]:
    """Revoke one token. Takes effect on the next request; the caller audits who did it."""
    from weirvern.admin import tokens as tokens_mod  # noqa: PLC0415

    try:
        record = store.revoke(token_id, revoked_by=revoked_by)
    except tokens_mod.TokenError as exc:
        return 400, {"ok": False, "error": str(exc)}
    except Exception as exc:  # noqa: BLE001
        return 502, {"error": f"could not revoke the token: {exc}", "code": 502}
    return 200, {"ok": True, "token_id": record.token_id, "record": record.public()}


def user_create(store: Any, *, username: str, role: str, password: str,
                must_change: bool) -> tuple[int, dict[str, Any]]:
    """Create an account. Admin only; the caller checks the role.

    THE STORE DECIDES THE POLICY -- a duplicate name, a password under the floor, a role outside
    ROLES -- and this function only turns its answer into the console's status and body. The 400 for
    a UserError carries no `code` key; that shape is the console's and is preserved.
    """
    from weirvern.admin import users as users_mod  # noqa: PLC0415

    try:
        record = store.create_user(username, role, password, must_change=must_change)
    except users_mod.UserError as exc:
        return 400, {"ok": False, "error": str(exc)}
    except Exception as exc:  # noqa: BLE001
        return 502, {"error": f"could not create the account: {exc}", "code": 502}
    logger.info("created account %s with role %s", record.username, record.role)
    return 200, {"ok": True, "user": record.public()}


def user_role(store: Any, sessions: Any, *, username: str, role: str) -> tuple[int, dict[str, Any]]:
    """Change an account's role, revoking its sessions only when the role actually CHANGED.

    THE BEFORE-ROLE IS READ AS A STRING, BEFORE THE WRITE. `find()` returns the store's LIVE record
    and `set_role` mutates it in place, so reading the record's role afterwards always says
    "unchanged"; and a no-op that revokes signs the operator out of the tab they are working in,
    which reads as the change having failed (reported live: "I can't change admin to admin").
    """
    from weirvern.admin import users as users_mod  # noqa: PLC0415

    try:
        existing = store.find(username)
        before_role = existing.role if existing is not None else None
        store.set_role(username, role)
    except users_mod.UserError as exc:
        return 400, {"ok": False, "error": str(exc)}
    except Exception as exc:  # noqa: BLE001
        return 502, {"error": f"could not change the role: {exc}", "code": 502}
    # An open tab keeps acting under the old role until its session is dropped, so a real change
    # revokes immediately; a no-op changed nothing and revokes nothing.
    if before_role is not None and before_role != role and sessions is not None:
        sessions.revoke_user(username)
    logger.info("role for %s set to %s", username, role)
    return 200, {"ok": True, "username": username, "role": role}


def user_delete(store: Any, sessions: Any, *, username: str) -> tuple[int, dict[str, Any]]:
    """Delete an account. The store refuses to remove the last admin."""
    from weirvern.admin import users as users_mod  # noqa: PLC0415

    try:
        store.delete_user(username)
    except users_mod.UserError as exc:
        return 400, {"ok": False, "error": str(exc)}
    except Exception as exc:  # noqa: BLE001
        return 502, {"error": f"could not delete the account: {exc}", "code": 502}
    if sessions is not None:
        sessions.revoke_user(username)
    logger.info("deleted account %s", username)
    return 200, {"ok": True, "username": username}


def user_reset(store: Any, sessions: Any, *, username: str,
               password: str) -> tuple[int, dict[str, Any]]:
    """Set a temporary password for another account and hold it at the password gate.

    The lost-password path that keeps this usable without email: an admin mints a password and hands
    it over, and the account must replace it at next sign-in.
    """
    from weirvern.admin import users as users_mod  # noqa: PLC0415

    try:
        store.set_password(username, password, must_change=True)
    except users_mod.UserError as exc:
        return 400, {"ok": False, "error": str(exc)}
    except Exception as exc:  # noqa: BLE001
        return 502, {"error": f"could not reset the password: {exc}", "code": 502}
    if sessions is not None:
        sessions.revoke_user(username)
    logger.info("password reset for %s (must change at next sign-in)", username)
    return 200, {"ok": True, "username": username,
                 "note": "the account must change this password at next sign-in"}


def login_refusal(ctx: Any) -> dict[str, Any] | None:
    """The 403 body for a GUI with no accounts, or None.

    CHECKED BEFORE THE BODY IS READ, on both surfaces: a deployment with no accounts refuses a
    sign-in whatever was posted, and the console has always answered that way.
    """
    from weirvern.admin import requestauth  # noqa: PLC0415

    if requestauth.accounts_on(ctx):
        return None
    note = getattr(ctx, "accounts_note", "") or "this deployment has no accounts provisioned"
    return {"ok": False, "error": f"cannot sign in: {note}"}


def login(ctx: Any, *, username: str, password: str, addr: str) -> tuple[int, dict[str, Any]]:
    """Verify a username and password, and mint a session token.

    THE CHECK IS SHARED (requestauth.authenticate): the JSON API and the rendered form ask the same
    function the same question, so they cannot disagree about a password, about timing, or about
    throttling. Only the TRANSPORT of the answer differs -- a token in JSON here, a signed cookie in
    the rendered UI.
    """
    from weirvern.admin import requestauth  # noqa: PLC0415

    ident, token, error = requestauth.authenticate(ctx, username, password, addr=addr)
    if ident is None:
        return 401, {"ok": False, "error": error}
    return 200, {"ok": True, "session": token, "username": ident.username,
                 "role": ident.role, "must_change": ident.must_change}


def session_required(ctx: Any, headers: Any) -> tuple[Any, tuple[int, dict[str, Any]] | None]:
    """The signed-in identity, or the refusal that answers for it.

    For the routes every account may use whatever its role -- signing out, changing one's OWN
    password. Deliberately NOT satisfiable by the operator token: a token has no account, so there is
    no password to change and nothing to sign out of, and pretending otherwise offers a button that
    cannot work.

    THE CALLER CHECKS THIS BEFORE READING A BODY, because that is the console's order: no session
    answers 401 even when the request is also malformed.
    """
    from weirvern.admin import requestauth  # noqa: PLC0415

    if not requestauth.accounts_on(ctx):
        return None, (403, {"error": "this deployment has no accounts provisioned", "code": 403})
    ident = requestauth.identity(ctx, headers)
    if ident is None:
        return None, (401, {"error": "sign in first", "code": 401})
    return ident, None


def logout(ctx: Any, ident: Any, headers: Any) -> tuple[int, dict[str, Any]]:
    """Drop this request's session, then audit it.

    A SESSION IS REQUIRED (the caller checked), for uniform audit rules: "every mutating route
    presents a session" is a rule somebody can check at a glance. A tab whose session already expired
    catches the refusal and clears its own state anyway, which is what signing out does.
    """
    from weirvern.admin import gui_auth, requestauth  # noqa: PLC0415

    sessions = getattr(ctx, "sessions", None)
    if sessions is not None:
        sessions.revoke(gui_auth.session_from_request(requestauth.headers_only(headers)))
    logger.info("signed out %s", ident.username)
    requestauth.audit_auth(ctx, "logout", ident.username, "signed out")
    return 200, {"ok": True}


def password_change(ctx: Any, ident: Any, *, current: str,
                    new: str) -> tuple[int, dict[str, Any]]:
    """Change the signed-in account's own password.

    THE CURRENT PASSWORD IS REQUIRED for two reasons: it stops a stolen session token from locking
    the owner out of their account, and it makes a `must_change` change an informed one rather than a
    form submitted blind. Every session is revoked afterwards -- a password change is the one moment
    where dropping the others is exactly what the operator expects.
    """
    from weirvern.admin import users as users_mod  # noqa: PLC0415

    store = getattr(ctx, "user_store", None)
    if store is None:
        return 503, {"error": ACCOUNTS_UNAVAILABLE, "code": 503}
    record = store.find(ident.username)
    if record is None:
        return 404, {"error": "this account no longer exists", "code": 404}
    if not users_mod.verify_password(current, record.hash):
        return 401, {"ok": False, "error": "the current password is not correct"}
    try:
        store.set_password(ident.username, new, must_change=False)
    except users_mod.UserError as exc:
        return 400, {"ok": False, "error": str(exc)}
    except Exception as exc:  # noqa: BLE001
        return 502, {"error": f"could not save the new password: {exc}", "code": 502}
    sessions = getattr(ctx, "sessions", None)
    revoked = sessions.revoke_user(ident.username) if sessions is not None else 0
    logger.info("password changed for %s (%d session(s) revoked)", ident.username, revoked)
    return 200, {"ok": True, "signed_out": True,
                 "note": "password changed; sign in again with the new one"}


def scan_job_create(client: Client, *, ip: str, readiness: dict[str, Any] | None = None,
                    lease_s: int = 900) -> tuple[int, dict[str, Any]]:
    """Queue one host scan for a weirling that can REACH and EXECUTE it.

    THE REFUSAL IS THE FEATURE. A job is only worth filing when some weirling both monitors the
    target's network and reports Nmap; otherwise the row can only sit in the queue while the
    console implies work is happening. So the three predicates are checked BEFORE a row exists:

      * the capability read worked            (else 503: an unknown answer is not a yes)
      * some registered weirling monitors it  (else 409, naming the declared networks)
      * one of those can scan (nmap present)  (else 409, naming the install step)

    AN ACTIVE JOB IS NOT AN ERROR either -- it answers `already: true` with the job that is
    running, so a double click does not queue a second scan.
    """
    from weirvern import scan_jobs  # noqa: PLC0415
    from weirvern import scanner as scanner_mod  # noqa: PLC0415

    try:
        capability = readiness if readiness is not None else scanner_mod.fleet_capability(
            client, ip=ip)
    except Exception as exc:  # noqa: BLE001
        return scan_job_failure(exc)
    if capability.get("available") is False:
        return 503, {"ok": False, "code": 503, "refused": "capability_unreadable",
                     "error": str(capability.get("reason") or
                                  "weirling scan capability could not be read")}
    if not capability.get("enabled"):
        refused = "no_weirling_can_scan" if capability.get("reachable_count") else \
            "target_not_monitored"
        return 409, {"ok": False, "code": 409, "refused": refused,
                     "error": str(capability.get("reason_unavailable") or
                                  scan_jobs.SCAN_UNAVAILABLE),
                     "eligibility": capability}
    try:
        asset = scan_jobs.find_asset(client, ip)
        if asset is None:
            return 404, {"ok": False, "code": 404, "error": f"{ip} is not in the asset registry"}
        active = scan_jobs.active_for_asset(client, str(asset["asset_key"]))
        if active is not None:
            return 200, {"ok": True, "job_id": str(active["job_id"]), "ip": ip,
                         "state": str(active["state"]), "already": True,
                         "eligibility": capability.get("sentence", "")}
        job = scan_jobs.create_job(client, asset, requested_by="operator")
    except Exception as exc:  # noqa: BLE001
        return scan_job_failure(exc)
    logger.info("manual scan queued for %s (%s)", ip, job["job_id"])
    return 200, {"ok": True, "job_id": str(job["job_id"]), "ip": ip,
                 "state": "queued", "already": False,
                 "eligibility": capability.get("sentence", ""),
                 "eligible_weirlings": [item["sensor_id"]
                                        for item in capability.get("eligible") or []]}


def _scan_audit(client: Client, *, action: str, job: dict[str, Any], reason: str,
                actor: str) -> None:
    """The FACT of a cancellation, kept after the job row is gone.

    The scan record is the operator's to remove; the evidence that they queued and cancelled
    one is not. One append-only row, with the original job id in `target` so a deleted scan
    cannot be used to erase that it was ever requested.
    """
    from weirvern import fleet_store  # noqa: PLC0415

    target = f"{job.get('ip') or 'unknown target'} job {job.get('job_id') or 'unknown'}"
    fleet_store.write_audit(client, scope="scan", action=action, target=target,
                            reason=reason, actor=actor)


def scan_job_cancel(client: Client, *, job_id: str, reason: str, actor: str = "operator",
                    lease_s: int = 900, scanning_enabled: bool = True,
                    unavailable_reason: str = "") -> tuple[int, dict[str, Any]]:
    """Remove a QUEUED job from the record; ask a RUNNING one to stop, and do not pretend.

    THE THREE ANSWERS ARE DIFFERENT ON PURPOSE:
      * queued          -> the row is DELETED (and audited), so the queue reflects the removal
      * claimed/running -> `cancel_requested`, 202, and the row STAYS until the weirling
                           confirms it killed its child. A running scan that vanishes from the
                           record while still probing the network is a lie.
      * finished        -> 409, nothing to remove.
    A reason is required for every path: months later the audit is the only answer to "why".
    """
    from weirvern import scan_jobs  # noqa: PLC0415

    why = str(reason or "").strip()
    if not why:
        return 400, {"ok": False, "code": 400, "refused": "reason_required",
                     "error": "a reason is required to cancel a scan; it is kept in the audit trail"}
    try:
        job = scan_jobs.get_job(client, job_id)
        if job is None:
            return 404, {"ok": False, "code": 404, "error": "no scan job with that id"}
        derived = scan_jobs.derive(job, lease_s=lease_s, scanning_enabled=scanning_enabled,
                                   unavailable_reason=unavailable_reason)
        state = str(derived.get("state") or "")
        if state in ("claimed", "cancel_requested"):
            if state != "cancel_requested":
                scan_jobs.request_cancel(client, derived, actor=actor)
            _scan_audit(client, action="scan_cancel_requested", job=derived, reason=why,
                        actor=actor)
            return 202, {
                "ok": False, "confirmed": False, "job_id": job_id,
                "ip": str(derived.get("ip") or ""), "state": "cancel_requested",
                "error": ("cancel requested; the weirling has not confirmed — the job stays "
                          "visible until it does"),
            }
        if state in scan_jobs.TERMINAL_STATES:
            return 409, {"ok": False, "code": 409, "refused": "already_finished",
                         "error": f"this job already finished ({state}); there is nothing to cancel"}
        _scan_audit(client, action="scan_cancel", job=derived, reason=why, actor=actor)
        scan_jobs.delete_job(client, job_id)
    except Exception as exc:  # noqa: BLE001
        return scan_job_failure(exc)
    logger.info("scan job %s removed from the queue by %s", job_id, actor)
    return 200, {
        "ok": True, "removed": True, "job_id": job_id,
        "ip": str(derived.get("ip") or ""), "reason": why,
        "note": f"removed job {job_id} for {derived.get('ip') or 'the target'}; "
                "the cancellation is recorded in the audit trail",
    }


def scan_jobs_cancel(client: Client, *, job_ids: list[str], reason: str,
                     actor: str = "operator", lease_s: int = 900,
                     scanning_enabled: bool = True,
                     unavailable_reason: str = "") -> tuple[int, dict[str, Any]]:
    """Cancel several jobs in one action, with the SAME reason and ONE audit row per job.

    Per-job outcomes, not one aggregate "ok": a batch where two rows vanished and one is still
    running must say which is which. The HTTP status is 200 when at least one row was removed,
    409 when none were, so a caller cannot read a total failure as success.
    """
    ids = [str(job_id or "").strip() for job_id in (job_ids or []) if str(job_id or "").strip()]
    if not ids:
        return 400, {"ok": False, "code": 400, "error": "no job ids were given"}
    if len(ids) > 100:
        return 400, {"ok": False, "code": 400, "error": "at most 100 jobs per cancellation"}
    removed, unconfirmed, failed = [], [], []
    for job_id in dict.fromkeys(ids):
        code, result = scan_job_cancel(
            client, job_id=job_id, reason=reason, actor=actor, lease_s=lease_s,
            scanning_enabled=scanning_enabled, unavailable_reason=unavailable_reason)
        entry = {"job_id": job_id, "status": code, "result": result}
        if result.get("removed"):
            removed.append(entry)
        elif code == 202:
            unconfirmed.append(entry)
        else:
            failed.append(entry)
    return (200 if removed else 409), {
        "ok": bool(removed), "removed": removed, "unconfirmed": unconfirmed, "failed": failed,
        "count": len(removed),
    }


def weirling_install(client: Client, settings: Any, *, sensor_id: str, reason: str,
                     actor: str = "operator", sudo_password: str | None = None
                     ) -> tuple[int, dict[str, Any]]:
    """Ask a weirling to install Nmap, with the sudo password only when that host needs one.

    THE PREDICATES ARE CHECKED BEFORE THE GATEWAY IS CALLED, from the capability row the agent
    itself wrote: an already-capable host is refused (nothing to install), a host with no
    package manager is refused (the console shows the copy-command line instead), and a host
    whose user is not in sudoers is refused with that sentence rather than a password prompt
    that cannot work. A password supplied for a host that does not need one is DROPPED here,
    not forwarded -- the gateway has no reason to hold a secret it will not use.
    """
    from weirvern import scanner as scanner_mod  # noqa: PLC0415
    from weirvern.admin import gateway_call  # noqa: PLC0415

    sid = str(sensor_id or "").strip().lower()
    why = str(reason or "").strip()
    if not sid:
        return 400, {"ok": False, "code": 400, "error": "a weirling id is required"}
    if not why:
        return 400, {"ok": False, "code": 400, "refused": "reason_required",
                     "error": "a reason is required to install Nmap; it is kept in the audit trail"}
    rows = client.query(
        "SELECT os_id, os_version, nmap_available, sudo_state "
        "FROM weirvern.scanner_status FINAL WHERE sensor_id = %(s)s LIMIT 1",
        parameters={"s": sid},
    ).result_rows
    if not rows:
        return 409, {
            "ok": False, "code": 409, "refused": "no_capability_report",
            "error": (f"{sid} has not reported its scan capability yet, so the console does not "
                      "know which package manager or privilege path applies"),
        }
    os_id = str(rows[0][0] or "")
    os_version = str(rows[0][1] or "")
    if bool(rows[0][2]):
        return 409, {"ok": False, "code": 409, "refused": "already_installed",
                     "error": f"{sid} already reports Nmap; there is nothing to install"}
    mode = str(rows[0][3] or "unknown")
    if mode == "none":
        return 403, {
            "ok": False, "code": 403, "refused": "no_privilege",
            "error": (f"{sid}'s user is not in sudoers and is not root; run the command as root "
                      "on the host instead"),
        }
    install = scanner_mod.nmap_install_command(os_id, os_version)
    if not install.get("known"):
        return 409, {
            "ok": False, "code": 409, "refused": "unknown_distro",
            "error": (f"no package manager was detected for {os_id or 'this OS'}; "
                      f"copy the command instead: {install.get('command')}"),
        }
    password = str(sudo_password or "") if mode == "password" else ""
    if mode == "password" and not password:
        return 400, {
            "ok": False, "code": 400, "refused": "sudo_password_required",
            "error": (f"sudo on {sid} asks for a password; it is used once, over mTLS, and is "
                      "never stored"),
        }
    try:
        code, payload = gateway_call.install_create(
            settings, host_id=sid, family=os_id, version=os_version, reason=why,
            actor=actor, sudo_password=(password or None))
    except gateway_call.GatewayUnavailable as exc:
        return 503, {"ok": False, "code": 503, "refused": "install_service_unavailable",
                     "error": str(exc)}
    if code != 200:
        return code, {"ok": False, "code": code,
                      "error": str(payload.get("error") or "the install request was refused")}
    # A WHITELIST, NOT THE GATEWAY'S WHOLE ANSWER. There is no password in it by construction;
    # naming the fields keeps a future addition from accidentally riding into the browser.
    return 200, {
        "ok": True, "request_id": str(payload.get("request_id") or ""), "host_id": sid,
        "command": str(payload.get("command") or ""), "state": str(payload.get("state") or ""),
        "expires_at": str(payload.get("expires_at") or ""),
        "password_used": mode == "password",
    }


def weirling_install_status(settings: Any, request_id: str) -> tuple[int, dict[str, Any]]:
    """Poll one install request. The gateway's public shape never contains the password."""
    from weirvern.admin import gateway_call  # noqa: PLC0415

    try:
        return gateway_call.install_status(settings, request_id)
    except gateway_call.GatewayUnavailable as exc:
        return 503, {"ok": False, "code": 503, "refused": "install_service_unavailable",
                     "error": str(exc)}


def sluice_block(client: Client, *, by: str, src_cidr: str, dst_cidr: str, domain: str,
                 mode: str, protocol: str, dst_port: int, direction: str, ttl_minutes: int,
                 reason: str, origin: str,
                 interval_s: int) -> tuple[int, dict[str, Any]]:
    """Record a blocking rule and describe what will happen next.

    THE NOTE IS PART OF THE ANSWER. The gate arms on its own interval, so the operator is told when
    enforcement picks the rule up rather than being left to assume the block is instant; an indefinite
    rule says it stays until revoked, because "recorded" alone reads as a bounded block; and ALERT
    mode says nothing will actually be dropped, which is the difference between a block and a tally.
    """
    from weirvern import sluice_store  # noqa: PLC0415
    from weirvern.sluice import SluiceError  # noqa: PLC0415

    try:
        rule = sluice_store.create_rule(
            client, src_cidr=src_cidr, dst_cidr=dst_cidr, domain=domain, mode=mode,
            protocol=protocol, dst_port=dst_port, direction=direction,
            ttl_minutes=ttl_minutes, created_by=by, reason=reason, origin=origin,
        )
    except SluiceError as exc:
        return 400, {"ok": False, "error": str(exc)}
    except Exception as exc:  # noqa: BLE001
        return sluice_block_failure(exc)
    return 200, {
        "ok": True, "rule_id": rule.rule_id, "describes": rule.describes(),
        "expires_at": rule.expires_at.isoformat() if rule.expires_at else "",
        "note": (f"recorded; enforcement picks it up within {int(interval_s)}s"
                 + ("" if rule.expires_at else "; it stays until it is revoked")
                 + (" — ALERT mode: hits are recorded, nothing is blocked"
                    if rule.mode == "alert" else "")),
    }


def scan_job_failure(exc: BaseException) -> tuple[int, dict[str, Any]]:
    """The console's own failure shape: an unreadable queue is a NAMED condition.

    Used both inside the fetcher and by a surface whose CONNECTION failed -- the console wraps the
    connection in the same try, so an unreachable cluster has always answered this sentence.
    """
    logger.warning("scan job request failed: %s", exc)
    return 503, {"ok": False, "error": "the scan-job table is not readable; no job was queued",
                 "code": 503}


def sluice_block_failure(exc: BaseException) -> tuple[int, dict[str, Any]]:
    """A rule that could not be recorded, named by the exception's TYPE and not its message.

    The type is what the console reports: a driver message can carry the cluster's internals, and the
    operator cannot act on it.
    """
    logger.warning("sluice block failed: %s", exc)
    return 502, {"error": f"could not record the rule: {type(exc).__name__}", "code": 502}


def sluice_revoke_failure(exc: BaseException) -> tuple[int, dict[str, Any]]:
    """A rule that could not be revoked, same contract as sluice_block_failure."""
    logger.warning("sluice revoke failed: %s", exc)
    return 502, {"error": f"could not revoke the rule: {type(exc).__name__}", "code": 502}


def sluice_revoke(client: Client, *, rule_id: str, rule_ids: list[str], reason: str, by: str,
                  interval_s: int) -> tuple[int, dict[str, Any]]:
    """Stop enforcing a rule, keeping the RECORD.

    The audit trail of what was blocked and why must not be destroyed by the act of unblocking it --
    that record is what an incident review reads, which is why the store soft-deletes.

    A BULK REVOKE REPORTS PER-ID FAILURES rather than swallowing them (`revoke_rules`), so a selection
    of ten rules with one bad id answers with what happened to each.

    `reason` is validated by the caller and, as on the console, NOT passed to the store: the route has
    always required it and never recorded it. Preserved rather than changed here -- adding a column is
    a schema decision, not a port.
    """
    from weirvern import sluice_store  # noqa: PLC0415

    try:
        if rule_ids:
            try:
                out = sluice_store.revoke_rules(client, rule_ids, by=by)
            except sluice_store.SluiceError as exc:
                return 400, {"error": str(exc), "code": 400}
            return 200, {"ok": True, **out,
                         "note": f"revoked; enforcement stops within {int(interval_s)}s"}
        ok = sluice_store.revoke_rule(client, rule_id, by=by)
    except Exception as exc:  # noqa: BLE001
        return sluice_revoke_failure(exc)
    if not ok:
        return 404, {"ok": False, "error": f"no rule with id {rule_id!r}"}
    return 200, {"ok": True, "rule_id": rule_id,
                 "note": f"revoked; enforcement stops within {int(interval_s)}s"}


def sluice_rule_mode(client: Client, *, by: str, rule_id: str,
                     mode: str) -> tuple[int, dict[str, Any]]:
    """Change a rule's mode in place -- the Blocked tab's "open the rule and modify it".

    MOVING TO block ARMS THE KERNEL; the `confirmed` friction is checked by the caller, before any
    query, because it is a request-shape requirement rather than something the store decides.
    """
    from weirvern import sluice_store  # noqa: PLC0415
    from weirvern.sluice import SluiceError  # noqa: PLC0415

    try:
        rule = sluice_store.update_rule_mode(client, rule_id, mode, by=by)
    except SluiceError as exc:
        return 400, {"ok": False, "error": str(exc)}
    except Exception as exc:  # noqa: BLE001
        return sluice_rule_failure(exc)
    return 200, {"ok": True, "rule": {"rule_id": rule.rule_id,
                                      "describes": rule.describes(), "mode": rule.mode}}


def sluice_rule_domain(client: Client, *, by: str, rule_id: str,
                       domain: str) -> tuple[int, dict[str, Any]]:
    """Rename a rule, including adding a `*.` marker. Stored as typed; subdomains were always covered."""
    from weirvern import sluice_store  # noqa: PLC0415
    from weirvern.sluice import SluiceError  # noqa: PLC0415

    try:
        rule = sluice_store.update_rule(client, rule_id, domain=domain, by=by)
    except SluiceError as exc:
        return 400, {"ok": False, "error": str(exc)}
    except Exception as exc:  # noqa: BLE001
        return sluice_rule_failure(exc)
    return 200, {"ok": True, "rule": {"rule_id": rule.rule_id,
                                      "describes": rule.describes(), "domain": rule.domain}}


def sluice_rule_disabled(client: Client, *, by: str, rule_id: str, rule_ids: list[str],
                         disabled: bool, interval_s: int) -> tuple[int, dict[str, Any]]:
    """Park a rule or put it back, for one id or a selection.

    A SELECTION REPORTS PER-ID REFUSALS instead of stopping at the first: the server re-reads every
    rule before flipping it, so one that was edited or revoked in the meantime comes back in `refused`
    with a sentence rather than being guessed past -- and the rest of the selection still lands.
    """
    from weirvern import sluice_store  # noqa: PLC0415

    changed: list[str] = []
    refused: list[dict[str, Any]] = []
    try:
        for rid in (rule_ids or [rule_id]):
            try:
                sluice_store.set_rule_disabled(client, rid, disabled, by=by)
                changed.append(rid)
            except sluice_store.SluiceError as exc:
                refused.append({"rule_id": rid, "error": str(exc)})
    except Exception as exc:  # noqa: BLE001
        return sluice_rule_disabled_failure(exc)
    return 200, {"ok": True, "changed": changed, "refused": refused,
                 "note": ("disabled" if disabled else "re-enabled")
                         + f"; enforcement reflects it within {int(interval_s)}s"}


def sluice_rule_failure(exc: BaseException) -> tuple[int, dict[str, Any]]:
    """A rule edit the store did not name a reason for: 503 with the READ failure wording.

    THE `{"ok": false}` ON A 503 IS THE CONSOLE'S SHAPE, not the house error body. A client reads `ok`
    to decide whether to re-render the rule, so normalising this would make a failure look like a
    success on one surface and not the other.
    """
    from weirvern.admin.web import read_failure  # noqa: PLC0415

    return 503, {"ok": False, "error": read_failure(exc)}


def sluice_rule_disabled_failure(exc: BaseException) -> tuple[int, dict[str, Any]]:
    """A disable/enable pass that failed outside the per-id refusals: the store never answered."""
    logger.warning("sluice rule disable failed: %s", exc)
    return 502, {"error": f"could not change the rule: {type(exc).__name__}", "code": 502}


def blocklist_sync(client: Client) -> tuple[int, dict[str, Any]]:
    """Sync every ENABLED source now. Slow on purpose: it fetches megabytes.

    THE CUSTOM LIST IS SKIPPED because it is not a feed: it is the names the operator typed, and
    fetching it would replace them with whatever a URL answered.
    """
    from weirvern import blocklists  # noqa: PLC0415

    try:
        blocklists.ensure_default_sources(client)
        results = []
        for src in blocklists.load_sources(client):
            if not src["enabled"] or src["source_id"] == "custom":
                continue
            results.append({"source_id": src["source_id"],
                            **blocklists.sync_source(client, src)})
    except Exception as exc:  # noqa: BLE001
        return blocklist_sync_failure(exc)
    return 200, {"ok": True, "results": results}


def blocklist_source_add(client: Client, *, url: str, name: str,
                         fmt: str) -> tuple[int, dict[str, Any]]:
    """Add a URL source, with its format named and validated by the store.

    THE FORMAT IS REQUIRED ON PURPOSE: a list with no stated format imports nothing and looks like a
    broken list. `domains` is the default; hosts and dnsmasq are accepted; Adblock and RPZ are refused
    with the reason, which arrives as a ValueError from the store.
    """
    from weirvern import blocklists  # noqa: PLC0415

    try:
        src = blocklists.add_source(client, url, name=name, fmt=fmt)
    except ValueError as exc:
        return 400, {"ok": False, "error": str(exc)}
    except Exception as exc:  # noqa: BLE001
        return blocklist_source_failure(exc)
    return 200, {"ok": True, "source": src,
                 "note": "added. Sync now to fetch it; importing records names, it does not block them."}


def blocklist_custom(client: Client, *, action: str,
                     domain: str) -> tuple[int, dict[str, Any]]:
    """Add or remove one operator-entered name, validated like a domain rule."""
    from weirvern import blocklists  # noqa: PLC0415
    from weirvern.sluice import SluiceError  # noqa: PLC0415

    try:
        if action == "remove":
            name = blocklists.remove_custom_domain(client, domain)
        else:
            name = blocklists.add_custom_domain(client, domain)
    except SluiceError as exc:
        return 400, {"ok": False, "error": str(exc)}
    except Exception as exc:  # noqa: BLE001
        return blocklist_custom_failure(exc)
    return 200, {"ok": True, "action": action, "domain": name}


def blocklist_enable(client: Client, *, source_id: str,
                     enabled: bool) -> tuple[int, dict[str, Any]]:
    """Click a list on or off. A WRITE: what the deployment watches changes.

    Off drops the list's names from the watch set at the next load, so the note says WHICH direction
    the operator just moved -- "saved" would leave them guessing whether the list is being used.
    """
    from weirvern import blocklists  # noqa: PLC0415

    try:
        src = blocklists.set_source_enabled(client, source_id, enabled)
    except ValueError as exc:
        return 400, {"ok": False, "error": str(exc)}
    except Exception as exc:  # noqa: BLE001
        return blocklist_enable_failure(exc)
    return 200, {"ok": True, "source": src,
                 "note": ("on \u2014 its names join the watch set at the next load"
                          if enabled else
                          "off \u2014 its names leave the watch set at the next load")}


def network_scope_save(client: Client, body: dict) -> tuple[int, dict[str, Any]]:
    """Create or update one operator-declared network scope, then answer with the whole overview.

    THE BODY IS PASSED THROUGH, not pre-parsed: `networks.save_scope` owns the field rules and raises
    ValueError with the sentence the form shows, so a second parser here would be free to disagree
    with it. The overview rides the answer because the page re-renders from it.
    """
    from weirvern import networks  # noqa: PLC0415

    try:
        scope = networks.save_scope(client, body)
        payload = networks.overview(client, hours=24)
    except ValueError as exc:
        return 400, {"error": str(exc), "code": 400}
    except Exception as exc:  # noqa: BLE001
        return network_save_failure(exc)
    payload["ok"] = True
    payload["scope"] = scope.public()
    return 200, payload


def network_scope_delete(client: Client, scope_id: str) -> tuple[int, dict[str, Any]]:
    """Retire one scope with a tombstone; the history remains until the merge window."""
    from weirvern import networks  # noqa: PLC0415

    try:
        removed = networks.delete_scope(client, scope_id)
        payload = networks.overview(client, hours=24)
    except ValueError as exc:
        return 400, {"error": str(exc), "code": 400}
    except Exception as exc:  # noqa: BLE001
        return network_delete_failure(exc)
    payload["ok"] = bool(removed)
    return 200, payload


def blocklist_sync_failure(exc: BaseException) -> tuple[int, dict[str, Any]]:
    logger.warning("blocklist sync failed: %s", exc)
    return 502, {"error": f"the sync failed: {type(exc).__name__}", "code": 502}


def blocklist_source_failure(exc: BaseException) -> tuple[int, dict[str, Any]]:
    logger.warning("blocklist source add failed: %s", exc)
    return 502, {"error": f"the list could not be added: {type(exc).__name__}", "code": 502}


def blocklist_custom_failure(exc: BaseException) -> tuple[int, dict[str, Any]]:
    logger.warning("blocklist custom change failed: %s", exc)
    return 502, {"error": f"the change failed: {type(exc).__name__}", "code": 502}


def blocklist_enable_failure(exc: BaseException) -> tuple[int, dict[str, Any]]:
    """The 503-with-`{"ok": false}` shape this route has always used, read_failure wording included."""
    from weirvern.admin.web import read_failure  # noqa: PLC0415

    return 503, {"ok": False, "error": read_failure(exc)}


def network_save_failure(exc: BaseException) -> tuple[int, dict[str, Any]]:
    """A 500 carrying the FIRST 200 CHARACTERS of the reason, as the console does.

    The truncation is deliberate there: a driver message can run to a page, and the form has one line
    for it. Truncating differently on one surface (or not at all) would make the same failure look
    like two.
    """
    logger.warning("network scope save failed: %s", exc)
    return 500, {"error": f"could not save the network scope: {str(exc)[:200]}", "code": 500}


def network_delete_failure(exc: BaseException) -> tuple[int, dict[str, Any]]:
    logger.warning("network scope delete failed: %s", exc)
    return 500, {"error": f"could not delete the network scope: {str(exc)[:200]}", "code": 500}


def gate_sensor_name() -> str:
    """The sensor identity this hub's own state rows are keyed by (the console's own helper).

    ONE DEFINITION: the expression must match the writer, so the console's `_gate_sensor_name` is
    called rather than repeated -- a second convention here would silently read an empty panel.
    """
    from weirvern.admin.web import _gate_sensor_name  # noqa: PLC0415

    return _gate_sensor_name()


def plan_subject(connect: Any, sensor_id: str, *, channel_only: bool = False) -> tuple[Any, str]:
    """Resolve the sensor a per-sensor plan write targets: (registration, refusal).

    WHY THE LOCAL SENSOR IS USUALLY REFUSED HERE, not silently accepted: this hub's OWN sensor is
    configured where it runs -- the Settings tab writes SENSOR_MODE and the INTERCEPT_* keys into
    the cluster ConfigMap, and the worker's supervisor reads them from its environment. Storing a
    registry plan for its MODE as well would create a second source of truth that nothing reads:
    a control that appears applied and moves nothing. The refusal names where the real control is.

    `channel_only` IS THE ONE EXCEPTION, AND IT IS NOT A HOLE IN THAT RULE. A channel is not a
    sensor mode: nothing in the ConfigMap describes a remote unit's bridge, and the registry row
    is the only per-sensor store. So a write that names ONLY the channel pair is allowed for this
    hub's own sensor too -- the mode and intercept controls still stay on the Settings tab.
    """
    from weirvern import fleet_store  # noqa: PLC0415

    if not sensor_id:
        return None, ("a sensor id is required: a plan belongs to one weirling "
                      "(the drill-down knows which one)")
    if sensor_id == gate_sensor_name() and not channel_only:
        return None, (
            f"{sensor_id!r} is this hub's OWN sensor, and its runtime is configured where it runs: "
            f"the Settings tab writes SENSOR_MODE and the INTERCEPT_* keys into the cluster "
            f"ConfigMap, and this hub's worker reads them. A plan stored here would be a second "
            f"source that nothing reads -- so the controls for this sensor stay on the Settings tab "
            f"(its channel pair is the exception: every weirling stores that in its plan)."
        )
    try:
        with connect() as client:
            reg, refusal = fleet_store.plan_subject(client, sensor_id)
    except Exception as exc:  # noqa: BLE001
        return None, f"the sensor could not be read: {str(exc)[:200]}"
    if refusal:
        return None, refusal
    return reg, ""


def weirling_register(client: Client, *, sensor_id: str, address: str, segment: str,
                      expected_mode: str, note: str, topology: str) -> tuple[int, dict[str, Any]]:
    """Register (or re-register) a sensor.

    A REJECTED REGISTRATION IS A 400, NOT A 5xx: it is a normal outcome of a form an operator is
    filling in, and an error page would read as the feature being broken rather than the input being
    wrong. The store's message names the fix, so it is passed through verbatim.
    """
    from weirvern import fleet_store  # noqa: PLC0415

    try:
        reg = fleet_store.register(
            client, sensor_id, address=address, segment=segment,
            expected_mode=expected_mode, note=note, topology=topology)
    except fleet_store.FleetError as exc:
        return 400, {"ok": False, "error": str(exc)}
    except fleet_store.FleetStoreError as exc:
        return 503, {"ok": False, "error": str(exc)}
    except Exception as exc:  # noqa: BLE001
        logger.warning("weirling registration failed: %s", exc)
        return 500, {"ok": False, "error": f"could not save: {str(exc)[:200]}"}
    return 200, {"ok": True, "sensor_id": reg.sensor_id}


def weirling_enable(client: Client, *, sensor_id: str,
                    enabled: bool) -> tuple[int, dict[str, Any]]:
    """Switch a registered sensor on or off WITHOUT revoking it.

    `enabled` is a STRICT boolean, checked by the caller: `bool("false")` is True, so a client sending
    the string "false" would silently ENABLE a sensor. Refused rather than coerced.
    """
    from weirvern import fleet_store  # noqa: PLC0415

    try:
        reg = fleet_store.set_enabled(client, sensor_id, enabled)
    except fleet_store.FleetError as exc:
        return 400, {"ok": False, "error": str(exc)}
    except fleet_store.FleetStoreError as exc:
        return 503, {"ok": False, "error": str(exc)}
    except Exception as exc:  # noqa: BLE001
        logger.warning("weirling enable failed: %s", exc)
        return 500, {"ok": False, "error": f"could not save: {str(exc)[:200]}"}
    return 200, {"ok": True, "sensor_id": reg.sensor_id, "enabled": reg.enabled}


def weirling_revoke(connect: Any, *, sensor_id: str, reason: str, actor: str,
                    config_client: Any = None) -> tuple[int, dict[str, Any]]:
    """Retire a registration. The row is kept; nothing is deleted.

    THE LOCAL SENSOR'S SETTINGS LIVE IN THE CONFIGMAP, NOT IN THE REGISTRY ROW. Clearing only the row
    left the worker forwarding and intercepting after a revoke, because the plan is read from the
    cluster environment and not from ClickHouse. So when the revoked sensor is this hub's own, the
    sensor-role keys are cleared and what read them is restarted. A FAILED SETTINGS CLEAR DOES NOT
    FAIL THE REVOKE -- the revoke is already durable, and a retry must stay possible -- so the answer
    carries `settings_cleared: false` and the reason instead of pretending the sensor is clean.
    """
    from weirvern import fleet_store  # noqa: PLC0415

    try:
        with connect() as client:
            reg = fleet_store.revoke_registration(client, sensor_id)
    except fleet_store.FleetError as exc:
        return 400, {"ok": False, "error": str(exc)}
    except fleet_store.FleetStoreError as exc:
        return 503, {"ok": False, "error": str(exc)}
    except Exception as exc:  # noqa: BLE001
        logger.warning("weirling revoke failed: %s", exc)
        return 500, {"ok": False, "error": f"could not save: {str(exc)[:200]}"}

    settings_cleared: bool | None = None
    settings_error = ""
    if reg.sensor_id == gate_sensor_name():
        try:
            from weirvern.admin import cluster_config as cc  # noqa: PLC0415

            config = config_client or cc.ClusterConfig()
            current = config.read()
            p = cc.plan(dict(cc.REVOCATION_CLEARS), current)
            config.apply(dict(cc.REVOCATION_CLEARS),
                         reason=f"weirling {reg.sensor_id} revoked: {reason}", by=actor)
            restarted: list[str] = []
            restart_errors: list[str] = []
            for target in p.restart_targets:
                try:
                    config.restart(target)
                    restarted.append(target)
                except Exception as exc:  # noqa: BLE001
                    restart_errors.append(f"{target}: {exc}")
            settings_cleared = True
            if restart_errors:
                settings_error = ("the settings were cleared but a restart failed: "
                                  + "; ".join(restart_errors))
        except Exception as exc:  # noqa: BLE001
            settings_cleared = False
            settings_error = f"the sensor was revoked but its settings were not cleared: {exc}"
            logger.warning("weirling revoke settings clear failed: %s", exc)
    try:
        with connect() as client:
            fleet_store.write_audit(client, scope="fleet", action="revoke",
                                    target=reg.sensor_id, reason=reason, actor=actor)
    except Exception as exc:  # noqa: BLE001
        logger.warning("fleet audit write failed: %s", exc)
    return 200, {"ok": True, "sensor_id": reg.sensor_id,
                 "settings_cleared": settings_cleared, "settings_error": settings_error}


_CHANNEL_FIELDS = ("channel_upstream", "channel_downstream")


def _channel_only(changes: dict) -> bool:
    """Whether a plan write names ONLY the inline channel pair.

    Used to decide whether the hub's own sensor may take a registry plan (see `plan_subject`):
    a channel is a per-sensor bridge, not the mode the ConfigMap describes.
    """
    keys = set(changes or {})
    return bool(keys) and keys <= set(_CHANNEL_FIELDS)


def _touches_channel(changes: dict) -> bool:
    """Whether a plan write names either side of the channel pair."""
    return bool(set(changes or {}) & set(_CHANNEL_FIELDS))


def _reported_nics(connect: Any, sensor_id: str) -> tuple[str, ...]:
    """The interfaces this sensor reports on its newest heartbeat, or ().

    `plan_nics` is authoritative when it exists. This is the fallback for a remote unit that has
    no per-NIC plan yet: without it the console would offer ports the API could not verify, and
    "every weirling can carry a channel" would be true only for seeded rows. A read failure
    yields () -- the plan write then refuses for lack of a declaration rather than guessing.
    """
    from weirvern import fleet_store  # noqa: PLC0415

    try:
        with connect() as client:
            rows, _why = fleet_store.read_heartbeats(client)
    except Exception:  # noqa: BLE001 -- a refusal is better than a guessed NIC list
        return ()
    for row in rows:
        if str(row.get("sensor_id") or "") == sensor_id:
            return tuple(str(name) for name in (row.get("interfaces") or [])
                         if str(name or "").strip() and str(name) != "lo")
    return ()


def weirling_plan(connect: Any, *, sensor_id: str, changes: dict,
                  settings: Any = None) -> tuple[int, dict[str, Any]]:
    """What a per-sensor plan change WOULD do. Touches nothing.

    THE SAME VALIDATION THE WRITE WILL USE: `fleet.plan_from_changes` runs here, so the preview cannot
    be looser than the apply, and the in-path cost comes back as a WARNING on the change that carries
    it rather than being something a client could skip by staging a plan itself.

    `settings` supplies the deployment's `mgmt_iface`, which is what the channel-pair validation
    uses to refuse enslaving the management port. It is a read-only hint: a caller without one
    still gets the conventional `eth0` fallback, the same one the sheet uses.
    """
    from weirvern import fleet as fleet_mod  # noqa: PLC0415

    reg, refusal = plan_subject(connect, sensor_id, channel_only=_channel_only(changes))
    if refusal:
        return 400, {"ok": False, "error": refusal}
    current = reg.plan if reg is not None else fleet_mod.SensorPlan()
    known_nics = _reported_nics(connect, sensor_id) if _touches_channel(changes) else ()
    try:
        merged = fleet_mod.plan_from_changes(
            current, changes, mgmt_iface=str(getattr(settings, "mgmt_iface", "") or ""),
            known_nics=known_nics)
    except fleet_mod.FleetError as exc:
        return 400, {"ok": False, "error": str(exc)}

    proposals = []
    for key in fleet_mod.PLAN_FIELDS:
        if key not in changes:
            continue
        value = merged.as_dict()[key]
        if value == current.as_dict()[key]:
            continue
        warning = ""
        if key == "mode" and value == "siphon":
            warning = (
                f"this puts {sensor_id} IN THE TRAFFIC PATH: every host the plan names will depend on "
                f"the sensor forwarding, so a stopped sensor is their outage -- and only those hosts, "
                f"which is why the target list is worth checking before applying."
            )
        proposals.append({"key": key, "value": value, "warning": warning})

    # Incompleteness is a plan-level WARNING, not a refusal: a half-filled plan is legitimate (stage
    # the segment now, the address tomorrow), and the sensor refuses to arm until it is complete --
    # saying so on its own heartbeat.
    warnings = list(merged.warnings())
    warnings += [f"the plan cannot arm yet: {gap}" for gap in merged.problems()]
    return 200, {
        "ok": True, "sensor_id": sensor_id, "proposals": proposals, "restart_targets": [],
        "warnings": warnings,
        "note": (f"{sensor_id} reads its own plan on every refresh (about 30 seconds) and arms or "
                 f"disarms itself then. Nothing on this hub restarts."),
    }


def weirling_apply(connect: Any, *, sensor_id: str, changes: dict, reason: str,
                   actor: str, settings: Any = None) -> tuple[int, dict[str, Any]]:
    """Write a per-sensor plan. The sensor picks it up on its next refresh.

    THE WRITE PATH CANNOT BE LOOSER THAN THE PREVIEW, or the preview is theatre, so the same
    `plan_from_changes` runs here -- and an in-path plan needs a reason, recorded with the actor.

    THE WRITE IS THE ONE THE PREVIEW VALIDATED: `register(plan=...)` replaces the plan as a group and
    keeps `expected_mode` in step with its mode, so the fleet view's declaration and the sensor's
    runbook stay one fact.

    `expected_mode=reg.expected_mode` IS EXPLICIT because a CHANNEL-ONLY write must not touch the
    declaration. `register`'s own default is `loch`, so passing nothing would quietly re-declare a
    sensor as passive while the operator was only wiring a bridge; when the plan carries a mode,
    `register` still overrides this with the plan's own mode (one fact, not two).
    """
    from weirvern import fleet as fleet_mod  # noqa: PLC0415
    from weirvern import fleet_store  # noqa: PLC0415

    reg, refusal = plan_subject(connect, sensor_id, channel_only=_channel_only(changes))
    if refusal:
        return 400, {"ok": False, "error": refusal}
    current = reg.plan if reg is not None else fleet_mod.SensorPlan()
    known_nics = _reported_nics(connect, sensor_id) if _touches_channel(changes) else ()
    try:
        merged = fleet_mod.plan_from_changes(
            current, changes, mgmt_iface=str(getattr(settings, "mgmt_iface", "") or ""),
            known_nics=known_nics)
    except fleet_mod.FleetError as exc:
        return 400, {"ok": False, "error": str(exc)}

    # BF-9: a plan that lands in-path needs a reason; every plan write is recorded.
    if merged.mode == "siphon" and not reason:
        return 400, {"ok": False, "error": (
            "putting this sensor in path is irreversible enough to deserve a reason; it is recorded "
            "with your name and the time")}

    applied = {k: v for k, v in merged.as_dict().items()
               if k in changes and v != current.as_dict()[k]}
    try:
        with connect() as client:
            fleet_store.register(
                client, sensor_id,
                expected_mode=(reg.expected_mode if reg is not None else "loch"),
                plan=merged)
    except fleet_store.FleetError as exc:
        return 400, {"ok": False, "error": str(exc)}
    except fleet_store.FleetStoreError as exc:
        return 503, {"ok": False, "error": str(exc)}
    except Exception as exc:  # noqa: BLE001
        logger.warning("weirling plan apply failed: %s", exc)
        return 500, {"ok": False, "error": f"could not save: {str(exc)[:200]}"}
    # THE TRAIL: what changed, on which sensor, why, by whom. A FAILED AUDIT WRITE DOES NOT FAIL THE
    # PLAN (the plan IS saved); it is logged so the gap is findable.
    try:
        with connect() as client:
            fleet_store.write_audit(client, scope="fleet", action="plan",
                                    target=sensor_id, reason=reason, actor=actor)
    except Exception as exc:  # noqa: BLE001
        logger.warning("fleet audit write failed: %s", exc)
    return 200, {
        "ok": True, "sensor_id": sensor_id, "applied": applied, "restart_targets": [],
        "note": (f"saved. {sensor_id} applies it on its next plan refresh (about 30 seconds) and "
                 f"reports the mode it ends up running."),
    }


def weirling_save_failure(exc: BaseException) -> tuple[int, dict[str, Any]]:
    """A fleet write the store did not classify: 500 with the FIRST 200 CHARACTERS of the reason.

    The truncation is the console's; a driver message can run to a page and the form has one line. Used
    by a surface whose CONNECTION failed as well, because the console wraps the connection in the same
    try.
    """
    logger.warning("weirling registration failed: %s", exc)
    return 500, {"ok": False, "error": f"could not save: {str(exc)[:200]}"}


def weirling_probe(connect: Any, *, sensor_id: str, iface: str,
                   seconds: int) -> tuple[int, dict[str, Any]]:
    """Queue a READ-ONLY capture-liveness probe for a remote weirling: (202, result).

    THE HUB NEVER REACHES INTO THE BOX. The sensor's own agent claims the request on its plan poll
    and measures its own NIC. This changes no mode, plan, sysctl or interface; an inline/ARP test is a
    different capability and is deliberately not served here.

    THE INTERFACE IS RESOLVED FROM THREE SOURCES IN ORDER -- the request, the sensor's plan, then the
    single NIC it reported -- and a sensor reporting several NICs is refused rather than guessed at,
    because probing the wrong interface would answer a question nobody asked.
    """
    from weirvern import fleet_store, probe_store  # noqa: PLC0415

    if sensor_id == gate_sensor_name():
        return 400, {"ok": False, "error": (
            "this is the hub's own sensor; use the Settings test run there. The remote capture probe "
            "is for units with an mTLS agent.")}
    try:
        with connect() as client:
            row = fleet_store.classify_one(client, sensor_id)
            regs = fleet_store.read_registrations(client)
    except Exception as exc:  # noqa: BLE001
        return 503, {"ok": False,
                     "error": f"the sensor could not be read: {str(exc)[:200]}"}
    reg = next((r for r in regs if r.sensor_id == sensor_id), None)
    if reg is None:
        return 404, {"ok": False, "error": f"no registered weirling named {sensor_id!r}"}
    iface = str(iface or (reg.plan.iface if reg.plan else "") or "").strip()
    if not iface:
        nics = list((row or {}).get("interfaces") or [])
        if len(nics) == 1:
            iface = nics[0]
        elif nics:
            return 400, {"ok": False, "error": (
                f"{sensor_id} reports several NICs ({', '.join(nics)}); name the capture interface "
                f"to probe.")}
    if not iface:
        return 400, {"ok": False, "error": (
            f"{sensor_id} has no capture interface in its plan and has not reported exactly one NIC; "
            f"name the interface to probe.")}
    try:
        with connect() as client:
            created = probe_store.create_request(client, sensor_id=sensor_id, iface=iface,
                                                 seconds=seconds)
    except Exception as exc:  # noqa: BLE001
        return 503, {"ok": False,
                     "error": f"the probe could not be queued: {str(exc)[:200]}"}
    return 202, {
        "ok": True, "request_id": created["request_id"], "sensor_id": created["sensor_id"],
        "iface": created["iface"], "seconds": created["seconds"], "status": created["status"],
        "scope": "capture-liveness",
    }


def network_scope_autofill(client: Client) -> tuple[int, dict[str, Any]]:
    """Create the scopes already implied by monitored networks, after one approval.

    DELIBERATELY A WRITE, NOT A READ SIDE EFFECT: reading coverage must never change what is
    monitored. The proposals come only from INTERCEPT_PLANS -- segments the operator already
    configured the sensor to watch -- never from observed traffic or an RFC1918 guess.

    THE 409 IS THE WHOLE POINT of the route being safe to call twice: scopes that already exist mean
    the operator edited something by hand, and overwriting that with a suggestion would undo their
    work.
    """
    from weirvern import networks  # noqa: PLC0415

    try:
        existing = networks.load_scopes(client)
        if existing:
            return 409, {"error": "network scopes are already declared", "code": 409}
        proposed = networks.suggested_monitored_scopes()
        if not proposed:
            return 400, {"error": "no monitored networks are configured to fill from", "code": 400}
        saved = [networks.save_scope(client, scope.public()) for scope in proposed]
        payload = networks.overview(client, hours=24)
    except ValueError as exc:
        return 400, {"error": str(exc), "code": 400}
    except Exception as exc:  # noqa: BLE001
        return network_autofill_failure(exc)
    payload["ok"] = True
    payload["created"] = len(saved)
    payload["scopes_added"] = [scope.public() for scope in saved]
    return 200, payload


def network_autofill_failure(exc: BaseException) -> tuple[int, dict[str, Any]]:
    logger.warning("network scope auto-fill failed: %s", exc)
    return 500, {"error": f"could not auto-fill network scopes: {str(exc)[:200]}", "code": 500}


def _retention_ratchet(settings: Any, configmap: dict | None) -> tuple[Any, str]:
    """The effective ratchet: the NEWEST of the worker's file and the operator's record.

    The GUI's /models is mounted read-only on purpose (the worker owns that volume), so the
    apply path records a reset in the ConfigMap. Reading both and taking the newer one is what
    makes a reset visible immediately while a later derivation can still raise the floor.
    A missing file and an absent key are a fresh install: no floor, exactly the old behaviour.
    """
    from weirvern import retention as retention_mod  # noqa: PLC0415

    loaded, error = retention_mod.load_ratchet(getattr(settings, "model_dir", None))
    recorded = retention_mod.ratchet_from_json(
        (configmap or {}).get(retention_mod.RETENTION_RATCHET_KEY)
        or (getattr(settings, "retention_ratchet", "") if settings is not None else ""))
    return retention_mod.latest_ratchet(loaded, recorded), error


def _retention_now(ctx: Any, current: dict[str, str], changes: dict) -> int | None:
    """The cluster's CURRENT effective retention, when this change touches retention.

    ONLY THEN, and only when the caller can reach ClickHouse: the plan route deliberately
    opens no database connection for an ordinary settings change, and inventing one would
    add a failure mode the console does not have. A failed measurement returns None, and the
    plan treats an explicit window as destructive rather than guessing it safe.

    THE EFFECTIVE WINDOW INCLUDES THE RATCHET. Measuring without it would compare a proposed
    value with the disk-derived number (239) while the tables actually hold the floor (284),
    and a change to 260 would be called a raise when it is a cut.
    """
    from weirvern import retention as retention_mod  # noqa: PLC0415
    from weirvern.admin import cluster_config as cc  # noqa: PLC0415

    rows = {cc.to_configmap_key(k) for k in changes}
    if not rows & {retention_mod.RETENTION_DAYS_KEY, retention_mod.RETENTION_RATIO_KEY}:
        return None
    connect = getattr(ctx, "connect_factory", None)
    if connect is None:
        return None
    try:
        state, _error = _retention_ratchet(getattr(ctx, "settings", None), current)
        with connect(getattr(ctx, "settings", None)) as ch:
            days, _report = retention_mod.resolve(
                ch,
                current.get(retention_mod.RETENTION_DAYS_KEY, retention_mod.AUTO),
                current.get(retention_mod.RETENTION_RATIO_KEY, retention_mod.DEFAULT_RATIO_PERCENT),
                ratchet=state,
            )
        return days
    except Exception as exc:  # noqa: BLE001 - unmeasured is a state the plan can express
        logger.debug("settings plan: the current retention could not be measured: %s", exc)
        return None


def settings_plan(ctx: Any, changes: dict) -> tuple[int, dict[str, Any]]:
    """Validate and describe a proposed change WITHOUT touching anything.

    THE UI CALLS THIS FIRST and shows the result, so the blast radius is stated before the change
    rather than discovered after.

    PROPOSALS ECHO THE CALLER'S KEY VOCABULARY. The GUI stages ROW keys (`sensor_mode`); `cc.plan`
    speaks CONFIGMAP keys (`SENSOR_MODE`) because the validator does. Returning the ConfigMap key
    meant the client's warning lookup never matched, so the costly-change confirmation dialog was
    skipped for exactly the changes that need it (the in-path mode among them). The translation back
    happens HERE, at the boundary, so both sides speak the key the caller used.
    """
    from weirvern.admin import cluster_config as cc  # noqa: PLC0415

    try:
        config = getattr(ctx, "config_client", None)
        current = cc.ClusterConfig().read() if config is None else config.read()
    except cc.ConfigError as exc:
        return 502, {"error": str(exc), "code": 502}
    except Exception as exc:  # noqa: BLE001
        return 502, {"error": f"could not read the configuration: {exc}", "code": 502}

    floor_state, _floor_error = _retention_ratchet(getattr(ctx, "settings", None), current)
    try:
        p = cc.plan({k: str(v) for k, v in changes.items()}, current,
                    retention_now_days=_retention_now(ctx, current, changes),
                    retention_floor_days=(floor_state.floor_days
                                          if floor_state is not None else None))
    except cc.ConfigError as exc:
        return 400, {"ok": False, "error": str(exc)}

    caller_key = {cc.to_configmap_key(k): k for k in changes}
    return 200, {
        "ok": True,
        "proposals": [
            {"key": caller_key.get(x.key, x.key), "current": x.current,
             "proposed": x.proposed, "restarts": x.restarts, "blast": x.blast,
             "warning": x.warning, "destructive": x.destructive}
            for x in p.proposals
        ],
        "restart_targets": p.restart_targets,
    }


def _proposed_value(changes: dict, config_key: str, current: dict, default: Any) -> Any:
    """The value an apply would write for a ConfigMap key, accepting EITHER vocabulary.

    The GUI stages ROW keys (`data_retention_days`); an API caller may send the ConfigMap
    key (`DATA_RETENTION_DAYS`). Looking up only one spelling silently falls back to the
    CURRENT value for the other, which would skip the disk-budget check on exactly the
    request that needs it.
    """
    row_key = config_key.lower()
    if config_key in changes:
        return changes[config_key]
    if row_key in changes:
        return changes[row_key]
    return current.get(config_key, default)


def settings_apply(ctx: Any, connect: Any, *, changes: dict, confirmed: bool, reason: str,
                   revert: bool, actor: str,
                   reset_ratchet: bool = False) -> tuple[int, dict[str, Any]]:
    """Write the configuration, then restart what reads it.

    THE WRITE IS VERIFIED BY READ-BACK inside ClusterConfig.apply, so a merge-patch that matched
    nothing is reported as a failure rather than as success. THE RESTART IS WHAT MAKES IT TAKE: a
    ConfigMap env var is read at process start, so without it the operator is told "saved" about a
    change that is inert -- which is why a saved-but-not-restarted change is reported as a failure of
    applying rather than folded into success.

    FOUR GATES STAND BETWEEN THE REQUEST AND THE WRITE, in this order, and every one of them is
    preserved: the in-path REASON (400), the plan's own validation (400), the explicit CONFIRMATION of
    any change carrying a warning (409 with the proposals), and the mode's own prerequisite gate (409),
    which is the same `mode.validate` the CLI runs. A GUI session must not be a way around it.

    A FIFTH GATE IS THE RATCHET. Lowering the effective window -- by an explicit day count or by
    lowering the ratio -- is refused unless the caller passes `reset_ratchet=True` AND a reason.
    The floor never follows a smaller number on its own; the write records the old floor, the new
    one, the actor and the reason, and the receipt carries both numbers.
    """
    from weirvern import apply_checks, fleet_store  # noqa: PLC0415
    from weirvern import retention as retention_mod  # noqa: PLC0415
    from weirvern.admin import cluster_config as cc  # noqa: PLC0415
    from weirvern.admin import web as web_mod  # noqa: PLC0415

    # BF-9: a destructive setting needs a reason, and the reason is recorded. Enabling siphon moves
    # the sensor IN PATH -- it becomes a cut point for its segment -- and the write trail must answer
    # who took it in-path and why.
    siphon_now = any(
        str(k).strip().lower() == "sensor_mode" and str(v).strip().lower() == "siphon"
        for k, v in changes.items())
    if siphon_now and not reason:
        return 400, {"ok": False, "error": (
            "enabling siphon puts this deployment in the traffic path; a reason is required and is "
            "recorded with your name and the time")}

    raw_changes = {k: str(v) for k, v in changes.items()}
    client = getattr(ctx, "config_client", None) or cc.ClusterConfig()
    try:
        current = client.read()
    except cc.ConfigError as exc:
        return 400, {"ok": False, "error": str(exc)}
    except Exception as exc:  # noqa: BLE001
        return 502, {"error": f"could not read the configuration: {exc}", "code": 502}

    # ── RETENTION IS MEASURED BEFORE IT IS JUDGED ────────────────────────────────────────────
    #
    # Three decisions read the same numbers: whether an explicit value fits the disk, whether
    # the change lowers what the tables hold, and what `auto` resolves to after the write.
    # Measured ONCE here, against the CURRENT setting (so "destructive" compares with what the
    # cluster has today); resolved again after the write with the new values.
    retention_touched = any(
        cc.to_configmap_key(k) in (retention_mod.RETENTION_DAYS_KEY,
                                   retention_mod.RETENTION_RATIO_KEY)
        for k in raw_changes)
    proposed_setting = _proposed_value(raw_changes, retention_mod.RETENTION_DAYS_KEY,
                                       current, retention_mod.AUTO)
    proposed_ratio = _proposed_value(raw_changes, retention_mod.RETENTION_RATIO_KEY,
                                     current, retention_mod.DEFAULT_RATIO_PERCENT)
    current_days: int | None = None
    budget_report: dict[str, Any] | None = None
    measure_error = ""
    ratchet_record: Any = None
    old_floor: int | None = None
    if retention_touched:
        # VALIDATE FIRST, so a bad number is refused with its own sentence rather than
        # surfacing as a measurement failure. These are the same parsers `cc.plan` uses.
        want_days: int | None = None
        if not retention_mod.is_auto(proposed_setting):
            try:
                want_days = retention_mod.normalise_days(proposed_setting)
            except ValueError as exc:
                return 400, {"ok": False, "error": str(exc)}
        try:
            ratio = retention_mod.normalise_ratio(proposed_ratio)
        except ValueError as exc:
            return 400, {"ok": False, "error": str(exc)}
        try:
            current_ratio = retention_mod.normalise_ratio(
                current.get(retention_mod.RETENTION_RATIO_KEY,
                            retention_mod.DEFAULT_RATIO_PERCENT))
        except ValueError:
            current_ratio = retention_mod.DEFAULT_RATIO_PERCENT
        ratchet, ratchet_error = _retention_ratchet(getattr(ctx, "settings", None), current)
        old_floor = int(ratchet.floor_days) if ratchet is not None else None
        try:
            with connect() as ch:
                current_days, _now = retention_mod.resolve(
                    ch, current.get(retention_mod.RETENTION_DAYS_KEY, retention_mod.AUTO),
                    current.get(retention_mod.RETENTION_RATIO_KEY,
                                retention_mod.DEFAULT_RATIO_PERCENT),
                    ratchet=ratchet)
                budget_report = retention_mod.auto_report(ch, ratio, ratchet=ratchet)
        except Exception as exc:  # noqa: BLE001 - an unmeasured disk is reported below
            measure_error = f"{type(exc).__name__}: {str(exc)[:160]}"
            logger.warning("settings: could not measure retention before applying: %s", exc)
            budget_report = retention_mod.unavailable(measure_error)
        if want_days is not None:
            if measure_error:
                # NO GUESSING. A window that cannot be compared with the disk is refused
                # rather than written blind; `auto` is the safe alternative and says why.
                return 400, {"ok": False, "error": (
                    f"cannot verify that {want_days} days fits this disk: {measure_error}. "
                    f"Set it to auto, or restore the database connection and try again.")}
            refusal = retention_mod.budget_refusal(want_days, budget_report or {})
            if refusal:
                return 400, {"ok": False, "error": refusal}

        # ── THE RATCHET ONLY FALLS BY EXPLICIT ACTION ────────────────────────────────────────
        # What would the number be after this change? For an explicit value it is that value;
        # for auto it is the resolved window (which includes the floor, and the capacity guard
        # when the floor no longer fits). If that is BELOW the floor, the request is a reset.
        lowered_to: int | None = None
        if old_floor is not None:
            if want_days is not None and want_days < old_floor:
                lowered_to = want_days
            elif want_days is None:
                effective = (budget_report or {}).get("days")
                disk_days = (budget_report or {}).get("disk_days")
                if isinstance(effective, int) and effective < old_floor:
                    # The capacity guard is refusing part of the floor; the held window is a cut.
                    lowered_to = int(effective)
                elif (ratio < current_ratio and isinstance(disk_days, int)
                      and disk_days < old_floor):
                    # LOWERING THE BUDGET IS A LOWERING, even while the floor currently masks
                    # it. Without the flag the operator is told what the reset would do and
                    # that the floor is what stands between them and it.
                    lowered_to = int(disk_days)
        if lowered_to is not None:
            if not reset_ratchet:
                return 400, {"ok": False, "error": (
                    f"the retention ratchet floor is {old_floor} days; lowering it to "
                    f"{lowered_to} days requires reset_ratchet=true and a reason. The floor only "
                    f"falls by explicit operator action -- without the flag nothing was written "
                    f"and no table was changed.")}
            if not reason:
                return 400, {"ok": False, "error": (
                    f"lowering the retention ratchet floor from {old_floor} days to {lowered_to} "
                    f"days is destructive and requires a reason, recorded with your name and the "
                    f"time.")}
        # THE NEW FLOOR. An explicit value becomes the floor when it is a raise or an authorised
        # reset; an auto window raises it to what the disk supports. A lower auto window is not a
        # new floor -- the guard may hold less than the floor, but the floor itself stays until
        # an operator resets it.
        new_floor: int | None = None
        if want_days is not None:
            new_floor = want_days
        elif isinstance((budget_report or {}).get("disk_days"), int):
            disk_days = int(budget_report["disk_days"])
            # NEVER QUIETLY LOWER THE FLOOR. A disk-derived number below the floor is normal
            # (that is what the ratchet exists for), so it is NOT recorded unless the operator
            # explicitly reset. A raise, a first record, or an authorised reset is recorded.
            if old_floor is None or disk_days > old_floor or reset_ratchet:
                new_floor = disk_days
        if new_floor is not None and new_floor != old_floor:
            ratchet_record = retention_mod.new_ratchet(
                new_floor, by=actor or "operator", reason=reason)

    try:
        p = cc.plan(raw_changes, current, retention_now_days=current_days,
                    retention_floor_days=old_floor)
    except cc.ConfigError as exc:
        return 400, {"ok": False, "error": str(exc)}
    except Exception as exc:  # noqa: BLE001
        return 502, {"error": f"could not read the configuration: {exc}", "code": 502}

    # A change with a warning must be confirmed explicitly: the value is legal but costly, and a plan
    # the caller never saw is not consent.
    if not confirmed and any(x.warning for x in p.proposals):
        return 409, {
            "ok": False, "needs_confirmation": True,
            "proposals": [{"key": x.key, "current": x.current, "proposed": x.proposed,
                           "warning": x.warning, "destructive": x.destructive}
                          for x in p.proposals if x.warning],
        }

    # LOWERING RETENTION IS DESTRUCTIVE, so it takes the same reason the in-path mode does:
    # the write trail has to answer who deleted history and why. The flag comes from the PLAN,
    # not from a second comparison here, so what the UI was shown and what the server demands
    # cannot disagree. The value is legal; that is a different question from whether it was
    # deliberate.
    if not reason and any(x.destructive for x in p.proposals):
        return 400, {"ok": False, "error": (
            "lowering data retention is destructive: ClickHouse expires every older row on its "
            "next merge, and that cannot be undone. A reason is required and is recorded with "
            "your name and the time.")}

    mode_error = web_mod.mode_gate(ctx, changes)
    if mode_error:
        return 409, {"ok": False, "error": mode_error}

    # THE PLAN OWNS THE CAPTURE PORT LIST. A per-NIC plan already says which ports capture and which
    # siphon; the legacy ZEEK_IFACES list can still name a NIC the plan leaves unassigned, and then
    # Settings says "capture" where the fleet row says "unassigned". Reconcile in the same write:
    # siphon needs Zeek too, so the effective list is capture ports UNION siphon ports.
    if "intercept_plans" in raw_changes:
        try:
            from weirvern.nic_plans import NicPlanSet  # noqa: PLC0415

            plans = NicPlanSet.from_json(raw_changes.get("intercept_plans") or "")
            ports = plans.capture_ports()
            if ports:
                raw_changes["zeek_ifaces"] = ",".join(ports)
                current_capture = str(current.get("CAPTURE_IFACE") or "").strip()
                if current_capture not in ports:
                    raw_changes["capture_iface"] = ports[0]
        except Exception as exc:  # noqa: BLE001
            # A malformed plan is refused by ClusterConfig.plan below with its own message; do not
            # turn it into a derivation traceback here.
            logger.warning("could not derive capture ports from intercept_plans: %s", exc)
    # The EFFECTIVE plan, including the reconciled keys, is what every later step uses.
    try:
        p = cc.plan(raw_changes, current, retention_now_days=current_days,
                    retention_floor_days=old_floor)
    except cc.ConfigError as exc:
        return 400, {"ok": False, "error": str(exc)}

    # APPLY-TIME CHECKS (BF-14): named assertions between the plan and the write. A failure BLOCKS
    # the apply and names itself; a check that cannot run says why. THE CHECKS FAILING MUST NOT FAIL
    # THE APPLY: they are a gate on the CHANGE, not a dependency of the write.
    try:
        norm_changes = {cc.to_configmap_key(k): v for k, v in raw_changes.items()}
        with connect() as ch:
            checks = apply_checks.run_apply_checks(
                changes=norm_changes, current=current, ch_client=ch)
    except Exception as exc:  # noqa: BLE001
        logger.warning("apply-time checks could not run: %s", exc)
        checks = {"results": [], "blocked": False, "failed": [],
                  "summary": f"the apply-time checks could not run ({type(exc).__name__})"}
    if checks.get("blocked"):
        return 409, {
            "ok": False, "blocked": True,
            "error": ("blocked by apply-time checks: "
                      + "; ".join(checks.get("failed") or [])),
            "tests": checks.get("results") or [],
            "summary": checks.get("summary") or "",
        }

    write_changes = dict(raw_changes)
    if ratchet_record is not None:
        # THE OPERATOR'S RECORD RIDES THE SAME PATCH as the settings. One write means a failed
        # apply cannot leave a reset recorded that no setting reflects (or the reverse).
        write_changes[retention_mod.RETENTION_RATCHET_KEY] = ratchet_record.to_json()
    try:
        landed = client.apply(write_changes, reason=reason, by=actor)
    except cc.ConfigError as exc:
        # A REFUSED WRITE STILL OWES A PER-ITEM RECEIPT: the read-back raised, but a fresh read can
        # still say which values ARE there, and that beats a whole-batch error nobody can act on.
        after = None
        try:
            after = client.read()
        except Exception:  # noqa: BLE001
            after = None
        return 502, {
            "ok": False, "error": str(exc),
            "at": datetime.datetime.now(datetime.UTC).isoformat(timespec="seconds"),
            "items": cc.receipt_items(raw_changes, None, after=after, error=str(exc)),
        }

    restarted: list[str] = []
    restart_errors: list[str] = []
    for target in p.restart_targets:
        try:
            client.restart(target)
            restarted.append(target)
        except cc.ConfigError as exc:
            restart_errors.append(str(exc))

    # ── RETENTION: THE CONFIGMAP VALUE IS NOT THE ENFORCEMENT ────────────────────────────────
    #
    # Writing DATA_RETENTION_DAYS records a decision; ClickHouse keeps its old TTL until
    # something ALTERs it. This is that something, in the same request. In `auto` the value is
    # DERIVED AGAIN here -- from current free disk and the ingest actually observed -- so the
    # receipt carries the arithmetic and the operator never edits a day count to follow the
    # disk. `converge` then reads `system.tables` back: `effective_days` is what the tables
    # actually have, a table the ALTER could not change is named with its previous TTL still
    # in place, and a read-back that disagrees is reported in `mismatched`.
    retention_report: dict[str, Any] | None = None
    if retention_touched:
        landing_window = landed.get(retention_mod.RETENTION_DAYS_KEY, retention_mod.AUTO)
        landing_ratio = landed.get(retention_mod.RETENTION_RATIO_KEY,
                                   retention_mod.DEFAULT_RATIO_PERCENT)
        # THE STATE THE LANDED CONFIGMAP IMPLIES, not the one this request started with. A reset
        # record written with the patch is the state; otherwise the existing floor still applies.
        post_state, _post_error = _retention_ratchet(
            getattr(ctx, "settings", None), landed)
        try:
            with connect() as ch:
                days, derivation = retention_mod.resolve(ch, landing_window, landing_ratio,
                                                         ratchet=post_state)
                retention_report = (
                    retention_mod.not_derived_report(derivation) if days is None
                    else retention_mod.converge(ch, days, derivation=derivation,
                                                bound_days=days))
        except Exception as exc:  # noqa: BLE001 - an ALTER failure is a report, not a 500
            logger.warning("settings: retention could not be applied: %s", exc)
            retention_report = {
                "ok": False, "applied": False, "requested_days": None,
                "derivation": retention_mod.unavailable(str(exc)),
                "tables": [], "changed": [], "failed": [], "failed_reasons": {},
                "missing": [], "mismatched": [],
                "error": f"{type(exc).__name__}: {str(exc)[:200]}",
                "summary": ("the setting was saved, but the tables' TTLs could not be read or "
                            "changed: " + str(exc)[:160]),
            }
        # THE RECEIPT NAMES BOTH FLOORS. A reset is only auditable if the number it replaced is
        # in the same object as the number it installed.
        effective_floor = (ratchet_record.floor_days if ratchet_record is not None
                           else (post_state.floor_days if post_state is not None else None))
        retention_report["ratchet"] = {
            "previous_floor_days": old_floor,
            "floor_days": effective_floor,
            "set_at": (ratchet_record.set_at if ratchet_record is not None
                       else (post_state.set_at if post_state is not None else "")),
            "by": (ratchet_record.by if ratchet_record is not None
                   else (post_state.by if post_state is not None else "")),
            "reason": (ratchet_record.reason if ratchet_record is not None
                       else (post_state.reason if post_state is not None else "")),
            "reset": bool(reset_ratchet and old_floor is not None
                          and effective_floor is not None and effective_floor < old_floor),
            "changed": bool(ratchet_record is not None),
        }

    # US-10: THE TRAIL GETS THE SETTINGS WRITE TOO, one row PER KEY so a multi-key apply stays
    # linkable from a single key's provenance row. A failed audit write does not fail the apply.
    action = "revert" if revert else "apply"
    try:
        with connect() as ch:
            for key in raw_changes:
                fleet_store.write_audit(
                    ch, scope="settings", action=action, target=str(key),
                    reason=reason, actor=actor)
    except Exception as exc:  # noqa: BLE001
        logger.warning("settings audit write failed: %s", exc)

    payload: dict[str, Any] = {
        "ok": True,
        # TRANSLATED AT THE BOUNDARY: `changes` is ROW-keyed (what the GUI staged) and `landed` is
        # the ConfigMap's own data (ConfigMap keys). `landed.get(row_key)` returned "" for every key,
        # so the confirmation read `saved: reverse_dns=(empty)` AFTER A WRITE THAT ACTUALLY LANDED:
        # the write was right and the receipt lied.
        "applied": {k: landed.get(cc.to_configmap_key(k), "") for k in raw_changes},
        "restarted": restarted,
        "restart_errors": restart_errors,
        "note": ("restarted " + ", ".join(restarted)) if restarted
                else "no workload needed a restart",
        "at": datetime.datetime.now(datetime.UTC).isoformat(timespec="seconds"),
        "items": cc.receipt_items(raw_changes, landed),
        "tests": checks.get("results") or [],
        "summary": checks.get("summary") or "",
    }
    if retention_report is not None:
        payload["retention"] = retention_report
        # A SAVED SETTING OVER A CLUSTER THAT DID NOT CHANGE IS NOT A SUCCESS. The ConfigMap
        # write did land, and `applied` says so; `ok: false` is the summary verdict, and the
        # per-table rows say which ALTER or read-back disagreed.
        payload["ok"] = bool(retention_report.get("ok"))
    return 200, payload


def settings_test(ctx: Any, connect: Any, *, seconds: float) -> tuple[int, dict[str, Any]]:
    """Run the intercept for a bounded TEST window, then revert the mode to loch.

    THE MOST CONSEQUENTIAL WRITE ON THIS PAGE: while the probe runs, this sensor is genuinely in the
    traffic path for the hosts the plan names -- the ARP mappings are real and the traffic really
    relays. What the probe changes is the ENDING: the mode is written back to loch in a finally, and
    the worker's restart stops the supervised intercept through its orderly SIGTERM path.

    THE LIVENESS EVIDENCE COMES FROM status.siphon_liveness -- the same check `weirvern status` uses --
    so the probe's verdict and the CLI's cannot disagree about what "an intercept was running" means.

    200 EVEN WHEN NO EVIDENCE WAS SEEN: the run happened and its outcome is the answer; only a failed
    REVERT is a problem to flag loudly, which is why that answers 500.
    """
    from weirvern.admin import cluster_config as cc  # noqa: PLC0415
    from weirvern.admin import siphon_probe as probe_mod  # noqa: PLC0415

    if getattr(ctx, "config_client", None) is not None:
        client = ctx.config_client
    else:
        try:
            client = cc.ClusterConfig()
        except cc.ConfigError as exc:
            return 503, {"ok": False, "error": str(exc)}

    def liveness():
        """Intercept evidence via the same check the CLI uses. None-safe."""
        try:
            with connect() as ch:
                configured = ""
                try:
                    configured = str((client.read() or {}).get("SENSOR_MODE") or "")
                except Exception:  # noqa: BLE001
                    configured = ""
                return status_mod.siphon_liveness(configured, ch)
        except Exception as exc:  # noqa: BLE001
            return {"live": False, "error": f"could not read intercept evidence: {exc}"}

    try:
        result = probe_mod.run_probe(client, seconds=seconds, liveness=liveness)
    except Exception as exc:  # noqa: BLE001
        logger.error("siphon probe failed", exc_info=True)
        return 500, {"ok": False, "error": f"the test run failed: {exc}"}
    if result.get("ok") is False:
        return 422, result
    return (200 if result.get("reverted") else 500), result


def settings_sonar(ctx: Any, connect: Any, *, sensor_id: str, iface: str, mgmt: str,
                   progress: Any = None) -> tuple[int, dict[str, Any]]:
    """Survey the capture interface's segment and return recommendations.

    THE SURVEY RUNS AS A ONE-SHOT JOB, NOT IN THIS PROCESS: this pod has its own network namespace and
    no capabilities, so a survey here would measure the wrong machine and recommend settings for
    interfaces the sensor node does not have. It changes NOTHING -- the UI stages the recommendations
    as pending changes -- and the only frames it sends are ARP requests.

    THE NAMED-SENSOR FORM surveys THAT sensor's port, resolved in a deliberate order: an explicit name,
    else the sensor's declared capture interface, else its single reported NIC -- and REFUSES, naming
    the candidates, when the answer is ambiguous. Surveying the wrong port produces a confident plan
    for a segment the sensor is not on, which is worse than no survey at all.

    A NAMED REMOTE SENSOR IS NOT A JOB IN THIS CLUSTER: the request goes through the ClickHouse handoff
    the remote agent polls, and that branch comes BEFORE any ClusterConfig or Job creation, or a hub
    interface with the same name would be surveyed and returned under the remote sensor's id.
    """
    import os  # noqa: PLC0415

    from weirvern.admin import cluster_config as cc  # noqa: PLC0415
    from weirvern.admin import sonar as sonar_mod  # noqa: PLC0415
    from weirvern.admin import web as web_mod  # noqa: PLC0415

    hub_sensor = web_mod._gate_sensor_name()
    remote = bool(sensor_id) and sensor_id != hub_sensor

    if remote:
        # A NAMED WEIRLING, so the port comes from the SENSOR's own report/plan. BOTH READS ARE TYPED:
        # the declaration from the registry (plan_subject), the report from the heartbeat rows.
        try:
            from weirvern import fleet_store  # noqa: PLC0415

            with connect() as ch:
                reg, refusal = fleet_store.plan_subject(ch, sensor_id)
                if refusal:
                    return 400, {"ok": False, "error": refusal}
                hb_rows, _hb_err = fleet_store.read_heartbeats(ch)
        except Exception as exc:  # noqa: BLE001
            return 503, {"ok": False,
                         "error": f"the sensor could not be read: {str(exc)[:200]}"}
        if not iface:
            iface = str(reg.plan.iface if reg is not None else "").strip()
        if not iface:
            nics = next(([str(n) for n in (hb.get("interfaces") or [])]
                         for hb in hb_rows if hb.get("sensor_id") == sensor_id), [])
            if len(nics) == 1:
                iface = nics[0]
            elif nics:
                return 400, {
                    "ok": False,
                    "error": (f"{sensor_id} reports several NICs ({', '.join(nics)}), so which one "
                              f"to survey is a choice, not a guess: name the capture interface."),
                    "sensor": sensor_id,
                    "interfaces": nics,
                }
            else:
                return 400, {
                    "ok": False,
                    "error": (f"{sensor_id} has not reported its NICs and no capture interface is "
                              f"set in its plan, so there is nothing to survey for it yet. The "
                              f"sensor reports its interfaces on every heartbeat -- wait for one, "
                              f"or name an interface."),
                    "sensor": sensor_id,
                }

    if not iface:
        # The interface the intercept would ACTUALLY run on: CAPTURE_IFACE wins when set (the
        # supervisor's rule), else the configured capture interface -- read from the environment so
        # the default cannot drift from what the worker's supervisor uses.
        iface = (os.environ.get("CAPTURE_IFACE") or os.environ.get("ZEEK_IFACE") or "").strip()
    if not mgmt:
        mgmt = (os.environ.get("MGMT_IFACE") or "").strip()
    if not iface:
        return 400, {
            "ok": False,
            "error": ("no capture interface is configured, so there is nothing to survey. Set the "
                      "capture interface (ZEEK_IFACE) in Settings first, or name one in this "
                      "request."),
        }

    # THE SHAPE CHECK AT THE REQUEST BOUNDARY (audit F091, CONFIRMED): `interface`/`mgmt_interface`
    # are the only free-text inputs this page takes, and they went from the body into a privileged
    # Job's env with no contract at all. `build_job` refuses too, so no caller can bypass this; the
    # check is repeated HERE because only here can the refusal carry a sentence an operator reads.
    why = sonar_mod.validate_survey_ifaces(iface, mgmt)
    if why:
        return 400, {"ok": False,
                     "error": f"cannot survey: {why}. {sonar_mod.iface_input_remedy()}"}

    if remote:
        try:
            with connect() as ch:
                result = sonar_mod.run_remote_survey(ch, sensor_id, iface, mgmt,
                                                     progress=progress)
        except sonar_mod.SonarError as exc:
            return 502, {"ok": False, "error": str(exc), "sensor": sensor_id}
        if isinstance(result, dict):
            result["sensor"] = sensor_id
        return (200 if result.get("ok") else 422), result

    client = getattr(ctx, "config_client", None)
    if client is None:
        try:
            client = cc.ClusterConfig()
        except cc.ConfigError as exc:
            return 503, {"ok": False, "error": str(exc)}

    try:
        result = sonar_mod.run_survey_job(client, iface, mgmt, progress=progress)
    except sonar_mod.SonarError as exc:
        return 502, {"ok": False, "error": str(exc)}
    # A refusal INSIDE the job (it ran, and said no) passes through with its reason, distinct from a
    # job that could not run at all. STAMPED WITH THE SENSOR IT RAN FOR, so the reply cannot be
    # staged against another one's plan.
    if isinstance(result, dict):
        result["sensor"] = sensor_id
    if isinstance(result, dict) and result.get("ok") is False:
        return 422, result
    return 200, result


def model_action(client: Client, *, action: str, note: str, target_id: str,
                 by: str) -> tuple[int, dict[str, Any]]:
    """File a retrain, keep or trash request, and say what happens next.

    NOTHING LIVE CHANGES ON REQUEST. A retrain files a candidate the worker builds on its next cycle;
    a keep or a trash is a DECISION the worker applies then. The note on the request says which of
    those the caller just did, because "filed" alone reads as done.

    THE TARGET OF A KEEP OR TRASH IS THE LATEST RETRAIN unless one is named, and a deployment with no
    retrain to judge answers 400 rather than filing an action with an empty target -- which the worker
    would then have to guess about.

    `note` IS REQUIRED FOR keep AND trash (checked by the caller) AND NOT RECORDED: the request is
    filed with an empty note, exactly as the console has always done. Preserved rather than fixed here,
    because whether the note belongs on the action row or in the write trail is a product decision.
    """
    from weirvern.models import actions  # noqa: PLC0415

    try:
        if action == actions.RETRAIN:
            action_id = actions.request(client, action=actions.RETRAIN, by=by, note=note)
            note_out = ("filed; the worker builds a candidate on its next cycle and NOTHING live "
                        "changes until you keep it")
        else:
            target = target_id
            if not target:
                latest = actions.latest(client, actions.RETRAIN) or {}
                target = str(latest.get("action_id") or "")
            if not target:
                return 400, {"error": "there is no retrain to judge yet", "code": 400}
            action_id = actions.request(client, action=action, by=by, target_id=target, note="")
            note_out = ("filed; the worker applies it on its next cycle" if action == actions.KEEP
                        else "filed; the worker discards the candidate on its next cycle")
    except Exception as exc:  # noqa: BLE001
        logger.warning("model action failed: %s", exc)
        return 502, {"error": f"could not record the request: {type(exc).__name__}", "code": 502}
    return 200, {"ok": True, "action": action, "action_id": action_id, "note": note_out}


def discover(client: Client, *, hours: int, feed: str, proto: int | None, addr: str,
             sensor: str, port: int | None, offset: int, limit: int,
             src: list, dst: list, sport: list, dport: list) -> dict[str, Any]:
    """DISCOVER: raw flows with a filter bar -- Kibana's Discover over the flow table.

    ONE ROUTE, THREE FEEDS. DNS filters the CLIENT address and hides the chips; Zeek takes only the
    sensor; netflow takes the whole bar. The branch lives here so both surfaces cannot choose a
    different feed for the same request.
    """
    from weirvern.admin import soc as soc_mod  # noqa: PLC0415

    try:
        if feed == "dns":
            return soc_mod.discover_dns(
                client, hours=hours, limit=limit, offset=offset,
                client_ip=addr, sensor=sensor,
            )
        if feed == "zeek":
            return soc_mod.discover_zeek(client, hours=hours, sensor=sensor)
        return soc_mod.discover(
            client, hours=hours, proto=proto, addr=addr or None, port=port,
            sensor=sensor or None, limit=limit, offset=offset,
            src=src, dst=dst, sport=sport, dport=dport,
        )
    except Exception as exc:  # noqa: BLE001
        return discover_failure(exc)


def discover_failure(exc: BaseException) -> dict[str, Any]:
    """The console's own failure shape for /api/discover."""
    from weirvern.admin.web import read_failure  # noqa: PLC0415

    logger.warning("discover unavailable: %s", exc)
    return {"available": False, "rows": [], "reason": read_failure(exc),
            "data_error": str(exc)}


def anomalies(client: Client, *, limit: int, min_score: float, hours: int, host: str,
              severity: str, model: str, feature: str, unreviewed_only: bool,
              watched_only: bool, settings: Any) -> dict[str, Any]:
    """The grouped anomaly queue, its header tiles, and every per-row state that rides along.

    EVERY AUXILIARY READ DEGRADES SEPARATELY. Reviews, adjustments and the watch list are read
    apart from the rows so a table that does not exist yet on an old schema leaves per-row
    "unavailable" chips rather than failing the whole queue. Two filters are SKIPPED when their
    state could not be read, because filtering on a state nobody could read would answer "nothing
    is unreviewed" -- a confident claim built from a failed query.
    """
    from weirvern import fleet_store  # noqa: PLC0415
    from weirvern.admin.web import _attach_anomaly_locations, _interface_network_names  # noqa: PLC0415
    from weirvern.criticality import annotate_bands, band_counts_from_severity_counts  # noqa: PLC0415

    rows = status_mod.anomalies_grouped(
        client, limit=limit, min_score=min_score, host=host, severity=severity,
        model=model, feature=feature, hours=hours)
    # ONE BAND PER ROW, SHIPPED FROM THE SERVER. The Alerts page renders the ripple list and
    # this list from the same low/medium/high vocabulary; the browser never folds a severity
    # itself, so the two lists cannot drift. A row with no severity is `unclassified` -- an
    # explicit state, not a quiet low.
    annotate_bands(rows)
    # The header tiles: counts per severity under min-score + host, NOT under the severity filter
    # itself (see status.anomaly_severity_counts for why).
    severity_counts = status_mod.anomaly_severity_counts(
        client, min_score=min_score, host=host, feature=feature, hours=hours)
    band_counts = band_counts_from_severity_counts(severity_counts)
    # FIRED VS ACTED-ON (BF-12): the alert-budget line, self-guarding like the tiles.
    discipline = status_mod.anomaly_discipline_counts(
        client, min_score=min_score, host=host, hours=hours)
    # SOC-1: review state, read separately so a missing table degrades to per-row chips.
    idx, rev_err, covered_since = status_mod.review_index(client)
    # covered_since is the index's OWN lower bound, so a row older than the review window is marked
    # unknowable rather than reading as "unreviewed".
    status_mod.attach_group_reviews(rows, idx, rev_err, covered_since)
    adj_idx, adj_err = status_mod.adjustment_index(client)
    status_mod.attach_adjustments(rows, adj_idx, adj_err)
    # US-6: the UNFILTERED total under the same min-score. A failed read is None (the header omits
    # "of Y"), never a zero.
    try:
        total_unfiltered = status_mod.anomalies_total_count(
            client, min_score=min_score, hours=hours)
    except Exception:  # noqa: BLE001
        total_unfiltered = None
    watch_set, watch_err = status_mod.watch_index(client)
    for r in rows:
        r["watched"] = (r.get("src_addr") in watch_set) if watch_err is None else None
    # WHERE EACH ALERT HAPPENED: the weirling that sees this host's network and the network itself,
    # resolved from the fleet's declared segments so the console and the fleet tab cannot disagree.
    try:
        fleet = fleet_store.build_fleet(client)
        _attach_anomaly_locations(
            rows, fleet.get("sensors") or [],
            _interface_network_names(getattr(settings, "interface_networks", "")),
        )
    except Exception as loc_exc:  # noqa: BLE001
        logger.warning("anomaly locations unavailable: %s", loc_exc)
    # THE FILTER IS SKIPPED WHEN THE STATE IS UNREADABLE: see the docstring.
    if unreviewed_only and rev_err is None:
        # A group counts as unreviewed when ANY of its occurrences is.
        rows = [r for r in rows if r.get("unreviewed_n", 0) > 0]
    if watched_only and watch_err is None:
        rows = [r for r in rows if r.get("watched")]
    # THE FUSED-SCORE STATUS IS COMPUTED WITH THE ROWS, so the header sentence and the list
    # cannot disagree. `score` is the strongest row in the list, `target` is the configured
    # strong-signal bar, and `detectors` is the union of the models that contributed to them.
    from weirvern.ensemble import strong_signal_threshold  # noqa: PLC0415

    try:
        fused_target = float(strong_signal_threshold(settings))
    except Exception:  # noqa: BLE001 - a settings read failure must not hide the list
        fused_target = None
    scores = []
    detector_names: set[str] = set()
    for row in rows:
        try:
            scores.append(float(row.get("anomaly_score") or 0.0))
        except (TypeError, ValueError):
            continue
        for name in str(row.get("detected_by_models") or "").split(","):
            if name.strip():
                detector_names.add(name.strip())
    fused = {
        "score": max(scores) if scores else None,
        "target": fused_target,
        "detectors": sorted(detector_names),
    }
    return web_api.anomalies_payload(
        rows, severity_counts=severity_counts, band_counts=band_counts, discipline=discipline,
        watch_error=watch_err, total_unfiltered=total_unfiltered, fused=fused)


def sluice(with_client: Any, *, hours: int, settings: Any) -> dict[str, Any]:
    """Every rule (live AND lapsed), the gate's state, and the static policy table.

    TAKES A CONNECTION FACTORY because the policies and the effective settings are STATIC: they are
    populated even when the database is unreachable, so an operator can read what each level does
    without a working cluster. A fetcher handed an open client would lose that the moment the
    connect failed, which is the exact case this payload exists to describe.

    BOTH RULE SETS, deliberately: "this rule exists but is not enforced" and "this rule does not
    exist" are different statements, and showing only live rules would make a lapsed block look
    DELETED -- the question an operator asks after a block stops working.
    """
    import datetime as _dt  # noqa: PLC0415

    from weirvern.admin.web import _gate_sensor_name  # noqa: PLC0415

    now = _dt.datetime.now(_dt.UTC)

    payload: dict = {
        "available": False, "reason": "", "rules": [], "live": 0, "gate": {},
        "policies": {}, "criticality": "", "enabled": False, "iface": "",
        "hits_hours": hours,
        # Firing evidence, keyed by rule id. "The rule is live" and "the rule has done
        # anything" are different statements, and only the event table can tell them apart.
        # An unreadable event table is its own state: the rule rows then say the evidence
        # could not be read rather than rendering a confident zero.
        "evidence": {}, "evidence_available": False, "evidence_reason": "",
        "blocklists_available": False, "blocklists_reason": "",
    }
    # The policies are STATIC, so they are populated even when the database is unreachable.
    try:
        from weirvern.sluice import CRITICALITY_POLICIES  # noqa: PLC0415

        payload["policies"] = {
            k: {"label": v["label"], "description": v["description"],
                "ttl_minutes": v["ttl_minutes"], "min_severity": v["min_severity"],
                "min_confidence": v["min_confidence"]}
            for k, v in CRITICALITY_POLICIES.items()
        }
    except Exception:  # noqa: BLE001
        pass
    try:
        payload["criticality"] = str(settings.sluice_criticality)
        payload["enabled"] = bool(settings.sluice_enabled)
        payload["iface"] = str(settings.sluice_iface or settings.zeek_iface or "")
    except Exception:  # noqa: BLE001
        pass

    payload["blocklists"] = []
    payload["hits"] = []
    try:
        from weirvern import blocklists, sluice_store  # noqa: PLC0415

        with with_client() as client:
            rules = sluice_store.load_all_rules(client)
            gate = sluice_store.load_gate_state(client, sensor=_gate_sensor_name())
            # The imported lists and the recent domain hits ride the same payload: "what would be
            # caught" and "what was caught" in one place, each degrading on its own.
            try:
                payload["blocklists"] = blocklists.load_sources(client)
                payload["blocklists_available"] = True
            except Exception as exc:  # noqa: BLE001
                payload["blocklists_reason"] = f"{type(exc).__name__}: {exc}"[:200]
                logger.warning("blocklist sources unavailable: %s", exc)
            try:
                # SAME WINDOW AS THE BLOCKS DRILL (SL3). "Recent" is not a window: the overview
                # chip and the ledger must count the same interval, or the operator sees 5 hits on
                # one surface and 0 on the other and cannot tell which is current.
                hit_rows = client.query(
                    "SELECT ts, rule_id, domain, query, src_addr "
                    "FROM weirvern.sluice_events WHERE kind = 'dns' "
                    f"AND ts >= now() - INTERVAL {int(hours)} HOUR "
                    "ORDER BY ts DESC LIMIT 50").result_rows
                payload["hits"] = [
                    {"ts": r[0].isoformat() if hasattr(r[0], "isoformat") else str(r[0]),
                     "rule_id": str(r[1]), "domain": str(r[2]), "query": str(r[3]),
                     "client": str(r[4])}
                    for r in hit_rows]
            except Exception as exc:  # noqa: BLE001
                logger.warning("domain hits unavailable: %s", exc)
            # ── WHAT EACH RULE HAS ACTUALLY DONE, IN THE SAME WINDOW ─────────────────────────
            #
            # The rule row is about to read as a sentence with its evidence ("12 matches in 24h,
            # last 6m ago"). That sentence is only honest when it comes from the event table:
            # an installed rule with no events is a rule that has caught nothing, which is a
            # different and more useful statement than a blank cell. One grouped read keeps the
            # cost flat as the rule count grows.
            try:
                ev_rows = client.query(
                    "SELECT rule_id, count(), max(ts), sum(packets), sum(bytes), "
                    "countIf(kind = 'dns'), countIf(kind != 'dns') "
                    "FROM weirvern.sluice_events "
                    f"WHERE ts >= now() - INTERVAL {int(hours)} HOUR "
                    "GROUP BY rule_id").result_rows
                payload["evidence"] = {}
                for r in ev_rows:
                    last = r[2]
                    age = None
                    if isinstance(last, _dt.datetime):
                        if last.tzinfo is None:
                            last = last.replace(tzinfo=_dt.UTC)
                        age = int((now - last).total_seconds())
                    payload["evidence"][str(r[0] or "")] = {
                        "events": int(r[1] or 0),
                        # The AGE is the honest reading: the GUI can print "6m ago" without
                        # doing clock arithmetic against a server in another timezone.
                        "last_age_s": age,
                        "last_ts": (last.isoformat() if hasattr(last, "isoformat")
                                    else str(last or "")),
                        "packets": int(r[3] or 0),
                        "bytes": int(r[4] or 0),
                        "dns": int(r[5] or 0),
                        "flow": int(r[6] or 0),
                    }
                payload["evidence_available"] = True
            except Exception as exc:  # noqa: BLE001
                payload["evidence_reason"] = f"{type(exc).__name__}: {exc}"[:200]
                logger.warning("rule firing evidence unavailable: %s", exc)
            # ONE RULE STORE, MANY GATES: every box that can enforce reports its own row, so the
            # operator sees who is actually filtering (and who has stopped).
            fleet_gates = sluice_store.load_gate_states(client)
    except Exception as exc:  # noqa: BLE001
        logger.warning("sluice view unavailable: %s", exc)
        return {**payload, "available": False,
                "reason": f"cannot read the gate: {type(exc).__name__}"}

    now = _dt.datetime.now(_dt.UTC)
    rows = []
    evidence = payload.get("evidence") or {}
    for r in rules:
        exp = r.expires_at
        if exp is not None and exp.tzinfo is None:
            # ClickHouse can hand back naive values; comparing one to an aware `now` RAISES, and
            # the row would then render as neither live nor lapsed.
            exp = exp.replace(tzinfo=_dt.UTC)
        rows.append({
            "rule_id": r.rule_id, "describes": r.describes(),
            # What the sentence means: a name rule's enforcement is its resolved addresses, and
            # alert-mode rules never reach the kernel (US-SL1).
            "domain": r.domain, "mode": r.mode,
            "resolved": len(r.resolved_ips or []),
            "src_cidr": r.src_cidr, "dst_cidr": r.dst_cidr, "protocol": r.protocol,
            "dst_port": r.dst_port, "direction": r.direction, "reason": r.reason,
            "origin": r.origin, "severity": r.severity, "created_by": r.created_by,
            "origin_ref": r.origin_ref, "live": r.is_live(now),
            "revoked": r.revoked_at is not None,
            # A PARKED RULE (schema/017): deliberately switched off, reversible, still listed.
            "disabled": r.disabled_at is not None,
            "expires_at": exp.isoformat() if exp else "",
            # SECONDS, not a timestamp: the GUI should not do clock arithmetic against a server it
            # may not share a timezone with, and a NEGATIVE value is a meaningful answer ("lapsed
            # N seconds ago") rather than an error.
            "expires_in_s": int((exp - now).total_seconds()) if exp else None,
            # The rule's own firing record for the selected window, or null when the event
            # table could not be read. Never a fabricated zero: the row renders "evidence
            # unavailable" instead of "no matches", because those mean different things.
            "evidence": evidence.get(r.rule_id),
        })
    # A GATE THAT STOPPED IS ITS OWN STATE, not an absent one. Four missed intervals is the
    # threshold: the cadence is minutes, and one slow cycle is not news.
    try:
        stale_after = max(180, 4 * int(settings.sluice_interval_s))
    except Exception:  # noqa: BLE001
        stale_after = 180
    # The local gate row is the same shape as a fleet row: the renderer reasons about both, and
    # "last reported" must be a measured age rather than "no report time" for the hub.
    try:
        updated = gate.get("updated_at")
        if isinstance(updated, _dt.datetime):
            if updated.tzinfo is None:
                updated = updated.replace(tzinfo=_dt.UTC)
            gate["age_s"] = int((now - updated).total_seconds())
    except Exception:  # noqa: BLE001
        pass
    payload.update({
        "available": True, "rules": rows,
        "live": sum(1 for r in rows if r["live"]), "gate": gate,
        **web_api.gates_payload(fleet_gates, _gate_sensor_name(), stale_after, now),
    })
    return payload


def settings_payload(*, settings: Any, backend: Any, config_client: Any = None,
                     auth: Any = None, role: str = "", via: str = "", identity: Any = None,
                     accounts_on: bool = False, connect: Any = None) -> dict[str, Any]:
    """The effective configuration, plus whether THIS caller may change it.

    THE LIVE CLUSTER CONFIG IS THE SOURCE, not this pod's startup environment: a settings change
    restarts the WORKER, not the GUI, so the pod env freezes at its start and the tab would report
    stale values through a demonstrably live intercept. When the cluster is unreachable the pod env
    remains the honest fallback, and rows keep their provenance labels.

    THE REQUEST-SCOPED FACTS ARRIVE AS ARGUMENTS (role, identity, accounts_on, auth) rather than
    being re-derived here: they belong to the request, and the two surfaces compute them from the
    same shared helpers.
    """
    import os  # noqa: PLC0415

    from weirvern.admin import cluster_config as cc  # noqa: PLC0415

    configmap = None
    client = config_client
    try:
        if client is None:
            client = cc.ClusterConfig()
        configmap = client.read()
    except Exception as exc:  # noqa: BLE001
        logger.debug("settings: live ConfigMap unavailable (%s); showing this process's view", exc)
    try:
        # The backend is passed so the VERSION row reports the running image tag rather than the
        # package's own literal, which had drifted (0.4.0 vs 0.5.6).
        #
        # THE RETENTION ARITHMETIC rides the payload because 'auto' is not a number the UI can
        # derive itself: free space and the observed ingest are measured HERE, against the LIVE
        # ConfigMap's ratio (a pod's startup env would be stale exactly like the values the live
        # map already corrects). A failed measurement is a sentence, not a blank row.
        retention_status = None
        if connect is not None:
            from weirvern import retention as retention_mod  # noqa: PLC0415

            try:
                ratio = ((configmap or {}).get(retention_mod.RETENTION_RATIO_KEY)
                         or os.environ.get(retention_mod.RETENTION_RATIO_KEY)
                         or retention_mod.DEFAULT_RATIO_PERCENT)
                # THE FLOOR AND ITS DATE are part of the row: the sentence the console renders
                # must state the ratchet beside the number, not hide it in a tooltip.
                ratchet, ratchet_error = _retention_ratchet(settings, configmap)
                with connect() as ch:
                    retention_status = retention_mod.auto_report(ch, ratio, ratchet=ratchet)
                if ratchet_error:
                    retention_status["ratchet_error"] = ratchet_error
            except Exception as exc:  # noqa: BLE001 - the tab still renders without it
                retention_status = retention_mod.unavailable(
                    f"{type(exc).__name__}: {str(exc)[:160]}")
        payload = status_mod.settings_overview(
            settings=settings, backend=backend, configmap=configmap,
            retention_status=retention_status,
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("settings view unavailable: %s", exc)
        return {"available": False, "groups": {},
                "reason": f"could not read the configuration: {type(exc).__name__}"}

    # US-10: the GUI-write provenance, per key. Read from the ConfigMap annotation the apply path
    # maintains; unreadable provenance is simply absent (the rows keep their values and lose the
    # "set via GUI" line).
    provenance: dict = {}
    if client is not None:
        try:
            raw = client.configmap_annotation(cc.GUI_WRITE_ANNOTATION)
            parsed = json.loads(raw) if raw else {}
            if isinstance(parsed, dict):
                provenance = {k: v for k, v in parsed.items()
                              if isinstance(v, dict) and "value" in v}
        except Exception:  # noqa: BLE001
            provenance = {}
    payload["provenance"] = provenance

    # Whether THIS caller may offer writes, and why not when they may not. Sent with every read so
    # the panel can DISABLE rather than hide: a control that vanishes teaches nothing, a disabled
    # one with a stated reason tells the operator what to do.
    from weirvern.admin import users as users_mod  # noqa: PLC0415

    if not accounts_on:
        # Pre-accounts posture: the token is the whole story, as before.
        payload["writes"] = {
            "enabled": bool(auth and auth.enabled),
            "reason": (auth.reason if auth else
                       "authentication is not available in this build"),
        }
    elif identity is not None and identity.must_change:
        payload["writes"] = {
            "enabled": False,
            "reason": "change your password before changing settings",
        }
    elif role == users_mod.ROLE_ADMIN:
        payload["writes"] = {"enabled": True, "reason": ""}
    elif role == users_mod.ROLE_VIEWER:
        payload["writes"] = {
            "enabled": False,
            "reason": "this account is a viewer: it can read every view but not change "
                      "settings. Ask an admin, or sign in as one.",
        }
    else:
        payload["writes"] = {
            "enabled": False,
            "reason": "sign in with an admin account to change settings.",
        }
    # WHO the settings write gate sees, so the panel names the caller rather than saying "an
    # operator": the audit trail starts with the page saying who you are.
    payload["caller"] = {"username": (identity.username if identity else ""),
                         "role": role, "via": via}

    # The editable keys, so the UI offers exactly what the server will accept -- derived here
    # rather than duplicated in JavaScript.
    try:
        from weirvern.admin.cluster_config import (  # noqa: PLC0415
            EDITABLE_KEYS,
            SETTING_CONTROLS,
            to_row_key,
        )

        # LOWER-CASED TO MATCH THE ROW KEYS. EDITABLE_KEYS are the ConfigMap's own key names
        # (BASE_THRESHOLD) because that is what an apply writes; the rows the GUI renders use
        # lowercase Settings attribute names. Sending the upper-case form made the intersection
        # the front end computes empty, so EVERY field rendered read-only and Apply was disabled
        # forever. Normalise here, at the boundary, so the two vocabularies meet in one place.
        payload["editable_keys"] = [to_row_key(k) for k in EDITABLE_KEYS]
        payload["controls"] = {to_row_key(k): dict(v) for k, v in SETTING_CONTROLS.items()}

        # THE DRIFT WARNING (audit F016): for every key the GUI has written whose manifest value
        # would override it, the operator gets the value they chose, when, and the fact that a
        # deploy can take it away. The computation lives in `settings_drift`, not here: an earlier
        # version computed it inline and the tests reimplemented it, so breaking the expression
        # left the suite green.
        try:
            from weirvern.admin.cluster_config import ClusterConfig  # noqa: PLC0415

            drift = [
                {**row, "key": to_row_key(row["key"])}
                for row in ClusterConfig(configmap="weirvern-env").settings_drift()
            ]
            payload["gui_written"] = drift
            if drift:
                payload["gui_written_note"] = (
                    "These keys were set through this page, not by k8s/*.yaml. "
                    "`kubectl apply -k` restores the manifest's value, so a deploy reverts "
                    "them. Re-apply the setting after a deploy, or put it in "
                    "k8s/20-configmap-env.yaml to make it permanent."
                )
        except Exception:  # noqa: BLE001
            # The warning is advisory. A cluster that cannot be read must still render the page,
            # since that is how an operator would diagnose it.
            payload["gui_written"] = []
    except Exception:  # noqa: BLE001
        payload["editable_keys"] = []
        payload["controls"] = {}
    return payload


def weirlings(with_client: Any, *, settings: Any, include_problems: bool,
              include_revoked: bool) -> dict[str, Any]:
    """The fleet: registrations compared against heartbeats, with the evidence that says whether
    each sensor is actually working.

    ONE PAYLOAD CARRIES BOTH THE ROWS AND THE AVAILABILITY, because "you have no sensors" and "the
    registry could not be read" are indistinguishable by the time a renderer sees a bare list.

    TAKES A CONNECTION FACTORY, like overview and sluice: the console opens a SEPARATE connection
    for the fleet read, the flow evidence and the revoked list, and each block has its own failure
    behaviour. One shared client would turn a connection error in the second block into a different
    answer than the first, which is the sort of drift this port exists to avoid.
    """
    import datetime  # noqa: PLC0415

    from weirvern import fleet_store  # noqa: PLC0415
    from weirvern.admin.web import (  # noqa: PLC0415
        _flow_exporters,
        _gate_sensor_name,
        _human_age,
        _interface_network_names,
    )

    try:
        with with_client() as client:
            payload = fleet_store.build_fleet(client, problems_only=include_problems)
            # ── DEMO MODE: A SEEDED HEARTBEAT IS NOT A LIVE SENSOR ────────────────────────────
            #
            # The staleness bar is 45 seconds (HEARTBEAT_S * 3), which is right for a fleet that
            # reports continuously and wrong for a demo whose heartbeat was written once. Without
            # this, every seeded sensor reads `stale` before the seed command has even finished
            # printing, and the tab says the fleet is broken. The original state is kept in
            # `state_before_demo` so the row does not hide what the classifier said.
            from weirvern import demo_state  # noqa: PLC0415

            demo = demo_state.read(client)
            if demo and demo["enabled"]:
                payload["demo"] = True
                summary = payload.get("summary") or {}
                moved = 0
                for sensor in payload.get("sensors") or []:
                    if sensor.get("is_problem"):
                        sensor["state_before_demo"] = sensor.get("state")
                        sensor["state"] = "alive"
                        sensor["is_problem"] = False
                        sensor["detail"] = ("demo mode: seeded heartbeat; liveness is not judged")
                        moved += 1
                # THE TILES ARE BUILT FROM THE SUMMARY, not from the rows, so moving a sensor
                # without moving its count leaves the tab saying "stale 2" beside two live rows.
                if moved and isinstance(summary, dict):
                    summary["stale"] = max(0, int(summary.get("stale") or 0) - moved)
                    summary["alive"] = int(summary.get("alive") or 0) + moved
                    summary["problems"] = max(0, int(summary.get("problems") or 0) - moved)
                    summary["demo"] = True
                    payload["summary"] = summary
    except Exception as exc:  # noqa: BLE001
        # A connection failure is the same fact as an unreadable registry from the operator's
        # side, so it takes the same shape rather than a 5xx that would blank the whole tab.
        logger.warning("weirlings unavailable: %s", exc)
        return {
            "available": False,
            "reason": f"the fleet could not be read: {str(exc)[:200]}",
            "sensors": [], "summary": None,
            "heartbeats_available": False, "heartbeat_reason": None,
        }

    # WHICH OF THESE SENSORS RUNS ON THIS HUB. A sensor's runtime can only be changed on the box
    # that runs it, so the row whose id is this deployment's own sensor is marked, through the same
    # helper the Sluice gate uses so the two cannot drift.
    local_name = _gate_sensor_name()
    payload["local_sensor"] = local_name
    network_names = _interface_network_names(
        str(getattr(settings, "interface_networks", "") or ""))
    for row in payload.get("sensors") or []:
        row["local"] = (row.get("sensor_id") == local_name)
        # The operator's own label for each interface (eth1=Servers), so a NIC line can read
        # "eth1 - Servers", not only a CIDR.
        row["network_names"] = network_names

    # ── DECLARED vs OBSERVED NETWORKS (operator, 2026-11-20) ──────────────────────────────────
    #
    # "weirlings tab says we only have 1 network, but we have 2." The summary counted only the
    # segments a sensor happened to report, so a declared scope with no NIC behind it vanished
    # from the tile while staying visible in Settings. Both counts now ride the payload, and
    # every declared-but-unobserved scope is named, so a bare observed count cannot contradict
    # a visible declaration.
    #
    # THE OBSERVED SET COMES FROM THE SUMMARY, never re-derived here: `summarise` counts the
    # sensor plans (including their parsed NIC plans) from the SensorHealth objects, and the
    # serialised rows do not carry `plan.nics` -- a second derivation would quietly disagree
    # with the count printed beside it.
    observed = set((payload.get("summary") or {}).get("networks_list") or [])
    coverage: dict[str, Any] = {
        "available": False, "reason": "the network scopes were not read", "declared": None,
        "declared_monitored": None, "observed": len(observed),
        "observed_segments": sorted(observed), "unobserved": [], "scopes": [],
        "unconfigured": False,
    }
    try:
        from weirvern import networks  # noqa: PLC0415

        with with_client() as net_client:
            scopes = networks.load_scopes(net_client, strict=True)
        coverage = networks.coverage(scopes, observed)
    except Exception as exc:  # noqa: BLE001 - a failed scope read is a named state
        coverage["reason"] = f"the declared networks could not be read: {str(exc)[:200]}"
    payload["network_coverage"] = coverage
    summary = payload.get("summary")
    if isinstance(summary, dict):
        # `networks` stays the OBSERVED count for older readers; the new keys are explicit.
        summary["networks_observed"] = len(observed)
        summary["networks_declared"] = coverage["declared_monitored"]
        summary["networks_declared_all"] = coverage["declared"]
        summary["networks_coverage_available"] = bool(coverage["available"])
        summary["networks_coverage_reason"] = coverage.get("reason") or ""

    # WL-1: the flow trend and the tap indicators, from the flows' own exporter address. One query
    # each for the whole fleet; a failure leaves the fields ABSENT (the list renders "not observed"
    # with its reason), never a fabricated zero. A row's exporter is its own address, but THIS
    # deployment's own sensor exports over loopback, so the local row looks up the loopback
    # samplers instead.
    exporters = _flow_exporters(payload.get("sensors") or [])
    addresses = sorted({a for group in exporters.values() for a in group})
    try:
        with with_client() as ev_client:
            evidence, ev_err = fleet_store.flow_evidence(ev_client, addresses)
            series, _series_err = fleet_store.flow_series(ev_client, addresses)
            zeek, _zeek_err = fleet_store.zeek_evidence(ev_client)
    except Exception as exc:  # noqa: BLE001
        logger.warning("fleet flow evidence unavailable: %s", exc)
        evidence, series = {}, {}
        zeek = {"observed": False, "rows": 0, "last_at": "", "why": str(exc)[:120]}
        ev_err = str(exc)[:120]
    for row in payload.get("sensors") or []:
        sid = str(row.get("sensor_id") or "")
        keys = exporters.get(sid) or []
        evs = [evidence.get(k) or {} for k in keys]
        flows = sum(int(e.get("flows") or 0) for e in evs)
        last = max((str(e.get("last_at") or "") for e in evs if e.get("last_at")), default="")
        # THE NEWEST EVIDENCE WINS: one exporter still sending means the feed is up.
        ages: list[int] = [int(e["age_s"]) for e in evs if e.get("age_s") is not None]
        age_s: int | None = min(ages) if ages else None
        stale = bool(keys) and (age_s is None or age_s > fleet_store.NETFLOW_STALE_S)
        merged_series = [0] * 12
        has_series = False
        for k in keys:
            vals = series.get(k) or []
            if vals:
                has_series = True
            for i, v in enumerate(vals[:12]):
                merged_series[i] += int(v or 0)
        row["flow_series"] = merged_series if has_series else []
        row["netflow"] = {
            "known": bool(keys),
            "observed": flows > 0,
            # OBSERVED IS NOT FRESH. A 24-hour count keeps a dead exporter looking healthy for a
            # day; `fresh` and `age_s` say whether it is sending NOW.
            "fresh": bool(keys) and not stale and flows > 0,
            "stale": stale,
            "age_s": age_s,
            "flows": flows,
            "last_at": last,
            # NETFLOW IS SENSOR-SCOPED, NOT PER-NIC: NETFLOW_IFACE is one sensor-level setting and
            # the exporter address belongs to the box, so a NIC line must not imply it owns a local
            # probe.
            "scope": "sensor",
            "scope_label": "netflow",
            "scope_note": ("the hub sees one sensor-wide NetFlow feed; it cannot "
                           "attribute it to this NIC"),
            "why": ("" if (flows and not stale) else
                    (f"exporter silent for {_human_age(age_s)}" if keys and stale
                     else "no flows from this sensor's exporter in 24h" if keys
                     else ("the sensor has not reported an address yet"
                           if ev_err else "no address reported yet"))),
        }
        row["zeek"] = (
            {"known": True, "observed": bool(zeek.get("observed")),
             "last_at": zeek.get("last_at") or "",
             "why": zeek.get("why") or ""}
            if row.get("local") else
            {"known": False, "observed": False, "last_at": "",
             "why": "only the hub runs Zeek; a remote weirling does not report one"}
        )
        # THE CHANNEL IS NOT THE MODE (measured live 2026-10-19: mode siphon, mappings 0, no flows
        # for 24h). The row states the evidence, and the reason when it is not there, so a
        # configured path cannot read as a working one.
        row["channel"] = fleet_store.channel_state(
            str(row.get("reported_mode") or row.get("expected_mode") or ""),
            int(row.get("mappings") or 0),
            bool(row.get("running")),
            row.get("state") == "alive",
        )

    if include_revoked:
        # Revoked rows are shown on request, for the audit question ("was this ever covered?").
        # Fetched separately and appended, so the normal view cannot accidentally include them.
        try:
            with with_client() as client:
                revoked = [r for r in fleet_store.read_registrations(
                    client, include_revoked=True) if not r.live]
            payload["revoked"] = [
                {"sensor_id": r.sensor_id, "segment": r.segment,
                 "address": r.address, "expected_mode": r.expected_mode,
                 "note": r.note,
                 "revoked_at": (r.revoked_at.isoformat()
                                if isinstance(r.revoked_at, datetime.datetime) else None)}
                for r in revoked
            ]
        except fleet_store.FleetStoreError as exc:
            payload["revoked"] = []
            payload["revoked_reason"] = str(exc)
    return payload


def watch(client: Client, *, src_addr: str, on: bool) -> tuple[int, dict[str, Any]]:
    """Toggle one host's place on the watch list, and read the state BACK from the store.

    RETURNS (STATUS, PAYLOAD). The write either lands or it does not, and the answer is what the
    store says afterwards -- the same read-back rule the review write follows. A 400 from the store
    is a rejected value; anything else is a failed write.
    """
    try:
        status_mod.write_watch(client, src_addr=src_addr, watching=on)
        watched, err = status_mod.watch_index(client)
    except ValueError as exc:
        return 400, {"error": str(exc), "code": 400}
    except Exception as exc:  # noqa: BLE001
        return watch_failure(exc)
    if err is not None:
        return 503, {"error": f"the watch was written but could not be read back: {err}",
                     "code": 503}
    return 200, {"ok": True, "watching": src_addr in watched, "src_addr": src_addr}


def watch_failure(exc: BaseException) -> tuple[int, dict[str, Any]]:
    """The console's own failure shape for a watch write that did not land."""
    logger.warning("watch write failed: %s", exc)
    return 503, {"error": f"could not record the watch: {exc}", "code": 503}


def review(client: Client, *, window_start: Any, src_addr: str, state: str, note: str,
           adjustment: Any) -> tuple[int, dict[str, Any]]:
    """Record an analyst's disposition of one anomaly, and optionally an active-learning adjustment.

    RETURNS (STATUS, PAYLOAD). A disposition is a write whose answer is what LANDED, and an
    adjustment carries its own validation: a non-object, a missing value or a non-numeric one is a
    400 with the sentence that says which, not a silent no-op beside a stored review.
    """
    try:
        status_mod.write_review(
            client, window_start=window_start, src_addr=src_addr, state=state, note=note)
        response: dict[str, Any] = {"ok": True, "state": state, "note": note}
        if adjustment is not None:
            if not isinstance(adjustment, dict):
                raise ValueError("'adjustment' must be an object")
            from weirvern.models.active_learning import (  # noqa: PLC0415
                build_adjustment,
                write_adjustment,
            )

            raw_before = adjustment.get("before_value")
            raw_after = adjustment.get("after_value")
            if raw_before is None or raw_after is None:
                raise ValueError("adjustment before_value and after_value are required")
            try:
                before_value = float(str(raw_before))
                after_value = float(str(raw_after))
            except ValueError as exc:
                raise ValueError(
                    "adjustment before_value and after_value must be numbers") from exc
            built = build_adjustment(
                scope=str(adjustment.get("scope") or "host"),
                subject=str(adjustment.get("subject") or src_addr),
                metric=str(adjustment.get("metric") or "page_budget"),
                before_value=before_value,
                after_value=after_value,
                reason=str(adjustment.get("reason") or note),
                review_window_start=status_mod._parse_stamp(window_start),
                review_src_addr=src_addr,
                expiry_days=int(adjustment.get("expiry_days") or 14),
            )
            write_adjustment(client, built)
            response["adjustment"] = built
    except ValueError as exc:
        return 400, {"error": str(exc), "code": 400}
    except Exception as exc:  # noqa: BLE001
        return review_failure(exc)
    return 200, response


def review_failure(exc: BaseException) -> tuple[int, dict[str, Any]]:
    """The console's own failure shape for a review that did not land."""
    logger.warning("review write failed: %s", exc)
    return 503, {"error": f"could not record the review: {exc}", "code": 503}


def review_state_refusal(state: str) -> dict[str, Any] | None:
    """The 400 body for an unknown review state, or None when the state is valid.

    A SHAPE OF ITS OWN, not the house error: the console sends `valid_states` so the caller can
    offer the right choices rather than guess.
    """
    if state in status_mod.VALID_REVIEW_STATES:
        return None
    return {"ok": False, "error": f"unknown review state {state!r}",
            "valid_states": [s for s in status_mod.VALID_REVIEW_STATES if s]}


def discover_trends(client: Client, hours: int) -> dict[str, Any]:
    """The Flows header's three feed trends: NetFlow, Zeek and DNS."""
    import logging  # noqa: PLC0415

    from weirvern.admin import soc as soc_mod  # noqa: PLC0415
    from weirvern.admin.web import read_failure  # noqa: PLC0415

    logger = logging.getLogger(__name__)
    try:
        return soc_mod.discover_trends(client, hours=hours)
    except Exception as exc:  # noqa: BLE001
        logger.warning("feed trends unavailable: %s", exc)
        return {"available": False, "feeds": {}, "reason": read_failure(exc),
                "data_error": str(exc)}


def dns_reverse(client: Client, ip: str, hours: int) -> dict[str, Any]:
    """Which names pointed at this address, inside the window."""
    import logging  # noqa: PLC0415

    from weirvern.admin import soc as soc_mod  # noqa: PLC0415
    from weirvern.admin.web import read_failure  # noqa: PLC0415

    logger = logging.getLogger(__name__)
    try:
        return soc_mod.dns_reverse_for(client, ip, hours=hours)
    except Exception as exc:  # noqa: BLE001
        logger.warning("reverse lookup unavailable: %s", exc)
        return {"available": False, "domains": [], "reason": read_failure(exc)}


def demo(client: Client) -> dict[str, Any]:
    """Is this deployment showing seeded data? The banner and the health checks read one row.

    A false answer is not a failure: a live deployment simply has no demo marker.
    """
    from weirvern import demo_state  # noqa: PLC0415

    state = demo_state.read(client)
    return {"available": True, "demo": state or {"enabled": False}}

