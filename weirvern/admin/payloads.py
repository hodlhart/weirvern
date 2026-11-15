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

from typing import Any

from clickhouse_connect.driver.client import Client

from weirvern.admin import status as status_mod
from weirvern.admin import web_api


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
    """
    return web_api.baselines_payload(status_mod.baselines_overview(client))


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


def ml_data_contract(client: Client) -> dict[str, Any]:
    """What 'covered' means, measured against the live tables."""
    try:
        from weirvern.models import data_contract  # noqa: PLC0415

        return data_contract.inventory(client)
    except Exception as exc:  # noqa: BLE001
        return {"available": False, "reason": f"cannot read the data contract: {exc}",
                "sources": [], "families": [], "gaps": [], "hosts": [],
                "population": {}, "promotion_ok": False}


# ── windowed reads: the arguments are part of the contract ──────────────────────────────────

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

