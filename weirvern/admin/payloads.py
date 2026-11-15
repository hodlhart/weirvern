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

import json
import logging
from typing import Any

from clickhouse_connect.driver.client import Client

from weirvern.admin import status as status_mod
from weirvern.admin import web_api

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

def assets(client: Client, *, hours: int) -> dict[str, Any]:
    """The asset inventory: every host seen, with a per-host summary.

    `hours` bounds the TRAFFIC columns only. A host whose last packet was days ago is still an asset,
    so it appears with zeroed counters rather than being dropped.
    """
    from weirvern.admin import assets as assets_mod  # noqa: PLC0415

    return assets_mod.asset_inventory(client, hours=hours)


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


def scan_jobs(client: Client, *, ip: str) -> dict[str, Any]:
    """The manual-scan queue: recent requests, optionally for one address.

    The row timestamps are serialised here, through the console's own `_iso`, so a job's
    `requested_at` is the same string on both surfaces.
    """
    from weirvern import scan_jobs as scan_jobs_mod  # noqa: PLC0415
    from weirvern.admin.web import _iso  # noqa: PLC0415

    rows = scan_jobs_mod.list_jobs(client, ip=ip, limit=20)
    out = []
    for job in rows:
        item = dict(job)
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
    """
    data = status_mod.model_overview(client, hours=hours, settings=settings)
    try:
        from weirvern.models import cards as cards_mod  # noqa: PLC0415

        data["model_cards"] = cards_mod.current_cards(client)
        data["model_cards_available"] = True
    except Exception as card_exc:  # noqa: BLE001
        data["model_cards"] = []
        data["model_cards_available"] = False
        data["model_cards_reason"] = f"cannot read the model registry: {card_exc}"
    return web_api.models_payload(data)


def models_failure(exc: BaseException) -> dict[str, Any]:
    """The console's own failure shape for /api/models: 200 with the reason, never a 503."""
    from weirvern.admin.web import read_failure  # noqa: PLC0415

    logger.warning("model overview unavailable: %s", exc)
    return {"available": False, "reason": read_failure(exc)}


def scanner(client: Client) -> dict[str, Any]:
    """Scanner readiness for the hub and every registered sensor.

    A SENSOR WITH NO ROW IS NOT "basic". It is "not_reported", which is a different fact and needs
    the setup sheet rather than a clean-looking profile, so the missing rows are filled with that
    state and the install command for the OS the sensor reported.
    """
    from weirvern.admin.web import _gate_sensor_name  # noqa: PLC0415

    status_rows = client.query(
        "SELECT sensor_id, profile, nmap_available, nmap_version, nmap_path, "
        "nse_available, os_id, os_version, detail, last_check "
        "FROM weirvern.scanner_status FINAL ORDER BY sensor_id"
    ).result_rows
    registered = client.query(
        "SELECT sensor_id FROM weirvern.weirlings FINAL "
        "WHERE revoked_at IS NULL AND enabled = 1 ORDER BY sensor_id"
    ).result_rows

    status: dict[str, dict[str, Any]] = {}
    for row in status_rows:
        sid = str(row[0] or "")
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
            "last_check": (row[9].isoformat() if hasattr(row[9], "isoformat")
                           else str(row[9] or "")),
            "state": "reported",
        }
    for row in registered:
        sid = str(row[0] or "")
        status.setdefault(sid, {
            "sensor_id": sid, "profile": "unknown", "nmap_available": False,
            "nmap_version": "", "nmap_path": "", "nse_available": False,
            "os_id": "", "os_version": "", "detail": "no scanner status reported yet",
            "last_check": "", "state": "not_reported",
        })

    commands = {
        "debian": "sudo apt-get update && sudo apt-get install -y nmap",
        "ubuntu": "sudo apt-get update && sudo apt-get install -y nmap",
        "linuxmint": "sudo apt-get update && sudo apt-get install -y nmap",
        "fedora": "sudo dnf install -y nmap",
        "rhel": "sudo dnf install -y nmap",
        "centos": "sudo dnf install -y nmap",
        "rocky": "sudo dnf install -y nmap",
        "almalinux": "sudo dnf install -y nmap",
        "alpine": "sudo apk add nmap",
        "arch": "sudo pacman -S --noconfirm nmap",
        "darwin": "brew install nmap",
    }
    for item in status.values():
        item["install_command"] = commands.get(str(item.get("os_id") or "").lower(), "")
        item["install_url"] = "https://nmap.org/download.html"
    sensors = sorted(status.values(),
                     key=lambda item: (item["state"] != "reported", item["sensor_id"]))
    return {"available": True, "reason": "", "sensors": sensors, "count": len(sensors),
            "local_sensor": _gate_sensor_name()}


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
        talkers = status_mod.top_talkers(client, hours=hours, limit=12, filters=filters)
        # The host lists are filtered; this says by how much, so a reader can tell "a quiet segment"
        # from "a noisy one with the noise hidden".
        noise = status_mod.noise_flows(client, hours=hours)
    except Exception as exc:  # noqa: BLE001
        return netflow_failure(exc)
    return web_api.netflow_payload(volume, proto, ports, spread, talkers, noise=noise)


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


def findings(client: Client, *, ip: str, severity: str, limit: int) -> dict[str, Any]:
    """Recorded scanner findings for the Findings drill.

    Findings are historical evidence, so the global time window does not hide them: a finding
    observed last week is still a fact about the host today. `limit` is NOT clamped here, which is
    the console's contract; the value is bounded by the caller, not by this layer.
    """
    from weirvern.admin import assets as assets_mod  # noqa: PLC0415

    try:
        payload = assets_mod.asset_findings_list(
            client, ip=ip, severity=severity, limit=limit)
    except Exception as exc:  # noqa: BLE001
        return findings_failure(exc)
    payload["filter"] = {"ip": ip, "severity": severity}
    return payload


def findings_failure(exc: BaseException) -> dict[str, Any]:
    """The console's own failure shape for /api/findings: a FIXED sentence, not `read_failure`."""
    logger.warning("findings unavailable: %s", exc)
    return {"available": False, "findings": [], "count": 0, "counts": {},
            "reason": "the data could not be read"}


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
    return web_api.retrain_payload(row, decision)


def model_retrain_failure(exc: BaseException) -> dict[str, Any]:
    """The console's own failure shape for /api/models/retrain."""
    from weirvern.admin.web import read_failure  # noqa: PLC0415

    logger.warning("model retrain state unavailable: %s", exc)
    return web_api.retrain_payload(None, None, available=False, reason=read_failure(exc))


def graph(client: Client, *, hours: int, tracked: list[str]) -> dict[str, Any]:
    """The connection graph, optionally restricted to the tracked hosts.

    AN EMPTY SELECTION MEANS NO RESTRICTION and returns the whole graph, which is what an operator
    expects from a cleared multi-select. The selection is echoed back when it is non-empty, so the UI
    can draw it as selected even when an edge is missing.
    """
    from weirvern.admin import assets as assets_mod  # noqa: PLC0415

    try:
        if tracked:
            payload = assets_mod.top_edges_for(client, tracked, hours=hours)
            payload.setdefault("tracked", tracked)
            return payload
        return assets_mod.connection_graph(client, hours=hours)
    except Exception as exc:  # noqa: BLE001
        return graph_failure(exc)


def graph_failure(exc: BaseException) -> dict[str, Any]:
    """The console's own failure shape for /api/graph."""
    from weirvern.admin.web import read_failure  # noqa: PLC0415

    logger.warning("graph unavailable: %s", exc)
    return {"available": False, "nodes": [], "edges": [],
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


def scan_job_create(client: Client, *, ip: str) -> tuple[int, dict[str, Any]]:
    """Queue one host scan for the scanner to claim under a lease.

    THE TABLE MAY NOT EXIST YET, and that is a named condition rather than a fault: a deployment on
    an older scanner answers 503 with the version that introduced the table. An ACTIVE job is not an
    error either -- it answers `already: true` with the job that is running, so a double click does
    not queue a second scan.
    """
    from weirvern import scan_jobs  # noqa: PLC0415

    try:
        asset = scan_jobs.find_asset(client, ip)
        if asset is None:
            return 404, {"error": f"{ip} is not in the asset registry", "code": 404}
        active = scan_jobs.active_for_asset(client, str(asset["asset_key"]))
        if active is not None:
            return 200, {"ok": True, "job_id": str(active["job_id"]), "ip": ip,
                         "state": str(active["state"]), "already": True}
        job = scan_jobs.create_job(client, asset, requested_by="operator")
    except Exception as exc:  # noqa: BLE001
        return scan_job_failure(exc)
    logger.info("manual scan queued for %s (%s)", ip, job["job_id"])
    return 200, {"ok": True, "job_id": str(job["job_id"]), "ip": ip,
                 "state": "queued", "already": False}


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
    """The console's own failure shape: a table that is not there yet is a NAMED condition.

    Used both inside the fetcher and by a surface whose CONNECTION failed -- the console wraps the
    connection in the same try, so an unreachable cluster has always answered this sentence.
    """
    logger.warning("scan job request failed: %s", exc)
    return 503, {"error": "the scan-job table is not ready; deploy scanner 0.14.13", "code": 503}


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

    rows = status_mod.anomalies_grouped(
        client, limit=limit, min_score=min_score, host=host, severity=severity,
        model=model, feature=feature, hours=hours)
    # The header tiles: counts per severity under min-score + host, NOT under the severity filter
    # itself (see status.anomaly_severity_counts for why).
    severity_counts = status_mod.anomaly_severity_counts(
        client, min_score=min_score, host=host, feature=feature, hours=hours)
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
    return web_api.anomalies_payload(
        rows, severity_counts=severity_counts, discipline=discipline,
        watch_error=watch_err, total_unfiltered=total_unfiltered)


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

    payload: dict = {
        "available": False, "reason": "", "rules": [], "live": 0, "gate": {},
        "policies": {}, "criticality": "", "enabled": False, "iface": "",
        "hits_hours": hours,
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
            except Exception as exc:  # noqa: BLE001
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
            # ONE RULE STORE, MANY GATES: every box that can enforce reports its own row, so the
            # operator sees who is actually filtering (and who has stopped).
            fleet_gates = sluice_store.load_gate_states(client)
    except Exception as exc:  # noqa: BLE001
        logger.warning("sluice view unavailable: %s", exc)
        return {**payload, "available": False,
                "reason": f"cannot read the gate: {type(exc).__name__}"}

    now = _dt.datetime.now(_dt.UTC)
    rows = []
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
        })
    # A GATE THAT STOPPED IS ITS OWN STATE, not an absent one. Four missed intervals is the
    # threshold: the cadence is minutes, and one slow cycle is not news.
    try:
        stale_after = max(180, 4 * int(settings.sluice_interval_s))
    except Exception:  # noqa: BLE001
        stale_after = 180
    payload.update({
        "available": True, "rules": rows,
        "live": sum(1 for r in rows if r["live"]), "gate": gate,
        **web_api.gates_payload(fleet_gates, _gate_sensor_name(), stale_after, now),
    })
    return payload


def settings_payload(*, settings: Any, backend: Any, config_client: Any = None,
                     auth: Any = None, role: str = "", via: str = "", identity: Any = None,
                     accounts_on: bool = False) -> dict[str, Any]:
    """The effective configuration, plus whether THIS caller may change it.

    THE LIVE CLUSTER CONFIG IS THE SOURCE, not this pod's startup environment: a settings change
    restarts the WORKER, not the GUI, so the pod env freezes at its start and the tab would report
    stale values through a demonstrably live intercept. When the cluster is unreachable the pod env
    remains the honest fallback, and rows keep their provenance labels.

    THE REQUEST-SCOPED FACTS ARRIVE AS ARGUMENTS (role, identity, accounts_on, auth) rather than
    being re-derived here: they belong to the request, and the two surfaces compute them from the
    same shared helpers.
    """
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
        payload = status_mod.settings_overview(
            settings=settings, backend=backend, configmap=configmap
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

