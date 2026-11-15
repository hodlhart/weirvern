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

