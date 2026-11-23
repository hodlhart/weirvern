"""Seed the surfaces the traffic generator cannot reach: the fleet and the asset inventory.

WHY A SECOND MODULE. `demo_seed` generates packets and flows, which populate every traffic view.
The Weirlings tab and the Assets tab read tables that only exist when a sensor or a scan has
reported, and a demo with those two tabs empty teaches a reader that the product has no fleet and
no inventory. This module writes the SMALLEST set of rows that makes each view real: one hub
sensor, one edge sensor, a lease history, a completed probe, and for every seeded host an asset
record with services, a scan, an observation and (for a few) a change with a posture score.

WHAT IT DOES NOT DO. It does not pretend a scan ran against a real network: `scan_mode` says
`demo`, `source` says `demo-seed`, and every address is in 192.0.2.0/24. A reader can tell the
inventory is seeded, which is the point of demo mode rather than a substitute for it.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

DEMO = "demo-seed"


def _identities(client, hosts: int) -> list[tuple[str, str, str, str]]:
    """(host, mac, os, hostname) from the inventory the seeder already wrote.

    Reading host_identity rather than inventing names keeps the Assets view consistent with the
    Network view: the same machine has one hostname and one MAC whichever panel a reader opens.
    """
    try:
        rows = client.query(
            "SELECT host, any(mac) AS mac, any(os) AS os, any(hostnames_seen) AS seen "
            "FROM weirvern.host_identity GROUP BY host ORDER BY host LIMIT %(n)s",
            parameters={"n": hosts},
        ).result_rows
    except Exception:  # noqa: BLE001 - a demo can still seed without the identity pass
        rows = []
    out = []
    for i, (host, mac, os_name, seen) in enumerate(rows):
        try:
            names = json.loads(seen) if seen else []
        except ValueError:
            names = []
        hostname = names[0] if names else f"demo-host-{i:02d}"
        out.append((str(host), str(mac), str(os_name), str(hostname)))
    return out


def seed_fleet(client, *, hosts: int, now: datetime | None = None) -> dict[str, Any]:
    """Two planned units, one reporting: a loch with a heartbeat and a siphon shown without ARP."""
    now = now or datetime.now(UTC)
    sensors = [
        # ONE LOCH AND ONE SIPHON, WITH NO ARP. The demo does not redirect traffic (Samuel,
        # 2026-11-23), so the siphon unit is in the fleet as a planned unit and gets no heartbeat:
        # a heartbeat would claim it is intercepting when nothing is. The channel is demonstrated
        # by the gate itself, because channel is a bridge, not a sensor mode.
        ("weir-site-a", "10.10.0.253", "10.10.0.0/24", "loch",
         "edge sensor, HQ clients (10.10.0.0/24)", True),
        ("weir-site-b", "192.168.20.253", "192.168.20.0/24", "loch",
         "edge sensor, branch clients (192.168.20.0/24)", True),
        ("weir-site-c", "172.16.30.253", "172.16.30.0/24", "siphon",
         "edge sensor, warehouse; siphon mode shown without ARP, so no heartbeat", False),
    ]
    written: dict[str, Any] = {}
    wl_rows = []
    ss_rows = []
    audit_rows = []
    enroll_rows = []
    probe_rows = []
    for i, (sensor_id, addr, segment, mode, note, live) in enumerate(sensors):
        wl_rows.append([
            sensor_id, addr, segment, mode, 1, note, now - timedelta(days=7),
            now, None, mode, "eth1", segment, addr, "192.0.2.1", "",
            [segment], "", "demo",
        ])
        if live:
            ss_rows.append([
                sensor_id, mode, "eth1", segment, hosts, 0, 1, 86_400.0 + i * 3_600, 0, 0,
                0.0, 1_000_000 + i * 100_000, 0, ["eth0", "eth1"], "{}", [],
                now - timedelta(minutes=1),
            ])
        audit_rows.append([
            now - timedelta(days=7), "fleet", "register", sensor_id, note, "demo-seed",
        ])
        enroll_rows.append([
            f"{sensor_id}-demo-token-hash", sensor_id, addr, segment, mode,
            now - timedelta(days=6), now - timedelta(days=7), now - timedelta(days=6),
        ])
        probe_rows.append([
            f"probe-{uuid.uuid4().hex[:12]}", sensor_id, "eth1", 30, "complete",
            json.dumps({"packets": 1200, "bytes": 480_000, "verdict": "traffic present"}),
            "", now - timedelta(hours=2), now - timedelta(hours=2),
        ])
    try:
        client.insert("weirvern.weirlings", wl_rows, column_names=[
            "sensor_id", "address", "segment", "expected_mode", "enabled", "note", "added_at",
            "updated_at", "revoked_at", "plan_mode", "plan_iface", "plan_segment", "plan_addr",
            "plan_gateway", "plan_targets", "networks", "plan_nics", "topology"])
        written["weirlings"] = len(wl_rows)
    except Exception as exc:  # noqa: BLE001
        written["weirlings"] = f"failed: {exc}"[:100]  # type: ignore[assignment]
    try:
        client.insert("weirvern.sensor_status", ss_rows, column_names=[
            "sensor_id", "mode", "iface", "segment", "hosts", "mappings", "running", "uptime_s",
            "restores", "refreshes", "capture_loss_pct", "packets_recv", "packets_dropped",
            "interfaces", "host_stats", "failures", "ts"])
        written["sensor_status"] = len(ss_rows)
    except Exception as exc:  # noqa: BLE001
        written["sensor_status"] = f"failed: {exc}"[:100]  # type: ignore[assignment]
    try:
        client.insert("weirvern.fleet_audit", audit_rows, column_names=[
            "at", "scope", "action", "target", "reason", "actor"])
        written["fleet_audit"] = len(audit_rows)
    except Exception as exc:  # noqa: BLE001
        written["fleet_audit"] = f"failed: {exc}"[:100]  # type: ignore[assignment]
    try:
        client.insert("weirvern.weirling_enrollments", enroll_rows, column_names=[
            "token_hash", "sensor_id", "address", "segment", "expected_mode", "expires_at",
            "used_at", "updated_at"])
        written["weirling_enrollments"] = len(enroll_rows)
    except Exception as exc:  # noqa: BLE001
        written["weirling_enrollments"] = f"failed: {exc}"[:100]  # type: ignore[assignment]
    try:
        client.insert("weirvern.weirling_probe_requests", probe_rows, column_names=[
            "request_id", "sensor_id", "iface", "seconds", "status", "result", "error",
            "requested_at", "updated_at"])
        written["weirling_probe_requests"] = len(probe_rows)
    except Exception as exc:  # noqa: BLE001
        written["weirling_probe_requests"] = f"failed: {exc}"[:100]  # type: ignore[assignment]
    return written


def seed_assets(client, *, hosts: int, now: datetime | None = None) -> dict[str, Any]:
    """An inventory, its services, a completed scan per host, and a few posture-scored changes."""
    now = now or datetime.now(UTC)
    identities = _identities(client, hosts)
    written: dict[str, Any] = {}
    if not identities:
        return {"assets": 0}

    registry, services, observations, scans, jobs, changes, scores = [], [], [], [], [], [], []
    service_map = {"windows": [445, 3389, 22], "macos": [22, 443], "ios": [443],
                   "android": [443], "linux": [22, 80, 443]}.get
    for i, (ip, mac, os_name, hostname) in enumerate(identities):
        asset_key = ip
        registry.append([asset_key, ip, mac, hostname, now - timedelta(days=30),
                         now - timedelta(minutes=5), "scanned", now - timedelta(hours=3),
                         "", DEMO])
        ports = service_map(os_name, [22, 443])
        for port in ports:
            proto = "tcp"
            service = {22: "ssh", 80: "http", 443: "https", 445: "microsoft-ds",
                       3389: "ms-wbt-server"}.get(port, "unknown")
            product = {"ssh": "OpenSSH", "http": "nginx", "https": "nginx",
                       "microsoft-ds": "Samba", "ms-wbt-server": "Microsoft RDP"}.get(service, "")
            services.append([asset_key, ip, port, proto, service, product, "demo",
                             "", now - timedelta(hours=3), f"scan-{i:02d}"])
        observations.append([asset_key, ip, 0, "os", "family", os_name,
                             now - timedelta(hours=3)])
        observations.append([asset_key, ip, ports[0], "service", "name",
                             str(ports[0]), now - timedelta(hours=3)])
        scans.append([f"scan-{i:02d}", asset_key, ip, "nmap", now - timedelta(hours=3),
                      now - timedelta(hours=3) + timedelta(minutes=4), "complete", "",
                      f"nmap -sV -oX - {ip}", 1])
        jobs.append([uuid.uuid4(), asset_key, ip, "demo-seed", now - timedelta(hours=3),
                     "complete", "", None, now - timedelta(hours=3),
                     now - timedelta(hours=3) + timedelta(minutes=4),
                     json.dumps({"open_ports": ports}), ""])
        if i % 4 == 0:
            change_key = f"port:{ports[0]}"
            changes.append([asset_key, ip, change_key, "opened", ports[0], "tcp", "",
                            str(ports[0]), "high",
                            f"port {ports[0]} appeared in the latest scan", f"scan-{i:02d}",
                            now - timedelta(hours=3), now - timedelta(hours=3), "unreviewed"])
            scores.append([asset_key, change_key, 0.72, "high",
                           ["new service exposed", "no matching baseline"],
                           json.dumps({"port": ports[0]}), "posture-demo",
                           now - timedelta(hours=3), "unreviewed"])

    def put(table: str, rows: list, columns: list[str]) -> None:
        try:
            client.insert(f"weirvern.{table}", rows, column_names=columns)
            written[table] = len(rows)
        except Exception as exc:  # noqa: BLE001
            written[table] = f"failed: {exc}"[:100]  # type: ignore[assignment]

    put("asset_registry", registry, [
        "asset_key", "ip", "mac", "hostname", "first_seen", "last_seen", "scan_state",
        "last_scan_at", "scan_error", "source"])
    put("asset_services", services, [
        "asset_key", "ip", "port", "protocol", "service", "product", "version", "cpe",
        "observed_at", "last_seen_scan_id"])
    put("asset_observations", observations, [
        "asset_key", "ip", "port", "script", "key", "value", "observed_at"])
    put("asset_scans", scans, [
        "scan_id", "asset_key", "ip", "kind", "started_at", "finished_at", "status", "error",
        "command", "scan_complete"])
    put("scan_jobs", jobs, [
        "job_id", "asset_key", "ip", "requested_by", "requested_at", "state", "lease_owner",
        "lease_until", "started_at", "finished_at", "result", "error"])
    put("asset_changes", changes, [
        "asset_key", "ip", "change_key", "kind", "port", "protocol", "old_value", "new_value",
        "confidence", "evidence", "scan_id", "first_seen", "last_seen", "review_state"])
    put("asset_posture_scores", scores, [
        "asset_key", "change_key", "score", "band", "reasons", "features", "model_version",
        "scored_at", "review_state"])
    # Scanner capability and one watch, so the Assets panel has a scanner row and a watch to show.
    put("scanner_status", [[
        "weir-hub-01", "demo", 1, "7.94", "/usr/bin/nmap", 1, "linux", "6.12",
        "demo scanner profile", now - timedelta(minutes=10), 0, "demo", 0, "not-installed",
        "Linux 6.12", "linux"]], [
        "sensor_id", "profile", "nmap_available", "nmap_version", "nmap_path", "nse_available",
        "os_id", "os_version", "detail", "last_check", "privileged", "scan_mode", "can_install",
        "sudo_state", "os_label", "os_family"])
    if identities:
        ip = identities[min(2, len(identities) - 1)][0]
        put("host_watches", [[ip, 1, now - timedelta(hours=1), "demo-seed"]], [
            "src_addr", "watching", "watched_at", "watched_by"])
    return written
