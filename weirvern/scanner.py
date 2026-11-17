"""Active asset inventory with Nmap and Nuclei.

WHY THIS IS A SEPARATE PROCESS
------------------------------
The worker's job is to watch traffic and train models; it must not block on a network scan or
hold a scanner's child process. This module is the scanner side of the same package and runs as
its own Deployment in the existing cluster (no new LXC, no new host):

    discovery -> registry (pending) -> Nmap services -> Nuclei templates -> findings

THE NEW-HOST PROMISE
--------------------
Every discovery pass unions two views of the LAN:

  * Nmap's active sweep, for hosts that answer; and
  * the last few minutes of Weirvern's own `flows`, for hosts that were seen passively.

A host that is not in `asset_registry` is inserted with `scan_state='pending'` and is scanned in
the same pass, not on the next scheduled sweep. A first run is treated as a BASELINE, not as a
wave of new devices: existing hosts are recorded as `known` unless SCAN_BOOTSTRAP=1. After that,
a genuinely new address or MAC is pending immediately.

DESIGN RULES
------------
* The scanner never invents a vulnerability finding. Nmap contributes services; Nuclei
  contributes template matches. The two are stored separately and with their evidence.
* Registry keys prefer `mac:` when a MAC is available and fall back to `ip:`. Addresses move
  under DHCP, so the MAC is the better long-lived key when one exists.
* Every invocation is recorded in `asset_scans`, including failures. "No findings" and "the
  scanner did not run" must not look the same in the UI.
* Scanning is opt-in (`SCAN_ENABLED`), scoped by the weirling registry, and never scans the whole
  internet.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import os
import shlex
import shutil
import socket
import subprocess
import time
import uuid
import xml.etree.ElementTree as ET
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from weirvern import db, scan_jobs
from weirvern.asset_changes import detect_service_changes
from weirvern.asset_posture import AssetPostureModel
from weirvern.config import Settings

logger = logging.getLogger(__name__)

REGISTRY_COLUMNS = [
    "asset_key", "ip", "mac", "hostname", "first_seen", "last_seen",
    "scan_state", "last_scan_at", "scan_error", "source",
]
SERVICE_COLUMNS = [
    "asset_key", "ip", "port", "protocol", "service", "product", "version", "cpe", "observed_at",
]
FINDING_COLUMNS = [
    "asset_key", "ip", "scanner", "finding_key", "template_id", "name", "severity", "cve",
    "matched_at", "description", "remediation", "first_seen", "last_seen",
]
OBSERVATION_COLUMNS = [
    "asset_key", "ip", "port", "script", "key", "value", "observed_at",
]
SCAN_COLUMNS = [
    "scan_id", "asset_key", "ip", "kind", "started_at", "finished_at", "status", "error", "command",
]
SCANNER_STATUS_COLUMNS = [
    "sensor_id", "profile", "nmap_available", "nmap_version", "nmap_path",
    "nse_available", "os_id", "os_version", "detail", "last_check",
]
HISTORY_COLUMNS = [
    "asset_key", "ip", "scan_id", "port", "protocol", "service", "product", "version",
    "cpe", "observed_at",
]
CHANGE_COLUMNS = [
    "asset_key", "ip", "change_key", "kind", "port", "protocol", "old_value", "new_value",
    "confidence", "evidence", "scan_id", "first_seen", "last_seen", "review_state",
]
POSTURE_COLUMNS = [
    "asset_key", "change_key", "score", "band", "reasons", "features", "model_version",
    "scored_at", "review_state",
]
HTTP_SERVICES = {"http", "http-proxy", "http-alt", "https", "https-alt", "ssl/http"}
HTTP_PORTS = {80, 443, 8000, 8080, 8443, 8888, 9000}
Network = ipaddress.IPv4Network | ipaddress.IPv6Network


@dataclass(frozen=True)
class Host:
    ip: str
    mac: str = ""
    hostname: str = ""
    source: str = "nmap"


@dataclass(frozen=True)
class Service:
    port: int
    protocol: str = "tcp"
    service: str = ""
    product: str = ""
    version: str = ""
    cpe: str = ""


@dataclass(frozen=True)
class Finding:
    finding_key: str
    template_id: str
    name: str
    severity: str
    cve: str
    matched_at: str
    description: str
    remediation: str


@dataclass(frozen=True)
class Observation:
    """One Nmap NSE fact, kept as a key/value observation rather than a vulnerability."""
    port: int
    script: str
    key: str
    value: str


# SAFE, PORTABLE IDENTITY SCRIPTS. These are bundled with the Nmap package, need no account or
# vendor controller, and are safe/default-category checks. `vuln`, `intrusive`, `brute`, `dos`
# and `external` scripts are deliberately NOT in this list: NSE vulnerability scripts are not a
# substitute for a reviewed scanner, and several are slow or disruptive.
NSE_IDENTITY_SCRIPTS = ",".join((
    "http-title", "http-headers", "http-methods", "ssl-cert",
    "smb-os-discovery", "smb2-security-mode", "smb2-time",
    "snmp-sysdescr", "snmp-info", "ssh2-enum-algos", "ssh-hostkey",
    "rdp-enum-encryption", "rdp-ntlm-info", "upnp-info", "ntp-info", "dns-nsid",
))


class ScanError(RuntimeError):
    """A scanner invocation failed in a way the operator needs to see."""


def _now() -> datetime:
    return datetime.now(UTC)


def _clip(value: object, limit: int) -> str:
    return str(value or "")[:limit]


def _norm_mac(mac: str) -> str:
    return (mac or "").strip().lower().replace("-", ":")


def parse_discovery_xml(text: str) -> list[Host]:
    """Read Nmap's `-sn -oX -` output into hosts, preserving MAC and hostname when present."""
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise ScanError(f"nmap discovery returned invalid XML: {exc}") from exc
    hosts: list[Host] = []
    for node in root.findall("host"):
        status = node.find("status")
        if status is None or status.get("state") != "up":
            continue
        ip = ""
        mac = ""
        for address in node.findall("address"):
            kind = (address.get("addrtype") or "").lower()
            value = (address.get("addr") or "").strip()
            if kind in {"ipv4", "ipv6"} and value and not ip:
                ip = value
            elif kind == "mac" and value:
                mac = value
        if not ip:
            continue
        hostname = ""
        hostnames = node.find("hostnames")
        if hostnames is not None:
            first = hostnames.find("hostname")
            if first is not None:
                hostname = (first.get("name") or "").strip()
        hosts.append(Host(ip=ip, mac=_norm_mac(mac), hostname=hostname, source="nmap"))
    return hosts


def parse_service_xml(text: str) -> list[Service]:
    """Read Nmap's `-sV -oX -` output. Only open TCP/UDP ports become service rows."""
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise ScanError(f"nmap service scan returned invalid XML: {exc}") from exc
    services: list[Service] = []
    for node in root.findall("host"):
        ports = node.find("ports")
        if ports is None:
            continue
        for port_node in ports.findall("port"):
            state = port_node.find("state")
            if state is None or state.get("state") != "open":
                continue
            try:
                port = int(port_node.get("portid") or 0)
            except ValueError:
                continue
            if not port:
                continue
            service_node = port_node.find("service")
            cpes: list[str] = []
            service = product = version = ""
            if service_node is not None:
                service = (service_node.get("name") or "").strip()
                product = (service_node.get("product") or "").strip()
                version = (service_node.get("version") or "").strip()
                cpes = [(c.text or "").strip() for c in service_node.findall("cpe") if (c.text or "").strip()]
            services.append(Service(
                port=port,
                protocol=(port_node.get("protocol") or "tcp").lower(),
                service=service,
                product=product,
                version=version,
                cpe=",".join(cpes),
            ))
    return services


def _script_rows(script: ET.Element, prefix: str = "") -> list[tuple[str, str]]:
    """Flatten the stable, readable parts of one NSE script result.

    Nmap's XML nests tables and elements. Identity needs the named facts (http title, SMB OS,
    certificate subject), not an arbitrary depth of the whole structure; two levels plus the
    script's plain output is enough and keeps the table bounded.
    """
    rows: list[tuple[str, str]] = []
    for elem in script.findall("elem"):
        key = str(elem.get("key") or "").strip()
        value = str(elem.text or "").strip()
        if key and value:
            rows.append((f"{prefix}{key}", value))
    for table in script.findall("table"):
        tkey = str(table.get("key") or "").strip()
        child_prefix = f"{prefix}{tkey}." if tkey else prefix
        for elem in table.findall("elem"):
            key = str(elem.get("key") or "").strip()
            value = str(elem.text or "").strip()
            if key and value:
                rows.append((f"{child_prefix}{key}", value))
    return rows


def parse_script_xml(text: str) -> list[Observation]:
    """Read safe NSE identity scripts from Nmap's XML into bounded key/value observations."""
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise ScanError(f"nmap script scan returned invalid XML: {exc}") from exc
    observations: list[Observation] = []

    def collect(script: ET.Element, port: int) -> None:
        script_id = str(script.get("id") or "").strip()
        if not script_id:
            return
        output = str(script.get("output") or "").strip()
        if output:
            observations.append(Observation(
                port=port, script=script_id, key="output", value=_clip(output, 4000),
            ))
        for key, value in _script_rows(script):
            observations.append(Observation(
                port=port, script=script_id, key=_clip(key, 200), value=_clip(value, 2000),
            ))

    for node in root.findall("host"):
        hostscript = node.find("hostscript")
        if hostscript is not None:
            for script in hostscript.findall("script"):
                collect(script, 0)
        for port_node in node.findall("./ports/port"):
            try:
                port = int(port_node.get("portid") or 0)
            except ValueError:
                port = 0
            for script in port_node.findall("script"):
                collect(script, port)
    return observations


def nuclei_targets(ip: str, services: Iterable[Service]) -> list[str]:
    """URLs worth giving to Nuclei, derived only from services Nmap actually saw open."""
    targets: list[str] = []
    for service in services:
        if service.protocol != "tcp":
            continue
        name = service.service.lower()
        if name not in HTTP_SERVICES and service.port not in HTTP_PORTS:
            continue
        scheme = "https" if name in {"https", "https-alt", "ssl/http"} or service.port in {443, 8443} else "http"
        host = f"[{ip}]" if ":" in ip else ip
        if (scheme == "http" and service.port == 80) or (scheme == "https" and service.port == 443):
            targets.append(f"{scheme}://{host}")
        else:
            targets.append(f"{scheme}://{host}:{service.port}")
    # A host may expose both an HTTP and an HTTPS service; keep both, but do not let one
    # host with hundreds of virtual-host ports produce an unbounded Nuclei command.
    return sorted(set(targets))[:32]


def _cve_value(value: object) -> str:
    if isinstance(value, list):
        return ",".join(str(item).strip() for item in value if str(item).strip())
    return str(value or "").strip()


def parse_nuclei_jsonl(text: str) -> list[Finding]:
    """Parse Nuclei's `-jsonl` output into stable, deduplicated findings."""
    findings: list[Finding] = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            logger.warning("nuclei emitted a non-JSON line: %s", line[:160])
            continue
        info = item.get("info") if isinstance(item.get("info"), dict) else {}
        raw_classification = info.get("classification")
        classification: dict[str, Any] = raw_classification if isinstance(raw_classification, dict) else {}
        template_id = str(item.get("template-id") or item.get("templateID") or "").strip()
        matched_at = str(item.get("matched-at") or item.get("host") or "").strip()
        matcher = str(item.get("matcher-name") or "").strip()
        name = str(info.get("name") or template_id or "Nuclei match").strip()
        severity = str(info.get("severity") or "unknown").strip().lower()
        cve = _cve_value(classification.get("cve-id") or classification.get("cve_id") or item.get("cve-id"))
        finding_key = hashlib.sha1(
            f"{template_id}|{matched_at}|{matcher}|{cve}".encode()
        ).hexdigest()
        findings.append(Finding(
            finding_key=finding_key,
            template_id=template_id,
            name=name,
            severity=severity,
            cve=cve,
            matched_at=matched_at,
            description=_clip(info.get("description"), 1600),
            remediation=_clip(info.get("remediation"), 1200),
        ))
    return findings


def _run(cmd: list[str], timeout_s: int) -> subprocess.CompletedProcess[str]:
    if shutil.which(cmd[0]) is None:
        raise ScanError(f"scanner binary not found: {cmd[0]}")
    try:
        result = subprocess.run(  # noqa: S603 - fixed argv, no shell
            cmd, capture_output=True, text=True, timeout=max(5, int(timeout_s)), check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise ScanError(f"{cmd[0]} timed out after {timeout_s}s") from exc
    if result.returncode != 0 and not (result.stdout or "").strip():
        detail = (result.stderr or "").strip().splitlines()
        raise ScanError(f"{cmd[0]} exited {result.returncode}: {detail[-1] if detail else 'no output'}")
    return result


def in_scope(addr: str, networks: Iterable[Network]) -> bool:
    """Whether an address is a HOST in a monitored network, not the network itself.

    `ip in network` is true for the network and broadcast addresses. Those are not assets: a
    passive flow can carry a broadcast destination (192.0.2.255 in a /24), and scanning it gives
    the inventory a device that does not exist. Multicast and unspecified addresses are excluded
    for the same reason.
    """
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    if ip.is_multicast or ip.is_unspecified or ip.is_loopback:
        return False
    for network in networks:
        if ip not in network:
            continue
        return not (network.version == 4 and (
            ip == network.network_address or ip == network.broadcast_address
        ))
    return False


def monitored_networks(client: Any) -> list[Network]:
    """The scan scope IS the weirling registry, not a second hand-maintained list.

    A monitored network is a network a registered, enabled weirling says it covers. The
    registration's `segment` is free text by design (it can read "third floor IDF"), so only
    values that parse as a CIDR become scan scope. `plan_segment` is already validated as a CIDR
    by the weirling plan code and is included too, which covers an in-path sensor whose plan was
    declared separately from its free-text location.

    A disabled or revoked weirling contributes nothing. An unreadable registry returns [] --
    the scanner must refuse to guess a scope, not fall back to a hard-coded RFC1918 range.
    """
    try:
        rows = client.query(
            "SELECT sensor_id, segment, plan_segment, networks FROM weirvern.weirlings FINAL "
            "WHERE revoked_at IS NULL AND enabled = 1"
        ).result_rows
    except Exception as exc:  # noqa: BLE001 - an unreadable scope is not a reason to scan
        logger.warning("scanner: could not read weirling networks: %s", exc)
        return []

    networks: dict[str, Network] = {}
    for row in rows:
        sensor_id = str(row[0] or "")
        row_networks = row[3] if len(row) > 3 else []
        for label, raw in [
            *[(f"networks[{i}]", value) for i, value in enumerate(row_networks or [])],
            ("segment", row[1]),
            ("plan_segment", row[2]),
        ]:
            value = str(raw or "").strip()
            if not value:
                continue
            try:
                network = ipaddress.ip_network(value, strict=False)
            except ValueError:
                # Free text is a legitimate registration value ("third floor IDF"); it is not
                # a scope mistake and must not stop another sensor's valid segment.
                logger.info("scanner: %s %s is not a CIDR (%r); skipped", sensor_id, label, value)
                continue
            networks[str(network)] = network
    if not networks:
        logger.warning(
            "scanner: no enabled weirling declares a CIDR segment; refusing to scan anything "
            "until the registry names a monitored network"
        )
    # ── AND THE OPERATOR'S OWN SCOPE TABLE HAS THE LAST WORD (2026-11-17) ──────────────────────
    #
    # The registry says which segments a sensor covers; `network_scopes` says which networks are
    # OURS. They are not the same claim, and nmap must never target something the operator has
    # not declared monitored. A registered segment outside every monitored scope is dropped here
    # with a log line -- the scanner keeps working on the segments that are ours instead of
    # refusing everything, and the omission is visible in the log rather than silent.
    from weirvern import monitored as monitored_mod  # noqa: PLC0415

    scopes = monitored_mod.networks(client)
    if scopes:
        for label, network in list(networks.items()):
            inside = any(
                scope.version == network.version
                and network.subnet_of(scope)  # type: ignore[arg-type]
                for scope in scopes
            )
            if not inside:
                logger.warning(
                    "scanner: %s is declared by a weirling but is not inside a monitored "
                    "network (%s); it will not be scanned",
                    label, ", ".join(str(s) for s in scopes))
                networks.pop(label, None)
    else:
        logger.warning(
            "scanner: network_scopes declares no monitored network, so the weirling registry is "
            "the only scope; add the segment to network_scopes to make the intent explicit")
    return list(networks.values())


def _os_release() -> tuple[str, str]:
    """The node's distribution and version, for the guided Nmap command."""
    values: dict[str, str] = {}
    try:
        with open("/etc/os-release", encoding="utf-8") as handle:
            for line in handle:
                if "=" in line:
                    key, value = line.rstrip("\n").split("=", 1)
                    values[key] = value.strip().strip('"')
    except OSError:
        pass
    return values.get("ID", ""), values.get("VERSION_ID", "")


def detect_scanner(settings: Settings) -> dict[str, Any]:
    """What this node can actually do, measured rather than assumed.

    Nmap is optional. A node with Nmap gets the deeper identity profile; a node without it
    stays on passive/basic discovery and never marks assets as clean. The same function runs
    on the hub and, when an agent carries it, on a weirling.
    """
    path = shutil.which(settings.scan_nmap_binary) or ""
    version = ""
    if path:
        try:
            probe = subprocess.run(  # noqa: S603 - fixed argv, no shell
                [path, "--version"], capture_output=True, text=True, timeout=10, check=False,
            )
            first = (probe.stdout or "").strip().splitlines()
            version = first[0].strip() if first else ""
        except (OSError, subprocess.SubprocessError):
            version = ""
    nse_available = os.path.isdir("/usr/share/nmap/scripts")
    os_id, os_version = _os_release()
    available = bool(path and version)
    return {
        # SENSOR_ID is the same identity the heartbeat and fleet registry use. Normalise it so
        # this row joins the registered weirling instead of appearing as a second sensor with a
        # different capitalisation.
        "sensor_id": (settings.sensor_name or socket.gethostname() or "scanner").strip().lower(),
        "profile": "nmap" if available else "basic",
        "nmap_available": available,
        "nmap_version": version,
        "nmap_path": path,
        "nse_available": nse_available,
        "os_id": os_id,
        "os_version": os_version,
        "detail": "" if available else (
            "Nmap is not installed; passive discovery continues and active service scans wait."
        ),
    }


def write_scanner_status(client: Any, status: dict[str, Any]) -> None:
    """Publish the capability row the Weirlings/Scanner UI reads."""
    _insert(client, "scanner_status", SCANNER_STATUS_COLUMNS, [[
        status["sensor_id"], status["profile"], int(bool(status["nmap_available"])),
        status["nmap_version"], status["nmap_path"], int(bool(status["nse_available"])),
        status["os_id"], status["os_version"], status["detail"], _now(),
    ]])


def discover_with_nmap(settings: Settings, networks: list[Network]) -> list[Host]:
    if not networks:
        return []
    cmd = [
        settings.scan_nmap_binary, "--unprivileged", "-sn", "-n", "-oX", "-",
        *[str(network) for network in networks],
    ]
    result = _run(cmd, settings.scan_timeout_s)
    return [host for host in parse_discovery_xml(result.stdout) if in_scope(host.ip, networks)]


def discover_passive(client: Any, networks: list[Network], minutes: int) -> list[Host]:
    """Hosts Weirvern already saw, including devices that do not answer Nmap probes."""
    if not networks:
        return []
    since = _now() - timedelta(minutes=max(1, int(minutes)))
    try:
        rows = client.query(
            "SELECT DISTINCT addr FROM ("
            "  SELECT src_addr AS addr FROM weirvern.flows WHERE timestamp >= %(since)s"
            "  UNION ALL"
            "  SELECT dst_addr AS addr FROM weirvern.flows WHERE timestamp >= %(since)s"
            ") WHERE addr != ''",
            parameters={"since": since},
        ).result_rows
    except Exception as exc:  # noqa: BLE001 - passive discovery must not stop active discovery
        logger.warning("scanner: passive discovery failed: %s", exc)
        return []
    return [Host(ip=str(row[0]), source="passive") for row in rows if in_scope(str(row[0]), networks)]


def merge_hosts(active: Iterable[Host], passive: Iterable[Host]) -> list[Host]:
    merged: dict[str, Host] = {}
    for host in passive:
        merged[host.ip] = host
    for host in active:
        previous = merged.get(host.ip)
        merged[host.ip] = Host(
            ip=host.ip,
            mac=host.mac or (previous.mac if previous else ""),
            hostname=host.hostname or (previous.hostname if previous else ""),
            source=host.source,
        )
    return list(merged.values())


def load_registry(client: Any) -> dict[str, dict[str, Any]]:
    rows = client.query(
        "SELECT asset_key, ip, mac, hostname, first_seen, last_seen, scan_state, "
        "       last_scan_at, scan_error, source FROM weirvern.asset_registry FINAL"
    ).result_rows
    return {str(row[0]): dict(zip(REGISTRY_COLUMNS, row, strict=False)) for row in rows}


def _insert(client: Any, table: str, columns: list[str], rows: list[list[Any]]) -> None:
    if rows:
        client.insert(f"weirvern.{table}", rows, column_names=columns)


def choose_key(host: Host, registry: dict[str, dict[str, Any]]) -> tuple[str, dict[str, Any] | None]:
    mac = _norm_mac(host.mac)
    if mac:
        for key, asset in registry.items():
            if _norm_mac(str(asset.get("mac") or "")) == mac:
                return key, asset
    for key, asset in registry.items():
        if str(asset.get("ip") or "") != host.ip:
            continue
        # SAME ADDRESS, DIFFERENT HARDWARE. A DHCP lease can move to a new device; treating the
        # old row as this host would both hide the new asset and attach stale findings to it.
        if mac and _norm_mac(str(asset.get("mac") or "")) not in {"", mac}:
            continue
        return key, asset
    return (f"mac:{mac}" if mac else f"ip:{host.ip}"), None


def record_host(
    client: Any, host: Host, registry: dict[str, dict[str, Any]], *, baseline: bool,
) -> tuple[str, bool]:
    """Insert or refresh a registry row. Return (asset_key, was_new)."""
    key, existing = choose_key(host, registry)
    now = _now()
    new = existing is None
    if existing is None:
        state = "known" if baseline else "pending"
        row = [
            key, host.ip, _norm_mac(host.mac), host.hostname, now, now,
            state, datetime.fromtimestamp(0, tz=UTC), "", host.source,
        ]
    else:
        row = [
            key, host.ip, _norm_mac(host.mac) or str(existing.get("mac") or ""),
            host.hostname or str(existing.get("hostname") or ""), existing["first_seen"], now,
            existing["scan_state"], existing["last_scan_at"], existing["scan_error"],
            str(existing.get("source") or host.source),
        ]
    _insert(client, "asset_registry", REGISTRY_COLUMNS, [row])
    registry[key] = dict(zip(REGISTRY_COLUMNS, row, strict=False))
    return key, new


def pending_assets(client: Any, limit: int = 8) -> list[dict[str, Any]]:
    rows = client.query(
        "SELECT asset_key, ip, mac, hostname, first_seen, last_seen, scan_state, "
        "       last_scan_at, scan_error, source FROM weirvern.asset_registry FINAL "
        "WHERE scan_state = 'pending' ORDER BY first_seen LIMIT %(limit)s",
        parameters={"limit": max(1, int(limit))},
    ).result_rows
    return [dict(zip(REGISTRY_COLUMNS, row, strict=False)) for row in rows]


def rescan_assets(client: Any, older_than_s: int, limit: int = 8) -> list[dict[str, Any]]:
    """Assets whose last successful/attempted scan is older than the rescan clock.

    Pending-only scanning is a new-host queue, not a change detector. `known` is included because
    a bootstrap host has never been scanned; `error` is included so a transient Nmap failure does
    not make a host permanently invisible. `scanning` is excluded: one scanner process must not
    start a second run against the same host.
    """
    since = _now() - timedelta(seconds=max(1, int(older_than_s)))
    rows = client.query(
        "SELECT asset_key, ip, mac, hostname, first_seen, last_seen, scan_state, "
        "       last_scan_at, scan_error, source FROM weirvern.asset_registry FINAL "
        "WHERE scan_state IN ('done', 'known', 'error') "
        "  AND last_scan_at <= %(since)s "
        "ORDER BY last_scan_at ASC LIMIT %(limit)s",
        parameters={"since": since, "limit": max(1, int(limit))},
    ).result_rows
    return [dict(zip(REGISTRY_COLUMNS, row, strict=False)) for row in rows]


def _mark(client: Any, asset: dict[str, Any], state: str, error: str = "", *, scanned: bool = False) -> None:
    now = _now()
    row = [
        asset["asset_key"], asset["ip"], asset.get("mac", ""), asset.get("hostname", ""),
        asset["first_seen"], now, state, now if scanned else asset.get("last_scan_at"),
        _clip(error, 500), asset.get("source", "scanner"),
    ]
    _insert(client, "asset_registry", REGISTRY_COLUMNS, [row])


def _record_scan(
    client: Any, scan_id: str, asset: dict[str, Any], kind: str, *,
    status: str, error: str = "", command: str = "",
) -> None:
    now = _now()
    _insert(client, "asset_scans", SCAN_COLUMNS, [[
        scan_id, asset["asset_key"], asset["ip"], kind, now,
        None if status == "running" else now, status, _clip(error, 500), _clip(command, 1000),
    ]])


def recover_incomplete(client: Any) -> int:
    """Return interrupted scans to the durable queue.

    A pod can be replaced in the middle of an Nmap run (the first live deploy hit this). The
    registry row is then `scanning` forever: `pending_assets` only selects `pending`, so a restart
    would leave those hosts unscanned and the inventory would look complete while six assets had
    no service data. Re-queue them; the scan itself is idempotent.
    """
    rows = client.query(
        "SELECT asset_key, ip, mac, hostname, first_seen, last_seen, scan_state, "
        "       last_scan_at, scan_error, source FROM weirvern.asset_registry FINAL "
        "WHERE scan_state = 'scanning'"
    ).result_rows
    recovered = 0
    for row in rows:
        asset = dict(zip(REGISTRY_COLUMNS, row, strict=False))
        _mark(client, asset, "pending", "scanner restarted before this scan finished; queued again")
        recovered += 1
    if recovered:
        logger.warning("scanner: re-queued %d interrupted scan(s)", recovered)
    return recovered


def nuclei_arguments(settings: Settings, targets: list[str]) -> list[str]:
    """The Nuclei argv, with the safety and resource flags applied in ONE place.

    THE EXCLUSIONS ARE NOT OPTIONAL STYLE. A template tagged `dos` performs the attack it names
    (CVE-2019-5544 sends an SLP heap-overflow payload); a scanner whose job is inventory must not
    run that against an appliance just because the template repository shipped it. `intrusive`,
    `fuzz`, `brute-force`, `headless` and `code` are excluded for the same reason. The flags are
    explicit here rather than trusting `.nuclei-ignore`, which changes between releases.
    """
    args = [
        settings.scan_nuclei_binary, "-jsonl", "-silent", "-nc", "-duc",
        "-severity", settings.scan_nuclei_severity,
        "-timeout", str(max(1, settings.scan_nuclei_timeout_s)),
        "-retries", str(max(0, settings.scan_nuclei_retries)),
        "-c", str(max(1, settings.scan_nuclei_concurrency)),
        "-bs", str(max(1, settings.scan_nuclei_bulk_size)),
        "-rl", str(max(1, settings.scan_nuclei_rate_limit)),
        "-rsr", str(max(65536, settings.scan_nuclei_response_size)),
        "-mhe", str(max(1, settings.scan_nuclei_max_host_error)),
    ]
    if settings.scan_nuclei_no_interactsh:
        args.append("-ni")
    if settings.scan_nuclei_exclude_tags.strip():
        args.extend(["-etags", settings.scan_nuclei_exclude_tags.strip()])
    if settings.scan_nuclei_exclude_ids.strip():
        args.extend(["-eid", settings.scan_nuclei_exclude_ids.strip()])
    if settings.scan_nuclei_tags.strip():
        args.extend(["-tags", settings.scan_nuclei_tags.strip()])
    if settings.scan_nuclei_templates:
        args.extend(["-t", settings.scan_nuclei_templates])
    for target in targets:
        args.extend(["-u", target])
    return args


def scan_asset(client: Any, settings: Settings, asset: dict[str, Any]) -> bool:
    """Nmap the host's services and safe identity scripts, then optionally run Nuclei.

    The default path is Nmap-only. NSE identity scripts are bundled with Nmap, need no vendor
    controller, and are portable to any network. Nuclei is an opt-in exposure layer, not part of
    the identity pipeline.
    """
    scan_id = str(uuid.uuid4())
    ok = True
    _mark(client, asset, "scanning")
    _record_scan(client, scan_id, asset, "service", status="running")
    command = ""
    error = ""
    try:
        command = (
            f"{settings.scan_nmap_binary} -sV --version-intensity 5 -Pn -T3 --max-retries 2 "
            f"--host-timeout 120s --script {NSE_IDENTITY_SCRIPTS} --script-timeout 30s "
            f"-p {settings.scan_ports} -oX - {asset['ip']}"
        )
        result = _run([
            settings.scan_nmap_binary, "--unprivileged", "-sV", "--version-intensity", "5",
            "-Pn", "-T3", "--max-retries", "2", "--host-timeout", "120s",
            "--script", NSE_IDENTITY_SCRIPTS, "--script-timeout", "30s",
            "-p", settings.scan_ports, "-oX", "-", asset["ip"],
        ], settings.scan_timeout_s)
        services = parse_service_xml(result.stdout)
        observations = parse_script_xml(result.stdout)
        now = _now()

        # THE PREVIOUS SNAPSHOT, BEFORE THIS SCAN OVERWRITES IT. asset_services is the current
        # state, so this is the last successful observation. A failed scan never reaches here.
        previous = client.query(
            "SELECT port, protocol, service, product, version, cpe "
            "FROM weirvern.asset_services FINAL WHERE asset_key = %(asset_key)s",
            parameters={"asset_key": asset["asset_key"]},
        ).result_rows
        # Fit the shadow posture model on history BEFORE this scan's rows are appended, so a new
        # listener is not counted as its own baseline.
        try:
            history = client.query(
                "SELECT port, protocol FROM weirvern.asset_service_history LIMIT 20000"
            ).result_rows
        except Exception:  # noqa: BLE001 - a scoring baseline must not fail the inventory
            history = []
        posture_model = AssetPostureModel.fit(history)
        changes = detect_service_changes(previous, [
            (service.port, service.protocol, service.service, service.product,
             service.version, service.cpe)
            for service in services
        ])

        _insert(client, "asset_services", SERVICE_COLUMNS, [[
            asset["asset_key"], asset["ip"], service.port, service.protocol, service.service,
            service.product, service.version, service.cpe, now,
        ] for service in services])
        if services:
            _insert(client, "asset_service_history", HISTORY_COLUMNS, [[
                asset["asset_key"], asset["ip"], scan_id, service.port, service.protocol,
                service.service, service.product, service.version, service.cpe, now,
            ] for service in services])
        if changes:
            existing_changes = {
                str(row[0]): row for row in client.query(
                    "SELECT change_key, first_seen, review_state FROM weirvern.asset_changes FINAL "
                    "WHERE asset_key = %(asset_key)s",
                    parameters={"asset_key": asset["asset_key"]},
                ).result_rows
            }
            change_rows = []
            for change in changes:
                prior = existing_changes.get(change.change_key)
                change_rows.append([
                    asset["asset_key"], asset["ip"], change.change_key, change.kind,
                    change.port, change.protocol, change.old_value, change.new_value,
                    change.confidence, change.evidence, scan_id,
                    prior[1] if prior else now, now,
                    prior[2] if prior else "new",
                ])
            _insert(client, "asset_changes", CHANGE_COLUMNS, change_rows)
            posture_rows = []
            for change in changes:
                posture = posture_model.score(change, host_services=[
                    (service.port, service.protocol) for service in services
                ])
                posture_rows.append([
                    asset["asset_key"], change.change_key, posture.score, posture.band,
                    list(posture.reasons), json.dumps(posture.features), posture.model_version,
                    now, "new",
                ])
            _insert(client, "asset_posture_scores", POSTURE_COLUMNS, posture_rows)
        if observations:
            _insert(client, "asset_observations", OBSERVATION_COLUMNS, [[
                asset["asset_key"], asset["ip"], item.port, item.script, item.key, item.value, now,
            ] for item in observations])

        # NUCLEI IS OPT-IN. Identity is complete after Nmap + NSE; an unconfigured appliance
        # must not download a template tree or run community exploit checks just to inventory.
        if not settings.scan_nuclei_enabled:
            _mark(client, asset, "done", scanned=True)
            _record_scan(
                client, scan_id, asset, "service", status="done", command=command
            )
            return True

        targets = nuclei_targets(asset["ip"], services)
        if not targets:
            _mark(client, asset, "done", scanned=True)
            _record_scan(client, scan_id, asset, "service", status="done", command=command)
            return True
        args = nuclei_arguments(settings, targets)
        nuclei_command = " ".join(shlex.quote(part) for part in args)
        nuclei_result = _run(args, settings.scan_timeout_s)
        findings = parse_nuclei_jsonl(nuclei_result.stdout)
        existing = {
            str(row[0]): row for row in client.query(
                "SELECT finding_key, first_seen FROM weirvern.asset_findings FINAL "
                "WHERE asset_key = %(asset_key)s",
                parameters={"asset_key": asset["asset_key"]},
            ).result_rows
        }
        now = _now()
        _insert(client, "asset_findings", FINDING_COLUMNS, [[
            asset["asset_key"], asset["ip"], "nuclei", finding.finding_key, finding.template_id,
            finding.name, finding.severity, finding.cve, finding.matched_at,
            finding.description, finding.remediation,
            existing.get(finding.finding_key, [None, now])[1], now,
        ] for finding in findings])
        _mark(client, asset, "done", scanned=True)
        _record_scan(client, scan_id, asset, "nuclei", status="done", command=nuclei_command)
    except Exception as exc:  # noqa: BLE001 - one host must not stop the inventory
        ok = False
        error = str(exc)
        logger.warning("scanner: %s failed: %s", asset.get("ip"), error)
        _mark(client, asset, "error", error, scanned=True)
        _record_scan(client, scan_id, asset, "service", status="error", error=error, command=command)
    return ok


def process_scan_jobs(client: Any, settings: Settings) -> int:
    """Claim at most one manual job and run it, under a lease.

    A job is a one-host request from the Assets view. It runs before the scheduled pending/rescan
    work so an operator's explicit click is not stuck behind a large hourly sweep. A failed Nmap
    invocation is recorded on the job as well as on the asset; the scanner never reports a queued
    job as done just because it tried.
    """
    lease_s = getattr(settings, "scan_job_lease_s", 0)
    if lease_s <= 0:
        return 0
    job = scan_jobs.claim_next_job(client, owner=socket.gethostname() or "scanner", lease_s=lease_s)
    if not job:
        return 0
    asset = scan_jobs.find_asset(client, job["ip"])
    if asset is None:
        scan_jobs.finish_job(
            client, job, ok=False,
            error="the host is no longer in the asset registry; run discovery first",
        )
        return 1
    try:
        ok = scan_asset(client, settings, asset)
    except Exception as exc:  # noqa: BLE001 - the job must reach a terminal state
        ok = False
        scan_jobs.finish_job(client, job, ok=False, error=str(exc))
        logger.warning("scanner: manual scan job %s failed: %s", job["job_id"], exc)
        return 1
    error = ""
    if not ok:
        refreshed = scan_jobs.find_asset(client, job["ip"])
        error = str((refreshed or {}).get("scan_error") or "the asset scan failed")
    scan_jobs.finish_job(client, job, ok=ok, error=error)
    logger.info("scanner: manual scan %s for %s -> %s", job["job_id"], job["ip"],
                "done" if ok else "error")
    return 1


def run_once(
    client: Any, settings: Settings, *, bootstrap: bool | None = None, discover: bool = True,
    scan_pending: bool = True,
) -> dict[str, int]:
    networks = monitored_networks(client)
    registry = load_registry(client)
    baseline = (not registry) and not (settings.scan_bootstrap if bootstrap is None else bootstrap)
    active: list[Host] = []
    if networks and discover and scan_pending:
        try:
            active = discover_with_nmap(settings, networks)
        except ScanError as exc:
            logger.warning("scanner: active discovery failed: %s", exc)
    passive = discover_passive(client, networks, settings.scan_passive_minutes)
    hosts = merge_hosts(active, passive)
    new_count = 0
    for host in hosts:
        _, new = record_host(client, host, registry, baseline=baseline)
        new_count += int(new)
    scanned = 0
    if scan_pending:
        scanned += process_scan_jobs(client, settings)
        for asset in pending_assets(client, settings.scan_max_hosts):
            scan_asset(client, settings, asset)
            scanned += 1
        # The second half of the scanner's job: revisit hosts that were already inventoried.
        # A new listener on an existing host is a change, and without this the change ledger
        # would stay empty forever. 0 disables the rescan clock.
        rescan_s = getattr(settings, "scan_rescan_s", 0)
        if rescan_s > 0:
            for asset in rescan_assets(client, rescan_s, settings.scan_max_hosts):
                scan_asset(client, settings, asset)
                scanned += 1
    return {"hosts": len(hosts), "new": new_count, "scanned": scanned}


def run_forever(settings: Settings) -> None:
    if not settings.scan_enabled:
        logger.info("scanner: SCAN_ENABLED is off; idling without touching the network")
        while True:
            time.sleep(3600)
    client = db.connect(settings)
    db.apply_schema(client, settings)
    recover_incomplete(client)
    logger.info(
        "scanner: enabled; scope=weirlings passive=%ss active=%ss nmap=%s nuclei=%s",
        settings.scan_interval_s, settings.scan_discovery_s,
        settings.scan_nmap_binary,
        settings.scan_nuclei_binary if settings.scan_nuclei_enabled else "disabled",
    )
    last_discovery = 0.0
    while True:
        try:
            capability = detect_scanner(settings)
            write_scanner_status(client, capability)
            now = time.monotonic()
            discover = (now - last_discovery) >= settings.scan_discovery_s
            result = run_once(
                client, settings, discover=discover,
                scan_pending=bool(capability["nmap_available"]),
            )
            if discover and capability["nmap_available"]:
                last_discovery = now
            note = "" if capability["nmap_available"] else " (basic: nmap not installed)"
            if not discover and capability["nmap_available"]:
                note = " (passive only)"
            logger.info("scanner: %s%s", result, note)
        except Exception as exc:  # noqa: BLE001 - the loop must survive a bad pass
            logger.warning("scanner: pass failed: %s", exc)
        time.sleep(max(10, settings.scan_interval_s))


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    run_forever(Settings())


if __name__ == "__main__":
    main()
