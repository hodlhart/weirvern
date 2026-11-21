"""Asset scanning: Nmap service and NSE identity measurements, executed by weirlings.

WHERE IT RUNS
-------------
Scanning is a FLEET job. There is no central scanner Deployment: every registered
weirling runs `weirvern.admin.sensor_agent`, which measures its own Nmap at startup
and claims manual jobs from the hub's queue only when it can actually run one
(`claim_next_job`). A weirling without Nmap reports that fact and never claims, so a
queued job is never held by a node that cannot execute it.

WHAT A SCAN IS
--------------
    Nmap services + safe NSE identity scripts -> registry, services, observations

Nmap contributes services and identity facts. Nothing here invents a vulnerability
finding: an NSE script's output is an OBSERVATION (what the device calls itself), not
proof of a missing patch. `vuln`, `intrusive`, `brute` and `dos` script categories are
deliberately excluded.

THE NEW-HOST PROMISE (hub-side inventory)
-----------------------------------------
Discovery helpers below union Nmap's active sweep with hosts seen passively, so a
device that never answers a probe is still inventoried. A first run is treated as a
BASELINE, not a wave of new devices: existing hosts are recorded as `known` unless
SCAN_BOOTSTRAP=1. After that, a genuinely new address or MAC is pending immediately.

DESIGN RULES
------------
* Registry keys prefer `mac:` when a MAC is available and fall back to `ip:`. Addresses
  move under DHCP, so the MAC is the better long-lived key when one exists.
* Every invocation is recorded in `asset_scans`, including failures. "No services" and
  "the scan did not run" must not look the same in the UI.
* Scanning is scoped by the weirling registry and never scans the whole internet.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import os
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

from weirvern import os_release, scan_jobs
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
OBSERVATION_COLUMNS = [
    "asset_key", "ip", "port", "script", "key", "value", "observed_at",
]
SCAN_COLUMNS = [
    "scan_id", "asset_key", "ip", "kind", "started_at", "finished_at", "status", "error", "command",
]
SCANNER_STATUS_COLUMNS = [
    "sensor_id", "profile", "nmap_available", "nmap_version", "nmap_path",
    "nse_available", "os_id", "os_version", "detail", "last_check",
    # Appended (never reordered): a pre-capability reader stays aligned.
    "privileged", "scan_mode", "can_install", "sudo_state",
    # Appended (051): the DISTRO label and package FAMILY, kept apart. os_id stays the machine
    # identifier; os_label is what a person reads ("Ubuntu 26.04 LTS (debian family — apt)").
    "os_label", "os_family",
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


class ScanCancelled(ScanError):
    """The operator asked the weirling to stop, and it did."""


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


def _run(cmd: list[str], timeout_s: int,
         cancel_check: Any = None) -> subprocess.CompletedProcess[str]:
    if shutil.which(cmd[0]) is None:
        raise ScanError(f"scanner binary not found: {cmd[0]}")
    if cancel_check is not None:
        # A CANCELLABLE SCAN IS A SCAN THAT CAN BE STOPPED. The hub's `cancel_requested` is
        # polled while Nmap runs; a cancel that only deletes a row would leave the probe live.
        deadline = time.monotonic() + max(1, int(timeout_s))
        process = subprocess.Popen(  # noqa: S603 - fixed argv, no shell
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            while True:
                try:
                    out, err = process.communicate(timeout=1.0)
                    break
                except subprocess.TimeoutExpired:
                    try:
                        stop = bool(cancel_check())
                    except Exception:  # noqa: BLE001 - a failed check is not a stop
                        stop = False
                    if stop:
                        process.kill()
                        out, err = process.communicate()
                        raise ScanCancelled("cancelled by the operator") from None
                    if time.monotonic() >= deadline:
                        process.kill()
                        process.communicate()
                        raise ScanError("the scan timed out") from None
        finally:
            if process.poll() is None:
                process.kill()
        if process.returncode != 0:
            raise ScanError((err or out or "the scan failed").strip()[:500])
        return subprocess.CompletedProcess(cmd, process.returncode, out, err)
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


def _os_release() -> dict[str, str]:
    """The host's /etc/os-release content. Empty when unreadable -- never a guess."""
    return os_release.read()


def detect_scanner(settings: Settings, sensor_id: str = "") -> dict[str, Any]:
    """What THIS node can actually do, measured rather than assumed.

    Runs on any weirling before it claims a job: Nmap is the capability, not a setting. A node
    without Nmap reports `nmap missing` and never claims, so a queued job cannot be held by a
    node that cannot run it. `sensor_id` is the fleet identity that makes the row join the
    registered weirling; it defaults to the configured sensor name for hub-side callers.
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
    identity = os_release.identity(_os_release())
    os_id = identity["os_id"]
    os_version = identity["os_version"]
    os_family = identity["os_family"]
    available = bool(path and version)
    ident = (sensor_id or settings.sensor_name or socket.gethostname() or "weirling").strip().lower()
    privilege = sudo_state()
    privileged = privilege == "root"
    caps = nmap_has_caps(path)
    mode = scan_mode(available, privileged, caps)
    # THE COMMAND COMES FROM THE ID FIRST, THEN THE FAMILY. The ID carries the nuances a family
    # loses (an old CentOS is yum, not dnf); the family is the fallback for a distro we do not
    # list but whose ID_LIKE names one we do. The DISPLAY is always the distro, never the family.
    install = nmap_install_command(os_id, os_version)
    if not install["known"] and os_family and os_family != os_id:
        install = nmap_install_command(os_family, os_version)
    os_label = identity["os_display"]
    if os_family and os_family != os_id and install["manager"]:
        os_label = f"{identity['os_display']} ({os_family} family — {install['manager']})"
    can_install = can_install_without_a_secret()
    detail = ""
    if not available:
        detail = (
            f"Nmap is not installed; install it with: {install['command']}, then "
            f"setcap cap_net_raw,cap_net_admin+eip /usr/bin/nmap. This unit cannot claim a scan "
            f"until then."
        )
    elif mode == "connect":
        detail = (
            "Nmap is present but this process has no raw-socket capability, so only TCP connect "
            "scans are available. Grant SYN/UDP with: "
            "sudo setcap cap_net_raw,cap_net_admin+eip /usr/bin/nmap"
        )
    return {
        "sensor_id": ident,
        "profile": "nmap" if available else "basic",
        "nmap_available": available,
        "nmap_version": version,
        "nmap_path": path,
        "nse_available": nse_available,
        "os_id": os_id,
        "os_version": os_version,
        "os_family": os_family,
        "os_label": os_label,
        "privileged": privileged,
        "scan_mode": mode,
        "can_install": can_install,
        "sudo_state": privilege,
        "detail": detail,
    }


def nmap_short_version(version: str) -> str:
    """`Nmap version 7.95 ( https://nmap.org )` -> `7.95`; empty when the line names none.

    The card has one line per weirling. Pasted whole, the vendor URL crowds out the fact the
    operator is reading for; a version that cannot be parsed stays empty rather than becoming a
    plausible-looking number.
    """
    text = str(version or "")
    marker = text.lower().find("version ")
    if marker < 0:
        return ""
    tail = text[marker + len("version "):].strip()
    if not tail:
        return ""
    token = tail.split()[0].strip("(),")
    # A REAL VERSION STARTS WITH A DIGIT. `not a version line` contains the words but names no
    # version; returning "line" would put a plausible-looking value in the card.
    return token if token[:1].isdigit() else ""


CAPABILITY_MAX_AGE_S = 900


def _parse_networks(values: object) -> list[Network]:
    out: list[Network] = []
    for raw in values if isinstance(values, list) else []:
        text = str(raw or "").strip()
        if not text:
            continue
        try:
            out.append(ipaddress.ip_network(text, strict=False))
        except ValueError:
            logger.warning("scanner: ignoring a malformed weirling network %r", text[:80])
    return out


def target_in_networks(ip: str, networks: Iterable[Network]) -> bool:
    """Is this target inside a weirling's declared monitored networks?

    EMPTY MEANS "NOT DECLARED", NEVER "COVERS NOTHING". A weirling with no networks cannot
    prove it can reach the target, so it is not eligible; the operator fixes that by declaring
    the network on the weirling, not by the hub guessing an RFC1918 range.

    Delegates to `scan_jobs.ip_allowed`, the definition the CLAIM uses. Two implementations
    would let the console promise a scan the claim then refuses.
    """
    return scan_jobs.ip_allowed(ip, [str(network) for network in networks])


def declared_networks(networks: object, segment: object = "", plan_segment: object = "") -> list[str]:
    """The CIDRs a registration actually declares, from every place it may declare one.

    `networks` is the explicit list; `segment` is free text by design ("third floor IDF") and
    `plan_segment` is the in-path plan's own field. Only values that PARSE as a CIDR count, in
    that order, deduplicated. This is the same rule `monitored_networks` has always used, so the
    claim, the eligibility count and the discovery scope cannot disagree about who covers what.
    """
    out: list[str] = []
    for raw in [
        *(list(networks) if isinstance(networks, list) else []),
        segment, plan_segment,
    ]:
        text = str(raw or "").strip()
        if not text:
            continue
        try:
            network = str(ipaddress.ip_network(text, strict=False))
        except ValueError:
            continue
        if network not in out:
            out.append(network)
    return out


def checked_at(value: Any) -> datetime | None:
    """One capability row's `last_check` as an aware UTC datetime, or None when it has none.

    ClickHouse hands back naive datetimes; the console compares them to `now`, so the naive form
    is read as UTC (the zone the writer stores) rather than silently as local time.
    """
    if isinstance(value, datetime):
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
    return None


def freshness(last_check: Any, *, now: datetime | None = None,
              max_age_s: int = CAPABILITY_MAX_AGE_S) -> tuple[bool, float | None]:
    """(fresh, age_seconds) for ONE capability report -- THE staleness rule, in one place.

    TWO READERS ASKED THE SAME QUESTION AND ONE ANSWERED WRONG. `fleet_capability` already
    ignored an aged row, but `/api/scanner` stamped every row it read as `reported`, so a
    seven-hour-old `nmap missing` was presented as this weirling's current verdict (and the
    card offered an install based on it). Both readers now call this function, so the window
    cannot drift between the readiness sentence and the scanner card.

    A row with no timestamp is NOT fresh: unknown is not a licence to claim a measurement.
    """
    when = checked_at(last_check)
    if when is None:
        return False, None
    moment = now or _now()
    return ((moment - when).total_seconds() <= max(60, int(max_age_s)),
            (moment - when).total_seconds())


def fleet_capability(client: Any, *, ip: str = "", now: datetime | None = None,
                     max_age_s: int = CAPABILITY_MAX_AGE_S) -> dict[str, Any]:
    """WHO can scan, from the fleet's own capability rows — never from a deployment setting.

    A registered weirling is counted only when its last `scanner_status` row is BOTH fresh and
    says Nmap is available. A stale row is not capability: the central scanner's last row can
    sit in the table for days after that workload is gone, and counting it would promise a scan
    nothing can execute (the exact class of lie this queue is being taught to stop telling).

    `ip` narrows the answer to ONE target: a weirling is eligible only when the address is
    inside the networks it declared in its own registration. Returns one shape for the card,
    the button, the POST refusal and the claim, so the four cannot drift.
    """
    moment = now or _now()
    age_limit = max(60, int(max_age_s))
    rows = client.query(
        "SELECT sensor_id, profile, nmap_available, nmap_version, detail, last_check, "
        "       scan_mode "
        "FROM weirvern.scanner_status FINAL ORDER BY sensor_id"
    ).result_rows
    registered = client.query(
        "SELECT sensor_id, networks, segment, plan_segment FROM weirvern.weirlings FINAL "
        "WHERE revoked_at IS NULL AND enabled = 1 ORDER BY sensor_id"
    ).result_rows

    latest: dict[str, dict[str, Any]] = {}
    for row in rows:
        sid = str(row[0] or "").strip().lower()
        if not sid or sid in latest:
            continue
        checked = row[5]
        when = checked_at(checked)
        latest[sid] = {
            "sensor_id": sid,
            "nmap_available": bool(row[2]),
            "nmap_version": nmap_short_version(str(row[3] or "")),
            "detail": str(row[4] or ""),
            "last_check": when,
            "scan_mode": str(row[6] if len(row) > 6 else "") or
                         ("raw" if bool(row[2]) else "none"),
        }

    capable: list[dict[str, Any]] = []
    incapable: list[dict[str, Any]] = []
    unknown: list[dict[str, Any]] = []
    names: list[str] = []
    networks_by_sensor: dict[str, list[Network]] = {}
    for item in registered:
        sid = str(item[0] or "").strip().lower()
        if not sid:
            continue
        names.append(sid)
        declared = declared_networks(item[1], item[2] if len(item) > 2 else "",
                                     item[3] if len(item) > 3 else "")
        networks_by_sensor[sid] = _parse_networks(declared)
    for sid in names:
        seen = latest.get(sid)
        declared = [str(n) for n in networks_by_sensor.get(sid, [])]
        base = {"sensor_id": sid, "nmap_version": "", "networks": declared,
                "scan_mode": "unknown"}
        if seen is None:
            unknown.append({**base, "reason": "no capability report has ever arrived from this weirling"})
            continue
        when = seen["last_check"]
        is_fresh, age_s = freshness(when, now=moment, max_age_s=age_limit)
        if not is_fresh:
            unknown.append({**base, "nmap_version": seen["nmap_version"],
                            "reason": (f"no capability report in {ago(age_s)}" if age_s is not None
                                       else "its capability report carries no timestamp")})
            continue
        if seen["nmap_available"]:
            capable.append({**base, "nmap_version": seen["nmap_version"],
                            "scan_mode": seen.get("scan_mode") or "connect",
                            "last_check": when.isoformat() if when else ""})
        else:
            incapable.append({**base, "reason": "nmap missing"})

    total = len(names)
    noun = "weirling" if total == 1 else "weirlings"

    eligible: list[dict[str, Any]] = []
    out_of_scope: list[dict[str, Any]] = []
    if ip:
        for item in capable:
            if target_in_networks(ip, networks_by_sensor.get(item["sensor_id"], [])):
                eligible.append(item)
            else:
                out_of_scope.append(item)
    else:
        eligible = list(capable)
    reachable = [sid for sid in names if not ip
                 or target_in_networks(ip, networks_by_sensor.get(sid, []))]
    enabled = bool(eligible) if ip else bool(capable)

    if enabled:
        versions = sorted({item["nmap_version"] for item in capable if item["nmap_version"]})
        detail = f" (nmap {', '.join(versions)})" if versions else ""
        modes = {item["scan_mode"] for item in eligible if item.get("scan_mode")}
        mode_note = ""
        if modes == {"connect"}:
            mode_note = " — connect scans only: no raw-socket capability on the scanning weirling"
        elif "raw" in modes:
            mode_note = " — SYN/UDP available"
        if ip:
            sentence = (f"{len(eligible)} of {len(reachable)} weirling"
                        f"{'s' if len(reachable) != 1 else ''} can scan {ip}{detail}{mode_note}")
            if total > len(reachable):
                sentence += f"; {total - len(reachable)} cannot reach it"
        else:
            sentence = f"{len(capable)} of {total} {noun} can scan{detail}{mode_note}"
        if incapable:
            sentence += ", " + ", ".join(f"{x['sensor_id']} cannot ({x['reason']})" for x in incapable)
        if unknown:
            sentence += ", " + ", ".join(f"{x['sensor_id']} unknown ({x['reason']})" for x in unknown)
        reason = ""
    elif total == 0:
        sentence = "no weirling is registered, so no node can run a scan"
        reason = sentence
    elif ip and not reachable:
        sentence = (f"no registered weirling monitors {ip}: "
                    + ", ".join(f"{sid} declares {', '.join(str(n) for n in networks_by_sensor[sid]) or 'no networks'}"
                                for sid in names)
                    + ". Add the network to a weirling's registration first.")
        reason = sentence
    elif ip and not eligible:
        bits = []
        for sid in reachable:
            if sid in {x["sensor_id"] for x in incapable}:
                bits.append(f"{sid} cannot (nmap missing)")
            elif sid in {x["sensor_id"] for x in unknown}:
                match = next(x for x in unknown if x["sensor_id"] == sid)
                bits.append(f"{sid} unknown ({match['reason']})")
        sentence = (f"{len(reachable)} weirling{'s' if len(reachable) != 1 else ''} can reach {ip}, "
                    "but none can scan: " + "; ".join(bits)
                    + ". Install Nmap on a weirling ('sudo apt-get install -y nmap' or the "
                      "command for its OS) and restart its agent.")
        reason = sentence
    else:
        bits = []
        for item in incapable:
            bits.append(f"{item['sensor_id']} cannot ({item['reason']})")
        for item in unknown:
            bits.append(f"{item['sensor_id']} unknown ({item['reason']})")
        sentence = (f"0 of {total} {noun} can scan: " + "; ".join(bits)
                    + ". Install Nmap on a weirling ('sudo apt-get install -y nmap' or the "
                      "command for its OS) and restart its agent.")
        reason = sentence
    return {
        "available": True, "reason": "",
        "enabled": enabled, "count": total,
        "capable_count": len(capable),
        "capable": capable, "incapable": incapable, "unknown": unknown,
        "ip": ip, "reachable_count": len(reachable),
        "eligible": eligible, "out_of_scope": out_of_scope,
        "max_age_s": age_limit,
        "sentence": sentence,
        "reason_unavailable": reason,
    }


def ago(seconds: float | None) -> str:
    if seconds is None:
        return "unknown"
    total = max(0, int(seconds))
    days, hours, minutes = total // 86400, (total % 86400) // 3600, (total % 3600) // 60
    if days:
        return f"{days}d"
    if hours:
        return f"{hours}h"
    if minutes:
        return f"{minutes}m"
    return f"{total}s"


def capability_failure(exc: BaseException) -> dict[str, Any]:
    """A failed capability read is NOT "no weirling can scan" — it is an unknown answer."""
    logger.warning("scanner capability unavailable: %s", exc)
    return {"available": False, "reason": f"weirling scan capability could not be read: {str(exc)[:200]}",
            "enabled": True, "count": 0, "capable_count": 0,
            "capable": [], "incapable": [], "unknown": [], "max_age_s": CAPABILITY_MAX_AGE_S,
            "sentence": "", "reason_unavailable": ""}


SUDOERS_ENTRY = "/etc/sudoers.d/weirvern-nmap"


def scan_mode(available: bool, privileged: bool, caps: bool) -> str:
    """What kind of scan this node can ACTUALLY run: `none` | `connect` | `raw`.

    THE DISTINCTION IS NOT COSMETIC. Unprivileged Nmap can only complete a TCP connection
    (`--unprivileged`, connect scan); SYN and UDP scans need CAP_NET_RAW/CAP_NET_ADMIN (or
    root). Reporting "can scan" without saying which would promise a scan type the node cannot
    perform, so readiness carries the mode and the console prints it.
    """
    if not available:
        return "none"
    return "raw" if (privileged or caps) else "connect"


def scan_mode_sentence(mode: str) -> str:
    return {
        "none": "nmap missing",
        "connect": "nmap present, unprivileged (connect scan only)",
        "raw": "nmap present with raw-socket capabilities (SYN/UDP available)",
    }.get(str(mode or ""), "scan capability unknown")


def nmap_has_caps(path: str) -> bool:
    """Does this Nmap binary carry the raw-socket file capabilities set by the installer?

    `getcap` is part of libcap2-bin; when it is absent the answer is a conservative False,
    because claiming raw scans from an unproven capability is the failure mode this exists to
    prevent. Root needs no capability and is handled by the caller.
    """
    if not path:
        return False
    getcap = shutil.which("getcap")
    if not getcap:
        return False
    try:
        out = subprocess.run(  # noqa: S603 - fixed argv, no shell
            [getcap, path], capture_output=True, text=True, timeout=5, check=False,
        ).stdout or ""
    except (OSError, subprocess.SubprocessError):
        return False
    return "cap_net_raw" in out and "cap_net_admin" in out


def sudo_state() -> str:
    """What sudo says about THIS user: root | passwordless | password | none | unknown.

    MEASURED, not assumed. `sudo -n -l` succeeds for a passwordless rule, asks for a password
    ("a password is required") when the user is in sudoers, and says "not in the sudoers file"
    when they are not. The distinction matters: a password can fix the middle case and cannot
    fix the last one, so the console must not offer a prompt that cannot succeed.
    """
    if os.geteuid() == 0:
        return "root"
    sudo = shutil.which("sudo")
    if not sudo:
        return "none"
    try:
        probe = subprocess.run(  # noqa: S603 - fixed argv, no shell
            [sudo, "-n", "-l"], capture_output=True, text=True, timeout=10, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    if probe.returncode == 0:
        return "passwordless"
    err = ((probe.stderr or "") + (probe.stdout or "")).lower()
    if "password is required" in err:
        return "password"
    if "not in the sudoers" in err:
        return "none"
    return "unknown"


def can_install_without_a_secret() -> bool:
    """Could this process install nmap with NO password prompt?

    Root, or a passwordless scoped sudoers entry. A user who *has* a sudo password is not
    counted: this build has no secret channel from the console to an agent, so offering a
    password field would be a UI that cannot deliver. That case is told plainly instead.
    """
    if os.geteuid() == 0:
        return True
    return os.access(SUDOERS_ENTRY, os.R_OK)


def nmap_install_command(os_id: str, os_version: str = "") -> dict[str, Any]:
    """The exact Nmap install command for a host's own OS, from the agent's report.

    ONE TABLE, keyed by `/etc/os-release` ID. An unknown distro gets a GENERIC instruction and
    `known: false` -- never a guessed package manager: running the wrong one is a failure the
    operator has to debug on a host they may not be sitting at.
    """
    ident = str(os_id or "").strip().lower()
    version = str(os_version or "").strip()
    apt = ("debian", "ubuntu", "linuxmint", "pop", "raspbian", "kali", "devuan", "elementary")
    dnf = ("fedora", "rocky", "almalinux", "ol", "rhel", "centos")
    if ident in apt:
        return {"manager": "apt", "known": True,
                "command": "sudo apt-get update && sudo apt-get install -y nmap"}
    if ident in dnf:
        major = version.split(".")[0]
        if ident in {"centos", "rhel"} and major.isdigit() and int(major) < 8:
            return {"manager": "yum", "known": True, "command": "sudo yum install -y nmap"}
        return {"manager": "dnf", "known": True, "command": "sudo dnf install -y nmap"}
    if ident == "alpine":
        return {"manager": "apk", "known": True,
                "command": "sudo apk add --no-cache nmap"}
    if ident in {"arch", "manjaro", "endeavouros", "garuda"}:
        return {"manager": "pacman", "known": True,
                "command": "sudo pacman -S --noconfirm nmap"}
    if ident in {"opensuse-leap", "opensuse-tumbleweed", "opensuse", "sles", "suse"}:
        return {"manager": "zypper", "known": True, "command": "sudo zypper install -y nmap"}
    return {
        "manager": "", "known": False,
        "command": ("install nmap with this host's package manager "
                    "(apt-get / dnf / apk / pacman / zypper), then restart the weirling agent"),
    }


def write_scanner_status(client: Any, status: dict[str, Any]) -> None:
    """Publish the capability row the Weirlings/Scanner UI reads."""
    _insert(client, "scanner_status", SCANNER_STATUS_COLUMNS, [[
        status["sensor_id"], status["profile"], int(bool(status["nmap_available"])),
        status["nmap_version"], status["nmap_path"], int(bool(status["nse_available"])),
        status["os_id"], status["os_version"], status["detail"], _now(),
        int(bool(status.get("privileged"))), str(status.get("scan_mode") or ""),
        int(bool(status.get("can_install"))), str(status.get("sudo_state") or ""),
        str(status.get("os_label") or ""), str(status.get("os_family") or ""),
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


def service_scan_argv(settings: Settings, ip: str, *, raw: bool = False) -> list[str]:
    """The one Nmap invocation a scan is, as argv. Fixed argv, no shell, no user input.

    `raw=True` omits `--unprivileged` so Nmap uses SYN/UDP where the installer granted
    CAP_NET_RAW/CAP_NET_ADMIN. The command is recorded in asset_scans, so which mode ran is
    auditable rather than implied.
    """
    lead = [settings.scan_nmap_binary] + ([] if raw else ["--unprivileged"])
    return [
        *lead, "-sV", "--version-intensity", "5",
        "-Pn", "-T3", "--max-retries", "2", "--host-timeout", "120s",
        "--script", NSE_IDENTITY_SCRIPTS, "--script-timeout", "30s",
        "-p", settings.scan_ports, "-oX", "-", ip,
    ]


def run_service_scan(settings: Settings, ip: str, *, raw: bool = False,
                     cancel_check: Any = None) -> dict[str, Any]:
    """MEASURE one host with Nmap: services and NSE observations, no database, no writes.

    Split from the recording half so a WEIRLING can run the measurement and send the facts
    to the hub, while the hub writes them with the same code it has always used. A unit with
    no database credential never needs one to scan.
    """
    argv = service_scan_argv(settings, ip, raw=raw)
    command = " ".join(argv)
    try:
        result = _run(argv, settings.scan_timeout_s, cancel_check=cancel_check)
        return {
            "ok": True,
            "command": command,
            "error": "",
            "services": parse_service_xml(result.stdout),
            "observations": parse_script_xml(result.stdout),
        }
    except Exception as exc:  # noqa: BLE001 - an invocation failure is a measured result
        return {"ok": False, "command": command, "error": str(exc),
                "cancelled": isinstance(exc, ScanCancelled),
                "services": [], "observations": []}


def _service_rows(payload: object) -> list[Service]:
    rows: list[Service] = []
    for item in payload if isinstance(payload, list) else []:
        if not isinstance(item, dict):
            continue
        try:
            port = int(item.get("port") or 0)
        except (TypeError, ValueError):
            continue
        rows.append(Service(
            port=port,
            protocol=str(item.get("protocol") or "tcp")[:16],
            service=str(item.get("service") or "")[:120],
            product=str(item.get("product") or "")[:200],
            version=str(item.get("version") or "")[:120],
            cpe=str(item.get("cpe") or "")[:300],
        ))
    return rows


def _observation_rows(payload: object) -> list[Observation]:
    rows: list[Observation] = []
    for item in payload if isinstance(payload, list) else []:
        if not isinstance(item, dict):
            continue
        try:
            port = int(item.get("port") or 0)
        except (TypeError, ValueError):
            port = 0
        rows.append(Observation(
            port=port,
            script=_clip(item.get("script"), 120),
            key=_clip(item.get("key"), 200),
            value=_clip(item.get("value"), 2000),
        ))
    return rows


def record_scan_result(client: Any, asset: dict[str, Any], result: dict[str, Any], *,
                       scan_id: str) -> bool:
    """Record ONE measured scan: services, history, changes, posture, observations.

    `result` is the shape `run_service_scan` returns, so a result measured on a weirling and
    sent over the mTLS gateway is written by THIS function -- the fleet cannot grow a second
    definition of what a scan row is. A failed invocation is marked `error`, never `done`.
    """
    ok = bool(result.get("ok"))
    command = str(result.get("command") or "")
    if not ok:
        error = str(result.get("error") or "the scan failed")
        _mark(client, asset, "error", error, scanned=True)
        _record_scan(client, scan_id, asset, "service", status="error", error=error, command=command)
        return False
    services = _service_rows(result.get("services"))
    observations = _observation_rows(result.get("observations"))
    try:
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
    except Exception as exc:  # noqa: BLE001 - one host must not stop the inventory
        error = str(exc)
        logger.warning("scanner: recording %s failed: %s", asset.get("ip"), error)
        _mark(client, asset, "error", error, scanned=True)
        _record_scan(client, scan_id, asset, "service", status="error", error=error, command=command)
        return False

    _mark(client, asset, "done", scanned=True)
    _record_scan(client, scan_id, asset, "service", status="done", command=command)
    return True


def scan_asset(client: Any, settings: Settings, asset: dict[str, Any],
               *, raw: bool = False, cancel_check: Any = None) -> bool:
    """Measure one host and record it: the hub-side path, unchanged by where it runs."""
    scan_id = str(uuid.uuid4())
    _mark(client, asset, "scanning")
    _record_scan(client, scan_id, asset, "service", status="running")
    return record_scan_result(
        client, asset, run_service_scan(settings, asset["ip"], raw=raw, cancel_check=cancel_check),
        scan_id=scan_id)


def run_claimed_job(client: Any, settings: Settings, job: dict[str, Any],
                    *, raw: bool = False, cancel_check: Any = None) -> bool:
    """Run ONE claimed manual job to a terminal state, on a claimer with database access.

    A cancelled job is DELETED (with an audit row), because the operator asked for the request
    to be removed and the weirling confirmed it stopped. Any other outcome is recorded on the
    asset and finished on the job -- a failed Nmap is never reported as done.
    """
    asset = scan_jobs.find_asset(client, str(job.get("ip") or ""))
    if asset is None:
        scan_jobs.finish_job(
            client, job, ok=False,
            error="the host is no longer in the asset registry; run discovery first",
        )
        return False
    scan_id = str(uuid.uuid4())
    try:
        _mark(client, asset, "scanning")
        _record_scan(client, scan_id, asset, "service", status="running")
        result = run_service_scan(settings, asset["ip"], raw=raw, cancel_check=cancel_check)
    except Exception as exc:  # noqa: BLE001 - the job must reach a terminal state
        scan_jobs.finish_job(client, job, ok=False, error=str(exc))
        logger.warning("scanner: manual scan job %s failed: %s", job.get("job_id"), exc)
        return False
    if result.get("cancelled"):
        from weirvern import fleet_store  # noqa: PLC0415

        fleet_store.write_audit(
            client, scope="scan", action="scan_cancelled_confirmed",
            target=f"{job.get('ip')} job {job.get('job_id')}",
            reason="the weirling confirmed it stopped the scan", actor=job.get("lease_owner", ""))
        scan_jobs.delete_job(client, str(job.get("job_id") or ""))
        _mark(client, asset, "pending", "scan cancelled by the operator")
        logger.info("scanner: manual scan %s cancelled at the operator's request",
                    job.get("job_id"))
        return False
    ok = record_scan_result(client, asset, result, scan_id=scan_id)
    error = ""
    if not ok:
        refreshed = scan_jobs.find_asset(client, str(job.get("ip") or ""))
        error = str((refreshed or {}).get("scan_error") or "the asset scan failed")
    scan_jobs.finish_job(client, job, ok=ok, error=error)
    logger.info("scanner: manual scan %s for %s -> %s", job.get("job_id"), job.get("ip"),
                "done" if ok else "error")
    return ok


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
        for asset in pending_assets(client, settings.scan_max_hosts):
            scan_asset(client, settings, asset)
            scanned += 1
        # The second half of the inventory: revisit hosts that were already inventoried.
        # A new listener on an existing host is a change, and without this the change ledger
        # would stay empty forever. 0 disables the rescan clock.
        rescan_s = getattr(settings, "scan_rescan_s", 0)
        if rescan_s > 0:
            for asset in rescan_assets(client, rescan_s, settings.scan_max_hosts):
                scan_asset(client, settings, asset)
                scanned += 1
    return {"hosts": len(hosts), "new": new_count, "scanned": scanned}
