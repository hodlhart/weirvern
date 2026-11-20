"""The scanner's parsers, capability rules and install table, without a network or a binary."""
from datetime import UTC, datetime, timedelta
from pathlib import Path

from weirvern import scanner
from weirvern.scanner import (
    Host,
    choose_key,
    parse_discovery_xml,
    parse_script_xml,
    parse_service_xml,
)

ROOT = Path(__file__).resolve().parents[1]

DISCOVERY = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="198.51.100.50" addrtype="ipv4"/>
    <address addr="AA-BB-CC-DD-EE-FF" addrtype="mac" vendor="Example"/>
    <hostnames><hostname name="printer.lan" type="PTR"/></hostnames>
  </host>
  <host><status state="down"/><address addr="198.51.100.51" addrtype="ipv4"/></host>
</nmaprun>"""

SERVICES = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="9.6"><cpe>cpe:/a:openbsd:openssh:9.6</cpe></service>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.24.0"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="closed"/>
        <service name="https"/>
      </port>
    </ports>
  </host>
</nmaprun>"""


def test_discovery_keeps_up_hosts_and_mac():
    hosts = parse_discovery_xml(DISCOVERY)
    assert hosts == [Host(ip="198.51.100.50", mac="aa:bb:cc:dd:ee:ff",
                          hostname="printer.lan", source="nmap")]


def test_service_parser_only_keeps_open_ports():
    services = parse_service_xml(SERVICES)
    assert [s.port for s in services] == [22, 80]
    assert services[0].product == "OpenSSH"
    assert services[0].cpe == "cpe:/a:openbsd:openssh:9.6"


def test_same_ip_new_mac_is_a_new_asset():
    old = {"asset_key": "mac:aa:aa:aa:aa:aa:aa", "ip": "198.51.100.50", "mac": "aa:aa:aa:aa:aa:aa"}
    key, existing = choose_key(Host("198.51.100.50", mac="bb:bb:bb:bb:bb:bb"), {"old": old})
    assert existing is None
    assert key == "mac:bb:bb:bb:bb:bb:bb"


def test_passive_hosts_are_merged_with_active_identity():
    merged = scanner.merge_hosts(
        [Host("198.51.100.50", mac="aa:bb:cc:dd:ee:ff", hostname="printer.lan")],
        [Host("198.51.100.50", source="passive")],
    )
    assert len(merged) == 1
    assert merged[0].mac == "aa:bb:cc:dd:ee:ff"
    assert merged[0].hostname == "printer.lan"


class InsertOnly:
    def __init__(self):
        self.inserted = []

    def insert(self, table, rows, column_names=None):
        self.inserted.append((table, rows, column_names))


def test_new_host_is_pending_unless_this_is_the_baseline():
    new_client = InsertOnly()
    _, new = scanner.record_host(new_client, Host("198.51.100.60", mac="aa:bb:cc:dd:ee:01"), {},
                                 baseline=False)
    assert new is True
    assert new_client.inserted[-1][1][0][6] == "pending"

    baseline_client = InsertOnly()
    _, new = scanner.record_host(baseline_client, Host("198.51.100.60", mac="aa:bb:cc:dd:ee:01"),
                                 {}, baseline=True)
    assert new is True
    assert baseline_client.inserted[-1][1][0][6] == "known"


def test_run_once_discovers_then_scans_pending(monkeypatch):
    from types import SimpleNamespace

    settings = SimpleNamespace(
        scan_bootstrap=False, scan_passive_minutes=10, scan_max_hosts=8,
        scan_nmap_binary="nmap", scan_timeout_s=30,
    )
    monkeypatch.setattr(scanner, "load_registry", lambda _c: {})
    monkeypatch.setattr(scanner, "discover_with_nmap", lambda _s, _n: [Host("198.51.100.70")])
    monkeypatch.setattr(scanner, "discover_passive", lambda _c, _n, _m: [])
    monkeypatch.setattr(scanner, "monitored_networks",
                        lambda _c: [scanner.ipaddress.ip_network("198.51.100.0/24")])
    monkeypatch.setattr(scanner, "record_host", lambda _c, _h, _r, **_kw: ("ip:198.51.100.70", True))
    pending = [{"asset_key": "ip:198.51.100.70", "ip": "198.51.100.70"}]
    monkeypatch.setattr(scanner, "pending_assets", lambda _c, _n: pending)
    scanned = []
    monkeypatch.setattr(scanner, "scan_asset", lambda _c, _s, asset: scanned.append(asset["ip"]))
    result = scanner.run_once(object(), settings)
    assert result == {"hosts": 1, "new": 1, "scanned": 1}
    assert scanned == ["198.51.100.70"]


class RowsResult:
    def __init__(self, rows):
        self.result_rows = rows


class RegistryOnly:
    def __init__(self, rows):
        self.rows = rows

    def query(self, sql, parameters=None):
        return RowsResult(self.rows)


def test_scope_comes_from_enabled_weirlings_and_skips_free_text():
    client = RegistryOnly([
        ("wl-lan", "third floor IDF", "", ["198.51.100.0/24"]),
        ("wl-dmz", "203.0.113.0/24", ""),
    ])
    networks = scanner.monitored_networks(client)
    assert {str(network) for network in networks} == {"198.51.100.0/24", "203.0.113.0/24"}


def test_unusable_addresses_are_not_assets():
    network = scanner.ipaddress.ip_network("203.0.113.0/24")
    assert scanner.in_scope("203.0.113.1", [network])
    assert not scanner.in_scope("203.0.113.0", [network])
    assert not scanner.in_scope("203.0.113.255", [network])


SCRIPTS = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <ports>
      <port protocol="tcp" portid="80">
        <script id="http-title" output="Example console">
          <elem key="title">Example console</elem>
        </script>
      </port>
      <port protocol="tcp" portid="445">
        <script id="smb-os-discovery" output="Windows Server 2022">
          <table key="os">
            <elem key="name">Windows Server 2022</elem>
          </table>
        </script>
      </port>
    </ports>
    <hostscript>
      <script id="ssh-hostkey" output="2048 SHA256:abc">
        <elem key="fingerprint">SHA256:abc</elem>
      </script>
    </hostscript>
  </host>
</nmaprun>"""


def test_parse_script_xml_keeps_host_and_port_identity_facts():
    observations = parse_script_xml(SCRIPTS)
    facts = {(item.port, item.script, item.key): item.value for item in observations}
    assert facts[(80, "http-title", "title")] == "Example console"
    assert facts[(445, "smb-os-discovery", "os.name")] == "Windows Server 2022"
    assert facts[(0, "ssh-hostkey", "fingerprint")] == "SHA256:abc"
    assert all(item.script for item in observations)


def test_rescan_only_returns_assets_that_are_due():
    now = datetime.now(UTC)
    rows = [
        ("mac:old", "198.51.100.10", "", "", now, now, "done", now - timedelta(hours=2), "", "nmap"),
        ("mac:known", "198.51.100.11", "", "", now, now, "known", now - timedelta(days=30), "", "nmap"),
        ("mac:error", "198.51.100.12", "", "", now, now, "error", now - timedelta(hours=2), "timeout", "nmap"),
    ]
    assets = scanner.rescan_assets(RegistryOnly(rows), 3600, 8)
    assert [asset["asset_key"] for asset in assets] == ["mac:old", "mac:known", "mac:error"]


def test_run_once_rescans_existing_hosts(monkeypatch):
    from types import SimpleNamespace

    settings = SimpleNamespace(
        scan_bootstrap=False, scan_passive_minutes=10, scan_max_hosts=8,
        scan_nmap_binary="nmap", scan_timeout_s=30, scan_rescan_s=3600,
    )
    monkeypatch.setattr(scanner, "load_registry", lambda _c: {})
    monkeypatch.setattr(scanner, "discover_with_nmap", lambda _s, _n: [])
    monkeypatch.setattr(scanner, "discover_passive", lambda _c, _n, _m: [])
    monkeypatch.setattr(scanner, "monitored_networks", lambda _c: [])
    monkeypatch.setattr(scanner, "pending_assets", lambda _c, _n: [])
    existing = [{"asset_key": "mac:old", "ip": "198.51.100.10"}]
    monkeypatch.setattr(scanner, "rescan_assets", lambda _c, _s, _n: existing)
    scanned = []
    monkeypatch.setattr(scanner, "scan_asset", lambda _c, _s, asset: scanned.append(asset["asset_key"]))
    result = scanner.run_once(object(), settings)
    assert result["scanned"] == 1
    assert scanned == ["mac:old"]


# ── capability, scope and the install table ───────────────────────────────────────────────────

def test_nmap_version_is_shortened_without_inventing_one():
    assert scanner.nmap_short_version("Nmap version 7.95 ( https://nmap.org )") == "7.95"
    assert scanner.nmap_short_version("Nmap version 7.94SVN ( https://nmap.org )") == "7.94SVN"
    assert scanner.nmap_short_version("not a version line") == ""


def test_install_command_is_exact_per_distro_and_generic_when_unknown():
    assert scanner.nmap_install_command("ubuntu")["command"] == (
        "sudo apt-get update && sudo apt-get install -y nmap")
    assert scanner.nmap_install_command("fedora")["command"] == "sudo dnf install -y nmap"
    assert scanner.nmap_install_command("centos", "7")["command"] == "sudo yum install -y nmap"
    assert scanner.nmap_install_command("alpine")["command"] == "sudo apk add --no-cache nmap"
    assert scanner.nmap_install_command("arch")["command"] == "sudo pacman -S --noconfirm nmap"
    assert scanner.nmap_install_command("opensuse-leap")["command"] == "sudo zypper install -y nmap"
    unknown = scanner.nmap_install_command("plan9", "4")
    assert unknown["known"] is False and unknown["manager"] == ""
    assert "package manager" in unknown["command"]


def test_declared_networks_accepts_networks_segment_and_plan_segment():
    assert scanner.declared_networks(["198.51.100.0/24"], "third floor IDF", "") == [
        "198.51.100.0/24"]
    assert scanner.declared_networks([], "203.0.113.0/24", "10.0.0.0/8") == [
        "203.0.113.0/24", "10.0.0.0/8"]
    assert scanner.declared_networks(["not-a-cidr"], "", "") == []


class FleetClient:
    """Answers the two reads `fleet_capability` makes, by SQL substring."""

    def __init__(self, status_rows, weirlings):
        self.status_rows = status_rows
        self.weirlings = weirlings

    def query(self, sql, parameters=None):
        if "scanner_status" in sql:
            return RowsResult(self.status_rows)
        if "weirlings" in sql:
            return RowsResult(self.weirlings)
        return RowsResult([])


def _status(sensor, available, version="Nmap version 7.95 ( https://nmap.org )", age_s=30):
    # Exactly the columns fleet_capability selects:
    # sensor_id, profile, nmap_available, nmap_version, detail, last_check
    return (sensor, "nmap" if available else "basic", 1 if available else 0, version, "",
            datetime.now(UTC) - timedelta(seconds=age_s))


def test_capability_counts_only_fresh_registered_rows():
    client = FleetClient(
        [_status("wl-a", True), _status("wl-b", False), _status("wl-c", True, age_s=7200)],
        [("wl-a", ["198.51.100.0/24"], "", ""),
         ("wl-b", ["198.51.100.0/24"], "", ""),
         ("wl-c", ["198.51.100.0/24"], "", "")],
    )
    cap = scanner.fleet_capability(client)
    assert cap["count"] == 3
    assert cap["capable_count"] == 1
    assert [x["sensor_id"] for x in cap["capable"]] == ["wl-a"]
    assert [x["sensor_id"] for x in cap["incapable"]] == ["wl-b"]
    assert [x["sensor_id"] for x in cap["unknown"]] == ["wl-c"]
    assert "1 of 3 weirlings can scan (nmap 7.95)" in cap["sentence"]
    assert cap["enabled"] is True


def test_capability_is_scope_aware_for_one_target():
    client = FleetClient(
        [_status("wl-lan", True), _status("wl-dmz", True)],
        [("wl-lan", ["198.51.100.0/24"], "", ""),
         ("wl-dmz", ["203.0.113.0/24"], "", "")],
    )
    inside = scanner.fleet_capability(client, ip="198.51.100.10")
    assert inside["enabled"] is True
    assert [x["sensor_id"] for x in inside["eligible"]] == ["wl-lan"]
    assert [x["sensor_id"] for x in inside["out_of_scope"]] == ["wl-dmz"]

    outside = scanner.fleet_capability(client, ip="192.0.2.5")
    assert outside["enabled"] is False
    assert outside["reachable_count"] == 0
    assert "no registered weirling monitors 192.0.2.5" in outside["reason_unavailable"]


def test_a_stale_row_cannot_make_a_fleet_look_capable():
    """The exact live defect: a removed scanner's last row sat in the table for days."""
    client = FleetClient([_status("wl-a", True, age_s=3 * 86400)],
                         [("wl-a", ["198.51.100.0/24"], "", "")])
    cap = scanner.fleet_capability(client)
    assert cap["enabled"] is False
    assert cap["capable_count"] == 0
    assert "no capability report in 3d" in cap["sentence"]
    assert "Install Nmap" in cap["reason_unavailable"]


class FilteringFleetClient:
    """A fake that APPLIES the registration predicate instead of ignoring the SQL.

    `FleetClient` answers with the rows it was handed, which is right for the freshness rules
    but cannot test the WHERE clause: a disabled or revoked weirling must not be a weirling at
    all, even with a fresh, capable status row. This one asserts the predicate is in the query
    and then applies it, so the test fails if either the SQL or the counting drifts.
    """

    def __init__(self, status_rows, registrations):
        self.status_rows = status_rows
        self.registrations = registrations

    def query(self, sql, parameters=None):
        if "scanner_status" in sql:
            return RowsResult(self.status_rows)
        if "weirlings" in sql:
            assert "revoked_at IS NULL" in sql, "the registration read stopped excluding revoked rows"
            assert "enabled = 1" in sql, "the registration read stopped excluding disabled rows"
            live = [r for r in self.registrations
                    if r["enabled"] == 1 and r["revoked_at"] is None]
            return RowsResult([(r["sensor_id"], r["networks"], r.get("segment", ""),
                                r.get("plan_segment", "")) for r in live])
        return RowsResult([])


def test_capability_counts_only_enabled_unrevoked_registrations():
    """A FRESH ROW IS NOT A WEIRLING. Registration state decides who is even in the fleet."""
    retired = datetime.now(UTC) - timedelta(days=2)
    client = FilteringFleetClient(
        [_status("wl-live", True), _status("wl-disabled", True), _status("wl-revoked", True)],
        [
            {"sensor_id": "wl-live", "networks": ["198.51.100.0/24"], "enabled": 1,
             "revoked_at": None},
            {"sensor_id": "wl-disabled", "networks": ["198.51.100.0/24"], "enabled": 0,
             "revoked_at": None},
            {"sensor_id": "wl-revoked", "networks": ["198.51.100.0/24"], "enabled": 1,
             "revoked_at": retired},
        ],
    )
    cap = scanner.fleet_capability(client)
    assert cap["count"] == 1, f"a retired registration was counted: {cap['capable']}"
    assert [item["sensor_id"] for item in cap["capable"]] == ["wl-live"]
    assert cap["capable_count"] == 1
    assert "1 of 1 weirling can scan" in cap["sentence"]
    assert "wl-disabled" not in cap["sentence"] and "wl-revoked" not in cap["sentence"]


# ── "can Weirvern install it?" and the scan TYPE it can run ──────────────────────────────────

def test_scan_modes_are_distinct_and_never_overclaim():
    assert scanner.scan_mode(False, False, False) == "none"
    assert scanner.scan_mode(True, False, False) == "connect"
    assert scanner.scan_mode(True, True, False) == "raw"
    assert scanner.scan_mode(True, False, True) == "raw"
    assert "connect scan only" in scanner.scan_mode_sentence("connect")
    assert "SYN/UDP available" in scanner.scan_mode_sentence("raw")
    assert scanner.scan_mode_sentence("none") == "nmap missing"


def test_raw_mode_omits_the_unprivileged_flag(monkeypatch):
    settings = type("S", (), {"scan_nmap_binary": "nmap", "scan_ports": "1-1024"})()
    connect = scanner.service_scan_argv(settings, "198.51.100.5")
    raw = scanner.service_scan_argv(settings, "198.51.100.5", raw=True)
    assert "--unprivileged" in connect
    assert "--unprivileged" not in raw


def test_an_unprovisioned_agent_cannot_install_and_says_so(monkeypatch):
    """The honest answer on today's box: unprivileged, no scoped entry, nmap absent."""
    import shutil
    import subprocess

    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/nmap" if name == "nmap"
                        else ("/usr/bin/getcap" if name == "getcap" else None))
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: type(
        "R", (), {"stdout": "Nmap version 7.95 ( https://nmap.org )", "returncode": 0})())
    monkeypatch.setattr(scanner.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(scanner.os, "access", lambda *a, **k: False)
    capability = scanner.detect_scanner(
        type("S", (), {"scan_nmap_binary": "nmap", "sensor_name": "wl-a"})())
    assert capability["nmap_available"] is True
    assert capability["scan_mode"] == "connect"      # gets a scan, but not a SYN scan
    assert capability["privileged"] is False
    assert capability["can_install"] is False
    assert "connect scans" in capability["detail"]


def test_no_blanket_sudoers_rule_is_shipped_or_generated():
    """A sensor that can run ANY root command is a bigger risk than the install it saves."""
    offenders = []
    for pattern in ("weirvern/**/*.py", "scripts/*.sh", "k8s/**/*.yaml", "docs/*.md"):
        for path in sorted(ROOT.glob(pattern)):
            text = path.read_text(encoding="utf-8")
            if "NOPASSWD: ALL" in text or "NOPASSWD:ALL" in text:
                offenders.append(str(path.relative_to(ROOT)))
    assert not offenders, f"a blanket sudoers rule is shipped: {offenders}"
