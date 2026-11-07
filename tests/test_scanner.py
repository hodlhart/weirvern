"""The scanner's parsers and identity rules, without a network or a scanner binary."""
from weirvern import scanner
from weirvern.scanner import (
    Host,
    Service,
    choose_key,
    parse_discovery_xml,
    parse_nuclei_jsonl,
    parse_script_xml,
    parse_service_xml,
)

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
    assert hosts == [Host(ip="198.51.100.50", mac="aa:bb:cc:dd:ee:ff", hostname="printer.lan", source="nmap")]


def test_service_parser_only_keeps_open_ports():
    services = parse_service_xml(SERVICES)
    assert [s.port for s in services] == [22, 80]
    assert services[0].product == "OpenSSH"
    assert services[0].cpe == "cpe:/a:openbsd:openssh:9.6"


def test_nuclei_targets_use_services_not_guesses():
    targets = scanner.nuclei_targets("198.51.100.50", [
        Service(port=80, service="http"),
        Service(port=443, service="https"),
        Service(port=22, service="ssh"),
    ])
    assert targets == ["http://198.51.100.50", "https://198.51.100.50"]


def test_nuclei_jsonl_parses_cve_and_severity():
    line = (
        '{"template-id":"CVE-2026-1234","matched-at":"http://198.51.100.50/login",'
        '"matcher-name":"body","info":{"name":"Example RCE","severity":"critical",'
        '"classification":{"cve-id":["CVE-2026-1234"]},"remediation":"Upgrade"}}'
    )
    findings = parse_nuclei_jsonl(line)
    assert len(findings) == 1
    assert findings[0].cve == "CVE-2026-1234"
    assert findings[0].severity == "critical"
    assert findings[0].remediation == "Upgrade"


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
    _, new = scanner.record_host(new_client, Host("198.51.100.60", mac="aa:bb:cc:dd:ee:01"), {}, baseline=False)
    assert new is True
    assert new_client.inserted[-1][1][0][6] == "pending"

    baseline_client = InsertOnly()
    _, new = scanner.record_host(baseline_client, Host("198.51.100.60", mac="aa:bb:cc:dd:ee:01"), {}, baseline=True)
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
    monkeypatch.setattr(scanner, "monitored_networks", lambda _c: [scanner.ipaddress.ip_network("198.51.100.0/24")])
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


def test_nuclei_never_runs_destructive_templates():
    s = scanner.Settings(scan_nuclei_exclude_tags="dos,intrusive,fuzz,brute-force,headless,code")
    args = scanner.nuclei_arguments(s, ["http://192.0.2.10"])
    assert "-etags" in args
    tags = args[args.index("-etags") + 1]
    for forbidden in ("dos", "intrusive", "fuzz", "brute-force", "headless", "code"):
        assert forbidden in tags.split(",")
    assert "-ni" in args
    assert args[-2:] == ["-u", "http://192.0.2.10"]


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


def test_nuclei_is_opt_in_and_defaults_off():
    assert scanner.Settings().scan_nuclei_enabled is False

def test_rescan_only_returns_assets_that_are_due():
    from datetime import UTC, datetime, timedelta

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
