"""The runtime halves of per-NIC support: capture processes and log discovery."""
from pathlib import Path

import yaml

from weirvern.ingester import _zeek_log_names


def test_zeek_starts_one_process_per_capture_nic_and_one_logdir_per_nic():
    spec = yaml.safe_load(Path("k8s/32-zeek.yaml").read_text())
    zeek = next(c for c in spec["spec"]["template"]["spec"]["containers"]
                if c["name"] == "zeek")
    script = "\n".join(zeek["args"])
    # The old path built one argument string with repeated -i and a single exec.
    assert "exec zeek $IFARGS" not in script
    assert 'zeek -i "$one"' in script
    assert 'LOGDIR="/zeek/logs/$one"' in script
    assert "trap 'kill $PIDS" in script


def test_the_ingester_finds_one_conn_log_per_nic_directory(tmp_path):
    for nic in ("eth1", "eth2"):
        d = tmp_path / nic
        d.mkdir()
        (d / "conn.log").write_text("#fields\tts\tuid\n")
    names = _zeek_log_names(str(tmp_path), "conn")
    assert "eth1/conn.log" in names
    assert "eth2/conn.log" in names
    # A flat deployment is unchanged.
    flat = tmp_path / "flat"
    flat.mkdir()
    (flat / "conn.log").write_text("#fields\tts\tuid\n")
    assert _zeek_log_names(str(flat), "conn") == ["conn.log"]


def test_the_siphon_init_reads_every_siphon_nic_from_the_plan():
    spec = yaml.safe_load(Path("k8s/32-zeek.yaml").read_text())
    init = spec["spec"]["template"]["spec"]["initContainers"][0]
    script = "\n".join(init["args"])
    assert "INTERCEPT_PLANS" in script
    assert "write_sysctl() {" in script
    assert "for one in $IFACES" in script
    assert 'write_sysctl "net/ipv4/conf/$one/rp_filter" 0' in script
    assert 'forwarding path ready on $one' in script


def test_the_nic_sheet_has_its_own_sluice_control():
    html = Path("weirvern/admin/web/index.html").read_text()
    js = Path("weirvern/admin/web/weirlings.js").read_text()
    assert 'id="wl-nic-sluice"' in html
    assert "sluice: !!(sluiceBox" in js
    assert "sluice.checked = !!plan.sluice" in js
