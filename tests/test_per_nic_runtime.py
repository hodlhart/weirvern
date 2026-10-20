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


def test_a_siphon_plan_arms_without_a_second_sensor_mode_flip():
    spec = yaml.safe_load(Path("k8s/32-zeek.yaml").read_text())
    init = spec["spec"]["template"]["spec"]["initContainers"][0]
    script = "\n".join(init["args"])
    # The plan is parsed BEFORE the mode exit, and the guard allows a plan-only siphon.
    assert script.index("PLAN_IFACES=") < script.index('if [ "$MODE" != "siphon" ] && [ -z "$PLAN_IFACES" ]')
    assert 'plan asks for siphon' in script


def test_the_nic_sheet_enables_the_gate_when_a_nic_is_marked_sluice():
    js = Path("weirvern/admin/web/weirlings.js").read_text()
    assert "const anySluice = Object.values(plans).some" in js
    assert 'stageChange("sluice_enabled", "1"' in js


def test_nic_rows_use_the_plan_roles_not_the_sensor_capture_interface():
    js = Path("weirvern/admin/web/weirlings.js").read_text()
    assert "const plans = wlPlans();" in js
    assert 'const siphon = planMode === "siphon" || plan.siphon === true;' in js
    assert 'channel: (siphon && wlChannelEnabled()) ? ((r.channel && r.channel.state) || "") : "",' in js
    assert "const hasNicPlan = Object.prototype.hasOwnProperty.call(plans, name);" in js


def test_sonar_on_a_nic_stages_that_nics_plan_not_the_global_intercept_keys():
    app = Path("weirvern/admin/web/app.js").read_text()
    js = Path("weirvern/admin/web/weirlings.js").read_text()
    assert "opts.stage !== false" in app
    assert "stage: false" in js
    assert "if (typeof wlStageNicSettings === \"function\") wlStageNicSettings();" in js
    # The old global recommendation path must not be called from the NIC scan.
    start = js.index("async function wlScanNetwork()")
    rest = js[start + 10:]
    ends = [i for i in (rest.find("\nfunction "), rest.find("\nasync function ")) if i >= 0]
    scan = js[start:start + 10 + min(ends)] if ends else js[start:]
    assert "stageSonarRecommendations" not in scan


def test_a_revoked_sensor_idles_instead_of_capturing_the_management_port():
    """The revoke path clears ZEEK_IFACE/ZEEK_IFACES. The script must not then default to
    eth0: that is the management NIC, and the live log after the first revoke showed Zeek
    sniffing it and warning that it was capturing the host's own traffic as the network."""
    import yaml

    d = yaml.safe_load(Path("k8s/32-zeek.yaml").read_text())
    z = next(c for c in d["spec"]["template"]["spec"]["containers"] if c["name"] == "zeek")
    script = z["args"][0]
    assert 'IFACE="${ZEEK_IFACE:-}"' in script
    assert 'IFACE="${ZEEK_IFACE:-eth0}"' not in script
    assert script.count("no capture interface configured") == 2
    assert "while :; do sleep 3600; done" in script
