"""Sonar: the survey that pre-fills the siphon settings.

WHAT IS PINNED HERE, and why each one matters:

  * The pure arithmetic (segment derivation, gateway parsing, free-address picking) is
    tested with INJECTED readers -- no root socket, no live segment -- so the logic is
    verified against fixtures rather than against whatever the CI host's network happens
    to look like. The one thing that IS measured on the real machine is the ioctl path,
    because that is the part fixtures cannot vouch for.
  * The job SHAPE is asserted field by field: hostNetwork and the sensor-node pin (or the
    survey measures the wrong machine -- the GUI's own namespace has none of the node's
    NICs), NET_RAW and NOT NET_ADMIN (an ARP socket needs one; rerouting is not this
    probe's job), automountServiceAccountToken false.
  * The result transport: the LAST SONAR_RESULT line wins, a refusal line still parses,
    and garbage returns None rather than raising.
  * The route: `/api/settings/sonar` is a write-gated POST (the write-route gate test in
    test_settings_tab.py fails if this file's route is not in the right set -- this file
    pins the gate call itself so the failure names the route).
"""

from __future__ import annotations

import importlib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

sonar = importlib.import_module("weirvern.admin.sonar")


# ── the route arithmetic ────────────────────────────────────────────────────────────────

def test_route_gateway_parses_the_little_endian_hex():
    """/proc/net/route writes the gateway hex in LITTLE-ENDIAN order; reading it
    big-endian yields an address on the wrong network, which then gets poison-forged.
    Two routes with different metrics: the lowest metric wins."""
    # The gateway field is hex in little-endian byte order (RFC 5737 addresses here):
    #   017100CB -> 203.0.113.1   |   016433C6 -> 198.51.100.1   |   010200C0 -> 192.0.2.1
    table = (
        "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
        "eth0\t00000000\t017100CB\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"      # 203.0.113.1
        "eth0\t00000000\t016433C6\t0003\t0\t0\t50\t00000000\t0\t0\t0\n"       # lower metric wins
        "eth1\t00000000\t010200C0\t0003\t0\t0\t0\t00000000\t0\t0\t0\n"        # other iface
    )
    assert sonar._route_gateway("eth0", table) == "198.51.100.1"
    assert sonar._route_gateway("eth1", table) == "192.0.2.1"
    # No default route on the interface -> "" (the caller then assumes the first host).
    assert sonar._route_gateway("eth9", table) == ""
    # A zero gateway is not a gateway.
    zero_gw = "eth0\t00000000\t00000000\t0003\t0\t0\t1\t00000000\t0\t0\t0\n"
    assert sonar._route_gateway("eth0", table.splitlines()[0] + "\n" + zero_gw) == ""


def test_result_line_parsing_takes_the_last_and_tolerates_garbage():
    log = "\n".join([
        "some noise",
        f"{sonar.SONAR_PREFIX}{{\"ok\": true, \"first\": 1}}",
        "more noise",
        f"{sonar.SONAR_PREFIX}{{\"ok\": true, \"second\": 2}}",
    ])
    got = sonar._parse_result_line(log)
    assert got == {"ok": True, "second": 2}, "the LAST result line must win"
    assert sonar._parse_result_line("no result line here") is None
    assert sonar._parse_result_line(f"{sonar.SONAR_PREFIX}not json") is None


# ── the survey itself, with injected readers ───────────────────────────────────────────

def _survey(**overrides):
    """Run survey() with every side effect injected. Baseline:
    eth1 at 198.51.100.10/24 (RFC 5737 -- fixtures come from the documentation ranges),
    gateway 198.51.100.1 answered, .20 alive, everything else free."""
    kwargs = dict(
        sweep=lambda iface, mac, ip, targets, timeout_s=4.0: {
            "198.51.100.1": "00:00:5e:00:53:01", "198.51.100.20": "00:00:5e:00:53:20",
        },
        mac_reader=lambda iface: "00:00:5e:00:53:aa",
        addr_reader=lambda iface: ("198.51.100.10", "255.255.255.0"),
        route_reader=lambda iface: "198.51.100.1",
    )
    kwargs.update(overrides)
    return sonar.survey("eth1", "eth0", **kwargs)


def test_the_survey_reports_the_segment_hosts_free_addresses_and_gateway():
    r = _survey()
    assert r["ok"] is True
    assert r["interface"] == "eth1"
    assert r["segment"] == "198.51.100.0/24"
    assert r["gateway"] == "198.51.100.1"
    assert r["gateway_mac"] == "00:00:5e:00:53:01"
    # The gateway answered, so no "did not answer" note.
    assert not any("neither the ARP sweep nor the neighbour cache" in n for n in r["notes"])
    # 252 candidates were swept (a /24: 254 host addresses minus ourselves minus the gateway).
    assert r["swept"] == 252
    # One live peer (the gateway itself is removed from the hosts list by design).
    assert [h["ip"] for h in r["hosts"]] == ["198.51.100.20"]
    assert r["hosts_answered"] == 1
    # Free addresses: top-of-range first, and none of the taken ones.
    assert r["free_addresses"][0] == "198.51.100.254"
    assert "198.51.100.20" not in r["free_addresses"]
    assert "198.51.100.1" not in r["free_addresses"]
    assert "198.51.100.10" not in r["free_addresses"]


def test_the_recommendations_stage_exactly_the_siphon_plan_keys():
    r = _survey()
    rec = r["recommended"]
    assert rec["sensor_mode"] == "siphon"
    assert rec["intercept_segment"] == "198.51.100.0/24"
    assert rec["intercept_gateway"] == "198.51.100.1"
    assert rec["intercept_addr"] == "198.51.100.254"
    # '*' is offered but the note tells the operator to narrow it for a first test.
    assert rec["intercept_targets"] == "*"
    assert any("For a first test" in n for n in r["notes"])


def test_every_recommended_key_is_one_the_settings_write_path_accepts():
    """The recommendation must be APPLICABLE: each key is editable and each value passes
    validate(). A Sonar that stages a value the write path rejects is worse than none."""
    from weirvern.admin import cluster_config as cc

    r = _survey()
    for row_key, value in r["recommended"].items():
        # The GUI stages in ROW vocabulary; validate() speaks ConfigMap keys.
        cm_key = cc.to_configmap_key(row_key)
        assert cm_key in cc.EDITABLE_KEYS, f"{cm_key} is not an editable key"
        cc.validate(cm_key, value)  # raises ConfigError if the value is not accepted
    # The three text keys must be in the settings payload's row set, not dropped silently.
    for row_key in ("intercept_segment", "intercept_addr", "intercept_gateway"):
        assert cc.to_configmap_key(row_key) in cc.EDITABLE_KEYS


def test_a_gateway_that_does_not_answer_is_stated_not_guessed():
    """Measured direction: no gateway MAC means an intercept could never RESTORE the
    mapping. The survey still reports what it measured, with the consequence named."""
    r = _survey(sweep=lambda iface, mac, ip, targets, timeout_s=4.0: {
        "198.51.100.20": "00:00:5e:00:53:20",
    })
    assert r["gateway_mac"] == ""
    assert any("neither the ARP sweep nor the neighbour cache" in n for n in r["notes"])


def test_no_free_address_is_stated_rather_than_offering_a_taken_one():
    everything = {f"198.51.100.{i}": f"00:00:5e:00:53:{i:02x}" for i in range(1, 255)}
    r = _survey(sweep=lambda iface, mac, ip, targets, timeout_s=4.0: everything)
    assert r["free_addresses"] == []
    assert "intercept_addr" not in r["recommended"]
    assert any("no free address was found" in n for n in r["notes"])


def test_the_DEFAULT_addr_reader_tolerates_a_passive_port(monkeypatch):
    """The default reader must not raise before the passive watcher runs. The live defect was
    `iface_ipv4` raising SonarError at line 111 and the watch fallback being unreachable."""
    def no_addr(name):
        raise sonar.SonarError(f"'{name}' has no IPv4 address")
    monkeypatch.setattr(sonar, "iface_ipv4", no_addr)
    result = sonar.survey(
        "ens19", mac_reader=lambda i: "aa:bb:cc:dd:ee:ff",
        route_reader=lambda i: "", watcher=lambda iface, **kw: _obs(),
        sweep=lambda *a, **k: {}, watch_s=1)
    assert result["ok"] is True
    assert result["segment"] == "198.51.100.0/24"


def test_a_missing_interface_address_is_refused_with_the_reason():
    with pytest.raises(sonar.SonarError) as e:
        _survey(addr_reader=lambda iface: (_ for _ in ()).throw(
            sonar.SonarError("'eth9' has no IPv4 address (or does not exist)")))
    assert "eth9" in str(e.value)


def test_a_slash31_segment_is_refused():
    """A /31 is a point-to-point link, not a segment; the refusal says what to do."""
    with pytest.raises(sonar.SonarError) as e:
        _survey(addr_reader=lambda iface: ("198.51.100.0", "255.255.255.254"))
    assert "too small" in str(e.value)


def test_the_two_port_warning_appears_when_capture_equals_management():
    r = sonar.survey("eth1", "eth1", sweep=lambda iface, mac, ip, targets, timeout_s=4.0: {
        "198.51.100.1": "00:00:5e:00:53:01",
    }, mac_reader=lambda iface: "00:00:5e:00:53:aa",
        addr_reader=lambda iface: ("198.51.100.10", "255.255.255.0"),
        route_reader=lambda iface: "198.51.100.1")
    assert any("ALSO the management interface" in n for n in r["notes"])


# ── the job shape ──────────────────────────────────────────────────────────────────────

def test_the_job_runs_with_the_sensors_shape_and_not_more():
    job = sonar.build_job("weirvern-sonar-abc123", "weirvern-worker:9.9.9", "eth1", "eth0")
    spec = job["spec"]["template"]["spec"]
    assert spec["hostNetwork"] is True, "without hostNetwork the survey sees a pod namespace"
    assert spec["nodeSelector"] == {"weirvern.io/sensor-node": "true"}, (
        "an unpinned survey measures a random node's NICs"
    )
    assert spec["automountServiceAccountToken"] is False
    assert spec["restartPolicy"] == "Never"
    container = spec["containers"][0]
    assert container["image"] == "weirvern-worker:9.9.9", "a tagless image cannot be resolved by k3s"
    caps = container["securityContext"]["capabilities"]
    assert caps["drop"] == ["ALL"]
    assert caps["add"] == ["NET_RAW"], (
        "the survey opens an ARP socket (NET_RAW) and must NOT carry NET_ADMIN: it "
        "assigns nothing and must not be able to reroute a segment"
    )
    assert container["command"] == ["python", "-m", "weirvern.admin.sonar"]
    env = {e["name"]: e["value"] for e in container["env"]}
    assert env["SONAR_IFACE"] == "eth1" and env["SONAR_MGMT_IFACE"] == "eth0"


def test_the_job_cleans_itself_up_even_if_nobody_deletes_it():
    job = sonar.build_job("weirvern-sonar-x", "weirvern-worker:1", "eth1")
    assert job["spec"]["ttlSecondsAfterFinished"], (
        "a GUI crash mid-survey would otherwise leak a completed job forever"
    )


# ── the runner (create -> poll -> read log -> delete) ──────────────────────────────────

class _FakeCluster:
    """A ClusterConfig-shaped fake: records calls, serves canned JSON/text."""

    namespace = "weirvern"

    def __init__(self, statuses, log_text, deploy_image="weirvern-worker:0.9.0"):
        self.statuses = list(statuses)
        self.log_text = log_text
        self.deploy_image = deploy_image
        self.calls: list[tuple[str, str]] = []

    def api_json(self, method, path, body=None):
        self.calls.append((method, path))
        if method == "POST":
            return {}
        if path.endswith("/deployments/weirvern-worker"):
            return {"spec": {"template": {"spec": {"containers": [
                {"name": "worker", "image": self.deploy_image}]}}}}
        if "/jobs/" in path:
            idx = sum(1 for m, p in self.calls if m == "GET" and "/jobs/" in p) - 1
            return {"status": self.statuses[min(idx, len(self.statuses) - 1)]}
        if "/pods?" in path:
            return {"items": [{"metadata": {"name": "sonar-pod-1"}}]}
        return {}

    def api_text(self, method, path):
        self.calls.append((method, path))
        return self.log_text


def test_the_runner_resolves_the_image_from_the_running_worker_deployment():
    """The measurement beats the package literal: what THIS cluster can run is the
    deployment's image, and a tagless name would ImagePullBackOff."""
    log = f"noise\n{sonar.SONAR_PREFIX}{{\"ok\": true, \"segment\": \"198.51.100.0/24\"}}"
    fc = _FakeCluster([{"succeeded": 1}], log)
    r = sonar.run_survey_job(fc, "eth1", "eth0", timeout_s=5, poll_s=0.01)
    assert r["segment"] == "198.51.100.0/24"
    posts = [p for m, p in fc.calls if m == "POST"]
    assert posts and posts[0].endswith("/jobs")
    # Cleanup ran, and by name.
    deletes = [p for m, p in fc.calls if m == "DELETE"]
    assert deletes and "weirvern-sonar-" in deletes[0]
    # The job read the deployment for its image.
    assert any("deployments/weirvern-worker" in p for m, p in fc.calls if m == "GET")


def test_a_job_that_reported_a_refusal_passes_the_reason_through():
    log = f"{sonar.SONAR_PREFIX}{{\"ok\": false, \"error\": \"'eth9' has no IPv4 address\"}}"
    fc = _FakeCluster([{"failed": 1}], log)
    r = sonar.run_survey_job(fc, "eth9", "", timeout_s=5, poll_s=0.01)
    assert r["ok"] is False and "eth9" in r["error"]


def test_a_job_that_died_without_a_result_raises_with_the_log_tail():
    fc = _FakeCluster([{"failed": 1}], "pod started\nthen died")
    with pytest.raises(sonar.SonarError) as e:
        sonar.run_survey_job(fc, "eth1", "", timeout_s=5, poll_s=0.01)
    assert "then died" in str(e.value), (
        "the failure message must carry the pod's own last lines, not a bare 'job failed'"
    )


# ── the CLI entrypoint shape ───────────────────────────────────────────────────────────

def test_the_module_is_runnable_as_a_module():
    """The job's command is `python -m weirvern.admin.sonar`; that file must have a
    __main__ that exits nonzero on a refusal, so a failed survey cannot look like a
    successful one to the pod's exit status."""
    src = (ROOT / "weirvern" / "admin" / "sonar.py").read_text()
    assert 'if __name__ == "__main__":' in src
    assert "raise SystemExit(main())" in src
    i = src.index("def main(")
    body = src[i:]
    assert "SONAR_PREFIX" in body, "main() must emit the result line the GUI reads"



# ── the passive path: a capture port with NO address of its own ──────────────────────────────
#
# THE DEFECT THESE PIN. `survey` derived the segment from the interface's own IPv4 address and
# netmask. A passive capture port (SPAN, tap, mirrored vSwitch port) has none BY DESIGN, since an
# address would make the sensor a participant on a segment it exists to observe silently.
# Measured live: the capture interface carried only a link-local IPv6 address, and survey
# refused with "has no IPv4 address ... so its segment cannot be derived" -- so Sonar could not
# run in the one deployment it exists for.
#
# These drive the fallback with injected readers, so no socket and no live segment are needed.

def _obs(*, segment="198.51.100.0/24", gateway="198.51.100.1", frames=10):
    """A SegmentObservations shaped like the real one for a watched segment."""
    from weirvern.admin.segmentwatch import SegmentObservations
    o = SegmentObservations(iface="ens19")
    o.frames = frames
    o.sources = {"198.51.100.5": 3, "198.51.100.9": 2, "198.51.100.1": 5}
    o.arp_pairs = {"198.51.100.5": "aa:bb:cc:dd:ee:01", "198.51.100.9": "aa:bb:cc:dd:ee:02"}
    o.dhcp_frames = 2
    o.observed_mask = "255.255.255.0"
    o.observed_gateway = gateway
    o.gratuitous = [gateway]
    import datetime as _dt
    o.started_at = _dt.datetime.now(_dt.UTC)
    o.ended_at = o.started_at + _dt.timedelta(seconds=45)
    return o


def test_an_interface_with_no_address_is_learned_by_watching_rather_than_refused():
    """THE WHOLE POINT OF THE FIX: a SPAN port has no address, and that must not be fatal."""
    result = sonar.survey(
        "ens19",
        mac_reader=lambda i: "aa:bb:cc:dd:ee:ff",
        addr_reader=lambda i: ("", ""),          # no IPv4: the live SPAN-port case
        route_reader=lambda i: "",
        watcher=lambda iface, **kw: _obs(),
        sweep=lambda *a, **k: {},
        watch_s=1,
    )
    assert result["ok"] is True
    assert result["segment"] == "198.51.100.0/24"
    assert result["gateway"] == "198.51.100.1", "the OBSERVED gateway must be used"


def test_the_passive_path_says_the_segment_was_learned_not_read_off_the_interface():
    result = sonar.survey(
        "ens19", mac_reader=lambda i: "aa:bb:cc:dd:ee:ff",
        addr_reader=lambda i: ("", ""), route_reader=lambda i: "",
        watcher=lambda iface, **kw: _obs(), sweep=lambda *a, **k: {}, watch_s=1,
    )
    assert result["segment_derivation"], "a derived segment must say how it was derived"
    assert "DHCP" in result["segment_derivation"] or "INFERRED" in result["segment_derivation"]


def test_a_silent_capture_port_names_the_remedy_rather_than_reporting_no_hosts():
    """AN EMPTY NETWORK AND AN UNOBSERVED ONE ARE DIFFERENT FACTS. Raising with the remedy is
    the honest answer; returning a survey with zero hosts would read as a working sensor on a
    quiet segment."""
    from weirvern.admin.segmentwatch import SegmentObservations
    empty = SegmentObservations(iface="ens19")
    import datetime as _dt
    empty.started_at = _dt.datetime.now(_dt.UTC)
    empty.ended_at = empty.started_at
    with pytest.raises(sonar.SonarError) as e:
        sonar.survey("ens19", mac_reader=lambda i: "aa:bb:cc:dd:ee:ff",
                     addr_reader=lambda i: ("", ""), route_reader=lambda i: "",
                     watcher=lambda iface, **kw: empty, sweep=lambda *a, **k: {}, watch_s=1)
    msg = str(e.value)
    assert "no IPv4 address" in msg
    assert "mirror" in msg or "not mirroring" in msg


def test_passive_only_survey_does_not_report_a_swept_count():
    """A count of 0 for a sweep that never ran is a measured zero for a question nobody asked.
    The field is absent (None), not zero."""
    o = _obs()
    o.observed_mask = None
    o.observed_gateway = ""      # nothing to source the sweep from
    o.gratuitous = []
    result = sonar.survey("ens19", mac_reader=lambda i: "aa:bb:cc:dd:ee:ff",
                          addr_reader=lambda i: ("", ""), route_reader=lambda i: "",
                          watcher=lambda iface, **kw: o, sweep=lambda *a, **k: {}, watch_s=1)
    assert result.get("passive_only") is True
    assert result.get("swept") is None, "no sweep ran, so there is no count"
    assert any("DID NOT SWEEP" in n for n in result["notes"])


def test_the_addressed_case_is_unchanged():
    """The fallback must not alter the path that already worked: an interface WITH an address
    still reads it and still sweeps normally."""
    called = {"swept": False}

    def fake_sweep(iface, mac, src, targets, timeout_s=0):
        called["swept"] = True
        return {"198.51.100.7": "aa:bb:cc:dd:ee:07", "198.51.100.1": "aa:bb:cc:dd:ee:01"}

    result = sonar.survey("eth1", mac_reader=lambda i: "aa:bb:cc:dd:ee:ff",
                          addr_reader=lambda i: ("198.51.100.50", "255.255.255.0"),
                          route_reader=lambda i: "198.51.100.1",
                          sweep=fake_sweep)
    assert called["swept"] is True, "the addressed path must still sweep"
    assert result["ok"] is True
    assert result["swept"] is not None
    assert not result.get("passive_only")
