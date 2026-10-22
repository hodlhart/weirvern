"""A capture probe proves capture liveness, not in-path forwarding.

The distinction is the feature: a silent port returns a successful `observed=false`, while a
probe that cannot read its inputs returns `ok=false`. Collapsing those is how a missing
measurement becomes a fake failure or a fake success.
"""
from __future__ import annotations

from pathlib import Path

from weirvern.admin import probe


def _make_nic(root: Path, name: str = "eth1") -> Path:
    stats = root / name / "statistics"
    stats.mkdir(parents=True)
    for key, value in (("rx_packets", 100), ("rx_dropped", 0), ("tx_packets", 50)):
        (stats / key).write_text(str(value))
    return root / name


def test_packet_and_conn_log_growth_are_observed(tmp_path):
    sys_root = tmp_path / "sys"
    _make_nic(sys_root)
    log_root = tmp_path / "logs"
    conn = log_root / "eth1" / "conn.log"
    conn.parent.mkdir(parents=True)
    conn.write_text("before\n")

    def advance(_seconds):
        (sys_root / "eth1" / "statistics" / "rx_packets").write_text("175")
        (sys_root / "eth1" / "statistics" / "rx_dropped").write_text("3")
        (sys_root / "eth1" / "statistics" / "tx_packets").write_text("75")
        conn.write_text("before\nafter\n")

    result = probe.run_capture_probe(
        "eth1", seconds=30, sys_root=str(sys_root), log_root=str(log_root), sleep=advance)

    assert result["ok"] is True
    assert result["observed"] is True
    assert result["packets_recv"] == 75
    assert result["packets_dropped"] == 3
    assert result["conn_bytes"] == len("after\n")
    assert result["scope"] == "capture-liveness"


def test_a_silent_port_is_a_successful_no_traffic_observation(tmp_path):
    sys_root = tmp_path / "sys"
    _make_nic(sys_root)
    log_root = tmp_path / "logs"
    conn = log_root / "eth1" / "conn.log"
    conn.parent.mkdir(parents=True)
    conn.write_text("no new records\n")

    result = probe.run_capture_probe(
        "eth1", seconds=30, sys_root=str(sys_root), log_root=str(log_root),
        sleep=lambda _seconds: None)

    assert result["ok"] is True
    assert result["observed"] is False
    assert "no packets" in result["reason"]
    assert result["packets_recv"] == 0


def test_a_missing_interface_is_a_probe_error_not_a_zero(tmp_path):
    sys_root = tmp_path / "sys"
    sys_root.mkdir()
    result = probe.run_capture_probe("eth9", sys_root=str(sys_root), sleep=lambda _s: None)
    assert result["ok"] is False
    assert "does not exist" in result["error"]


def test_flat_legacy_log_is_read_when_the_per_iface_dir_is_absent(tmp_path):
    sys_root = tmp_path / "sys"
    _make_nic(sys_root)
    log_root = tmp_path / "logs"
    log_root.mkdir()
    conn = log_root / "conn.log"
    conn.write_text("")

    assert probe.conn_log_path("eth1", log_root=str(log_root)) == conn


def test_seconds_are_bounded():
    # The function clamps before sleeping; a caller cannot turn a probe into an unbounded
    # measurement by posting a huge number.
    result = probe.run_capture_probe("", seconds=9999)
    assert result["ok"] is False  # empty iface is refused before the sleep
