"""The host system sampler: parse the kernel's numbers without inventing any."""
from __future__ import annotations

from weirvern.admin import system_metrics as sm


def test_cpu_line_sums_every_field_and_includes_iowait_as_idle() -> None:
    text = "cpu  10 2 3 20 5 0 0 0 0 0\ncpu0 10 2 3 20 5 0 0 0 0 0\n"
    assert sm.parse_cpu(text) == (40, 25)
    assert sm.parse_cpu("cpu0 1 2 3 4\n") is None


def test_meminfo_reports_used_and_percent_from_the_kernel() -> None:
    text = "MemTotal:       8192000 kB\nMemFree: 1000000 kB\nMemAvailable:   4096000 kB\n"
    mem = sm.parse_meminfo(text)
    assert mem["total_bytes"] == 8192000 * 1024
    assert mem["used_bytes"] == (8192000 - 4096000) * 1024
    assert mem["percent"] == 50.0


def test_netdev_reads_rx_and_tx_counters_per_interface() -> None:
    text = (
        "Inter-|   Receive                                                |  Transmit\n"
        " face |bytes    packets errs drop fifo frame compressed multicast|bytes    "
        "packets errs drop fifo colls carrier compressed\n"
        "    lo: 100 1 0 0 0 0 0 0 100 1 0 0 0 0 0 0\n"
        "  eth1: 900 4 1 2 0 0 0 0 700 3 0 1 0 0 0 0\n"
    )
    rows = sm.parse_netdev(text)
    assert "lo" not in rows or rows["lo"]["rx_bytes"] == 100
    assert rows["eth1"]["rx_bytes"] == 900
    assert rows["eth1"]["tx_bytes"] == 700
    assert rows["eth1"]["rx_drops"] == 2
    assert rows["eth1"]["tx_drops"] == 1


def test_a_configured_host_proc_boundary_wins_over_a_larger_kernel_view(tmp_path, monkeypatch) -> None:
    """The live confusion: the pod's /proc reports 40 GiB, the LXC/VM file mount 10 GiB.

    A configured HOST_PROC names the sensor's boundary; size is only the fallback when the
    deployment did not mount one.
    """
    (tmp_path / "meminfo").write_text(
        "MemTotal:       10485760 kB\nMemAvailable:    8388608 kB\n", encoding="utf-8")
    monkeypatch.setenv("HOST_PROC", str(tmp_path))
    assert sm.proc_root() == tmp_path
