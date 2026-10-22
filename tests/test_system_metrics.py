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


def test_meminfo_includes_swap_and_keeps_zero_swap_distinct_from_unknown() -> None:
    text = ("MemTotal: 8192000 kB\nMemAvailable: 4096000 kB\n"
            "SwapTotal: 2048000 kB\nSwapFree: 1024000 kB\n")
    mem = sm.parse_meminfo(text)
    assert mem["swap_total_bytes"] == 2048000 * 1024
    assert mem["swap_used_bytes"] == 1024000 * 1024
    assert mem["swap_percent"] == 50.0
    no_swap = sm.parse_meminfo("MemTotal: 8192000 kB\nMemAvailable: 8192000 kB\n")
    assert no_swap["swap_total_bytes"] == 0 and no_swap["swap_percent"] is None


def test_cpu_cores_load_uptime_and_task_counters_are_parsed() -> None:
    stat = ("cpu  10 2 3 20 5 0 0 0 0 0\n"
            "cpu0 10 2 3 20 5 0 0 0 0 0\n"
            "cpu1 1 2 3 4 0 0 0 0 0 0\n"
            "procs_running 4\nprocs_blocked 1\nprocesses 12345\nctxt 999\n")
    assert sm.parse_cpu_cores(stat) == {"cpu0": (40, 25), "cpu1": (10, 4)}
    assert sm.parse_loadavg("0.63 0.53 0.45 1/1139 734159") == {
        "one": 0.63, "five": 0.53, "fifteen": 0.45}
    assert sm.parse_uptime("4192.52 4192.52") == 4192.52
    assert sm.parse_stat(stat) == {"procs_running": 4, "procs_blocked": 1,
                                   "processes": 12345, "ctxt": 999}


def test_diskstats_counts_whole_disks_once() -> None:
    text = ("   8       0 sda 100 0 2048 0 50 0 4096 0 0 0 0\n"
            "   8       1 sda1 100 0 2048 0 50 0 4096 0 0 0 0\n"
            " 259       0 nvme0n1 1 0 8 0 1 0 16 0 0 0 0\n"
            "   7       0 loop0 1 0 999 0 1 0 999 0 0 0 0\n")
    disk = sm.parse_diskstats(text)
    assert disk["read_bytes"] == (2048 + 8) * sm.SECTOR_BYTES
    assert disk["write_bytes"] == (4096 + 16) * sm.SECTOR_BYTES


def test_scope_names_the_kernel_host_instead_of_calling_it_a_sensor(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("HOST_PROC", raising=False)
    scope, label, note = sm.scope_for(sm.Path("/proc"))
    assert scope == "kernel_host" and label == "kernel host"
    assert "not a per-sensor allocation" in note

    (tmp_path / "meminfo").write_text("MemTotal: 1024 kB\n", encoding="utf-8")
    monkeypatch.setenv("HOST_PROC", str(tmp_path))
    scope, label, _ = sm.scope_for(tmp_path)
    assert scope == "configured" and "configured" in label


def test_the_sample_exposes_scope_and_the_operational_metrics(tmp_path, monkeypatch) -> None:
    (tmp_path / "stat").write_text(
        "cpu  10 2 3 20 5 0 0 0 0 0\ncpu0 10 2 3 20 5 0 0 0 0 0\n"
        "procs_running 3\nprocs_blocked 1\nprocesses 99\n", encoding="utf-8")
    (tmp_path / "meminfo").write_text(
        "MemTotal: 8192000 kB\nMemAvailable: 4096000 kB\n"
        "SwapTotal: 2048000 kB\nSwapFree: 1024000 kB\n", encoding="utf-8")
    (tmp_path / "loadavg").write_text("0.50 0.40 0.30 1/99 1234\n", encoding="utf-8")
    (tmp_path / "uptime").write_text("7200.00 7200.00\n", encoding="utf-8")
    (tmp_path / "diskstats").write_text(
        "   8 0 sda 1 0 100 0 1 0 200 0 0 0 0\n", encoding="utf-8")
    monkeypatch.setattr(sm, "proc_root", lambda: tmp_path)
    monkeypatch.setattr(sm, "read_net_counters", lambda: {
        "eth0": {"rx_bytes": 100, "tx_bytes": 200, "rx_packets": 1, "tx_packets": 2,
                 "rx_drops": 0, "tx_drops": 0, "rx_errors": 0, "tx_errors": 0},
        "veth0": {"rx_bytes": 5, "tx_bytes": 6, "rx_packets": 1, "tx_packets": 1,
                  "rx_drops": 0, "tx_drops": 0, "rx_errors": 0, "tx_errors": 0},
    })
    for name in ("_HISTORY", "_PREV_CPU", "_PREV_CORES", "_PREV_NET", "_PREV_DISK"):
        if name == "_HISTORY":
            monkeypatch.setattr(sm, name, [])
        elif name in ("_PREV_CORES", "_PREV_NET"):
            monkeypatch.setattr(sm, name, {})
        else:
            monkeypatch.setattr(sm, name, None)
    d = sm.sample()
    assert d["scope"] == "custom" and d["scope_label"] == str(tmp_path)
    assert d["cpu_count"] == 1 and d["load"]["one"] == 0.5
    assert d["memory_total_bytes"] == 8192000 * 1024
    assert d["swap_used_bytes"] == 1024000 * 1024
    assert d["tasks"]["procs_running"] == 3
    assert d["network"]["rx_bytes"] == 100, "virtual interfaces must not enter the physical aggregate"
    assert d["interfaces"][0]["physical"] is True
    assert d["disk"]["read_bytes"] == 100 * sm.SECTOR_BYTES
