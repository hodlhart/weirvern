"""Read the sensor host's CPU, memory, and interface counters.

The GUI normally runs in its own namespace, where `/proc` describes a container, not the
box the operator calls the sensor. Kubernetes mounts the host's procfs read-only at
`/host-proc` (see k8s/34-gui.yaml); this module reads that path when it exists and falls
back to `/proc` for a developer running the console directly on the host.

The history is deliberately in-process and small. It is a reading surface: a console
restart starts a new trend window, never inventing points from before it was watching.
"""
from __future__ import annotations

import os
import re
import threading
import time
from pathlib import Path

HISTORY_LIMIT = 288          # about 72 minutes at the console's 15-second refresh
_HISTORY: list[dict] = []
_PREV_CPU: tuple[int, int] | None = None
_PREV_CORES: dict[str, tuple[int, int]] = {}
_PREV_NET: dict[str, dict[str, int]] = {}
_PREV_DISK: tuple[int, int] | None = None
_LOCK = threading.Lock()

SECTOR_BYTES = 512
_WHOLE_DISK_RE = re.compile(
    r"^(?:sd[a-z]+|vd[a-z]+|xvd[a-z]+|hd[a-z]+|nvme\d+n\d+|mmcblk\d+|dm-\d+|md\d+|zd\d+|nbd\d+)$"
)


def proc_root() -> Path:
    """The procfs with the host's CPU and memory, not a cgroup-sized one.

    A hostPath /proc mount is not a guarantee: on this k3s the mounted `/host-proc` reports
    the pod's 512 MiB memory limit, while the pod's own `/proc` reports the host's 40 GiB.
    Pick the candidate with the larger MemTotal instead of trusting the mount's name; if
    neither is readable, keep `/proc` so the caller gets a real error rather than a guess.
    """
    configured = os.environ.get("HOST_PROC", "").strip()
    if configured:
        # A CONFIGURED BOUNDARY IS AUTHORITATIVE. The file-mounted host procfs in the GUI
        # reports the LXC/VM's 10 GiB; the pod's own /proc reports the 40 GiB kernel view.
        # Picking the larger MemTotal therefore selected the wrong machine. The deployment
        # sets HOST_PROC to the file-mounted boundary; only fall back to size if it is not
        # readable.
        candidate = Path(configured)
        try:
            text = (candidate / "meminfo").read_text(encoding="utf-8", errors="replace")
        except OSError:
            text = ""
        if "MemTotal:" in text:
            return candidate
    candidates = [Path("/proc"), Path("/host-proc")]
    best: tuple[int, Path] = (-1, Path("/proc"))
    for candidate in candidates:
        try:
            text = (candidate / "meminfo").read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for line in text.splitlines():
            if line.startswith("MemTotal:"):
                try:
                    total = int(line.split()[1])
                except (IndexError, ValueError):
                    total = 0
                if total > best[0]:
                    best = (total, candidate)
                break
    return best[1]


def scope_for(root: Path) -> tuple[str, str, str]:
    """(scope, label, note) for a procfs root. The label is part of the measurement.

    The GUI runs in a container. Its `/proc` is the kernel's view, which is not the sensor
    LXC/VM's memory boundary; `/host-proc` is an lxcfs view of the GUI pod's cgroup, not that
    boundary either. We report the kernel host honestly instead of renaming 40 GiB "sensor".
    A deployment that mounts a true boundary sets HOST_PROC, and that is named as configured.
    """
    configured = os.environ.get("HOST_PROC", "").strip()
    if configured and root == Path(configured):
        return ("configured",
                "configured procfs boundary",
                "HOST_PROC names this boundary; it is not inferred from a larger MemTotal.")
    if str(root) == "/proc":
        return ("kernel_host",
                "kernel host",
                "kernel-wide CPU and memory. This container cannot see the sensor LXC/VM "
                "boundary; the total is the kernel's, not a per-sensor allocation.")
    if str(root) == "/host-proc":
        return ("container",
                "container cgroup (lxcfs)",
                "the lxcfs view of this container's cgroup, not the kernel host or a sensor VM.")
    return ("custom", str(root), "a configured procfs path.")


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def parse_cpu(text: str) -> tuple[int, int] | None:
    """Return (total jiffies, idle jiffies) from the aggregate `cpu` line."""
    for line in text.splitlines():
        if not line.startswith("cpu "):
            continue
        fields = line.split()[1:]
        try:
            values = [int(v) for v in fields]
        except ValueError:
            return None
        if len(values) < 4:
            return None
        total = sum(values)
        idle = values[3] + (values[4] if len(values) > 4 else 0)  # idle + iowait
        return total, idle
    return None


def parse_meminfo(text: str) -> dict[str, int | float | None]:
    """Memory and swap facts in bytes; zero when the file is unreadable.

    `MemAvailable` is the kernel's own estimate of what can be allocated without swapping.
    A missing value is NOT zero: a reading without it still has a total, and the caller must
    say "not measured" rather than "no memory available".
    """
    values: dict[str, int] = {}
    for line in text.splitlines():
        key, _, rest = line.partition(":")
        if key not in ("MemTotal", "MemAvailable", "SwapTotal", "SwapFree"):
            continue
        parts = rest.split()
        if not parts:
            continue
        try:
            values[key] = int(parts[0]) * 1024
        except ValueError:
            continue
    total = values.get("MemTotal", 0)
    available = values.get("MemAvailable", 0)
    used = max(0, total - available)
    percent = round((used / total) * 100, 1) if total else None
    swap_total = values.get("SwapTotal", 0)
    swap_free = values.get("SwapFree", 0)
    swap_used = max(0, swap_total - swap_free)
    swap_percent = round((swap_used / swap_total) * 100, 1) if swap_total else None
    return {"total_bytes": total, "available_bytes": available,
            "used_bytes": used, "percent": percent,
            "swap_total_bytes": swap_total, "swap_used_bytes": swap_used,
            "swap_percent": swap_percent}


def parse_cpu_cores(text: str) -> dict[str, tuple[int, int]]:
    """Per-core (total jiffies, idle jiffies) from `cpu0`, `cpu1`, ... lines."""
    out: dict[str, tuple[int, int]] = {}
    for line in text.splitlines():
        name, _, rest = line.partition(" ")
        if not name.startswith("cpu") or name == "cpu":
            continue
        try:
            values = [int(v) for v in rest.split()]
        except ValueError:
            continue
        if len(values) < 4:
            continue
        out[name] = (sum(values), values[3] + (values[4] if len(values) > 4 else 0))
    return out


def parse_loadavg(text: str) -> dict[str, float]:
    """The three load averages, or empty when the line is absent."""
    parts = text.split()
    if len(parts) < 3:
        return {}
    try:
        one, five, fifteen = (float(v) for v in parts[:3])
    except ValueError:
        return {}
    return {"one": one, "five": five, "fifteen": fifteen}


def parse_uptime(text: str) -> float | None:
    """Seconds since boot from /proc/uptime, or None when unreadable."""
    try:
        return float(text.split()[0])
    except (IndexError, ValueError):
        return None


def parse_stat(text: str) -> dict[str, int]:
    """The kernel's task counters that make a load average actionable."""
    wanted = ("procs_running", "procs_blocked", "processes", "ctxt")
    out: dict[str, int] = {}
    for line in text.splitlines():
        key, _, rest = line.partition(" ")
        if key not in wanted:
            continue
        try:
            out[key] = int(rest.strip())
        except ValueError:
            continue
    return out


def parse_diskstats(text: str) -> dict[str, int]:
    """Whole-disk read/write sectors from /proc/diskstats.

    Partitions are deliberately excluded. On this host `sda` and `sda1` both report the same
    I/O, so summing every line would double-count the only disk. The regex is a whitelist:
    a device shape this module does not know is omitted rather than guessed at.
    """
    read_sectors = write_sectors = 0
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 10:
            continue
        name = fields[2]
        if not _WHOLE_DISK_RE.match(name):
            continue
        try:
            read_sectors += int(fields[5])
            write_sectors += int(fields[9])
        except ValueError:
            continue
    return {"read_bytes": read_sectors * SECTOR_BYTES,
            "write_bytes": write_sectors * SECTOR_BYTES}


def is_physical_iface(name: str) -> bool:
    """Whether an interface is a real NIC, not a container/virtual fabric device."""
    if not name or name == "lo":
        return False
    virtual = ("veth", "docker", "flannel", "cni", "br-", "virbr", "tun", "tap",
               "tailscale", "wg", "vxlan", "dummy", "sit", "ip6tnl")
    return not name.startswith(virtual)


def parse_netdev(text: str) -> dict[str, dict[str, int]]:
    """The kernel's per-interface counters, keyed by interface name."""
    out: dict[str, dict[str, int]] = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        name, _, rest = line.partition(":")
        name = name.strip()
        if not name or name == "Inter-|   Receive":
            continue
        fields = rest.split()
        if len(fields) < 16:
            continue
        try:
            nums = [int(v) for v in fields[:16]]
        except ValueError:
            continue
        out[name] = {
            "rx_bytes": nums[0], "rx_packets": nums[1],
            "rx_errors": nums[2], "rx_drops": nums[3],
            "tx_bytes": nums[8], "tx_packets": nums[9],
            "tx_errors": nums[10], "tx_drops": nums[11],
        }
    return out


def read_net_counters() -> dict[str, dict[str, int]]:
    """Interface counters from the host's sysfs, falling back to this procfs' netdev.

    `/proc/net/dev` is network-namespace scoped even when procfs is the host's: a mount
    changes the filesystem, not the namespace. `/sys/class/net` is the host's interface
    list, so the counters are read there when the GUI has the read-only mount.
    """
    configured = os.environ.get("HOST_SYS", "").strip()
    base = Path(configured) if configured else Path("/host-sys")
    class_net = base / "class" / "net"
    if class_net.is_dir():
        out: dict[str, dict[str, int]] = {}
        for iface in sorted(class_net.iterdir()):
            stats = iface / "statistics"
            if not stats.is_dir():
                continue

            def one(name: str, stats: Path = stats) -> int:
                try:
                    return int((stats / name).read_text().strip())
                except (OSError, ValueError):
                    return 0

            out[iface.name] = {
                "rx_bytes": one("rx_bytes"), "rx_packets": one("rx_packets"),
                "rx_errors": one("rx_errors"), "rx_drops": one("rx_dropped"),
                "tx_bytes": one("tx_bytes"), "tx_packets": one("tx_packets"),
                "tx_errors": one("tx_errors"), "tx_drops": one("tx_dropped"),
            }
        if out:
            return out
    return parse_netdev(_read(proc_root() / "net" / "dev"))


def _rate(now: int, before: int, elapsed: float) -> float:
    if elapsed <= 0:
        return 0.0
    return round(max(0, now - before) / elapsed, 1)


def sample() -> dict:
    """One reading, plus rates since the previous reading and a bounded history.

    Every field names what it measures. Memory total comes from the procfs root chosen by
    `proc_root`; `scope` says whether that is the kernel host or a configured boundary.
    """
    with _LOCK:
        global _PREV_CPU, _PREV_CORES, _PREV_NET, _PREV_DISK
        root = proc_root()
        now = time.time()
        stat_text = _read(root / "stat")
        cpu = parse_cpu(stat_text)
        cores = parse_cpu_cores(stat_text)
        mem = parse_meminfo(_read(root / "meminfo"))
        load = parse_loadavg(_read(root / "loadavg"))
        uptime_s = parse_uptime(_read(root / "uptime"))
        tasks = parse_stat(stat_text)
        disk = parse_diskstats(_read(root / "diskstats"))
        net = read_net_counters()

        cpu_percent = None
        if cpu is not None and _PREV_CPU is not None:
            total_delta = cpu[0] - _PREV_CPU[0]
            idle_delta = cpu[1] - _PREV_CPU[1]
            if total_delta > 0:
                cpu_percent = round(max(0.0, min(100.0,
                                    (1.0 - idle_delta / total_delta) * 100.0)), 1)
        if cpu is not None:
            _PREV_CPU = cpu

        per_core = []
        for name, (total, idle) in sorted(cores.items()):
            previous = _PREV_CORES.get(name)
            percent = None
            if previous is not None and total > previous[0]:
                percent = round(max(0.0, min(100.0,
                                     (1.0 - (idle - previous[1]) / (total - previous[0])) * 100.0)), 1)
            per_core.append({"name": name, "percent": percent})
        if cores:
            _PREV_CORES = cores

        elapsed = None
        if _HISTORY:
            elapsed = max(0.0, now - float(_HISTORY[-1]["t"]))
        interfaces = []
        previous_net = _PREV_NET
        physical_rx = physical_tx = 0
        physical_rx_drops = physical_tx_drops = physical_rx_errors = physical_tx_errors = 0
        for name, counters in sorted(net.items()):
            if name == "lo":
                continue
            before = previous_net.get(name)
            rx_bps = _rate(counters["rx_bytes"], before["rx_bytes"], elapsed) if before and elapsed else 0.0
            tx_bps = _rate(counters["tx_bytes"], before["tx_bytes"], elapsed) if before and elapsed else 0.0
            physical = is_physical_iface(name)
            if physical:
                physical_rx += counters["rx_bytes"]
                physical_tx += counters["tx_bytes"]
                physical_rx_drops += counters["rx_drops"]
                physical_tx_drops += counters["tx_drops"]
                physical_rx_errors += counters["rx_errors"]
                physical_tx_errors += counters["tx_errors"]
            interfaces.append({
                "name": name,
                "physical": physical,
                "rx_bps": rx_bps, "tx_bps": tx_bps,
                "rx_packets": counters["rx_packets"], "tx_packets": counters["tx_packets"],
                "rx_drops": counters["rx_drops"], "tx_drops": counters["tx_drops"],
                "rx_errors": counters["rx_errors"], "tx_errors": counters["tx_errors"],
            })
        _PREV_NET = net

        # THE AGGREGATE IS COMPUTED FROM THE SAME COUNTERS, not by summing per-interface rates
        # that may have been measured against different elapsed windows. A first sample has no
        # predecessor, so its rates are 0.0; the caller can see `history.length` to know why.
        prev_rx = sum(c["rx_bytes"] for n, c in previous_net.items() if is_physical_iface(n))
        prev_tx = sum(c["tx_bytes"] for n, c in previous_net.items() if is_physical_iface(n))
        physical_rx_bps = _rate(physical_rx, prev_rx, elapsed) if previous_net and elapsed else 0.0
        physical_tx_bps = _rate(physical_tx, prev_tx, elapsed) if previous_net and elapsed else 0.0
        disk_read_bps = disk_write_bps = None
        previous_disk = _PREV_DISK
        if previous_disk is not None and elapsed:
            disk_read_bps = _rate(disk["read_bytes"], previous_disk[0], elapsed)
            disk_write_bps = _rate(disk["write_bytes"], previous_disk[1], elapsed)
        _PREV_DISK = (disk["read_bytes"], disk["write_bytes"])

        point = {"t": round(now, 3), "cpu": cpu_percent, "memory": mem["percent"]}
        if cpu_percent is not None or mem["percent"] is not None:
            _HISTORY.append(point)
            del _HISTORY[:-HISTORY_LIMIT]

        scope, scope_label, scope_note = scope_for(root)
        load_per_core = None
        if load and cores:
            load_per_core = round(load["one"] / len(cores), 2)
        available = cpu is not None or bool(mem["total_bytes"])
        return {
            "available": available,
            "reason": "" if available else f"no readable procfs at {root}",
            "proc_root": str(root),
            "scope": scope,
            "scope_label": scope_label,
            "scope_note": scope_note,
            "sampled_at": point["t"],
            "cpu_percent": cpu_percent,
            "cpu_count": len(cores),
            "load": {**load, "per_core": load_per_core} if load else {},
            "per_core": per_core,
            "memory_percent": mem["percent"],
            "memory_used_bytes": mem["used_bytes"],
            "memory_total_bytes": mem["total_bytes"],
            "memory_available_bytes": mem["available_bytes"],
            "swap_total_bytes": mem["swap_total_bytes"],
            "swap_used_bytes": mem["swap_used_bytes"],
            "swap_percent": mem["swap_percent"],
            "uptime_s": uptime_s,
            "tasks": tasks,
            "network": {
                "rx_bps": physical_rx_bps, "tx_bps": physical_tx_bps,
                "rx_bytes": physical_rx, "tx_bytes": physical_tx,
                "rx_drops": physical_rx_drops, "tx_drops": physical_tx_drops,
                "rx_errors": physical_rx_errors, "tx_errors": physical_tx_errors,
            },
            "disk": {"read_bytes": disk["read_bytes"], "write_bytes": disk["write_bytes"],
                     "read_bps": disk_read_bps, "write_bps": disk_write_bps},
            "history": list(_HISTORY),
            "interfaces": interfaces,
        }
