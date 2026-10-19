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
import threading
import time
from pathlib import Path

HISTORY_LIMIT = 288          # about 72 minutes at the console's 15-second refresh
_HISTORY: list[dict] = []
_PREV_CPU: tuple[int, int] | None = None
_PREV_NET: dict[str, dict[str, int]] = {}
_LOCK = threading.Lock()


def proc_root() -> Path:
    """The procfs with the host's CPU and memory, not a cgroup-sized one.

    A hostPath /proc mount is not a guarantee: on this k3s the mounted `/host-proc` reports
    the pod's 512 MiB memory limit, while the pod's own `/proc` reports the host's 40 GiB.
    Pick the candidate with the larger MemTotal instead of trusting the mount's name; if
    neither is readable, keep `/proc` so the caller gets a real error rather than a guess.
    """
    configured = os.environ.get("HOST_PROC", "").strip()
    candidates = ([Path(configured)] if configured else []) + [Path("/proc"), Path("/host-proc")]
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
    """MemTotal and MemAvailable in bytes; zero when the file is unreadable."""
    values: dict[str, int] = {}
    for line in text.splitlines():
        key, _, rest = line.partition(":")
        if key not in ("MemTotal", "MemAvailable"):
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
    return {"total_bytes": total, "available_bytes": available,
            "used_bytes": used, "percent": percent}


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
    """One reading, plus rates since the previous reading and a bounded history."""
    with _LOCK:
        global _PREV_CPU, _PREV_NET
        root = proc_root()
        now = time.time()
        cpu = parse_cpu(_read(root / "stat"))
        mem = parse_meminfo(_read(root / "meminfo"))
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

        elapsed = None
        if _HISTORY:
            elapsed = max(0.0, now - float(_HISTORY[-1]["t"]))
        interfaces = []
        for name, counters in sorted(net.items()):
            if name == "lo":
                continue
            before = _PREV_NET.get(name)
            rx_bps = _rate(counters["rx_bytes"], before["rx_bytes"], elapsed) if before and elapsed else 0.0
            tx_bps = _rate(counters["tx_bytes"], before["tx_bytes"], elapsed) if before and elapsed else 0.0
            interfaces.append({
                "name": name,
                "rx_bps": rx_bps, "tx_bps": tx_bps,
                "rx_packets": counters["rx_packets"], "tx_packets": counters["tx_packets"],
                "rx_drops": counters["rx_drops"], "tx_drops": counters["tx_drops"],
                "rx_errors": counters["rx_errors"], "tx_errors": counters["tx_errors"],
            })
        _PREV_NET = net

        point = {"t": round(now, 3), "cpu": cpu_percent, "memory": mem["percent"]}
        if cpu_percent is not None or mem["percent"] is not None:
            _HISTORY.append(point)
            del _HISTORY[:-HISTORY_LIMIT]

        available = cpu is not None or bool(mem["total_bytes"])
        return {
            "available": available,
            "reason": "" if available else f"no readable procfs at {root}",
            "proc_root": str(root),
            "sampled_at": point["t"],
            "cpu_percent": cpu_percent,
            "memory_percent": mem["percent"],
            "memory_used_bytes": mem["used_bytes"],
            "memory_total_bytes": mem["total_bytes"],
            "history": list(_HISTORY),
            "interfaces": interfaces,
        }
