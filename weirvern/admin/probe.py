"""A bounded, read-only capture-liveness probe for a remote weirling.

WHAT IT PROVES: the named NIC exists, its kernel counters advanced during the window, and the
capture process wrote Zeek records for that NIC. WHAT IT DOES NOT PROVE: forwarding, ARP
injection, dropping or that the unit is in the path. Those are different claims and must never
be rendered as this probe's result.

No configuration, mode or sysctl is changed. The probe runs on the sensor because only that host
can read its own `/sys/class/net` and `/zeek/logs`; the hub queues the request and stores the
measured answer.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path

DEFAULT_SECONDS = 30
MIN_SECONDS = 5
MAX_SECONDS = 120
ZEEK_LOG_ROOT = "/zeek/logs"


class ProbeError(RuntimeError):
    """The probe could not run (as opposed to a valid no-traffic observation)."""


@dataclass(frozen=True)
class Counters:
    rx_packets: int
    rx_dropped: int
    tx_packets: int


def _read_int(path: Path) -> int:
    try:
        return int(path.read_text().strip())
    except (OSError, ValueError) as exc:
        raise ProbeError(f"could not read {path}: {exc}") from exc


def read_counters(iface: str, *, sys_root: str = "/sys/class/net") -> Counters:
    """Read this NIC's counters. Raises ProbeError when the interface/counter is unreadable."""
    base = Path(sys_root) / str(iface or "").strip()
    if not base.is_dir():
        names = sorted(p.name for p in Path(sys_root).glob("*")) if Path(sys_root).is_dir() else []
        raise ProbeError(
            f"{iface!r} does not exist on this host; interfaces present: "
            + (", ".join(names) or "none")
        )
    return Counters(
        rx_packets=_read_int(base / "statistics" / "rx_packets"),
        rx_dropped=_read_int(base / "statistics" / "rx_dropped"),
        tx_packets=_read_int(base / "statistics" / "tx_packets"),
    )


def conn_log_path(iface: str, *, log_root: str = ZEEK_LOG_ROOT) -> Path | None:
    """The Zeek conn.log for this NIC, if one exists.

    Trunk mode writes one log directory per VLAN interface. A flat directory is the legacy
    single-interface layout. Returning None means no Zeek log is visible, which is NOT the same
    as "zero records": the caller reports the missing path separately.
    """
    root = Path(log_root)
    for candidate in (root / str(iface or "") / "conn.log", root / "conn.log"):
        if candidate.is_file():
            return candidate
    return None


def _size(path: Path | None) -> int:
    if path is None:
        return 0
    try:
        return path.stat().st_size
    except OSError:
        return 0


def run_capture_probe(iface: str, *, seconds: int = DEFAULT_SECONDS,
                      sys_root: str = "/sys/class/net",
                      log_root: str = ZEEK_LOG_ROOT, sleep=time.sleep) -> dict:
    """Measure a capture window and return evidence. Never writes configuration.

    A no-traffic window returns `ok=True, observed=False` with a reason. A probe that cannot read
    its inputs returns `ok=False` with `error`; the two are deliberately different results.
    """
    iface = str(iface or "").strip()
    if not iface:
        return {"ok": False, "error": "a capture interface is required for this probe"}
    seconds = max(MIN_SECONDS, min(MAX_SECONDS, int(seconds or DEFAULT_SECONDS)))
    try:
        before = read_counters(iface, sys_root=sys_root)
    except ProbeError as exc:
        return {"ok": False, "error": str(exc)}
    log = conn_log_path(iface, log_root=log_root)
    log_before = _size(log)
    started = time.monotonic()
    sleep(seconds)
    elapsed = max(0.0, time.monotonic() - started)
    try:
        after = read_counters(iface, sys_root=sys_root)
    except ProbeError as exc:
        return {"ok": False, "error": str(exc)}
    log_after = _size(log)
    rx_delta = max(0, after.rx_packets - before.rx_packets)
    drop_delta = max(0, after.rx_dropped - before.rx_dropped)
    tx_delta = max(0, after.tx_packets - before.tx_packets)
    # A rotating log can shrink; report 0 growth rather than a negative number. The packet
    # counter remains the primary evidence in that case.
    log_delta = max(0, log_after - log_before)
    observed = rx_delta > 0 or log_delta > 0
    reason = ""
    if not observed:
        reason = (
            "the interface is present but no packets and no Zeek conn-log growth were seen "
            "during the window; the mirror/segment may be silent, or the capture process "
            "may not be attached to this NIC"
        )
    return {
        "ok": True,
        "observed": observed,
        "iface": iface,
        "seconds": seconds,
        "elapsed_s": round(elapsed, 1),
        "packets_recv": rx_delta,
        "packets_dropped": drop_delta,
        "packets_tx": tx_delta,
        "conn_log": str(log or ""),
        "conn_bytes": log_delta,
        "reason": reason,
        "scope": "capture-liveness",
    }
