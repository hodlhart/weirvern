"""Adaptive 802.1Q trunk support: discover VLANs, create their subinterfaces, report the ports.

WHY THIS IS THE DEFAULT, NOT A MODE. A sensor is wired to whatever port the operator has:
an access port carries one untagged segment, a trunk carries several tagged ones. The sensor
cannot know which until it looks. Sonar already watches a port and records every 802.1Q tag
it sees; this module turns that observation into the host interfaces the capture side can
use. No tag is a statement: use the parent port (`eth1`). Tags are a statement too: use one
subinterface per tag (`eth1.10`, `eth1.20`) and leave the parent out.

THE INTERFACES ARE REAL, NOT A VIEW. `ip link add link eth1 name eth1.10 type vlan id 10`
creates a VLAN device in the host network namespace. Kernel VLAN devices strip the tag on
receive and add it on transmit, so the tools downstream (`zeek`, `siphonnet`, `sonar`) keep
seeing ordinary Ethernet frames while each VLAN keeps its own segment, address, gateway and
policy table. A container with host networking sees the same devices.

CAPABILITY. Creating a VLAN device and bringing it up needs `NET_ADMIN`; passive observation
needs `NET_RAW`. A caller that has neither gets a reason, not a silent fallback. If creation
fails the caller may still capture the parent -- but that is a degraded result and is recorded
as such, never presented as trunk support.

THE STATE FILE IS PART OF THE CONTRACT. `/state/trunk.json` records which parent, which tags
and which interfaces this manager last made. `/state/ifaces` is the newline list the capture
shell reads. The list is written atomically, so a capture process never reads half a name.
Only interfaces this manager previously created are removed when a later probe sees no tags;
an operator's hand-made VLAN device is not ours to delete.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

DEFAULT_WATCH_S = 12.0
MAX_VLANS = 64
STATE_JSON = "trunk.json"
STATE_IFACES = "ifaces"


class TrunkError(RuntimeError):
    """The trunk state could not be established. Message names the reason."""


@dataclass
class TrunkState:
    parent: str
    vlans: list[int] = field(default_factory=list)
    ifaces: list[str] = field(default_factory=list)
    managed: list[str] = field(default_factory=list)
    error: str = ""
    detected_at: str = ""

    @property
    def trunk(self) -> bool:
        return bool(self.vlans)

    def as_dict(self) -> dict:
        return {
            "parent": self.parent,
            "vlans": list(self.vlans),
            "ifaces": list(self.ifaces),
            "managed": list(self.managed),
            "error": self.error,
            "detected_at": self.detected_at,
        }


def vlan_iface(parent: str, vid: int) -> str:
    """`parent.<vid>`, with the kernel's name and VLAN-id bounds enforced."""
    name = f"{str(parent).strip()}.{int(vid)}"
    if not str(parent).strip():
        raise TrunkError("a trunk parent interface name is required")
    if int(vid) < 1 or int(vid) > 4094:
        raise TrunkError(f"VLAN id {vid} is outside 1..4094")
    if len(name.encode()) > 15:
        raise TrunkError(
            f"'{name}' is {len(name.encode())} bytes; a Linux interface name is limited to 15. "
            f"Use a shorter parent name."
        )
    return name


def _run_ip(args: list[str], *, runner=None) -> tuple[int, str]:
    if runner is not None:
        return runner(args)
    try:
        proc = subprocess.run(["ip", *args], capture_output=True, text=True, timeout=8,
                              check=False)
        return proc.returncode, (proc.stdout or proc.stderr or "").strip()
    except (OSError, subprocess.SubprocessError) as exc:
        return 127, str(exc)


def _exists(iface: str) -> bool:
    return Path("/sys/class/net", iface).exists()


def _iface_mac(iface: str) -> str:
    """The parent's MAC, or '' when it cannot be read. Never a reason to fail the probe."""
    try:
        return Path("/sys/class/net", iface, "address").read_text().strip().lower()
    except OSError:
        return ""


def _read_state(state_dir: Path) -> dict:
    try:
        data = json.loads((state_dir / STATE_JSON).read_text())
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _write_state(state_dir: Path, state: TrunkState) -> None:
    """Write the JSON and the shell list atomically, list last.

    The list is the file the capture process reads; writing it after the JSON means a reader
    never sees a list that disagrees with the recorded parent/tags.
    """
    state_dir.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(state.as_dict(), indent=2, sort_keys=True) + "\n"
    for name, text in ((STATE_JSON, payload),
                       (STATE_IFACES, "".join(f"{i}\n" for i in state.ifaces))):
        tmp = state_dir / f".{name}.tmp.{os.getpid()}"
        tmp.write_text(text)
        os.replace(tmp, state_dir / name)
    try:
        (state_dir / STATE_JSON).chmod(0o644)
        (state_dir / STATE_IFACES).chmod(0o644)
    except OSError:
        pass


def _remove_managed(parent: str, managed: list[str], keep: set[str], *, runner=None) -> list[str]:
    """Delete only previously-managed interfaces for THIS parent that are no longer wanted."""
    removed: list[str] = []
    prefix = f"{parent}."
    for name in managed:
        if name in keep or not name.startswith(prefix):
            continue
        rc, out = _run_ip(["link", "del", name], runner=runner)
        if rc == 0 or not _exists(name):
            removed.append(name)
        else:
            logger.warning("trunk: could not remove %s: %s", name, out[:200])
    return removed


def sync(parent: str, *, seconds: float = DEFAULT_WATCH_S, state_dir: str = "/run/weirvern/trunk",
         watcher=None, runner=None, dry_run: bool = False) -> TrunkState:
    """Observe `parent`, create/remove VLAN devices, write state. Default behavior.

    `watcher` is `segmentwatch.observe_segment` by default and is injectable for tests. It is
    READ-ONLY; this function is the only part that changes the host.
    """
    parent = str(parent or "").strip()
    if not parent:
        raise TrunkError("a parent interface is required")
    if _exists(parent) is False and watcher is None:
        raise TrunkError(f"trunk parent '{parent}' does not exist on this host")

    if watcher is None:
        from weirvern.admin import segmentwatch  # noqa: PLC0415

        watcher = segmentwatch.observe_segment
        # Ignore the parent's own MAC. The VLAN devices this manager creates inherit it, and
        # their IPv6 neighbour discovery is emitted tagged on the parent; counting it would
        # make a trunk impossible to fall back to an access port.
        own_mac = _iface_mac(parent)
    else:
        own_mac = ""
    try:
        if own_mac:
            obs = watcher(parent, seconds=float(seconds), ignore_source_mac=own_mac)
        else:
            obs = watcher(parent, seconds=float(seconds))
    except Exception as exc:  # noqa: BLE001 -- an observation refusal is a state, not a crash
        # A sensor whose port is quiet can still capture the parent. Record WHY it is not a
        # trunk rather than failing the capture start; the operator sees the reason in state.
        previous = _read_state(Path(state_dir))
        state = TrunkState(parent=parent, ifaces=[parent], managed=list(previous.get("managed") or []),
                           error=f"VLAN observation failed: {exc}", detected_at=_now())
        if not dry_run:
            _write_state(Path(state_dir), state)
        return state

    vlans = sorted({int(v) for v in (getattr(obs, "vlans", set()) or set())
                    if 1 <= int(v) <= 4094})[:MAX_VLANS]
    previous = _read_state(Path(state_dir))
    managed = [str(v) for v in (previous.get("managed") or []) if str(v)]
    wanted = [vlan_iface(parent, v) for v in vlans] if vlans else [parent]
    state = TrunkState(parent=parent, vlans=vlans, ifaces=wanted,
                       managed=managed, detected_at=_now())

    if dry_run:
        return state

    # Remove old managed VLAN devices first, but only those this parent owned and that are
    # not in the new wanted set. If there are still VLANs, keep the parent itself out of the
    # capture list (the tag is stripped by the VLAN device, not by the parent).
    _remove_managed(parent, managed, set(wanted), runner=runner)

    newly_created: list[str] = []
    if vlans:
        for vid, name in zip(vlans, wanted, strict=False):
            if _exists(name):
                _run_ip(["link", "set", name, "up"], runner=runner)
                continue
            rc, out = _run_ip(["link", "add", "link", parent, "name", name,
                               "type", "vlan", "id", str(vid)], runner=runner)
            if rc != 0:
                state.error = (f"could not create {name}: {out[:240] or 'ip link failed'}. "
                               f"The capture can fall back to {parent}, but per-VLAN capture "
                               f"needs NET_ADMIN in the trunk detector.")
                logger.warning("trunk: %s", state.error)
                # Fall back to the parent ONLY as an explicit degraded state.
                state.ifaces = [parent]
                state.managed = managed
                _write_state(Path(state_dir), state)
                return state
            _run_ip(["link", "set", name, "up"], runner=runner)
            newly_created.append(name)

    state.ifaces = wanted
    # Only devices this manager actually built or already owned are ours to remove later. An
    # operator-made VLAN device is not adopted into the managed set just because its name
    # matches the pattern.
    state.managed = sorted((set(wanted) & set(managed)) | set(newly_created))
    _write_state(Path(state_dir), state)
    return state


def _now() -> str:
    from datetime import UTC, datetime  # noqa: PLC0415

    return datetime.now(UTC).isoformat()


def _state_path(state: str) -> str:
    """Accept either the state DIRECTORY or a path ending in trunk.json."""
    p = Path(state)
    return str(p.parent if p.name == STATE_JSON else p)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="adaptive 802.1Q trunk interface manager")
    sub = ap.add_subparsers(dest="command", required=True)
    p = sub.add_parser("detect", help="observe the parent and create/remove VLAN interfaces")
    p.add_argument("--parent", required=True)
    p.add_argument("--state", default="/run/weirvern/trunk")
    p.add_argument("--seconds", type=float, default=float(os.environ.get("TRUNK_DETECT_S", DEFAULT_WATCH_S)))
    p.add_argument("--dry-run", action="store_true")
    a = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    try:
        state = sync(a.parent, seconds=a.seconds, state_dir=_state_path(a.state),
                     dry_run=a.dry_run)
    except TrunkError as exc:
        print(f"trunk: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(state.as_dict(), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
