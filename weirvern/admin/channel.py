"""Channel: a weirling wired IN LINE -- an upstream port and a downstream port, one bridge.

WHAT A CHANNEL IS. `siphon` puts this host into the traffic path by ARP forging: effective, and
the most consequential thing this appliance can do. A CHANNEL puts it there PHYSICALLY -- one
port cabled toward the network (upstream), one toward the protected device or segment
(downstream), both enslaved to a single Linux bridge, so traffic between them passes THROUGH
this host. The gate's forward-hook rules then discard real traffic instead of counting drops on
packets that were never going to traverse a listener -- and the sensor stays in `loch` (passive
capture): nothing is forged and nothing is redirected.

WHAT THIS MODULE IS FOR. "Is the channel active" must never be inferred from a ConfigMap that
says somebody intended one. Every condition below is read from the KERNEL, and each failure
names itself:

  * both ports declared, present, and up WITH CARRIER -- a channel with a pulled cable looks
    exactly as healthy as a working one from inside the kernel's state tables;
  * both enslaved to the SAME bridge. Two bridges in line is a spanning-tree problem, not a
    channel;
  * each port's bridge state is FORWARDING (STP convergence shows as listening/learning, which
    is honestly not-yet-in-path);
  * `net.bridge.bridge-nf-call-iptables` (and the ip6tables twin) read "1". WITHOUT bridge-nf a
    bridged packet never reaches the inet `forward` hook where the gate's rules live: the rules
    would install, count nothing, and the panel would read ARMED. That is the measured trap
    this module exists to prevent -- the CLI has warned about this sysctl since the k3s
    bring-up; this is the gate finally acting on it.

WHAT IS DELIBERATELY NOT CHECKED: whether traffic is FLOWING. A wired, configured, quiet
channel is a working channel; demanding counters would degrade a healthy gate on a segment
that has nothing to say, and flow is observable elsewhere (the capture).

Reads sysfs and /proc/sys directly, with both roots injectable, so the entire table of checks
is testable against a fabricated tree -- the same pattern `interfaces.probe_local` uses for the
same reason.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

SYSFS_NET = "/sys/class/net"
PROC_SYS = "/proc/sys"

# The sysctls bridge-nf needs so bridged traffic reaches the inet hooks the gate writes to.
# BOTH families, because the gate compiles v4 AND v6 rules and a half-covered channel would
# block one family while silently passing the other.
BRIDGE_NF_SYSCTLS: tuple[tuple[str, str], ...] = (
    ("net/bridge/bridge-nf-call-iptables", "IPv4"),
    ("net/bridge/bridge-nf-call-ip6tables", "IPv6"),
)

# /sys/class/net/<port>/brport/state: the value that means "passing frames now".
BRIDGE_PORT_FORWARDING = 3


@dataclass
class ChannelState:
    """What the channel check found. `active` is the only field a verdict may key on."""

    declared: bool = False
    active: bool = False
    upstream: str = ""
    downstream: str = ""
    bridge: str = ""
    ports: list[str] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)

    @property
    def detail(self) -> str:
        """One sentence for the gate's state row and the panel."""
        if not self.declared:
            return "no channel is configured (CHANNEL_UPSTREAM / CHANNEL_DOWNSTREAM are empty)"
        if self.active:
            return (
                f"channel active: {self.upstream} <-> {self.downstream} bridged on "
                f"{self.bridge}; traffic between the ports traverses this host, so the gate's "
                f"rules apply to real traffic"
            )
        if self.problems:
            return "channel declared but NOT active: " + "; ".join(self.problems)
        return "channel declared but NOT active"


def _read(path: Path) -> str:
    try:
        return path.read_text().strip()
    except OSError:
        return ""


def _master_of(sysfs: Path, iface: str) -> str:
    """The bridge `iface` is enslaved to, or "" when it is not a bridge port."""
    try:
        target = os.readlink(sysfs / iface / "master")
    except OSError:
        return ""
    return os.path.basename(target.rstrip("/"))


def _int_file(path: Path) -> int | None:
    try:
        return int(_read(path))
    except ValueError:
        return None


def detect(upstream: str, downstream: str, *, sysfs: str | Path = SYSFS_NET,
           proc_sys: str | Path = PROC_SYS) -> ChannelState:
    """Whether the declared channel is REAL, as read from the kernel. Never raises."""
    up = (upstream or "").strip()
    down = (downstream or "").strip()
    state = ChannelState(declared=bool(up and down), upstream=up, downstream=down)
    if not state.declared:
        # Not a problem to shout about: most deployments have no channel and the gate says so
        # in one calm sentence (see `detail`). A blank row must not read as a broken one.
        return state
    if up == down:
        state.problems.append(f"upstream and downstream are the same port ({up})")
        return state

    root = Path(sysfs)
    for role, name in (("upstream", up), ("downstream", down)):
        if not (root / name).is_dir():
            state.problems.append(f"the {role} port '{name}' does not exist on this host")
    if state.problems:
        return state
    state.ports = [up, down]

    masters = {name: _master_of(root, name) for name in (up, down)}
    for name, master in masters.items():
        if not master:
            state.problems.append(
                f"'{name}' is not enslaved to a bridge -- a channel needs both ports joined "
                f"into one bridge (ip link set {name} master <bridge>)"
            )
    if len(set(masters.values())) != 1:
        if all(masters.values()):
            state.problems.append(
                "the ports are on different bridges ("
                + ", ".join(f"{n}: {m}" for n, m in sorted(masters.items()))
                + ") -- one channel is one bridge"
            )
        return state
    bridge = next(iter(set(masters.values())))
    state.bridge = bridge
    if not (root / bridge).is_dir():
        state.problems.append(f"the bridge '{bridge}' does not exist on this host")
        return state
    if _read(root / bridge / "operstate") == "down":
        state.problems.append(f"the bridge '{bridge}' is down")

    for name in (up, down):
        operstate = _read(root / name / "operstate")
        if operstate in ("down", "dormant", "lowerlayerdown"):
            state.problems.append(f"'{name}' is not up (operstate {operstate})")
        if _int_file(root / name / "carrier") == 0:
            state.problems.append(
                f"'{name}' has no link (carrier 0) -- a pulled cable is not a channel"
            )
        pstate = _int_file(root / name / "brport" / "state")
        if pstate is not None and pstate != BRIDGE_PORT_FORWARDING:
            state.problems.append(
                f"'{name}' is not forwarding yet (bridge port state {pstate}; "
                f"{BRIDGE_PORT_FORWARDING} is forwarding) -- STP may still be converging"
            )

    proc = Path(proc_sys)
    for key, family in BRIDGE_NF_SYSCTLS:
        dotted = key.replace("/", ".")
        value = _read(proc / key)
        if value == "":
            state.problems.append(
                f"{dotted} is missing, so bridged {family} traffic never reaches the gate's "
                f"inet rules (is br_netfilter loaded?) -- the gate would install, count "
                f"nothing, and read ARMED"
            )
        elif value != "1":
            state.problems.append(
                f"{dotted}={value}: bridged {family} traffic bypasses the inet forward hook "
                f"the gate's rules live on. Fix: sysctl -w {dotted}=1"
            )

    state.active = not state.problems
    if state.active:
        logger.info("channel: %s <-> %s bridged on %s -- in line, enforcement path live",
                    up, down, bridge)
    else:
        logger.warning("channel declared but NOT active: %s", "; ".join(state.problems))
    return state
