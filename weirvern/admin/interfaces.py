"""Interface discovery and capture-port validation.

WHY THIS EXISTS
---------------
A packet sensor is only as good as the port it listens on, and the failure mode is
silent: Zeek starts, logs happily, and captures nothing useful. We measured this on a
real deployment -- a sensor attached to a veth inside a container saw 73% broadcast
and multicast noise and only traffic addressed to itself, because a bridged port is
not a mirror port. Nothing in Zeek's output says "you picked the wrong interface".

So the interface choice is treated as a first-class configuration decision with a
probe, a diagnosis, and an explicit recommendation, rather than a string an operator
guesses at and then debugs from packet captures.

THE TWO-PORT MODEL this models (the shape that actually works):

    mgmt port   (e.g. eth0)  -> normal networking, default route, SSH, cluster API
    capture port(e.g. eth1)  -> dedicated, promiscuous, receiving a SPAN/mirror feed

They must be different interfaces. Capturing on the management port gives you only
traffic to and from the host itself plus broadcast noise, which is not a network
view -- and it is the specific mistake that produced the noise-only capture we saw.

THE PROBE reads /sys/class/net and /proc/net/route. Pure stdlib, no `ip`, no
`ethtool`: the Zeek and worker images do not all ship those tools (a previous bug in
this project was an interface check that failed because `ip` was absent, and reported
it as a missing interface). The same probe runs either locally or inside a
hostNetwork pod on the sensor node, so what it reports is exactly what Zeek will see.
"""
from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field

# IFF_PROMISC from <net/if.h>. /sys/class/net/<if>/flags is a hex bitmask.
IFF_PROMISC = 0x100
IFF_UP = 0x1
IFF_LOOPBACK = 0x8

# Virtual interface prefixes that can never be a mirror/SPAN port: a tap into the
# host's own stack (or a tunnel) does not receive frames the switch mirrored
# elsewhere. Kept as a prefix list because the suffix is an arbitrary hash.
VIRTUAL_PREFIXES = (
    "lo", "docker", "br-", "veth", "virbr", "vmbr", "flannel", "cni", "cni-",
    "kube-", "tun", "tap", "wg", "tailscale", "zt", "dummy", "bond-",
)


def _probe_source() -> str:
    """The probe program, as a string, so it can run locally or in a pod.

    Emits JSON on stdout. Deliberately stdlib-only: the images involved do not
    reliably contain `ip`, `ethtool`, or even `awk`, and a probe that fails for a
    missing tool is worse than no probe because it reports a false negative.
    """
    return r'''
import json, os, pathlib, socket, struct

net = pathlib.Path("/sys/class/net")


def read(path, default=""):
    try:
        return pathlib.Path(path).read_text().strip()
    except OSError:
        return default


def default_iface():
    """The interface carrying the default route, from /proc/net/route.

    Parsed by hand rather than shelling out to `ip route`: see the module docstring.
    /proc/net/route columns are Iface, Destination, Gateway, ... with the address
    fields in little-endian hex; a zeroed destination is the default route.
    """
    try:
        for line in pathlib.Path("/proc/net/route").read_text().splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 2 and parts[1] == "00000000":
                return parts[0]
    except OSError:
        pass
    return ""


def addrs(name):
    """IPv4/IPv6 addresses on an interface, via SIOCGIFADDR-free means.

    Reads /proc/net/fib_trie is fragile; instead this uses the presence of a
    global-scope address through `socket` only where available, falling back to
    reporting nothing. The UI only needs to show whether an address EXISTS, and
    the default-route interface already identifies the management port, so this is
    best-effort by design.
    """
    out = []
    try:
        import subprocess
        r = subprocess.run(["hostname", "-I"], capture_output=True, text=True, timeout=3)
        out = r.stdout.split()
    except Exception:
        out = []
    return out


result = {"interfaces": [], "default_route_iface": default_iface(),
          "host_addresses": addrs(""), "hostname": socket.gethostname()}

for d in sorted(net.iterdir()):
    # /sys/class/net also holds plain FILES that are not interfaces:
    # `bonding_masters` (always) and `bonding_slaves` (some kernels). They have no
    # `flags` or `operstate`, and reporting them as virtual NICs is noise that
    # obscures the real list. Only directories are interfaces.
    if not d.is_dir():
        continue
    name = d.name
    rec = {
        "name": name,
        "operstate": read(d / "operstate"),
        "flags": read(d / "flags"),
        "address": read(d / "address"),
        "iflink": read(d / "iflink"),
        "speed": read(d / "speed"),
        "mtu": read(d / "mtu"),
        # Structural facts that decide whether this can be a mirror port.
        "is_bridge": (d / "bridge").exists(),          # a bridge DEVICE
        "is_bridge_port": (d / "brport").exists(),     # enslaved TO a bridge
        "is_virtual_path": "/devices/virtual/" in str((d / "device").resolve()) if (d / "device").exists() else True,
        "has_device": (d / "device").exists(),
        "rx_packets": read(d / "statistics" / "rx_packets", "0"),
        "rx_bytes": read(d / "statistics" / "rx_bytes", "0"),
        "rx_dropped": read(d / "statistics" / "rx_dropped", "0"),
        "rx_errors": read(d / "statistics" / "rx_errors", "0"),
        "tx_packets": read(d / "statistics" / "tx_packets", "0"),
    }
    # Driver, when the kernel exposes it. Useful for identifying a physical NIC
    # behind a rename (enp3s0 vs eth1) and for the docs' promisc instructions.
    for cand in ("device/driver", "device/uevent"):
        p = d / cand
        if p.exists():
            try:
                if cand.endswith("driver"):
                    rec["driver"] = os.path.basename(os.path.realpath(p))
                else:
                    for line in p.read_text().splitlines():
                        if line.startswith("DRIVER="):
                            rec["driver"] = line.split("=", 1)[1]
            except OSError:
                pass
    result["interfaces"].append(rec)

print(json.dumps(result))
'''


def _flags_int(raw: str) -> int:
    """Parse the hex flags string from /sys/class/net/<if>/flags.

    Tolerates a missing or malformed value by returning 0 rather than raising, so one
    unreadable interface cannot fail the whole probe.
    """
    try:
        return int(raw.strip(), 16)
    except (TypeError, ValueError, AttributeError):
        return 0


@dataclass
class InterfaceInfo:
    """One interface, with the facts that decide whether it can capture traffic."""

    name: str
    operstate: str = ""
    flags: int = 0
    address: str = ""
    driver: str = ""
    speed: str = ""
    mtu: str = ""
    is_bridge: bool = False
    is_bridge_port: bool = False
    has_device: bool = False
    rx_packets: int = 0
    rx_dropped: int = 0
    rx_errors: int = 0
    is_default_route: bool = False

    @classmethod
    def from_probe(cls, rec: dict, default_iface: str = "") -> InterfaceInfo:
        def as_int(key: str) -> int:
            try:
                return int(rec.get(key) or 0)
            except (TypeError, ValueError):
                return 0

        return cls(
            name=rec.get("name", ""),
            operstate=rec.get("operstate", ""),
            flags=_flags_int(rec.get("flags", "")),
            address=rec.get("address", ""),
            driver=rec.get("driver", ""),
            speed=rec.get("speed", ""),
            mtu=rec.get("mtu", ""),
            is_bridge=bool(rec.get("is_bridge")),
            is_bridge_port=bool(rec.get("is_bridge_port")),
            has_device=bool(rec.get("has_device")),
            rx_packets=as_int("rx_packets"),
            rx_dropped=as_int("rx_dropped"),
            rx_errors=as_int("rx_errors"),
            is_default_route=(rec.get("name") == default_iface and bool(default_iface)),
        )

    # -- derived facts ---------------------------------------------------------
    @property
    def is_up(self) -> bool:
        return bool(self.flags & IFF_UP) and self.operstate.lower() not in ("down", "lowerlayerdown")

    @property
    def is_loopback(self) -> bool:
        return bool(self.flags & IFF_LOOPBACK) or self.name == "lo"

    @property
    def promiscuous(self) -> bool:
        return bool(self.flags & IFF_PROMISC)

    @property
    def is_virtual(self) -> bool:
        """A software interface, by name or by lacking a backing PCI/USB device.

        Both signals are used because either alone is wrong: `virbr0` is virtual but
        has no /device, while a renamed physical NIC still has one. A veth sometimes
        has a device path, so the name check matters too.
        """
        if self.name.startswith(VIRTUAL_PREFIXES):
            return True
        return not self.has_device

    @property
    def can_be_capture_port(self) -> bool:
        """Structurally able to receive mirrored traffic.

        A bridge port or a virtual interface cannot: mirroring is a switch function
        that delivers frames to a physical port. A veth sees only what the host's
        bridge floods to it, which is the broadcast-noise trap we measured.
        """
        # Written as a positive condition so the reason is readable at the call
        # site; ruff's suggested inversion would make this harder to follow.
        unusable = (self.is_loopback or self.is_virtual
                    or self.is_bridge_port or self.is_bridge)
        return not unusable


@dataclass
class ProbeResult:
    """Everything the probe learned, plus the derived judgement."""

    interfaces: list[InterfaceInfo] = field(default_factory=list)
    default_route_iface: str = ""
    hostname: str = ""
    source: str = "local"          # "local" or a node name
    error: str = ""

    def by_name(self, name: str) -> InterfaceInfo | None:
        for i in self.interfaces:
            if i.name == name:
                return i
        return None

    @property
    def candidates(self) -> list[InterfaceInfo]:
        """Interfaces that could serve as a mirror/SPAN capture port, best first.

        INCLUDES interfaces that are currently DOWN. A mirror port is often cabled
        and up-checked after the NIC is identified, so requiring UP at this point
        made the command report "no valid capture port" on a host that has an
        unused physical NIC -- which is exactly the host someone is trying to
        configure. Ordering puts live interfaces first, so a DOWN one is only
        suggested when nothing better exists.
        """
        out = [i for i in self.interfaces if i.can_be_capture_port]
        out.sort(key=lambda i: (not i.is_up, not i.promiscuous, i.is_default_route,
                                -i.rx_packets))
        return out
        return out

    @property
    def mgmt(self) -> InterfaceInfo | None:
        return self.by_name(self.default_route_iface) if self.default_route_iface else None


def parse_probe(stdout: str, source: str = "local") -> ProbeResult:
    """Turn probe JSON into a ProbeResult. Raises ValueError on unparseable output."""
    try:
        data = json.loads(stdout)
    except (ValueError, TypeError) as exc:
        raise ValueError(f"probe output was not JSON: {exc}") from exc
    default_iface = data.get("default_route_iface", "")
    return ProbeResult(
        interfaces=[InterfaceInfo.from_probe(r, default_iface)
                    for r in data.get("interfaces", [])],
        default_route_iface=default_iface,
        hostname=data.get("hostname", ""),
        source=source,
    )


def probe_local(timeout: int = 15) -> ProbeResult:
    """Run the probe against THIS host.

    Correct when the CLI runs on the sensor node itself. On Kubernetes it is usually
    the wrong host to ask, which is why probe_node() exists -- but this is the honest
    fallback when there is no cluster, and it is reported as `local` so the operator
    can see which host answered.
    """
    import sys

    try:
        r = subprocess.run([sys.executable, "-c", _probe_source()],
                           capture_output=True, text=True, timeout=timeout)
    except (subprocess.SubprocessError, OSError) as exc:
        return ProbeResult(source="local", error=f"probe failed: {exc}")
    if r.returncode != 0:
        return ProbeResult(source="local",
                           error=f"probe exited {r.returncode}: {(r.stderr or '').strip()[:200]}")
    try:
        return parse_probe(r.stdout, source="local")
    except ValueError as exc:
        return ProbeResult(source="local", error=str(exc))


def probe_node(namespace: str, node: str = "", image: str = "",
               timeout: int = 120) -> ProbeResult:
    """Run the probe in a one-shot hostNetwork pod, i.e. what Zeek actually sees.

    WHY A POD rather than asking the CLI's own host: on Kubernetes the sensor runs on
    a node, and the operator's workstation (or the control-plane node) has entirely
    different interfaces. Reporting the wrong host's NIC list is how someone selects
    an interface that exists nowhere in the cluster.

    Uses `kubectl run --rm -i` with overrides so there is no manifest to clean up if
    the command is interrupted. The pod is deleted by --rm.
    """
    py = _probe_source()
    # Pass the program via an env var rather than embedding it in the args array:
    # quoting a multi-line Python program through kubectl's argv is fragile.
    overrides: dict = {
        "apiVersion": "v1",
        "spec": {
            "hostNetwork": True,
            "restartPolicy": "Never",
            "automountServiceAccountToken": False,
            "containers": [{
                "name": "probe",
                "image": image,
                "command": ["python", "-c", py],
                "env": [],
                "securityContext": {"runAsUser": 0, "allowPrivilegeEscalation": False},
            }],
        },
    }
    if node:
        overrides["spec"]["nodeName"] = node

    args = ["kubectl", "-n", namespace, "run", "weirvern-ifprobe",
            "--rm", "-i", "--restart=Never", "--attach",
            "--image", image,
            "--overrides", json.dumps(overrides),
            "--quiet"]
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    except (subprocess.SubprocessError, OSError) as exc:
        return ProbeResult(source=node or "node", error=f"probe pod failed: {exc}")
    out = (r.stdout or "").strip()
    if r.returncode != 0 or not out:
        detail = (r.stderr or r.stdout or "").strip()[:200]
        return ProbeResult(source=node or "node",
                           error=f"probe pod did not report (exit {r.returncode}): {detail}")
    # kubectl may prepend a "pod deleted" line; take the last line that parses.
    for line in reversed(out.splitlines()):
        line = line.strip()
        if line.startswith("{"):
            try:
                return parse_probe(line, source=node or "node")
            except ValueError:
                continue
    return ProbeResult(source=node or "node", error=f"no JSON in probe output: {out[:200]}")


# ---------------------------------------------------------------------------
# validation
# ---------------------------------------------------------------------------
@dataclass
class CaptureVerdict:
    """Whether a chosen capture interface is sound, and what to do about it."""

    iface: str
    ok: bool
    fatal: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def summary(self) -> str:
        if self.fatal:
            return f"{self.iface}: NOT usable as a capture port"
        if self.warnings:
            return f"{self.iface}: usable, with caveats"
        return f"{self.iface}: looks like a valid mirror/SPAN port"


def validate_capture_iface(probe: ProbeResult, iface: str,
                           mgmt_iface: str = "") -> CaptureVerdict:
    """Judge whether `iface` can serve as the mirror/SPAN capture port.

    Ordered from fatal structural problems to advisory notes. Every message names
    the consequence, because the operator's next question is always "so what do I
    do about it" -- and the whole point of this function is that the wrong choice
    otherwise shows up only as a thin Zeek log days later.
    """
    v = CaptureVerdict(iface=iface, ok=True)
    info = probe.by_name(iface)

    if not iface.strip():
        v.ok = False
        v.fatal.append("no capture interface is configured (ZEEK_IFACE is empty)")
        return v

    if info is None:
        v.ok = False
        v.fatal.append(
            f"'{iface}' does not exist on {probe.source if probe.source != 'local' else 'this host'}"
        )
        names = ", ".join(sorted(i.name for i in probe.interfaces)) or "none"
        v.notes.append(f"interfaces present: {names}")
        return v

    if info.is_loopback:
        v.ok = False
        v.fatal.append("'lo' is the loopback interface and carries no network traffic")
        return v

    if info.is_bridge or info.name.startswith("vmbr"):
        v.ok = False
        v.fatal.append(
            f"'{iface}' is a bridge DEVICE, not a port. Sniffing a bridge sees only "
            f"traffic that traverses it; mirror the physical port instead of the bridge"
        )

    if info.is_bridge_port:
        # The measured failure. Phrased around the observed symptom so it is
        # recognisable to someone who already has a thin capture.
        v.ok = False
        v.fatal.append(
            f"'{iface}' is enslaved to a bridge, so it receives only flooded traffic "
            f"(broadcast, multicast, ARP) plus traffic addressed to the host itself. "
            f"A captured sample from exactly this configuration was 73% broadcast "
            f"noise. Use a dedicated port that is NOT a bridge member."
        )

    if info.is_virtual and not info.is_bridge_port and not info.is_bridge:
        v.ok = False
        v.fatal.append(
            f"'{iface}' is a virtual interface. Only a physical port can receive a "
            f"switch's mirrored frames; a veth/tunnel sees nothing the host does not"
        )

    if not info.is_up:
        v.ok = False
        v.fatal.append(f"'{iface}' is not UP (operstate={info.operstate or 'unknown'})")

    if info.is_default_route:
        # Name the RIGHT interface, not just the wrong one. An operator told only
        # "this is the management port" has to go and find the alternative; this
        # project's whole theme is that a diagnostic must say what to do next.
        suggestion = recommend(probe, mgmt_iface or info.name)
        advice = f" Use '{suggestion}' instead." if suggestion else ""
        # When MGMT_IFACE also names this interface, the two facts collapse into one
        # sentence. Emitting both produced near-identical warnings twice.
        both = bool(mgmt_iface) and mgmt_iface.strip() == iface
        tail = (
            f" MGMT_IFACE names it too, so the two-port model has no separate capture "
            f"port.{advice}"
            if both else f" Point ZEEK_IFACE at the dedicated mirror port.{advice}"
        )
        v.warnings.append(
            f"'{iface}' carries the default route, so this is the MANAGEMENT port. "
            f"Capturing here sees only this host's own traffic plus broadcast — not the "
            f"network.{tail}"
        )

    # Reported ONCE, here, and only when the default-route clause above has not
    # already covered it (that clause says "MGMT_IFACE names it too" when both apply).
    # An earlier version emitted both, so the operator saw near-identical warnings
    # twice and the output read as a bug.
    needs_separate = (bool(mgmt_iface) and mgmt_iface.strip() == iface
                      and not info.is_default_route)
    if needs_separate:
        v.warnings.append(
            f"MGMT_IFACE and ZEEK_IFACE are both '{iface}'. The two-port model needs "
            f"them separate: one for management, one for capture."
        )

    if not info.promiscuous:
        v.warnings.append(
            f"'{iface}' is not in promiscuous mode. A SPAN/mirror port normally has it "
            f"set by the host: ip link set {iface} promisc on (Weirvern does not set it — "
            f"the Zeek container deliberately has no NET_ADMIN)"
        )

    if info.rx_packets == 0:
        v.notes.append(
            f"'{iface}' has received 0 packets since boot; a mirror port that never "
            f"reports traffic usually means the switch is not sending to it"
        )
    if info.rx_dropped:
        v.notes.append(
            f"kernel dropped {info.rx_dropped} packets on '{iface}' — raise the capture "
            f"ring buffer or the CPU limit before trusting detection"
        )
    if info.rx_errors:
        v.warnings.append(f"'{iface}' reports {info.rx_errors} receive errors")

    if info.speed and info.speed.isdigit() and int(info.speed) > 0:
        v.notes.append(f"link speed {int(info.speed)} Mb/s")
    if info.driver:
        v.notes.append(f"driver {info.driver}")

    return v


def describe(probe: ProbeResult) -> list[tuple[str, str, str]]:
    """Rows for a table: (name, role, detail). Pure formatting, no policy.

    The ROLE column is the recommendation, which is the part an operator cannot
    derive by looking at interface names.
    """
    rows: list[tuple[str, str, str]] = []
    candidates = {i.name for i in probe.candidates}
    for i in sorted(probe.interfaces, key=lambda x: x.name):
        if i.is_loopback:
            continue
        if i.name == probe.default_route_iface:
            role = "mgmt"
        elif i.name in candidates:
            role = "CAPTURE?"
        elif i.is_bridge or i.is_bridge_port:
            role = "bridge"
        elif i.is_virtual:
            role = "virtual"
        else:
            role = "-"

        bits = []
        if i.operstate:
            bits.append(i.operstate)
        if i.promiscuous:
            bits.append("promisc")
        if i.address:
            bits.append(i.address)
        if i.driver:
            bits.append(i.driver)
        if i.rx_packets:
            bits.append(f"rx={i.rx_packets}")
        rows.append((i.name, role, " ".join(bits)))
    return rows


def recommend(probe: ProbeResult, mgmt_iface: str = "") -> str:
    """The suggested capture interface, or "" when there is no good candidate.

    Returns "" rather than guessing, because a wrong recommendation that gets
    accepted is worse than no recommendation: it produces a thin capture that looks
    like a quiet network.
    """
    mgmt = mgmt_iface or probe.default_route_iface
    for i in probe.candidates:
        if i.name != mgmt and i.promiscuous:
            return i.name
    for i in probe.candidates:
        if i.name != mgmt:
            return i.name
    return ""
