"""THE TAP — capture a port into rotating segments, summarise each into IPFIX.

WHAT THIS IS. One long-lived `tcpdump` per selected interface writes SHORT ROTATING pcap
segments (bounded by time and size); every tick, each COMPLETED segment is summarised by a
one-shot `softflowd` and deleted. The IPFIX lands at the deployment's own collector (goflow2
on the node's 2055, which writes flows.jsonl and the ingester tails it into `weirvern.flows`).

WHY IT IS ITS OWN MODULE, AND WHY IT LEFT THE WORKER. The worker runs as a non-root uid. A
capability added to a non-root container is DROPPED by Kubernetes -- measured again on
2026-11-17: the worker's pod spec carried `add: ["NET_RAW"]` and `/proc/self/status` inside it
read `CapEff: 0000000000000000`, so tcpdump could not open the capture socket and flows
stopped while everything looked configured. The capture grant belongs to the process that
actually reads the wire, and the wire belongs to the CAPTURE boundary:

  * on the hub, a `tap` sidecar in the Zeek DaemonSet -- same image, same host network, root
    with NET_RAW (the only uid for which the grant is effective);
  * on a weirling, the agent container -- the unit's sensor boundary, which already holds the
    grant in the in-path overlay.

The worker keeps no capture code and needs no capture capability. It reads the collector's
output like any other flow source.

WHY SEGMENTS AND A BATCH SUMMARISER, every part MEASURED on the test box (2026-10-16), because
each simpler shape was tried and failed for a stated reason:

  * softflowd's OWN live-capture loop never dispatches on this kernel: its libpcap counter
    grows with every packet (105 -> 115 across a burst) while "Packets processed" stays 0 --
    on a bridge port and a plain NIC alike. strace shows its poll on the packet-ring socket
    never firing, while tcpdump's blocking read from the same socket captures fine.
  * softflowd reading a LIVE tcpdump pipe BLOCKS FOREVER: header read, "starting data
    collection", then nothing -- not a record, not even its stats on SIGTERM -- while tcpdump
    demonstrably wrote the packets into the pipe.
  * softflowd reading a COMPLETED stream is perfect: a capture file, or a pipe that has hit
    EOF, processes 30/30 packets and its flows export.
  * goflow2 ingests softflowd's IPFIX (v10) -- "type":"IPFIX" in flows.jsonl -- and silently
    DROPS its v9. (The production gateway exports IPFIX too.)
  * Debian's tcpdump drops privileges to a `tcpdump` user that cannot be switched to inside
    this container ("Couldn't change to 'tcpdump' ... Operation not permitted") and exits at
    once -- the tap therefore runs with -Z root. The children's stderr is INHERITED (the pod
    log): the first version sent it to /dev/null and that hid this exact failure.

THE SEGMENT RING. Rotation every 30s or 16 MB, at most 240 files. The directory is the
container's own /tmp: the ring is a TRANSIENT buffer (each segment is summarised and deleted
within a tick of completion), so a pod restart losing the tail is the same class of gap as the
restart itself -- and it keeps the process from needing a writable share of the flow volume,
which the worker deliberately mounts read-only.
"""
from __future__ import annotations

import contextlib
import json
import logging
import os
import shutil
import signal
import subprocess
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# goflow2, hostNetwork on this node.
TAP_COLLECTOR = "127.0.0.1:2055"
TAP_PORT = 2055


def collector_for(index: int, *, port: int = TAP_PORT) -> str:
    """The collector address for the index-th NIC: 127.0.0.1:2055, 127.0.0.2:2055, and so on.

    ONE PORT, ONE ADDRESS PER NIC (operator, 2026-11-18: "how can we continue to use 2055 for
    each nic"). Two listeners may share a port as long as they bind different addresses, and
    Linux routes all of 127.0.0.0/8 locally, so a second collector costs no interface, no
    firewall rule and no new port. The PORT the exporter targets never changes; the FILE a
    collector writes is what names the NIC, which is honest in a way a synthetic header field
    would not be -- softflowd cannot report an interface when it reads a pcap, measured four
    ways on the box (ingress index, exporter IP, interface name, plain).
    """
    n = index + 1
    if not 1 <= n <= 254:
        raise ValueError("more than 254 interfaces have no loopback address to bind")
    return f"127.0.0.{n}:{port}"
# Timeouts chosen for a monitoring pipeline that re-evaluates five-minute buckets: idle flows
# export within a minute or two and long flows at least every ten, rather than the half-hour-to-
# hour defaults of a router exporting for billing. The `arp` term in the tap filter is not
# recorded (softflowd counts it as ignored) -- it keeps the stream ticking on quiet segments so
# flow expiries are still evaluated promptly.
TAP_TIMEOUTS = ("-t", "tcp=120", "-t", "udp=60", "-t", "icmp=60",
                "-t", "general=180", "-t", "maxlife=600")
TAP_FILTER = "ip or ip6 or arp"
TAP_DIR = "/tmp/weirvern-tap"
TAP_SEGMENT_S = 30
TAP_SEGMENT_MB = 16
TAP_KEEP_SEGMENTS = 240
# THE RING'S DISK BUDGET, IN MB (measured 2026-11-17). `-W 240` x `-C 16` is a 3.84 GB worst case,
# and it is only reachable the way that matters: softflowd stops consuming. Every other failure
# already bounds itself -- a dead tcpdump stops writing, and `stop()` deletes the ring outright --
# but a softflowd that exists, starts, and then hangs leaves tcpdump happily filling the node's
# disk for two hours of segment time. The sweep deletes each segment as it succeeds, so a healthy
# ring is two files (20 KB measured); anything approaching this budget is already a failure, and
# 512 MB is 16 minutes of capture -- far more than the 120s a summariser is allowed to take, so
# pruning to it cannot cost data that was still going to be read.
TAP_RING_MAX_MB = 512
# A crash loop that writes a log line and doomed children every tick is worse than a tap that
# is visibly not running: one warning, then a five-minute cooldown, then a retry.
RETRY_S = 300.0
# How often a running tap sweeps its completed segments. The worker used its detection cadence
# (five minutes by default); the tap owns its own clock now and can be prompt without costing
# anything: a sweep is a listdir, and softflowd runs only when a segment has closed.
TICK_S = 15.0


@dataclass(frozen=True)
class Target:
    """One interface to meter, and WHY it is being metered (for the log and the tests)."""

    iface: str
    source: str  # "channel" | "siphon" | "loch"


def iface_list(value) -> list[str]:
    """Normalize a comma/semicolon-separated interface setting, preserving order."""
    out: list[str] = []
    for part in str(value or "").replace(";", ",").split(","):
        name = part.strip()
        if name and name not in out:
            out.append(name)
    return out


def select_targets(*, netflow_mode: str = "auto", channel_netflow: str = "off",
                   channel_upstream: str = "", channel_downstream: str = "",
                   siphon_netflow: bool = False, sensor_mode: str = "",
                   netflow_iface: str = "", capture_iface: str = "",
                   zeek_iface: str = "", channel_active: bool = False,
                   siphon_live: bool | None = None) -> list[Target]:
    """Which interfaces to tap, from the plan and the EVIDENCE -- never from config alone.

    TWO SOURCES, ONE TAP PER INTERFACE:

      * `channel_netflow=upstream|downstream` -- a port of the channel's bridge, while the
        channel is verified active;
      * `siphon_netflow=1` (or siphon mode in `auto`) -- the interfaces a LIVE siphon intercept
        relays through, while the intercept is verified live.

    A box with more than one capture NIC runs one tap per selected interface: the per-NIC
    switches stage a comma-separated `netflow_iface`. A channel still wins over siphon:
    tapping both a channel port and an intercept of the same traffic would count it twice.

    `siphon_live` is THREE-VALUED on purpose. True = verified live; False = verified not;
    None = the evidence could not be read, which is NOT a reason to start tapping -- a probe
    started on the strength of a ConfigMap would collect records of a segment that is not
    flowing through this box.

    CHANNEL IS NOT A SYNONYM FOR A NIC. The channel belongs to the INLINE path only;
    `CHANNEL_UPSTREAM`/`CHANNEL_DOWNSTREAM` are a bridged pair and sampling either side is
    sufficient because every frame crosses both. An ordinary capture NIC is selected through
    `netflow_iface` and gets its own tap.
    """
    flow_mode = str(netflow_mode or "auto").strip().lower()
    if flow_mode not in ("auto", "passive", "active"):
        flow_mode = "auto"
    mode = str(channel_netflow or "off").strip().lower()
    sensor = str(sensor_mode or "").strip().lower()

    def _by_iface(setting: str) -> list[str]:
        ifaces = iface_list(setting)
        if not ifaces:
            one = str(capture_iface or zeek_iface or "").strip()
            ifaces = [one] if one else []
        return ifaces

    if flow_mode == "passive":
        # THE ROUTER OWNS THE FEED. Any sensor-generated tap stops; the external exporter
        # continues into the collector exactly as before.
        return []
    if flow_mode == "active":
        # ACTIVE MEANS THIS SENSOR MEASURES ITS OWN CAPTURE. In siphon the tap follows the
        # verified relay; in loch it samples the selected mirrored interfaces continuously.
        if mode in ("upstream", "downstream") and channel_active:
            iface = (channel_upstream if mode == "upstream" else channel_downstream).strip()
            return [Target(iface, "channel")] if iface else []
        if sensor == "siphon":
            if siphon_live is True:
                return [Target(iface, "siphon") for iface in _by_iface(netflow_iface)]
            return []
        return [Target(iface, "loch") for iface in _by_iface(netflow_iface)]

    if mode in ("upstream", "downstream") and channel_active:
        iface = (channel_upstream if mode == "upstream" else channel_downstream).strip()
        return [Target(iface, "channel")] if iface else []
    if (siphon_netflow or sensor == "siphon") and siphon_live is True:
        # AUTO, the historical behaviour. A SIPHON SENSOR WANTS FLOW RECORDS, and it is still
        # gated on VERIFIED liveness below: a configured-but-dead intercept must not fill the
        # flows table with records of nothing. The tap follows the SIPHON port, not the Zeek
        # port -- when the operator chooses a different capture interface the relay runs there.
        return [Target(iface, "siphon") for iface in _by_iface(netflow_iface)]
    return []


def select_from_settings(settings, *, channel_active: bool = False,
                          siphon_live: bool | None = None,
                          sensor_mode: str | None = None,
                          capture_iface: str | None = None,
                          zeek_iface: str | None = None) -> list[Target]:
    """`select_targets` reading the attribute names off a Settings-shaped object.

    The overrides exist for a weirling: its capture port and its mode come from the UNIT's own
    plan, never from the hub's `SENSOR_MODE` (which describes the hub's sensor). Passing them
    explicitly keeps that distinction visible at the call site instead of buried in a default.
    """
    def get(name: str, default: object = "") -> object:
        return getattr(settings, name, default)

    return select_targets(
        netflow_mode=str(get("netflow_mode", "auto") or "auto"),
        channel_netflow=str(get("channel_netflow", "off") or "off"),
        channel_upstream=str(get("channel_upstream", "") or ""),
        channel_downstream=str(get("channel_downstream", "") or ""),
        siphon_netflow=bool(get("siphon_netflow", False)),
        sensor_mode=str(sensor_mode if sensor_mode is not None else get("sensor_mode", "")),
        netflow_iface=str(get("netflow_iface", "") or ""),
        capture_iface=str(capture_iface if capture_iface is not None
                          else get("capture_iface", "")),
        zeek_iface=str(zeek_iface if zeek_iface is not None else get("zeek_iface", "")),
        channel_active=channel_active,
        siphon_live=siphon_live,
    )


def prune_ring(*, directory: str | None = None, max_mb: int = TAP_RING_MAX_MB) -> int:
    """Drop the OLDEST completed segments when the ring outgrows its disk budget.

    A backstop, not a policy: on a working tap this returns 0 because the sweep has already
    deleted every segment it summarised (two files, ~20 KB, measured). It exists for the one
    failure that otherwise has no bound -- softflowd present but hung, so `sweep_completed` keeps
    failing and tcpdump keeps rotating through 3.84 GB.

    THE NEWEST FILE IS NEVER TOUCHED. That is the segment tcpdump is writing right now; deleting
    it would make the next rotation re-use a name tcpdump still holds open. Oldest-first falls out
    of the sort: `-W` numbers its files with a fixed-width suffix ("ch-20261117-153000.pcap000"),
    so lexical order is capture order.

    Returns how many segments were dropped, so the caller can log one line rather than one per file.
    """
    root = directory or TAP_DIR
    try:
        names = sorted(n for n in os.listdir(root) if ".pcap" in n)
    except OSError:
        return 0
    names = names[:-1]  # the newest is the live segment
    sizes: dict[str, int] = {}
    total = 0
    for name in names:
        try:
            sizes[name] = os.path.getsize(os.path.join(root, name))
        except OSError:
            continue
        total += sizes[name]
    budget = max(1, int(max_mb)) * 1024 * 1024
    if total <= budget:
        return 0
    dropped = 0
    for name in names:
        if total <= budget:
            break
        try:
            os.unlink(os.path.join(root, name))
        except OSError:
            continue
        total -= sizes.get(name, 0)
        dropped += 1
    if dropped:
        logger.warning(
            "tap: ring over the %dMB budget — dropped %d oldest segment(s), %dMB still pending. "
            "softflowd is not keeping up with the capture; flows in the dropped segments were "
            "never exported.",
            max_mb, dropped, total // (1024 * 1024),
        )
    return dropped


def publish_state(supervisor: Supervisor, targets: Sequence[Target], settings,
                  *, path: str | None = None) -> bool:
    """Write the tap's own state where a health probe can read it. Best-effort, once per tick.

    WHY A FILE AND NOT A ROW (measured 2026-11-17). The tap deliberately has no database client:
    it must keep capturing when ClickHouse is away, and a capture process that dies with the
    database is the wrong dependency direction. The health probe, meanwhile, runs in a different
    pod (the GUI) or a different container (the worker CLI) and cannot see this process's /tmp.
    A hostPath file that all of them mount is the smallest thing that crosses that boundary.

    WHAT IT ADDS THAT NO OTHER PROBE HAS. Everything else infers capture from the ROWS that
    arrive, and "no rows" is the same fact whether the network is quiet or the tap is dead -- the
    exact ambiguity that hid a 16-hour outage. This says the process is alive, on which interface,
    how many segments it has summarised, and what last went wrong.

    ATOMIC BY RENAME: a reader either sees the previous tick or this one, never a half-written
    file. A failure to write is DEBUG, not a warning: a read-only mount or a missing hostPath must
    not spam a capture process that is otherwise doing its job.
    """
    from weirvern.config import tap_state_path  # noqa: PLC0415 -- no cycle at import time

    dest = path or tap_state_path()
    ring_files = 0
    ring_bytes = 0
    roots = {entry.get("dir") or supervisor.directory for entry in supervisor.taps.values()}
    for root in roots or {supervisor.directory}:
        try:
            names = [n for n in os.listdir(root) if ".pcap" in n]
        except OSError:
            continue
        ring_files += len(names)
        for name in names:
            with contextlib.suppress(OSError):
                ring_bytes += os.path.getsize(os.path.join(root, name))
    payload = {
        "ts": time.time(),
        "pid": os.getpid(),
        "running": bool(supervisor.taps),
        "targets": [{"iface": t.iface, "source": t.source,
                     "collector": collector_for(i)} for i, t in enumerate(targets)],
        "netflow_mode": str(getattr(settings, "netflow_mode", "")),
        "sensor_mode": str(getattr(settings, "sensor_mode", "")),
        "collector": TAP_COLLECTOR,
        "segments_swept": int(supervisor.segments_swept),
        "ring_files": ring_files,
        "ring_bytes": ring_bytes,
        "last_error": supervisor.last_error,
    }
    tmp = f"{dest}.tmp.{os.getpid()}"
    try:
        parent = os.path.dirname(dest)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(payload, fh)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, dest)
        return True
    except OSError as exc:
        logger.debug("tap: could not publish state to %s: %s", dest, exc)
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        return False


def sweep_completed(*, run: Callable | None = None, probe: str | None = None,
                    now: Callable[[], float] | None = None,
                    directory: str | None = None,
                    collector: str | None = None) -> int:
    """Summarise every COMPLETED capture segment into IPFIX, and delete it once it is in.

    Returns how many segments were summarised. Injectable `run` / `probe` / `now` / `directory`
    so the whole decision table -- which files are complete, what happens on success, on
    failure, on an empty ring -- is unit-testable without a kernel, a network or a child.
    """
    runner = run or subprocess.run
    clock = now or time.time
    root = directory or TAP_DIR
    # THE COLLECTOR FOLLOWS THE DIRECTORY: each NIC exports to its own loopback address on the
    # one port, so the file a collector writes -- not a header field softflowd cannot set --
    # carries the identity.
    target = collector or TAP_COLLECTOR
    try:
        # `.pcap` IN the name, not a suffix match: tcpdump's -W rotation numbers the files it
        # writes ("ch-20261015-200648.pcap000"), so a `.endswith(".pcap")` filter matched nothing
        # and the sweep silently found no work -- measured on the first v3 deploy.
        names = sorted(n for n in os.listdir(root) if ".pcap" in n)
    except OSError:
        return 0
    if len(names) < 2:
        return 0  # a single file is the one the tap is writing right now
    binary = probe or shutil.which("softflowd")
    if not binary:
        return 0  # the start path already warns about the missing binary
    done = 0
    for name in names[:-1]:  # the newest is still being written (rotation is atomic)
        path = os.path.join(root, name)
        try:
            if clock() - os.path.getmtime(path) < 5.0:
                continue  # young enough that rotation may not have closed it yet
        except OSError:
            continue
        # NO -p / NO -c: a one-shot summariser has no use for a pidfile or a control socket, and
        # measured on the box, the same invocation WITH them hung for the runner's whole timeout
        # while the same file summarised cleanly (82/82 packets, flows flushed) without them.
        # stdin is DEVNULL: this child reads a FILE; it has no business inheriting the tap's stdin.
        argv = [binary, "-r", path, "-n", target, "-v", "10", "-d", *TAP_TIMEOUTS]
        try:
            result = runner(argv, timeout=120, capture_output=True, stdin=subprocess.DEVNULL)
        except Exception as exc:  # noqa: BLE001
            logger.warning("tap: summarising %s failed: %s", name, exc)
            continue
        if getattr(result, "returncode", 1) == 0:
            with contextlib.suppress(OSError):
                os.unlink(path)
            done += 1
        else:
            err = (getattr(result, "stderr", b"") or b"")
            if isinstance(err, bytes):
                err = err.decode("utf-8", "replace")
            logger.warning("tap: summarising %s failed (rc=%s): %s",
                           name, getattr(result, "returncode", "?"), err.strip()[:200])
    return done


class Supervisor:
    """Owns the capture children: start, stop, restart, and the per-tick sweep.

    Module-level singleton state is deliberately avoided: the sidecar has one instance, and a
    weirling's agent has one of its own, so two sensors in one process would be a bug this
    shape cannot express.
    """

    def __init__(self, *, directory: str = TAP_DIR,
                 spawn: Callable | None = None, which: Callable | None = None,
                 run: Callable | None = None, clock: Callable[[], float] | None = None) -> None:
        self.directory = directory
        self.taps: dict[str, dict] = {}
        self.retry_after = 0.0
        # Counters for the published state. They are what turns "flows stopped" into a diagnosis:
        # a live tap that has swept nothing for ten minutes is a different fault from a dead one.
        self.segments_swept = 0
        self.last_error = ""
        self._spawn = spawn or subprocess.Popen
        self._which = which or shutil.which
        self._run = run
        self._clock = clock or time.monotonic

    # ── the decision table, once per tick ────────────────────────────────────────────────────
    def tick(self, targets: Sequence[Target]) -> None:
        """One supervision pass. Cheap when nothing changed."""
        target_ifaces = [t.iface for t in targets]
        running = any(entry.get("tap") is not None and entry["tap"].poll() is None
                      for entry in self.taps.values())
        dead = [iface for iface, entry in self.taps.items()
                if entry.get("tap") is None or entry["tap"].poll() is not None]

        if dead and self.taps:
            rc = next((getattr(self.taps[i].get("tap"), "returncode", None) for i in dead), None)
            self.stop(f"the tap on {', '.join(dead)} exited")
            self.retry_after = max(self.retry_after, self._clock() + RETRY_S)
            self.last_error = f"the tap on {', '.join(dead)} exited (code {rc})"
            logger.warning("tap: a capture tap exited (code %s); next attempt in 5 minutes", rc)
            running = False
        elif running and set(self.taps) != set(target_ifaces):
            self.stop(f"the source moved to {', '.join(target_ifaces)}" if target_ifaces
                      else "the selection is off, or the channel/intercept is not active")
            running = False

        if not target_ifaces:
            if running:
                self.stop("no active target")
            return
        if running:
            self._sweep()
            return
        if self._clock() < self.retry_after:
            return

        probe, tap_binary = self._which("softflowd"), self._which("tcpdump")
        if not probe or not tap_binary:
            self.retry_after = self._clock() + RETRY_S
            logger.warning("tap: %s is not in this image, so the selection cannot collect "
                           "flows (the image contract test pins both)",
                           "softflowd" if not probe else "tcpdump")
            return
        started: dict[str, dict] = {}
        try:
            for index, target in enumerate(targets):
                # One NIC keeps the historical flat directory; two or more get a directory each
                # so one tap's still-being-written segment cannot hold up another's sweep.
                if len(targets) == 1:
                    directory = self.directory
                else:
                    safe = "".join(ch if ch.isalnum() or ch in "._-" else "_"
                                   for ch in target.iface)
                    directory = os.path.join(self.directory, safe or "iface")
                os.makedirs(directory, exist_ok=True)
                tap_proc = self._spawn(
                    # -Z root: Debian's tcpdump DROPS PRIVILEGES to a `tcpdump` user that cannot
                    # be switched to inside this container ("Couldn't change to 'tcpdump' ...:
                    # Operation not permitted") and exits at once -- measured, with the stderr
                    # that was being swallowed until it was left INHERITED.
                    # -C / -G / -W: bounded rotating segments; the %.pcap name is strftime
                    # because -G is set. One tap per NIC writes into its own directory.
                    [tap_binary, "-Z", "root", "-i", target.iface, "-U", "-s", "160",
                     "-C", str(TAP_SEGMENT_MB), "-G", str(TAP_SEGMENT_S),
                     "-W", str(TAP_KEEP_SEGMENTS),
                     "-w", os.path.join(directory, "ch-%Y%m%d-%H%M%S.pcap"),
                     TAP_FILTER])
                started[target.iface] = {"tap": tap_proc, "source": target.source,
                                          "dir": directory,
                                          "collector": collector_for(index)}
            self.taps = started
            for target in targets:
                logger.info("%s netflow: tapping %s into %s (segment %ss / %sMB) and "
                            "summarising each completed segment to %s IPFIX",
                            target.source, target.iface, started[target.iface]["dir"],
                            TAP_SEGMENT_S, TAP_SEGMENT_MB, started[target.iface]["collector"])
        except Exception as exc:  # noqa: BLE001
            self.stop()
            self.retry_after = self._clock() + RETRY_S
            self.last_error = str(exc)
            logger.warning("tap: could not start the probe: %s", exc)

    # ── the sweep ────────────────────────────────────────────────────────────────────────────
    def _sweep(self) -> None:
        probe = self._which("softflowd")
        for entry in self.taps.values():
            directory = entry.get("dir") or self.directory
            done = sweep_completed(run=self._run, probe=probe, directory=directory,
                                   collector=entry.get("collector"))
            if isinstance(done, int):
                self.segments_swept += done
            # AFTER the sweep, never before: whatever could still be summarised has been. The
            # guard is a backstop for a summariser that is not consuming (see TAP_RING_MAX_MB).
            prune_ring(directory=directory)

    # ── shutdown ─────────────────────────────────────────────────────────────────────────────
    def stop(self, reason: str = "") -> None:
        """Stop every capture tap, drop pending segments, and say why. Best-effort: never raises.

        The pending segments go with the taps ON PURPOSE: they contain captured traffic that has
        not been summarised yet, and "off" has to mean nothing is being collected -- leaving them
        on disk would keep the traffic this feature captured after the operator switched it off.
        """
        stopped = 0
        for entry in list(self.taps.values()):
            tap = entry.get("tap")
            if tap is None:
                continue
            try:
                tap.terminate()
                try:
                    tap.wait(timeout=5)
                except Exception:  # noqa: BLE001 -- TimeoutExpired without importing it
                    tap.kill()
                stopped += 1
            except Exception as exc:  # noqa: BLE001
                logger.warning("tap: could not stop the capture tap: %s", exc)
        self.taps = {}
        dropped = 0
        roots = [self.directory]
        with contextlib.suppress(OSError):
            roots.extend(os.path.join(self.directory, name) for name in os.listdir(self.directory)
                         if os.path.isdir(os.path.join(self.directory, name)))
        for root in roots:
            try:
                names = os.listdir(root)
            except OSError:
                continue
            for name in names:
                if name.endswith(".pcap"):
                    with contextlib.suppress(OSError):
                        os.unlink(os.path.join(root, name))
                        dropped += 1
        if stopped or dropped:
            logger.info("tap: %d probe(s) stopped%s%s", stopped,
                        f" ({reason})" if reason else "",
                        f"; {dropped} pending segment(s) removed" if dropped else "")


class SiphonLiveness:
    """Is a siphon intercept actually relaying right now? None when the evidence is unreadable.

    SAME QUESTION THE GATE ASKS, through the same helper, deliberately: "configured" is not
    "intercepting". The rows come from the intercept's own heartbeat, which is the only writer
    that knows how many mappings it forged. A connection failure is cached as "unknown" and
    retried on the next tick, so a database that is briefly away cannot be mistaken for a live
    intercept -- nor for a dead one.
    """

    def __init__(self, settings, *, connect: Callable | None = None) -> None:
        self._settings = settings
        self._connect = connect
        self._client = None

    def __call__(self) -> bool | None:
        try:
            if self._client is None:
                from weirvern import db  # noqa: PLC0415

                # ONE attempt, not the worker's thirty: this runs inside a tick, and a 150-second
                # block would stall the sweep the tap is also responsible for.
                self._client = (self._connect or db.connect)(self._settings, retries=1)
            from weirvern.admin import status  # noqa: PLC0415

            return bool(status.siphon_liveness(self._settings.sensor_mode, self._client)
                        .get("live"))
        except Exception as exc:  # noqa: BLE001
            self._client = None
            logger.warning("tap: could not read siphon intercept evidence: %s", exc)
            return None


def _channel_active(settings) -> bool:
    """Whether the configured in-line channel is verified active, from the kernel.

    Only consulted when a channel is actually selected: the check reads sysfs (bridge, carrier,
    forwarding state) and costs nothing, but a box with no channel should not run it at all.
    """
    mode = str(getattr(settings, "channel_netflow", "off") or "off").strip().lower()
    if mode not in ("upstream", "downstream"):
        return False
    try:
        from weirvern.admin import channel  # noqa: PLC0415

        return bool(channel.detect(getattr(settings, "channel_upstream", ""),
                                   getattr(settings, "channel_downstream", "")).active)
    except Exception as exc:  # noqa: BLE001
        logger.warning("tap: could not verify the channel: %s", exc)
        return False


def main() -> None:
    """Run the tap as its own process: the hub's sidecar, or a weirling's agent container."""
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")
    from weirvern.config import get_settings  # noqa: PLC0415

    settings = get_settings()
    supervisor = Supervisor()
    liveness = SiphonLiveness(settings)
    stop = threading.Event()

    def _term(_signum, _frame) -> None:
        stop.set()

    signal.signal(signal.SIGTERM, _term)
    signal.signal(signal.SIGINT, _term)

    logger.info("tap: netflow_mode=%s channel_netflow=%s sensor_mode=%s -- sweeping every %ss",
                getattr(settings, "netflow_mode", "auto"),
                getattr(settings, "channel_netflow", "off"),
                getattr(settings, "sensor_mode", ""), int(TICK_S))

    while not stop.wait(TICK_S):
        try:
            targets = select_from_settings(
                settings,
                channel_active=_channel_active(settings),
                # The three-valued answer only matters in siphon mode, and the DB is not touched
                # otherwise (a passive box makes no queries and needs no credential).
                siphon_live=(liveness() if str(getattr(settings, "sensor_mode", ""))
                             .strip().lower() == "siphon" else None),
            )
            supervisor.tick(targets)
            # Publish what this process is doing, once per tick: the only evidence that capture is
            # ALIVE rather than merely configured. Never raises, never blocks the sweep.
            publish_state(supervisor, targets, settings)
        except Exception as exc:  # noqa: BLE001 -- a monitoring feature must not die on a tick
            logger.warning("tap: tick failed (retrying): %s", exc)

    supervisor.stop("tap shutdown")
    logger.info("tap: stopped")


if __name__ == "__main__":
    main()
