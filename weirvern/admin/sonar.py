"""Sonar: survey the capture interface and pre-fill the siphon settings.

WHAT IT ANSWERS, in the order an operator needs it:

    which segment is this interface on        (its own address + netmask -- the segment is a
                                               fact the kernel already holds, not a guess)
    who answers on that segment               (ONE ARP sweep: the same frames every host on
                                               the LAN sends constantly, only asking)
    which addresses are FREE                  (candidates that answered nothing -- offered
                                               for INTERCEPT_ADDR, top-of-range first because
                                               DHCP pools hand out from the bottom)
    which gateway responds, and its MAC       (from the routing table when the interface has
                                               a default route, else assumed as the first
                                               host of the segment; VERIFIED by the sweep,
                                               because interception needs the real MAC both
                                               to forge the mapping and to restore it)

WHY IT RUNS AS A JOB, NOT AS A GUI REQUEST. The GUI pod is deliberately the most ordinary
workload in the project -- its own network namespace, no capabilities, no node pin. A
survey run inside it would measure the WRONG MACHINE and recommend settings for interfaces
that do not exist on the sensor node. The Job runs with the sensor's shape (hostNetwork,
pinned to weirvern.io/sensor-node, NET_RAW for the ARP socket), so what it reports is
exactly what a flip to siphon will do. The GUI creates it, reads the result from the pod
log, and deletes it -- the transport is a log line because it needs no volume, no sidecar,
and no network path back (see `run_survey_job`).

WHAT IT DELIBERATELY DOES NOT DO. It does not change any setting (the GUI STAGES the
recommendations as pending changes and a human presses Apply), does not enable siphon
mode, does not assign any address, and sends nothing but ARP requests. Least privilege
is the rule: NET_RAW is the only capability it holds, because an ARP socket is the only
thing it opens -- the intercept itself needs NET_ADMIN and the overlay grants it there.

THE PRE-FILL IS A RECOMMENDATION, NOT A DECISION. INTERCEPT_ADDR is a heuristic (a host
that is merely powered off also answers nothing -- the CLI has always said so and this
module repeats it in the notes). The values land in the browser's pending-changes list
where they are visible, editable, and inert until Apply.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import struct
import time
import uuid
from pathlib import Path
from socket import AF_INET, SOCK_DGRAM, inet_ntoa, socket

logger = logging.getLogger(__name__)

# The result line the Job prints and the GUI reads back. A prefix rather than a plain JSON
# line so diagnostics can sit in the same log without ambiguity about which line is the result.
SONAR_PREFIX = "SONAR_RESULT "

# How long the GUI waits for the Job. A /24 sweep takes seconds; the budget is generous
# because a cold image import on a loaded node can add tens of seconds of scheduling delay.
SONAR_TIMEOUT_S = 120.0
SONAR_POLL_S = 2.0
# The survey's own bound on ARP drain time, passed through to intercept.arp_sweep.
SONAR_SWEEP_TIMEOUT_S = 4.0

# HOW LONG TO WATCH A SEGMENT BEFORE SWEEPING IT, when the interface carries no address of its
# own. A passive capture port has none by design, so the segment has to be LEARNED from traffic
# rather than read off the interface.
#
# 45 seconds is chosen against what actually has to arrive: a DHCP lease renewal (typically
# every 30 minutes per host, so with any real population of devices one lands inside 45s most of
# the time) and the gratuitous ARP a gateway sends at boot or failover. The first draft used 60s
# and was reduced because this is a wait an operator sits through, and the fallback (inferring
# the prefix from observed addresses) covers the case where no DHCP arrives.
#
# IT IS NOT LONGER FOR A REASON: a longer window finds more hosts but proves nothing extra about
# liveness, which is the sweep's job. Watching and sweeping answer different questions.
SONAR_WATCH_S = 45.0
# How many free addresses are offered. Five is enough to choose from without turning the
# panel into a list; the FIRST is the recommendation.
SONAR_FREE_OFFERED = 5

# ioctl request codes for interface address/netmask, from <net/if.h>. Stdlib-only on
# purpose: this project has been burned before by interface probes that shelled out to
# `ip`, which is not present in every image (see interfaces.py's module docstring).
SIOCGIFADDR = 0x8915
SIOCGIFNETMASK = 0x891b


class SonarError(RuntimeError):
    """A refusal with an operator-actionable reason. Never a bare failure."""


def iface_ipv4(name: str) -> tuple[str, str]:
    """(address, netmask) for an interface, via ioctl. Stdlib only.

    Raises SonarError when the interface does not exist or holds no IPv4 address --
    the segment cannot be derived without one, and a silent "" would present as an
    empty network rather than as the missing address it is.
    """
    import fcntl

    sock = socket(AF_INET, SOCK_DGRAM)
    try:
        def addr(code: int) -> str:
            packed = struct.pack("256s", name.encode()[:15])
            return inet_ntoa(fcntl.ioctl(sock.fileno(), code, packed)[20:24])

        try:
            ip = addr(SIOCGIFADDR)
            mask = addr(SIOCGIFNETMASK)
        except OSError as exc:
            raise SonarError(
                f"'{name}' has no IPv4 address (or does not exist), so its segment cannot be "
                f"derived: the survey reads the segment the interface is ON. Give it an address "
                f"on the segment you intend to test, or survey the interface that has one. "
                f"({exc})"
            ) from exc
        return ip, mask
    finally:
        sock.close()


def _route_gateway(iface: str, route_table: str | None = None) -> str:
    """The default gateway whose route rides `iface`, or "" when there is none.

    Parses /proc/net/route rather than shelling `ip route`, for the same stdlib-only reason
    as iface_ipv4. Columns: Iface Destination Gateway Flags RefCnt Use Metric Mask.
    Destination 00000000 is the default route; the gateway is hex in LITTLE-ENDIAN order
    (the classic trap -- reading it big-endian yields an address on the wrong network).
    Multiple default routes on one interface: the lowest metric wins.
    """
    best: tuple[int, str] = (1 << 30, "")
    try:
        text = route_table if route_table is not None else Path("/proc/net/route").read_text()
    except OSError:
        return ""
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 8 or parts[0] != iface or parts[1] != "00000000":
            continue
        try:
            gw = inet_ntoa(struct.pack("<L", int(parts[2], 16)))
            metric = int(parts[6])
        except (ValueError, OSError):
            continue
        if gw != "0.0.0.0" and metric < best[0]:
            best = (metric, gw)
    return best[1]


def _top_of_range_first(addr: str) -> int:
    return -int(addr.split(".")[-1])


def _passive_only_result(iface: str, mgmt_iface: str, our_mac: str, segment: str,
                         observed: dict, gateway: str, gateway_source: str,
                         notes: list[str], source_ip: str) -> dict:
    """A survey that could only WATCH, because there was no address to sweep from.

    RETURNED RATHER THAN RAISED, and the shape says which questions it answers. The observation
    is a genuine answer to "what network is this", while "who is alive right now" is explicitly
    NOT answered -- reporting `hosts_answered: 0` would be a measured zero for a question nobody
    asked, which this project treats as the failure it is.

    `ok` is true because the survey ran and produced real findings. `swept` is absent, not 0.
    """
    notes.append(
        "THIS SURVEY DID NOT SWEEP. No addresses were probed, so nothing here says who is "
        "alive: the hosts listed are the ones that happened to SPEAK during the window, and a "
        "quiet host is invisible. Give the capture interface an address on the segment (or run "
        "the intercept, which has one) to sweep it."
    )
    return {
        "ok": True,
        "interface": iface,
        "mgmt_interface": mgmt_iface or "",
        "our_mac": our_mac,
        # No address of our own: stated as empty rather than invented, because every other
        # field here is read against this one.
        "address": source_ip or "",
        "address_source": "none: this interface only listens" if not source_ip else "",
        "segment": segment,
        "segment_derivation": observed.get("segment_derivation", ""),
        "gateway": gateway,
        "gateway_mac": "",
        "gateway_source": gateway_source,
        "hosts": [{"ip": a, "mac": m} for a, m in sorted(observed.get("arp_pairs", {}).items())],
        "hosts_answered": len(observed.get("arp_pairs", {}) or {}),
        "hosts_seen": observed.get("hosts_seen", 0),
        # ABSENT, not zero: no sweep ran, so there is no count to report.
        "swept": None,
        "free_addresses": [],
        "observed": observed,
        "passive_only": True,
        # WHAT A PASSIVE SURVEY CAN HONESTLY FILL. The segment and gateway were observed (or
        # inferred and said so); the intercept ADDRESS cannot be, because no sweep ran and a
        # free address is a liveness fact, not a segment fact. Offer the three fields rather
        # than an empty object that made the sheet look like Sonar found nothing.
        "recommended": {
            "intercept_segment": segment,
            "intercept_gateway": gateway,
            "intercept_targets": "*",
        },
        "notes": notes,
    }


def survey(iface: str, mgmt_iface: str = "", *,
           sweep=None, mac_reader=None, addr_reader=None, route_reader=None,
           watcher=None, watch_s: float | None = None,
           sweep_timeout_s: float = SONAR_SWEEP_TIMEOUT_S) -> dict:
    """Measure the segment on `iface` and produce recommendations. Read-only.

    Every side-effecting dependency is injectable -- sweep (ARP), mac_reader, addr_reader,
    route_reader, watcher (passive capture) -- so the arithmetic and the recommendations are
    testable without a root socket or a live segment, the same shape the siphon supervisor's
    spawn hook uses.

    TWO WAYS TO LEARN THE SEGMENT, AND THE SECOND IS THE ONE THAT MATTERS HERE.

    THE ADDRESSED CASE reads the interface's own IPv4 address and netmask. Correct on an
    interface that has one, and WRONG for the deployment this feature is for: a passive
    capture port (SPAN, tap, mirrored vSwitch port) has NO IPv4 address, deliberately, since
    assigning one makes the sensor a participant on a segment it is meant to observe silently.
    Measured live: the capture interface carried only a link-local IPv6 address, and this
    function refused, so Sonar could not run in the one place it exists for.

    THE PASSIVE CASE therefore WATCHES FIRST. A silent port still sees the segment's traffic,
    and that traffic carries what is needed: the subnet mask from a DHCP reply, the gateway
    from the DHCP router option or a gratuitous ARP, and the hosts from their own frames.
    Nothing is transmitted, which is also what makes it safe on a port where transmitting is
    not possible.

    The sweep then runs over whatever segment was learned, so the two phases compose rather
    than replacing each other: passive learning answers "what network is this", and the sweep
    answers "who is there right now". Only the second can find a host that is quiet.

    Raises SonarError with a named remedy for every structural refusal.
    """
    from weirvern.admin import intercept as ic_mod
    from weirvern.admin import segmentwatch, siphonnet

    mac_reader = mac_reader or siphonnet.read_mac
    # A passive capture port has NO IPv4 address by design. `iface_ipv4` raises in that case
    # (correct for callers that need an address), but the fallback below is the whole point of
    # this path: treat "no address" as an empty read and let the passive watcher learn the
    # segment. An injected reader still owns its own refusal.
    def _addr_or_empty(name: str) -> tuple[str, str]:
        try:
            return iface_ipv4(name)
        except SonarError:
            return "", ""
    addr_reader = addr_reader or _addr_or_empty
    route_reader = route_reader or _route_gateway
    sweep = sweep or ic_mod.arp_sweep
    watcher = watcher or segmentwatch.observe_segment

    # ── VALIDATE BEFORE READING ANYTHING (audit F091) ─────────────────────────────────────────
    #
    # First, and through a REASON rather than an exception from `read_mac`: a caller that injected
    # its own mac_reader would otherwise bypass the check that function now performs, and the
    # refusal here is the one that can be turned into an operator-readable SonarError. Placed
    # before the MAC read so a malformed name is never reported as "this interface has no MAC"
    # -- which would send the operator to inspect hardware that is fine.
    why = validate_survey_ifaces(iface, mgmt_iface)
    if why:
        raise SonarError(
            f"cannot survey: {why}. {iface_input_remedy()}"
        )

    our_mac = (mac_reader(iface) or "").strip()
    if not our_mac:
        raise SonarError(
            f"cannot read a MAC for '{iface}'; the survey needs the interface to exist on the "
            f"sensor node (check the interface name in Settings against the node's NICs)"
        )

    notes: list[str] = []
    observed: dict = {}

    ip, mask = addr_reader(iface)
    if not ip:
        # ── THE PASSIVE PATH. No address on the interface is the NORMAL case for a capture
        # port, not an error, so this is a fallback rather than a refusal.
        window = SONAR_WATCH_S if watch_s is None else watch_s
        obs = watcher(iface, seconds=window)
        observed = segmentwatch.summarise(obs)
        notes.extend(segmentwatch.notes_for(obs, observed))
        if not observed.get("segment"):
            raise SonarError(
                f"'{iface}' has no IPv4 address of its own, and watching it for "
                f"{int(window)}s found no traffic to learn the segment from. Either the port "
                f"is not mirroring anything, or the segment was silent. Give the interface an "
                f"address on the segment you intend to test if you know it, or check the "
                f"mirror configuration."
            )
        net = ipaddress.ip_network(observed["segment"], strict=False)
        # No local address: the interface is only listening, so there is nothing of ours to
        # exclude from the sweep and nothing to advertise as our source. The sweep still
        # needs a source address the segment will accept, and without our own address the
        # only honest choices are the gateway (which we may have learned) or nothing.
        ip = observed.get("gateway") or ""
        if not ip:
            notes.append(
                "this interface has no address of its own and no gateway was learned, so an "
                "ARP sweep cannot source its requests from an address the segment accepts. "
                "The survey reports what was OBSERVED and does not sweep."
            )
        else:
            notes.append(
                f"no address on '{iface}', so the sweep sources its ARP requests from the "
                f"learned gateway {ip}. That is a real transmission on the segment: the "
                f"survey is no longer purely passive from this point."
            )
    else:
        net = ipaddress.ip_network(f"{ip}/{mask}", strict=False)
        if net.version != 4:
            raise SonarError(f"'{iface}' carries IPv6 ({ip}); siphon mode is IPv4-only")
        if net.prefixlen >= 31:
            raise SonarError(
                f"'{iface}' is {ip}/{net.prefixlen} -- too small to be a segment. Siphon needs "
                f"the interface to sit ON the segment it will intercept (a /24 is the common case)"
            )

    segment = str(net)

    # The gateway: prefer the interface's own default route; an OBSERVED DHCP router option or
    # gratuitous ARP beats an assumption; otherwise assume the segment's first host (the
    # near-universal convention) and SAY it was assumed. Either way the sweep verifies it.
    gateway = route_reader(iface) or (observed.get("gateway") or "")
    gateway_source = (
        "default route on the interface" if route_reader(iface)
        else (observed.get("gateway_source") or "assumed as the first host of the segment")
    )
    if not gateway:
        first = next(net.hosts(), None)
        if first is None:
            raise SonarError(f"segment {segment} has no usable host addresses")
        gateway = str(first)
        gateway_source = "assumed as the first host of the segment (no default route here)"
        if observed:
            notes.append(
                f"the gateway {gateway} is ASSUMED (first host of the segment): no default "
                f"route, no DHCP router option and no gratuitous ARP were available to observe."
            )

    # Free candidates exclude ourselves and the gateway before the sweep; the sweep decides
    # the rest by who answers.
    skip = {ip, gateway}
    candidates = [str(h) for h in net.hosts() if str(h) not in skip] if ip else []
    if not candidates:
        if observed:
            # Passive-only survey: report what was seen and say the liveness question is
            # unanswered, rather than raising -- the observation IS a useful answer.
            return _passive_only_result(
                iface, mgmt_iface, our_mac, segment, observed, gateway, gateway_source,
                notes, ip)
        raise SonarError(f"segment {segment} has no addresses to survey")

    # ONE SWEEP. It answers both questions -- who is alive, and which addresses are free --
    # so the survey never sends the same frames twice (the CLI's dry-run runs two sweeps
    # because it offers the free list only after the plan; this does it in one pass).
    answered = sweep(iface, our_mac, ip, candidates, timeout_s=sweep_timeout_s)
    # A MAC equal to ours is us (or a mirror of us); never recommend ourselves.
    hosts = {a: m for a, m in answered.items()
             if (m or "").lower() != our_mac.lower() and a != gateway}

    gateway_mac = (answered.get(gateway) or "").lower()
    if not gateway_mac:
        # Second source: the kernel's neighbour cache. Only reached when the gateway did not
        # answer the ARP request, which is itself worth stating.
        gateway_mac = (siphonnet.resolve_mac(iface, gateway) or "").lower()
        if gateway_mac:
            notes.append(
                f"the gateway {gateway} did not answer the ARP sweep; its MAC came from the "
                f"neighbour cache. Interception would need it reachable -- confirm it is alive"
            )
        else:
            notes.append(
                f"the gateway {gateway} answered neither the ARP sweep nor the neighbour cache. "
                f"Interception cannot start without its real MAC (the watchdog restores the "
                f"mapping with it); check that '{iface}' has L2 reachability to the segment"
            )

    free = sorted((a for a in candidates if a not in answered), key=_top_of_range_first)
    if not free:
        notes.append(
            "no free address was found -- every probed address answered. Choose the intercept "
            "address deliberately against your own records"
        )

    if mgmt_iface and mgmt_iface.strip() == iface:
        notes.append(
            f"the capture interface is ALSO the management interface ('{iface}'). The two-port "
            f"model needs them separate: a sensor capturing on its management port sees this "
            f"host's own traffic plus broadcast, not the network"
        )

    recommended: dict[str, str] = {
        "sensor_mode": "siphon",
        "intercept_segment": segment,
        "intercept_gateway": gateway,
        "intercept_targets": "*",
    }
    if free:
        recommended["intercept_addr"] = free[0]

    # Stated before it is applied, because this list becomes the blast radius.
    notes.append(
        f"'{'*'}' means every host on the segment. For a first test, edit 'intercept targets' to "
        f"one or two addresses: each named host has its ARP cache forged while the intercept runs"
    )

    return {
        "ok": True,
        "interface": iface,
        "mgmt_interface": mgmt_iface or "",
        "our_mac": our_mac,
        "address": f"{ip}/{net.prefixlen}",
        "segment": segment,
        # HOW THE SEGMENT WAS LEARNED, present on BOTH paths. Empty when it came from the
        # interface's own address, which needs no explanation; a sentence when it was observed
        # or inferred, which does.
        "segment_derivation": (
            "read from this interface's own address and netmask"
            if not observed else observed.get("segment_derivation", "")
        ),
        "observed": observed or None,
        "passive_only": False,
        "gateway": gateway,
        "gateway_mac": gateway_mac,
        "gateway_source": gateway_source,
        "hosts": [{"ip": a, "mac": hosts[a]} for a in sorted(
            hosts, key=lambda s: tuple(int(x) for x in s.split(".")))],
        "hosts_answered": len(hosts),
        "swept": len(candidates),
        "free_addresses": free[:SONAR_FREE_OFFERED],
        "recommended": recommended,
        "notes": notes,
    }


# ── the Job: created by the GUI, read via its log, deleted after ────────────────────────

def validate_survey_ifaces(iface: object, mgmt_iface: object = "") -> str:
    """WHY the survey's interface inputs are unusable, or "" when they are fine.

    ONE function for the whole product (audit F091), because the same two strings arrive from four
    places -- the request body, the CLI, the Job's own environment, and `survey()`'s arguments --
    and four copies of a rule is how a rule acquires three behaviours. Callers differ only in what
    they do with the reason: the route formats it into a sentence, `survey` raises SonarError, and
    `build_job` raises ValueError.

    Checks BOTH names. Either one reaching the privileged Job matters: `mgmt_interface` is optional
    but rides in the same env and drives the two-port warning, so a malformed one would be
    reported back to the operator as a fact about their sensor.
    """
    from weirvern.admin import siphonnet

    for value, label in ((iface, "interface"), (mgmt_iface, "mgmt_interface")):
        if value is None or value == "":
            continue
        reason = siphonnet.iface_name_error(value)
        if reason:
            return f"{label} {str(value)!r}: {reason}"
    return ""


def iface_input_remedy() -> str:
    """The sentence that tells an operator how to find the right name.

    Kept beside the check rather than typed at each call site, so every refusal says the same
    actionable thing. Interface names come from the node's own NICs, and on this product the
    operator is usually looking at a container's view rather than the sensor's -- so naming the
    command matters.
    """
    return ("Interface names come from the sensor node's own NICs -- check the name against "
            "`ip link` on that node (Sonar surveys the node, not the pod).")


def build_job(name: str, image: str, iface: str, mgmt_iface: str = "",
              namespace: str = "weirvern") -> dict:
    """The one-shot survey Job body.

    THE SHAPE IS THE POINT: hostNetwork (so it sees the NODE's interfaces, not a pod
    namespace), pinned to the sensor node (the machine whose NICs matter), and NET_RAW --
    the one capability an AF_PACKET ARP socket needs. NET_ADMIN is deliberately ABSENT:
    the survey assigns nothing, and a probe should not carry the power to reroute.

    ── THE NAMES ARE VALIDATED HERE (audit F091, CONFIRMED) ─────────────────────────────────────

    This is the LAST point before a string becomes a privileged pod's environment, and until now
    it accepted anything: `build_job(... 'eth0; echo pwned')` produced a Job whose SONAR_IFACE
    held exactly that. The value lands in an env var, not a shell, so the immediate risk is not
    command injection -- but it is a root, hostNetwork, NET_RAW pod, the job runs on the sensor
    node, and the string is echoed straight back into the operator's UI. A control that accepts
    arbitrary text into a privileged workload and shows it back is a control with no input
    contract at all, and the next person to shell out with it inherits the gap.

    Refusing here rather than only at the route means every caller is covered -- the route, the
    CLI, and any future one -- which is the difference between validating a request and validating
    a boundary.

    `image` must carry its tag. The k3s node resolves images from its own containerd by
    exact name:tag, and a bare `weirvern-worker` means `:latest`, which was never imported
    -- the job would sit in ImagePullBackOff while the failure looked like a cluster problem.
    """
    why = validate_survey_ifaces(iface, mgmt_iface)
    if why:
        raise ValueError(f"the survey Job will not be built with an unusable {why}")
    if not str(iface or ""):
        # ── EMPTY IS REFUSED HERE, THOUGH IT IS LEGAL ELSEWHERE (F091) ────────────────────────
        #
        # `validate_survey_ifaces` deliberately skips empty values because an empty
        # `mgmt_interface` is a normal request, and `survey()`'s own caller may legitimately pass
        # "" for the optional name. But the CAPTURE interface is the one thing this Job cannot do
        # without -- it would run, survey nothing, and report that as a fact about the segment.
        # The route already refuses an empty interface before reaching here; this makes the
        # boundary true for every caller rather than only for the one that checks first.
        raise ValueError("the survey Job needs a capture interface; none was given")
    mgmt_iface = str(mgmt_iface or "")
    return {
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": {
            "name": name,
            "namespace": namespace,
            "labels": {"app.kubernetes.io/name": "weirvern-sonar",
                       "app.kubernetes.io/part-of": "weirvern"},
        },
        "spec": {
            "backoffLimit": 0,
            # Self-cleaning if the GUI dies mid-run and never gets to delete it.
            "ttlSecondsAfterFinished": 600,
            "template": {
                "metadata": {"labels": {"app.kubernetes.io/name": "weirvern-sonar",
                                        "app.kubernetes.io/part-of": "weirvern"}},
                "spec": {
                    "restartPolicy": "Never",
                    "nodeSelector": {"weirvern.io/sensor-node": "true"},
                    "hostNetwork": True,
                    # The Kubernetes default for a hostNetwork pod is `Default`, which
                    # resolves through the node -- stated explicitly for the same reason
                    # the siphon overlay sets it: the difference is silent when wrong.
                    "dnsPolicy": "ClusterFirstWithHostNet",
                    "automountServiceAccountToken": False,
                    "securityContext": {"runAsNonRoot": False, "runAsUser": 0, "runAsGroup": 0,
                                        "seccompProfile": {"type": "RuntimeDefault"}},
                    "containers": [{
                        "name": "sonar",
                        "image": image,
                        "command": ["python", "-m", "weirvern.admin.sonar"],
                        "env": [{"name": "SONAR_IFACE", "value": iface},
                                {"name": "SONAR_MGMT_IFACE", "value": mgmt_iface}],
                        "securityContext": {
                            "runAsUser": 0,
                            "runAsGroup": 0,
                            "allowPrivilegeEscalation": False,
                            "capabilities": {"drop": ["ALL"], "add": ["NET_RAW"]},
                        },
                        "resources": {"requests": {"cpu": "50m", "memory": "128Mi"},
                                      "limits": {"cpu": "300m", "memory": "256Mi"}},
                    }],
                },
            },
        },
    }


def _parse_result_line(log_text: str) -> dict | None:
    """The LAST `SONAR_RESULT ` line in a pod log, parsed. None when absent."""
    found = None
    for line in (log_text or "").splitlines():
        line = line.strip()
        if line.startswith(SONAR_PREFIX):
            found = line[len(SONAR_PREFIX):]
    if found is None:
        return None
    try:
        return json.loads(found)
    except ValueError:
        return None


def run_survey_job(client, iface: str, mgmt_iface: str = "", *,
                   timeout_s: float = SONAR_TIMEOUT_S, poll_s: float = SONAR_POLL_S) -> dict:
    """Create the survey Job, wait for it, read its result, delete it. Returns the result.

    `client` is a ClusterConfig-shaped object (api_json/api_text/namespace). Every failure
    path raises SonarError with the reason -- a survey that cannot run must say why, because
    the operator's next click depends on this answer.

    IMAGE RESOLUTION: read from the running worker Deployment, not the package version --
    the deployment is the measurement of what this cluster can actually run. Falls back to
    the package literal, which a test ties to the kustomization tag.
    """
    namespace = client.namespace
    name = f"weirvern-sonar-{uuid.uuid4().hex[:8]}"

    image = ""
    try:
        deploy = client.api_json(
            "GET", f"/apis/apps/v1/namespaces/{namespace}/deployments/weirvern-worker")
        containers = (((deploy or {}).get("spec") or {}).get("template") or {}).get("spec", {}) \
            .get("containers") or []
        image = (containers[0].get("image") or "") if containers else ""
    except Exception:  # noqa: BLE001 - fall through to the package literal
        image = ""
    if not image:
        try:
            from weirvern import __version__

            image = f"weirvern-worker:{__version__}"
        except Exception as exc:  # noqa: BLE001
            raise SonarError(f"could not determine the worker image for the survey: {exc}") from exc

    job = build_job(name, image, iface, mgmt_iface, namespace=namespace)
    path = f"/apis/batch/v1/namespaces/{namespace}/jobs"
    try:
        client.api_json("POST", path, job)
    except Exception as exc:  # noqa: BLE001
        raise SonarError(f"could not create the survey job: {exc}") from exc

    deadline = time.monotonic() + timeout_s
    result: dict | None = None
    failure = ""
    try:
        while time.monotonic() < deadline:
            status: dict = {}
            try:
                got = client.api_json("GET", f"{path}/{name}")
                status = (got or {}).get("status") or {}
            except Exception as exc:  # noqa: BLE001
                failure = f"could not read the survey job's status: {exc}"
                break
            if status.get("succeeded"):
                break
            if status.get("failed"):
                # The log still carries the refusal line; read it below.
                failure = "the survey job failed"
                break
            time.sleep(poll_s)
        else:
            failure = (f"the survey job did not finish within {int(timeout_s)}s. On a single "
                       f"node this usually means the pod could not schedule -- check that the "
                       f"sensor node carries the weirvern.io/sensor-node=true label")

        log_text = ""
        try:
            pods = client.api_json(
                "GET",
                f"/api/v1/namespaces/{namespace}/pods?labelSelector=job-name%3D{name}")
            items = (pods or {}).get("items") or []
            if items:
                pod = items[0]["metadata"]["name"]
                log_text = client.api_text(
                    "GET", f"/api/v1/namespaces/{namespace}/pods/{pod}/log?tailLines=400")
        except Exception:  # noqa: BLE001
            log_text = ""

        parsed = _parse_result_line(log_text)
        if parsed is not None:
            result = parsed
        else:
            # ALWAYS CARRY THE LOG TAIL when there is no result line: the pod's own words are
            # what an operator needs ("no IPv4 address", an import error, an RBAC refusal),
            # and a bare "the job failed" sends them to kubectl to look for what this
            # function already had in hand.
            tail = "\n".join(log_text.strip().splitlines()[-6:])
            base = failure or "the survey produced no output"
            failure = f"{base}. Last log lines: {tail}" if tail else base
    finally:
        # Cleanup is best-effort: the TTL would reap it anyway, and a DELETE failure must
        # never replace the survey's real answer with a cleanup error.
        try:
            client.api_json(
                "DELETE", f"{path}/{name}?propagationPolicy=Background")
        except Exception:  # noqa: BLE001
            logger.debug("could not delete survey job %s", name, exc_info=True)

    if result is None:
        raise SonarError(failure or "the survey produced no result")
    return result


def main() -> int:
    """The Job's entrypoint: survey, print one SONAR_RESULT line, exit.

    Exit codes: 0 survey ok; 2 refused (the SONAR_RESULT line still carries {ok: false,
    error} so the GUI can show the reason from the same transport). Diagnostics go to the
    log around the result line, where an operator reading the job afterwards can see them.
    """
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    iface = (os.environ.get("SONAR_IFACE") or "").strip()
    mgmt = (os.environ.get("SONAR_MGMT_IFACE") or "").strip()
    try:
        if not iface:
            raise SonarError(
                "no capture interface is configured, so there is nothing to survey "
                "(set ZEEK_IFACE, or CAPTURE_IFACE to override it for the intercept)"
            )
        # DEFENCE IN DEPTH (audit F091). `build_job` already refuses a malformed name, so this
        # should be unreachable -- which is exactly why it belongs here: this is the privileged
        # side (root, NET_RAW, hostNetwork), and it must not depend on a check made by the
        # process that CREATED it. An env var is an input like any other, and the one place a
        # value is finally used is the place to be sure of it.
        _why = validate_survey_ifaces(iface, mgmt)
        if _why:
            raise SonarError(f"the survey job's environment is unusable: {_why}")
        result = survey(iface, mgmt)
    except SonarError as exc:
        print(f"{SONAR_PREFIX}{json.dumps({'ok': False, 'error': str(exc)})}", flush=True)
        logger.error("sonar refused: %s", exc)
        return 2
    except Exception as exc:  # noqa: BLE001
        print(f"{SONAR_PREFIX}{json.dumps({'ok': False, 'error': f'unexpected error: {exc}'})}",
              flush=True)
        logger.error("sonar failed", exc_info=True)
        return 2
    for note in result.get("notes") or []:
        logger.info("note: %s", note)
    print(f"{SONAR_PREFIX}{json.dumps(result)}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
