"""Learn a segment's addresses by WATCHING, without owning an address on it.

WHY THIS EXISTS, AND THE DEFECT IT REPLACES. Sonar derived the segment to survey from the
capture interface's OWN IPv4 address and netmask:

    ip, mask = addr_reader(iface)
    net = ipaddress.ip_network(f"{ip}/{mask}", strict=False)

That is correct for an interface on a NORMAL network and wrong for the one place this
feature is used. A passive capture interface -- a SPAN port, a tap, or a mirrored vSwitch
port -- is a RECEIVE-ONLY port with NO IPv4 address, deliberately: assigning one would make
the sensor a participant on a segment it is supposed to observe silently. Measured on the
live sensor node: `ens19` carried only a link-local IPv6 address, and Sonar refused with
"'ens19' has no IPv4 address (or does not exist), so its segment cannot be derived".

So Sonar could not run in the exact deployment it was written for, and the workaround is
one an operator should not have to know: put an address on the monitoring port, which is
what the port is supposed to avoid.

THE REPLACEMENT: listen first. A passive port still SEES the segment's traffic, and that
traffic is enough to learn which addresses are in use, what the prefix is, and who the
gateway is -- from the hosts themselves, with nothing injected. Only then, if a sweep is
still wanted, does it become possible to sweep a segment we have actually observed.

WHAT IS LEARNED, AND FROM WHAT -- each from a frame that was already on the wire:

  * SOURCES, from the layer-3 source of every IPv4 frame (and the sender protocol address
    of ARP, which is what populates a peer's cache).
  * THE PREFIX, from the subnet mask inside DHCP ACKs and Offers (`option 1`), which is
    the only place a passive observer can read the real mask. Falls back to the widest
    common prefix of what was seen, and SAYS which of the two it used -- a guessed mask
    presented as a measured one is the failure this project names most.
  * THE GATEWAY, from the router field of a DHCP ACK (`option 3`) and from the sender of
    gratuitous ARP, which is what a gateway announces itself with.
  * ARP MAPPINGS, from every ARP frame's sender pair, which is how the sensor accumulates
    a view of the segment without asking anything.

WHY NOT JUST LISTEN LONGER AND SKIP THE SWEEP. A sweep proves liveness AT A MOMENT: a host
that is quiet right now still answers an ARP request. Passive learning finds what has SPOKEN
recently, which is the right answer for "who is on this segment" and the wrong one for
"who is there right now". So this is a FIRST PHASE, not a replacement: it makes the segment
knowable, and a sweep over a segment learned this way is then possible and meaningful.

WHAT IT DELIBERATELY DOES NOT DO: send anything. No ARP requests, no DHCP, no probes. The
function takes a socket and reads it, which is also what makes it safe to run on a SPAN port
where transmitting is not even possible.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime

logger = logging.getLogger(__name__)

# Ethernet
ETH_P_IP = 0x0800
ETH_P_ARP = 0x0806
ETH_P_IPV6 = 0x86DD

# The default observation window. Long enough that a quiet /24 almost certainly shows its
# DHCP traffic (a lease is typically renewed well inside an hour, and any new device that
# joins during the window broadcasts), and short enough that an operator waits for it.
# The CLI passes something larger when it can afford to.
DEFAULT_WATCH_S = 60.0

# How often a learned address must be seen before it is trusted as a host rather than a
# stray. ONE frame is enough: an address that emitted traffic EXISTS, and requiring a repeat
# would drop the host that spoke once -- typically the most interesting one.
MIN_FRAMES_FOR_HOST = 1


@dataclass
class SegmentObservations:
    """What watching the wire taught us. Every field says how it was learned, or is empty."""

    iface: str
    # Every IPv4 address seen as a source, with how many frames it sent.
    sources: dict[str, int] = field(default_factory=dict)
    # ARP sender pairs: ip -> mac. Populated from ARP frames only.
    arp_pairs: dict[str, str] = field(default_factory=dict)
    # The mask from a DHCP ACK/Offer, if one was seen. None means NOT OBSERVED.
    observed_mask: str | None = None
    # The gateway from a DHCP ACK's router option, if one was seen.
    observed_gateway: str | None = None
    # Addresses that sent a gratuitous ARP, which is how a gateway announces itself.
    gratuitous: list[str] = field(default_factory=list)
    # VLAN tags seen, for the note that says a trunk port may carry several segments.
    vlans: set[int] = field(default_factory=set)
    frames: int = 0
    # Frames that were IPv4 but could not be parsed. Non-zero means the parser is wrong, so
    # it is reported rather than swallowed.
    unparsed: int = 0
    truncated: bool = False
    # DHCP: whether any was seen at all. Absence is meaningful -- a segment with no DHCP
    # gives no mask and no gateway, and the caller must not read the empty fields as zeroes.
    dhcp_frames: int = 0
    started_at: datetime | None = None
    ended_at: datetime | None = None

    @property
    def mask_source(self) -> str:
        """Where the mask came from, for the report. Never a bare value."""
        if self.observed_mask:
            return "a DHCP reply on this segment (option 1)"
        return ""

    @property
    def gateway_source(self) -> str:
        if self.observed_gateway:
            return "the router field of a DHCP reply (option 3)"
        if self.gratuitous:
            return "gratuitous ARP: the gateway announced itself"
        return ""


def _parse_dhcp_options(payload: bytes) -> dict[int, bytes]:
    """DHCP options from a UDP payload. {} when it is not a well-formed DHCP message.

    THE MAGIC COOKIE IS CHECKED FIRST. Every DHCP option parse is only valid after
    `63 82 53 63`; without that check a UDP frame on port 67 that is not DHCP (a stray
    scanner, a malformed packet) yields nonsense options that then look like a subnet mask.
    A mask of 255.255.255.0 out of a random packet is exactly the plausible-wrong-answer
    this module must not produce.
    """
    if len(payload) < 240 or payload[236:240] != b"\x63\x82\x53\x63":
        return {}
    out: dict[int, bytes] = {}
    i = 240
    while i < len(payload):
        code = payload[i]
        if code == 0:      # pad
            i += 1
            continue
        if code == 255:    # end
            break
        if i + 1 >= len(payload):
            break
        length = payload[i + 1]
        if i + 2 + length > len(payload):
            break
        out[code] = payload[i + 2:i + 2 + length]
        i += 2 + length
    return out


def _observe_frame(frame: bytes, obs: SegmentObservations) -> None:
    """Fold one captured frame into the observations. Never raises: a malformed frame on a
    monitor port must not end the observation."""
    try:
        if len(frame) < 14:
            return
        ethertype = int.from_bytes(frame[12:14], "big")
        offset = 14

        # 802.1Q. A trunk or mirror port can carry tagged frames, and reading the tag as the
        # ethertype yields garbage -- so the tag is consumed and RECORDED, because several
        # VLANs on one port means several segments and the report must say so.
        if ethertype == 0x8100 and len(frame) >= 18:
            vid = int.from_bytes(frame[14:16], "big") & 0x0FFF
            obs.vlans.add(vid)
            ethertype = int.from_bytes(frame[16:18], "big")
            offset = 18

        if ethertype == ETH_P_ARP:
            # ARP: htype(2) ptype(2) hlen(1) plen(1) oper(2) sha(6) spa(4) tha(6) tpa(4)
            #      0        2        4       5       6       8      14     18      24
            # THE TARGET PROTOCOL ADDRESS IS AT 24, NOT 20. Reading it at 20 takes two bytes
            # of the target HARDWARE address and two of the target IP, so the value is
            # nonsense -- and the gratuitous-ARP check compares it against the sender, so it
            # silently never matched. Found by pinning the offsets in a test against a real
            # frame layout rather than trusting the arithmetic I had written from memory.
            if len(frame) < offset + 28:
                obs.unparsed += 1
                return
            arp = frame[offset:offset + 28]
            oper = int.from_bytes(arp[6:8], "big")
            sha = ":".join(f"{b:02x}" for b in arp[8:14])
            spa = str(ipaddress.ip_address(arp[14:18]))
            if sha and sha != "00:00:00:00:00:00" and spa != "0.0.0.0":
                obs.arp_pairs[spa] = sha
                obs.sources[spa] = obs.sources.get(spa, 0) + 1
                # A GRATUITOUS ARP is a request or reply whose target is its own address, or
                # a request for the address it is itself claiming. A gateway announces itself
                # this way at boot and on failover, so it is a real gateway signal.
                tpa = str(ipaddress.ip_address(arp[24:28]))
                if spa == tpa and (oper == 1 or oper == 2) and spa not in obs.gratuitous:
                    obs.gratuitous.append(spa)
            return

        if ethertype != ETH_P_IP:
            return
        if len(frame) < offset + 20:
            obs.unparsed += 1
            return
        ihl = (frame[offset] & 0x0F) * 4
        if ihl < 20 or len(frame) < offset + ihl:
            obs.unparsed += 1
            return
        src = str(ipaddress.ip_address(frame[offset + 12:offset + 16]))
        obs.sources[src] = obs.sources.get(src, 0) + 1

        # DHCP, read for the SUBNET MASK and the ROUTER, which are the only passive source of
        # a real prefix. A DHCP reply arrives from the server to the client (or broadcast),
        # so either port 67 or 68 carrying a message type of Offer (2) or ACK (5).
        proto = frame[offset + 9]
        if proto != 17:
            return
        ihl_off = offset + ihl
        if len(frame) < ihl_off + 8:
            return
        sport = int.from_bytes(frame[ihl_off:ihl_off + 2], "big")
        dport = int.from_bytes(frame[ihl_off + 2:ihl_off + 4], "big")
        if not ({sport, dport} & {67, 68}):
            return
        udp_len = int.from_bytes(frame[ihl_off + 4:ihl_off + 6], "big")
        payload = frame[ihl_off + 8:min(len(frame), ihl_off + udp_len)]
        opts = _parse_dhcp_options(payload)
        if not opts:
            # Port 67/68 traffic whose options did not parse. Counted, not silently ignored:
            # a non-zero count with no mask is how a parser bug is told from an absent DHCP.
            obs.dhcp_frames += 1
            obs.unparsed += 1
            return
        obs.dhcp_frames += 1
        mask = opts.get(1)
        if mask and len(mask) == 4 and obs.observed_mask is None:
            obs.observed_mask = str(ipaddress.ip_address(mask))
        router = opts.get(3)
        if router and len(router) >= 4 and obs.observed_gateway is None:
            obs.observed_gateway = str(ipaddress.ip_address(router[:4]))
    except Exception:  # noqa: BLE001
        # A monitor port sees malformed and hostile traffic by design. One bad frame must
        # never end the observation: the value of this function is the aggregate.
        obs.unparsed += 1


def observe_segment(iface: str, *, seconds: float = DEFAULT_WATCH_S,
                    max_frames: int = 200_000,
                    reader=None) -> SegmentObservations:
    """Watch `iface` for `seconds` and report what the segment is.

    READ-ONLY BY CONSTRUCTION: an AF_PACKET socket opened with ETH_P_ALL is bound and read,
    never written, so this is safe on a SPAN port, a tap, or a mirror port where transmitting
    is not possible at all.

    `reader` is injectable for tests, the same shape `sonar.survey` uses for its sweep: the
    parsing and the reporting are testable against synthetic frames without a live segment.

    Raises SegmentError with a named remedy when the interface cannot be observed.
    """
    obs = SegmentObservations(iface=iface)
    obs.started_at = datetime.now(UTC)
    if reader is None:
        reader = _read_frames

    try:
        for frame in reader(iface, seconds=seconds, max_frames=max_frames, obs=obs):
            obs.frames += 1
            _observe_frame(frame, obs)
    except PermissionError as exc:
        raise SegmentError(
            f"cannot observe '{iface}': opening a capture socket needs NET_RAW. The survey "
            f"job holds it; a process run by hand needs root."
        ) from exc
    except OSError as exc:
        raise SegmentError(
            f"cannot observe '{iface}': {exc}. Check the interface name against the node's "
            f"NICs, and that the port really is mirroring traffic."
        ) from exc

    obs.ended_at = datetime.now(UTC)
    return obs


class SegmentError(RuntimeError):
    """The segment could not be observed. Message names the remedy."""


def _read_frames(iface: str, *, seconds: float, max_frames: int,
                 obs: SegmentObservations) -> list[bytes]:
    """Capture frames from `iface` for a bounded window. Local, because it is the only part
    that needs a socket; everything else is testable without one.

    A NON-BLOCKING READ WITH A DEADLINE, so the window is honoured even on a silent segment:
    a blocking recv on a port with no traffic would hang past the deadline and the operator
    would see a survey that never returns.
    """
    frames: list[bytes] = []
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    try:
        sock.bind((iface, 0))
        sock.settimeout(0.5)
        deadline = time.monotonic() + max(0.1, seconds)
        while time.monotonic() < deadline and len(frames) < max_frames:
            try:
                frames.append(sock.recv(65535))
            except TimeoutError:
                continue
            except OSError:
                # The window ended or the socket was interrupted. Either way the frames
                # already read are real, so return them rather than discarding the work.
                break
    finally:
        sock.close()
    return frames


def derive_network(obs: SegmentObservations) -> tuple[ipaddress.IPv4Network | None, str]:
    """(network, how it was derived) for an observed segment.

    THE MASK IS TAKEN FROM DHCP WHEN ONE WAS SEEN, because that is the only place a passive
    observer can read a REAL mask. Otherwise it is inferred from the widest common prefix of
    the observed addresses, and the answer SAYS it was inferred -- a guessed prefix presented
    as a measured one is the failure this project names most often.

    Returns (None, reason) when nothing was observed. That is NOT an error: a silent segment
    is a real finding, and the caller must say "nothing was heard", never "no hosts".
    """
    addrs: list[ipaddress.IPv4Address] = []
    for a in obs.sources:
        try:
            ip = ipaddress.ip_address(a)
        except ValueError:
            continue
        # isinstance, not `ip.version == 4`: the property check does not narrow the type for
        # the checker under every target version (measured: three errors at a 3.14 target on a
        # tree a 3.12 target accepts), while isinstance states the same boundary in the code
        # and narrows under all of them.
        if isinstance(ip, ipaddress.IPv4Address):
            addrs.append(ip)
    if not addrs:
        return None, ("no IPv4 traffic was observed on this interface, so its segment is "
                      "unknown. Either the port is not mirroring anything, or the segment "
                      "was silent for the whole window.")

    if obs.observed_mask:
        try:
            # THE MASK IS CONVERTED TO A PREFIX LENGTH EXPLICITLY, and the network is built from
            # that. Joining the address and the mask as strings (`f"{anchor}/{mask}"`) makes the
            # RESULT's family follow whichever operand is not IPv4 -- and a mask is often written
            # in a form that parses as an unrelated address, so the network could come back as
            # IPv6 for an IPv4 segment. Taking `prefixlen` off a validated IPv4 mask, then
            # building the network from a validated IPv4 anchor, keeps the family fixed.
            mask_addr = ipaddress.ip_address(obs.observed_mask)
            if mask_addr.version != 4:
                raise ValueError(f"mask {obs.observed_mask} is not IPv4")
            mask_bits = ipaddress.ip_network(f"0.0.0.0/{mask_addr}").prefixlen
            # `addr` rather than `a`: the loop above already binds `a` as a STRING, and reusing
            # the name here rebinds it as an address. mypy caught that as a type error, which is
            # the checker correctly saying these are two different things wearing one name.
            counts: dict[str, int] = {}
            for addr in addrs:
                counts[str(addr)] = counts.get(str(addr), 0) + 1
            anchor = ipaddress.ip_address(max(counts, key=lambda k: counts[k]))
            if anchor.version != 4:
                raise ValueError("anchor is not IPv4")
            net = ipaddress.ip_network(f"{anchor}/{mask_bits}", strict=False)
            if not isinstance(net, ipaddress.IPv4Network):
                raise ValueError("the network is not IPv4")
            if net.prefixlen < 8:
                return None, (
                    f"the observed mask {obs.observed_mask} gives a /{net.prefixlen}, which is "
                    f"too wide to be one segment (and too wide to survey safely). Treating the "
                    f"mask as unreadable rather than trusting it."
                )
            return net, f"the observed mask {obs.observed_mask} (from {obs.mask_source})"
        except ValueError:
            pass

    # No DHCP: the widest common prefix of what was actually seen. Deliberately the widest,
    # because a NARROWER guess would exclude hosts that exist -- and the whole point is to
    # reach the segment, not a subset of it.
    #
    # A DIFFERENT NAME FROM THE DHCP BRANCH'S `prefix`. Reusing it made mypy report the
    # reassignment as an error, which was the type checker correctly pointing out that the two
    # values are different things: one is a mask read off the wire, the other is inferred from
    # addresses that happened to speak. Naming them apart keeps that visible.
    inferred_prefix = max(
        (p for p in range(8, 33)
         if len({ipaddress.ip_network(f"{a}/{p}", strict=False) for a in addrs}) == 1),
        default=None,
    )
    if inferred_prefix is None:
        return None, (
            f"the observed addresses ({', '.join(str(a) for a in sorted(addrs)[:4])}"
            f"{', ...' if len(addrs) > 4 else ''}) share no single prefix wider than /8, so "
            f"they are not one segment. This interface may be mirroring several networks, "
            f"or carrying traffic that is not local."
        )
    inferred = ipaddress.ip_network(f"{addrs[0]}/{inferred_prefix}", strict=False)
    if not isinstance(inferred, ipaddress.IPv4Network):
        # Unreachable while `addrs` holds only IPv4, and stated rather than asserted: the
        # return type is IPv4-only because siphon is IPv4-only, so this is the boundary that
        # keeps a future change to `addrs` from widening the type silently.
        return None, "the observed addresses are not IPv4, so no segment can be derived"
    return inferred, (f"the widest common prefix of {len(addrs)} observed address(es), with NO DHCP "
                 f"reply seen to give a real mask -- so this prefix is INFERRED, not measured, "
                 f"and it may be wider than the true segment")


def summarise(obs: SegmentObservations) -> dict:
    """The report the survey and the GUI both consume.

    Carries `mask_source` and `gateway_source` so a value is never presented without where it
    came from, and `observed` booleans so an empty field is never read as a measurement.
    """
    net, derivation = derive_network(obs)
    gateway = obs.observed_gateway or (obs.gratuitous[0] if obs.gratuitous else "")
    return {
        "iface": obs.iface,
        "frames": obs.frames,
        "unparsed": obs.unparsed,
        "hosts_seen": len(obs.sources),
        "addresses": sorted(obs.sources, key=lambda a: ipaddress.ip_address(a)),
        "arp_pairs": dict(sorted(obs.arp_pairs.items())),
        "segment": str(net) if net else "",
        "segment_derivation": derivation,
        "mask_observed": obs.observed_mask,
        "mask_source": obs.mask_source,
        "gateway": gateway,
        "gateway_source": obs.gateway_source,
        "gateway_observed": bool(gateway),
        "gratuitous": list(obs.gratuitous),
        "vlans": sorted(obs.vlans),
        "dhcp_frames": obs.dhcp_frames,
        "window_s": (
            (obs.ended_at - obs.started_at).total_seconds()
            if obs.started_at and obs.ended_at else None
        ),
        "started_at": obs.started_at.isoformat() if obs.started_at else None,
    }


def notes_for(obs: SegmentObservations, report: dict) -> list[str]:
    """Operator-facing sentences about what the observation does and does not establish.

    Kept beside the report so a reader cannot show the numbers without the qualifications,
    which is how a passive observation gets mistaken for a scan.
    """
    out: list[str] = []
    if obs.frames == 0:
        out.append(
            f"NO traffic was captured on '{obs.iface}' for the whole window. That is a "
            f"measurement, not a failure: either the port is not mirroring or the segment is "
            f"silent. Nothing about the network can be concluded from it."
        )
        return out

    if not obs.dhcp_frames:
        out.append(
            "no DHCP traffic was observed, so the subnet mask and gateway could not be READ. "
            "Anything below is inferred from the addresses that happened to speak."
        )
    if report.get("segment") and not obs.observed_mask:
        out.append(
            f"the segment {report['segment']} is INFERRED (widest common prefix of observed "
            f"addresses), not measured. Treat it as a hint rather than a fact."
        )
    if not report.get("gateway_observed"):
        out.append(
            "no gateway was identified: no DHCP router option and no gratuitous ARP. A "
            "segment without a known gateway cannot be intercepted, because the intercept "
            "has to forge its MAC."
        )
    elif obs.observed_gateway and obs.gratuitous and obs.observed_gateway not in obs.gratuitous:
        out.append(
            f"the DHCP router option says the gateway is {obs.observed_gateway}, and the "
            f"gratuitous ARP came from {obs.gratuitous[0]}. They disagree; check which is "
            f"the real next hop before intercepting."
        )
    if obs.vlans:
        out.append(
            f"{len(obs.vlans)} VLAN tag(s) were seen ({', '.join(str(v) for v in sorted(obs.vlans))}), "
            f"so this port carries several segments. A sweep in one VLAN cannot see the others."
        )
    if obs.unparsed:
        out.append(
            f"{obs.unparsed} frame(s) could not be parsed. Some malformed traffic is normal on "
            f"a monitor port; a LARGE number would mean the parser is wrong rather than the "
            f"traffic being odd."
        )
    out.append(
        "this observation is PASSIVE: nothing was transmitted and nothing was asked. It shows "
        "what has spoken recently, which is not the same as what is alive right now -- a quiet "
        "host that would answer an ARP request is invisible here."
    )
    return out
