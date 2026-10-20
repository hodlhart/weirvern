"""DHCP and ARP probes for Sonar.

Two questions a passive capture cannot answer on a quiet segment:

  * WHAT IS THE MASK/GATEWAY?  A DHCPDISCOVER gets an OFFER whose options 1 and 3
    carry the subnet mask and router. This is a real transmission, not a guess.
  * IS THIS ADDRESS FREE?  An ARP probe from 0.0.0.0 (the DHCP duplicate-address
    check) asks the segment whether anybody already owns the candidate.

Both use AF_PACKET and NET_RAW only. Nothing is assigned to the interface, and the
DHCP lease is not accepted: the OFFER is read for its options and abandoned. On a
SPAN/mirror port that cannot transmit, both calls return a named failure instead of
pretending the segment is empty.
"""

from __future__ import annotations

import ipaddress
import random
import socket
import struct
import time
from dataclasses import dataclass

ETH_P_IP = 0x0800
ETH_P_ARP = 0x0806
ETH_P_ALL = 0x0003
BROADCAST = "ff:ff:ff:ff:ff:ff"
ZERO_MAC = "00:00:00:00:00:00"
MAGIC = b"\x63\x82\x53\x63"


class ProbeError(RuntimeError):
    """The probe could not run; the message names the reason."""


def _mac_bytes(mac: str) -> bytes:
    try:
        parts = [int(part, 16) for part in mac.split(":")]
    except (AttributeError, ValueError) as exc:
        raise ProbeError(f"invalid MAC {mac!r}") from exc
    if len(parts) != 6 or any(not 0 <= p <= 255 for p in parts):
        raise ProbeError(f"invalid MAC {mac!r}")
    return bytes(parts)


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


@dataclass(frozen=True)
class DhcpOffer:
    yiaddr: str
    mask: str
    gateway: str
    server: str
    lease_seconds: int

    @property
    def segment(self) -> str:
        return str(ipaddress.ip_network(f"{self.yiaddr}/{self.mask}", strict=False))


def build_discover(our_mac: str, xid: int | None = None) -> tuple[bytes, int]:
    """A broadcast DHCPDISCOVER frame; returns (frame, xid)."""
    mac = _mac_bytes(our_mac)
    xid = int(xid if xid is not None else random.getrandbits(32))

    bootp = struct.pack(
        "!BBBBIHHIIII16s64s128s",
        1, 1, 6, 0, xid, 0, 0x8000,
        0, 0, 0, 0,
        mac + b"\x00" * 10,
        b"", b"",
    )
    options = MAGIC + bytes([
        53, 1, 1,                    # DHCP message type: DISCOVER
        55, 4, 1, 3, 6, 51,           # ask for mask, router, DNS, lease time
        61, 7, 1, *mac,               # client identifier
        255,
    ])
    payload = bootp + options
    udp = struct.pack("!HHHH", 68, 67, 8 + len(payload), 0) + payload
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, 20 + len(udp), random.getrandbits(16), 0,
        64, 17, 0, socket.inet_aton("0.0.0.0"), socket.inet_aton("255.255.255.255"),
    )
    ip = ip[:10] + struct.pack("!H", _checksum(ip)) + ip[12:]
    frame = _mac_bytes(BROADCAST) + mac + struct.pack("!H", ETH_P_IP) + ip + udp
    return frame, xid


def parse_offer(frame: bytes, xid: int) -> DhcpOffer | None:
    """Parse a DHCPOFFER from an Ethernet frame, or None when it is not one."""
    if len(frame) < 42:
        return None
    if int.from_bytes(frame[12:14], "big") != ETH_P_IP:
        return None
    ihl = (frame[14] & 0x0F) * 4
    if len(frame) < 14 + ihl + 8:
        return None
    if frame[14 + 9] != 17:      # UDP
        return None
    udp = 14 + ihl
    sport, dport = struct.unpack("!HH", frame[udp:udp + 4])
    if not (sport == 67 and dport == 68):
        return None
    bootp = udp + 8
    if len(frame) < bootp + 236:
        return None
    if frame[bootp] != 2:        # BOOTREPLY
        return None
    if int.from_bytes(frame[bootp + 4:bootp + 8], "big") != xid:
        return None
    yiaddr = socket.inet_ntoa(frame[bootp + 16:bootp + 20])
    if not yiaddr or yiaddr == "0.0.0.0":
        return None
    options = frame[bootp + 236:]
    if not options.startswith(MAGIC):
        return None
    mask = gateway = server = ""
    lease = 0
    i = len(MAGIC)
    while i < len(options):
        code = options[i]
        if code == 255:
            break
        if code == 0:
            i += 1
            continue
        if i + 1 >= len(options):
            break
        length = options[i + 1]
        value = options[i + 2:i + 2 + length]
        if code == 1 and length == 4:
            mask = socket.inet_ntoa(value)
        elif code == 3 and length >= 4:
            gateway = socket.inet_ntoa(value[:4])
        elif code == 54 and length == 4:
            server = socket.inet_ntoa(value)
        elif code == 51 and length == 4:
            lease = int.from_bytes(value, "big")
        i += 2 + length
    if not mask:
        # A DHCPOFFER without option 1 cannot give a measured prefix; say so.
        return None
    return DhcpOffer(yiaddr, mask, gateway, server, lease)


def dhcp_offer(iface: str, our_mac: str, *, timeout_s: float = 4.0) -> DhcpOffer:
    """Send one DISCOVER and return the first matching OFFER.

    Raises ProbeError when the interface cannot transmit/receive, or when no
    offer arrived. No address is assigned and no lease is accepted.
    """
    frame, xid = build_discover(our_mac)
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    except PermissionError as exc:
        raise ProbeError("DHCP probe needs NET_RAW (the Sonar job holds it)") from exc
    try:
        sock.bind((iface, 0))
        sock.settimeout(0.4)
        try:
            sock.send(frame)
        except OSError as exc:
            raise ProbeError(f"DHCP DISCOVER could not be sent on '{iface}': {exc}") from exc
        deadline = time.monotonic() + max(0.5, timeout_s)
        while time.monotonic() < deadline:
            try:
                reply = sock.recv(2048)
            except (TimeoutError, OSError):
                continue
            offer = parse_offer(reply, xid)
            if offer is not None:
                return offer
        raise ProbeError(
            f"no DHCP offer arrived on '{iface}' within {timeout_s:.0f}s. Either the "
            "segment has no DHCP server, or this port cannot transmit (a SPAN/mirror "
            "port only receives)."
        )
    finally:
        sock.close()


def _arp_request(our_mac: str, source_ip: str, target_ip: str) -> bytes:
    mac = _mac_bytes(our_mac)
    return (
        _mac_bytes(BROADCAST) + mac + struct.pack("!H", ETH_P_ARP)
        + struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1)
        + mac + socket.inet_aton(source_ip)
        + _mac_bytes(ZERO_MAC) + socket.inet_aton(target_ip)
    )


def arp_probe(iface: str, our_mac: str, candidate: str, *,
              timeout_s: float = 1.5) -> str:
    """Probe whether `candidate` is already owned; return its MAC or \"\".

    THE SOURCE IS 0.0.0.0 ON PURPOSE: this is the DHCP duplicate-address-detection
    probe. It asks without claiming the address. A reply for the candidate means
    somebody owns it. No reply is evidence, not proof: a host may be quiet, firewalled
    from ARP, or the port may not transmit -- callers must say which.
    """
    try:
        socket.inet_aton(candidate)
    except OSError as exc:
        raise ProbeError(f"invalid candidate address {candidate!r}") from exc
    frame = _arp_request(our_mac, "0.0.0.0", candidate)
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    except PermissionError as exc:
        raise ProbeError("ARP probe needs NET_RAW (the Sonar job holds it)") from exc
    try:
        sock.bind((iface, 0))
        sock.settimeout(0.4)
        try:
            sock.send(frame)
        except OSError as exc:
            raise ProbeError(f"ARP probe could not be sent on '{iface}': {exc}") from exc
        deadline = time.monotonic() + max(0.3, timeout_s)
        while time.monotonic() < deadline:
            try:
                reply = sock.recv(2048)
            except (TimeoutError, OSError):
                continue
            if len(reply) < 42 or int.from_bytes(reply[12:14], "big") != ETH_P_ARP:
                continue
            if int.from_bytes(reply[20:22], "big") != 2:
                continue
            sender_ip = socket.inet_ntoa(reply[28:32])
            if sender_ip == candidate:
                return ":".join(f"{b:02x}" for b in reply[22:28])
        return ""
    finally:
        sock.close()


def gateway_mac(iface: str, our_mac: str, gateway: str, *, timeout_s: float = 1.5) -> str:
    """Resolve a gateway's MAC with an ARP probe (no address claimed)."""
    frame = _arp_request(our_mac, "0.0.0.0", gateway)
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    except PermissionError as exc:
        raise ProbeError("ARP probe needs NET_RAW (the Sonar job holds it)") from exc
    try:
        sock.bind((iface, 0))
        sock.settimeout(0.4)
        try:
            sock.send(frame)
        except OSError as exc:
            raise ProbeError(f"ARP probe could not be sent on '{iface}': {exc}") from exc
        deadline = time.monotonic() + max(0.3, timeout_s)
        while time.monotonic() < deadline:
            try:
                reply = sock.recv(2048)
            except (TimeoutError, OSError):
                continue
            if len(reply) < 42 or int.from_bytes(reply[12:14], "big") != ETH_P_ARP:
                continue
            if int.from_bytes(reply[20:22], "big") != 2:
                continue
            if socket.inet_ntoa(reply[28:32]) == gateway:
                return ":".join(f"{b:02x}" for b in reply[22:28])
        return ""
    finally:
        sock.close()
