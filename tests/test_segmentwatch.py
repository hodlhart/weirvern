"""Passive segment learning: reading a segment without an address on it.

THE DEFECT THESE PIN. Sonar derived the segment to survey from the capture interface's own
IPv4 address and netmask. A passive capture port -- a SPAN port, a tap, a mirrored vSwitch
port -- has NO IPv4 address BY DESIGN, because assigning one makes the sensor a participant
on a segment it is meant to observe silently. Measured live: the capture interface carried
only a link-local IPv6 address, and Sonar refused with "has no IPv4 address ... so its
segment cannot be derived".

So the module could not run in the deployment it exists for. The replacement listens first:
a passive port still SEES the segment, and that traffic carries the mask and the gateway.

THE FRAMES BELOW ARE REAL BYTE LAYOUTS, built here rather than captured, so the tests say
exactly which field each assertion rests on. A parser tested against a fixture whose layout
came from the parser's own assumptions proves nothing.
"""

from __future__ import annotations

import ipaddress

import pytest

from weirvern.admin import segmentwatch as sw


def eth(payload: bytes, ethertype: int = sw.ETH_P_IP, vlan: int | None = None) -> bytes:
    """An Ethernet frame. `vlan` inserts an 802.1Q tag, which a trunk/mirror port produces."""
    dst = bytes.fromhex("ffffffffffff")
    src = bytes.fromhex("aabbccddeeff")
    if vlan is not None:
        tag = vlan.to_bytes(2, "big")
        return dst + src + b"\x81\x00" + tag + ethertype.to_bytes(2, "big") + payload
    return dst + src + ethertype.to_bytes(2, "big") + payload


def ipv4(src: str, dst: str, proto: int, payload: bytes) -> bytes:
    """An IPv4 packet with a 20-byte header. Checksums are not filled: nothing here verifies
    them, and computing them would obscure which bytes the test actually asserts on."""
    total = 20 + len(payload)
    hdr = bytes([
        0x45, 0x00,
        (total >> 8) & 0xFF, total & 0xFF,
        0x00, 0x00, 0x40, 0x00, 64, proto, 0x00, 0x00,
    ]) + ipaddress.ip_address(src).packed + ipaddress.ip_address(dst).packed
    return hdr + payload


def udp(sport: int, dport: int, payload: bytes) -> bytes:
    length = 8 + len(payload)
    return (sport.to_bytes(2, "big") + dport.to_bytes(2, "big")
            + length.to_bytes(2, "big") + b"\x00\x00" + payload)


def arp(sha_hex: str, spa: str, tpa: str, *, oper: int = 1,
        tha_hex: str = "000000000000") -> bytes:
    """An ARP frame. htype=1 (Ethernet), ptype=0x0800, hlen=6, plen=4."""
    return (b"\x00\x01\x08\x00\x06\x04" + oper.to_bytes(2, "big")
            + bytes.fromhex(sha_hex) + ipaddress.ip_address(spa).packed
            + bytes.fromhex(tha_hex) + ipaddress.ip_address(tpa).packed)


def dhcp_reply(mask: str, router: str, *, msg_type: int = 5) -> bytes:
    """A DHCP ACK-sized message with options 1 (mask) and 3 (router).

    The magic cookie is present, because that is the ONE thing that distinguishes a real
    DHCP message from a random UDP frame on port 68 -- and the parser relies on it.
    """
    body = bytearray(240)
    body[0] = 2                     # op: BOOTREPLY
    body[236:240] = b"\x63\x82\x53\x63"
    body += bytes([53, 1, msg_type])                       # message type
    body += bytes([1, 4]) + ipaddress.ip_address(mask).packed    # option 1: subnet mask
    body += bytes([3, 4]) + ipaddress.ip_address(router).packed  # option 3: router
    body += bytes([255])
    return bytes(body)


def feed(obs: sw.SegmentObservations, *frames: bytes) -> sw.SegmentObservations:
    for f in frames:
        obs.frames += 1
        sw._observe_frame(f, obs)
    return obs


def watch(*frames: bytes, iface: str = "ens19") -> sw.SegmentObservations:
    """The whole pipeline: frames in, observations out, no socket anywhere."""
    return sw.observe_segment(iface, seconds=0, reader=lambda *a, **k: list(frames))


# ── the defect: a segment with no address on the interface ───────────────────────────────────

def test_an_interface_with_no_ipv4_still_yields_a_segment():
    """THE WHOLE POINT. This is the live SPAN-port case that made Sonar unusable."""
    obs = watch(
        eth(ipv4("198.51.100.5", "198.51.100.20", 6, b"\x00" * 20)),
        eth(ipv4("198.51.100.20", "198.51.100.5", 6, b"\x00" * 20)),
    )
    report = sw.summarise(obs)
    assert report["segment"], "a segment must be derivable with no address on the interface"
    assert report["hosts_seen"] == 2


def test_nothing_observed_is_not_an_empty_segment():
    """A silent port is a MEASUREMENT, and it must not render as "a network with no hosts"."""
    obs = watch()
    report = sw.summarise(obs)
    assert report["frames"] == 0
    assert report["segment"] == ""
    assert "no IPv4 traffic was observed" in report["segment_derivation"]
    assert sw.notes_for(obs, report), "a silent segment must produce an explanation"


# ── the mask: DHCP is the only passive source, and it must be labelled as OBSERVED ───────────

def test_the_mask_comes_from_dhcp_and_is_labelled_as_observed():
    obs = watch(
        eth(ipv4("198.51.100.1", "255.255.255.255", 17, udp(67, 68, dhcp_reply("255.255.255.0",
                                                                              "198.51.100.1")))),
        eth(ipv4("198.51.100.7", "198.51.100.1", 6, b"\x00" * 20)),
    )
    report = sw.summarise(obs)
    assert report["mask_observed"] == "255.255.255.0"
    assert "DHCP" in report["mask_source"], "the source of a value must travel with it"
    assert report["gateway"] == "198.51.100.1"
    assert "DHCP" in report["gateway_source"]


def test_with_no_dhcp_the_prefix_is_marked_INFERRED_not_measured():
    """The distinction the whole project runs on: a guess presented as a measurement is the
    failure named most often. With no DHCP reply, the mask is unknowable and must say so."""
    obs = watch(
        eth(ipv4("198.51.100.5", "198.51.100.20", 6, b"\x00" * 20)),
        eth(ipv4("198.51.100.9", "198.51.100.20", 6, b"\x00" * 20)),
    )
    report = sw.summarise(obs)
    assert report["mask_observed"] is None
    assert "INFERRED" in report["segment_derivation"]
    assert any("INFERRED" in n for n in sw.notes_for(obs, report))


def test_a_random_udp_frame_on_port_68_is_not_mistaken_for_dhcp():
    """THE PLAUSIBLE-WRONG-ANSWER CASE. Without the magic-cookie check, a stray frame on the
    DHCP ports yields option bytes that read as a subnet mask -- and a confident 255.255.255.0
    out of noise is worse than no mask at all."""
    junk = bytes(range(240)) + b"\x01\x04\xff\xff\xff\x00" + b"\xff"
    obs = watch(eth(ipv4("198.51.100.1", "198.51.100.7", 17, udp(68, 67, junk))))
    report = sw.summarise(obs)
    assert report["mask_observed"] is None, "a frame with no magic cookie is not DHCP"
    assert obs.unparsed >= 1


def test_an_absurd_mask_is_refused_rather_than_surveyed():
    """A /2 from a corrupted option would be surveyed as two thirds of the internet, which is
    both useless and unsafe. Refused as unreadable instead."""
    obs = watch(
        eth(ipv4("198.51.100.1", "255.255.255.255", 17, udp(67, 68, dhcp_reply("192.0.0.0",
                                                                              "198.51.100.1")))),
        eth(ipv4("198.51.100.7", "198.51.100.1", 6, b"\x00" * 20)),
    )
    report = sw.summarise(obs)
    assert report["segment"] == "" or ipaddress.ip_network(report["segment"]).prefixlen >= 8


# ── ARP: mappings, and the gateway's self-announcement ───────────────────────────────────────

def test_arp_frames_yield_mappings_without_asking_anything():
    obs = watch(eth(arp("aabbccddeeff", "198.51.100.20", "198.51.100.5"), ethertype=sw.ETH_P_ARP))
    assert obs.arp_pairs == {"198.51.100.20": "aa:bb:cc:dd:ee:ff"}


def test_gratuitous_arp_identifies_a_gateway_with_no_dhcp():
    """How a gateway announces itself at boot and on failover. This is the only gateway
    signal available on a segment where DHCP was never seen."""
    obs = watch(eth(arp("001122334455", "198.51.100.1", "198.51.100.1", oper=2),
                    ethertype=sw.ETH_P_ARP))
    report = sw.summarise(obs)
    assert report["gateway"] == "198.51.100.1"
    assert "gratuitous" in report["gateway_source"]
    assert report["gateway_observed"] is True


def test_a_gateway_that_disagrees_with_dhcp_is_surfaced():
    """Two real signals pointing at different next hops. Averaging or picking silently would
    send an intercept at the wrong MAC, which breaks the segment it was meant to watch."""
    obs = watch(
        eth(ipv4("198.51.100.1", "255.255.255.255", 17, udp(67, 68, dhcp_reply("255.255.255.0",
                                                                              "198.51.100.1")))),
        eth(arp("001122334455", "198.51.100.254", "198.51.100.254", oper=2),
            ethertype=sw.ETH_P_ARP),
    )
    report = sw.summarise(obs)
    notes = " ".join(sw.notes_for(obs, report))
    assert "disagree" in notes, "two conflicting gateway signals must not be silently resolved"


def test_a_zero_sender_is_not_a_host():
    """A DHCP DISCOVER carries 0.0.0.0 as its sender. Counting it as a host would report an
    address that does not exist and can never be swept."""
    obs = watch(eth(arp("aabbccddeeff", "0.0.0.0", "255.255.255.255"), ethertype=sw.ETH_P_ARP))
    assert obs.arp_pairs == {}
    assert obs.sources == {}


def test_a_zero_mac_is_not_a_mapping():
    obs = watch(eth(arp("000000000000", "198.51.100.5", "198.51.100.9"),
                    ethertype=sw.ETH_P_ARP))
    assert obs.arp_pairs == {}


# ── robustness: a monitor port sees malformed traffic by design ──────────────────────────────

def test_a_truncated_frame_does_not_end_the_observation():
    """A monitor port sees malformed and hostile traffic. The value of this function is the
    AGGREGATE, so one bad frame must not discard everything already learned."""
    obs = watch(
        # A runt: shorter than an Ethernet header. Not IPv4 at all, so it is skipped without
        # being counted as a parse FAILURE -- there was nothing to parse.
        b"\x00" * 8,
        eth(b"\x45", ethertype=sw.ETH_P_IP),               # IPv4 header cut off: a real failure
        eth(ipv4("198.51.100.5", "198.51.100.20", 6, b"\x00" * 20)),
    )
    assert obs.frames == 3
    assert obs.unparsed >= 1, "a truncated IPv4 header is a parse failure and must be counted"
    assert "198.51.100.5" in obs.sources, "the good frame must still count"


def test_vlan_tags_are_read_and_reported():
    """A trunk or mirror port carries several segments. Reading the tag as the ethertype
    yields garbage, and one VLAN's sweep cannot see the others -- so it must be stated."""
    obs = watch(
        eth(ipv4("198.51.100.5", "198.51.100.20", 6, b"\x00" * 20), vlan=10),
        eth(ipv4("198.51.100.6", "198.51.100.20", 6, b"\x00" * 20), vlan=20),
    )
    report = sw.summarise(obs)
    assert report["vlans"] == [10, 20]
    assert "VLAN" in " ".join(sw.notes_for(obs, report))


def test_a_frame_claiming_ipv6_is_ignored_rather_than_misparsed():
    obs = watch(eth(b"\x60" * 40, ethertype=sw.ETH_P_IPV6))
    assert obs.sources == {}
    assert obs.unparsed == 0, "IPv6 is out of scope, not malformed -- it must not be counted as a parse failure"


# ── the interface could not be opened: the remedy is named ───────────────────────────────────

def test_a_permission_failure_names_NET_RAW():
    def deny(*a, **k):
        raise PermissionError("Operation not permitted")

    with pytest.raises(sw.SegmentError) as e:
        sw.observe_segment("ens19", seconds=0, reader=deny)
    assert "NET_RAW" in str(e.value)


def test_a_bad_interface_names_the_interface():
    def fail(*a, **k):
        raise OSError("No such device")

    with pytest.raises(sw.SegmentError) as e:
        sw.observe_segment("ens99", seconds=0, reader=fail)
    assert "ens99" in str(e.value)


# ── the honest qualifications ────────────────────────────────────────────────────────────────

def test_the_report_says_it_was_passive():
    """A passive observation is not a scan, and the difference is what an operator acts on:
    a host that is quiet right now is invisible here but would answer an ARP request."""
    obs = watch(eth(ipv4("198.51.100.5", "198.51.100.20", 6, b"\x00" * 20)))
    notes = " ".join(sw.notes_for(obs, sw.summarise(obs)))
    assert "PASSIVE" in notes
    assert "alive right now" in notes


def test_no_gateway_found_says_interception_is_impossible():
    """An intercept has to forge the gateway's MAC. Saying so here prevents a survey that
    recommends a plan which cannot be carried out."""
    obs = watch(eth(ipv4("198.51.100.5", "198.51.100.20", 6, b"\x00" * 20)))
    report = sw.summarise(obs)
    assert report["gateway_observed"] is False
    assert "cannot be intercepted" in " ".join(sw.notes_for(obs, report))


def test_unparsed_frames_are_reported_rather_than_swallowed():
    obs = watch(eth(b"\x45", ethertype=sw.ETH_P_IP))
    report = sw.summarise(obs)
    assert report["unparsed"] >= 1
    assert any("could not be parsed" in n for n in sw.notes_for(obs, report))


def test_the_window_is_reported_so_a_short_observation_is_visible():
    obs = watch(eth(ipv4("198.51.100.5", "198.51.100.20", 6, b"\x00" * 20)))
    report = sw.summarise(obs)
    assert report["window_s"] is not None
    assert report["started_at"] is not None
