"""The DHCP probe's frame builder and offer parser, without a socket."""
import socket
import struct

from weirvern.admin import dhcp_probe as dp


def _offer_frame(*, xid=0x12345678, yiaddr="192.0.2.50", mask="255.255.255.0",
                 gateway="192.0.2.1", server="192.0.2.2"):
    mac = bytes.fromhex("aabbccddeeff")
    bootp = struct.pack(
        "!BBBBIHHIIII16s64s128s",
        2, 1, 6, 0, xid, 0, 0, 0,
        struct.unpack("!I", socket.inet_aton(yiaddr))[0], 0, 0,
        mac + b"\x00" * 10, b"", b"")
    options = dp.MAGIC + bytes([1, 4]) + socket.inet_aton(mask)
    options += bytes([3, 4]) + socket.inet_aton(gateway)
    options += bytes([54, 4]) + socket.inet_aton(server)
    options += bytes([51, 4, 0, 0, 0x0e, 0x10, 255])
    payload = bootp + options
    udp = struct.pack("!HHHH", 67, 68, 8 + len(payload), 0) + payload
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 1, 0,
                     64, 17, 0, socket.inet_aton(server), socket.inet_aton("255.255.255.255"))
    return (dp._mac_bytes(dp.BROADCAST) + mac + struct.pack("!H", dp.ETH_P_IP)
            + ip + udp)


def test_a_discover_is_a_broadcast_with_the_magic_cookie_and_option_53():
    frame, xid = dp.build_discover("aa:bb:cc:dd:ee:ff", xid=7)
    assert frame[:6] == bytes.fromhex("ffffffffffff")
    assert struct.unpack("!H", frame[12:14])[0] == dp.ETH_P_IP
    assert dp.MAGIC in frame
    assert bytes([53, 1, 1]) in frame


def test_an_offer_yields_the_measured_mask_gateway_and_offered_address():
    offer = dp.parse_offer(_offer_frame(), 0x12345678)
    assert offer is not None
    assert offer.yiaddr == "192.0.2.50"
    assert offer.mask == "255.255.255.0"
    assert offer.gateway == "192.0.2.1"
    assert offer.server == "192.0.2.2"
    assert offer.segment == "192.0.2.0/24"


def test_a_reply_for_another_transaction_is_ignored():
    assert dp.parse_offer(_offer_frame(xid=1), 2) is None
