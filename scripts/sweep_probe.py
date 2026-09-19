"""Sweep the capture segment and report every host that answers.

RUN INSIDE THE WORKER POD (which is `hostNetwork: true`, so it shares the host's eth1) because
that is where the capture NIC and CAP_NET_RAW live. A sweep from anywhere else tests a different
path than the one under test.

`our_ip` MUST be a real address on the segment, and `our_mac` must be the interface's own MAC. A
request sourced from 0.0.0.0 or sent from a zero MAC is ignored by most stacks, so the sweep
returns an empty dict and reports a LIVE segment as an empty one. An earlier version of this probe
passed empty strings and reported "0 hosts answering ARP" for a segment whose gateway answered 3/3
pings one command later. That false negative is the exact trap `arp_sweep` documents, and it is
worth repeating here because an instrument that reports an empty network is very convincing.

The borrowed address is withdrawn in a `finally`, so this never leaves one behind.
"""

from __future__ import annotations

import sys

from weirvern.admin import intercept as ic
from weirvern.admin import weirnet
from weirvern.config import Settings


def main() -> int:
    s = Settings()
    iface = s.zeek_iface or "eth1"
    segment = getattr(s, "intercept_segment", "") or "192.168.3.0/24"
    print(f"  iface={iface} segment={segment}", flush=True)

    our_mac = weirnet.read_mac(iface) or ""
    our_ip = getattr(s, "intercept_addr", "") or ""
    borrowed = False

    if not our_mac:
        print("  cannot read the interface MAC; a zero-MAC request is ignored", flush=True)
        return 1

    if not our_ip:
        # Borrow a free address, exactly as the intercept does: the capture interface normally has
        # no address of its own, and without a source the segment will not answer.
        try:
            free = weirnet.find_free_addresses(iface, segment, "")
        except Exception as exc:  # noqa: BLE001
            print(f"  could not look for a free address: {type(exc).__name__}: {exc}", flush=True)
            return 1
        our_ip = free[0] if free else ""
        if not our_ip:
            print("  no free address found on the segment", flush=True)
            return 1
        rc, out = weirnet.add_address(iface, our_ip, segment)
        if rc != 0:
            print(f"  could not assign {our_ip}: rc={rc} {out}", flush=True)
            return 1
        borrowed = True
        print(f"  borrowed {our_ip} for the sweep (withdrawn below)", flush=True)

    try:
        hosts = ic.arp_sweep(iface, our_mac, our_ip, ic.parse_cidr(segment), timeout_s=6)
    except Exception as exc:  # noqa: BLE001
        print(f"  sweep failed: {type(exc).__name__}: {exc}", flush=True)
        return 1
    finally:
        if borrowed:
            weirnet.remove_address(iface, our_ip, segment)
            print(f"  withdrew {our_ip}", flush=True)

    print(f"  hosts answering ARP: {len(hosts)}", flush=True)
    for ip, mac in sorted(hosts.items(), key=lambda kv: tuple(int(x) for x in kv[0].split("."))):
        print(f"    {ip:16} {mac}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
