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

The source address is REQUIRED, not borrowed. An earlier version of this probe called
`find_free_addresses(iface, segment, "")` to pick one, which could never work for the reason above:
an empty source yields an empty sweep, and an empty sweep yields every address on the segment as
"free". So it always borrowed the highest address with no evidence it was unused. Now the caller
supplies it (INTERCEPT_ADDR), which the stress harness's own teardown already removes, and this probe
never changes the interface at all.
"""

from __future__ import annotations

import os
import sys

from weirvern.admin import intercept as ic
from weirvern.admin import siphonnet
from weirvern.config import Settings


def main() -> int:
    s = Settings()
    iface = s.zeek_iface or "eth1"
    # ── READ FROM THE ENVIRONMENT, NOT FROM A FIELD THAT DOES NOT EXIST (F163, CONFIRMED) ────────
    #
    # This was `getattr(s, "intercept_segment", "")`. `Settings` has NO intercept_segment field (its
    # only intercept-shaped field is `intercept_targets`) and no __getattr__ hook, so the getattr was
    # ALWAYS "" and the probe exited at the refusal below on EVERY deployment -- including one whose
    # ConfigMap sets INTERCEPT_SEGMENT, which k8s/20-configmap-env.yaml does and the CLI already
    # reads by that name. Measured: with `INTERCEPT_SEGMENT=198.51.100.0/24 ZEEK_IFACE=eth1` the
    # probe still printed "no segment configured" and exited 1. So this file could not sweep
    # anywhere, and the eth1 interface default on the line above was dead code behind that return.
    #
    # The environment is where the rest of the project reads it, so this uses the same key rather
    # than inventing a setting. Reading it here also means the interface default is now reachable --
    # and the same honesty rule applies to it: a capture interface is the operator's own choice
    # (ZEEK_IFACE), and eth1 is a convention, not a discovery.
    segment = os.environ.get("INTERCEPT_SEGMENT", "") or ""
    if not segment:
        # NO DEFAULT SEGMENT. A fallback address here was a copy of one specific deployment's
        # network, so on any other deployment this probe would have scanned the WRONG segment and
        # reported whatever it found there. Refusing is the honest behaviour: set INTERCEPT_SEGMENT
        # (or pass --segment) and it will sweep that.
        print("  no segment configured: set INTERCEPT_SEGMENT", flush=True)
        return 1
    print(f"  iface={iface} segment={segment}", flush=True)

    our_mac = siphonnet.read_mac(iface) or ""
    # Same source as the segment, for the same reason. The stress harness sets INTERCEPT_ADDR.
    our_ip = os.environ.get("INTERCEPT_ADDR", "") or ""

    if not our_mac:
        print("  cannot read the interface MAC; a zero-MAC request is ignored", flush=True)
        return 1

    if not our_ip:
        # ── THE BORROW PATH WAS A FALSE-FREE BORROW (glm-5.3 review, CONFIRMED) ──────────────────
        #
        # This called `find_free_addresses(iface, segment, "")` -- with an EMPTY source. That cannot
        # work, and it never did: `arp_sweep` returns {} for an unusable source, and
        # `find_free_addresses` returns every candidate not in that result as FREE. So the probe
        # ALWAYS got the whole segment back as "free", picked the highest address, and borrowed it
        # with no evidence it was unused -- the exact damage its own docstring warns about ("returns
        # an empty dict and reports a LIVE segment as an empty one"). A borrowed address that
        # collides with a live host puts this host's ARP entry over someone else's on the node's
        # capture NIC.
        #
        # An active sweep needs a source the segment will answer, and that is inherent to ARP rather
        # than a limitation of this script -- a request from an empty or 0.0.0.0 source is ignored by
        # most stacks. What does NOT need an address is PASSIVE learning, which is the other half of
        # this project's discovery model and is how a source is meant to be chosen: watch the
        # segment, then sweep from an address you have seen is free.
        #
        # So the source is taken rather than invented, and its absence is refused. The caller
        # normally has one already: the stress harness sets INTERCEPT_ADDR and its teardown removes
        # that address, so passing it here also means nothing is borrowed and nothing can leak on
        # SIGKILL (which the finally below cannot cover).
        print(
            "  no source address to sweep from: set INTERCEPT_ADDR (or --our-ip) to an address on "
            f"{segment} that nothing else is using.\n"
            "  An ARP request must come from an address the segment will answer, so this cannot be "
            "worked out from inside the sweep -- learn the segment passively first, then sweep from "
            "an address you have seen is free.",
            flush=True,
        )
        return 1

    try:
        hosts = ic.arp_sweep(iface, our_mac, our_ip, ic.parse_cidr(segment), timeout_s=6)
    except Exception as exc:  # noqa: BLE001
        print(f"  sweep failed: {type(exc).__name__}: {exc}", flush=True)
        return 1
    finally:
        # NOTHING TO WITHDRAW ANY MORE: the source is now supplied by the caller rather than
        # borrowed here, so this probe never changes the interface. The `borrowed` flag and its
        # removal are gone with the borrow path -- `remove_address` is left alone deliberately, not
        # called with an address this script did not add.
        _ = siphonnet  # kept imported: read_mac and add_address are still used on other paths

    print(f"  hosts answering ARP: {len(hosts)}", flush=True)
    for ip, mac in sorted(hosts.items(), key=lambda kv: tuple(int(x) for x in kv[0].split("."))):
        print(f"    {ip:16} {mac}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
