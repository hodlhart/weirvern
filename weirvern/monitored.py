"""Which addresses are OURS: the networks this deployment monitors, and nothing else.

WHY THIS EXISTS. An asset inventory is a list of things the operator is responsible for, and a
scanner's target list is a list of things it is allowed to touch. Both were built from "every
address that appeared on the wire", so the inventory filled with external peers -- CDNs, torrent
swarm members, DNS resolvers -- and the scanner's scope came from a second source (the weirling
registry) that could disagree with the operator's own `network_scopes` table.

The rule is now one rule with one source: `network_scopes` rows with `monitored = 1`. Anything
outside them is a PEER, not an asset, and is never a scan target. External addresses stay visible
in the flow, discovery and graph views, where they belong; they are simply not ours.

AN EMPTY LIST IS NOT A LICENCE. If no monitored network can be read, `sql_predicate` returns a
predicate that matches NOTHING and `in_scope` returns False, because "we could not work out what
we own" must never degrade into "scan everything".
"""
from __future__ import annotations

import ipaddress
import logging
from typing import Any

logger = logging.getLogger(__name__)


def networks(client: Any) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """The monitored networks, from the operator's own scope table.

    A row that does not parse as a CIDR is skipped with a log line rather than crashing the view:
    the table is operator-editable and one typo must not take the inventory down. Rows with
    `monitored = 0` are deliberately excluded -- that column exists to say "we can see this
    traffic but it is not ours", which is exactly the distinction this module enforces.
    """
    try:
        rows = client.query(
            "SELECT cidr FROM weirvern.network_scopes WHERE monitored = 1"
        ).result_rows
    except Exception as exc:  # noqa: BLE001 - an unreadable scope list is not permission
        logger.warning("monitored networks could not be read: %s", exc)
        return []
    out: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for row in rows or []:
        raw = str((row or [""])[0] or "").strip()
        if not raw:
            continue
        try:
            net = ipaddress.ip_network(raw, strict=False)
        except ValueError:
            logger.info("monitored networks: %r is not a CIDR; skipped", raw)
            continue
        if net not in out:
            out.append(net)
    return out


def in_scope(addr: str, nets: list[ipaddress.IPv4Network | ipaddress.IPv6Network]) -> bool:
    """True only when this address is inside one of OUR networks."""
    try:
        ip = ipaddress.ip_address(str(addr or "").strip())
    except ValueError:
        return False
    return any(ip in net for net in nets if net.version == ip.version)


def sql_predicate(column: str, nets: list[ipaddress.IPv4Network | ipaddress.IPv6Network]) -> str:
    """A ClickHouse fragment that is true only for addresses inside a monitored network.

    Returns `0` (matches nothing) when there is no scope, so a caller that forgets to check can
    only under-report, never over-reach.
    """
    if not nets:
        return "0"
    tests = [f"isIPAddressInRange({column}, '{net}')" for net in nets]
    return "(" + " OR ".join(tests) + ")"


def summary(nets: list[ipaddress.IPv4Network | ipaddress.IPv6Network]) -> dict[str, Any]:
    """What the view says out loud about the filter it applied."""
    return {
        "networks": [str(n) for n in nets],
        "enforced": True,
        "rule": ("assets and scan targets are limited to networks flagged monitored in "
                 "network_scopes; every other address is a peer, not an asset"),
    }
