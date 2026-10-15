"""SLUICE GATE: operator-controlled traffic blocking, and why it fails OPEN.

A WEIR HOLDS WATER BACK; A SLUICE GATE DECIDES WHAT PASSES. Weirvern already SEES everything; this
is the part that can stop it. The gate is a decision point an operator opens and closes, not a
wall, and every decision it makes is recorded.

WHAT THIS IS. An operator picks addresses, a destination or a port; the sensor enforces it in the
kernel; every block is recorded with the rule that caused it.

WHY IT FAILS OPEN, AND WHY THAT IS CORRECT HERE.

Weirvern is a MONITORING APPLIANCE an operator has been persuaded to put IN LINE with their
network. That is already a large ask. A gate that stays shut when its supervisor dies, its rules
fail to compile, or the database becomes unreachable would turn a monitoring tool into an outage:
the network would keep working only until the thing watching it had a bad day. Nobody deploys that
twice.

So the invariant is inverted from a firewall's:

    ENFORCEMENT REQUIRES A LIVE, HEALTHY SUPERVISOR ON EVERY PASS. If control is lost, the gate
    OPENS and the reported state is DEGRADED with the reason.

This is safe because of what the gate is for. It is not the network's security boundary -- the
firewall is. It is an INCIDENT RESPONSE tool: an analyst sees something on the wire and wants it to
stop NOW, without a change request. Losing the block degrades from "stopped" to "watched and
alerted", which is what the appliance was already doing.

It is not safe BY ACCIDENT, and the code makes that explicit: `arm()` re-evaluates expiry on every
pass, a failure is never reported as ARMED, and `healthy()` distinguishes "holding" from "held the
last time anyone asked".

WHY THE KERNEL AND NOT USERSPACE. This runs on the same host that relays siphon traffic, so
anything in the data path costs the network throughput. An nftables set lookup is a hash probe in
the kernel's packet path; a userspace filter would copy every packet through a process and back.
The enforcement layer therefore compiles rules into kernel objects and never sees a packet.

WHAT IS DELIBERATELY NOT HERE.
  - No permanent blocks. Every rule carries an expiry, enforced in the schema AND again here,
    because a bound that one layer forgets is not a bound.
  - No blocking of the management interface, or of the sensor's own address. Refused at authoring
    time with a sentence, rather than locking the operator out of the appliance.
  - No "block everything that looks bad" mode. A derived rule names the detection that justified
    it, and the GUI shows that evidence beside the block so an analyst can disagree with it.

TWO DEFECTS IN THIS MODULE WERE FOUND ONLY BY RUNNING IT AGAINST A REAL KERNEL, and both are
pinned by tests because a reviewer reading the code could not have seen either:

  1. The first compiler emitted the SET DECLARATIONS and never the elements. The ruleset installed,
     `nft -f` exited 0, the read-back found the table -- and the gate blocked nothing.
  2. nft's interval sets REJECT a ruleset whose elements overlap. `198.51.100.0/24` together with
     `198.51.100.7/32` is "conflicting intervals specified" and NOTHING is installed. Overlap is
     the ordinary case: block a scanner's subnet, then one host inside it.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import re
import shutil
import subprocess
import time
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from typing import Any

logger = logging.getLogger(__name__)

# ── constants ─────────────────────────────────────────────────────────────────────────────────

# An empty predicate means "this does not apply". Addresses may be a host or a CIDR; the parser is
# strict and raises, because a rule that silently matched everything would block the network
# rather than a target.
_CIDR = re.compile(r"^[0-9a-fA-F:.]+(/\d{1,3})?$")

PROTOCOLS = ("tcp", "udp", "icmp", "any")
DIRECTIONS = ("forward", "in")

GATE_STATE_ARMED = "armed"
GATE_STATE_DISARMED = "disarmed"
GATE_STATE_DEGRADED = "degraded"

# A table of our own, so teardown is one delete and a foreign ruleset cannot be damaged by mistake.
# A namespaced name because a host may run other tooling.
NFT_TABLE = "weirvern_sluice"
NFT_SET_V4 = "sluice_block_v4"
NFT_SET_V6 = "sluice_block_v6"
# Direction 'in' rules hook INPUT rather than FORWARD, so they live in a second table. Keeping them
# apart is what stops a relay rule from blocking the operator's own session.
NFT_TABLE_IN = f"{NFT_TABLE}_in"

# A set is a lookup regardless of how many members it holds, whereas one nft rule per address is a
# linear walk of the chain. This cap exists because the whole set is loaded in ONE transaction: a
# partial load would leave the gate half-armed, which is worse than a refusal.
MAX_SET_MEMBERS = 65536


class SluiceError(Exception):
    """A rule could not be authored or compiled. Always carries the reason an operator needs."""


# ── module helpers (defined before the classes that bind them at import time) ─────────────────


def collapse_networks(members: list[str]) -> list[str]:
    """Merge addresses/CIDRs into a sorted, minimal, DISJOINT list.

    nft's interval sets refuse to load when two elements overlap -- and they refuse the WHOLE
    ruleset, not just the offending element, so nothing is installed at all while the caller
    believes it armed. Overlap is not an edge case: blocking a scanner's /24 and then one host
    inside it is the ordinary way an operator builds a list.

    The merge is the standard interval union: sort by (network address, prefix length) so a larger
    network precedes the smaller ones it contains, then walk once, skipping any member already
    covered by the last one kept. Sorting by address alone is not enough -- the /24 and the /32
    share no prefix lexically, and the /24 (which starts earlier) must come first.

    Merging must NOT extend to neighbours: 192.0.2.1/32 and 192.0.2.2/32 must stay separate, or a
    /31 would block an address the operator never named.
    """
    nets: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for raw in members:
        try:
            nets.append(ipaddress.ip_network(raw, strict=False))
        except ValueError:
            # A member that will not parse cannot be enforced. Dropping it silently would leave a
            # rule the operator believes is in force, so it is named in the log. The authoring
            # path (`parse_cidr`) already refuses these, so reaching here means a hand-written row.
            logger.warning("sluice: ignoring unparseable set member %r", raw)
    nets.sort(key=lambda n: (int(n.network_address), n.prefixlen))
    out: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for net in nets:
        # Mixed families cannot be nested, so `subnet_of` would raise on a v4/v6 pair. Comparing
        # the version first is cheaper than catching that, and keeps the intent visible.
        if out and net.version == out[-1].version and net.subnet_of(out[-1]):  # type: ignore[arg-type]
            continue
        out.append(net)
    return [str(n) for n in out]


def _nft_run(args: list[str], stdin: str | None = None,
             capture: bool = False) -> tuple[bool, str]:
    """Run nft. Isolated so the backend can be driven without a kernel in tests."""
    try:
        proc = subprocess.run(  # noqa: S603
            args, input=stdin, capture_output=True, text=True, timeout=15, check=False
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return False, str(exc)
    out = (proc.stdout or "") + (proc.stderr or "")
    if proc.returncode != 0:
        return False, out.strip()
    return True, out if capture else ""


def _nft_can_write() -> bool:
    """Whether this process can install a ruleset.

    A WRITE PROBE is the only honest test: `nft list ruleset` needs no privilege and would report
    success on a host where enforcement is impossible. The probe uses a table name nothing else
    uses and removes it immediately, so a failure cannot leave state behind.
    """
    if not shutil.which("nft"):
        return False
    if not _nft_run(["nft", "-f", "-"], stdin="table inet weirvern_probe { }\n")[0]:
        return False
    _nft_run(["nft", "delete", "table", "inet", "weirvern_probe"], capture=True)
    return True


# ── the shape of a rule ───────────────────────────────────────────────────────────────────────


@dataclass
class Rule:
    """One blocking decision, in the shape the enforcement layer consumes."""

    rule_id: str
    src_cidr: str = ""
    dst_cidr: str = ""
    protocol: str = ""
    dst_port: int = 0
    direction: str = "forward"
    expires_at: datetime | None = None
    created_by: str = ""
    reason: str = ""
    origin: str = "manual"
    origin_ref: str = ""
    severity: str = ""
    revoked_at: datetime | None = None

    def is_live(self, now: datetime | None = None) -> bool:
        """Whether this rule should be enforced RIGHT NOW.

        Expiry is checked HERE as well as in the schema, deliberately. A rule a failed cleanup left
        behind would otherwise keep blocking forever, and the operator's only clue would be a
        network that stopped working. A bound checked at use is a bound.
        """
        if self.revoked_at is not None:
            return False
        if self.expires_at is None:
            # Not reachable through the API (the schema forbids it) but reachable through a manual
            # INSERT. Treat "no bound" as INERT rather than infinite: refusing to enforce is the
            # safe direction for an unbounded rule.
            logger.warning("sluice rule %s has no expiry; treating it as inert", self.rule_id)
            return False
        now = now or datetime.now(UTC)
        exp = self.expires_at
        if exp.tzinfo is None:
            # ClickHouse can hand back naive values. Comparing naive to aware RAISES, and a rule
            # that fails to compare would silently stop being enforced -- so the naive value is
            # anchored to UTC, which is how it was stored.
            exp = exp.replace(tzinfo=UTC)
        return exp > now

    def describes(self) -> str:
        """A one-line human summary, for the audit row and the GUI table."""
        parts = []
        if self.src_cidr:
            parts.append(f"from {self.src_cidr}")
        if self.dst_cidr:
            parts.append(f"to {self.dst_cidr}")
        if self.dst_port:
            parts.append(f"{self.protocol or 'tcp'}/{self.dst_port}")
        return " ".join(parts) or "(no predicate)"

    def snapshot(self) -> str:
        """What this rule WAS, copied into an event row at enforcement time.

        A rule can be edited or revoked later; the event must still say what was in force when it
        fired, or the history is rewritten by every subsequent edit.
        """
        return json.dumps({
            "rule_id": self.rule_id,
            "src_cidr": self.src_cidr,
            "dst_cidr": self.dst_cidr,
            "protocol": self.protocol,
            "dst_port": self.dst_port,
            "direction": self.direction,
            "reason": self.reason,
            "origin": self.origin,
        }, sort_keys=True)

    def matches(self, src: str, dst: str, proto: str, port: int) -> bool:
        """Whether a flow matches. Used by `--dry-run` and the tests.

        The LIVE path does not call this: it pushes the predicates into a kernel set. This exists
        so the semantics are testable without a kernel, and it must agree with the compiler -- a
        dry-run that predicts a block the ruleset would not perform is worse than no dry-run.
        """
        if not self._addr_in(self.src_cidr, src):
            return False
        if not self._addr_in(self.dst_cidr, dst):
            return False
        if self.protocol and self.protocol != "any" and proto.lower() != self.protocol:
            return False
        # A rule with no port applies to every port; one with a port applies to that port only.
        return not (self.dst_port and port != self.dst_port)

    @staticmethod
    def _addr_in(cidr: str, addr: str) -> bool:
        if not cidr:
            return True
        try:
            return ipaddress.ip_address(addr) in ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            return False


@dataclass
class GateState:
    """What the gate is doing, in words an operator can act on."""

    state: str = GATE_STATE_DISARMED
    iface: str = ""
    mgmt_iface: str = ""
    rules_active: int = 0
    rules_total: int = 0
    packets_blocked: int = 0
    bytes_blocked: int = 0
    detail: str = ""
    backend: str = ""
    backend_expected: str = "nft"
    # WHICH VERIFIED PATH IS ENFORCING: 'channel' (in line, physically), 'siphon' (ARP redirect
    # with LIVE intercept evidence), 'none' (rules installed, no verified path), or '' (no
    # verdict was taken). "Is this gate doing anything" depends on it; see admin/channel.py and
    # schema/013_channel.sql.
    enforcement: str = ""

    @property
    def holding(self) -> bool:
        """Whether the gate is actually enforcing. NOT the same as 'armed' having been requested."""
        return self.state == GATE_STATE_ARMED


# ── authoring: the refusals that keep an operator out of trouble ──────────────────────────────


def parse_cidr(token: str, what: str) -> str:
    """Validate an address or CIDR, returning its normal form.

    Strict on purpose. A mistyped rule that matched NOTHING is a silent no-op; a mistyped rule that
    matched EVERYTHING takes the network down. So an unrecognised token raises with the token
    quoted, rather than being coerced or ignored.
    """
    token = (token or "").strip()
    if not token:
        return ""
    if not _CIDR.match(token):
        raise SluiceError(
            f"{what} {token!r} is not an address or CIDR "
            "(expected e.g. 198.51.100.7 or 198.51.100.0/24)"
        )
    try:
        net = ipaddress.ip_network(token, strict=False)
    except ValueError as exc:
        raise SluiceError(f"{what} {token!r} is not a valid network: {exc}") from exc
    # A host address is returned as a /32 or /128 so the two are never confused downstream.
    if net.num_addresses == 1:
        return f"{net.network_address}/{net.max_prefixlen}"
    return str(net)


def refuse_reason(*, src_cidr: str, dst_cidr: str, iface: str, mgmt_iface: str,
                  sensor_addrs: list[str], protocol: str, dst_port: int,
                  direction: str = "forward") -> str:
    """Why this rule must NOT be created, or empty when it is acceptable.

    Every refusal here is a rule that would have been a mistake an operator could plausibly make,
    and each names the fix. Returns a sentence rather than raising so the API can show several
    reasons at once; the caller decides whether to refuse.
    """
    if not src_cidr and not dst_cidr:
        return (
            "a rule needs at least one address: a source, a destination, or both. "
            "A rule with neither would block everything on the segment."
        )
    if src_cidr and dst_cidr:
        return (
            "a rule names a source OR a destination, not both: a source rule installs as "
            "\"everything from that source\" (scoped to a port if one is set), so a "
            "combined rule would block more than it says. Block the source or the "
            "destination; to scope one service, use the port field."
        )
    if direction == "in" and not src_cidr:
        return (
            "an inbound rule blocks traffic FROM a source arriving at this sensor; a "
            "destination-only inbound rule would match nothing while reading as enforced. "
            "Give it a source."
        )
    if dst_port and not protocol:
        return (
            "a port is only meaningful with a protocol: set protocol to tcp or udp, "
            "or drop the port."
        )
    if protocol and protocol not in PROTOCOLS:
        return f"protocol must be one of {', '.join(PROTOCOLS)} (got {protocol!r})."
    if protocol == "icmp" and dst_port:
        return "icmp has no ports; drop the port or choose tcp/udp."

    if iface and mgmt_iface and iface == mgmt_iface:
        return (
            f"the gate cannot be armed on the management interface ({iface}); blocking there "
            "would cut off whoever administers this appliance. Choose the capture interface."
        )

    # THE SELF-BLOCK CHECK. The sensor's own addresses must never be a block target: an operator
    # blocking a scanner by pasting an address they saw in the GUI can easily paste their own.
    for addr in sensor_addrs:
        if not addr:
            continue
        for cidr, what in ((src_cidr, "source"), (dst_cidr, "destination")):
            if not cidr:
                continue
            try:
                if ipaddress.ip_address(addr) in ipaddress.ip_network(cidr, strict=False):
                    return (
                        f"the {what} {cidr} contains {addr}, which is this sensor's own address. "
                        "Blocking it would cut the sensor off from the network it is watching."
                    )
            except ValueError:
                continue

    # A rule covering the whole of IPv4 or IPv6 is almost always a paste error, and it is the
    # single most damaging one available.
    for cidr, what in ((src_cidr, "source"), (dst_cidr, "destination")):
        if cidr.endswith("/0"):
            return (
                f"{cidr} as the {what} covers the entire internet. If that is genuinely intended, "
                "block a smaller range or use the detection-driven policy instead."
            )
    return ""


# ── the enforcement backends ──────────────────────────────────────────────────────────────────


class Backend:
    """A way of putting rules into the kernel. Separated so the policy is testable without one."""

    name = "none"

    def available(self) -> bool:
        return False

    def arm(self, rules: list[Rule], *, iface: str) -> tuple[bool, str]:
        """Install rules. Returns (ok, detail). Must be idempotent."""
        return False, "no backend"

    def disarm(self) -> tuple[bool, str]:
        return False, "no backend"

    def counters(self) -> tuple[int, int]:
        """(packets, bytes) blocked, as the kernel counts them. (0, 0) when unknown."""
        return 0, 0


class NftBackend(Backend):
    """nftables, compiled into sets.

    WHY SETS. A blocklist compiled as one nft rule per address is a linear walk of the chain for
    every packet, so its cost grows with the list -- 500 addresses would be 500 comparisons for
    every packet on the wire. A `set` with `flags interval` is a lookup with no meaningful growth.

    ── MEASURED: WHAT THE GATE COSTS, AND WHAT IS TOO NOISY TO CLAIM ──────────────────────────

    scripts/bench_sluice_cost.py measures this on a real forwarded path (two network namespaces on
    two subnets, routed by the host) with iperf3, three runs per configuration. Two full runs,
    taken back to back on the same node:

        configuration                        run 1    run 2
        baseline (no gate)                   120.0    119.0   Gbit/s
        10 members, no input rules           109.2    115.7
        240 members, no input rules          109.2    116.0
        240 members + 1 input port rule      108.7    114.1
        240 members + 25 input port rules    109.0    115.7
        240 members + 100 input port rules   109.8    108.7

    TWO THINGS ARE STABLE ACROSS BOTH RUNS, and those are the only ones stated as findings:

      * THE MEMBER COUNT DOES NOT MATTER. 10 members and 240 members are indistinguishable in both
        runs. That is the property the sets buy, and it is what makes a large blocklist viable:
        the kernel's per-packet work tracks the number of RULES, not the number of addresses.
      * The cost is SMALL in absolute terms -- single-digit percent of a >100 Gbit/s path.

    WHAT IS NOT CLAIMABLE, and this matters more than the numbers: the two runs disagree by up to
    6 percentage points on the SAME configuration, which is larger than the differences being
    attributed. Run 1 has the 100-input-rule case as the FASTEST gate configuration; run 2 has it
    as the slowest. So no per-configuration cost is asserted here -- an earlier version of this
    comment quoted "~3%" and "~3% at 20000 entries" from a single set of runs, which is a precision
    this environment does not support. Resolving a 2% effect here would need many more samples per
    configuration, and the honest statement is the one above.

    WHY THAT IS WORTH WRITING DOWN RATHER THAN QUIETLY DROPPING: an operator deciding whether to
    enable the gate on a production segment needs to know the order of magnitude, and needs to know
    when a number is a measurement and when it is noise. The input chain evaluates up to one rule
    per configured port, in order, for packets addressed to this host -- that is a real scaling
    property, it is visible in the configuration, and it is not resolvable on this path.

    And enforcement was verified separately, which needs no statistics: with the source in the set
    the transfer FAILS, and after teardown it succeeds again. Load, drop, unload.

    THE FIRST RUN OF THE HARNESS MEASURED NOTHING AND LOOKED LIKE A CATASTROPHE. Every
    configuration reported "no transfer", baseline included, because k3s sets
    `iptables -P FORWARD DROP` on the node -- the same defect this project found in siphon mode,
    where relayed LAN traffic is discarded before any nft hook is reached. Read as a performance
    result it would have said the gate costs 100% of throughput. The harness now inserts the
    interface-scoped ACCEPTs that the product itself reports, and PROVES the path carries traffic
    with a ping before measuring anything.


    A NOTE ON WHAT THESE NUMBERS ARE NOT. They are a veth test on one host, not a production
    segment. They establish that the gate imposes no MEMBER-COUNT-dependent penalty and that it is
    not the bottleneck -- and they do not resolve a per-configuration percentage, as the two runs
    above show. A throughput figure for a real network would be governed by the NIC and the switch,
    and would need to be measured there.
    """

    name = "nft"

    def __init__(self, runner: Any = None) -> None:
        # Injectable so tests can drive the compiled ruleset without touching a kernel.
        self._run = runner or _nft_run

    def available(self) -> bool:
        return bool(shutil.which("nft")) and _nft_can_write()

    def _base_ruleset(self, rules: list[Rule], iface: str) -> str:
        """Compile rules into an nft ruleset. Pure text in, text out -- testable without a kernel.

        THE BUG THIS FUNCTION EXISTS IN ITS SECOND FORM TO AVOID. The first version collected
        addresses into per-family lists, emitted the SET DECLARATIONS and never the elements -- so
        the ruleset compiled, the table existed, the read-back passed, and the gate blocked
        NOTHING. Hence the test that every live rule appears in the output.
        """
        # ── THE COMPILER REFUSES WHAT IT CANNOT EXPRESS (review round 2026-10-15) ────────────
        #
        # A rule naming BOTH a source and a destination used to take the source branch below, so
        # "from X to Y:443" compiled to "from X, dport 443" -- an over-block, the dangerous
        # direction for a gate, while describes() and the dry-run's matches() both described the
        # narrower rule. Authoring refuses it now (refuse_reason + create_rule); this pass refuses
        # it AGAIN because a hand-written row must not compile into something wider than it says.
        # The same goes for an inbound rule without a source, which _in_split would drop silently
        # while the rule still reads as enforced.
        for r in rules:
            if r.src_cidr and r.dst_cidr:
                raise SluiceError(
                    f"rule {r.rule_id}: a rule with both a source and a destination cannot "
                    "be compiled by this backend; refused rather than installed as a wider block"
                )
            if r.direction == "in" and not r.src_cidr:
                raise SluiceError(
                    f"rule {r.rule_id}: an inbound rule without a source cannot be compiled; "
                    "refused rather than dropped silently"
                )
        v4: list[str] = []
        v6: list[str] = []
        port_v4: dict[tuple[str, int], list[str]] = {}
        port_v6: dict[tuple[str, int], list[str]] = {}
        dst_rules: list[Rule] = []
        inbound: list[Rule] = []

        for r in rules:
            if r.direction == "in":
                inbound.append(r)
                continue
            if r.src_cidr:
                try:
                    net = ipaddress.ip_network(r.src_cidr, strict=False)
                except ValueError:
                    continue
                if r.dst_port:
                    key = (r.protocol if r.protocol in ("tcp", "udp") else "tcp", r.dst_port)
                    (port_v4 if net.version == 4 else port_v6).setdefault(key, []).append(
                        r.src_cidr
                    )
                elif net.version == 4:
                    v4.append(r.src_cidr)
                else:
                    v6.append(r.src_cidr)
            elif r.dst_cidr:
                dst_rules.append(r)

        def _set(name: str, family: str, members: list[str]) -> str:
            # Members are COLLAPSED first: nft rejects a ruleset whose interval elements overlap,
            # and rejects the WHOLE ruleset, so nothing gets installed. See collapse_networks.
            body = f"  set {name} {{ type {family}; flags interval"
            merged = collapse_networks(members)
            if merged:
                body += "; elements = { " + ", ".join(merged) + " }"
            # An empty set is still declared: the chain references it unconditionally, and nft
            # rejects a reference to a set that does not exist.
            return body + "; }"

        lines: list[str] = [
            f"# weirvern sluice gate, armed on {iface} at {datetime.now(UTC):%FT%TZ}",
            f"table inet {NFT_TABLE} {{",
            _set(NFT_SET_V4, "ipv4_addr", v4),
            _set(NFT_SET_V6, "ipv6_addr", v6),
        ]
        for (proto, port), members in sorted(port_v4.items()):
            lines.append(_set(f"port_{proto}_{port}", "ipv4_addr", members))
        for (proto, port), members in sorted(port_v6.items()):
            lines.append(_set(f"port6_{proto}_{port}", "ipv6_addr", members))

        lines += [
            "  chain forward {",
            # priority -50 puts this BEFORE the default filter chain, so a blocked packet is
            # dropped without walking the rest of the ruleset. `policy accept` is the fail-open
            # default: anything this table does not match continues on its way.
            "    type filter hook forward priority -50; policy accept;",
            f"    ip saddr @{NFT_SET_V4} counter drop",
            f"    ip6 saddr @{NFT_SET_V6} counter drop",
        ]
        for r in dst_rules:
            fam = "ip6" if ":" in r.dst_cidr else "ip"
            lines.append(f"    {fam} daddr {r.dst_cidr} counter drop")
        for proto, port in sorted(port_v4):
            lines.append(f"    {proto} dport {port} ip saddr @port_{proto}_{port} counter drop")
        for proto, port in sorted(port_v6):
            lines.append(f"    {proto} dport {port} ip6 saddr @port6_{proto}_{port} counter drop")
        lines += ["  }", "}"]

        if inbound:
            # ── THE PORT MUST SURVIVE INTO THE INPUT RULE ─────────────────────────────────────
            #
            # MEASURED DEFECT (found by running the shipped path on the live node, 2026-09-23). The
            # input rule was a bare `ip saddr @in_v4 counter drop`, so an operator who asked to
            # block ONE PORT from a source had EVERY port from that source dropped. The proof was
            # decisive rather than suggestive: blocking 127.0.0.1:9473 dropped 9473 AND 9474, and
            # the compiled ruleset did not contain the port number anywhere (`str(9473) in
            # ruleset` was False).
            #
            # That is the most dangerous shape a gate can have: it does MORE than the operator
            # asked. A block intended for one service becomes a full-source block on the INPUT
            # hook, which is where this host's own management and API traffic arrives -- so the
            # likely outcome is an operator locking themselves out of the box they are defending,
            # having asked for something far narrower.
            #
            # WHY A SET PER (proto, port), like the forward chain: nft's interval sets match
            # addresses only, so a port cannot be a set member. One set per port keeps the lookup a
            # hash regardless of how many addresses are in it, which is the same reason the forward
            # chain compiles that way. A rule with no port applies to the whole source, which is
            # what "block this source" means and is correct.
            def _in_split(rs: list[Rule], v6: bool) -> tuple[list[str], dict[tuple[str, int], list[str]]]:
                plain: list[str] = []
                by_port: dict[tuple[str, int], list[str]] = {}
                for r in rs:
                    if not r.src_cidr or (":" in r.src_cidr) != v6:
                        continue
                    if r.dst_port and r.protocol:
                        by_port.setdefault((r.protocol, r.dst_port), []).append(r.src_cidr)
                    else:
                        plain.append(r.src_cidr)
                return plain, by_port

            in_v4, in_p4 = _in_split(inbound, v6=False)
            in_v6, in_p6 = _in_split(inbound, v6=True)
            lines.append(f"table inet {NFT_TABLE_IN} {{")
            lines.append(_set("in_v4", "ipv4_addr", in_v4))
            lines.append(_set("in_v6", "ipv6_addr", in_v6))
            for (proto, port), members in sorted(in_p4.items()):
                lines.append(_set(f"inport_{proto}_{port}", "ipv4_addr", members))
            for (proto, port), members in sorted(in_p6.items()):
                lines.append(_set(f"inport6_{proto}_{port}", "ipv6_addr", members))
            lines += [
                "  chain input {",
                "    type filter hook input priority -50; policy accept;",
            ]
            for proto, port in sorted(in_p4):
                lines.append(
                    f"    {proto} dport {port} ip saddr @inport_{proto}_{port} counter drop"
                )
            for proto, port in sorted(in_p6):
                lines.append(
                    f"    {proto} dport {port} ip6 saddr @inport6_{proto}_{port} counter drop"
                )
            lines += [
                "    ip saddr @in_v4 counter drop",
                "    ip6 saddr @in_v6 counter drop",
                "  }",
                "}",
            ]
            # ORDER MATTERS, and it is load-bearing: the PORT-SCOPED rules come first, the
            # whole-source rules last. A port-scoped rule and a whole-source rule for the same
            # address can coexist (an operator may block a source entirely and one of its ports,
            # which collapse_networks does not merge because they are different rules), and nft
            # evaluates in order -- putting the whole-source rule first would drop the narrow
            # traffic before the narrow rule's counter ever saw it, making the port rule
            # unobservable while still being enforced. This order keeps every rule's counter
            # meaningful, which is what the GUI displays.
        return "\n".join(lines) + "\n"

    def arm(self, rules: list[Rule], *, iface: str) -> tuple[bool, str]:
        if len(rules) > MAX_SET_MEMBERS:
            return False, (
                f"{len(rules)} active rules exceeds the {MAX_SET_MEMBERS} this backend will "
                "compile; the set is loaded in one transaction and a partial load is worse than "
                "a refused one"
            )
        # ── ARM MUST BE A REPLACE, NOT AN ACCUMULATE (glm-5.3 review) ────────────────────────────
        #
        # `_base_ruleset` is purely DECLARATIVE: it creates tables and adds rules, with no flush and
        # no delete first. So arming twice could only ADD to whatever the previous arm left, and the
        # only code that removes kernel state is `disarm()` -- which the enforcement cycle never calls
        # between passes. MEASURED consequence: a rule that EXPIRED, or that the operator REVOKED,
        # stopped being compiled into the set while its already-installed drop rule kept matching, so
        # traffic stayed blocked after the block was withdrawn. For a tool whose gate is supposed to
        # fail OPEN, a block that outlives its rule is the worst failure available.
        #
        # Deleting both tables first makes arm() idempotent in the strong sense: the kernel state
        # after arm() is a function of `rules` alone, never of what was there before.
        for table in (NFT_TABLE, NFT_TABLE_IN):
            # Absence is expected on a first arm, and its error is ignored for the same reason
            # disarm() ignores it.
            self._run(["nft", "delete", "table", "inet", table], capture=True)
        # A rule the compiler refuses must fail the ARM and be reported: the same reason the
        # rule-count check above exists -- a partial install (or a silently wider one) is worse
        # than a refused one, because the operator cannot tell it happened.
        try:
            text = self._base_ruleset(rules, iface)
        except SluiceError as exc:
            return False, f"the ruleset was refused rather than compiled: {exc}"
        # ── THE INSTALL RESULT MUST BE READ (glm-5.3 review) ─────────────────────────────────────
        #
        # This called `self._run([...])` without unpacking, inside a try/except. `_nft_run` RETURNS
        # (False, err) and never raises, so the except was DEAD CODE for the real backend: a ruleset
        # nft rejected was discarded and `arm()` reported success.
        #
        # The read-back below is not a substitute. It asks whether a TABLE by that name exists, which
        # is true of a stale table left by a previous arm -- so "nft rejected this ruleset" and "the
        # gate is armed with the new ruleset" were indistinguishable, and the second is what the
        # caller reports to the operator.
        ok, err = self._run(["nft", "-f", "-"], stdin=text)
        if not ok:
            return False, f"nft rejected the ruleset: {err}"
        # READ BACK. A successful exit is not the same as an installed gate; this is the project's
        # recurring failure mode, so the state is verified rather than assumed.
        ok, present = self._run(["nft", "list", "table", "inet", NFT_TABLE], capture=True)
        if not ok or NFT_TABLE not in (present or ""):
            return False, "nft reported success but the table is not present on read-back"
        return True, f"{len(rules)} rule(s) compiled into sets on {iface}"

    def disarm(self) -> tuple[bool, str]:
        # BOTH TABLES. Direction 'in' rules live in a second table, and deleting only the forward
        # one would leave input rules enforcing after the operator disarmed -- a block that
        # survives being turned off. Every table this backend can create is deleted, and the
        # absence of each is VERIFIED rather than inferred from an exit code.
        for table in (NFT_TABLE, NFT_TABLE_IN):
            self._run(["nft", "delete", "table", "inet", table], capture=True)
        still = []
        for table in (NFT_TABLE, NFT_TABLE_IN):
            ok, present = self._run(["nft", "list", "table", "inet", table], capture=True)
            if present and table in present:
                still.append(table)
        if still:
            return False, f"these tables are still present after deletion: {', '.join(still)}"
        return True, "gate removed"

    def counters(self) -> tuple[int, int]:
        """Read the byte/packet counters nft keeps on the drop rules, across BOTH tables.

        Reading only the forward table would under-report: a block that fired on the input path
        would be invisible in the GUI's total, and an operator would conclude the gate was idle.
        """
        packets = bytes_ = 0
        for table in (NFT_TABLE, NFT_TABLE_IN):
            ok, out = self._run(["nft", "-j", "list", "table", "inet", table], capture=True)
            if not ok or not out:
                continue
            try:
                data = json.loads(out)
            except ValueError:
                continue
            for item in data.get("nftables", []):
                rule = item.get("rule")
                if not rule:
                    continue
                for expr in rule.get("expr", []):
                    # NAMED `nft_counter` DELIBERATELY. This is nft's own JSON output, not a
                    # database row, and `counter` read too much like one -- the schema audit
                    # flagged `.get("counter")` as a phantom column read, correctly, because a
                    # bare name like that is indistinguishable from a row lookup. The prefix says
                    # where the data comes from, for a reader and for the audit.
                    nft_counter = expr.get("counter")
                    if nft_counter:
                        packets += int(nft_counter.get("packets", 0))
                        bytes_ += int(nft_counter.get("bytes", 0))
        return packets, bytes_


def choose_backend(preferred: str = "nft") -> Backend:
    """The backend to use, and the honest answer when the preferred one is missing.

    Returning a backend that cannot enforce would be worse than returning an empty one: the gate
    would report ARMED while dropping nothing, which is the failure this project treats as its
    worst. The caller gets a backend whose `available()` is False, and the reported state is
    DEGRADED with the reason rather than a cheerful ARMED.
    """
    nft = NftBackend()
    if preferred == "nft" and nft.available():
        return nft
    return Backend()


# ── the supervisor ────────────────────────────────────────────────────────────────────────────


@dataclass
class SluiceSupervisor:
    """Owns the gate: loads rules, compiles them, and reports state honestly.

    Design notes that are load-bearing:
      * The gate is RE-ARMED periodically rather than only on change. Rules expire, so a gate armed
        once and left would keep enforcing a rule that should have lapsed -- something has to
        re-check the bound, and this loop is that something.
      * Every failure path results in DEGRADED with a reason, never a silent 'armed'.
      * `last_ok` is tracked so a caller can distinguish "the gate is holding" from "the gate held
        the last time anyone asked".
    """

    iface: str = ""
    mgmt_iface: str = ""
    sensor_addrs: list[str] = field(default_factory=list)
    backend: Backend = field(default_factory=NftBackend)
    state: GateState = field(default_factory=GateState)
    last_ok: float = 0.0
    last_error: str = ""

    def arm(self, rules: list[Rule]) -> GateState:
        live = [r for r in rules if r.is_live()]
        expired = len(rules) - len(live)

        if not self.iface:
            return self._degrade(
                rules_total=len(rules), rules_active=0,
                detail="no enforcement interface is configured; block rules exist but nothing is "
                       "being enforced",
            )
        if not self.backend.available():
            return self._degrade(
                rules_total=len(rules), rules_active=len(live),
                detail=f"the {self.backend.name!r} backend cannot install rules on this host "
                       "(nft missing, or no NET_ADMIN). The gate is OPEN and traffic is not being "
                       "blocked.",
            )

        ok, detail = self.backend.arm(live, iface=self.iface)
        packets, bytes_ = self.backend.counters()
        if not ok:
            return self._degrade(
                rules_total=len(rules), rules_active=len(live),
                packets=packets, bytes_=bytes_,
                detail=f"the ruleset did not install, so the gate is OPEN: {detail}",
            )

        self.last_ok = time.time()
        self.last_error = ""
        note = f"{len(live)} rule(s) enforced on {self.iface}"
        if expired:
            note += f"; {expired} lapsed and are no longer enforced"
        self.state = GateState(
            state=GATE_STATE_ARMED if live else GATE_STATE_DISARMED,
            iface=self.iface, mgmt_iface=self.mgmt_iface,
            rules_total=len(rules), rules_active=len(live),
            packets_blocked=packets, bytes_blocked=bytes_,
            detail=note if live else "no live rules: the gate is open by choice",
            backend=self.backend.name, backend_expected="nft",
        )
        return self.state

    def _degrade(self, *, rules_total: int, rules_active: int, detail: str,
                 packets: int = 0, bytes_: int = 0) -> GateState:
        self.last_error = detail
        self.state = GateState(
            state=GATE_STATE_DEGRADED, iface=self.iface, mgmt_iface=self.mgmt_iface,
            rules_total=rules_total, rules_active=rules_active,
            packets_blocked=packets, bytes_blocked=bytes_,
            detail=detail, backend=self.backend.name, backend_expected="nft",
        )
        return self.state

    def disarm(self) -> GateState:
        ok, detail = self.backend.disarm()
        self.state = GateState(
            state=GATE_STATE_DISARMED if ok else GATE_STATE_DEGRADED,
            iface=self.iface, mgmt_iface=self.mgmt_iface,
            detail="the gate is open and no rules are installed" if ok else detail,
            backend=self.backend.name, backend_expected="nft",
        )
        if not ok:
            self.last_error = detail
        return self.state

    def healthy(self, max_age_s: float = 120.0) -> bool:
        """Whether the gate is holding AND was confirmed recently.

        The distinction matters: a supervisor that stopped running leaves `state=armed` behind, and
        an operator reading that would believe the block still holds. Age is the tie-breaker.
        """
        return self.state.holding and (time.time() - self.last_ok) <= max_age_s


# ── the criticality policy: block on ML severity ──────────────────────────────────────────────


# WHAT AN OPERATOR'S CRITICALITY SETTING MEANS. These four levels are what the GUI offers, and the
# mapping is explicit rather than computed because the difference between them is a judgement about
# the operator's network, not arithmetic.
#
# The numbers are deliberately conservative. A false positive that blocks a real host is a far
# worse outcome than a false negative that leaves something watched, because this appliance's whole
# purpose is visibility -- so the default ('high') blocks only what the ensemble called high
# severity with strong agreement, and even then for a bounded window.
CRITICALITY_POLICIES: dict[str, dict[str, Any]] = {
    "off": {
        "label": "Off",
        "min_severity": None,
        "ttl_minutes": 0,
        "min_confidence": 0.0,
        "description": "Detections are recorded and alerted but never block anything.",
    },
    "high": {
        "label": "High only",
        "min_severity": "high",
        "ttl_minutes": 30,
        "min_confidence": 0.85,
        "description": (
            "Block only flows the ensemble scored high severity with strong agreement, for 30 "
            "minutes. The conservative default: a host that looks like a scanner stops scanning, "
            "and if the detection was wrong the host recovers within half an hour."
        ),
    },
    "medium": {
        "label": "Medium and above",
        "min_severity": "medium",
        "ttl_minutes": 15,
        "min_confidence": 0.70,
        "description": (
            "Block medium and high severity for 15 minutes. Catches more, at the cost of "
            "occasionally pausing a host that was merely unusual."
        ),
    },
    "strict": {
        "label": "Strict",
        "min_severity": "low",
        "ttl_minutes": 5,
        "min_confidence": 0.50,
        "description": (
            "Block anything the ensemble flagged, for 5 minutes. For an isolated lab segment or a "
            "declared incident. Expect false positives: unusual is not the same as hostile."
        ),
    },
}

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def policy_allows(policy: str, *, severity: str, confidence: float) -> tuple[bool, str]:
    """Whether the criticality policy permits a block derived from this detection.

    Returns (allowed, reason). The reason is returned in BOTH directions because the GUI shows it:
    an operator who cannot see why a detection did or did not block cannot tune the policy.
    """
    spec = CRITICALITY_POLICIES.get(policy)
    if spec is None:
        return False, f"unknown criticality policy {policy!r}"
    if spec["min_severity"] is None:
        return False, "the criticality policy is Off: detections never block"
    if SEVERITY_RANK.get(severity, 0) < SEVERITY_RANK[spec["min_severity"]]:
        return False, (
            f"severity {severity or 'unscored'} is below this policy's floor "
            f"({spec['min_severity']})"
        )
    if confidence < spec["min_confidence"]:
        return False, (
            f"confidence {confidence:.2f} is below this policy's floor "
            f"({spec['min_confidence']:.2f}); a weak detection is not grounds to block a host"
        )
    return True, (
        f"severity {severity} at confidence {confidence:.2f} meets the {spec['label']} policy; "
        f"the block lapses after {spec['ttl_minutes']} minutes"
    )

# ── the enforcement loop ──────────────────────────────────────────────────────────────────────


# The two VERIFIED ways a drop can be real, and the honest third answer. Recorded on the state
# row so the panel can say HOW this gate is enforcing, not merely that it believes it is.
ENFORCEMENT_CHANNEL = "channel"
ENFORCEMENT_SIPHON = "siphon"
ENFORCEMENT_NONE = "none"


def _resolve_enforcement_path(sensor_mode: str, channel: Any,
                              siphon_live: bool | None) -> tuple[str, str]:
    """(path, detail) for the enforcement verdict. "" means "no opinion -- leave as-is".

    THE MATRIX, cell by cell (Samuel's ask, 2026-10-15: "verify if channel and loch are active
    or siphon"):

      * a LIVE channel enforces REGARDLESS of mode -- it is physically in line, and the check
        before calling it live is kernel-side (admin/channel.py: both ports on one forwarding
        bridge with carrier, and bridge-nf enabled so the gate's inet hooks see bridged
        traffic);
      * siphon counts only with LIVE intercept evidence (True). False degrades with the
        reason; unverifiable (None) degrades too, because "could not check" is not "fine" --
        the rule this module's neighbours keep re-learning;
      * loch with no channel cannot enforce, and a DECLARED-but-inactive channel says exactly
        what is wrong with the wiring, which is the sentence the operator needs to fix it;
      * an UNSPECIFIED mode keeps the caller's old behaviour: unknown is not the same as
        passive, and a caller that did not say did not ask for a verdict about it.
    """
    if channel is not None and channel.active:
        return ENFORCEMENT_CHANNEL, (
            f"enforcing IN LINE on the channel bridge {channel.bridge} "
            f"({channel.upstream} <-> {channel.downstream}): traffic between those ports "
            f"traverses this host, so these drops are real. Capture stays passive; nothing is "
            f"forged or redirected."
        )
    if sensor_mode == "siphon":
        if siphon_live is True:
            return ENFORCEMENT_SIPHON, (
                "enforcing via the live siphon intercept (verified: fresh sensor_status "
                "evidence with forged mappings)."
            )
        if siphon_live is False:
            return ENFORCEMENT_NONE, (
                "siphon mode is configured but NO live intercept is running, so this host is "
                "not in the traffic path and nothing on the segment is actually blocked. Check "
                "the supervisor's refusal notes in sensor_status.failures."
            )
        return ENFORCEMENT_NONE, (
            "siphon mode is configured but the intercept evidence could not be verified, so "
            "this gate does not claim the traffic path. Check the database connection."
        )
    if sensor_mode:
        if channel is not None and channel.declared:
            return ENFORCEMENT_NONE, (
                f"the rules are installed, but the channel is not active, so nothing is "
                f"actually blocked. {channel.detail} Fix the wiring (both ports enslaved to "
                f"one forwarding bridge, bridge-nf enabled), or use siphon mode."
            )
        return ENFORCEMENT_NONE, (
            f"the rules are installed, but this sensor is in {sensor_mode} (passive) mode and "
            "is not in the traffic path, so nothing on the segment is actually blocked. "
            "Enforcement needs a channel (wire two ports in line and set CHANNEL_UPSTREAM / "
            "CHANNEL_DOWNSTREAM) or siphon mode on a segment this host sits in front of. "
        )
    return "", ""


def enforcement_pass(
    store: Any,
    supervisor: SluiceSupervisor,
    *,
    client: Any,
    sensor: str,
    policy: str = "off",
    max_block_s: int = 3600,
    detections: list[dict] | None = None,
    sensor_mode: str = "",
    channel: Any = None,
    siphon_live: bool | None = None,
) -> GateState:
    """One cycle: load rules, let detections add more, arm, and RECORD what happened.

    WHY THE DETECTIONS ARE ADDED EVERY PASS RATHER THAN ONCE. The worker re-derives them anyway, and
    the alternative -- keeping a list of what has already been blocked -- is state that must survive
    a restart, and its loss would mean either duplicate rules or silently unblocked hosts. Re-deriving
    from the policy is stateless, and the policy's own TTL bounds the result.

    A FAILURE READING RULES DOES NOT DISARM. `load_live_rules` raises on a database error, and the
    correct response is to report DEGRADED and leave whatever the kernel currently has installed
    alone -- NOT to arm an empty ruleset, which would open the gate because the database blipped.
    Failing open on a LOST CONNECTION is right; failing open on a FAILED QUERY would mean an
    attacker who can slow the database can unblock themselves.

    WHY THE MODE IS CONSULTED AT ALL, AND NOW THE CHANNEL TOO. A gate only blocks anything if the
    traffic it matches would have traversed THIS host, and there are exactly two VERIFIED ways
    that is true: a CHANNEL (two ports wired in line on one forwarding bridge with bridge-nf on --
    the checks are in admin/channel.py) or a LIVE siphon intercept (fresh sensor_status evidence
    with forged mappings -- status.siphon_liveness, the same check the CLI shouts with). In `loch`
    with neither, a FORWARD drop discards traffic that was never going to reach the kernel's
    forward path: the gate would still compile, still install, and still count its own drops, so
    it would read ARMED while changing nothing about the network an operator was trying to stop.
    That is this project's most-repeated failure: a green reading over work that did not happen.
    Rather than refuse to arm (which would make the feature silently unavailable and send the
    operator hunting), the gate arms AND reports DEGRADED with the reason -- and says which path,
    if any, is live, in `enforcement`.
    """
    rules: list[Rule] = []
    try:
        rules = store.load_live_rules(client)
    except Exception as exc:  # noqa: BLE001
        # Deliberately NOT `arm([])`. See the docstring: an unreadable ruleset is not an empty one.
        state = supervisor.state
        return GateState(
            state=GATE_STATE_DEGRADED,
            iface=supervisor.iface, mgmt_iface=supervisor.mgmt_iface,
            rules_total=state.rules_total, rules_active=state.rules_active,
            packets_blocked=state.packets_blocked, bytes_blocked=state.bytes_blocked,
            detail=(
                f"could not read the rules ({type(exc).__name__}), so the gate is left as it is. "
                "It is NOT reopened: an unreadable ruleset is not an empty one, and a query "
                "failure must not unblock a host."
            ),
            backend=supervisor.backend.name, backend_expected="nft",
        )

    if policy != "off" and detections:
        for spec in store.derived_rules_for_detections(
            # max_block_s is SECONDS (a config knob an operator reads); the function takes
            # MINUTES. Named conversion rather than a bare //60, because that is the line a
            # unit-change breaks silently.
            detections, policy=policy, max_ttl_minutes=max(1, int(max_block_s) // 60)
        ):
            try:
                rules.append(store.create_rule(client, **spec))
            except Exception as exc:  # noqa: BLE001
                # One bad detection must not stop the pass: the manual rules still need arming.
                logger.warning("sluice: could not record a derived rule: %s", exc)

    state = supervisor.arm(rules)

    # ── CAN THIS DEPLOYMENT ENFORCE AT ALL, AND BY WHICH VERIFIED PATH? ───────────────────────
    #
    # The rules installed correctly and the kernel will count drops -- but a drop only matters if
    # the traffic it matches would have traversed THIS host. There are exactly two paths that make
    # that true, and each is VERIFIED rather than assumed (the matrix is in _resolve_enforcement_path):
    #
    #   * CHANNEL -- physically in line (upstream <-> downstream on one bridge), read from the
    #     kernel by admin/channel.py. Enforces while the mode stays `loch`.
    #   * SIPHON  -- in path by ARP redirect, and the interception must be LIVE: a configured
    #     siphon with no intercept running is a sensor that is NOT in the path.
    #
    # Placed AFTER arm() on purpose -- the rules stay installed whichever way this goes, so a path
    # coming up later starts enforcing immediately rather than requiring a re-arm.
    path, path_detail = _resolve_enforcement_path(sensor_mode, channel, siphon_live)
    if path:
        state = replace(
            state,
            detail=(path_detail + " " + (state.detail or "")).strip(),
            enforcement=path,
        )
    if path == ENFORCEMENT_NONE:
        state = replace(state, state=GATE_STATE_DEGRADED)

    try:
        store.write_gate_state(client, sensor, state)
    except Exception as exc:  # noqa: BLE001
        # The gate IS armed even if the state row failed; say so rather than implying it is not.
        logger.warning("sluice: gate state could not be recorded: %s", exc)
        state.detail += f" (note: this state could not be recorded: {type(exc).__name__})"
    return state
