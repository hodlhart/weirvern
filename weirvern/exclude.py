"""Traffic exclusion: which addresses a sensor refuses to learn from.

WHY THIS EXISTS. A scanner sweeping a VLAN produces enormous one-shot flow volume: every address
it touches becomes a "new" destination, every port a "new" service. That is not a picture of the
network, it is a picture of the scanner, and it swamps the baseline the detectors learn from.

The first case that prompted this was self-inflicted: a test generator emitted 91,532 NetFlow v5
records for a synthetic 10.20.30.0/24 in a 1.4-minute run, and those rows then sat in the store as
21% of all flow data, ready to feed the next retrain.

TWO LAYERS, AND THEY ARE NOT INTERCHANGEABLE:

  * CAPTURE exclusion (a BPF filter on Zeek's socket) happens BEFORE anything is written. Nothing
    is recorded, so nothing can be re-examined later. Right for traffic that is genuinely
    worthless -- this host's own chatter, the cluster's pod and service CIDRs, broadcast.
  * INGEST exclusion happens at the row layer, AFTER the flow record exists. The record is
    counted and dropped rather than stored, and the count is reported. Right for traffic you may
    still want evidence about -- a scanner, a noisy test host -- because capture-level filtering
    destroys the forensic trail.

The default here is INGEST. Filtering at capture is the irreversible choice, so it is opt-in per
rule rather than the global behaviour.

EVERYTHING IS COUNTED. A filter that silently reduces the total is the same class of defect as a
panel that renders an empty chart for a failed query: the number looks smaller and nobody knows
why. Excluded records are counted per rule, and the counts are readable so a surface can say
"24,284 flows excluded from the synthetic test range" instead of quietly showing less traffic.

A RULE THAT CAN REJECT NOTHING IS A BUG, NOT A NO-OP. Every CIDR is parsed at load and a malformed
one raises immediately: a typo silently matching nothing is how an exclusion appears to work while
filtering none of the traffic it was added for.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import threading
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# The environment variable holding the exclusion list. Comma- or newline-separated CIDRs, or bare
# addresses (which are treated as /32 and /128).
EXCLUDE_ENV = "WEIRVERN_EXCLUDE_CIDRS"

# The same list, but for the CAPTURE layer only. Deliberately separate: a rule here destroys the
# record before it exists, so it must be chosen per-rule rather than inherited from a list someone
# added for ingest.
CAPTURE_EXCLUDE_ENV = "WEIRVERN_CAPTURE_EXCLUDE_CIDRS"

# NEVER LEARN FROM THESE, and the reasoning is per entry rather than "these are internal":
#
#   10.42.0.0/16  the pod CIDR. Pod-to-pod chatter is the cluster's own plumbing and does not
#                 describe the monitored network. It also appears as a SAMPLER address when an
#                 external sender is SNAT'd, which is how a synthetic test run was misread as a
#                 foreign network for an hour.
#   10.43.0.0/16  the service CIDR, same reasoning.
#   172.17.0.0/16 the docker bridge on the node.
#   169.254.0.0/16 link-local: never meaningful flow.
#   224.0.0.0/4   multicast, and 255.255.255.255 broadcast.
#
# NOT INCLUDED, deliberately: loopback and RFC1918 generally. A sensor monitoring a 10.x or 192.168.x
# network would otherwise exclude the very traffic it exists to watch -- and the synthetic test range
# that started this was 10.20.30.0/24, inside RFC1918. A blanket private-range rule would have been
# convenient and wrong.
DEFAULT_EXCLUDES: tuple[str, ...] = (
    "10.42.0.0/16",
    "10.43.0.0/16",
    "172.17.0.0/16",
    "169.254.0.0/16",
    "224.0.0.0/4",
    "255.255.255.255/32",
)


def parse_cidrs(spec: str) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """Parse a comma/newline-separated CIDR list, raising on anything malformed.

    RAISES rather than skipping. A malformed entry that is quietly dropped means an exclusion
    appears configured while filtering nothing -- and the traffic it was meant to catch keeps
    flowing into the models. Better to refuse to start with the offending text in the message.
    """
    out: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for raw in (spec or "").replace("\n", ",").split(","):
        token = raw.strip()
        if not token:
            continue
        try:
            # `strict=False` so 10.0.0.1/24 is accepted as 10.0.0.0/24. An operator writing a
            # host address with a prefix length means the network, and rejecting it would be
            # pedantry that produces a refused write.
            net = ipaddress.ip_network(token, strict=False)
        except ValueError as exc:
            raise ValueError(
                f"'{token}' is not a valid CIDR or address. Refusing to load the exclusion list: a "
                f"malformed entry would silently match nothing while appearing configured."
            ) from exc
        out.append(net)
    return out


@dataclass
class ExclusionStats:
    """Per-rule counters. Read by the GUI so exclusions are visible rather than inferred."""

    counts: dict[str, int] = field(default_factory=dict)
    total: int = 0

    def record(self, rule: str) -> None:
        self.counts[rule] = self.counts.get(rule, 0) + 1
        self.total += 1

    def as_dict(self) -> dict:
        return {"total": self.total, "by_rule": dict(self.counts)}


class TrafficFilter:
    """Decides which addresses are excluded, and counts what it drops.

    Built once at startup and shared by the flow and Zeek ingest paths, so the two cannot disagree
    about what is excluded. Thread-safe because the ingester runs a thread per source.
    """

    def __init__(self, spec: str | None = None,
                 extra: list[str] | None = None, *, use_defaults: bool = True) -> None:
        parts: list[str] = []
        if use_defaults:
            parts.extend(DEFAULT_EXCLUDES)
        if spec:
            parts.append(spec)
        if extra:
            parts.extend(extra)

        self._rules: list[tuple[str, ipaddress.IPv4Network | ipaddress.IPv6Network]] = []
        for text in parts:
            for net in parse_cidrs(text):
                self._rules.append((str(net), net))
        self._stats = ExclusionStats()
        self._lock = threading.Lock()

    @property
    def rules(self) -> list[str]:
        return [text for text, _ in self._rules]

    @property
    def enabled(self) -> bool:
        return bool(self._rules)

    def match(self, addr: str | None) -> str | None:
        """The rule that excludes this address, or None. Pure; does not count."""
        if not addr:
            return None
        try:
            ip = ipaddress.ip_address(addr.strip())
        except ValueError:
            # An unparseable address is NOT excluded. Dropping it here would hide a mapper bug
            # behind a filter, and the row would vanish with no explanation.
            return None
        for text, net in self._rules:
            # version check first: comparing a v4 address against a v6 network raises.
            if ip.version == net.version and ip in net:
                return text
        return None

    def excluded(self, *addrs: str | None) -> str | None:
        """The rule excluding ANY of these addresses, counting the drop once.

        Accepts None and junk deliberately: these come from a mapper, and an unparseable value must
        read as "not excluded" rather than raising inside the ingest loop or vanishing silently.

        ANY, not all: a flow between an excluded and an included host is still traffic the sensor
        was told not to learn from. Counting it once per record keeps the total meaningful -- a
        per-address count would report double for a self-to-self flow.
        """
        for addr in addrs:
            rule = self.match(addr)
            if rule is not None:
                with self._lock:
                    self._stats.record(rule)
                return rule
        return None

    def stats(self) -> dict:
        with self._lock:
            return self._stats.as_dict()

    def reset_stats(self) -> None:
        with self._lock:
            self._stats = ExclusionStats()


def from_env(environ: dict | None = None, *, use_defaults: bool = True) -> TrafficFilter:
    """Build the filter from the environment. Raises on a malformed list."""
    env = environ if environ is not None else os.environ
    spec = env.get(EXCLUDE_ENV, "")
    f = TrafficFilter(spec, use_defaults=use_defaults)
    if f.enabled:
        logger.info("traffic exclusion active: %s (plus %d default rule(s))",
                    spec or "(none from env)", len(DEFAULT_EXCLUDES) if use_defaults else 0)
    return f


def capture_filter_expr(extra: list[str] | None = None) -> str:
    """A BPF expression for the CAPTURE layer, or "" when nothing should be filtered.

    DELIBERATELY NOT DERIVED FROM DEFAULT_EXCLUDES. Every entry there is an ingest-layer rule, and
    turning them into a capture filter would silently stop recording that traffic altogether --
    including the pod CIDR, where a future investigation into cluster-side behaviour would then
    find no data and no reason for its absence.

    What this DOES build is the negation of an explicit capture list: traffic to or from an
    excluded address is dropped at the socket. Written as a single expression because Zeek takes
    one `-f` string, and a malformed one either fails the sensor at startup or -- worse -- matches
    everything and produces an empty-but-healthy capture. `validate_bpf_expr` exists for that.
    """
    nets = parse_cidrs(",".join(extra or []))
    if not nets:
        return ""
    terms: list[str] = []
    for net in nets:
        if net.version != 4:
            # A BPF capture filter for IPv6 needs a different expression shape; refusing is
            # better than emitting something that silently matches nothing.
            raise ValueError(
                f"capture filter does not support IPv6 yet ('{net}'). Use it for ingest "
                f"exclusion instead, which handles both families."
            )
        terms.append(f"net {net}")
    # `not (...)` so the filter PASSES everything except the listed networks.
    return "not ( " + " or ".join(terms) + " )"


def validate_bpf_expr(expr: str) -> tuple[bool, str]:
    """Whether a BPF expression is well-formed enough to trust.

    Returns (ok, reason). Checks SHAPE only -- pcap has the real parser, and this cannot invoke it
    everywhere. The failure this guards is specific and silent: an expression that is accepted but
    matches nothing produces a capture with no errors and no packets, which reads as a quiet
    network. So the obvious malformations are rejected here, and the sensor additionally logs the
    filter it is using so an operator can compare it against what they meant.
    """
    if not expr or not expr.strip():
        return True, "no capture filter (all traffic captured)"
    text = expr.strip()
    # Balanced parentheses, so a truncated expression cannot pass.
    if text.count("(") != text.count(")"):
        return False, f"unbalanced parentheses in {text!r}"
    # An expression that is only a negation is suspicious rather than invalid; flag it as the
    # likely typo it is (`not` with nothing after means "capture nothing").
    stripped = text.replace("not", "").strip()
    if not stripped.strip("() "):
        return False, f"{text!r} negates everything, so the capture would be empty"
    # `net` must be followed by something network-shaped, or it is a typo that matches nothing.
    import re

    for m in re.finditer(r"\bnet\s+([^\s()]+)", text):
        token = m.group(1)
        try:
            ipaddress.ip_network(token, strict=False)
        except ValueError:
            return False, f"{token!r} after 'net' is not a network"
    # `host` likewise.
    for m in re.finditer(r"\bhost\s+([^\s()]+)", text):
        token = m.group(1)
        try:
            ipaddress.ip_address(token)
        except ValueError:
            return False, f"{token!r} after 'host' is not an address"
    return True, "expression looks well-formed"
