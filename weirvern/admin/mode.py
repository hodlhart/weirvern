"""Sensor modes: how Weirvern gets its packets.

The names come from the creature the product is named for. A wyvern keeps its water in
a LOCH and draws it through a SIPHON — so holding still and flowing through are the two
ways Weirvern can watch a network.

    loch  PASSIVE. Still water: Zeek listens on a promiscuous NIC fed by a switch
          SPAN/mirror port or a passive TAP, and observes. Weirvern cannot affect
          traffic because it is not in the path. A sensor that dies is a monitoring gap,
          nothing more — the water keeps flowing past untouched.

    siphon  IN-PATH INTERCEPT. A conduit the water is drawn THROUGH: Weirvern ARP-spoofs
          selected hosts so their traffic is relayed through it, capturing as it passes.
          Works with NO switch, router or DHCP change — which is the appeal — but
          Weirvern becomes a ROUTER: every packet waits on it, and a crashed or
          overloaded sensor is a LAN OUTAGE. The whole flow is drawn through the siphon;
          when it stops, the flow stops with it.

WHY THIS MODULE EXISTS SEPARATELY rather than as a boolean in two places: the choice
carries a failure mode the operator cannot discover by reading code, and the settings
that make it safe (see `REQUIRED_SYSCTLS`) are non-obvious and each one has a specific
symptom if missing. Centralising the definition means the CLI and the runtime
all agree on what "siphon" implies and what has to be true before it is allowed.
"""
from __future__ import annotations

from dataclasses import dataclass, field

MODE_LOCH = "loch"
MODE_SIPHON = "siphon"
DEFAULT_MODE = MODE_LOCH

# The failure mode of each mode, stated in one line. Shown at selection time and in
# `weirvern status`, because the blast radius is the thing an operator most needs to
# hold in mind and it is invisible from the config value alone.
IMPACT = {
    MODE_LOCH: "passive — a failed sensor is a monitoring gap",
    MODE_SIPHON: "in-path — a failed sensor is a LAN outage",
}

SUMMARY = {
    MODE_LOCH: "passive capture (promiscuous NIC / SPAN / mirror / TAP)",
    MODE_SIPHON: "in-path intercept (ARP spoof; relays traffic through Weirvern)",
}

REQUIREMENTS = {
    MODE_LOCH: [
        "a NIC that receives a copy of the traffic (SPAN/mirror port or TAP)",
        "that NIC in promiscuous mode (set on the host, not by Weirvern)",
    ],
    MODE_SIPHON: [
        "an interface with two-way L2 reachability to the hosts to intercept",
        "CAP_NET_ADMIN and CAP_NET_RAW (Weirvern configures forwarding itself)",
        "net.ipv4.ip_forward=1 and a route to the destinations being relayed",
        "a fail-open watchdog — required, not optional (see watchdog.py)",
    ],
}

# Each of these has a named symptom when missing, all verified in a sandbox. Recording
# the symptom alongside the setting is what makes a misconfiguration diagnosable.
REQUIRED_SYSCTLS = [
    ("net.ipv4.ip_forward", "1",
     "without it the intercept captures nothing and silently drops the traffic it "
     "intercepted — a LAN outage caused by the sensor"),
    ("net.ipv4.conf.all.rp_filter", "0",
     "reverse-path filtering drops the relayed packet because its source belongs to "
     "neither us nor our subnet"),
    ("net.ipv4.conf.all.send_redirects", "0",
     "the kernel tells the victim to send directly, silently undoing the intercept a "
     "few packets in — the MITM 'works' then quietly stops"),
]

# Traffic that must NEVER be intercepted even in siphon mode. ARP spoofing the gateway
# itself would break the sensor's own management path and the cluster API.
NEVER_INTERCEPT = (
    "the management interface's own subnet gateway",
    "the sensor's own address",
    "the Kubernetes API server or any cluster node",
    "the DNS resolver used by the sensor",
)


@dataclass
class ModeVerdict:
    """Whether a mode may be enabled, and why not if not."""

    mode: str
    ok: bool
    blockers: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def summary(self) -> str:
        if self.mode not in (MODE_LOCH, MODE_SIPHON):
            return f"unknown mode '{self.mode}'"
        if not self.ok:
            return f"{self.mode}: cannot enable ({len(self.blockers)} blocker(s))"
        return f"{self.mode}: {IMPACT.get(self.mode, '')}"


def normalise(value: str) -> str:
    """Accept the mode name case-insensitively, plus a few obvious synonyms.

    Deliberately does NOT accept 'intercept'/'promisc' as the stored value: those
    describe the mechanism, and the stored value uses the product's own vocabulary so
    a config file reads as part of Weirvern rather than generic networking terms.
    """
    v = (value or "").strip().lower()
    if v in ("", MODE_LOCH):
        return MODE_LOCH
    if v == MODE_SIPHON:
        return MODE_SIPHON
    # Tolerate the mechanism names on INPUT so an operator reaching for the familiar
    # word is not punished, but store the product name.
    if v in ("passive", "promisc", "promiscuous", "span", "mirror", "tap"):
        return MODE_LOCH
    if v in ("intercept", "inline", "in-path", "inpath", "arp", "spoof"):
        return MODE_SIPHON
    if v == "weir":  # the former name of siphon, kept so pre-rename configs keep working
        return MODE_SIPHON
    return v


def describe(mode: str) -> str:
    m = normalise(mode)
    return f"{m} — {SUMMARY.get(m, 'unknown mode')}  [{IMPACT.get(m, '?')}]"


def validate(mode: str, *, has_net_admin: bool = False,
             has_net_raw: bool = False, watchdog_available: bool = False) -> ModeVerdict:
    """Can this mode be enabled in the current environment?

    siphon mode has HARD blockers rather than warnings, and the asymmetry is deliberate.
    loch mode failing is a monitoring gap; siphon mode failing is an outage. A sensor
    that intercepts traffic without the ability to forward it takes the LAN down, so
    the capability and watchdog checks gate the mode instead of advising about it.
    """
    m = normalise(mode)
    v = ModeVerdict(mode=m, ok=True)

    if m not in (MODE_LOCH, MODE_SIPHON):
        v.ok = False
        v.blockers.append(
            f"unknown sensor mode '{mode}' — expected '{MODE_LOCH}' or '{MODE_SIPHON}'"
        )
        return v

    if m == MODE_LOCH:
        # Nothing to block on: passive capture cannot break the network. A missing
        # interface is reported at startup by the sensor itself.
        v.warnings.append(
            "passive capture only sees what the switch sends you — verify with "
            "`weirvern interfaces` that ZEEK_IFACE is not the management port"
        )
        return v

    # --- siphon mode gates ------------------------------------------------------
    if not has_net_raw:
        v.ok = False
        v.blockers.append(
            "CAP_NET_RAW is required to send forged ARP frames (the sensor container "
            "needs it, as it already does for capture)"
        )
    if not has_net_admin:
        v.ok = False
        v.blockers.append(
            "CAP_NET_ADMIN is required in siphon mode: forwarding, rp_filter and "
            "send_redirects must be configured. The passive sensor deliberately does "
            "NOT have it — enabling siphon widens the container's privileges"
        )
    if not watchdog_available:
        v.ok = False
        v.blockers.append(
            "no fail-open watchdog is available. In siphon mode Weirvern is a router: "
            "if it stops forwarding without restoring the ARP caches, the intercepted "
            "hosts lose the network until their entries expire. The watchdog is a "
            "prerequisite, not an enhancement"
        )

    for name, want, symptom in REQUIRED_SYSCTLS:
        v.warnings.append(f"{name}={want} — {symptom}")

    v.warnings.append(
        "intercept only hosts you are authorised to intercept. Weirvern relays and "
        "records their traffic; see USAGE_POLICY.md"
    )
    v.warnings.append(
        "never intercept: " + "; ".join(NEVER_INTERCEPT)
    )
    return v


def env_value(mode: str) -> str:
    """The value as it should appear in .env / the ConfigMap."""
    return normalise(mode)
