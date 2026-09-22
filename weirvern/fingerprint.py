"""Passive host identification: what IS this machine, without asking it?

WHY THIS IS PASSIVE, AND WHY THAT IS THE POINT.

A vulnerability scanner or an authenticated agent asks a host what it runs. That is fine on
machines you own and useless on a network you are monitoring: it needs credentials, it needs
the host to answer, and it is loud. Everything here is derived from traffic the sensor already
sees -- nothing is sent, no host is probed, and a device that never answers anything is still
identifiable if it ever spoke.

THE THREE SOURCES, AND WHY THEY ARE COMBINED RATHER THAN TRUSTED SEPARATELY.

    1. software.log      Zeek parses the application banner. This is the strongest source by a
                         wide margin because the banner NAMES the distribution:
                         "OpenSSH_10.2p1 Ubuntu-2ubuntu3.6" is Ubuntu, and it says so.
                         It only appears for protocols Zeek has a software analyzer for
                         (SSH, HTTP User-Agent, SMB, MySQL, ...).

    2. dhcp.log          A client's DHCP request carries its hostname, its FQDN option and its
                         MAC. The hostname is a weak but independent naming convention signal
                         (DESKTOP-7A3B2C and -MacBookPro are habits, not truths), and the MAC
                         is a hardware vendor fact. A lease tells us about a host BEFORE it
                         sends any application traffic, which is when you most want to know.

    3. ssl.log ja4       The TLS ClientHello in the clear. The FULL JA4 is a stack identity --
                         two hosts with the same JA4 run the same TLS library, which usually
                         means the same OS family and build source.

WHY CONFIDENCE IS THE OUTPUT AND NOT A GUESS.

Each source can be wrong, and wrong in a different way. A hostname is a user's typing. A MAC
vendor says who made the NIC, not what is installed on it -- a Linux box has an Intel NIC and a
Windows VM has the same virtual OUI as a Linux VM. And JA4 identifies the TLS STACK, so a
Windows host running Chrome and a Mac running Chrome can share a fingerprint. So the answer is
a VERDICT over independent signals: two sources agreeing is stronger evidence than either alone,
and one weak source is reported as weak rather than as an answer.

THE REFERENCE TABLE IS SELF-BUILT, DELIBERATELY.

There are public fingerprint databases (option-55 sequences, JA4 hash sets) that would seed
this far faster. They are not used here, for two reasons that are worth stating plainly rather
than leaving as a silent choice:

  * A LICENSE CONSTRAINT. The TLS fingerprint format this project ships is BSD-3-Clause and
    free to redistribute. The vendor whose tooling produces the well-known companion hashes
    does NOT license them that way, and the repository bans references to that tooling in CI
    (tests/test_ja4_licensing.py). Shipping a table derived from it would reintroduce exactly
    the problem that scan exists to prevent.
  * A CORRECTNESS ONE. A downloaded hash set is unverifiable from inside this repository: we
    could not say which version we had, whether it was still current, or on what it was based.
    A table that states its own reasoning can be checked and corrected; an imported one can
    only be trusted or ignored.

So `KNOWN_*` below holds only entries whose reasoning is written down beside them, and the
schema is designed to GROW: the `host_fingerprints` table records what was observed, so an
operator confirming a host's real OS turns the next run into a stronger classification. This
is a table that earns its confidence instead of asserting it.
"""
from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

# ── OS families ──────────────────────────────────────────────────────────────────────────
#
# A closed set, because the point of the label is to be comparable across hosts. "Linux" is
# one answer, not "Ubuntu 26.04.1 LTS (GNU/Linux 7.0.0-31-generic x86_64)" -- the detail is
# carried separately so a report can be read at either resolution.
OS_WINDOWS = "windows"
OS_LINUX = "linux"
OS_MACOS = "macos"
OS_BSD = "bsd"
OS_IOS = "ios"
OS_ANDROID = "android"
OS_NETWORK = "network-device"
OS_EMBEDDED = "embedded"
OS_UNKNOWN = "unknown"

OS_LABELS: dict[str, str] = {
    OS_WINDOWS: "Windows",
    OS_LINUX: "Linux",
    OS_MACOS: "macOS",
    OS_BSD: "BSD",
    OS_IOS: "iOS",
    OS_ANDROID: "Android",
    OS_NETWORK: "Network device",
    OS_EMBEDDED: "Embedded / appliance",
    OS_UNKNOWN: "Unknown",
}

# How much each SOURCE is trusted for the OS question, independent of which host it describes.
#
# These are not arbitrary. A software banner is the application stating its own build, so it is
# near-authoritative for the platform it was compiled on. A DHCP hostname is a naming habit. A
# MAC vendor says who made the NIC. A JA4 identifies the TLS library, not the operating system.
SOURCE_WEIGHTS: dict[str, float] = {
    "software": 1.0,
    "dhcp_fqdn": 0.6,
    "dhcp_hostname": 0.45,
    "dhcp_vendor": 0.5,
    "oui": 0.35,
    "ja4": 0.5,
    # A decoded JA4 header is a structural observation, NOT an OS signal: it says "TLS 1.3, 15
    # ciphers, ALPN h2" and nothing about the platform. Declared at 0.0 so the weight table is
    # complete -- a source with no entry silently takes the default, and the default would imply
    # this carries evidence it does not.
    "ja4_structure": 0.0,
    "reverse_dns": 0.3,
    "operator": 1.0,  # a confirmed human answer outranks every inference
}

# The confidence thresholds. Deliberately conservative: a single weak signal cannot reach
# "high" no matter how it scores on its own, because the whole failure mode of fingerprinting
# is a confident wrong answer that nobody rechecks.
CONF_HIGH_MIN_SOURCES = 2
CONF_HIGH_MIN_SCORE = 1.0
CONF_MEDIUM_MIN_SCORE = 0.45


# ── The reference tables ─────────────────────────────────────────────────────────────────
#
# EVERY ENTRY CARRIES ITS REASONING. An entry nobody can justify is an entry nobody can
# correct, and a fingerprint table that cannot be corrected is worse than an empty one.
#
# Matching is case-insensitive substring matching on the banner, not equality: banners carry
# build suffixes, so "OpenSSH_9.6p1 Ubuntu-3ubuntu13.5" and "OpenSSH_10.2p1 Ubuntu-2ubuntu3.6"
# must both resolve. Ordered: the FIRST match wins, so the more specific entry goes first.

# software.log `unparsed_version` / `name` -> (os, human reason)
KNOWN_SOFTWARE: list[tuple[str, str, str]] = [
    # Linux distributions name themselves in the SSH banner.
    ("ubuntu", OS_LINUX, "banner names Ubuntu"),
    ("debian", OS_LINUX, "banner names Debian"),
    ("raspbian", OS_LINUX, "banner names Raspbian"),
    ("centos", OS_LINUX, "banner names CentOS"),
    ("red hat", OS_LINUX, "banner names Red Hat"),
    ("rhel", OS_LINUX, "banner names RHEL"),
    ("fedora", OS_LINUX, "banner names Fedora"),
    ("alpine", OS_LINUX, "banner names Alpine"),
    ("arch linux", OS_LINUX, "banner names Arch"),
    ("suse", OS_LINUX, "banner names SUSE"),
    ("amazon linux", OS_LINUX, "banner names Amazon Linux"),
    # BSDs
    ("freebsd", OS_BSD, "banner names FreeBSD"),
    ("openbsd", OS_BSD, "banner names OpenBSD"),
    ("netbsd", OS_BSD, "banner names NetBSD"),
    # Network gear, which usually announces itself proudly.
    ("cisco", OS_NETWORK, "banner names Cisco"),
    ("juniper", OS_NETWORK, "banner names Juniper"),
    ("mikrotik", OS_NETWORK, "banner names MikroTik"),
    ("routeros", OS_NETWORK, "banner names RouterOS"),
    ("fortinet", OS_NETWORK, "banner names Fortinet"),
    ("pfsense", OS_BSD, "banner names pfSense (FreeBSD-based)"),
    ("opensense", OS_BSD, "banner names OPNsense (FreeBSD-based)"),
    # Windows does NOT put its version in the SSH banner, but Windows OpenSSH ships a
    # distinctive one, and WinHTTP/win-http appear in HTTP User-Agents.
    ("windows", OS_WINDOWS, "banner names Windows"),
    ("microsoft", OS_WINDOWS, "banner names Microsoft"),
    ("win32", OS_WINDOWS, "banner names win32"),
    ("win64", OS_WINDOWS, "banner names win64"),
    ("darwin", OS_MACOS, "banner names Darwin (macOS kernel)"),
    ("macos", OS_MACOS, "banner names macOS"),
    ("apple", OS_MACOS, "banner names Apple"),
]

# HTTP User-Agent substrings. A browser's UA is a deliberate, well-known string, so this is a
# strong signal for the desktop family in a way a hostname is not.
KNOWN_USER_AGENT: list[tuple[str, str, str]] = [
    ("iphone", OS_IOS, "User-Agent names iPhone"),
    ("ipad", OS_IOS, "User-Agent names iPad"),
    ("android", OS_ANDROID, "User-Agent names Android"),
    ("windows nt", OS_WINDOWS, "User-Agent names Windows NT"),
    ("macintosh", OS_MACOS, "User-Agent names Macintosh"),
    ("x11; linux", OS_LINUX, "User-Agent names X11 Linux"),
    ("ubuntu", OS_LINUX, "User-Agent names Ubuntu"),
    ("fedora", OS_LINUX, "User-Agent names Fedora"),
    ("freebsd", OS_BSD, "User-Agent names FreeBSD"),
]

# DHCP hostname conventions. These are HABITS, not facts, and are weighted accordingly --
# a hostname is whatever a person typed at setup, and the same box renamed is a different
# string. They are still worth having because they arrive before any application traffic.
KNOWN_HOSTNAME: list[tuple[str, str, str]] = [
    ("desktop-", OS_WINDOWS, "Windows default computer-name pattern"),
    ("laptop-", OS_WINDOWS, "Windows default computer-name pattern"),
    ("win-", OS_WINDOWS, "Windows default computer-name pattern"),
    ("-pc", OS_WINDOWS, "Windows-style hostname suffix"),
    ("macbook", OS_MACOS, "Apple naming convention"),
    ("imac", OS_MACOS, "Apple naming convention"),
    ("mac-mini", OS_MACOS, "Apple naming convention"),
    ("macmini", OS_MACOS, "Apple naming convention"),
    ("iphone", OS_IOS, "Apple naming convention"),
    ("ipad", OS_IOS, "Apple naming convention"),
    ("raspberrypi", OS_LINUX, "Raspberry Pi default hostname"),
    ("raspberry", OS_LINUX, "Raspberry Pi naming convention"),
    ("ubuntu", OS_LINUX, "Ubuntu naming convention"),
    ("debian", OS_LINUX, "Debian naming convention"),
    ("archlinux", OS_LINUX, "Arch naming convention"),
    ("fedora", OS_LINUX, "Fedora naming convention"),
    ("android-", OS_ANDROID, "Android default naming pattern"),
]

# MAC OUI -> vendor. THE WEAKEST SOURCE, and it is included for one specific use: telling a
# VIRTUAL machine from a physical one, and identifying appliance vendors. It says who made the
# NETWORK INTERFACE, which on a VM is the hypervisor and on a physical host is a NIC maker --
# neither of which is the operating system. Weighted low for that reason.
#
# A full OUI table is ~30,000 entries and is not shipped here: it would be unverifiable from
# inside this repository (same reasoning as the header). The entries below are the ones that
# answer a question an operator actually asks -- "is this virtual?" and "what kind of device
# is this?" -- and the schema records the raw MAC so a fuller table can be added later without
# re-ingesting anything.
KNOWN_OUI: dict[str, tuple[str, str]] = {
    # Virtualisation platforms. A virtual host is a fact worth knowing on its own: a
    # "Windows desktop" that is actually a VM on a hypervisor changes what you do about it.
    "00:05:69": (OS_UNKNOWN, "VMware"),
    "00:0c:29": (OS_UNKNOWN, "VMware"),
    "00:1c:14": (OS_UNKNOWN, "VMware"),
    "00:50:56": (OS_UNKNOWN, "VMware"),
    "00:15:5d": (OS_UNKNOWN, "Microsoft Hyper-V"),
    "00:16:3e": (OS_UNKNOWN, "Xen / Citrix"),
    "52:54:00": (OS_UNKNOWN, "QEMU / KVM"),
    "08:00:27": (OS_UNKNOWN, "VirtualBox"),
    "bc:24:11": (OS_UNKNOWN, "Proxmox VE"),
    "02:42": (OS_UNKNOWN, "Docker container"),
    # Common physical NIC vendors, for the "what is this" question.
    "00:1b:21": (OS_UNKNOWN, "Intel"),
    "00:1e:67": (OS_UNKNOWN, "Intel"),
    "3c:97:0e": (OS_UNKNOWN, "Intel"),
    "b8:27:eb": (OS_LINUX, "Raspberry Pi Foundation"),
    "dc:a6:32": (OS_LINUX, "Raspberry Pi Trading"),
    "e4:5f:01": (OS_LINUX, "Raspberry Pi Trading"),
}

# JA4 STRUCTURE. Only the first field is parsed here, and only for what it provably means.
#
# A JA4 looks like     t13d1516h2_8daaf6152771_02713d6af862
#                      ^^^^^^^^ ^^^^^^^^^^^^ ^^^^^^^^^^^^
#                      header   cipher hash  extension hash
#
# The header encodes protocol, version, SNI presence, cipher count, extension count and ALPN.
# That is a REAL, checkable fact about the stack: `t13d1516h2` is a TLS 1.3 client offering 15
# ciphers and 16 extensions with HTTP/2. What it is NOT is an operating system: the two hashes
# need a labelled database to become a name, and one is not shipped here (see the header).
#
# So this function reports what the header says and stops. Guessing "this is Windows" from an
# ALPN would be exactly the confident-wrong-answer this module exists to avoid; a JA4 becomes a
# NAME once an operator confirms one, and that is what the table's `operator` signal is for.
#
# The header is TEN characters and every position is fixed:
#
#     t 13 d 15 16 h2
#     |  | |  |  |  +-- ALPN: h2 / h3 (QUIC) / h1 / 00 (none)
#     |  | |  |  +----- extension count, 2 digits
#     |  | |  +-------- cipher count, 2 digits
#     |  | +----------- SNI: 'd' = a domain was sent, 'i' = an IP was, so no SNI
#     |  +------------- TLS version: 13 / 12 / 11 / 10
#     +---------------- transport: 't' = TCP, 'q' = QUIC
#
# An earlier pattern in this file had the field order wrong (a phantom type char before the SNI
# flag, and 't'/'f' where the format uses 'd'/'i'), so it rejected EVERY real fingerprint. It
# failed closed -- no structure reported, no crash -- which is why only a live-value test caught
# it: a regex that matches nothing looks exactly like a sensor that sends nothing.
_JA4_HEADER = re.compile(r"^([tq])(\d{2})([di])(\d{2})(\d{2})(h\d|00)?$", re.I)


def parse_ja4_header(ja4: str) -> dict[str, Any] | None:
    """Decode the STRUCTURAL half of a JA4. Returns None for anything that is not one.

    This deliberately does not classify. It reports the transport, the TLS version, whether SNI
    was sent, the cipher and extension counts, and the ALPN -- all of which are readable from
    the string itself and none of which name an operating system.
    """
    if not ja4 or ja4 in {"-", "(empty)"}:
        return None
    head = ja4.split("_", 1)[0]
    m = _JA4_HEADER.match(head)
    if not m:
        return None
    proto, ver, sni, ciphers, exts, alpn = m.groups()
    # THE VERSION FIELD IS VALIDATED, not merely matched. `t99d1516h2` has the right SHAPE and a
    # version that does not exist, and decoding it would report "version 99" as a structural fact
    # about a host -- a malformed input producing a confident answer, which is the failure mode
    # this module exists to avoid.
    if ver not in {"13", "12", "11", "10"}:
        return None
    version = {"13": "TLS 1.3", "12": "TLS 1.2", "11": "TLS 1.1", "10": "TLS 1.0"}[ver]
    return {
        "transport": "QUIC" if proto.lower() == "q" else "TCP",
        "tls_version": version,
        "sni": "sent" if sni.lower() == "d" else "not sent",
        "cipher_count": int(ciphers) if ciphers.isdigit() else None,
        "extension_count": int(exts) if exts.isdigit() else None,
        "alpn": alpn or "",
        "header": head,
    }


@dataclass(frozen=True)
class Signal:
    """One observation that bears on which OS a host runs.

    `detail` is the human-readable evidence, and it is not optional: a verdict whose signals
    cannot be read is a verdict an analyst cannot check, and an unchecked fingerprint is how a
    wrong one survives.
    """

    source: str
    os: str
    detail: str
    weight: float = 0.0

    def __post_init__(self) -> None:
        if not self.weight:
            object.__setattr__(self, "weight", SOURCE_WEIGHTS.get(self.source, 0.3))


@dataclass
class Verdict:
    """The combined answer for one host, with the evidence that produced it."""

    os: str = OS_UNKNOWN
    confidence: str = "unknown"
    signals: list[Signal] = field(default_factory=list)
    ja4_structure: dict[str, Any] | None = None

    @property
    def label(self) -> str:
        return OS_LABELS.get(self.os, self.os)

    @property
    def score(self) -> float:
        return sum(s.weight for s in self.signals if s.os == self.os)

    @property
    def disagreement(self) -> list[Signal]:
        """Signals that point somewhere other than the verdict.

        Reported rather than hidden. A host whose SSH banner says Ubuntu and whose hostname says
        DESKTOP- is either a renamed machine or a dual-boot, and either way the analyst should
        see both facts instead of a tidy answer.
        """
        return [s for s in self.signals if s.os != self.os]


def _match(table: list[tuple[str, str, str]], text: str) -> tuple[str, str] | None:
    """First case-insensitive substring match, or None. Order matters: specific entries first."""
    low = (text or "").lower()
    if not low:
        return None
    for needle, os_name, reason in table:
        if needle in low:
            return os_name, reason
    return None


def signal_from_software(name: str, version: str = "", unparsed: str = "",
                         software_type: str = "") -> Signal | None:
    """software.log -> a signal. The strongest single source in this module.

    The banner is checked FIRST because it is the string the build actually emitted, and it is
    what carries the distribution name ("OpenSSH_10.2p1 Ubuntu-2ubuntu3.6"). `name`/`version`
    are Zeek's parse of the same thing and are the fallback when a banner is absent.
    """
    # The banner first, then Zeek's parse of name+version. Both are source "software"; the
    # order is what matters, because the banner is the string the build actually emitted.
    for text in (unparsed, f"{name} {version}"):
        hit = _match(KNOWN_SOFTWARE, text)
        if hit:
            os_name, reason = hit
            shown = (unparsed or f"{name} {version}").strip()
            kind = f" ({software_type})" if software_type else ""
            return Signal(source="software", os=os_name,
                          detail=f"{shown}{kind} - {reason}")
    # A User-Agent arrives through HTTP as software with a long unparsed_version.
    hit = _match(KNOWN_USER_AGENT, unparsed or name)
    if hit:
        os_name, reason = hit
        return Signal(source="software", os=os_name,
                      detail=f"{(unparsed or name).strip()[:120]} - {reason}")
    return None


def signal_from_dhcp(host_name: str = "", client_fqdn: str = "", domain: str = "") -> list[Signal]:
    """dhcp.log -> signals. Arrives before application traffic, which is the point of using it.

    Returns a LIST because a hostname and an FQDN are separate observations and can disagree;
    collapsing them here would hide exactly the disagreement a verdict should show.
    """
    out: list[Signal] = []
    # The FQDN is the host's own statement of its name, so it is weighted above a bare hostname.
    hit = _match(KNOWN_HOSTNAME, client_fqdn)
    if hit:
        os_name, reason = hit
        out.append(Signal("dhcp_fqdn", os_name, f"FQDN {client_fqdn!r} - {reason}"))
    hit = _match(KNOWN_HOSTNAME, host_name)
    if hit:
        os_name, reason = hit
        out.append(Signal("dhcp_hostname", os_name, f"hostname {host_name!r} - {reason}"))
    # A domain suffix is a naming convention too ("home", "lan", "corp"). Not included as an OS
    # signal: it says who configured the network, not what the client runs. Recorded in the
    # caller's row so it is available without being mistaken for evidence.
    return out


def signal_from_mac(mac: str) -> Signal | None:
    """MAC OUI -> a vendor signal. The weakest source; see KNOWN_OUI for why it is included."""
    if not mac or mac in {"-", ""}:
        return None
    norm = mac.lower().replace("-", ":")
    oui = ":".join(norm.split(":")[:3])
    hit = KNOWN_OUI.get(oui)
    if not hit:
        return None
    os_name, vendor = hit
    return Signal("oui", os_name, f"NIC vendor {vendor} (OUI {oui})")


def signal_from_ja4(ja4: str) -> tuple[Signal | None, dict[str, Any] | None]:
    """JA4 -> (signal, structure). The structure is always returned; the signal may be None.

    A JA4 with no operator confirmation yields NO os signal -- deliberately. Reporting the
    structure lets the GUI show "TLS 1.3, 15 ciphers, ALPN h2" as the observable fact it is,
    while the OS claim waits for evidence that actually supports it.
    """
    return None, parse_ja4_header(ja4)


def classify(signals: Iterable[Signal], ja4_structure: dict[str, Any] | None = None) -> Verdict:
    """Combine independent signals into one verdict with a stated confidence.

    THE RULE THAT MATTERS: agreement across INDEPENDENT sources raises confidence, and volume
    from ONE source does not. Three hostname conventions matching is one weak source repeated,
    which is why the count is of distinct sources rather than of signals.
    """
    sigs = list(signals)
    v = Verdict(signals=sigs, ja4_structure=ja4_structure)
    if not sigs:
        return v

    # Weight per OS family, so a disagreement is resolved by evidence rather than by order.
    tally: dict[str, float] = {}
    for s in sigs:
        tally[s.os] = tally.get(s.os, 0.0) + s.weight
    best = max(tally, key=lambda k: tally[k])
    v.os = best

    sources = {s.source for s in sigs if s.os == best}
    score = tally[best]
    # An operator confirmation is an answer, not an inference, so it needs no corroboration --
    # it is ORed with the agreement test rather than nested under it.
    if (
        "operator" in sources
        or (len(sources) >= CONF_HIGH_MIN_SOURCES and score >= CONF_HIGH_MIN_SCORE)
    ):
        v.confidence = "high"
    elif len(sources) >= 2 and score >= CONF_MEDIUM_MIN_SCORE:
        v.confidence = "medium"
    elif max((s.weight for s in sigs if s.os == best), default=0.0) >= 0.6:
        # ONE source can carry medium, but only a source strong enough to stand alone -- an
        # application banner is the build naming its own platform. A bare hostname is a habit
        # somebody typed, and reporting it as "medium confidence" would be presenting a guess
        # in the same shape as a finding.
        v.confidence = "medium"
    else:
        v.confidence = "low"
    return v


def summarise(signals: Iterable[Signal], ja4_structure: dict[str, Any] | None = None) -> dict[str, Any]:
    """The verdict as a serialisable dict, for the API and the table.

    A single choke point, so the GUI and the stored row cannot describe the same host
    differently -- the defect class this project has already shipped twice.
    """
    v = classify(signals, ja4_structure)
    return {
        "os": v.os,
        "os_label": v.label,
        "confidence": v.confidence,
        "score": round(v.score, 3),
        "sources": sorted({s.source for s in v.signals}),
        "signal_count": len(v.signals),
        "signals": [
            {"source": s.source, "os": s.os, "os_label": OS_LABELS.get(s.os, s.os),
             "detail": s.detail, "weight": s.weight}
            for s in sorted(v.signals, key=lambda s: -s.weight)
        ],
        # Disagreement is DATA, not noise. A host that reads as two things is a finding.
        "disagreement": [
            {"source": s.source, "os_label": OS_LABELS.get(s.os, s.os), "detail": s.detail}
            for s in v.disagreement
        ],
        "ja4_structure": v.ja4_structure,
    }
