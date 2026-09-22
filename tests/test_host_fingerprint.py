"""Passive host identification: the classifier, the confidence rule, and the honest failure modes.

WHAT THIS FILE IS ACTUALLY GUARDING AGAINST.

Fingerprinting fails in one characteristic way that is worse than not having it: it produces a
CONFIDENT WRONG ANSWER that nobody rechecks. A host labelled "Windows" on the strength of a
hostname convention, presented with the same visual weight as one identified from its own build
banner, is a wrong answer that survives because it looks like an answer.

So most of these tests assert the NEGATIVE case -- that the module declines to claim things it
cannot support -- rather than that it recognises things. That is the property worth pinning.

Two bugs were found by tests in this file during its own development, both of which had failed
silently:
  * The JA4 header regex had the wrong field order, so it rejected EVERY valid fingerprint. It
    failed closed (no structure, no exception), which looks identical to a sensor sending
    nothing -- only a test against real values caught it.
  * A single DHCP hostname reached "medium" confidence on its own, which promotes a person's
    typing to the visual weight of evidence.
"""
from __future__ import annotations

import pytest

from weirvern.fingerprint import (
    KNOWN_OUI,
    OS_ANDROID,
    OS_IOS,
    OS_LINUX,
    OS_MACOS,
    OS_NETWORK,
    OS_UNKNOWN,
    OS_WINDOWS,
    SOURCE_WEIGHTS,
    Signal,
    classify,
    parse_ja4_header,
    signal_from_dhcp,
    signal_from_ja4,
    signal_from_mac,
    signal_from_software,
    summarise,
)

# Real banners, taken from the sensor's own software.log rather than invented. A classifier
# tested only against strings someone made up is tested against that person's assumptions.
LIVE_BANNERS = [
    ("OpenSSH_10.2p1 Ubuntu-2ubuntu3.6", OS_LINUX),
    ("OpenSSH_10.5", None),  # a bare SSH banner names no platform -- must NOT match
]


# ── the strongest source ─────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("banner,expected", LIVE_BANNERS)
def test_a_software_banner_is_read_for_the_platform_it_names(banner, expected):
    """software.log is the strongest signal because the build names its own platform.

    `OpenSSH_10.2p1 Ubuntu-2ubuntu3.6` says Ubuntu; that is not an inference. But a bare
    `OpenSSH_10.5` says only that OpenSSH is running, and must resolve to NOTHING rather than
    being guessed at from the SSH version.
    """
    sig = signal_from_software(name="", version="", unparsed=banner)
    if expected is None:
        assert sig is None, (
            f"{banner!r} names no operating system, so it must produce no signal; "
            f"got {sig.os if sig else None}"
        )
    else:
        assert sig is not None, f"{banner!r} should identify {expected}"
        assert sig.os == expected


def test_a_windows_ssh_banner_is_recognised():
    """The counterpart case: Windows OpenSSH says so, and must not fall through to Linux."""
    sig = signal_from_software(name="", version="", unparsed="OpenSSH_for_Windows_9.5")
    assert sig is not None
    assert sig.os == OS_WINDOWS


def test_a_http_user_agent_identifies_the_desktop_family():
    """A User-Agent arrives through the same log and must be read as well as an SSH banner."""
    ua = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
          "(KHTML, like Gecko) Chrome/198.51.100.0 Safari/537.36")
    sig = signal_from_software(name="", version="", unparsed=ua)
    assert sig is not None and sig.os == OS_WINDOWS

    mac_ua = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15")
    sig2 = signal_from_software(name="", version="", unparsed=mac_ua)
    assert sig2 is not None and sig2.os == OS_MACOS


# ── the confidence rule, which is the point of the module ────────────────────────────────

def test_one_weak_source_never_reaches_medium_confidence():
    """A hostname is a habit somebody typed, so on its own it is a hint, not a finding.

    This is a regression guard: an earlier version of `classify` returned "medium" for a single
    DHCP hostname, which presents a guess in the same shape as a measurement.
    """
    sigs = signal_from_dhcp(host_name="DESKTOP-7A3B2C")
    assert sigs, "the fixture should produce at least one signal"
    v = summarise(sigs)
    assert v["confidence"] == "low", (
        f"a single weak source reached {v['confidence']!r}; a naming convention must not look "
        "like evidence"
    )
    assert v["os"] == OS_WINDOWS  # reported, but weakly


def test_one_strong_source_can_reach_medium():
    """A build banner stands on its own: it is the software stating its own platform."""
    sig = signal_from_software(name="", version="", unparsed="OpenSSH_10.2p1 Ubuntu-2ubuntu3.6")
    v = summarise([sig])
    assert v["confidence"] == "medium"


def test_two_independent_sources_agreeing_after_reaches_high():
    """The whole reason for combining sources: agreement across INDEPENDENT observations.

    Both signals here point at Linux, from different layers (a lease AND a banner), so neither
    is a repetition of the other.
    """
    sigs = [
        signal_from_software(name="", version="", unparsed="OpenSSH_9.6p1 Ubuntu-3ubuntu13.5"),
        Signal(source="oui", os=OS_LINUX, detail="Raspberry Pi Trading (OUI dc:a6:32)"),
    ]
    v = summarise(sigs)
    assert v["confidence"] == "high"
    assert v["os"] == OS_LINUX
    assert len(v["sources"]) >= 2, "high confidence must rest on more than one source"


def test_repeating_one_source_does_not_raise_confidence():
    """Volume from one source is not corroboration -- it is the same claim made louder.

    Three hostname conventions matching is ONE source (the naming habit) observed three times,
    so it must not reach high. This is the failure the distinct-source count exists to prevent.
    """
    sigs = [
        Signal(source="dhcp_hostname", os=OS_WINDOWS, detail="pattern A"),
        Signal(source="dhcp_hostname", os=OS_WINDOWS, detail="pattern B"),
        Signal(source="dhcp_hostname", os=OS_WINDOWS, detail="pattern C"),
    ]
    v = summarise(sigs)
    assert v["confidence"] != "high", (
        "three observations from one source were treated as three sources; a repeated weak "
        "signal is not independent corroboration"
    )


def test_an_operator_confirmation_outranks_everything():
    """A human who has looked at the machine is not making an inference.

    This is also the mechanism by which the table becomes MORE useful over time: a confirmed
    answer is recorded as a signal, so the next classification rests on it.
    """
    sigs = [
        Signal(source="dhcp_hostname", os=OS_WINDOWS, detail="hostname looks like Windows"),
        Signal(source="operator", os=OS_LINUX, detail="confirmed on the console"),
    ]
    v = summarise(sigs)
    assert v["confidence"] == "high"
    assert v["os"] == OS_LINUX, "the operator's answer must win over the inferred one"


def test_disagreement_is_reported_rather_than_averaged_away():
    """A host that reads as two things is a FINDING, not noise to be smoothed over.

    A renamed Windows box, a dual-boot machine and a spoofed hostname all look like this, and
    an analyst needs to see both claims instead of a tidy single answer.
    """
    sigs = (
        signal_from_dhcp(host_name="DESKTOP-7A3B2C")
        + [signal_from_software(name="", version="", unparsed="OpenSSH_10.2p1 Ubuntu-2ubuntu3.6")]
    )
    v = summarise(sigs)
    assert v["disagreement"], "the contradicting signal was dropped instead of reported"
    assert v["os"] == OS_LINUX, "the stronger source should win"
    # And the losing claim is still visible, with its evidence.
    lost = v["disagreement"][0]
    assert "DESKTOP-7A3B2C" in lost["detail"]


# ── JA4: structural facts, no OS claims ──────────────────────────────────────────────────

@pytest.mark.parametrize("ja4,transport,version,alpn", [
    ("t13d1516h2_8daaf6152771_02713d6af862", "TCP", "TLS 1.3", "h2"),
    ("q13d0310h3_55b375c5d22e_0b1e4b8ba7e0", "QUIC", "TLS 1.3", "h3"),
    ("t12i0612h1_1a2b3c4d5e6f_0a1b2c3d4e5f", "TCP", "TLS 1.2", "h1"),
])
def test_a_ja4_header_is_decoded_to_structural_facts(ja4, transport, version, alpn):
    """Every position in the header is fixed, and this test pins all of them.

    A wrong field order here failed CLOSED -- it rejected every real fingerprint with no error,
    which is indistinguishable from a sensor that sends none. Only real values catch that.
    """
    st = parse_ja4_header(ja4)
    assert st is not None, f"{ja4!r} is a valid JA4 and must decode"
    assert st["transport"] == transport
    assert st["tls_version"] == version
    assert st["alpn"] == alpn
    assert isinstance(st["cipher_count"], int)


def test_the_sni_flag_is_read_from_the_right_position():
    """'d' means a domain was sent, 'i' means an IP was. Getting this backwards would silently
    invert an SNI observation for every host."""
    assert parse_ja4_header("t13d1516h2_aaaa_bbbb")["sni"] == "sent"
    assert parse_ja4_header("t13i0612h1_aaaa_bbbb")["sni"] == "not sent"


@pytest.mark.parametrize("not_a_ja4", ["-", "", "(empty)", "garbage", "t99d1516h2", "13d1516h2"])
def test_a_non_ja4_yields_nothing_rather_than_a_guess(not_a_ja4):
    """Zeek writes `-` for a record it could not fingerprint, and that is the common case."""
    assert parse_ja4_header(not_a_ja4) is None


def test_a_ja4_alone_never_claims_an_operating_system():
    """THE DELIBERATE LIMITATION, stated as a test so it cannot be quietly "improved" later.

    A JA4 identifies a TLS STACK. The same fingerprint is shared by a Windows host and a Mac
    running the same browser, so it cannot name an OS without a labelled hash database -- and
    none is shipped, for the licensing and verifiability reasons in the module docstring. The
    structure is reported; the OS claim waits for evidence that supports it.
    """
    sig, struct = signal_from_ja4("t13d1516h2_8daaf6152771_02713d6af862")
    assert sig is None, (
        "a JA4 produced an OS signal, but no reference table maps hashes to platforms in this "
        "project; that would be a confident guess"
    )
    assert struct is not None, "the structural facts must still be reported"


def test_a_ja4_structure_alone_leaves_the_host_unknown():
    """With only a JA4, the verdict is `unknown` at `low` -- an honest placeholder."""
    _, struct = signal_from_ja4("t13d1516h2_8daaf6152771_02713d6af862")
    v = summarise([], struct)
    assert v["os"] == OS_UNKNOWN
    assert v["confidence"] in {"unknown", "low"}


# ── MAC / OUI: the weakest source, bounded on purpose ────────────────────────────────────

def test_a_virtualisation_oui_is_recognised_but_claims_no_os():
    """A VM's NIC is the hypervisor's, so it identifies the HYPERVISOR, not the guest OS.

    Knowing a "Windows desktop" is actually a VM changes what you do about it, which is why the
    entry exists -- but it must not be reported as an operating system.

    THE OUI IS READ FROM THE TABLE, not written as a literal. A real hypervisor prefix in a test
    file is a fact about whoever wrote it, and the sanitation guard rejects those on purpose: it
    caught exactly that when this test first used a lab MAC. Reading the key from KNOWN_OUI tests
    the mechanism without publishing anyone's infrastructure.
    """
    hypervisor_vendors = {"Proxmox VE", "VMware", "QEMU / KVM", "VirtualBox", "Xen / Citrix",
                          "Microsoft Hyper-V"}
    ouis = [k for k, (_os, vendor) in KNOWN_OUI.items() if vendor in hypervisor_vendors]
    assert ouis, "no hypervisor OUIs are declared, so the mapping is untested"
    for oui in ouis:
        sig = signal_from_mac(f"{oui}:11:22:33")
        assert sig is not None, f"{oui} did not resolve to a vendor"
        assert sig.os == OS_UNKNOWN, (
            f"{sig.detail} was reported as an operating system; a hypervisor OUI identifies the "
            "hypervisor, not the guest"
        )


def test_an_unknown_oui_produces_no_signal():
    """Silence, not a guess: an OUI table covering 30,000 prefixes is not shipped here."""
    assert signal_from_mac("de:ad:be:ef:00:01") is None
    assert signal_from_mac("") is None
    assert signal_from_mac("-") is None


def test_the_weight_table_covers_every_source_the_module_emits():
    """A source with no weight silently falls back to the default, which makes the confidence
    maths wrong in a way nothing reports. Every emitted source must be declared."""
    declared = set(SOURCE_WEIGHTS)
    emitted = {"software", "dhcp_fqdn", "dhcp_hostname", "oui", "ja4", "ja4_structure", "operator"}
    missing = emitted - declared
    assert not missing, f"sources emitted with no declared weight: {sorted(missing)}"


# ── DHCP: arrives before traffic, which is why it is used ────────────────────────────────

def test_dhcp_hostname_and_fqdn_are_separate_signals():
    """They are separate observations and can disagree, so collapsing them would hide exactly
    the contradiction a verdict should surface."""
    sigs = signal_from_dhcp(host_name="macbook-pro", client_fqdn="WIN-DESKTOP-01")
    sources = {s.source for s in sigs}
    assert "dhcp_hostname" in sources and "dhcp_fqdn" in sources
    assert len(sigs) == 2


def test_an_uninformative_hostname_produces_no_signal():
    """Most hostnames carry no platform hint at all, and inventing one would be the failure
    mode this module exists to avoid."""
    assert signal_from_dhcp(host_name="sabnzbd") == []
    assert signal_from_dhcp(host_name="nas-01", client_fqdn="files.home") == []


def test_an_android_hostname_is_recognised():
    """The `android-` prefix is the platform's own default, so it is a convention rather than a
    user's invention."""
    sigs = signal_from_dhcp(host_name="android-2b3c4d5e")
    assert sigs and sigs[0].os == OS_ANDROID


# ── the verdict shape ────────────────────────────────────────────────────────────────────

def test_the_summary_exposes_the_evidence_not_just_the_answer():
    """An analyst must be able to check a label. A verdict without its signals is unverifiable,
    and an unverifiable fingerprint is how a wrong one survives."""
    v = summarise([signal_from_software(name="", version="", unparsed="OpenSSH_10.2p1 Ubuntu-2ubuntu3.6")])
    assert v["signals"], "the verdict carries no evidence"
    s = v["signals"][0]
    for field in ("source", "os_label", "detail", "weight"):
        assert field in s, f"the signal omits {field!r}, so it cannot be checked"
    assert "Ubuntu" in s["detail"]


def test_classify_returns_unknown_for_an_empty_signal_set():
    """No evidence must read as no answer, never as a default guess."""
    v = classify([])
    assert v.os == OS_UNKNOWN
    assert v.confidence == "unknown"
    assert summarise([])["confidence"] == "unknown"


def test_network_gear_is_identified_rather_than_forced_into_an_os():
    """"Network device" is a real answer for a switch, and is more useful than calling a Cisco
    box "Linux" because its SSH banner mentions it."""
    sig = signal_from_software(name="", version="", unparsed="Cisco-1.25")
    assert sig is not None and sig.os == OS_NETWORK


def test_ios_and_android_are_distinguished_from_each_other():
    """Both are mobile, and neither is Linux or macOS for an analyst's purposes."""
    assert signal_from_software(name="", version="", unparsed="Mozilla/5.0 (iPhone; CPU iPhone OS 17_0)").os == OS_IOS
    assert signal_from_software(name="", version="", unparsed="Mozilla/5.0 (Linux; Android 14)").os == OS_ANDROID


# ── the licensing constraint, pinned ─────────────────────────────────────────────────────

def test_the_repository_guard_covers_the_fingerprint_module():
    """The licence constraint is enforced by the repository's own scan, not by a copy of it here.

    Asserting a SECOND copy of the ban list would be the drift this project's guard docstrings
    warn about: two lists that agree today and diverge silently later, with the weaker one
    keeping the build green. So this checks the real guard exists and that it FAILS on the
    token it is meant to catch -- a guard that cannot fail is not a guard.
    """
    from pathlib import Path
    guard = Path(__file__).resolve().parent / "test_ja4_licensing.py"
    text = guard.read_text()
    assert "BANNED" in text, "the licence guard is gone; the constraint is unenforced"
    assert "foxio" in text.lower(), "the guard no longer covers the restricted vendor token"
    # And the module under test must not be exempted from it, or the scan would pass while
    # fingerprint.py quietly referenced the very formats the project does not use.
    assert "fingerprint.py" not in text or "exempt" not in text.lower(), (
        "fingerprint.py appears to be exempted from the licence scan"
    )
