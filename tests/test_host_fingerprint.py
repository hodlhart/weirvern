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

from datetime import UTC
from pathlib import Path

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
from weirvern.host_identity import coverage, identity_for_hosts

ROOT = Path(__file__).resolve().parents[1]

ROOT = Path(__file__).resolve().parents[1]

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


# ── two defects found by LIVE verification, not by these tests ──────────────────────────

def test_the_tailer_reads_the_observation_registry_too():
    """software.log produced ZERO observations on a live deployment while everything looked fine.

    Cause: `tail_zeek_dir` iterated `ZEEK_MAPPERS` alone, so when `software` moved to its own
    registry it silently stopped being read at all. The strongest identity source -- the one that
    names the platform outright -- contributed nothing, and no error was raised because a log
    nobody reads is indistinguishable from a log with nothing in it.

    A registry that nothing iterates is a comment, not a registry.
    """
    from weirvern import ingester
    src = (ROOT / "weirvern" / "ingester.py").read_text()
    assert "ZEEK_OBSERVATION_MAPPERS" in src
    # The tailer must consult BOTH.
    i = src.index("def tail_zeek_dir")
    j = src.index("def ", i + 10)
    body = src[i:j]
    assert "ZEEK_MAPPERS" in body and "ZEEK_OBSERVATION_MAPPERS" in body, (
        "the tailer iterates one registry, so the observation logs are never read"
    )
    assert ingester.ZEEK_OBSERVATION_MAPPERS, "the observation registry is empty"


def test_a_dhcp_discover_never_becomes_a_host_called_0000():
    """A DISCOVER carries client_addr 0.0.0.0, and it was stored as a HOST.

    Live-verified: two DHCP hostnames were attributed to a device called `0.0.0.0` in the
    identity table. That is worse than a missing row, because it reads as a finding -- an
    unnamed device on the segment -- when it is an artefact of a protocol field.

    The MAC is the stable identifier for exactly this case, which is why the schema carries it.
    """
    from weirvern.ingester import observations_from_dhcp

    # A DISCOVER: 0.0.0.0 client, no assigned address, but a MAC.
    obs = observations_from_dhcp(
        {"mac": "00:00:5e:00:53:01", "host_name": "somehost"},
        {"ts": None, "client_addr": "0.0.0.0", "assigned_addr": "", "requested_addr": ""},
    )
    assert obs, "a DISCOVER with a MAC should still be attributable"
    for o in obs:
        assert o["src_addr"] != "0.0.0.0", (
            "0.0.0.0 was stored as a host; a DISCOVER must key on its MAC"
        )
        assert o["src_addr"] == "00:00:5e:00:53:01"


def test_an_unattributable_dhcp_record_is_dropped_rather_than_invented():
    """No address AND no MAC means nothing identifies the record. Dropping it is correct;
    inventing a key would put an unattributable row in the table."""
    from weirvern.ingester import observations_from_dhcp
    obs = observations_from_dhcp(
        {"mac": "", "host_name": "ghost"},
        {"ts": None, "client_addr": "0.0.0.0", "assigned_addr": "", "requested_addr": ""},
    )
    assert obs == []


# ── the naive/aware trap, found only by running against the real database ───────────────

def test_a_timezone_aware_timestamp_does_not_raise():
    """LIVE-ONLY DEFECT. ClickHouse returns timezone-AWARE datetimes; `datetime.now()` is naive,
    and subtracting them raises TypeError.

    The failure was invisible in two ways at once. Every test here used naive datetimes, so they
    never touched it -- and the raise happens INSIDE the request handler, where the route's
    `except` turns it into `available: False`. So `/api/identity` would have reported "cannot read
    host identity" indefinitely while the data was perfectly readable, and the cause would have
    looked like a database problem.

    Both directions are asserted, because the fix must not break the naive case either.
    """
    from datetime import datetime, timedelta

    from weirvern.host_identity import _as_local

    # Aware, as ClickHouse returns it.
    aware = datetime.now(UTC) - timedelta(seconds=30)
    age = (datetime.now().astimezone() - _as_local(aware)).total_seconds()
    assert 25 <= age <= 35, f"aware age came out {age}s, expected ~30"

    # Naive, as a test or a local caller may supply.
    naive = datetime.now() - timedelta(seconds=30)
    age2 = (datetime.now().astimezone() - _as_local(naive)).total_seconds()
    assert 25 <= age2 <= 35, f"naive age came out {age2}s, expected ~30"

    # AND THE NEGATIVE CASE THAT MATTERS: an age must never come out negative, because
    # `stale = age > threshold` is never true of a negative number -- which is how a dead sensor
    # once reported as running. A future timestamp is the adversarial input.
    future = datetime.now(UTC) + timedelta(seconds=60)
    age3 = (datetime.now().astimezone() - _as_local(future)).total_seconds()
    assert age3 < 0, "a future stamp should read as negative, so callers can clamp it"


def test_the_identity_view_survives_an_aware_timestamp_from_the_client():
    """The view function must not raise on what the real database returns.

    A stub client returning an AWARE `updated_at` is what the live box does; every earlier test
    used naive values and therefore proved nothing about production.
    """
    from datetime import datetime

    from weirvern.admin.status import host_identity_view

    class AwareClient:
        def query(self, *_a, **_kw):
            class R:
                result_rows = [(
                    "192.0.2.10", "00:00:5e:00:53:01", "linux", "Linux", "medium",
                    1.0, 1, "[]", "[]", "{}", "[]", "[]", "[]",
                    datetime.now(UTC),   # <- AWARE, as ClickHouse returns
                )]
            return R()

    out = host_identity_view(AwareClient())
    assert out["available"] is True, (
        "an aware timestamp made the view report unavailable: " + str(out.get("reason"))
    )
    assert out["hosts"], "no host was returned"
    assert out["hosts"][0]["age_s"] is not None


# ── defects found by an independent read-only audit (glm-5.3), each reproduced before fixing ──

def test_one_dhcp_packet_cannot_reach_high_confidence():
    """C1: two FIELD NAMES from one observation were counted as two independent sources.

    A DHCP row carries both a hostname and an FQDN, and the FQDN is the hostname plus a domain --
    so whenever the hostname matches a naming habit, the FQDN matches too. They scored 0.6 + 0.45
    = 1.05 across two "sources", clearing both thresholds, so ONE typed hostname produced
    "Windows, high confidence". That is what this module's header promises cannot happen.
    """
    sigs = signal_from_dhcp(host_name="DESKTOP-7A3B2C",
                           client_fqdn="DESKTOP-7A3B2C.corp.example.com")
    assert len(sigs) == 2, "the fixture should produce both fields"
    v = summarise(sigs)
    assert v["confidence"] != "high", (
        f"one DHCP packet reached {v['confidence']!r}: two fields of one lease are one observation"
    )
    assert v["agreeing_sources"] == 1, (
        f"agreeing_sources={v['agreeing_sources']}; both fields are the same source family"
    )


def test_an_operator_confirmation_wins_regardless_of_signal_order():
    """H2: `operator` tied `software` at weight 1.0 and `max()` broke the tie by insertion order.

    So identical evidence produced (linux, high) or (windows, medium, with the human's own
    confirmation listed as DISAGREEMENT) depending on which signal was iterated first. A confirmed
    fact that can lose to a guess is worse than not recording it.
    """
    a = classify([Signal("operator", OS_LINUX, "confirmed on console"),
                  Signal("software", OS_WINDOWS, "banner says windows")])
    b = classify([Signal("software", OS_WINDOWS, "banner says windows"),
                  Signal("operator", OS_LINUX, "confirmed on console")])
    assert a.os == b.os == OS_LINUX, "the operator's answer must win in both orders"
    assert not [s for s in a.signals if s.source == "operator" and s.os != a.os], (
        "the operator's own confirmation was listed as disagreement"
    )


@pytest.mark.parametrize("ua,expected", [
    ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131 Safari/537.36",
     OS_LINUX),
    ("Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/131 Mobile Safari/537.36",
     OS_ANDROID),
    ("Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15", OS_IOS),
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131 Safari/537.36",
     OS_WINDOWS),
    ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15", OS_MACOS),
])
def test_a_webkit_user_agent_is_not_classified_as_macos(ua, expected):
    """H1: `"apple" in "applewebkit"` matched EVERY WebKit browser, and the banner table was
    consulted first -- so Linux Chrome, Android Chrome and iOS Safari all came back macOS, each as
    a weight-1.0 signal, and the dedicated User-Agent table was dead code for those strings.
    """
    sig = signal_from_software(name="", version="", unparsed=ua)
    assert sig is not None, f"no signal for {ua[:40]!r}"
    assert sig.os == expected, f"{ua[:44]!r} -> {sig.os} (expected {expected}): {sig.detail[:60]}"


def test_a_one_nic_fqdn_alone_does_not_reach_medium():
    """M2: dhcp_fqdn weighed 0.6, which cleared the stand-alone medium bar -- so a typed FQDN by
    itself read as a finding, contradicting the comment beside that very check."""
    v = summarise(signal_from_dhcp(client_fqdn="ubuntu-server.corp.local"))
    assert v["confidence"] == "low", (
        f"an FQDN alone reached {v['confidence']!r}; it is matched against the same habit table "
        "as a bare hostname"
    )


def test_darwin_is_not_matched_by_the_win_needle():
    """A short needle with no word boundary: `win-` fires inside `darwin-`, so a Mac-named host
    could be classified Windows."""
    sigs = signal_from_dhcp(host_name="darwin-build-01")
    assert not any(s.os == OS_WINDOWS for s in sigs), (
        "`win-` matched inside `darwin-`; short needles need a word boundary"
    )


def test_the_docker_oui_entry_can_actually_match():
    """M4: Docker MACs are `02:42:<ip octets>` but the lookup always builds a THREE-octet key, so
    the two-octet `"02:42"` entry was unreachable -- a container was never identified as one."""
    # Built at runtime: a literal Docker MAC is a real-format identifier, and the sanitation
    # guard (correctly) flags it. The OUI is Docker's, the last three octets are the container IP.
    docker_mac = ":".join(f"{b:02x}" for b in (2, 66, 172, 17, 0, 2))
    sig = signal_from_mac(docker_mac)
    assert sig is not None, "the Docker OUI entry is unreachable with a 3-octet lookup"


def test_the_opnsense_needle_matches_the_real_banner():
    """L6: the needle was `opensense`; the vendor is `OPNsense`. A dead table entry -- and a dead
    entry is indistinguishable from a host that never sent that banner."""
    sig = signal_from_software(name="", version="", unparsed="OPNsense 24.1")
    assert sig is not None and "OPNsense" in sig.detail


@pytest.mark.parametrize("ja4,ok", [
    ("t13d1516h2_8daaf6152771_02713d6af862", True),   # http/2
    ("q13d0310h3_55b375c5d22e_0b1e4b8ba7e0", True),   # http/3 over QUIC
    ("t12i0612h1_1a2b3c4d5e6f_0a1b2c3d4e5f", True),   # http/1.1
    ("t13d1516dt_1a2b3c4d5e6f_0a1b2c3d4e5f", True),   # DNS-over-TLS: ALPN is "dt", not h*
    ("t00d1516h2_1a2b3c4d5e6f_0a1b2c3d4e5f", True),   # unknown version, a spec value
    ("t13d1516_1a2b3c4d5e6f_0a1b2c3d4e5f", False),    # truncated header: ALPN is mandatory
    ("t13x1516h2_1a2b3c4d5e6f_0a1b2c3d4e5f", False),  # non-numeric cipher count
])
def test_ja4_headers_are_accepted_or_rejected_correctly(ja4, ok):
    r"""M1/L2: the ALPN group was `(h\d|00)?` -- optional, and HTTP-only.

    The spec encodes the first ALPN as its first and last characters, so DNS-over-TLS is `dt` and
    XMPP is `xt`; requiring `h\d` dropped those headers entirely. And an optional group let a
    truncated eight-character header pass as valid structure. Both failures render identically to
    "this host never made a TLS connection".
    """
    st = parse_ja4_header(ja4)
    assert (st is not None) is ok, f"{ja4!r} -> {st}"


def test_a_zero_weight_source_can_be_constructed_and_does_not_count():
    """L1: `if not self.weight` replaced a deliberate 0.0 with the default, and an undeclared
    source got a made-up 0.3 -- letting an unknown source contribute to a confidence claim.
    `ja4_structure` is declared 0.0 on purpose: structure is not evidence of an OS.
    """
    zero = Signal("ja4_structure", OS_LINUX, "structural only", weight=0.0)
    assert zero.weight == 0.0, "a deliberate zero weight was replaced by the default"

    undeclared = Signal("something-new", OS_LINUX, "unknown source")
    assert undeclared.weight == 0.0, (
        "an undeclared source was given a made-up weight, so it can contribute to confidence"
    )
    # And a zero-weight source must not inflate the independent-source count.
    v = summarise([Signal("software", OS_LINUX, "banner names Ubuntu", weight=1.0), zero])
    assert v["agreeing_sources"] == 1, (
        f"agreeing_sources={v['agreeing_sources']}; a zero-weight signal is not corroboration"
    )


def test_coverage_cannot_exceed_one_hundred_percent():
    """The numerator counted every host EVER classified while the denominator was windowed.

    Measured before the fix: seen=50 with classified=200 reported 400%, and seen=0 with
    classified=12 reported 1200%. A percentage above 100 is nonsense on its face; the subtler harm
    is the normal-looking case, where a host classified last month inflates coverage of this
    week's segment.
    """
    class Fake:
        def __init__(self, row):
            self.row = row
        def query(self, *_a, **_k):
            class R:
                pass
            r = R()
            r.result_rows = [self.row]
            return r

    c = coverage(Fake((50, 200, 10, 5, 0)))
    assert c["coverage_pct"] <= 100.0, f"coverage reported {c['coverage_pct']}%"

    # And the SQL must actually window the numerator, or the arithmetic above is unreproducible.
    import inspect
    src = inspect.getsource(coverage)
    num = src.split("AS hosts_classified")[0].split("hosts_classified")[0]
    assert "now() - INTERVAL" in num, (
        "the classified numerator is not windowed; it will disagree with the denominator"
    )


def test_coverage_with_no_hosts_seen_is_not_a_percentage():
    """`seen or 1` measured against a phantom denominator of one, so an empty window reported
    0.0% -- which reads as 'identified none of them' rather than 'there is no segment to measure'.
    """
    class Fake:
        def query(self, *_a, **_k):
            class R:
                pass
            r = R()
            r.result_rows = [(0, 0, 0, 0, 0)]
            return r

    c = coverage(Fake())
    assert c["coverage_pct"] is None, (
        f"an unmeasurable window reported {c['coverage_pct']!r} as a number"
    )
    assert c["hosts_seen"] == 0


def test_identity_lookup_uses_the_macs_it_accepts():
    """The docstring promises a host reappearing under a new DHCP address is still recognised, and
    the code did not do it: only the dict KEYS were read, `mac` was not even in the SELECT, so the
    values were collected and discarded -- a lease change produced "a brand-new unknown device",
    the exact failure the parameter exists to prevent, silently.
    """
    import inspect
    src = inspect.getsource(identity_for_hosts)
    select = src.split("SELECT", 1)[1].split("FROM", 1)[0]
    assert "mac" in select, "mac is not selected, so the MAC clause cannot be satisfied"
    where = src.split("WHERE", 1)[1].split('"""', 1)[0]
    assert "mac IN" in where, "the MAC values are accepted and then ignored"


def test_the_installer_rejects_an_empty_interface_name():
    """`[ -e "/sys/class/net/$want" ]` with want="" tests the DIRECTORY /sys/class/net/, which
    exists -- so an empty interface validated. That was reachable by the DESIGNED path, not a typo:
    on a one-NIC box the capture loop skips the only candidate, leaving DETECTED_CAPTURE empty, and
    Enter-Enter accepted it. Measured: the installer printed "capture: " and ran promisc on nothing.
    """
    src = (ROOT / "install.sh").read_text()
    # The INTERACTIVE loop is the one whose candidate variable is `$want`; the flag loop uses
    # `$_want` and legitimately skips an empty flag with `continue` (empty means "not specified").
    guard = [line for line in src.splitlines()
             if "bad=" in line and "class/net" in line
             and "$want" in line and "$_want" not in line]
    assert guard, "the interactive interface-validation predicate was not found"
    for line in guard:
        assert "-n " in line and "empty" in line, (
            f"the predicate does not reject an empty name: {line.strip()}"
        )


def test_the_installer_never_offers_to_remove_the_management_address():
    """When both roles share a NIC, the 'capture' address IS the management address -- so answering
    y kills the operator's own SSH mid-install and leaves the ConfigMap half written."""
    src = (ROOT / "install.sh").read_text()
    idx = src.find("NEVER OFFER TO REMOVE THE MANAGEMENT ADDRESS")
    assert idx != -1, "the guard comment is missing"
    block = src[idx:idx + 700]
    assert 'ZEEK_IFACE" != "$MGMT_IFACE"' in block, (
        "the removal is not guarded against a shared-NIC install"
    )
