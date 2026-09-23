"""ATT&CK technique mapping: the rules, and — more importantly — their limits.

WHAT THESE TESTS ARE REALLY GUARDING.

A technique mapping is the most dangerous kind of feature to get wrong, because it converts a
threshold crossing into a named behaviour with a MITRE ID attached. An analyst who reads
"T1078 Valid Accounts" stops looking. So the assertions here are weighted towards the ways a
mapping OVERSTATES:

  * a busy server must not map to a port scan (volume alone is not discovery)
  * an ordinary DCE/RPC call must not map to service execution (only a service-control
    OPERATION is)
  * an empty result must never read as "benign" (it means "not in this set")
  * every emitted ID must be a real ATT&CK technique, and the mapping must not claim
    endpoint-only techniques that a network tap cannot see

The positive cases matter too, but they are the easy direction. These tests exist mainly to
pin the negative ones.
"""
from __future__ import annotations

import re

import pytest

from weirvern import attack

# ── every emitted technique must be a real, network-observable ATT&CK technique ──

# The subset of ATT&CK that a network sensor can legitimately observe, with its real names.
# Duplicated here ON PURPOSE: this is the independent check. If weirvern/attack.py renamed or
# re-identified a technique, a test that imported the table could not notice.
KNOWN = {
    "T1046": "Network Service Discovery",
    "T1595": "Active Scanning",
    "T1021": "Remote Services",
    "T1021.002": "Remote Services: SMB/Windows Admin Shares",
    "T1021.003": "Remote Services: Distributed Component Object Model",
    "T1569.002": "System Services: Service Execution",
    "T1059": "Command and Scripting Interpreter",
    "T1041": "Exfiltration Over C2 Channel",
    "T1048": "Exfiltration Over Alternative Protocol",
    "T1071": "Application Layer Protocol",
    "T1071.004": "Application Layer Protocol: DNS",
    "T1573": "Encrypted Channel",
    "T1078": "Valid Accounts",
    "T1558": "Steal or Forge Kerberos Tickets",
    "T1110": "Brute Force",
    "T1018": "Remote System Discovery",
    "T1190": "Exploit Public-Facing Application",
    "T1200": "Hardware Additions",
}


def test_every_technique_id_is_well_formed():
    """`T` + digits, optionally `.` + 3 digits for a sub-technique."""
    for tid in attack.TECHNIQUES:
        assert re.fullmatch(r"T\d{4}(\.\d{3})?", tid), f"{tid} is not a valid ATT&CK id"


def test_every_technique_id_and_name_matches_mitre():
    """THE KEY CHECK. A wrong name on a right ID is how a mapping misleads: the ID looks
    authoritative in a table while the label sends the analyst somewhere else."""
    for tid, tech in attack.TECHNIQUES.items():
        assert tid in KNOWN, (
            f"{tid} is not in this project's list of network-observable techniques -- if it is "
            f"genuinely observable, add it to KNOWN with its real name"
        )
        assert tech.name == KNOWN[tid], (
            f"{tid} is named {tech.name!r} but MITRE calls it {KNOWN[tid]!r}"
        )


def test_the_mapping_does_not_claim_endpoint_only_techniques():
    """Process injection, credential dumping and registry edits are not visible from a flow
    record. Mapping them would be the most damaging kind of false confidence."""
    for tid in ("T1055", "T1003", "T1112", "T1547", "T1053", "T1562"):
        assert tid not in attack.TECHNIQUES, (
            f"{tid} requires endpoint telemetry and must not be mapped by a network sensor"
        )
        assert tid in attack.OUT_OF_REACH, (
            f"{tid} is correctly not mapped, but the reason is not stated anywhere -- so a "
            f"reader cannot tell 'not observable' from 'not implemented'"
        )


def test_out_of_reach_entries_explain_themselves():
    for tid, why in attack.OUT_OF_REACH.items():
        assert why, f"{tid} has no reason recorded"
        assert len(why) > 20, f"{tid}'s reason is too terse to be useful: {why!r}"


# ── Discovery: T1046 / T1595 ────────────────────────────────────────────────────

def test_a_zero_byte_port_scan_maps_to_service_discovery():
    """The case the whole detection stack was tuned on: 305 flows, 0 bytes, 300 ports. DBSCAN
    scores it 0.99 while the volume models have no opinion, because a scan moves no bytes."""
    matches = attack.map_techniques({
        "unique_dst_ports": 300, "port_entropy": 7.9, "total_bytes": 0, "resp_bytes": 0,
        "unique_dst_ips": 60,   # a RANGE, which is what makes it reconnaissance
    })
    ids = {m.technique.id for m in matches}
    assert "T1046" in ids
    assert "T1595" in ids, "a sweep across 60 hosts is range reconnaissance as well as discovery"


def test_a_deep_single_host_scan_is_not_reconnaissance():
    """THE DISTINCTION THE FIRST VERSION GOT WRONG. 900 ports on ONE host is a deep T1046.
    Calling it T1595 would tell the analyst something external is mapping the network, when
    the evidence says one host is being probed hard."""
    matches = attack.map_techniques({
        "unique_dst_ports": 900, "port_entropy": 9.0, "total_bytes": 0, "unique_dst_ips": 1,
    })
    ids = {m.technique.id for m in matches}
    assert "T1046" in ids
    assert "T1595" not in ids, (
        "a single-host deep scan was mapped to Active Scanning; that technique is about "
        "sweeping a range, and the measurement is hosts, not ports"
    )


def test_a_busy_server_is_not_a_port_scan():
    """THE OVERSTATEMENT THIS MUST PREVENT. A server talking to many clients touches many
    ports and moves real data. Ports alone must never be sufficient."""
    matches = attack.map_techniques({
        "unique_dst_ports": 400, "port_entropy": 8.0,
        "total_bytes": 5_000_000, "resp_bytes": 9_000_000,
    })
    assert "T1046" not in {m.technique.id for m in matches}, (
        "a high-volume host with many ports was mapped to a port scan; the zero-byte "
        "qualifier is load-bearing"
    )


def test_a_narrow_scan_does_not_map_to_active_scanning():
    """T1595 is range-sized pre-compromise scanning. Ten ports is discovery, not that."""
    matches = attack.map_techniques({
        "unique_dst_ports": 120, "port_entropy": 4.0, "total_bytes": 100,
    })
    ids = {m.technique.id for m in matches}
    assert "T1046" in ids
    assert "T1595" not in ids


def test_low_entropy_port_spread_is_not_a_scan():
    """Many packets to few ports is a flood, not discovery. Entropy is what separates them."""
    matches = attack.map_techniques({
        "unique_dst_ports": 300, "port_entropy": 0.4, "total_bytes": 0,
    })
    assert "T1046" not in {m.technique.id for m in matches}


def test_scan_evidence_names_the_measurement_and_the_threshold():
    """An analyst must be able to check the claim. Evidence that says only "a scan was
    detected" cannot be verified and cannot be argued with."""
    matches = attack.map_techniques({
        "unique_dst_ports": 300, "port_entropy": 7.9, "total_bytes": 0,
    })
    scan = next(m for m in matches if m.technique.id == "T1046")
    assert scan.evidence, "no evidence recorded"
    joined = " ".join(scan.evidence)
    assert "300" in joined, "the observed port count is not in the evidence"
    assert str(attack.DISCOVERY_MIN_PORTS) in joined, "the threshold is not in the evidence"


def test_discovery_confidence_scales_with_the_port_count():
    narrow = attack.map_techniques(
        {"unique_dst_ports": 120, "port_entropy": 4.0, "total_bytes": 0})
    wide = attack.map_techniques(
        {"unique_dst_ports": 900, "port_entropy": 9.0, "total_bytes": 0})
    rank = {"low": 1, "medium": 2, "high": 3}
    n = next(m for m in narrow if m.technique.id == "T1046")
    w = next(m for m in wide if m.technique.id == "T1046")
    assert rank[w.confidence] >= rank[n.confidence], (
        "a 900-port scan is reported as less confident than a 120-port one "
        # Confidence is a LABEL. Comparing the strings alphabetically puts 'high' below
        # 'medium', which is a defect in the test rather than in the mapping.
    )


# ── Remote system discovery: T1018 ──────────────────────────────────────────────

def test_many_hosts_with_no_data_maps_to_remote_system_discovery():
    matches = attack.map_techniques({
        "unique_dst_ips": 60, "total_bytes": 200, "unique_dst_ports": 60, "port_entropy": 5.0,
    })
    assert "T1018" in {m.technique.id for m in matches}


def test_many_hosts_with_real_data_is_not_discovery():
    """A CDN or a backup job contacts many hosts and moves real volume."""
    matches = attack.map_techniques({"unique_dst_ips": 60, "total_bytes": 50_000_000})
    assert "T1018" not in {m.technique.id for m in matches}


# ── Exfiltration ────────────────────────────────────────────────────────────────

def test_one_way_large_transfer_maps_to_exfiltration():
    matches = attack.map_techniques({
        "total_bytes": 50_000_000, "orig_bytes": 50_000_000, "resp_bytes": 1000,
        "dst_port": 443,
    })
    ids = {m.technique.id for m in matches}
    assert "T1041" in ids
    assert "T1048" not in ids, "443 is a standard web port, so this is not the alternative-protocol case"


def test_exfiltration_on_an_odd_port_also_maps_to_alternative_protocol():
    # `zeek_outbound_ratio` is the REAL asymmetry field, not orig_bytes/resp_bytes: those are not
    # columns of flows_aggregated and nothing merges them in, so the previous form of this test
    # passed on input production never produced. T1048 additionally needs a destination port,
    # which is a per-FLOW fact on raw `flows` -- so this asserts the volume+asymmetry half, which
    # is what the volumetric row can actually support.
    matches = attack.map_techniques({
        "total_bytes": 50_000_000, "zeek_outbound_ratio": 0.9998,
    })
    assert "T1041" in {m.technique.id for m in matches}


def test_balanced_large_transfer_is_not_exfiltration():
    """A large two-way transfer is a legitimate bulk protocol -- SMB copy, backup, video. The
    ratio is what makes 'large' mean 'one way'."""
    matches = attack.map_techniques({
        "total_bytes": 50_000_000, "zeek_outbound_ratio": 50_000_000 / 98_000_000,
    })
    assert "T1041" not in {m.technique.id for m in matches}


def test_a_normal_download_is_not_exfiltration():
    matches = attack.map_techniques({"total_bytes": 2_000, "zeek_outbound_ratio": 0.25})
    assert matches == []


# ── DNS tunnelling / C2 ─────────────────────────────────────────────────────────

def test_high_entropy_unanswered_dns_maps_to_dns_c2():
    # The names the Zeek query ACTUALLY emits. This test previously passed
    # `dns_query_count` / `dns_mean_entropy` / `dns_no_answer`, none of which any query
    # produces -- so it asserted the rule fired on keys that, in production, always read 0.0.
    # A test written against invented names cannot fail for the reason it exists.
    matches = attack.map_techniques({
        "zeek_dns_count": 200, "zeek_dns_mean_query_entropy": 4.4, "zeek_dns_failed_ratio": 0.75,
    })
    assert "T1071.004" in {m.technique.id for m in matches}


def test_normal_dns_does_not_map_to_tunnelling():
    """Ordinary browsing produces many queries with real answers. Requiring the failure ratio
    is what keeps this from firing on every busy hour."""
    matches = attack.map_techniques({
        "dns_query_count": 200, "dns_mean_entropy": 2.9, "dns_no_answer": 3,
    })
    assert "T1071.004" not in {m.technique.id for m in matches}


def test_entropy_alone_is_not_tunnelling():
    matches = attack.map_techniques({
        "dns_query_count": 200, "dns_mean_entropy": 4.9, "dns_no_answer": 0,
    })
    assert "T1071.004" not in {m.technique.id for m in matches}


# ── Kerberos and authentication ─────────────────────────────────────────────────

def test_many_DISTINCT_spns_from_one_principal_maps_to_kerberos_ticket_theft():
    """Kerberoasting is one client requesting many service principals in order to crack the
    tickets offline -- and it is invisible in conn.log.

    `kind` is set because that is what the protocol union emits; see the F044 note below for why a
    row without it exercises a different code path.
    """
    rows = [{"kind": "zeek_kerberos", "operation": "TGS", "endpoint": f"svc{i}/host.corp.local"}
            for i in range(attack.KERB_MIN_SPNS + 5)]
    matches = attack.map_zeek_techniques(rows)
    assert "T1558" in {m.technique.id for m in matches}


# ── THE THRESHOLD COUNTED REQUESTS, NOT SERVICE PRINCIPALS (audit F044) ──────────────────────────
#
# `KERB_MIN_SPNS` is named for service principals and the comment says "many DISTINCT service
# principals", but the rule tested `kerb_types["TGS"]` -- a bare per-request-type counter. The SPN was
# already in the row (`request_type AS operation, service AS endpoint`) and simply never read.
#
# MEASURED by driving the real mapper, with `kind` set as the union sets it:
#     15 requests naming 15 DISTINCT SPNs -> T1558   (genuine signature)
#     15 requests naming  1 SPN, x15      -> T1558   (FALSE POSITIVE before the fix)
#    200 requests naming  1 SPN          -> T1558   (FALSE POSITIVE before the fix)
#
# This matters because asking for the SAME service repeatedly is what any Kerberos client does, so
# the rule fired on the benign pattern while calling it a roasting signature.


def test_one_SPN_requested_repeatedly_is_NOT_kerberoasting():
    """THE DEFECT. Ten tickets for one service is a client reconnecting, not an attack."""
    rows = [{"kind": "zeek_kerberos", "operation": "TGS", "endpoint": "cifs/dc01.example.com"}
            for _ in range(attack.KERB_MIN_SPNS + 5)]
    ids = {m.technique.id for m in attack.map_zeek_techniques(rows)}
    assert "T1558" not in ids, (
        f"{len(rows)} TGS requests naming ONE service principal raised Kerberoasting. The rule is "
        f"counting requests, not distinct SPNs (audit F044)"
    )


def test_a_FLOOD_against_one_SPN_is_still_not_kerberoasting():
    """The strongest version: 200 requests, one SPN. Volume alone must not manufacture the signal."""
    rows = [{"kind": "zeek_kerberos", "operation": "TGS", "endpoint": "host/dc01.example.com"}
            for _ in range(200)]
    ids = {m.technique.id for m in attack.map_zeek_techniques(rows)}
    assert "T1558" not in ids, "200 requests for a single SPN raised Kerberoasting"


def test_an_empty_spn_does_not_count_as_a_distinct_principal():
    """A log line with no `service` must not be counted as a principal.

    Counting an absent SPN as distinct would manufacture the exact signal being measured: a window of
    kerberos rows with no service field would look like a roast.
    """
    rows = [{"kind": "zeek_kerberos", "operation": "TGS", "endpoint": ""}
            for _ in range(attack.KERB_MIN_SPNS + 20)]
    ids = {m.technique.id for m in attack.map_zeek_techniques(rows)}
    assert "T1558" not in ids, (
        f"{attack.KERB_MIN_SPNS + 20} TGS rows with NO service principal raised Kerberoasting; an "
        f"absent SPN is being counted as a distinct one"
    )


def test_the_evidence_reports_BOTH_numbers():
    """The operator must be able to tell a real roast from a retried service."""
    rows = [{"kind": "zeek_kerberos", "operation": "TGS", "endpoint": f"svc{i}/h.example.com"}
            for i in range(14)]
    ev = [m.evidence[0] for m in attack.map_zeek_techniques(rows) if m.technique.id == "T1558"]
    assert ev, "the genuine signature did not fire"
    assert "14 distinct TGS service principals" in ev[0], ev[0]
    assert "14 requests" in ev[0], ev[0]


# ── `endpoint` IS NOT A DCE/RPC FIELD (audit F044, found while measuring the above) ──────────────
#
# The protocol union reuses trailing column names across arms, and FIVE arms put something other than
# a DCE endpoint in `endpoint`: kerberos -> service, tunnel -> action, quic -> server_name,
# ldap_search -> base_object, dhcp -> mac. Reading it unconditionally made a pure-Kerberos window
# raise T1021.003 with evidence "DCE/RPC to endpoint cifs/dc01.example.com".


@pytest.mark.parametrize(("kind", "operation", "endpoint"), [
    ("zeek_kerberos", "TGS", "cifs/dc01.example.com"),
    ("zeek_tunnel", "dns", "established"),
    ("zeek_quic", "h3", "host-a.example.com"),
    ("zeek_ldap_search", "sub", "DC=corp,DC=local"),
    ("zeek_dhcp", "ACK", "aa:bb:cc:dd:ee:ff"),
])
def test_a_NON_dce_arm_does_not_raise_the_DCE_technique(kind, operation, endpoint):
    """Each of these puts a real value in `endpoint` that is NOT a DCE endpoint."""
    rows = [{"kind": kind, "operation": operation, "endpoint": endpoint}]
    ids = {m.technique.id for m in attack.map_zeek_techniques(rows)}
    assert "T1021.003" not in ids, (
        f"a {kind} row raised T1021.003 with the evidence naming {endpoint!r} as a DCE/RPC endpoint. "
        f"`endpoint` is a shared column alias, not a DCE field (audit F044)"
    )


def test_the_real_dce_rpc_arm_still_raises_the_technique():
    """The allowlist must not have broken the case it exists for."""
    rows = [{"kind": "zeek_dce_rpc", "operation": "NetrShareEnum", "endpoint": "lsarpc"}]
    ids = {m.technique.id for m in attack.map_zeek_techniques(rows)}
    assert "T1021.003" in ids, "a genuine DCE/RPC row no longer raises T1021.003"

    rows2 = [{"kind": "zeek_dce_rpc", "operation": "CreateServiceW", "endpoint": "svcctl"}]
    ids2 = {m.technique.id for m in attack.map_zeek_techniques(rows2)}
    assert "T1021.003" in ids2, "a real service-control operation no longer raises T1021.003"


def test_a_row_with_NO_kind_keeps_the_previous_behaviour():
    """Compatibility, deliberately.

    Callers that hand-build a row predate the `kind` column. Silently dropping their DCE evidence
    would trade a false positive for a false negative.
    """
    rows = [{"operation": "NetrShareEnum", "endpoint": "lsarpc"}]
    ids = {m.technique.id for m in attack.map_zeek_techniques(rows)}
    assert "T1021.003" in ids, (
        "a row without `kind` stopped raising T1021.003; rows that predate the column must keep "
        "working"
    )


def test_a_few_tgs_requests_do_not_map_to_roasting():
    """Normal Kerberos use requests TGS tickets constantly. The threshold is the distinction."""
    rows = [{"operation": "TGS", "endpoint": "cifs/dc01"} for _ in range(3)]
    assert "T1558" not in {m.technique.id for m in attack.map_zeek_techniques(rows)}


def test_authentication_failures_map_to_brute_force():
    rows = [{"username": "a", "success": False} for _ in range(40)]
    matches = attack.map_zeek_techniques(rows)
    assert "T1110" in {m.technique.id for m in matches}


def test_successful_authentications_are_not_brute_force():
    rows = [{"username": "a", "success": True} for _ in range(40)]
    assert "T1110" not in {m.technique.id for m in attack.map_zeek_techniques(rows)}


# ── Lateral movement, from the Zeek protocol logs ───────────────────────────────

def test_admin_share_access_maps_to_smb_admin_shares():
    """`\\\\HOST\\ADMIN$` is a direct observation: conn.log reports `service=smb` and nothing
    else, which is why smb_mapping.log had to be ingested."""
    matches = attack.map_zeek_techniques([{"smb_path": "\\\\DC01\\ADMIN$"}])
    ids = {m.technique.id for m in matches}
    assert "T1021.002" in ids
    assert "T1021" in ids, "the parent technique should also be reported: different tactic"


def test_an_ordinary_share_is_not_admin_share_access():
    matches = attack.map_zeek_techniques([{"smb_path": "\\\\FILESERVER\\public\\docs"}])
    assert "T1021.002" not in {m.technique.id for m in matches}


def test_service_creation_maps_to_service_execution():
    """PsExec and WMI arrive as DCE/RPC to SVCCTL with a service-control operation."""
    matches = attack.map_zeek_techniques(
        [{"operation": "CreateServiceW", "endpoint": "SVCCTL"}])
    ids = {m.technique.id for m in matches}
    assert "T1569.002" in ids
    assert "T1021.003" in ids


def test_a_read_only_rpc_call_is_only_low_confidence_lateral_movement():
    """THE OVERSTATEMENT CASE. An RPC endpoint was touched, but no service was created -- so
    claiming service execution would be naming a technique the evidence does not support."""
    matches = attack.map_zeek_techniques(
        [{"operation": "NetShareEnum", "endpoint": "SRVSVC"}])
    ids = {m.technique.id: m for m in matches}
    assert "T1569.002" not in ids, "no service-control operation was observed"
    assert ids.get("T1021.003") is not None
    assert ids["T1021.003"].confidence == "low"


def test_deprecated_tls_maps_to_encrypted_channel_at_low_confidence():
    rows = [{"ja4": "t10d190800_abc", "version": "TLSv10"} for _ in range(10)]
    matches = attack.map_zeek_techniques(rows)
    tls = [m for m in matches if m.technique.id == "T1573"]
    assert tls and tls[0].confidence == "low", (
        "using TLS at all is not a technique; only the deprecated-version signal is, and it is "
        "weak evidence"
    )


def test_modern_tls_is_not_a_technique():
    rows = [{"ja4": "t13d1516h2_abc", "version": "TLSv13"} for _ in range(10)]
    assert "T1573" not in {m.technique.id for m in attack.map_zeek_techniques(rows)}


# ── absence, which must never be reported as safety ─────────────────────────────

def test_an_empty_zeek_row_set_yields_no_matches():
    """On this deployment the Zeek join is sparse (91 NetFlow hosts vs 35 Zeek hosts, overlap
    of 2), so this is the COMMON case. It must return empty rather than raising or guessing."""
    assert attack.map_zeek_techniques([]) == []


def test_an_unremarkable_window_maps_to_nothing():
    assert attack.map_techniques({
        "unique_dst_ports": 4, "port_entropy": 1.2, "total_bytes": 50_000,
        "resp_bytes": 40_000, "unique_dst_ips": 3,
    }) == []


def test_no_match_is_never_described_as_benign():
    """The single most important string in this module. "no technique matched" is a statement
    about the mapping; "benign" would be a statement about the network."""
    text = attack.summarise([])
    assert "no ATT&CK technique matched" in text
    for word in ("benign", "clean", "safe", "no threat", "nothing found", "normal"):
        assert word not in text.lower(), (
            f"the no-match summary contains {word!r}, which reads as a clearance"
        )


def test_the_summary_hedges_a_match():
    """A match is a hypothesis. The wording must not present it as a conclusion."""
    matches = attack.map_techniques(
        {"unique_dst_ports": 300, "port_entropy": 7.9, "total_bytes": 0})
    text = attack.summarise(matches)
    assert "consistent with" in text, f"the summary does not hedge: {text!r}"


def test_label_is_short_enough_for_a_table_cell():
    matches = attack.map_techniques({
        "unique_dst_ports": 900, "port_entropy": 9.0, "total_bytes": 0, "unique_dst_ips": 90,
    })
    text = attack.label(matches)
    assert len(text) <= 120, f"label is {len(text)} chars and would be truncated in a cell"
    assert attack.label([]) == ""


# ── robustness: this runs on the alert path ─────────────────────────────────────

def test_a_malformed_row_does_not_raise():
    """These values come from a database row or a JSON blob. A crash here takes the alert path
    down, which is worse than a missing technique -- the alert still has to be delivered."""
    for bad in ({"unique_dst_ports": "many"}, {"total_bytes": None},
                {"port_entropy": ""}, {"zeek_dns_count": "unknown"}):
        attack.map_techniques(bad)  # must not raise


def test_a_string_number_still_parses():
    """ClickHouse returns some aggregates as strings depending on the driver version."""
    matches = attack.map_techniques(
        {"unique_dst_ports": "300", "port_entropy": "7.9", "total_bytes": "0"})
    assert "T1046" in {m.technique.id for m in matches}


def test_zeek_rule_requires_its_own_evidence_not_the_flow_row():
    """Every Zeek rule keys on a protocol field. A row with only volume measurements must not
    accidentally satisfy a protocol rule."""
    assert attack.map_zeek_techniques([{"total_bytes": 99_000_000}]) == []


# ── coverage reporting ──────────────────────────────────────────────────────────

def test_coverage_lists_what_is_mapped_and_what_is_not():
    cov = attack.coverage()
    assert cov["technique_count"] == len(attack.TECHNIQUES)
    assert cov["tactics"], "no tactics reported"
    assert cov["out_of_reach"], "nothing reported as unreachable"
    assert cov["attack_version"].startswith("v")


def test_coverage_states_the_network_only_limitation():
    """Exported so the GUI and the docs can state it. Without it, an empty mapping on a screen
    reads as an all-clear."""
    limits = attack.coverage()["limits"].lower()
    assert "network" in limits
    assert "endpoint" in limits, "the limitation must name what is missing, not just exist"
    assert "not evidence" in limits or "not" in limits


def test_attribution_is_present():
    """ATT&CK is free to use commercially WITH attribution. That requirement is discharged in
    the code rather than in a wish."""
    assert "MITRE" in attack.ATTRIBUTION
    assert "attack.mitre.org" in attack.ATTRIBUTION
    assert attack.ATTRIBUTION in attack.coverage()["attribution"]


def test_every_technique_declares_its_network_visibility():
    """An analyst reading a technique label needs to know whether Weirvern SAW it or INFERRED
    it. Every entry carries the answer."""
    for tid, tech in attack.TECHNIQUES.items():
        assert tech.network_visibility, f"{tid} does not state what a network sensor can see"
        # The rating must be the FIRST TOKEN, and the entries qualify it in several legitimate
        # styles -- "STRONG. Many destination ports ...", "STRONG for the connection, ...",
        # "WEAK without payload inspection", "NOT VISIBLE. A device plugged in ...". Rather
        # than normalising the prose, take the first word and check it against the rating
        # vocabulary; a genuine typo or a missing rating still fails.
        # `NOT VISIBLE` is two words, so the prefix is checked rather than a single token.
        text = tech.network_visibility.strip()
        head = next((r for r in ("NOT VISIBLE", "STRONG", "PARTIAL", "WEAK")
                     if text.startswith(r)), None)
        assert head is not None, (
            f"{tid}'s visibility {tech.network_visibility[:30]!r} does not open with a rating"
        )


def test_mapped_ids_matches_the_table():
    assert attack.mapped_ids() == set(attack.TECHNIQUES)


def test_a_match_serialises_for_the_api():
    matches = attack.map_techniques(
        {"unique_dst_ports": 300, "port_entropy": 7.9, "total_bytes": 0})
    d = matches[0].as_dict()
    for key in ("id", "name", "tactic", "confidence", "evidence", "network_visibility"):
        assert key in d, f"the serialised match is missing {key}"
    assert isinstance(d["evidence"], list), "evidence must be a list for the GUI to render"


def test_every_tactic_used_is_a_real_attack_tactic():
    real = {
        "Reconnaissance", "Resource Development", "Initial Access", "Execution",
        "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
        "Discovery", "Lateral Movement", "Collection", "Command and Control",
        "Exfiltration", "Impact",
    }
    for tid, tech in attack.TECHNIQUES.items():
        assert tech.tactic in real, f"{tid} has tactic {tech.tactic!r}, which is not an ATT&CK tactic"


# ── THE AS-REP ARM HAD NO TEST, SO ITS MUTATION SURVIVED (audit F044) ────────────────────────────
#
# Mutation testing caught the TGS threshold reverting but MISSED the AS arm reverting, because every
# test above only ever exercised TGS. The two arms were fixed together and only one was pinned.


def test_many_DISTINCT_as_spns_maps_to_as_rep_roasting():
    """AS-REP roasting iterates principals to find those without preauth required."""
    rows = [{"kind": "zeek_kerberos", "operation": "AS", "endpoint": f"user{i}@corp.local"}
            for i in range(attack.KERB_MIN_SPNS + 5)]
    ids = {m.technique.id for m in attack.map_zeek_techniques(rows)}
    assert "T1558" in ids, (
        f"{len(rows)} AS requests naming distinct principals did not raise T1558; the AS arm is not "
        f"counting distinct principals"
    )


def test_one_AS_principal_requested_repeatedly_is_NOT_as_rep_roasting():
    """THE AS ARM'S OWN F044 CASE: the same defect shape as TGS, on the arm nothing tested."""
    rows = [{"kind": "zeek_kerberos", "operation": "AS", "endpoint": "user1@corp.local"}
            for _ in range(attack.KERB_MIN_SPNS + 5)]
    ids = {m.technique.id for m in attack.map_zeek_techniques(rows)}
    assert "T1558" not in ids, (
        f"{len(rows)} AS requests naming ONE principal raised AS-REP roasting; the AS arm is counting "
        f"REQUESTS, not distinct principals (audit F044)"
    )


def test_an_absent_spn_never_becomes_a_distinct_principal():
    """THE EMPTY-SPN CASE, with rows that DIFFER in every other field.

    My first version used identical rows with an empty endpoint, and a mutation counting empty SPNs
    as distinct was MISSED -- because the empty string entered a SET, so N identical empty values
    still counted as ONE and the assertion could not tell. The rows here differ in request_type-adjacent
    detail, so the only way to reach the threshold is to treat "no service" as a principal.
    """
    # THE MIXED WINDOW IS WHERE THE GUARD ACTUALLY BITES, and my first two attempts at this test did
    # not reach it. Identical empty rows collapse to a ONE-element set, so counting them changes
    # nothing -- which is why the mutation kept surviving. The harm is an empty string acting as a
    # TENTH distinct principal in a window that named only nine real ones, pushing it over a
    # threshold of ten. That is a real false positive built entirely from absent data.
    real = [{"kind": "zeek_kerberos", "operation": "TGS", "endpoint": f"svc{i}/h.example.com"}
            for i in range(attack.KERB_MIN_SPNS - 1)]        # 9 distinct, one under the bar
    blank = [{"kind": "zeek_kerberos", "operation": "TGS", "endpoint": "", "uuid": f"u{i}"}
             for i in range(50)]                             # 50 rows with no service at all

    under = {m.technique.id for m in attack.map_zeek_techniques(real)}
    assert "T1558" not in under, "the 9-SPN fixture already trips the rule, so this proves nothing"

    ids = {m.technique.id for m in attack.map_zeek_techniques(real + blank)}
    assert "T1558" not in ids, (
        f"{attack.KERB_MIN_SPNS - 1} distinct real SPNs plus 50 rows with NO service principal raised "
        f"Kerberoasting. The empty string is being counted as a distinct principal, so an absent "
        f"service field supplies the tenth 'principal' and manufactures the signal"
    )


def test_an_absent_AS_principal_never_becomes_a_distinct_one():
    """The AS arm's version of the mixed window, which the TGS test cannot cover.

    Same shape as the TGS case: nine real principals, one under the bar, plus rows with no service at
    all. Counting the empty string pushes the AS arm over its threshold on absent data.
    """
    real = [{"kind": "zeek_kerberos", "operation": "AS", "endpoint": f"user{i}@corp.local"}
            for i in range(attack.KERB_MIN_SPNS - 1)]
    blank = [{"kind": "zeek_kerberos", "operation": "AS", "endpoint": "", "uuid": f"u{i}"}
             for i in range(50)]

    under = {m.technique.id for m in attack.map_zeek_techniques(real)}
    assert "T1558" not in under, "the 9-principal AS fixture already trips the rule"

    ids = {m.technique.id for m in attack.map_zeek_techniques(real + blank)}
    assert "T1558" not in ids, (
        f"{attack.KERB_MIN_SPNS - 1} distinct AS principals plus 50 rows with NO service raised "
        f"AS-REP roasting; the empty string is being counted as a principal on the AS arm too"
    )
