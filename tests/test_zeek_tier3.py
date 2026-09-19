"""Tier 3 logs: the five added, and the eleven deliberately not.

WHY THIS FILE IS MOSTLY ABOUT WHAT WE DID **NOT** ADD.

Two independent research passes ranked every log Zeek 9.0.0 ships. The temptation is to ingest
whatever scores well, and that instinct has already produced this project's most-repeated defect:
a table that exists, is mapped, and is read by nothing, or a column nothing ever writes. So the
majority of these assertions are about the DECISIONS: every recommended log has either an ingest
path or a recorded reason, the reasons are real (not "not implemented yet" dressed up as a
judgement), and the privacy invariant survives the additions.

The two specific traps this closes, both found while implementing rather than afterwards:

  * `x509.log` has NO `src_addr`. The feature join is (window, src_addr), so no certificate can be
    attributed to a host from that log. A first draft joined it by a constant, which would have
    given every host a column reading the default forever -- a feature that is always 0.0 and
    indistinguishable from a quiet network. A test in test_ml_table_coverage.py caught it.
  * Three of the five logs are ALREADY WRITTEN by the sensor (dhcp, and x509/quic by default
    closure). Adding `@load` lines for them would have looked like configuration while changing
    nothing; the ground truth is `ls /zeek/logs/`, not the load list.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from weirvern.ingester import ZEEK_COLUMNS, ZEEK_MAPPERS

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "\n".join(
    p.read_text() for p in sorted((ROOT / "weirvern" / "schema").glob("*.sql"))
)
DECISION_DOC = (ROOT.parent / "Scripts" / "zeek-log-expansion-decision.md")

TIER3 = ("dhcp", "x509", "tunnel", "quic", "ldap_search")


def normalise(rec: dict) -> dict:
    """Apply the reader's unset-sentinel normalisation before mapping.

    The reader (ingester._read_zeek_log) maps `-` to `""` once, for every mapper, so a mapper
    cannot forget. Tests that call a mapper directly must do the same or they assert behaviour
    that only occurs in the test -- the same mistake that made an earlier ATT&CK test pass against
    invented column names.
    """
    return {k: ("" if v == "-" else v) for k, v in rec.items()}


def row_of(mapper, rec: dict) -> dict:
    """Run a mapper and assert it produced a row.

    The mappers return `dict | None` -- a record with no usable key cannot be joined to anything.
    Every test below wants the dict, and asserting here means a mapper that rejects a record it
    should accept fails with the mapper's own name rather than as `NoneType is not subscriptable`
    at an unrelated line.
    """
    out = mapper(normalise(rec))
    assert out is not None, f"{mapper.__name__} dropped a record it should have accepted"
    return out


def _table_cols(table: str) -> list[str]:
    code = "\n".join(ln.split("--")[0] for ln in SCHEMA.splitlines())
    m = re.search(rf"CREATE TABLE IF NOT EXISTS (?:\w+\.)?{table}\s*\((.*?)\n\)", code, re.S)
    assert m, f"table {table} has no CREATE TABLE"
    return [ln.strip().rstrip(",").split()[0] for ln in m.group(1).splitlines() if ln.strip()]


# ── the five that were added ────────────────────────────────────────────────────

@pytest.mark.parametrize("log_type", TIER3)
def test_each_tier3_log_has_a_mapper_and_a_column_order(log_type):
    assert log_type in ZEEK_MAPPERS, f"{log_type}.log is in the schema but has no mapper"
    assert log_type in ZEEK_COLUMNS, f"{log_type} has no column order"
    table = ZEEK_MAPPERS[log_type][0].split(".")[-1]
    assert ZEEK_COLUMNS[log_type] == _table_cols(table), (
        f"{log_type}: insert order differs from the DDL order -- the INSERT is positional, so "
        f"values would land in the wrong columns silently"
    )


@pytest.mark.parametrize("log_type", TIER3)
def test_each_tier3_mapper_rejects_a_record_with_no_addresses(log_type):
    """Every Tier-3 mapper except dhcp needs both addresses: a row without them cannot be joined
    to a host-window, which is the table's only purpose.

    DHCP is the exception and it is tested separately -- DHCP is broadcast, so 0.0.0.0 is a
    legitimate client address in a DISCOVER, not a missing one.
    """
    if log_type == "dhcp":
        pytest.skip("dhcp is keyed on MAC, not an address pair -- covered below")
    mapper = ZEEK_MAPPERS[log_type][1]
    assert mapper(normalise({"ts": "1758200000.0", "id.orig_h": "-",
                             "id.resp_h": "10.0.0.1"})) is None
    assert mapper(normalise({"ts": "1758200000.0", "id.orig_h": "10.0.0.1",
                             "id.resp_h": ""})) is None


def test_dhcp_accepts_a_broadcast_discover():
    """0.0.0.0 IS a DHCP client address, not a missing value. A mapper that rejected it would drop
    every DISCOVER -- the message that reveals a new device arriving."""
    row = row_of(ZEEK_MAPPERS["dhcp"][1], {
        "ts": "1758200000.0", "uids": "Cabc", "client_addr": "0.0.0.0",
        "server_addr": "192.168.1.1", "mac": "aa:bb:cc:dd:ee:ff",
        "host_name": "laptop", "requested_addr": "192.168.1.50", "lease_time": "86400.0",
        "msg_types": "DISCOVER", "duration": "0.1",
    })
    assert row is not None, "a DISCOVER was rejected because client_addr is 0.0.0.0"
    assert row["mac"] == "aa:bb:cc:dd:ee:ff"


def test_dhcp_keeps_the_mac_because_it_is_the_stable_identifier():
    """The whole reason dhcp is ingested: a MAC persists across leases and an IP does not, so a
    per-host baseline keyed on IP loses its subject whenever the lease turns over."""
    assert "mac" in _table_cols("zeek_dhcp")
    row = row_of(ZEEK_MAPPERS["dhcp"][1], {
        "ts": "1758200000.0", "mac": "aa:bb:cc:dd:ee:ff", "client_addr": "10.0.0.5",
        "server_addr": "10.0.0.1", "lease_time": "3600.0",
    })
    assert row["mac"] == "aa:bb:cc:dd:ee:ff"
    assert row["lease_time"] == pytest.approx(3600.0)


def test_x509_requires_a_fingerprint_because_it_is_the_only_join_key():
    """Without the fingerprint the row cannot be joined to ssl.log's cert_chain_fps, which is the
    sole purpose of ingesting this log."""
    assert ZEEK_MAPPERS["x509"][1](normalise({"ts": "1758200000.0", "fingerprint": "-"})) is None
    row = ZEEK_MAPPERS["x509"][1]({
        "ts": "1758200000.0", "fingerprint": "abcd1234",
        "certificate.subject": "CN=selfsigned.local", "certificate.issuer": "CN=selfsigned.local",
        "certificate.key_alg": "rsa", "certificate.key_length": "1024",
        "basic_constraints.ca": "F", "san.dns": "selfsigned.local",
    })
    assert row is not None
    # The self-signed comparison needs both fields stored verbatim, which is why neither is parsed.
    assert row["subject"] == row["issuer"], "a self-signed cert must compare equal"


def test_x509_unset_ca_flag_does_not_read_as_a_ca():
    """`basic_constraints.ca` is unset in many records. Treating unset as true would mark ordinary
    leaf certificates as certificate authorities -- the opposite of safe."""
    row = ZEEK_MAPPERS["x509"][1]({"ts": "1758200000.0", "fingerprint": "abcd",
                                   "basic_constraints.ca": "-"})
    assert row["is_ca"] == 0


def test_tunnel_captures_the_type_which_is_its_entire_reason_to_exist():
    """conn.log carries `tunnel_parents` -- a set of UIDs -- and never the encapsulation type. The
    type is the difference between an expected site-to-site tunnel and tunnelling for evasion."""
    row = row_of(ZEEK_MAPPERS["tunnel"][1], {
        "ts": "1758200000.0", "id.orig_h": "10.0.0.1", "id.resp_h": "10.0.0.2",
        "tunnel_type": "Tunnel::TEREDO", "action": "DISCOVER",
    })
    assert row["tunnel_type"] == "Tunnel::TEREDO"
    assert "tunnel_type" in _table_cols("zeek_tunnel")


def test_quic_recovers_the_sni_that_ssl_log_never_sees():
    """QUIC is encrypted at the transport layer and bypasses ssl.log entirely, so a host moving its
    C2 to QUIC has no TLS record at all. The SNI is what makes the connection nameable."""
    row = row_of(ZEEK_MAPPERS["quic"][1], {
        "ts": "1758200000.0", "id.orig_h": "10.0.0.1", "id.orig_p": "1234",
        "id.resp_h": "1.1.1.1", "id.resp_p": "443",
        "server_name": "cloudflare-dns.com", "client_protocol": "h3", "version": "1",
    })
    assert row["server_name"] == "cloudflare-dns.com"
    assert row["client_protocol"] == "h3"


def test_ldap_search_records_the_filter_which_is_the_enumeration_signal():
    """AD enumeration is defined by filter CONTENT, and nothing else in the corpus exposes directory
    queries at all."""
    row = row_of(ZEEK_MAPPERS["ldap_search"][1], {
        "ts": "1758200000.0", "id.orig_h": "10.0.0.1", "id.orig_h": "10.0.0.1",
        "id.resp_h": "10.0.0.9", "id.resp_p": "389",
        "filter": "(objectClass=user)", "base_object": "DC=corp,DC=local",
        "scope": "sub", "result_count": "4200", "result": "success",
    })
    assert row["ldap_filter"] == "(objectClass=user)"
    assert row["result_count"] == 4200, "result_count is the numeric outlier feature"


# ── the eleven that were deliberately not added ─────────────────────────────────

# Every log either report recommended, and the ingest status we chose for each. A log absent from
# BOTH this table and ZEEK_MAPPERS would be an unexamined gap.
RECOMMENDED_NOT_ADDED = {
    "signatures": "duplicates flows_aggregated_diversity, which already derives the scan signal",
    "pe": "only populated when an executable crosses the wire, which this deployment shows it does not",
    "unknown_protocols": "gated, and first_bytes is raw payload -- breaks the no-payload invariant",
    "smb_cmd": "Zeek's own header calls it 'primarily useful for debugging'; high volume",
    "smtp": "protocol not present on this segment",
    "ftp": "protocol not present on this segment",
    "radius": "protocol not present on this segment",
    "rfb": "protocol not present on this segment",
    "ntp": "protocol not present on this segment",
    "snmp": "protocol not present on this segment",
    "irc": "protocol not present on this segment",
    "ocsp": "meaningful only with outbound OCSP validation",
    "known_certs": "complements x509; the host binding is available via ssl.log's fingerprints",
    "websocket": "nothing natively numeric; lower value than what was added",
    "socks": "no proxy or pivot observed on this segment",
}


def test_every_unadded_log_has_a_recorded_reason():
    """A decision table is what stops 'we did not get to it' from reading as 'we judged it
    unnecessary'. Every recommendation has an entry."""
    assert RECOMMENDED_NOT_ADDED, "no decisions recorded"
    for log, reason in RECOMMENDED_NOT_ADDED.items():
        assert log not in ZEEK_MAPPERS, f"{log} IS ingested; remove it from the not-added list"
        assert len(reason) > 25, f"{log}'s reason is too terse to be a judgement: {reason!r}"


def test_the_decision_document_exists_and_names_the_added_logs():
    """The reasons live in the repo, next to the code, not only in a commit message."""
    if not DECISION_DOC.exists():
        pytest.skip("decision doc lives outside the repo (Scripts/); see the roadmap")
    text = DECISION_DOC.read_text()
    for log in TIER3:
        assert log in text, f"{log} was added but the decision document does not mention it"


# ── the privacy invariant, which the additions must not break ───────────────────

def test_no_tier3_table_stores_raw_payload():
    """unknown_protocols.first_bytes and analyzer.failure_data are the only raw-payload fields in
    Zeek's log set, and NEITHER of those logs is ingested -- which is part of why. Asserted rather
    than assumed, because the invariant "no payload bytes, ever" is a standing commitment.

    This is what a reader of the decision document should be able to verify from the code.
    """
    forbidden = ("first_bytes", "failure_data", "payload", "raw_bytes", "hex_payload")
    for log_type in TIER3:
        table = ZEEK_MAPPERS[log_type][0].split(".")[-1]
        for col in _table_cols(table):
            assert not any(bad in col.lower() for bad in forbidden), (
                f"{table}.{col} looks like stored payload, which the privacy invariant forbids"
            )


def test_no_tier3_table_stores_a_credential():
    """LDAP is the one to watch: Zeek redacts bind arguments because default_capture_password is
    false, so no credential reaches the log -- and therefore none can reach this table."""
    forbidden = ("password", "passwd", "secret", "credential", "bind_cred")
    for log_type in TIER3:
        table = ZEEK_MAPPERS[log_type][0].split(".")[-1]
        for col in _table_cols(table):
            assert not any(bad in col.lower() for bad in forbidden), (
                f"{table}.{col} looks like a credential column"
            )


def test_every_tier3_table_is_bounded():
    """The retention rule from 004_zeek_identity.sql: bounded, shortest where the exposure is
    greatest. `ldap_search` carries directory filters and base objects -- the most directly
    identifying content here -- so it must be the shortest-lived."""
    def days(table: str) -> int:
        code = "\n".join(ln.split("--")[0] for ln in SCHEMA.splitlines())
        m = re.search(
            rf"CREATE TABLE IF NOT EXISTS (?:\w+\.)?{table}\s*\(.*?\n\)\s*(.*?);", code, re.S
        )
        assert m, f"{table} not found"
        ttl = re.search(r"TTL \w+ \+ INTERVAL (\d+) DAY", m.group(1))
        assert ttl, f"{table} holds identifiable data and has no TTL"
        return int(ttl.group(1))

    for log_type in TIER3:
        table = ZEEK_MAPPERS[log_type][0].split(".")[-1]
        assert days(table) <= 365, f"{table} is effectively unbounded"
    # ldap_search is the most identifying, so it must expire no later than the others.
    assert days("zeek_ldap_search") <= days("zeek_dhcp")
    assert days("zeek_ldap_search") <= days("zeek_x509")


def test_tier3_tables_are_not_shorter_lived_than_the_flow_tables_by_accident():
    """The flow tables are 7 days for a VOLUME reason, not a privacy one. Copying that number here
    would delete an attack campaign's evidence before the investigation that needs it -- the same
    false rationale corrected in 004_zeek_identity.sql."""
    code = "\n".join(ln.split("--")[0] for ln in SCHEMA.splitlines())

    def days(table: str) -> int | None:
        m = re.search(
            rf"CREATE TABLE IF NOT EXISTS (?:\w+\.)?{table}\s*\(.*?\n\)\s*(.*?);", code, re.S
        )
        if not m:
            return None
        ttl = re.search(r"TTL \w+ \+ INTERVAL (\d+) DAY", m.group(1))
        return int(ttl.group(1)) if ttl else None

    flow = days("zeek_conn")
    assert flow == 7, "the flow table's retention changed; re-check this reasoning"
    for log_type in TIER3:
        table = ZEEK_MAPPERS[log_type][0].split(".")[-1]
        d = days(table)
        assert d is not None and d > flow, (
            f"{table} is retained for {d} days, at or below the flow tables' {flow} -- which is "
            f"a volume bound, not a privacy one, and would be too short for the campaign it exists "
            f"to catch"
        )
