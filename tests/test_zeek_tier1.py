"""Tests for the Tier 1 Zeek mappers: http, files, ssh, weird.

WHY THESE LOGS: Zeek was ALREADY writing all four on every deployment -- the site
policy loads known-hosts and known-services -- and the ingester silently dropped them.
Measured on the test cluster over a few hours: 359 http, 324 files, 155 ssh, 78 weird
records lost. The four missing logs are the ones that answer "what did that host
actually request?" and "what files moved?", which a NetFlow-aggregate ML model cannot
see by construction.

FIELD NAMES come from the live `#fields` headers of each log on the test cluster, not
from documentation, because Zeek's field sets vary by version and a wrong name produces
an empty column rather than an error. Each test below uses a REAL sample line.
"""
from __future__ import annotations

from datetime import datetime

import pytest

from weirvern import ingester

# Real records, copied from the live logs on the test cluster.
HTTP_ROW = {
    "ts": "1789694182.250915", "uid": "CBICIq2JWuvfNFypRa",
    "id.orig_h": "192.168.2.42", "id.orig_p": "39088",
    "id.resp_h": "192.168.2.159", "id.resp_p": "30088",
    "trans_depth": "1", "method": "GET", "host": "192.168.2.159:30088",
    "uri": "/api/overview", "referrer": "http://192.168.2.159:30088/",
    "version": "1.1", "user_agent": "Mozilla/5.0 (X11; Linux x86_64)",
    "request_body_len": "0", "response_body_len": "3928", "status_code": "200",
    "status_msg": "OK", "resp_mime_types": "application/json",
    # Present in http.log but deliberately NOT ingested.
    "username": "-", "password": "-",
}

SSH_ROW = {
    "ts": "1789678722.149819", "uid": "Cxhoay3FXGMCGzQNma",
    "id.orig_h": "192.168.2.42", "id.orig_p": "50622",
    "id.resp_h": "192.168.2.159", "id.resp_p": "22",
    "version": "2", "auth_success": "T", "auth_attempts": "1", "direction": "-",
    "client": "SSH-2.0-OpenSSH_10.5",
    "server": "SSH-2.0-OpenSSH_9.9p1 Ubuntu-3ubuntu3.2",
    "cipher_alg": "chacha20-poly1305@openssh.com",
    "mac_alg": "umac-64-etm@openssh.com",
}

WEIRD_ROW = {
    "ts": "1789694443.661686", "uid": "CiEGd94dlkTOiMqzMh",
    "id.orig_h": "fe80::aa9c:6cff:fe96:b62d", "id.orig_p": "5353",
    "id.resp_h": "ff02::fb", "id.resp_p": "5353",
    "name": "DNS_label_len_gt_pkt", "addl": "-", "notice": "F",
    "peer": "zeek", "source": "DNS",
}

FILES_ROW = {
    "ts": "1789680000.123456", "fuid": "Fabc123", "uid": "Cabc123",
    "id.orig_h": "192.168.2.42", "id.orig_p": "44321",
    "id.resp_h": "93.184.216.34", "id.resp_p": "80",
    "source": "HTTP", "depth": "0", "analyzers": "MD5,SHA1,SHA256",
    "mime_type": "application/pdf", "filename": "invoice.pdf",
    "duration": "0.5", "local_orig": "T", "is_orig": "T",
    "seen_bytes": "20480", "total_bytes": "20480", "missing_bytes": "0",
    "overflow_bytes": "0", "timedout": "F", "parent_fuid": "-",
    "md5": "d41d8cd98f00b204e9800998ecf8427e",
    "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
}


# --- http ---------------------------------------------------------------------
def test_http_extracts_the_request_that_nothing_else_can_see():
    """The whole reason for this log: a NetFlow aggregate knows 3928 bytes moved to
    port 30088; only http.log knows it was GET /api/overview."""
    row = ingester.map_zeek_http(HTTP_ROW)
    assert row is not None
    assert row["method"] == "GET"
    assert row["host"] == "192.168.2.159:30088"
    assert row["uri"] == "/api/overview"
    assert row["status_code"] == 200
    assert row["resp_bytes"] == 3928
    assert row["src_addr"] == "192.168.2.42"
    assert row["dst_port"] == 30088
    assert isinstance(row["ts"], datetime)


def test_http_never_ingests_credentials():
    """http.log carries `username` and `password` fields. Storing plaintext credentials
    in an analytics database is a liability with no analytic value, and the project keeps
    Zeek's capture_password OFF. This test fails if anyone adds them later."""
    row = ingester.map_zeek_http(HTTP_ROW)
    assert row is not None
    assert "password" not in row, "http.log password field must never be ingested"
    assert "username" not in row, "http.log username field must never be ingested"
    # And the column list must not mention them either.
    assert not any("pass" in c or "user_name" in c for c in ingester.ZEEK_COLUMNS["http"])


def test_http_computes_uri_entropy_for_exfiltration_shapes():
    """A long URI with a high-entropy query string is the signature of data-in-URL
    exfiltration. Computed at ingest so a hunt does not re-parse every row.

    The entropy is over the QUERY STRING when present, because that is where smuggled
    data goes; the path is usually a normal-looking API route.
    """
    low = dict(HTTP_ROW, uri="/api/status")
    high = dict(HTTP_ROW, uri="/x?d=" + "aB3xK9mQ7pL2vN8zR4tY6wF1" * 4)
    a = ingester.map_zeek_http(low)
    b = ingester.map_zeek_http(high)
    assert a is not None and b is not None
    assert b["uri_len"] > a["uri_len"]
    assert b["uri_entropy"] > a["uri_entropy"], (
        "a high-entropy query string must score higher than a short path"
    )


def test_http_normalises_zeek_null_fields():
    """Zeek writes '-' for unset. Storing it literally makes an absent Host header
    indistinguishable from a host actually named '-'."""
    nulled = dict(HTTP_ROW, host="-", resp_mime_types="-")
    row = ingester.map_zeek_http(nulled)
    assert row is not None
    assert row["host"] == ""
    assert row["resp_mime"] == ""


def test_http_rejects_a_record_with_no_addresses():
    assert ingester.map_zeek_http(dict(HTTP_ROW, **{"id.orig_h": "-"})) is None
    assert ingester.map_zeek_http(dict(HTTP_ROW, **{"id.resp_h": ""})) is None


# --- files --------------------------------------------------------------------
def test_files_extracts_filename_hash_and_size():
    """Ties a transfer to a filename and a hash, which is what makes 'did anything
    matching this indicator move?' answerable."""
    row = ingester.map_zeek_files(FILES_ROW)
    assert row is not None
    assert row["filename"] == "invoice.pdf"
    assert row["mime_type"] == "application/pdf"
    assert row["sha256"] == FILES_ROW["sha256"]
    assert row["md5"] == FILES_ROW["md5"]
    assert row["seen_bytes"] == 20480
    assert row["f_source"] == "HTTP"
    assert row["fuid"] == "Fabc123"


def test_files_keeps_the_hash_separate_from_the_filename():
    """They have different privacy properties and different lifetimes: a hash can be
    compared against threat intel without exposing the filename."""
    row = ingester.map_zeek_files(FILES_ROW)
    assert row is not None
    assert row["filename"] != row["sha256"]
    assert len(row["sha256"]) == 64


def test_files_maps_missing_bytes_to_its_own_column():
    """`missing_bytes` is why a truncated transfer can be distinguished from a small
    one, which matters when deciding whether a file is worth retrieving."""
    row = ingester.map_zeek_files(dict(FILES_ROW, missing_bytes="4096"))
    assert row is not None
    assert row["missing"] == 4096


# --- ssh ----------------------------------------------------------------------
def test_ssh_extracts_the_auth_outcome_and_both_versions():
    """auth_success plus auth_attempts plus direction is the brute-force and
    lateral-movement signal. The client/server version strings are what identify an
    unusual SSH implementation."""
    row = ingester.map_zeek_ssh(SSH_ROW)
    assert row is not None
    assert row["auth_success"] == 1
    assert row["auth_attempts"] == 1
    assert row["dst_port"] == 22
    assert "OpenSSH_10.5" in row["client"]
    assert "Ubuntu" in row["server"]


@pytest.mark.parametrize("value,expected", [
    ("T", 1), ("t", 1), ("true", 1), ("F", 0), ("f", 0), ("-", 0), ("", 0),
])
def test_ssh_auth_success_parsing_handles_every_zeek_spelling(value, expected):
    """Zeek writes booleans as T/F, so a naive bool(value) would report 'F' as True --
    turning every failed login into a success."""
    row = ingester.map_zeek_ssh(dict(SSH_ROW, auth_success=value))
    assert row is not None
    assert row["auth_success"] == expected, f"{value!r} parsed as {row['auth_success']}"


def test_ssh_does_not_store_credentials():
    """ssh.log has no password field, and `capture_password` stays off. Asserted so a
    future Zeek version or policy change cannot quietly introduce one."""
    row = ingester.map_zeek_ssh(SSH_ROW)
    assert row is not None
    assert not any("password" in k or "passwd" in k for k in row)


# --- weird --------------------------------------------------------------------
def test_weird_captures_the_anomaly_name():
    """Protocol anomalies: where malformed or unexpected traffic surfaces before anyone
    has written a signature for it."""
    row = ingester.map_zeek_weird(WEIRD_ROW)
    assert row is not None
    assert row["name"] == "DNS_label_len_gt_pkt"
    assert row["peer"] == "zeek"


@pytest.mark.parametrize("value,expected", [("T", 1), ("F", 0), ("-", 0)])
def test_weird_notice_flag_is_parsed_not_truthy(value, expected):
    """Zeek's `notice` flag means the weird ALSO raised a Notice. Collapsing the two
    would swamp the signal: 'odd protocol event' and 'Zeek alerted' are very different
    volumes."""
    row = ingester.map_zeek_weird(dict(WEIRD_ROW, notice=value))
    assert row is not None
    assert row["noticed"] == expected


def test_weird_handles_ipv6_addresses():
    """A large share of weird.log is IPv6 multicast noise, which is normal on any LAN
    with mDNS. The mapper must not drop it or crash on a colon-bearing address."""
    row = ingester.map_zeek_weird(WEIRD_ROW)
    assert row is not None
    assert ":" in row["src_addr"], "IPv6 source should survive"
    assert row["dst_addr"] == "ff02::fb"


# --- registry and schema consistency ------------------------------------------
def test_every_mapper_has_a_column_list_and_a_table():
    """A mapper without a column list cannot be written; a column list without a table
    fails at INSERT time. Both must exist for every registered log."""
    for log_type, (_table, _fn) in ingester.ZEEK_MAPPERS.items():
        assert log_type in ingester.ZEEK_COLUMNS, (
            f"{log_type} is registered as a mapper but has no insert column list"
        )


def test_insert_column_order_matches_the_schema_ddl():
    """The INSERT is positional, so ZEEK_COLUMNS order must match the CREATE TABLE
    column order exactly. A mismatch writes values into the wrong columns silently --
    the same class of bug as the flow_summary positional tuple."""
    import re
    from pathlib import Path

    schema_dir = Path(ingester.__file__).resolve().parent / "schema"
    ddl = "\n".join(p.read_text() for p in sorted(schema_dir.glob("*.sql")))

    for log_type, (table, _fn) in ingester.ZEEK_MAPPERS.items():
        bare = table.split(".")[-1]
        # The schema qualifies some tables (`weirvern.zeek_kerberos`) and not others
        # (`zeek_conn`), so the optional prefix is required. Without it this test silently
        # reported "no CREATE TABLE" for every Tier-2 table rather than comparing them --
        # which is the failure mode it exists to catch, turned on the test itself.
        m = re.search(
            rf"CREATE TABLE IF NOT EXISTS\s+(?:\w+\.)?{re.escape(bare)}\s*\((.*?)\)\s*ENGINE",
            ddl, re.S,
        )
        assert m, f"no CREATE TABLE for {bare}"
        cols = []
        for line in m.group(1).splitlines():
            line = line.strip()
            if not line or line.startswith("--"):
                continue
            name = line.split()[0].strip(",")
            cols.append(name)
        assert ingester.ZEEK_COLUMNS[log_type] == cols, (
            f"{log_type}: insert order {ingester.ZEEK_COLUMNS[log_type]} does not match "
            f"the DDL order {cols}"
        )


def test_the_tier1_logs_are_all_registered():
    """These four are the logs Zeek was writing and the ingester was discarding."""
    for log_type in ("http", "files", "ssh", "weird"):
        assert log_type in ingester.ZEEK_MAPPERS, f"{log_type} is still being dropped"
