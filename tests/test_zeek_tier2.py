"""Tier-2 Zeek mappers: the identity and lateral-movement set.

WHY THESE TESTS EXIST IN THIS SHAPE.

A schema without a mapper produces empty tables, and an empty table is indistinguishable from
a quiet network. `004_zeek_identity.sql` was committed with six tables and no ingester for
them, so every one of them would have stayed empty forever while `weirvern status` reported a
healthy sensor. Nothing failed; nothing was logged; the data was read and discarded.

The specific defects these guard against were all found by reading the `&log` declarations in
the INSTALLED Zeek source rather than documentation, because documentation and prose
summaries disagree with each other and with the shipped code:

  * kerberos declares `from` / `till`, and the schema said `ticket_from` / `ticket_till` --
    two permanently empty columns
  * smb_files declares the basename as `name`, and the schema said `filename` -- one more
  * kerberos `error_code` is `&optional` WITHOUT `&log`, so it is not in the log at all; a
    column for it could never populate, which is the same defect as the dead ja3/ja3s columns

So each mapper is tested against a record shaped like the REAL Zeek output, with the field
names taken from the source, and the column order is checked against the SQL rather than
duplicated in a literal.
"""
from __future__ import annotations

import re
from datetime import UTC, datetime
from pathlib import Path

import pytest

from weirvern.ingester import (
    ZEEK_COLUMNS,
    ZEEK_MAPPERS,
    map_zeek_dce_rpc,
    map_zeek_kerberos,
    map_zeek_ntlm,
    map_zeek_smb_files,
    map_zeek_smb_mapping,
)

ROOT = Path(__file__).resolve().parents[1]


def normalise(rec: dict) -> dict:
    """Apply the same unset-field normalisation the reader applies before mapping.

    The reader (ingester._read_zeek_log) maps `-` to `""` once, for every mapper, so a
    mapper cannot forget. Tests call it here so they exercise the mapper under the same
    contract the reader provides -- otherwise they would assert behaviour that only occurs
    when a mapper is called directly, which is not how it runs in production.
    """
    return {k: ("" if v == "-" else v) for k, v in rec.items()}


def row_of(mapper, rec: dict) -> dict:
    """Run a mapper and assert it produced a row.

    The mappers return `dict | None` because a record with no address pair cannot be joined
    to anything. Every test below wants the dict, and asserting it here means a mapper that
    rejects a record it should accept fails with the mapper's own name rather than as a
    `NoneType is not subscriptable` at some unrelated line.
    """
    out = mapper(normalise(rec))
    assert out is not None, f"{mapper.__name__} dropped a record it should have accepted"
    return out
TIER2_SQL = (ROOT / "weirvern" / "schema" / "004_zeek_identity.sql").read_text()

# Zeek's unset sentinel, as it appears in a real log line.
UNSET = "-"  # Zeek's #unset_field, read from a live log header


# ── the registry, which is where the whole failure started ──────────────────────

def test_every_tier2_table_has_a_mapper():
    """THE REGRESSION. All five identity logs must be in ZEEK_MAPPERS. The schema landed
    without them once and the tables were empty for the life of the deployment."""
    for log_type in ("kerberos", "dce_rpc", "smb_mapping", "smb_files", "ntlm"):
        assert log_type in ZEEK_MAPPERS, (
            f"{log_type}.log has a table but no mapper, so it is read and discarded"
        )


def test_every_mapper_is_wired_to_a_real_table():
    """A mapper pointing at a table that does not exist fails at INSERT time, in production,
    on the first record -- which on a quiet segment could be days."""
    for log_type, (target, _mapper) in ZEEK_MAPPERS.items():
        table = target.split(".")[-1]
        assert re.search(rf"CREATE TABLE IF NOT EXISTS (?:\w+\.)?{table}\b",
                         _all_schema_sql()), f"{log_type} maps to missing table {table}"


def test_every_mapper_has_a_column_order():
    """`ZEEK_COLUMNS[log_type]` is indexed directly in the writer, so a missing entry is a
    KeyError on the first line of the log rather than at import."""
    for log_type in ZEEK_MAPPERS:
        assert log_type in ZEEK_COLUMNS, f"{log_type} has no column order"


def test_column_order_matches_the_schema_for_every_tier2_table():
    """The writer builds a POSITIONAL insert. If the order disagrees with the CREATE TABLE,
    values land in the wrong columns -- no error, plausible-looking wrong data."""
    for log_type, target in ((lt, t) for lt, (t, _m) in ZEEK_MAPPERS.items()):
        table = target.split(".")[-1]
        expected = _columns_of(table)
        assert expected, f"could not read the column list for {table}"
        assert ZEEK_COLUMNS[log_type] == expected, (
            f"{log_type}: ingester order {ZEEK_COLUMNS[log_type]} != schema order {expected}"
        )


def test_the_mapper_dict_keys_match_the_column_order():
    """A mapper that returns a key the column list does not name would be dropped silently;
    one that omits a key would write a positional gap."""
    records = {
        "kerberos": _KERBEROS_RECORD,
        "dce_rpc": _DCE_RPC_RECORD,
        "smb_mapping": _SMB_MAPPING_RECORD,
        "smb_files": _SMB_FILES_RECORD,
        "ntlm": _NTLM_RECORD,
    }
    for log_type, rec in records.items():
        mapper = ZEEK_MAPPERS[log_type][1]
        row = mapper(rec)
        assert row is not None, f"{log_type} mapper rejected a valid record"
        assert set(row) == set(ZEEK_COLUMNS[log_type]), (
            f"{log_type}: mapper keys {sorted(set(row) ^ set(ZEEK_COLUMNS[log_type]))} "
            f"differ from the column order"
        )


# ── records shaped like the real thing ─────────────────────────────────────────

def _base(ts: str = "1758200000.000000") -> dict[str, str]:
    return {"ts": ts, "uid": "CAbc123", "id.orig_h": "198.51.100.5", "id.orig_p": "49152",
            "id.resp_h": "198.51.100.9", "id.resp_p": "88", "proto": "tcp"}


# Field names read from the &log declarations in the installed Zeek 9.0.0 source:
#   base/protocols/krb/main.zeek
_KERBEROS_RECORD = {
    **_base(),
    "request_type": "TGS",
    "client": "alice@CORP.LOCAL",
    "service": "cifs/dc01.corp.local",
    "success": "T",
    "error_msg": UNSET,
    "from": "1758199000.000000",   # NOTE: `from`, not `ticket_from`
    "till": "1758285400.000000",   # and `till`, not `ticket_till`
    "cipher": "aes256-cts-hmac-sha1-96",
    "forwardable": "T",
    "renewable": "F",
}

#   base/protocols/dce-rpc/main.zeek
_DCE_RPC_RECORD = {
    **_base(),
    "rtt": "0.001234",
    "named_pipe": "\\PIPE\\svcctl",
    "endpoint": "b3671ee1-9d9d-4d2c-b4e6-1b1d4c4d4b4e",
    "operation": "CreateServiceW",
}

#   base/protocols/smb/main.zeek  (Smb_Mapping)
_SMB_MAPPING_RECORD = {
    **_base(),
    "path": "\\\\DC01\\ADMIN$",
    "service": "SMB2",
    "native_file_system": "NTFS",
    "share_type": "DISK",
}

#   base/protocols/smb/main.zeek  (Smb_File) -- the basename is `name`, NOT `filename`
_SMB_FILES_RECORD = {
    **_base(),
    "fuid": "FYz1a2b3c",
    "action": "SMB_FILE_WRITE",
    "path": "\\\\DC01\\ADMIN$\\Temp\\",
    "name": "tool.exe",             # NOTE: `name`, not `filename`
    "size": "71680",
    "prev_name": UNSET,
}

#   base/protocols/ntlm/main.zeek
_NTLM_RECORD = {
    **_base(),
    "username": "alice",
    "hostname": "WORKSTATION01",
    "domainname": "CORP",
    "success": "T",
    "server_nb_computer_name": "DC01",
    "server_dns_computer_name": UNSET,
    "server_tree_name": UNSET,
}


# ── kerberos ────────────────────────────────────────────────────────────────────

def test_kerberos_reads_the_ticket_window_from_from_and_till():
    """THE DEFECT THIS CATCHES: the schema says `ticket_from`/`ticket_till`, Zeek says
    `from`/`till`. Reading the schema's names from the record yields the epoch for every
    ticket -- a column that is never empty and never correct, which is worse than empty."""
    row = row_of(map_zeek_kerberos, _KERBEROS_RECORD)
    assert row["ticket_from"] == datetime.fromtimestamp(1758199000, UTC)
    assert row["ticket_till"] == datetime.fromtimestamp(1758285400, UTC)
    # And specifically not the epoch, which is what the wrong field name produces.
    assert row["ticket_till"] != datetime.fromtimestamp(0, UTC)


def test_kerberos_distinguishes_unset_tickets_from_the_epoch():
    """A ticket with no logged window must not read as "expired in 1970" -- that is a
    missing value, and a query for expired tickets would match every row."""
    row = row_of(map_zeek_kerberos, {**_KERBEROS_RECORD, "from": UNSET, "till": UNSET})
    assert row["ticket_till"] == datetime.fromtimestamp(0, UTC)


def test_kerberos_records_the_spn_and_principal_that_make_roasting_visible():
    """The whole reason this log is ingested: client + service + request_type is the fact
    that conn.log cannot express."""
    row = row_of(map_zeek_kerberos, _KERBEROS_RECORD)
    assert row["request_type"] == "TGS"
    assert row["client"] == "alice@CORP.LOCAL"
    assert row["service"] == "cifs/dc01.corp.local"


def test_kerberos_success_and_flags_parse_zeek_booleans():
    row = row_of(map_zeek_kerberos, _KERBEROS_RECORD)
    assert row["success"] == 1
    assert row["forwardable"] == 1
    assert row["renewable"] == 0
    # Zeek writes unset booleans as `-`; they must not become true.
    assert row_of(map_zeek_kerberos, {**_KERBEROS_RECORD, "success": UNSET})["success"] == 0


def test_kerberos_does_not_reference_error_code():
    """`error_code` is `&optional` WITHOUT `&log` in Zeek 9.0.0, so it is not in the log.
    A column or a lookup for it can never populate -- the same defect as ja3/ja3s."""
    row = row_of(map_zeek_kerberos, _KERBEROS_RECORD)
    assert "error_code" not in row
    assert "error_code" not in ZEEK_COLUMNS["kerberos"]
    assert not re.search(r"^\s*error_code\s", _table_body("zeek_kerberos"), re.M)


def test_kerberos_error_msg_is_kept_as_the_text_signal():
    row = row_of(map_zeek_kerberos, {**_KERBEROS_RECORD, "error_msg": "NEEDED_PREAUTH"})
    assert row["error_msg"] == "NEEDED_PREAUTH"


def test_kerberos_rejects_a_record_without_both_addresses():
    """Every identity table keys on the pair; a row without it cannot be joined to anything."""
    assert map_zeek_kerberos(dict(_KERBEROS_RECORD, **{"id.orig_h": UNSET})) is None
    assert map_zeek_kerberos(dict(_KERBEROS_RECORD, **{"id.resp_h": UNSET})) is None


# ── dce_rpc ─────────────────────────────────────────────────────────────────────

def test_dce_rpc_records_endpoint_operation_and_named_pipe():
    """PsExec is a named pipe plus a service-control operation. Without the endpoint and
    operation this row is indistinguishable from any other SMB traffic."""
    row = row_of(map_zeek_dce_rpc, _DCE_RPC_RECORD)
    assert row["named_pipe"] == "\\PIPE\\svcctl"
    assert row["operation"] == "CreateServiceW"
    assert row["endpoint"].startswith("b3671ee1")


def test_dce_rpc_rtt_is_a_float_not_truncated():
    """Zeek logs `rtt` as an interval in seconds. `_safe_int` would floor every value to
    zero, losing the latency signal entirely."""
    assert row_of(map_zeek_dce_rpc, _DCE_RPC_RECORD)["rtt"] == pytest.approx(0.001234)


def test_dce_rpc_handles_unset_optional_fields():
    row = row_of(map_zeek_dce_rpc, {**_DCE_RPC_RECORD, "operation": UNSET, "named_pipe": UNSET})
    assert row["operation"] == ""
    assert row["named_pipe"] == ""


# ── smb_mapping ─────────────────────────────────────────────────────────────────

def test_smb_mapping_keeps_the_share_path_verbatim():
    """The admin-share path is the finding. Normalising or stripping it destroys the
    signal, and the leading `\\\\HOST\\` is part of what identifies the target."""
    row = row_of(map_zeek_smb_mapping, _SMB_MAPPING_RECORD)
    assert row["path"] == "\\\\DC01\\ADMIN$"
    assert row["share_type"] == "DISK"


def test_smb_mapping_handles_unset_share_type():
    """`share_type` has an &default of "DISK" but is still optional in output; an unset
    value must be empty, not the literal string "unset_field"."""
    row = row_of(map_zeek_smb_mapping, {**_SMB_MAPPING_RECORD, "share_type": UNSET})
    assert row["share_type"] == ""


# ── smb_files ───────────────────────────────────────────────────────────────────

def test_smb_files_reads_the_basename_from_name_not_filename():
    """THE DEFECT THIS CATCHES: Zeek declares the basename as `name`. Reading `filename`
    gives an empty column on every row while `path` populates normally -- a defect that
    looks exactly like "Zeek isn't logging filenames"."""
    row = row_of(map_zeek_smb_files, _SMB_FILES_RECORD)
    assert row["filename"] == "tool.exe"
    assert row["filename"] != "", "the basename column is empty -- wrong source field name"


def test_smb_files_keeps_the_action_verbatim():
    """Ransomware detection is a burst of RENAME/DELETE; the action string is the feature."""
    assert row_of(map_zeek_smb_files, _SMB_FILES_RECORD)["action"] == "SMB_FILE_WRITE"


def test_smb_files_size_is_an_integer():
    assert row_of(map_zeek_smb_files, _SMB_FILES_RECORD)["size"] == 71680


def test_smb_files_records_prev_name_for_renames():
    """RENAME is only interpretable with the previous name."""
    row = row_of(map_zeek_smb_files, {**_SMB_FILES_RECORD, "action": "SMB_FILE_RENAME",
                              "prev_name": "old.txt"})
    assert row["prev_name"] == "old.txt"
    # And unset must be empty rather than the sentinel.
    assert row_of(map_zeek_smb_files, _SMB_FILES_RECORD)["prev_name"] == ""


# ── ntlm ────────────────────────────────────────────────────────────────────────

def test_ntlm_records_the_identity_triple():
    """username + hostname + domainname together are what makes pass-the-hash visible:
    one credential on many hosts. No single field shows it."""
    row = row_of(map_zeek_ntlm, _NTLM_RECORD)
    assert row["username"] == "alice"
    assert row["hostname"] == "WORKSTATION01"
    assert row["domainname"] == "CORP"


def test_ntlm_success_flag_for_the_aggregation():
    """The materialized view filters on `success = 1`, so a mis-parsed flag silently
    changes what the identity graph contains."""
    assert row_of(map_zeek_ntlm, _NTLM_RECORD)["success"] == 1
    assert row_of(map_zeek_ntlm, {**_NTLM_RECORD, "success": "F"})["success"] == 0


def test_ntlm_ignores_the_server_side_optional_fields():
    """server_nb_computer_name etc. are not columns -- they duplicate the destination
    already held as dst_addr/hostname, and storing them invites a second source of truth."""
    row = row_of(map_zeek_ntlm, _NTLM_RECORD)
    assert "server_nb_computer_name" not in row
    assert "server_dns_computer_name" not in row


# ── the aggregation the identity graph depends on ───────────────────────────────

def test_the_identity_aggregation_is_fed_by_a_materialized_view():
    """`ntlm_identity_daily` is only populated by the MV. Without it the table is empty and
    the pass-the-hash query returns nothing while appearing to work."""
    assert "ntlm_identity_daily_mv" in TIER2_SQL
    mv = TIER2_SQL[TIER2_SQL.index("CREATE MATERIALIZED VIEW"):]
    assert "TO weirvern.ntlm_identity_daily" in mv
    assert "FROM weirvern.zeek_ntlm" in mv


# ── privacy, which is a test in this project rather than a comment ──────────────

def test_every_pii_table_is_bounded():
    """The invariant that matters is that each of these tables EXPIRES, not that it expires
    before some other table.

    An earlier version of this test asserted the identity tables outlive less than the flow
    tables, which is false and was also the wrong rule: `zeek_conn` is 7 days because it is
    enormous, not because it is sensitive, so using it as the reference would have justified
    deleting Kerberos history after a week -- shorter than the campaign it exists to catch.
    What must never happen is an unbounded table holding usernames and file paths.
    """
    for table in ("zeek_kerberos", "zeek_dce_rpc", "zeek_smb_mapping", "zeek_smb_files",
                  "zeek_ntlm", "ntlm_identity_daily"):
        days = _ttl_of(table)
        assert days is not None, f"{table} holds PII and has NO TTL -- it is unbounded"
        assert days <= 365, f"{table} retains PII for {days} days, which is effectively forever"


def test_retention_is_ordered_by_exposure():
    """Shortest where the exposure is greatest, which is the rule the schema documents.

    `smb_files` records WHAT was touched -- verbatim paths and filenames -- so it must expire
    first. `dce_rpc` is RPC metadata with no username or path, so it may live longest.
    """
    def days(table: str) -> int:
        d = _ttl_of(table)
        assert d is not None, f"{table} has no TTL"
        return d

    assert days("zeek_smb_files") < days("zeek_smb_mapping") <= days("zeek_kerberos")
    assert days("zeek_smb_files") < days("zeek_ntlm") <= days("zeek_kerberos")
    # The aggregate must outlive the raw rows it summarises, or the identity graph is
    # summarised into a table that expires before the events.
    assert days("ntlm_identity_daily") > days("zeek_ntlm")


def test_the_schema_does_not_claim_the_flow_tables_as_the_privacy_reference():
    """The comment made a false claim about retention, and a false privacy rationale is worse
    than none: it reads as a considered judgement while justifying the opposite numbers."""
    # Comments stripped: the corrected header now QUOTES the false claim while explaining
    # why it was wrong, and a naive search reads that explanation as the claim itself. (This
    # is the fourth time in this project an assertion had to read code rather than prose.)
    header = "\n".join(ln.split("--")[0] for ln in TIER2_SQL.splitlines())
    assert "SHORTER retention than the flow tables" not in header, (
        "the schema still claims these tables are shorter-lived than the flow tables, which "
        "the TTLs contradict (flow tables are 7d, these are 30-90d)"
    )
    for table in ("zeek_smb_files", "zeek_ntlm", "zeek_kerberos"):
        assert table in header, f"{table}'s retention is not justified in the header"


# ── helpers ─────────────────────────────────────────────────────────────────────

def _all_schema_sql() -> str:
    return "\n".join(p.read_text() for p in sorted((ROOT / "weirvern" / "schema").glob("*.sql")))


def _table_body(table: str) -> str:
    """The CREATE TABLE statement body for `table`, comment-stripped."""
    m = re.search(rf"CREATE TABLE IF NOT EXISTS (?:\w+\.)?{table}\s*\((.*?)\n\)",
                  _all_schema_sql(), re.S)
    assert m, f"table {table} not found in the schema"
    return m.group(1)


def _columns_of(table: str) -> list[str]:
    cols = []
    for line in _table_body(table).splitlines():
        line = line.split("--")[0].strip().rstrip(",")
        if not line:
            continue
        cols.append(line.split()[0])
    return cols


def _ttl_of(table: str) -> int | None:
    """The TTL in days for `table`, or None if it has none.

    COMMENTS ARE STRIPPED FIRST. The schema's header discusses retention in prose, and the
    column bodies carry explanatory comments that mention intervals; a naive search reads
    that discussion as if it were a clause. (This is the third place in this project where an
    assertion had to be made against code rather than the prose describing the code.)
    """
    sql = "\n".join(ln.split("--")[0] for ln in _all_schema_sql().splitlines())
    m = re.search(rf"CREATE TABLE IF NOT EXISTS (?:\w+\.)?{table}\s*\(.*?\n\)\s*(.*?);",
                  sql, re.S)
    if not m:
        return None
    ttl = re.search(r"TTL \w+ \+ INTERVAL (\d+) DAY", m.group(1))
    return int(ttl.group(1)) if ttl else None
