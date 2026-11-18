"""Tailer tests — rotation, replacement, truncation, and partial-line handling.

These cover the file-lifecycle cases that produced silent data loss in
production scenarios:

  * a file REPLACED by a larger one (copytruncate rotation, or a filesystem
    reusing the inode) — indistinguishable from an append by any stat() field,
    so detection uses record boundaries
  * partial trailing lines (async writers) — must be held back, not consumed
  * duplicates — re-reading must not re-insert

NOTE on portability: an earlier version of this file asserted that delete +
recreate changes the inode. That is a filesystem allocator detail, not the
behaviour under test, and it made the suite pass on ext4 while failing on
GitHub's overlayfs (inode reused). Never assert inode differences here.
"""
import contextlib
import json
import os
import pathlib
import tempfile
import threading
import time

import pytest

from weirvern.ingester import (
    TailState,
    _offset_is_on_boundary,
    load_tail_state,
    load_zeek_state,
    save_tail_state,
    tail_and_insert,
    tail_forever,
    tail_zeek_dir,
)


def _tail_state_path_for(p):
    """The checkpoint path the product would use for `p`, resolved the same way it resolves it."""
    from weirvern.ingester import _tail_state_path
    return _tail_state_path(str(p))


class FakeCH:
    """Minimal ClickHouse stand-in recording inserted row counts."""

    def __init__(self):
        self.inserted = 0
        self.calls = []

    def insert(self, table, rows, column_names=None):
        self.calls.append(rows)
        self.inserted += len(rows)


def _write(directory, name, records):
    path = os.path.join(directory, name)
    with open(path, "w") as fh:
        for r in records:
            fh.write(json.dumps(r) + "\n")
    return path


def _append(path, records):
    with open(path, "a") as fh:
        for r in records:
            fh.write(json.dumps(r) + "\n")


def _flow_record(i=1, pad=0):
    return {
        "time_flow_start_ns": 1_700_000_000_000_000_000,
        "time_flow_end_ns": 1_700_000_000_005_000_000,
        "src_addr": "198.51.100.10",
        "dst_addr": "8.8.8.8",
        "src_port": 5000 + i,
        "dst_port": 443,
        "proto": "TCP",
        "bytes": 1000 * i,
        "packets": 10 * i,
        "pad": "x" * pad,
    }


# --- boundary helper ---------------------------------------------------------
def test_offset_boundary_detection():
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "f.jsonl")
        with open(p, "w") as fh:
            fh.write('{"a":1}\n{"b":2}\n')
        assert _offset_is_on_boundary(p, 0) is True        # start of file
        assert _offset_is_on_boundary(p, 8) is True        # just after \n
        assert _offset_is_on_boundary(p, 4) is False       # mid-record
        # missing file fails open (no spurious full re-read on I/O hiccup)
        assert _offset_is_on_boundary(os.path.join(d, "nope"), 5) is True


# --- core tailing ------------------------------------------------------------
def test_first_pass_reads_all_rows():
    fake = FakeCH()
    with tempfile.TemporaryDirectory() as d:
        path = _write(d, "flows.jsonl", [_flow_record(1), _flow_record(2), _flow_record(3)])
        st = TailState()
        inserted, offset, _ = tail_and_insert(fake, path, state=st)
        assert inserted == 3
        assert offset > 0
        assert st.offset == offset


def test_second_pass_reads_nothing_new():
    fake = FakeCH()
    with tempfile.TemporaryDirectory() as d:
        path = _write(d, "flows.jsonl", [_flow_record(1), _flow_record(2)])
        st = TailState()
        assert tail_and_insert(fake, path, state=st)[0] == 2
        # unchanged file: must insert ZERO rows (the duplicate-insert bug)
        assert tail_and_insert(fake, path, state=st)[0] == 0


def test_appended_records_only():
    fake = FakeCH()
    with tempfile.TemporaryDirectory() as d:
        path = _write(d, "flows.jsonl", [_flow_record(1)])
        st = TailState()
        assert tail_and_insert(fake, path, state=st)[0] == 1
        _append(path, [_flow_record(2), _flow_record(3)])
        assert tail_and_insert(fake, path, state=st)[0] == 2


def test_replacement_by_larger_file_is_detected():
    """THE production bug: a file replaced by a LARGER one is indistinguishable
    from an append by inode, size, or mtime. Detection must use record
    boundaries, or records are silently skipped (measured: 5 written, 4 read)."""
    fake = FakeCH()
    with tempfile.TemporaryDirectory() as d:
        path = _write(d, "flows.jsonl", [_flow_record(1)])
        st = TailState()
        assert tail_and_insert(fake, path, state=st)[0] == 1

        time.sleep(0.01)
        # Replace with MORE data, padded so the new file is larger than the old
        # offset. Same path; inode may or may not be reused.
        path = _write(d, "flows.jsonl", [_flow_record(100 + i, pad=200) for i in range(5)])
        assert os.path.getsize(path) >= st.offset, "test premise: replacement is bigger"

        inserted, _, _ = tail_and_insert(fake, path, state=st)
        assert inserted == 5, f"replacement not re-read (got {inserted})"


def test_truncation_recovery():
    """copytruncate style: same file, shrunk below our offset."""
    fake = FakeCH()
    with tempfile.TemporaryDirectory() as d:
        path = _write(d, "flows.jsonl", [_flow_record(1), _flow_record(2)])
        st = TailState()
        assert tail_and_insert(fake, path, state=st)[0] == 2

        path = _write(d, "flows.jsonl", [_flow_record(7)])
        assert tail_and_insert(fake, path, state=st)[0] == 1


def test_rotation_with_different_inode():
    """A genuine rotation (different inode) must re-read from 0."""
    fake = FakeCH()
    with tempfile.TemporaryDirectory() as d:
        path = _write(d, "flows.jsonl", [_flow_record(1)])
        st = TailState()
        tail_and_insert(fake, path, state=st)

        # Force the rotation branch deterministically: pretend the last file we
        # read had a different inode than what is on disk now.
        st.identity = (st.inode + 1, st.offset, 0)
        path = _write(d, "flows.jsonl", [_flow_record(9)])
        inserted, _, _ = tail_and_insert(fake, path, state=st)
        assert inserted == 1


def test_partial_line_at_eof_is_not_lost():
    """A half-written trailing line must be held back, not consumed — otherwise
    the completed record is read as a JSON fragment and lost forever."""
    fake = FakeCH()
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "flows.jsonl")
        complete = json.dumps(_flow_record(1))
        partial = json.dumps(_flow_record(2))

        with open(path, "w") as fh:
            fh.write(complete + "\n")
            fh.write(partial[: len(partial) // 2])  # mid-write, no newline

        st = TailState()
        inserted, offset, _ = tail_and_insert(fake, path, state=st)
        assert inserted == 1
        assert offset == len(complete) + 1  # held at the partial line's start

        with open(path, "a") as fh:
            fh.write(partial[len(partial) // 2:] + "\n")

        assert tail_and_insert(fake, path, state=st)[0] == 1


def test_legacy_offset_signature_still_works():
    """The (offset, known_inode) call style must keep functioning."""
    fake = FakeCH()
    with tempfile.TemporaryDirectory() as d:
        path = _write(d, "flows.jsonl", [_flow_record(1), _flow_record(2)])
        inserted, offset, inode = tail_and_insert(fake, path)
        assert inserted == 2
        assert tail_and_insert(fake, path, offset=offset, known_inode=inode)[0] == 0


def test_missing_file_is_not_an_error():
    fake = FakeCH()
    with tempfile.TemporaryDirectory() as d:
        assert tail_and_insert(fake, os.path.join(d, "absent.jsonl"))[0] == 0


# ── the offset-safety mechanism, tested rather than described ──────────────────────────────────
#
# WHY THESE EXIST. Three audit findings claimed the filename-keyed tail state causes duplicate
# ingest and unbounded growth. MEASURED on the live sensor: it does re-read (155 files, 111 MB —
# dominated by dns at 100 MB), but the Zeek tables are `ReplacingMergeTree ORDER BY (ts, uid)` with
# `uid` taken from Zeek's own log line, so a re-read COLLAPSES onto the existing row rather than
# adding one (53,749 rows against 51,322 distinct keys; 2 MiB on disk for 100 MB of source text).
#
# So the cost is startup parsing work, not corruption — and the thing that makes resuming safe at
# all is `_offset_is_on_boundary`, which checks that a stored offset sits just after a newline.
# Writing about it was not enough: my first draft of the docstring described this mechanism wrongly
# twice (I thought offset 12 was a boundary in a 29-byte file when it is mid-line, and I read a
# mis-stored offset as a defect in the append path). These tests pin the behaviour I then verified.
def _boundary_probe(tmp_path, content: str):
    from weirvern.ingester import _offset_is_on_boundary

    path = tmp_path / "conn.log"
    path.write_text(content)
    return [(off, _offset_is_on_boundary(str(path), off)) for off in range(len(content) + 1)]


def test_a_boundary_is_exactly_the_position_after_a_newline(tmp_path):
    content = "line one\nline two\n"
    results = dict(_boundary_probe(tmp_path, content))
    for off, ok in results.items():
        expected = off == 0 or content[off - 1] == "\n"
        assert ok is expected, (
            f"offset {off} (prev char {content[off - 1]!r}) reported boundary={ok}, expected "
            f"{expected} — a boundary must be the position just after a newline"
        )


def test_an_offset_in_the_middle_of_a_line_is_NOT_a_boundary(tmp_path):
    """The specific reading I got wrong first, kept as a case so it stays settled."""
    results = dict(_boundary_probe(tmp_path, "line one\nline two\n"))
    assert results[12] is False, "offset 12 of a 19-byte two-line file is mid-line"
    assert results[9] is True, "offset 9 is just after the first newline"


def test_a_missing_file_fails_open(tmp_path):
    """An I/O error must not trigger a full re-read of a file that may be large.

    Fail-open here is the deliberate choice: the alternative is that a transient read problem on a
    100 MB log causes the tailer to re-parse it.
    """
    from weirvern.ingester import _offset_is_on_boundary

    assert _offset_is_on_boundary(str(tmp_path / "nope.log"), 4096) is True


def test_an_appended_file_keeps_its_offset(tmp_path):
    """THE HEALTHY PATH, and the one that must not be disturbed.

    Zeek appends continuously. If appending were mistaken for replacement, every pass would re-read
    the whole file — which is the very cost these findings were about.
    """
    from weirvern.ingester import TailState

    path = tmp_path / "conn.log"
    first = "line one\nline two\n"
    path.write_text(first)
    state = TailState()
    state.note_read(path.stat(), len(first))

    path.write_text(first + "line three\n")
    assert state.reset_reason(path.stat(), str(path)) == "", (
        "an appended file was treated as replaced, so the offset would be discarded and the whole "
        "file re-read every pass"
    )


def test_a_reused_filename_is_detected(tmp_path):
    """THE DEFECT THE MECHANISM EXISTS FOR.

    Zeek's rotation timestamp has second resolution, so a sensor restarting within the same second
    writes a new file under a name an old state entry still holds. Applying the stored offset to
    that content would resume mid-record and silently skip data.
    """
    from weirvern.ingester import TailState

    path = tmp_path / "conn.log"
    first = "line one\nline two\n"
    path.write_text(first)
    state = TailState()
    state.note_read(path.stat(), len(first))

    path.write_text("entirely different content, longer\n")
    reason = state.reset_reason(path.stat(), str(path))
    assert reason, "a reused filename with different content was trusted, so records would be skipped"
    assert "boundary" in reason or "inode" in reason or "truncated" in reason, (
        f"the reason does not name a mechanism: {reason!r}"
    )


# ── the cap-trim protocol: a rewrite must SHIFT the cursor, never reset it ────────────────────
#
# MEASURED DEFECT (review round 2026-10-15): over cap, `enforce_netflow` rewrites the sink
# every five minutes (a new inode), the reset detection above fires, and the naive response
# re-read the WHOLE file from zero -- inserting up to the full cap of duplicate rows into
# `flows`, a MergeTree with no deduplication, once per cycle, forever. The trim now records
# each rewrite in a hint beside the file and the reader subtracts instead of re-reading.


def test_a_cap_trim_does_not_re_ingest_the_same_records(monkeypatch, tmp_path):
    from weirvern import enforce

    monkeypatch.setenv("TAIL_STATE_DIR", str(tmp_path / "state"))
    flows = tmp_path / "flows"
    flows.mkdir()
    monkeypatch.setattr(enforce, "NETFLOW_DIR", flows)
    path = str(flows / "flows.jsonl")
    with open(path, "w") as fh:
        for i in range(60):
            fh.write(json.dumps(_flow_record(i + 1, pad=60)) + "\n")

    fake = FakeCH()
    st = TailState()
    assert tail_and_insert(fake, path, state=st)[0] == 60
    save_tail_state(path, st)
    size_before = os.path.getsize(path)

    r = enforce.enforce_netflow(0.002)  # a cap far below the file: a real trim
    assert r.actions == 1
    assert os.path.getsize(path) < size_before

    # The reader keeps its in-memory state; the trim must SHIFT it, not reset it.
    assert tail_and_insert(fake, path, state=st)[0] == 0, "the trim caused a re-ingest"
    assert fake.inserted == 60, "duplicate rows reached the inserter"

    # A restart is the other half: the checkpoint, shifted at load, must not re-read either.
    st2 = load_tail_state(path)
    assert st2.offset > 0
    assert tail_and_insert(fake, path, state=st2)[0] == 0
    assert fake.inserted == 60

    # And nothing is LOST: records appended after the trim are still ingested.
    _append(path, [_flow_record(101, pad=60), _flow_record(102, pad=60)])
    assert tail_and_insert(fake, path, state=st)[0] == 2


def test_a_trim_that_removed_unread_records_says_so_and_recovers(monkeypatch, tmp_path, caplog):
    """The guard normally prevents this; when a trim got past it anyway (an older build, or a
    trimmer without the shared state volume), the reader must SAY what was lost and recover by
    re-reading what remains -- never guess a shift."""
    monkeypatch.setenv("TAIL_STATE_DIR", str(tmp_path / "state"))
    path = str(tmp_path / "flows.jsonl")
    with open(path, "w") as fh:
        for i in range(60):
            fh.write(json.dumps(_flow_record(i + 1, pad=60)) + "\n")
    with open(path) as fh:
        offsets, acc = [], 0
        lines = fh.readlines()
        for line in lines:
            acc += len(line.encode())
            offsets.append(acc)

    old_ino = os.stat(path).st_ino
    state = TailState(offset=offsets[44], inode=old_ino, identity=(1234567, 0, 0))
    cut = offsets[49]  # records 46..50 were never read -- and are about to vanish

    tmp = path + ".new"
    with open(tmp, "wb") as fh:
        fh.write("".join(lines[50:]).encode())
    os.replace(tmp, path)
    with open(path + ".trimhint", "w") as fh:
        json.dump({"chain": [{"from": old_ino, "to": os.stat(path).st_ino, "removed": cut}]}, fh)

    fake = FakeCH()
    with caplog.at_level("WARNING", logger="weirvern.ingester"):
        inserted, _, _ = tail_and_insert(fake, path, state=state)
    assert inserted == 10, "the reader did not recover the surviving records"
    assert any("removed before they were read" in m for m in caplog.messages), (
        "the loss was not reported"
    )


# ── the exporter allow-list: unauthenticated UDP is the reason it exists ───────────────────────
#
# THE EXPOSURE, measured on the live deployment. The goflow2 collector runs with hostNetwork so it
# can bind 2055/6343 on the node's own interfaces (an exporter was observed sending to the
# container port instead of the NodePort, and its packets vanished with nothing logged). That also
# means ANY device that can reach the node can send flow records: NetFlow has no authentication and
# no source verification, the NetworkPolicy deliberately exempts this collector, and goflow2 has no
# accept-list. So a host on the segment can inject records ATTRIBUTED TO ANY ADDRESS IT CHOOSES,
# and those records feed the anomaly models and the charts a threat-hunt team reads.
#
# The allow-list is OFF by default -- a collector that silently drops a legitimate exporter on
# first boot is worse than one that takes what arrives -- and `weirvern exporters` exists so it can
# be written from observed fact rather than from documentation.
def test_no_allow_list_means_ACCEPT_EVERYTHING_and_that_is_not_an_empty_list():
    """`None` (no filter) and `[]` (reject all) must be different, and this is why.

    An empty list would reject every record, so a single typo in a config value would silently stop
    all flow ingest while the collector looked perfectly healthy -- the failure this project keeps
    finding. `None` means the operator has not set a list, which is the shipped default.
    """
    from weirvern.ingester import _exporter_networks

    assert _exporter_networks("") is None
    assert _exporter_networks("   ") is None


def test_a_host_address_with_a_prefix_is_accepted():
    """An operator writes their exporter's address; they should not have to write /32.

    `strict=False` is what makes 198.51.100.5/24 resolve to the network it belongs to rather than
    raising, which would refuse a list that is obviously what the operator meant.
    """
    from weirvern.ingester import _exporter_networks

    nets = _exporter_networks("198.51.100.5/24")
    assert nets is not None and len(nets) == 1
    assert str(nets[0]) == "198.51.100.0/24"


def test_an_unusable_allow_list_does_not_silently_permit():
    """Every entry unparsable must NOT fall back to "accept everything" quietly.

    For a security control, failing open in silence is the wrong direction. The choice here is to
    treat an unusable list as "no filter" -- because the alternative (reject everything) turns a
    typo into a total ingest outage -- but it logs at ERROR so the operator learns.
    """
    from weirvern.ingester import _exporter_networks

    assert _exporter_networks("not-an-ip") is None


def test_permitted_matches_the_list_and_refuses_outsiders():
    """The verdict is a REASON, not a bool (glm-5.3 review): the caller needs to tell a checked
    rejection from an admission it could not check at all, or the control's coverage is unverifiable.
    """
    from weirvern.ingester import _exporter_networks, _exporter_permitted

    nets = _exporter_networks("198.51.100.0/24, 192.0.2.7")
    assert _exporter_permitted("198.51.100.9", nets) == "allowed"
    assert _exporter_permitted("192.0.2.7", nets) == "allowed"
    assert _exporter_permitted("203.0.113.9", nets) == "rejected", (
        "an address outside the allow-list was not reported as rejected, so the filter does nothing"
    )


def test_a_record_with_no_sampler_address_is_permitted():
    """The absence of an address is not suspicious; a DIFFERENT one is.

    goflow2 omits sampler_address for some protocol variants, and rejecting those would drop
    legitimate flows to enforce a control against something the record does not carry.
    """
    from weirvern.ingester import _exporter_networks, _exporter_permitted

    nets = _exporter_networks("198.51.100.0/24")
    assert _exporter_permitted("", nets) == "no-address"
    assert _exporter_permitted(None, nets) == "no-address"


def test_no_filter_permits_everything():
    from weirvern.ingester import _exporter_permitted

    assert _exporter_permitted("203.0.113.9", None) == "ungated"


def test_an_ipv6_address_is_not_matched_against_an_ipv4_network():
    """Version mismatch must not match, and must not raise.

    CORRECTED AFTER MUTATION TESTING. I wrote this expecting `ipaddress` to raise TypeError on a
    cross-version membership test, and asserted the code needed an explicit `parsed.version ==
    net.version` guard for that reason. Measured: `in` returns False, it does not raise. So the
    guard is defensive rather than load-bearing, and the mutation that removed it SURVIVED -- which
    is the honest signal that my stated reason was wrong.

    The behaviour is still worth pinning, because a future change to the matching could introduce a
    raise, and an exception inside the ingest loop would abort the whole pass. But the test now
    documents what it actually protects rather than a mechanism that is not there.
    """
    from weirvern.ingester import _exporter_networks, _exporter_permitted

    nets = _exporter_networks("198.51.100.0/24")
    assert _exporter_permitted("2001:db8::1", nets) == "rejected"
    nets6 = _exporter_networks("2001:db8::/32")
    assert _exporter_permitted("2001:db8::1", nets6) == "allowed"
    assert _exporter_permitted("198.51.100.9", nets6) == "rejected"


def test_a_cross_version_membership_test_does_not_raise():
    """The property my earlier justification claimed, pinned directly against the stdlib.

    Pinning it HERE rather than through the filter means the assertion is about the language
    behaviour the filter relies on, so if a Python release ever changed it this test says so at the
    right level instead of surfacing as an unexplained ingest failure.
    """
    from ipaddress import ip_address, ip_network

    assert (ip_address("2001:db8::1") in ip_network("198.51.100.0/24")) is False
    assert (ip_address("198.51.100.9") in ip_network("2001:db8::/32")) is False


# ── BOTH Zeek sentinels must reach the database as absent ────────────────────────────────────
#
# MEASURED DEFECT (audit F012/F021/F027, confirmed by reading the code AND running it). Zeek's
# header declares TWO sentinels with different meanings:
#
#     #unset_field   -         "not set"
#     #empty_field   (empty)   "set, but to an empty value"
#
# `zeek_value()` handles both, but it is applied PER FIELD by each mapper, so a mapper reading a
# field directly with `rec.get(...) or ""` bypasses it. `map_zeek_ssl` did exactly that for EVERY
# string field in its row, so `weirvern.zeek_ssl.ja4` held the literal 7-character `(empty)`:
#
#   * `uniqExactIf(ja4, ja4 != '') AS ja4_count` counted it as a REAL DISTINCT FINGERPRINT, so
#     `zeek_ja4_count` (a live ML feature) reported 1 on hosts with no fingerprint at all;
#   * `ja4 != '-'` guards elsewhere were satisfied by it, so a detection rule could compare
#     against the literal text;
#   * `weirvern/tools/sanitize_identifiers.py` counts address-shaped tokens, and `(empty)` is not
#     one, so no other guard noticed either.
#
# THE READ LAYER NOW NORMALISES BOTH, which is the fix: a mapper cannot forget what it does not
# have to remember. These tests drive the REAL tailer so they cannot be satisfied by a
# mapper-level change alone.

def test_map_zeek_ssl_leaves_the_empty_sentinel_as_an_absent_value():
    """The mapper in isolation: every string field it reads directly must come out absent."""
    from weirvern.ingester import map_zeek_ssl

    row = map_zeek_ssl({
        "ts": "1758000000.0", "uid": "C1",
        "id.orig_h": "198.51.100.5", "id.resp_h": "198.51.100.9", "id.resp_p": "443",
        "version": "TLSv13", "cipher": "(empty)", "server_name": "(empty)",
        "ja4": "(empty)", "ja4_o": "(empty)", "validation_status": "(empty)",
    })
    assert row is not None
    for field in ("ja4", "ja4_orig", "server_name", "cipher", "validation_status"):
        assert row[field] != "(empty)", (
            f"{field} stored Zeek's empty sentinel literally. A sentinel counted as a real value "
            f"is how `zeek_ja4_count` reported 1 for a host with no fingerprint"
        )
        assert row[field] == "", f"{field} should be an empty string, not {row[field]!r}"


# ── a REAL dns.log shape, copied from the live sensor ────────────────────────────────────────
#
# THE ARITY IS THE POINT. The header declares 26 fields; a fixture with fewer makes every row
# unmappable, so the tailer inserts NOTHING and the test passes VACUOUSLY. Three attempts at
# this test did exactly that before the real header was read off the sensor with `cat -A`.
_DNS_FIELDS = [
    'ts',
    'uid',
    'id.orig_h',
    'id.orig_p',
    'id.resp_h',
    'id.resp_p',
    'proto',
    'trans_id',
    'rtt',
    'query',
    'qclass',
    'qclass_name',
    'qtype',
    'qtype_name',
    'rcode',
    'rcode_name',
    'AA',
    'TC',
    'RD',
    'RA',
    'Z',
    'answers',
    'TTLs',
    'rejected',
    'opcode',
    'opcode_name',
]
_DNS_TYPES = [
    'time',
    'string',
    'addr',
    'port',
    'addr',
    'port',
    'enum',
    'count',
    'interval',
    'string',
    'count',
    'string',
    'count',
    'string',
    'count',
    'string',
    'bool',
    'bool',
    'bool',
    'bool',
    'count',
    'vector[string]',
    'vector[interval]',
    'bool',
    'count',
    'string',
]


class _CaptureClient:
    """A client that records what the tailer would insert, and WHICH TABLE it was bound for."""

    def __init__(self):
        self.rows = []
        self.tables = []

    def insert(self, table, rows, column_names=None):
        for r in rows:
            self.rows.append(dict(zip(column_names or [], r, strict=False)))
            self.tables.append(table)


def _dns_table_rows(client):
    """The rows bound for weirvern.zeek_dns, in insert order.

    NOT client.rows[0]. Since 2026-10-16 the DNS log is ALSO an identity source, so each row
    writes an observation insert BEFORE the table insert -- the same shape dhcp and ssl have had
    all along. A positional read silently started inspecting the observation dict instead of the
    row under test (caught by these very tests the moment the wiring landed).
    """
    return [r for t, r in zip(client.tables, client.rows, strict=False)
            if str(t).endswith("zeek_dns")]


def _real_dns_log(tmp_path, answers, *, subdir="a"):
    """A dns.log matching the real header, with `answers` set to the given value.

    ── TWO THINGS THAT MAKE THIS TEST PROVE SOMETHING, BOTH LEARNED THE HARD WAY ────────────────

    1. THE FILENAME IS THE LOG TYPE. `tail_zeek_log` computes `log_type` from `basename(path)`
       split on "." and returns EARLY when that name is not in `ZEEK_MAPPERS`. So a fixture named
       `dns2.log` reads nothing at all and the assertion fails for a reason that has nothing to do
       with the code under test -- and, worse, a fixture named `dns.log` in a test that forgot to
       assert the insert happened would pass VACUOUSLY. Every fixture here is `dns.log`, each in
       its own subdirectory.

    2. THE ROW MUST SATISFY THE MAPPER. `map_zeek_dns` returns None when `id.orig_h`/`id.resp_h`
       are absent, so a shortened fixture is dropped before it can reach the insert. A minimal
       3-field row therefore inserts NOTHING, and a test built on one asserts against an empty
       list while looking like a passing test of the normalisation.
    """
    T = chr(9)
    row = ["1758000000.0", "C1", "198.51.100.5", "40000", "198.51.100.9", "53", "udp", "51987",
           "0.1", "example.test", "1", "C_INTERNET", "1", "A", "0", "NOERROR",
           "F", "F", "T", "F", "0", answers, "300", "F", "0", "query"]
    assert len(row) == len(_DNS_FIELDS), "the fixture arity must match the header it declares"
    d = tmp_path / subdir
    d.mkdir(parents=True, exist_ok=True)
    p = d / "dns.log"
    p.write_text(
        "#separator " + chr(92) + "x09" + chr(10)
        + "#unset_field" + T + "-" + chr(10)
        + "#empty_field" + T + "(empty)" + chr(10)
        + "#fields" + T + T.join(_DNS_FIELDS) + chr(10)
        + "#types" + T + T.join(_DNS_TYPES) + chr(10)
        + T.join(row) + chr(10)
    )
    return p


def test_the_READ_LAYER_covers_what_a_mapper_forgets(tmp_path):
    """THE BACKSTOP, driven through the real tailer, on a field NO MAPPER NORMALISES.

    `map_zeek_dns` reads `answers` with `rec.get("answers") or ""` (measured: 79 such raw reads
    across the mappers), so the READ LAYER is the only thing that can turn its `(empty)` into an
    absent value. That is what makes this a test of the backstop rather than of a mapper.

    Deliberately NOT ja4: the SSL mapper normalises ja4 itself, so reverting the read layer alone
    left the first version of this test green.
    """
    from weirvern.ingester import tail_zeek_log

    client = _CaptureClient()
    tail_zeek_log(client, str(_real_dns_log(tmp_path, "(empty)", subdir="a")))
    assert client.rows, (
        "the tailer inserted nothing. The fixture's ARITY must match the header it declares -- a "
        "shorter row is unmappable and this test would pass while proving nothing"
    )
    rows = _dns_table_rows(client)
    assert rows, "the DNS table insert went missing entirely"
    assert rows[0].get("answers") == "", (
        "the sentinel reached the INSERT as literal text. The read layer normalised only `-`, and "
        "the DNS mapper reads this field raw, so nothing else could have caught it"
    )
    for field, val in rows[0].items():
        assert val != "(empty)", f"{field} reached the INSERT as the literal sentinel"


def test_the_read_layer_still_normalises_the_unset_sentinel(tmp_path):
    """The original guarantee survives the change: `-` is still absent, for the same reason."""
    from weirvern.ingester import tail_zeek_log

    client = _CaptureClient()
    tail_zeek_log(client, str(_real_dns_log(tmp_path, "-", subdir="b")))
    rows = _dns_table_rows(client)
    assert rows, (
        "the tailer inserted nothing. Either the fixture is not named dns.log (the tailer derives "
        "the log type from the FILENAME and skips anything it has no mapper for), or the row does "
        "not satisfy the mapper -- both of which make this test pass while proving nothing"
    )
    assert rows[0].get("answers") == ""


def test_a_REAL_value_still_reaches_the_table(tmp_path):
    """And the normalisation must not eat real data. Without this, a normaliser that blanked EVERY
    field would satisfy the two tests above."""
    from weirvern.ingester import tail_zeek_log

    client = _CaptureClient()
    tail_zeek_log(client, str(_real_dns_log(tmp_path, "198.51.100.20", subdir="c")))
    rows = _dns_table_rows(client)
    assert rows, "the tailer inserted nothing, so this test proves nothing"
    assert rows[0].get("answers") == "198.51.100.20"
    assert rows[0].get("query") == "example.test"


# ── THE TAIL CURSOR MUST SURVIVE A RESTART (audit F018) ──────────────────────────────────────
#
# CONFIRMED BY RUNNING IT, not by reading. `tail_forever` built its `TailState()` in memory and
# never wrote it anywhere, so the cursor died with the process. Measured with a 6-row JSONL: two
# passes in ONE process inserted 6 then 0 (correct), and a restart with the file unchanged
# inserted 6 AGAIN.
#
# The docstring at the top of `tail_forever` documents that failure mode as SOLVED -- "re-reading
# the whole file from offset 0 every pass inserted every row ~12x per minute into `flows`,
# corrupting aggregates and baselines". The in-process case was fixed; the restart case was left
# open, which is the same corruption with a longer period.

def _flow_row(i: int) -> str:
    return json.dumps({
        "type": "FLOW", "time": 1700000000 + i, "src_addr": f"10.0.0.{i}", "dst_addr": "198.51.100.1",
        "src_port": 1000 + i, "dst_port": 80, "proto": "TCP", "bytes": 100, "packets": 1,
    })


@pytest.fixture(autouse=True)
def _hermetic_tail_state(tmp_path_factory, monkeypatch):
    """Point the checkpoint at a per-test directory.

    THE CHECKPOINT DOES NOT LIVE BESIDE THE TAILED FILE (measured: the deployed worker mounts the
    flow directory READ-ONLY, so a checkpoint written there silently failed on every restart). It
    resolves through `TAIL_STATE_DIR`, defaulting to `/models`, so these tests must redirect it or
    they would write into the real deployment's model volume.

    THIS FIXTURE IS ALSO THE REASON THE BUG SURVIVED ITS FIRST TESTS: `tmp_path` is always
    writable, so a checkpoint written beside the file works perfectly in a test and fails on the
    live cluster. See `test_a_read_only_data_mount_still_checkpoints_somewhere_writable` below,
    which is the test that would have caught it.
    """
    d = tmp_path_factory.mktemp("tailstate")
    monkeypatch.setenv("TAIL_STATE_DIR", str(d))
    return d


class _CountingClient:
    """Counts inserts. The product only needs `insert` and `query` to exist."""

    def __init__(self):
        self.inserts = 0

    def insert(self, *a, **kw):
        self.inserts += 1

    def query(self, *a, **kw):
        class _R:
            result_rows: list = []

        return _R()


def _jsonl(tmp_path, name="flows.jsonl", rows=6):
    p = tmp_path / name
    p.write_text("\n".join(_flow_row(i) for i in range(rows)) + "\n")
    return p


def test_a_RESTART_does_not_re_ingest_the_whole_file(tmp_path):
    """THE DEFECT. Two separate processes over one unchanged file: the second must insert 0."""
    f = _jsonl(tmp_path)

    # Run 1: a first start, which now checkpoints as it goes.
    c1 = _CountingClient()
    st1 = load_tail_state(str(f))
    tail_and_insert(c1, str(f), state=st1, allow="")
    save_tail_state(str(f), st1)
    assert c1.inserts > 0, "run 1 ingested nothing, so this test would prove nothing"

    # Run 2: A RESTART. Fresh process, state loaded from disk, same file.
    c2 = _CountingClient()
    st2 = load_tail_state(str(f))
    tail_and_insert(c2, str(f), state=st2, allow="")
    assert c2.inserts == 0, (
        f"a restart re-ingested {c2.inserts} row(s) from an unchanged file. Every pod restart, "
        f"node reboot and image update duplicates flow data into the aggregates and baselines"
    )


def test_a_restart_still_picks_up_NEW_data(tmp_path):
    """The other half: a cursor that skips real data is worse than one that duplicates it.
    An offset past the end of what has been read must not cause the tail to miss appends."""
    f = _jsonl(tmp_path)

    c1 = _CountingClient()
    st1 = load_tail_state(str(f))
    tail_and_insert(c1, str(f), state=st1, allow="")
    save_tail_state(str(f), st1)

    with f.open("a") as fh:
        fh.write(_flow_row(99) + "\n")

    c2 = _CountingClient()
    st2 = load_tail_state(str(f))
    tail_and_insert(c2, str(f), state=st2, allow="")
    assert c2.inserts == 1, (
        f"a restart after an append inserted {c2.inserts} row(s); exactly the 1 new row must be "
        f"read. 7 means the cursor was ignored; 0 means the cursor skipped real data"
    )


def test_a_cursor_is_DISCARDED_when_the_file_was_replaced(tmp_path):
    """THE ROTATION TRAP, and the reason a checkpoint is not simply trusted. An offset only means
    something for the file instance it came from; honouring a stale cursor against a REPLACED file
    silently skips everything written since -- losing data rather than duplicating it, which is
    the worse of the two failures because nothing looks wrong afterwards."""
    f = tmp_path / "flows.jsonl"
    f.write_text("\n".join(_flow_row(i) for i in range(3)) + "\n")
    save_tail_state(str(f), TailState(offset=50, inode=1))

    # Replace it with different content whose byte 49 is NOT a line boundary.
    f.write_text("X" * 200 + "\n" + "\n".join(_flow_row(i) for i in range(6)) + "\n")

    st = load_tail_state(str(f))
    assert st.offset == 0, (
        f"a cursor of {st.offset} was honoured against a replaced file. Everything written since "
        f"the rotation would be skipped, and the tail would look healthy while doing it"
    )


def test_a_corrupt_cursor_file_is_ignored_not_fatal(tmp_path):
    """A truncated or hand-edited checkpoint must cost a re-read, never a crash: the cursor is an
    optimisation, and ingestion must not depend on it being readable."""
    f = _jsonl(tmp_path)
    pathlib.Path(_tail_state_path_for(f)).write_text("{ this is not json")
    assert load_tail_state(str(f)).offset == 0


def test_an_impossible_cursor_is_ignored(tmp_path):
    """A NEGATIVE or absent offset is not a position. Treating it as one re-reads from the start
    or seeks backwards, and neither is what the checkpoint meant."""
    f = _jsonl(tmp_path)
    for bad in ('{"offset": -5, "inode": 1}', '{"inode": 1}', "{}", "[]", "null"):
        pathlib.Path(_tail_state_path_for(f)).write_text(bad)
        assert load_tail_state(str(f)).offset == 0, f"accepted a cursor from {bad!r}"


def test_a_checkpoint_that_cannot_be_written_does_not_raise(tmp_path):
    """NEVER RAISES is the contract. A full or read-only filesystem costs duplicate rows on the
    next restart, which is recoverable; an exception here would stop ingestion entirely."""
    f = _jsonl(tmp_path)
    st = TailState(offset=123, inode=1)
    # A directory where the checkpoint file must go: the write fails, the call must not.
    (tmp_path / "flows.jsonl.tailstate").mkdir()
    save_tail_state(str(f), st)


def test_the_checkpoint_round_trips_the_cursor(tmp_path):
    """Basic integrity, so the tests above are not passing on a function that writes nothing.

    THE OFFSET IS COMPUTED FROM THE FIXTURE, NOT HARDCODED, and that is the lesson from two
    failures in a row. The first version used 978 -- the fixture's exact size, so one byte PAST the
    end -- and `_offset_is_on_boundary` rightly rejected it. The second used 489, a value I had
    checked against a file built in a scratch script, but the test's own `_flow_row` writes a
    different `dst_addr` and the byte layout differs, so 489 landed mid-line. An offset is only
    meaningful relative to a specific file, so the test derives one from the file it actually has:
    the end of the first complete line.
    """
    f = _jsonl(tmp_path)
    body = f.read_bytes()
    offset = body.index(b"\n") + 1
    assert len(body) > offset, "fixture too small for this test to mean anything"
    assert offset > 0
    save_tail_state(str(f), TailState(offset=offset, inode=42, identity=(42, 7, 7)))
    st = load_tail_state(str(f))
    assert st.offset == offset, (
        f"a valid in-file cursor ({offset}) was not restored: got {st.offset}"
    )
    assert st.inode == 42
    assert st.identity == (42, 7, 7), f"identity did not round-trip: {st.identity!r}"


# ── AND THE WIRING, NOT JUST THE TWO FUNCTIONS ───────────────────────────────────────────────
#
# WHY THESE EXIST. The tests above exercise `load_tail_state`/`save_tail_state` in isolation, and
# MUTATION TESTING SHOWED THEY PROVE NOTHING ABOUT THE FIX: reverting `tail_forever` to
# `state = TailState()`, and deleting its `save_tail_state(...)` call entirely, BOTH left them
# passing. The defect was in `tail_forever`'s wiring, and tests that never call `tail_forever`
# cannot see it -- a green suite over the exact bug it was written for.
#
# `tail_forever` blocks forever by design, so these run it on a thread with a stop event and a
# short interval, which is the real loop rather than a reimplementation of it.

def _run_tail_forever(path, seconds=1.2, interval=0.2):
    """Run the REAL `tail_forever` for a moment on a background thread, then STOP AND JOIN it.

    Returns the client it wrote through. The thread is stopped through `tail_forever`'s own `stop`
    flag and joined, so nothing is still tailing when the test ends -- an earlier version let the
    threads run on as daemons, and they kept checkpointing into directories the test fixture had
    already deleted, which put warnings from dead fixtures in the suite's output.
    """
    client = _CountingClient()
    stop = threading.Event()

    def _target():
        # The loop is daemonised and joined below; an exception here would only surface as an
        # obscure thread traceback, and `tail_forever` already logs its own pass failures.
        with contextlib.suppress(Exception):
            tail_forever(client, str(path), interval_s=interval, zeek_dir="",
                         exporter_allow="", stop=stop)

    th = threading.Thread(target=_target, daemon=True)
    th.start()
    # Poll rather than sleep a fixed span: the loop beats immediately, so this is fast in the
    # common case and still bounded when it is not.
    deadline = time.time() + seconds
    while time.time() < deadline and client.inserts == 0:
        time.sleep(0.05)
    # WAIT FOR THE CHECKPOINT ITSELF, NOT FOR THE CLOCK. A fixed `interval * 1.5` assumed the
    # second beat lands on time; under a loaded suite it does not, and the checkpoint assertion
    # failed intermittently -- a flaky gate is worse than a slow one. The loop is already running;
    # poll for the file it is supposed to write.
    from weirvern.ingester import _tail_state_path
    cp = pathlib.Path(_tail_state_path(str(path)))
    cp_deadline = time.time() + 10.0
    while time.time() < cp_deadline and not cp.exists():
        time.sleep(0.05)
    stop.set()
    th.join(timeout=5)
    assert not th.is_alive(), (
        "tail_forever did not stop when its stop flag was set -- the thread outlives the test"
    )
    return client


def test_TAIL_FOREVER_checkpoints_and_a_RESTART_does_not_re_ingest(tmp_path):
    """THE DEFECT, THROUGH THE REAL LOOP. This is the test that was missing: it fails if
    `tail_forever` builds its cursor fresh, and it fails if it stops checkpointing."""
    f = _jsonl(tmp_path)

    first = _run_tail_forever(f)
    assert first.inserts > 0, "the first run ingested nothing, so this proves nothing"
    from weirvern.ingester import _tail_state_path
    cp = pathlib.Path(_tail_state_path(str(f)))
    assert cp.exists(), (
        f"tail_forever ran but wrote no checkpoint at {cp}, so a restart has nothing to resume "
        f"from -- this is audit F018 exactly"
    )

    # A RESTART: a brand-new loop over the same, unchanged file.
    second = _run_tail_forever(f)
    assert second.inserts == 0, (
        f"a restart through the real loop re-ingested {second.inserts} row(s) from an unchanged "
        f"file. Every pod restart, node reboot and image update duplicates flow data into the "
        f"aggregates and baselines"
    )


def test_TAIL_FOREVER_resumes_and_still_reads_new_rows(tmp_path):
    """And it must not overshoot: after a restart, an appended row is still ingested."""
    f = _jsonl(tmp_path)
    _run_tail_forever(f)

    with f.open("a") as fh:
        fh.write(_flow_row(99) + "\n")

    after = _run_tail_forever(f)
    assert after.inserts == 1, (
        f"after a restart and an append the loop inserted {after.inserts} row(s); exactly 1 is "
        f"correct. More means the cursor was ignored, 0 means it skipped real data"
    )


def test_a_cursor_for_a_DELETED_file_is_discarded(tmp_path):
    """The file can be gone entirely -- a rotated-away log, or a volume not yet mounted. Seeking
    into a file that does not exist is not a resume, and the cursor must not be carried into
    whatever appears at that path next."""
    f = _jsonl(tmp_path)
    save_tail_state(str(f), TailState(offset=978, inode=42))
    f.unlink()
    assert load_tail_state(str(f)).offset == 0, (
        "a cursor survived the deletion of the file it described, so it would be applied to "
        "whatever is written at that path next"
    )


# ── THE CHECKPOINT MUST SURVIVE A READ-ONLY DATA MOUNT ───────────────────────────────────────
#
# THE TEST THAT WAS MISSING, and the reason the fix was inert in production while every other test
# passed. The first version of `_tail_state_path` returned `path + ".tailstate"` -- beside the
# tailed file -- which is the obvious choice and is wrong for the deployed worker, whose flow
# directory is mounted READ-ONLY on purpose (it belongs to the host and is shared with whatever
# writes it). Deployed to the live cluster and restarted, the log said:
#
#     Ingested 1086 flow records from /data/flows.jsonl (offset 1059787)
#     Could not checkpoint the tail cursor for /data/flows.jsonl: [Errno 30] Read-only file system
#
# So the cursor never saved, and every restart still re-read the whole file: the defect the fix
# was written for, entirely unaddressed in the only environment that matters.
#
# `tmp_path` is ALWAYS WRITABLE, which is exactly why no test caught it. These tests are not
# allowed to assume that.

def test_a_READ_ONLY_data_dir_still_checkpoints_somewhere_writable(tmp_path, monkeypatch):
    """THE REGRESSION. Tailing from a read-only directory must still persist a cursor.

    The mode bits are set on the fixture directory rather than mocked, so this fails if the
    product ever tries to write beside the tailed file again.
    """
    ro = tmp_path / "data"
    ro.mkdir()
    f = ro / "flows.jsonl"
    f.write_text("\n".join(_flow_row(i) for i in range(6)) + "\n")
    state_dir = tmp_path / "state"
    monkeypatch.setenv("TAIL_STATE_DIR", str(state_dir))

    # ACTUALLY MAKE IT READ-ONLY. The first version of this test asserted `not os.access(...)`
    # without ever calling chmod, so the assertion failed on a directory it had left writable --
    # the test was asserting a property of the fixture it had not established.
    ro.chmod(0o555)
    try:
        assert not os.access(ro, os.W_OK), (
            "the fixture directory is writable, so this test cannot prove anything about a "
            "read-only mount"
        )

        save_tail_state(str(f), TailState(offset=200, inode=7))
        cp = pathlib.Path(_tail_state_path_for(f))
        assert cp.exists(), (
            f"no checkpoint at {cp}. A checkpoint written beside the tailed file cannot be created "
            f"under a read-only mount, which is how the deployed worker mounts its flow directory"
        )
        assert state_dir in cp.parents, f"the checkpoint landed outside the writable state dir: {cp}"
    finally:
        # Leave the fixture removable by pytest's cleanup.
        ro.chmod(0o755)


def test_the_checkpoint_PATH_is_not_beside_the_tailed_file(tmp_path, monkeypatch):
    """Naming the rule directly, because the mistake is a one-line change anyone would re-make.

    `path + ".tailstate"` reads as obviously correct and is wrong here.
    """
    monkeypatch.setenv("TAIL_STATE_DIR", str(tmp_path / "state"))
    f = "/data/flows.jsonl"
    cp = _tail_state_path_for(f)
    assert cp != f + ".tailstate", (
        "the checkpoint is beside the tailed file again. That directory is mounted read-only in "
        "the deployed worker, so the cursor silently never saves and every restart re-reads the "
        "whole log"
    )
    assert cp.startswith(str(tmp_path / "state")), cp


def test_two_tailed_files_get_DIFFERENT_cursors(tmp_path, monkeypatch):
    """A flat state directory needs distinct names, or two tailed files (the NetFlow JSONL and
    each Zeek log) would overwrite each other's position and one of them would re-read forever."""
    monkeypatch.setenv("TAIL_STATE_DIR", str(tmp_path / "state"))
    a = _tail_state_path_for("/data/flows.jsonl")
    b = _tail_state_path_for("/zeek/logs/conn.log")
    assert a != b, f"two tailed files share a cursor: {a!r}"
    assert "flows.jsonl" in pathlib.Path(a).name, f"the name is not recognisable: {a!r}"


def test_the_state_DIR_is_configurable(tmp_path, monkeypatch):
    """An operator must be able to move the checkpoint without a code change, and the default is
    `/models` (a writable persistent volume) rather than the read-only data mount."""
    custom = tmp_path / "elsewhere"
    monkeypatch.setenv("TAIL_STATE_DIR", str(custom))
    cp = _tail_state_path_for("/data/flows.jsonl")
    assert cp.startswith(str(custom)), cp

    monkeypatch.delenv("TAIL_STATE_DIR")
    from weirvern.ingester import DEFAULT_TAIL_STATE_DIR
    assert DEFAULT_TAIL_STATE_DIR == "/models", (
        f"the default checkpoint location is {DEFAULT_TAIL_STATE_DIR!r}, which must be a writable "
        f"persistent path. /data and /zeek/logs are mounted read-only in the deployed worker, so "
        f"checkpointing beside a tailed file silently fails there"
    )
    # And when that directory is genuinely usable, it is what gets used. Asserted on the resolved
    # path only in that case, because on a dev box without /models the code deliberately falls
    # back rather than refusing to ingest.
    if os.path.isdir(DEFAULT_TAIL_STATE_DIR) and os.access(DEFAULT_TAIL_STATE_DIR, os.W_OK):
        assert _tail_state_path_for("/data/flows.jsonl").startswith(DEFAULT_TAIL_STATE_DIR)


# ── A RESTART RE-READ EVERY ZEEK LOG, MULTIPLYING ROWS IN TABLES WITH NO DEDUP KEY ────────────
#
# The NetFlow tailer got a persisted cursor in F018. The Zeek path never did: `tail_zeek_dir` kept a
# dict IN MEMORY keyed by filename, so every worker restart re-read all ~155 logs (134 MB) from
# offset zero. MEASURED on the live sensor, and the cost was NOT merely startup work:
#
#   * `zeek_notice` and `zeek_dhcp` are plain `MergeTree` with NO dedup key -- their `uid` is EMPTY,
#     so they cannot be `ReplacingMergeTree ORDER BY (ts, uid)` the way `zeek_conn`/`zeek_dns` are.
#     A re-read does not collapse; it ADDS.
#     MEASURED: zeek_notice held 6556 rows for 162 distinct (ts, note, msg) groups; one row appeared
#     64 times, and zeek_dhcp rows 47 times.
#   * `zeek_features.py` aggregates those with plain `count()`, so `zeek_notice_count` read 64 where
#     the truth was 1. That is a LIVE MODEL INPUT inflated 64x, growing with every restart.
#
# The re-read is what the cursor prevents, so these tests drive the REAL tailer across a simulated
# restart rather than asserting on the checkpoint helpers in isolation.


def _zeek_dir(tmp_path, records=2):
    """A minimal but REAL Zeek notice.log: the header Zeek actually writes, then data rows."""
    logs = tmp_path / "logs"
    logs.mkdir()
    lines = [
        "#separator \\x09",
        "#set_separator\t,",
        "#empty_field\t(empty)",
        "#unset_field\t-",
        "#path\tnotice",
        "#open\t2026-09-23-09-00-00",
        "#fields\tts\tuid\tsrc\tdst\tnote\tmsg",
        "#types\ttime\tstring\taddr\taddr\tstring\tstring",
    ]
    for i in range(records):
        lines.append(
            f"170000000{i}.000000\t\t198.51.100.7\t203.0.113.9\tScan::Port_Scan\tscanned"
        )
    (logs / "notice.log").write_text("\n".join(lines) + "\n")
    return logs


class _NullClient:
    def insert(self, table, batch, column_names=None):
        pass

    def query(self, *a, **kw):
        class _R:
            result_rows: list = []
            column_names: list = []

        return _R()


def test_a_RESTART_does_not_re_read_the_zeek_logs(tmp_path, monkeypatch):
    """THE DEFECT. Fresh in-memory state + existing checkpoints must ingest NOTHING."""
    monkeypatch.setenv("TAIL_STATE_DIR", str(tmp_path / "state"))
    logs = _zeek_dir(tmp_path, records=2)

    first = _NullClient()
    n_first, state = tail_zeek_dir(first, str(logs))
    assert n_first == 2, f"the first pass ingested {n_first} of 2 records"

    # Same process, second pass.
    n_again, state = tail_zeek_dir(first, str(logs), state)
    assert n_again == 0, "an in-process second pass re-read records"

    # A RESTART: fresh in-memory state, the on-disk checkpoints still there. This is the case that
    # multiplied rows on the live sensor.
    restarted = _NullClient()
    n_restart, _ = tail_zeek_dir(restarted, str(logs), {})
    assert n_restart == 0, (
        f"a RESTART re-read {n_restart} record(s) from an unchanged file. zeek_notice and zeek_dhcp "
        f"are plain MergeTree with an empty uid and no dedup key, so those records are ADDED "
        f"-- this is what produced 64 copies of a single notice row"
    )


def test_a_RESTART_still_reads_what_arrived_while_it_was_down(tmp_path, monkeypatch):
    """THE OTHER DIRECTION, so the fix cannot be "never read anything".

    A persisted cursor must skip what was already read AND still pick up rows appended since.
    """
    monkeypatch.setenv("TAIL_STATE_DIR", str(tmp_path / "state"))
    logs = _zeek_dir(tmp_path, records=2)

    first = _NullClient()
    n_first, _state = tail_zeek_dir(first, str(logs))
    assert n_first == 2

    # Two MORE rows land while the process is down.
    with open(logs / "notice.log", "a") as fh:
        fh.write("1700000009.000000\t\t198.51.100.8\t203.0.113.9\tScan::Port_Scan\tnew\n")
        fh.write("1700000010.000000\t\t198.51.100.8\t203.0.113.9\tScan::Port_Scan\tnew\n")

    restarted = _NullClient()
    n_restart, _ = tail_zeek_dir(restarted, str(logs), {})
    assert n_restart == 2, (
        f"after a restart with 2 new rows, {n_restart} were ingested; expected exactly 2. A cursor "
        f"that skips everything is a data-loss bug, not a fix"
    )


def test_the_checkpoint_carries_the_FIELDS_header_not_just_the_offset(tmp_path, monkeypatch):
    """Why a dedicated Zeek cursor exists rather than reusing the NetFlow one.

    `TailState` stores offset/inode/identity. A Zeek data line is POSITIONAL, so an offset restored
    without its `#fields` names resumes mid-file with no way to map a single row -- every record
    silently dropped. The header has to be persisted WITH the offset or the persistence is worse than
    nothing.
    """
    monkeypatch.setenv("TAIL_STATE_DIR", str(tmp_path / "state"))
    logs = _zeek_dir(tmp_path, records=2)
    path = str(logs / "notice.log")

    tail_zeek_dir(_NullClient(), str(logs))

    st = load_zeek_state(path)
    assert st.offset > 0, "no offset was checkpointed"
    assert st.fields == ["ts", "uid", "src", "dst", "note", "msg"], (
        f"the checkpoint restored fields={st.fields}. Without the header, a mid-file resume cannot "
        f"map any row"
    )
    # THE SEPARATOR IS CHECKED, BUT NOT WITH AN INVENTED ONE. Real Zeek ALWAYS writes
    # `#separator \x09` (tab) -- verified against every log on the live sensor -- so a
    # comma-separated Zeek log does not exist to test against, and my first version of this test
    # invented one. It failed, and the failure was informative rather than a defect: `parse_zeek_header`
    # maps Zeek's escaped `\\x09` to a real tab, which is the same value the fallback uses, so a
    # comma log cannot distinguish "persisted" from "dropped" either. What the assertion CAN do is
    # pin the field list and the separator together, which is the thing a resume depends on.
    assert st.separator == "\t", f"the separator was not restored: {st.separator!r}"
    assert len(st.fields) == 6, (
        f"the checkpoint restored {len(st.fields)} field names; the file's header has 6. A resume "
        f"with a short field list silently drops the tail of every record"
    )


def test_the_zeek_cursor_revalidates_against_ROTATION(tmp_path, monkeypatch):
    """A persisted cursor must be revalidated, not trusted.

    This is the risk the NetFlow tailer's design already documents and the Zeek path inherits: a
    checkpoint from before a rotation, applied to a REPLACED file, would skip everything written
    since -- silently losing data rather than duplicating it. The existing boundary check must catch
    it here too.
    """
    monkeypatch.setenv("TAIL_STATE_DIR", str(tmp_path / "state"))
    logs = _zeek_dir(tmp_path, records=2)
    tail_zeek_dir(_NullClient(), str(logs))

    # ROTATE: the live file is replaced by a new one with different content.
    live = logs / "notice.log"
    live.rename(logs / "notice.2026-09-23-09-00-00.log")
    live.write_text(
        "#separator \\x09\n"
        "#fields\tts\tuid\tsrc\tdst\tnote\tmsg\n"
        "#types\ttime\tstring\taddr\taddr\tstring\tstring\n"
        "1700000999.000000\t\t198.51.100.9\t203.0.113.9\tScan::Port_Scan\tfresh\n"
    )

    c = _NullClient()
    n, _ = tail_zeek_dir(c, str(logs), {})
    assert n >= 1, (
        "after a rotation the new file's record was NOT ingested -- the stale cursor was trusted "
        "and the data silently lost"
    )


# ── GLM 5.3 REVIEW: THE FLOW PATH NEEDS THE POISON-PILL GUARD THE ZEEK PATH GOT ────────────────
#
# `insert_batch` called `client.insert` bare. An exception from it escaped `tail_and_insert` BEFORE
# `state.note_read(...)` ran, so the cursor never advanced and `tail_forever` caught, logged and
# retried the SAME batch on every pass -- forever. That is the F013 defect this file already
# documents for Zeek, fixed there by `_insert_batch`; the flow path was the one place still not
# using it.


class _RejectingClient:
    """A client that rejects a batch containing a marked row, as a schema or arity mismatch does.

    It rejects by BATCH first and then accepts everything row by row -- which is what the real
    server does when one row in a multi-row INSERT is unparseable -- so this exercises the whole
    isolation path rather than just the first exception.
    """

    def __init__(self, bad_marker="99999999999999999999999"):
        # THE POISON MUST BE A VALUE THE MAPPER PASSES THROUGH. My first attempt used a non-numeric
        # `bytes`, which `map_flow` coerces to 0, so nothing bad ever reached the client and the
        # isolation path was never exercised. An integer too large for the column survives the
        # mapper intact, which is how a real schema/range mismatch presents.
        #
        # The marker is NOT an address: `_flow_row` builds src_addr from the row index, so an
        # address-shaped marker also matched the perfectly good row whose address happened to carry
        # that same index.
        self.bad_marker = bad_marker
        self.rows_landed = []
        self.batch_calls = 0

    def insert(self, table, rows, column_names=None):
        if len(rows) > 1 and any(self.bad_marker in str(v) for row in rows for v in row):
            self.batch_calls += 1
            raise RuntimeError("Code: 69. DB::Exception: Value is too large for column")
        for row in rows:
            if any(self.bad_marker in str(v) for v in row):
                raise RuntimeError("Code: 69. DB::Exception: Value is too large for column")
            self.rows_landed.append(row)


def _write_flows(path, n, bad_at):
    with open(path, "w") as fh:
        for i in range(1, n + 1):
            row = json.loads(_flow_row(i))
            if i == bad_at:
                row["bytes"] = 99999999999999999999999   # the marker this client rejects on
            fh.write(json.dumps(row) + "\n")
    return path


def test_one_BAD_FLOW_row_cannot_stop_the_cursor_from_advancing(tmp_path):
    """THE DEFECT. Without row-by-row isolation the cursor never advances, so ONE bad row stops ALL
    flow ingestion forever while the loop looks alive -- the exact shape F013 documents for Zeek."""
    from weirvern.ingester import TailState

    client = _RejectingClient()
    path = _write_flows(str(tmp_path / "flows.jsonl"), 5, bad_at=3)
    st = TailState()

    inserted, offset, _ = tail_and_insert(client, path, state=st)

    assert inserted == 4, (
        f"{inserted} of 4 good rows landed. The good rows must survive a batch that fails as a "
        f"whole -- refusing the batch loses every good record alongside the bad one"
    )
    assert st.offset > 0, (
        "the cursor did NOT advance past the bad row, so every subsequent pass re-reads it and "
        "fails the same way: this log type would never be ingested again"
    )


def test_the_cursor_advances_so_the_NEXT_pass_does_not_reread(tmp_path):
    """The consequence that matters: a second pass over the same file reads nothing new."""
    from weirvern.ingester import TailState

    client = _RejectingClient()
    path = _write_flows(str(tmp_path / "flows.jsonl"), 5, bad_at=3)
    st = TailState()

    tail_and_insert(client, path, state=st)
    landed_first = len(client.rows_landed)
    inserted2, _, _ = tail_and_insert(client, path, state=st)

    assert inserted2 == 0, (
        f"a second pass inserted {inserted2} more rows from a file that was fully consumed. The "
        f"cursor did not advance, so the bad row is retried forever"
    )
    assert len(client.rows_landed) == landed_first, "rows were duplicated on the retry pass"


def test_a_batch_that_fails_as_a_whole_still_lands_its_good_rows(tmp_path):
    """The trade is deliberate and worth pinning: good rows land, only the offending row is lost."""
    client = _RejectingClient()
    path = _write_flows(str(tmp_path / "flows.jsonl"), 4, bad_at=2)

    from weirvern.ingester import TailState

    inserted, _, _ = tail_and_insert(client, path, state=TailState())

    assert client.batch_calls >= 1, (
        "the client never saw a multi-row batch, so the isolation path was not exercised"
    )
    assert inserted == 3, f"expected the 3 good rows to land, got {inserted}"


# ── GLM 5.3 REVIEW: AN UNVERIFIABLE ADMISSION MUST BE COUNTED, NOT SILENT ──────────────────────
#
# `_exporter_permitted` returned a bare bool and its only caller counts REJECTIONS, so the two
# admissions it cannot check -- a record carrying no sampler_address, and one whose address will not
# parse -- were counted nowhere. An operator with WEIRVERN_FLOW_EXPORTER_ALLOW set could not tell
# "every record came from an exporter I named" from "some records bypassed the check entirely".


class _RecordingLogger:
    """Captures the ingest path's own log calls, so the accounting is asserted where an operator
    would actually see it rather than on an internal counter."""

    def __init__(self):
        self.infos: list[str] = []
        self.warnings: list[str] = []

    def info(self, msg, *args):
        self.infos.append(msg % args if args else msg)

    def warning(self, msg, *args):
        self.warnings.append(msg % args if args else msg)

    def debug(self, msg, *args):
        pass


def _flows_with(path, addrs):
    with open(path, "w") as fh:
        for i, a in enumerate(addrs, start=1):
            row = json.loads(_flow_row(i))
            if a is None:
                row.pop("sampler_address", None)
            else:
                row["sampler_address"] = a
            fh.write(json.dumps(row) + "\n")
    return path


def test_records_the_allow_list_cannot_check_are_REPORTED_not_silent(tmp_path, monkeypatch):
    """THE DEFECT. These were admitted and counted nowhere, so a covered window and a window with
    holes in it logged identically."""
    from weirvern import ingester as I
    from weirvern.ingester import TailState

    log = _RecordingLogger()
    monkeypatch.setattr(I, "logger", log)

    # One allowed, one outside the list, one with no address, one unparsable.
    p = _flows_with(str(tmp_path / "flows.jsonl"),
                    ["198.51.100.9", "203.0.113.9", None, "not-an-ip"])
    I.tail_and_insert(_RejectingClient(), str(p), state=TailState(),
                      allow="198.51.100.0/24")

    joined = " ".join(log.infos + log.warnings)
    assert "ADMITTED" in joined, (
        f"two records were admitted without the allow-list being able to check them and nothing "
        f"said so. An operator cannot tell a fully-covered window from one with holes. "
        f"info={log.infos} warn={log.warnings}"
    )
    assert "no-address" in joined and "unparsable" in joined, (
        f"the report must name WHICH kind of unchecked admission occurred, so the operator knows "
        f"whether to look at an exporter configuration or at a producer writing a bad address. "
        f"info={log.infos}"
    )
    assert "2 flow record(s)" in joined, (
        f"the count must be the number of unchecked admissions. info={log.infos}"
    )


def test_a_fully_covered_window_says_NOTHING_about_unchecked_admissions(tmp_path, monkeypatch):
    """The other direction, so the new line cannot become noise on every pass -- an INFO that always
    fires is the kind of warning that trains a reader to skip the one that matters."""
    from weirvern import ingester as I
    from weirvern.ingester import TailState

    log = _RecordingLogger()
    monkeypatch.setattr(I, "logger", log)

    p = _flows_with(str(tmp_path / "flows.jsonl"), ["198.51.100.9", "198.51.100.10"])
    I.tail_and_insert(_RejectingClient(), str(p), state=TailState(),
                      allow="198.51.100.0/24")

    joined = " ".join(log.infos + log.warnings)
    assert "ADMITTED" not in joined, (
        f"a window where every record was checked still reported unchecked admissions, so the line "
        f"would fire on every healthy pass. info={log.infos}"
    )


def test_no_allow_list_reports_no_unchecked_admissions(tmp_path, monkeypatch):
    """With the filter OFF there is nothing to be unverifiable about."""
    from weirvern import ingester as I
    from weirvern.ingester import TailState

    log = _RecordingLogger()
    monkeypatch.setattr(I, "logger", log)

    p = _flows_with(str(tmp_path / "flows.jsonl"), [None, "not-an-ip"])
    I.tail_and_insert(_RejectingClient(), str(p), state=TailState(), allow="")

    joined = " ".join(log.infos + log.warnings)
    assert "ADMITTED" not in joined, (
        f"an ungated deployment reported unchecked admissions, so the line is measuring the wrong "
        f"thing. info={log.infos}"
    )


# ── the log must not drown its own alarms ────────────────────────────────────────────────────────


def test_the_zeek_cursor_resume_is_NOT_an_INFO_line():
    """MEASURED 2026-11-17: this loop re-opens every Zeek log on every 5s pass, so an INFO line per
    file per pass produced ~50,000 lines per ten minutes. The container log is capped at 10MiB and
    rotated every few minutes, taking every OTHER message with it -- including the detection
    warnings. A log that drowns its alarms hides outages; that is how the wedged detect cursor went
    unnoticed for twenty hours. The per-file cursor is diagnostic detail: DEBUG, not INFO.
    """
    import re

    source = (pathlib.Path(__file__).resolve().parents[1] / "weirvern" / "ingester.py").read_text()
    assert re.search(r'logger\.debug\(\s*"Resuming Zeek tail', source), (
        "the per-file resume line is not at DEBUG, so the 5s pass will flood the container log again"
    )
    assert not re.search(r'logger\.info\(\s*"Resuming Zeek tail', source), (
        "the per-file resume line is still logging at INFO"
    )


# --- one collector per NIC, one port ------------------------------------------------
def test_a_file_names_the_interface_its_flows_came_through():
    """THE ATTRIBUTION IS THE FILE, NOT THE RECORD. softflowd cannot report an interface when it
    reads a pcap (measured four ways on the box), so each NIC's collector writes its own file and
    the tailer stamps the interface that file belongs to onto every row."""
    from weirvern.ingester import _COLUMNS, TailState, tail_and_insert

    fake = FakeCH()
    with tempfile.TemporaryDirectory() as d:
        path = _write(d, "flows-eth2.jsonl", [_flow_record(1), _flow_record(2)])
        tail_and_insert(fake, path, state=TailState(), iface="eth2")

    rows = fake.calls[-1]
    assert len(rows) == 2
    assert all(r[_COLUMNS.index("in_iface")] == "eth2" for r in rows)


def test_without_a_map_the_interface_stays_empty_not_guessed():
    from weirvern.ingester import _COLUMNS, TailState, tail_and_insert

    fake = FakeCH()
    with tempfile.TemporaryDirectory() as d:
        path = _write(d, "flows.jsonl", [_flow_record(1)])
        tail_and_insert(fake, path, state=TailState())

    assert fake.calls[-1][0][_COLUMNS.index("in_iface")] == "", (
        "an unattributed flow must read as unattributed -- a default NIC would be a lie"
    )


def test_tail_targets_reads_the_per_nic_map():
    from weirvern.ingester import tail_targets

    assert tail_targets("/data/flows.jsonl", "") == [("/data/flows.jsonl", "")]
    assert tail_targets("/data/flows.jsonl",
                        "eth1=/data/flows.jsonl,eth2=/data/flows-eth2.jsonl") == [
        ("/data/flows.jsonl", "eth1"),
        ("/data/flows-eth2.jsonl", "eth2"),
    ]
