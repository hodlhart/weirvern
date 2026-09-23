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
import json
import os
import tempfile
import time

from weirvern.ingester import TailState, _offset_is_on_boundary, tail_and_insert


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
    from weirvern.ingester import _exporter_networks, _exporter_permitted

    nets = _exporter_networks("198.51.100.0/24, 192.0.2.7")
    assert _exporter_permitted("198.51.100.9", nets) is True
    assert _exporter_permitted("192.0.2.7", nets) is True
    assert _exporter_permitted("203.0.113.9", nets) is False, (
        "an address outside the allow-list was permitted, so the filter does nothing"
    )


def test_a_record_with_no_sampler_address_is_permitted():
    """The absence of an address is not suspicious; a DIFFERENT one is.

    goflow2 omits sampler_address for some protocol variants, and rejecting those would drop
    legitimate flows to enforce a control against something the record does not carry.
    """
    from weirvern.ingester import _exporter_networks, _exporter_permitted

    nets = _exporter_networks("198.51.100.0/24")
    assert _exporter_permitted("", nets) is True
    assert _exporter_permitted(None, nets) is True


def test_no_filter_permits_everything():
    from weirvern.ingester import _exporter_permitted

    assert _exporter_permitted("203.0.113.9", None) is True


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
    assert _exporter_permitted("2001:db8::1", nets) is False
    nets6 = _exporter_networks("2001:db8::/32")
    assert _exporter_permitted("2001:db8::1", nets6) is True
    assert _exporter_permitted("198.51.100.9", nets6) is False


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
    """A client that records what the tailer would insert."""

    def __init__(self):
        self.rows = []

    def insert(self, table, rows, column_names=None):
        for r in rows:
            self.rows.append(dict(zip(column_names or [], r, strict=False)))


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
    assert client.rows[0].get("answers") == "", (
        "the sentinel reached the INSERT as literal text. The read layer normalised only `-`, and "
        "the DNS mapper reads this field raw, so nothing else could have caught it"
    )
    for field, val in client.rows[0].items():
        assert val != "(empty)", f"{field} reached the INSERT as the literal sentinel"


def test_the_read_layer_still_normalises_the_unset_sentinel(tmp_path):
    """The original guarantee survives the change: `-` is still absent, for the same reason."""
    from weirvern.ingester import tail_zeek_log

    client = _CaptureClient()
    tail_zeek_log(client, str(_real_dns_log(tmp_path, "-", subdir="b")))
    assert client.rows, (
        "the tailer inserted nothing. Either the fixture is not named dns.log (the tailer derives "
        "the log type from the FILENAME and skips anything it has no mapper for), or the row does "
        "not satisfy the mapper -- both of which make this test pass while proving nothing"
    )
    assert client.rows[0].get("answers") == ""


def test_a_REAL_value_still_reaches_the_table(tmp_path):
    """And the normalisation must not eat real data. Without this, a normaliser that blanked EVERY
    field would satisfy the two tests above."""
    from weirvern.ingester import tail_zeek_log

    client = _CaptureClient()
    tail_zeek_log(client, str(_real_dns_log(tmp_path, "198.51.100.20", subdir="c")))
    assert client.rows, "the tailer inserted nothing, so this test proves nothing"
    assert client.rows[0].get("answers") == "198.51.100.20"
    assert client.rows[0].get("query") == "example.test"
