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
