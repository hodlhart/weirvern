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
        "src_addr": "192.168.3.10",
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
