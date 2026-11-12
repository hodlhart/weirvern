"""Tests for disk-cap enforcement.

The bug these prevent: the caps were advisory. `weirvern disk` recommended values, the
config accepted them, and nothing acted on them -- so a cap that was set and a cap that
was ignored looked identical. These pin that a set cap actually frees space, and that the
destructive paths never corrupt the data they keep.
"""
from __future__ import annotations

import json
import os
import time
import tracemalloc
from pathlib import Path

import pytest

from weirvern import enforce


@pytest.fixture(autouse=True)
def _isolated_dirs(tmp_path, monkeypatch):
    """Point every component at a temp dir.

    Without this the tests would run against /zeek/logs and /models -- the real cluster
    paths -- and a test that "frees space" could delete the deployed models.
    """
    z = tmp_path / "zeek"
    n = tmp_path / "flows"
    m = tmp_path / "models"
    for d in (z, n, m):
        d.mkdir()
    monkeypatch.setattr(enforce, "ZEEK_DIR", z)
    monkeypatch.setattr(enforce, "NETFLOW_DIR", n)
    monkeypatch.setattr(enforce, "ML_DIR", m)
    return {"zeek": z, "netflow": n, "ml": m}


def _rotated(d: Path, log_type: str, when: str, size: int) -> Path:
    """A rotated Zeek log with an OLD filename but a FRESH mtime.

    That combination is the realistic one for a directory restored from backup, and it is
    what exposed the age-source bug: the module sorted by filename but measured the grace
    period by mtime, so every restored file looked "recent" and nothing was ever pruned.
    """
    f = d / f"{log_type}.{when}.log"
    f.write_bytes(b"x" * size)
    return f


# ── no cap means no action ──────────────────────────────────────────────────────


def test_no_cap_touches_nothing(_isolated_dirs):
    _rotated(_isolated_dirs["zeek"], "conn", "2020-01-01-00-00-00", 100_000)
    r = enforce.enforce_zeek(0)
    assert r.actions == 0
    assert r.skipped == "no cap set"
    assert list(_isolated_dirs["zeek"].iterdir()), "files were deleted without a cap"


def test_a_missing_directory_is_reported_not_crashed(monkeypatch, tmp_path):
    monkeypatch.setattr(enforce, "ZEEK_DIR", tmp_path / "nope")
    r = enforce.enforce_zeek(100)
    assert r.actions == 0
    assert "does not exist" in r.skipped


# ── zeek: the real path ─────────────────────────────────────────────────────────


def test_zeek_cap_actually_frees_space(_isolated_dirs):
    """The headline case: files over the cap, old enough, must go."""
    for hour in range(10):
        _rotated(_isolated_dirs["zeek"], "conn", f"2020-01-01-{hour:02d}-00-00", 200_000)
    r = enforce.enforce_zeek(1, grace_s=0)
    assert r.actions > 0, "a 2 MB directory under a 1 MB cap reclaimed nothing"
    assert r.after_mb < r.before_mb
    assert r.after_mb <= 1.05, f"still {r.after_mb:.2f} MB after a 1 MB cap"


def test_the_grace_period_protects_new_files_even_when_named_old(_isolated_dirs):
    """Grace must key off the FILENAME timestamp, not mtime.

    This is the regression: with name-based ordering and mtime-based grace, a directory
    whose files all have fresh mtimes (any restore) was never pruned at all.
    """
    # Named NOW, so inside the grace window.
    now = time.strftime("%Y-%m-%d-%H-%M-%S")
    _rotated(_isolated_dirs["zeek"], "conn", now, 500_000)
    r = enforce.enforce_zeek(0.1, grace_s=3600)
    assert r.actions == 0, "deleted a file inside the grace period"
    assert _isolated_dirs["zeek"].iterdir()


def test_age_comes_from_the_filename_not_the_mtime(_isolated_dirs):
    """A restored directory (old names, new mtimes) must still be prunable."""
    f = _rotated(_isolated_dirs["zeek"], "conn", "2020-01-01-00-00-00", 300_000)
    os.utime(f, None)  # fresh mtime, as a restore or a copy would give it
    from weirvern import prune
    cands = prune.rotated_files(_isolated_dirs["zeek"])
    assert cands and cands[0].age_s > 86_400, "age was taken from mtime, not the name"


# ── netflow: the destructive rewrite ────────────────────────────────────────────


def test_netflow_trim_leaves_only_parseable_json_lines(_isolated_dirs):
    """A byte offset that lands mid-line must not leave a truncated record.

    A half-written JSON object at the head of the file is worse than the space it saves:
    the ingester reports a parse error on every pass forever.
    """
    d = _isolated_dirs["netflow"]
    f = d / "flows.jsonl"
    rows = [json.dumps({"i": i, "pad": "p" * 80}) for i in range(400)]
    f.write_text("\n".join(rows) + "\n")

    r = enforce.enforce_netflow(0.02)  # far below the file size, so a real trim happens
    assert r.actions == 1
    assert r.after_mb < r.before_mb

    text = f.read_text()
    assert text, "the trim removed everything"
    for n, line in enumerate(text.splitlines()):
        if not line.strip():
            continue
        try:
            json.loads(line)
        except json.JSONDecodeError as exc:
            pytest.fail(f"line {n} is not valid JSON after the trim: {line[:60]!r} ({exc})")


def test_a_large_trim_streams_instead_of_reading_the_file_into_memory(_isolated_dirs):
    """The flow log reached 17.9 GB live; reading the remainder OOM-killed the prune job.

    A trim must move bytes in bounded chunks. tracemalloc is the cheap stand-in for a memory
    limit: the whole-file read this replaced allocated the remainder (tens of MB here), while
    a streamed copy holds one chunk at a time.
    """
    d = _isolated_dirs["netflow"]
    f = d / "flows.jsonl"
    row = json.dumps({"i": 0, "pad": "p" * 200}) + "\n"
    with open(f, "w") as fh:
        for i in range(120_000):
            fh.write(row.replace('"i": 0', f'"i": {i}'))

    tracemalloc.start()
    r = enforce.enforce_netflow(1.0)  # ~1 MB cap against a ~26 MB file
    _current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    assert r.actions == 1
    assert peak < 8 * 1024 * 1024, f"trim allocated {peak / 1048576:.1f} MB; it must stream"
    assert f.stat().st_size > 0
    assert json.loads(f.read_text().splitlines()[0])


def test_netflow_under_cap_is_untouched(_isolated_dirs):
    f = _isolated_dirs["netflow"] / "flows.jsonl"
    f.write_text('{"i": 1}\n')
    before = f.read_text()
    r = enforce.enforce_netflow(100)
    assert r.actions == 0
    assert f.read_text() == before


def test_netflow_whole_files_are_removed_when_older(_isolated_dirs):
    d = _isolated_dirs["netflow"]
    old = d / "old.jsonl"
    old.write_text("a" * 200_000)
    os.utime(old, (time.time() - 9999, time.time() - 9999))
    new = d / "new.jsonl"
    new.write_text("b" * 200_000)
    r = enforce.enforce_netflow(0.25)
    assert r.actions >= 1
    assert r.after_mb <= 0.26


# ── the reader protocol: a trim must never strand or destroy the tail cursor ─────────────────
#
# MEASURED DEFECT (review round 2026-10-15): the trim REPLACES the file (new inode), the
# ingester's reset detection fires, and its naive response re-read the whole file from zero.
# While over cap that happened EVERY FIVE MINUTES, re-inserting up to the full cap into
# `flows` -- a MergeTree with no deduplication. Two protocols fix it: never cut past the
# reader's checkpointed offset, and record each rewrite so the reader can SHIFT instead of
# re-reading. The trim-side is exercised here; the reader-side loop lives in test_ingester.py.


def _jsonl_bytes(count: int, pad: int = 80) -> bytes:
    out = b""
    for i in range(count):
        out += (json.dumps({"i": i, "pad": "p" * pad}) + "\n").encode()
    return out


def _cursor_at(path: Path, offset: int, inode: int) -> None:
    from weirvern.ingester import TailState, save_tail_state
    save_tail_state(str(path), TailState(offset=offset, inode=inode, identity=None))


def test_the_guard_reads_a_checkpoint_only_for_the_current_instance(_isolated_dirs,
                                                                    monkeypatch):
    d = _isolated_dirs["netflow"]
    f = d / "flows.jsonl"
    f.write_bytes(b'{"a": 1}\n{"b": 2}\n')
    monkeypatch.setenv("TAIL_STATE_DIR", str(d / "state"))
    _cursor_at(f, 9, f.stat().st_ino)
    assert enforce._reader_boundary(f, 18) == 9
    # A checkpoint from a PREVIOUS instance must not bound the trim: the reader is not
    # positioned in this file at all, so its offset says nothing about what is unread here.
    _cursor_at(f, 9, f.stat().st_ino + 1)
    assert enforce._reader_boundary(f, 18) is None


def test_a_trim_never_removes_bytes_the_reader_has_not_read(_isolated_dirs, monkeypatch):
    """The cut is capped at the reader's checkpoint: removing unread bytes would destroy
    records before anything saw them, and the cap is a ceiling, not a deadline -- waiting a
    cycle is always the better trade."""
    d = _isolated_dirs["netflow"]
    f = d / "flows.jsonl"
    data = _jsonl_bytes(200)
    f.write_bytes(data)
    reader_at = data.index(b"\n", len(data) // 4) + 1  # a real record boundary, ~25% in
    monkeypatch.setenv("TAIL_STATE_DIR", str(d / "state"))
    _cursor_at(f, reader_at, f.stat().st_ino)

    r = enforce.enforce_netflow(0.004)  # the cap demands a cut far past the reader's offset
    assert r.actions == 1
    # Nothing at or beyond the reader's offset was touched: the file now starts EXACTLY there.
    assert f.read_bytes() == data[reader_at:]
    # And the rewrite is recorded so the reader can shift by exactly that much.
    hint = json.loads((d / "flows.jsonl.trimhint").read_text())
    assert hint["chain"][-1]["removed"] == reader_at


def test_a_trim_below_the_cursor_frees_normally_and_chains(_isolated_dirs, monkeypatch):
    d = _isolated_dirs["netflow"]
    f = d / "flows.jsonl"
    data = _jsonl_bytes(200)
    f.write_bytes(data)
    monkeypatch.setenv("TAIL_STATE_DIR", str(d / "state"))
    _cursor_at(f, len(data), f.stat().st_ino)  # the reader is fully caught up
    old_inode = f.stat().st_ino

    r = enforce.enforce_netflow(0.004)
    assert r.actions == 1
    hint = json.loads((d / "flows.jsonl.trimhint").read_text())
    removed = hint["chain"][-1]["removed"]
    assert 0 < removed < len(data)
    assert f.read_bytes() == data[removed:]
    assert hint["chain"][-1]["from"] == old_inode

    # A second trim extends the chain (contiguous: from == previous to), so a reader that
    # was behind for TWO cycles can still follow it.
    _cursor_at(f, f.stat().st_size, f.stat().st_ino)
    r2 = enforce.enforce_netflow(0.001)
    assert r2.actions == 1
    chain = json.loads((d / "flows.jsonl.trimhint").read_text())["chain"]
    assert len(chain) == 2
    assert chain[1]["from"] == chain[0]["to"]


def test_ml_keeps_the_newest_sets_even_under_pressure(_isolated_dirs):
    """Deleting the model the worker is serving is an outage, not housekeeping."""
    d = _isolated_dirs["ml"]
    for i in range(5):
        sub = d / f"run{i}"
        sub.mkdir()
        (sub / "iso.joblib").write_bytes(b"x" * 100_000)
        # Ascending mtimes so run4 is newest.
        os.utime(sub, (time.time() + i, time.time() + i))
    r = enforce.enforce_ml(0.05, keep_newest=2)  # impossible cap
    assert r.actions >= 1
    remaining = sorted(p.name for p in d.iterdir())
    assert "run4" in remaining and "run3" in remaining, (
        f"the two newest sets must survive an unsatisfiable cap; have {remaining}")


def test_ml_below_the_floor_is_untouched(_isolated_dirs):
    d = _isolated_dirs["ml"]
    (d / "run0").mkdir()
    (d / "run0" / "m.joblib").write_bytes(b"x" * 10)
    r = enforce.enforce_ml(0, keep_newest=2)
    assert r.actions == 0
    assert (d / "run0").exists()


# ── the aggregate ───────────────────────────────────────────────────────────────


def test_one_component_failing_does_not_stop_the_others(monkeypatch, _isolated_dirs):
    """A broken ML path must not prevent Zeek from being pruned.

    If components were sequential without isolation, one exception would abort the run and
    the disk would fill from the direction nobody was watching.
    """
    for hour in range(6):
        _rotated(_isolated_dirs["zeek"], "conn", f"2020-01-01-{hour:02d}-00-00", 200_000)

    def boom(cap: int, keep_newest: int = 2):
        raise RuntimeError("simulated ML failure")

    monkeypatch.setattr(enforce, "enforce_ml", boom)
    results = enforce.enforce({"zeek": 1, "netflow": 0, "ml": 1}, grace_s=0)
    by = {r.component: r for r in results}
    assert by["zeek"].actions > 0, "zeek was skipped because ml raised"
    assert by["ml"].errors, "the ml failure was swallowed silently"


def test_render_reports_every_component(_isolated_dirs):
    out = enforce.render(enforce.enforce({"zeek": 0, "netflow": 0, "ml": 0}))
    for comp in ("zeek", "netflow", "ml"):
        assert comp in out


def test_a_component_with_no_cap_says_so_rather_than_claiming_success(_isolated_dirs):
    """"unset" and "within cap" must be distinguishable in the output.

    They look identical on a disk that happens to be under its limit, and only one of them
    means the cap will keep holding next month.
    """
    out = enforce.render([enforce.enforce_zeek(0)])
    assert "unset" in out


def test_a_trim_preserves_the_mode_the_writer_needs(_isolated_dirs):
    """Replacing the log creates a new inode; if the mode changes, the collector cannot append.

    Measured live 2026-11-12: the prune job (uid 10001) rewrote flows.jsonl as 644 while goflow2
    runs as uid 100, so the collector hit "permission denied" and NetFlow went dark.
    """
    d = _isolated_dirs["netflow"]
    f = d / "flows.jsonl"
    rows = "".join(json.dumps({"i": i, "pad": "p" * 120}) + "\n" for i in range(2000))
    f.write_text(rows)
    f.chmod(0o664)

    enforce.enforce_netflow(0.05)

    assert f.stat().st_size > 0
    assert f.stat().st_mode & 0o777 == 0o664, "the collector's write bit must survive the trim"


def test_a_trim_keeps_the_inode_the_collector_has_open(_isolated_dirs):
    """A rename swaps the inode under an open writer; its later records go to the unlinked file.

    Measured live 2026-11-12: flows stopped at 19:17:57, the visible log froze at the trim point,
    and the disk filled to 17.9 GB through a handle nothing could see.
    """
    d = _isolated_dirs["netflow"]
    f = d / "flows.jsonl"
    rows = "".join(json.dumps({"i": i, "pad": "p" * 120}) + "\n" for i in range(2000))
    f.write_text(rows)
    before = f.stat().st_ino

    enforce.enforce_netflow(0.05)

    assert f.stat().st_ino == before, "the collector's open handle must stay valid"
    assert f.stat().st_size > 0
