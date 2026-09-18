"""Tests for rotation enforcement.

The bug this prevents, measured: Zeek rotates hourly and deletes nothing, so the test
deployment reached 87 rotated files / 11 MB in a few hours on a 40 GB disk, growing
~7 MB/hour. Zeek's rotation is bounded in TIME and unbounded in SPACE, so the sensor
eventually fills its disk and stops capturing.

The tests that matter are about SAFETY of deletion, not about freeing space:
  * the CURRENT file (being written) must never be deleted
  * a rotated file that may not have been ingested must never be deleted
  * tiny diagnostic logs must survive, because deleting capture_loss HIDES a problem
    rather than making room
"""
from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from weirvern import prune


def make_logs(tmp_path: Path, spec: dict[str, list[tuple[str, int]]]) -> Path:
    """Create rotated logs. `spec` maps a log type to [(timestamp, size_bytes), ...].

    Timestamps are written into the FILENAME as Zeek does, because the module sorts by
    the name rather than by mtime.
    """
    for log_type, entries in spec.items():
        for ts, size in entries:
            (tmp_path / f"{log_type}.{ts}.log").write_bytes(b"x" * size)
    return tmp_path


# A FIXED clock for everything in this file.
#
# WHY: every test here compares a file's name-embedded timestamp against the current time,
# and `plan_prune` accepts a `now` parameter for exactly that reason -- but none of the 11
# call sites used it, so each read the wall clock. That makes the grace-period assertions
# depend on how long the test takes and on where the wall clock happens to sit when the
# fixture is built. A timestamp formatted to whole SECONDS from a `time.time()` that lands
# at a fractional second shifts by up to 1s between the name and the comparison, which is
# harmless against a 3600s grace but is the kind of drift that turns a tight assertion flaky
# for reasons nobody can reproduce later.
#
# A single frozen instant removes the whole class: names and comparisons derive from the same
# value, so the arithmetic is exact.
NOW = 1_800_000_000.0   # 2027-01-15 12:00:00 UTC, arbitrary but fixed


@pytest.fixture(autouse=True)
def _frozen_clock(monkeypatch):
    """Pin `time.time()` for every test in this module.

    `prune.py` reads the wall clock internally (both for a file's age and for `plan_prune`'s
    default `now`), and its own `now` parameter is not accepted by the deleting wrapper
    `prune()`. Patching the clock at the source covers every path uniformly, so a test cannot
    accidentally compare timestamps taken from two different instants -- which is what made
    the grace-period assertions depend on how long the suite happened to take.

    `time.localtime` and `strftime` are left alone: the fixtures format real calendar
    timestamps with them, and only the "what time is it now" answer needs to be pinned.
    """
    monkeypatch.setattr(prune.time, "time", lambda: NOW)
    yield


def old_ts(hours_ago: int) -> str:
    """A Zeek-style timestamp, sufficiently past the grace period."""
    return time.strftime("%Y-%m-%d-%H-%M-%S", time.localtime(NOW - (hours_ago * 3600)))


def recent_ts(minutes_ago: int) -> str:
    return time.strftime("%Y-%m-%d-%H-%M-%S", time.localtime(NOW - (minutes_ago * 60)))


MB = 1024 * 1024


# --- recognition --------------------------------------------------------------
def test_only_rotated_files_are_candidates(tmp_path):
    """The live `<type>.log` has no timestamp and is being appended to. Deleting it
    would destroy the sensor's active output, so it must not match."""
    (tmp_path / "dns.log").write_bytes(b"live")
    (tmp_path / "dns.2026-09-17-21-00-00.log").write_bytes(b"rotated")
    found = prune.rotated_files(tmp_path)
    names = {c.path.name for c in found}
    assert "dns.2026-09-17-21-00-00.log" in names
    assert "dns.log" not in names, "the live file must never be a prune candidate"


def test_unrecognised_files_are_left_alone(tmp_path):
    """Better to leave an unrecognised file than to delete the wrong one. An operator may
    have put something in the directory deliberately."""
    for name in ("notes.txt", "dns.log.bak", "weird.2026-09-17.log", "README"):
        (tmp_path / name).write_bytes(b"keep me")
    assert prune.rotated_files(tmp_path) == []


def test_candidates_are_ordered_newest_first(tmp_path):
    """Ordering decides what survives, and it comes from the NAME not the mtime: a
    directory copy preserves names and not mtimes, so mtime ordering silently becomes
    wrong after a backup round trip."""
    make_logs(tmp_path, {"dns": [
        ("2026-09-17-19-00-00", 10), ("2026-09-17-21-00-00", 10), ("2026-09-17-20-00-00", 10),
    ]})
    got = [c.path.name for c in prune.rotated_files(tmp_path)]
    assert got == [
        "dns.2026-09-17-21-00-00.log",
        "dns.2026-09-17-20-00-00.log",
        "dns.2026-09-17-19-00-00.log",
    ]


def test_ordering_ignores_mtime(tmp_path):
    """Directly: touch the OLDEST-named file so it has the newest mtime. Name order must
    still win, or a restore would make the newest data look oldest and delete it."""
    make_logs(tmp_path, {"dns": [("2026-09-17-19-00-00", 10), ("2026-09-17-21-00-00", 10)]})
    os.utime(tmp_path / "dns.2026-09-17-19-00-00.log", None)   # newest mtime
    oldest_named = time.time() - 7200
    os.utime(tmp_path / "dns.2026-09-17-21-00-00.log", (oldest_named, oldest_named))
    got = [c.path.name for c in prune.rotated_files(tmp_path)]
    assert got[0] == "dns.2026-09-17-21-00-00.log", (
        "ordering followed mtime, so a restore would cause the newest logs to be deleted"
    )


# --- the cap ------------------------------------------------------------------
def test_nothing_is_deleted_below_the_cap(tmp_path):
    make_logs(tmp_path, {"dns": [(old_ts(5), MB), (old_ts(4), MB)]})
    assert prune.plan_prune(tmp_path, cap_mb=10) == []


def test_oldest_files_are_deleted_first(tmp_path):
    """The newest data is the most valuable for an investigation, so it must survive."""
    make_logs(tmp_path, {"dns": [(old_ts(30), MB), (old_ts(20), MB), (old_ts(10), MB)]})
    doomed = prune.plan_prune(tmp_path, cap_mb=2, grace_s=60)
    names = {c.path.name for c in doomed}
    assert len(doomed) == 1, f"expected one file over a 2 MB cap, got {len(doomed)}"
    assert "oldest-is-kept" not in names
    # The deleted one must be the OLDEST (30 hours ago).
    assert doomed[0].path.name == f"dns.{old_ts(30)}.log"


def test_prune_actually_frees_space(tmp_path):
    make_logs(tmp_path, {"dns": [(old_ts(30), MB), (old_ts(20), MB), (old_ts(10), MB)]})
    before = sum(c.size_bytes for c in prune.rotated_files(tmp_path))
    r = prune.prune(tmp_path, cap_mb=2, grace_s=60)
    after = sum(c.size_bytes for c in prune.rotated_files(tmp_path))
    assert r.deleted_files == 1
    assert after < before
    assert r.deleted_bytes == MB


def test_the_cap_is_honoured_not_approximated(tmp_path):
    """Ten 1 MB files against a 3 MB cap must leave 3, not 4."""
    make_logs(tmp_path, {"dns": [(old_ts(50 - i), MB) for i in range(10)]})
    prune.prune(tmp_path, cap_mb=3, grace_s=60)
    remaining = prune.rotated_files(tmp_path)
    assert sum(c.size_bytes for c in remaining) <= 3 * MB
    assert len(remaining) == 3


def test_dry_run_reports_without_deleting(tmp_path):
    """`weirvern disk --prune --dry-run` must be able to say what WOULD go."""
    make_logs(tmp_path, {"dns": [(old_ts(30), MB), (old_ts(20), MB)]})
    r = prune.prune(tmp_path, cap_mb=1, grace_s=60, dry_run=True)
    assert r.deleted_files == 1
    assert len(prune.rotated_files(tmp_path)) == 2, "dry run deleted something"


# --- the safety rules ---------------------------------------------------------
def test_files_within_the_grace_period_are_never_deleted(tmp_path):
    """THE most important rule. A log the worker has not ingested yet is not stale data,
    it is UNREAD data — deleting it loses records permanently and invisibly, which is
    worse than a full disk, because a full disk at least fails loudly."""
    make_logs(tmp_path, {"dns": [(old_ts(30), 5 * MB), (recent_ts(2), 5 * MB)]})
    doomed = prune.plan_prune(tmp_path, cap_mb=1, grace_s=3600)
    names = {c.path.name for c in doomed}
    assert names == {f"dns.{old_ts(30)}.log"}, (
        f"a file inside the grace period was selected for deletion: {names}"
    )


def test_protected_diagnostics_are_never_deleted(tmp_path):
    """capture_loss is the ONLY signal that the sensor is dropping packets, and it is
    tiny. Deleting it would hide a real problem to free almost nothing."""
    make_logs(tmp_path, {
        "capture_loss": [(old_ts(30), MB)],
        "loaded_scripts": [(old_ts(30), MB)],
        "dns": [(old_ts(29), MB)],
    })
    doomed = prune.plan_prune(tmp_path, cap_mb=1, grace_s=60)
    types = {c.log_type for c in doomed}
    assert "capture_loss" not in types
    assert "loaded_scripts" not in types
    assert "dns" in types, "the ordinary log should still be pruned"


def test_every_protected_type_is_reportable(tmp_path):
    """The result must distinguish 'nothing needed deleting' from 'the cap is not
    enforced', or an operator cannot tell a healthy directory from a broken pruner."""
    make_logs(tmp_path, {"capture_loss": [(old_ts(30), MB)], "dns": [(recent_ts(1), MB)]})
    r = prune.prune(tmp_path, cap_mb=1, grace_s=3600)
    assert r.skipped_protected == 1
    assert r.skipped_recent == 1
    assert r.deleted_files == 0


def test_a_delete_failure_is_recorded_not_swallowed(tmp_path, monkeypatch):
    """Failing to free space while reporting success is how a disk fills up quietly."""
    make_logs(tmp_path, {"dns": [(old_ts(30), MB), (old_ts(20), MB)]})

    def boom(_path):
        raise OSError("simulated EACCES")

    monkeypatch.setattr(prune.os, "unlink", boom)
    r = prune.prune(tmp_path, cap_mb=1, grace_s=60)
    assert r.errors, "a failed unlink must be reported"
    assert "simulated EACCES" in r.errors[0]


# --- per-type mode ------------------------------------------------------------
def test_per_type_gives_each_log_its_own_share(tmp_path):
    """Prevents one noisy log (dns) crowding out a quiet but important one (ssh). Without
    this, a 4 MB cap shared by two types lets dns take everything and ssh gets pruned to
    nothing even though it is tiny."""
    make_logs(tmp_path, {
        "dns": [(old_ts(40), MB), (old_ts(39), MB), (old_ts(38), MB), (old_ts(37), MB)],
        "ssh": [(old_ts(36), 10_000)],
    })
    doomed = {c.log_type for c in prune.plan_prune(tmp_path, cap_mb=2, grace_s=60, per_type=True)}
    assert doomed == {"dns"}, f"ssh was pruned despite being tiny: {doomed}"


# --- totals -------------------------------------------------------------------
def test_total_bytes_counts_live_files_too(tmp_path):
    """The cap is about DISK USAGE, and the live files occupy disk. Ignoring them makes
    the cap overshoot by however much the sensor is writing right now."""
    (tmp_path / "dns.log").write_bytes(b"x" * 100)
    (tmp_path / "dns.2026-09-17-21-00-00.log").write_bytes(b"x" * 200)
    assert prune.total_bytes(tmp_path) == 300


def test_missing_directory_is_harmless(tmp_path):
    """The pruner runs in the sensor container, which may start before the directory is
    populated. It must not crash."""
    missing = tmp_path / "nope"
    assert prune.rotated_files(missing) == []
    assert prune.total_bytes(missing) == 0
    r = prune.prune(missing, cap_mb=10)
    assert r.deleted_files == 0


# --- the real naming on the deployment ----------------------------------------
def test_parses_the_real_zeek_rotation_names():
    """Taken from the rotated files on the test cluster, so the pattern matches what
    Zeek actually writes rather than what the docs imply."""
    real = [
        "dns.2026-09-17-21-00-00.log",
        "conn.2026-09-18-01-00-00.log",
        "capture_loss.2026-09-17-20-56-31.log",
        "loaded_scripts.2026-09-18-01-16-41.log",
        "http.2026-09-18-00-00-00.log",
    ]
    for name in real:
        assert prune.ROTATED_RE.match(name), f"does not parse: {name}"
    # And the live files must NOT match.
    for name in ("dns.log", "conn.log", "http.log"):
        assert not prune.ROTATED_RE.match(name), f"live file parsed as rotated: {name}"
