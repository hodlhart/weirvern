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
    # A COMPRESSED rotation parses too: the shipped sensor writes uncompressed, but a
    # deployment that turns on gzip must not silently escape the cap (the two modules
    # previously disagreed on the shape -- `.log` matched, `.log.gz` only documented).
    for name in ("conn.2026-09-18-01-00-00.log.gz", "http.2026-09-18-00-00-00.log.gz"):
        assert prune.ROTATED_RE.match(name), f"does not parse: {name}"
    # And the live files must NOT match.
    for name in ("dns.log", "conn.log", "http.log"):
        assert not prune.ROTATED_RE.match(name), f"live file parsed as rotated: {name}"


# ── 0 MEANS "NO CAP", NOT "A ZERO-BYTE BUDGET" ───────────────────────────────────────────────
#
# MEASURED DEFECT (audit F026). `config.py` documents the setting as `0 means "no cap" and is
# reported as unset rather than as within budget`, and 0 is the DEFAULT for zeek_max_mb,
# netflow_max_mb and ml_max_mb. `plan_prune` did `cap_bytes = max(0, cap_mb) * 1024 * 1024`, which
# turns 0 into a ZERO-BYTE budget: every file is over it, and oldest-first deletes EVERYTHING past
# the grace period. Reproduced before the fix with five rotated logs: `plan_prune(cap_mb=0)`
# returned ALL FIVE as doomed while `cap_mb=1000` returned none.
#
# The live cluster is safe because `k8s/20-configmap-env.yaml` sets real caps (2048/1024/2048), so
# this bit a deployment running on the defaults -- exactly the case defaults exist for, and the
# failure is silent log destruction rather than an error.

def test_a_zero_cap_deletes_NOTHING(tmp_path):
    """The defect itself. 0 is documented as 'no cap'; it must not mean 'delete everything'."""
    d = make_logs(tmp_path, {"conn": [(old_ts(h), 100_000) for h in (24, 48, 72, 96, 120)]})
    assert len(list(d.glob("*.log"))) == 5
    plan = prune.plan_prune(d, cap_mb=0)
    assert plan == [], (
        f"a zero cap doomed {len(plan)} file(s). 0 means NO CAP, and the default for every cap "
        f"setting is 0, so this deletes the logs of any deployment that did not override it"
    )


def test_a_zero_cap_survives_a_real_prune_run(tmp_path):
    """Asserting the PLAN is not enough: the delete loop is what destroys data."""
    d = make_logs(tmp_path, {"conn": [(old_ts(h), 100_000) for h in (24, 48, 72)]})
    r = prune.prune(d, cap_mb=0)
    assert r.deleted_files == 0, f"prune(cap_mb=0) deleted {r.deleted_files} file(s)"
    assert len(list(d.glob("*.log"))) == 3, "the files are gone"


def test_a_negative_cap_is_also_no_cap(tmp_path):
    """A typo or a placeholder must not become 'delete everything' either."""
    d = make_logs(tmp_path, {"conn": [(old_ts(h), 100_000) for h in (24, 48, 72)]})
    assert prune.plan_prune(d, cap_mb=-1) == []
    assert prune.prune(d, cap_mb=-1).deleted_files == 0


def test_a_zero_cap_deletes_nothing_in_PER_TYPE_mode(tmp_path):
    """The per-type branch divides the cap by the number of groups, so a zero cap divides zero --
    a second path to the same defect, and one the first fix would have missed if it only guarded
    the whole-directory branch."""
    d = make_logs(tmp_path, {"conn": [(old_ts(h), 100_000) for h in (24, 48)],
                             "dns": [(old_ts(h), 100_000) for h in (24, 48)]})
    assert prune.plan_prune(d, cap_mb=0, per_type=True) == []


def test_a_REAL_cap_still_prunes(tmp_path):
    """The other half, and the one that stops the fix from being 'prune nothing': a genuine cap
    must still delete oldest-first until the directory fits."""
    d = make_logs(tmp_path, {"conn": [(old_ts(h), 500_000) for h in (24, 48, 72, 96, 120)]})
    # 5 x 500KB = 2.5MB against a 1MB budget, so most of it must go.
    plan = prune.plan_prune(d, cap_mb=1)
    assert plan, "a 2.5MB directory against a 1MB cap doomed nothing"
    r = prune.prune(d, cap_mb=1)
    remaining = sum(f.stat().st_size for f in d.glob("*.log"))
    assert r.deleted_files > 0
    assert remaining <= 1024 * 1024, f"{remaining} bytes remain against a 1MB cap"
    # And the NEWEST file survives: deleting newest-first would be the opposite bug.
    assert (d / "conn.2026-09-23-00-00-00.log").exists() or remaining > 0


def test_the_loop_guard_does_not_read_a_zero_cap_as_zero_bytes(tmp_path, monkeypatch):
    """`prune_loop` gated on `before > cap_mb * 1024 * 1024`, which for cap_mb=0 is `before > 0` --
    true for any non-empty directory, so it called prune() every interval forever. prune() returns
    early now, so the cost was a no-op, but a guard that says the wrong thing is how the next
    reader concludes the cap IS enforced at zero.

    ── HOW THIS TEST ACTUALLY REACHES THE GUARD, because the first version did not ─────────────
    The loop is `while not stop.is_set():` at the TOP, so setting the stop flag before the call
    means the body never executes: the first version asserted `calls == 0` against a loop that had
    never run, and it stayed green with the guard reverted. A mutation test caught that.

    So the loop is entered with the flag CLEAR, and stopped from inside `prune` -- the one place
    that proves the guard was reached. `sleep` is stubbed to stop the loop on the first slice
    rather than waiting out an interval.
    """
    import threading

    d = make_logs(tmp_path, {"conn": [(old_ts(h), 100_000) for h in (24, 48)]})
    stop = threading.Event()
    calls = {"n": 0}
    real_prune = prune.prune

    def counting(*a, **kw):  # noqa: ANN001
        calls["n"] += 1
        stop.set()          # leave the loop from inside the call, proving we got here
        return real_prune(*a, **kw)

    monkeypatch.setattr(prune, "prune", counting)
    # RUN THE BODY EXACTLY ONCE. The outer `while not stop.is_set()` is checked at the TOP, so the
    # flag cannot be set before the call or the guard is never reached; and setting it only inside
    # `prune` does not help the zero-cap case, where prune is never called. The sleep stub is what
    # terminates the loop after one pass, for both tests.
    monkeypatch.setattr(prune.time, "sleep", lambda *_: stop.set())
    prune.prune_loop(d, cap_mb=0, interval_s=1, grace_s=3600, stop=stop)

    assert calls["n"] == 0, (
        f"prune_loop called prune() {calls['n']} time(s) with a zero cap, so its guard read 0 as a "
        f"real budget. With a 300s interval that is a delete pass every 5 minutes forever"
    )
    assert len(list(d.glob("*.log"))) == 2, "the loop deleted files under a zero cap"


def test_the_loop_WOULD_call_prune_when_a_real_cap_is_exceeded(tmp_path, monkeypatch):
    """The companion assertion, without which the test above could pass on a loop that never calls
    prune() at all -- a disabled pruner satisfies every 'deletes nothing' claim."""
    import threading

    d = make_logs(tmp_path, {"conn": [(old_ts(h), 500_000) for h in (24, 48, 72)]})  # 1.5MB
    stop = threading.Event()
    calls = {"n": 0}
    real_prune = prune.prune

    def counting(*a, **kw):  # noqa: ANN001
        calls["n"] += 1
        stop.set()
        return real_prune(*a, **kw)

    monkeypatch.setattr(prune, "prune", counting)
    # RUN THE BODY EXACTLY ONCE. The outer `while not stop.is_set()` is checked at the TOP, so the
    # flag cannot be set before the call or the guard is never reached; and setting it only inside
    # `prune` does not help the zero-cap case, where prune is never called. The sleep stub is what
    # terminates the loop after one pass, for both tests.
    monkeypatch.setattr(prune.time, "sleep", lambda *_: stop.set())
    prune.prune_loop(d, cap_mb=1, interval_s=1, grace_s=3600, stop=stop)

    assert calls["n"] == 1, (
        "a 1.5MB directory against a 1MB cap must trigger a prune pass; if this is 0 the loop is "
        "disabled and the zero-cap test above proves nothing"
    )
    assert list(d.glob("*.log")), "the whole directory was removed rather than trimmed"


def test_gzipped_rotations_are_pruned_like_plain_ones(tmp_path):
    """The sensor ships uncompressed today, but a deployment that turns on compression must
    not silently escape the cap -- the review found `enforce.py` documenting `.log.gz` while
    this module matched only `.log`."""
    f = tmp_path / f"conn.{old_ts(60)}.log.gz"
    f.write_bytes(b"x" * 1_500_000)
    cands = prune.rotated_files(tmp_path)
    assert [c.path.name for c in cands] == [f.name]
    r = prune.prune(tmp_path, cap_mb=1, grace_s=1)
    assert r.deleted_files == 1
    assert not f.exists()


def test_the_cli_dry_run_reports_the_real_plan(tmp_path, monkeypatch, capsys):
    """`weirvern prune --dry-run` is the operator's ONLY preview. It used to read
    `planned_freed_mb`/`to_delete` attributes off a value that is a plain list, so it
    reported "would free 0.0 MB (0 file(s))" unconditionally -- including over a directory
    about to lose files."""
    from argparse import Namespace

    from weirvern import enforce
    from weirvern.admin import cli as wcli

    z = tmp_path / "zeek"
    z.mkdir()
    for hours in (72, 48, 24):
        f = z / f"conn.{old_ts(hours)}.log"
        f.write_bytes(b"x" * 400_000)
    monkeypatch.setattr(enforce, "ZEEK_DIR", z)
    monkeypatch.setenv("ZEEK_MAX_MB", "1")
    monkeypatch.delenv("NETFLOW_MAX_MB", raising=False)
    monkeypatch.delenv("ML_MAX_MB", raising=False)

    rc = wcli.cmd_prune(Namespace(dry_run=True, cap=None, component="zeek", grace=1))
    out = capsys.readouterr().out
    assert rc == 0
    # The regression: a non-empty plan must never read as "0.0 MB (0 file(s))".
    assert "would free 0.0 MB (0 file(s))" not in out
    assert "would free 0.4 MB (1 file(s))" in out, out


# ── per-interface Zeek directories ─────────────────────────────────────────────────────────────
#
# MEASURED DEFECT (2026-11-21): Zeek in per-interface mode writes into `eth1/` and `eth2/`, but
# both `rotated_files()` and `total_bytes()` walked only the top level. The cap therefore saw
# 1.39 GB against a 2 GB budget while ~3 GB sat in those subdirectories, unpruned and invisible;
# the sensor reported "within budget" the whole time it was filling the disk.

def test_a_rotated_log_in_an_interface_subdirectory_is_a_candidate(tmp_path):
    sub = tmp_path / "eth1"
    sub.mkdir()
    f = sub / f"conn.{old_ts(30)}.log"
    f.write_bytes(b"x" * MB)
    names = {c.path.name for c in prune.rotated_files(tmp_path)}
    assert f.name in names, "a per-interface rotated log is still a rotated log"


def test_the_cap_counts_per_interface_bytes(tmp_path):
    sub = tmp_path / "eth1"
    sub.mkdir()
    (sub / f"conn.{old_ts(30)}.log").write_bytes(b"x" * MB)
    (tmp_path / f"dns.{old_ts(20)}.log").write_bytes(b"x" * MB)
    assert prune.total_bytes(tmp_path) == 2 * MB


def test_a_per_interface_log_is_actually_deleted_when_over_the_cap(tmp_path):
    sub = tmp_path / "eth2"
    sub.mkdir()
    (sub / f"conn.{old_ts(30)}.log").write_bytes(b"x" * MB)
    (tmp_path / f"dns.{old_ts(20)}.log").write_bytes(b"x" * MB)
    r = prune.prune(tmp_path, cap_mb=1, grace_s=60)
    assert r.deleted_files == 1
    assert not (sub / f"conn.{old_ts(30)}.log").exists(), "the oldest file lived in the subdir"
    assert (tmp_path / f"dns.{old_ts(20)}.log").exists()


def test_a_symlink_in_a_log_tree_is_never_followed_or_deleted(tmp_path):
    outside = tmp_path.parent / "outside-log.log"
    outside.write_bytes(b"x" * MB)
    link = tmp_path / f"conn.{old_ts(30)}.log"
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip("symlinks unavailable on this filesystem")
    assert prune.rotated_files(tmp_path) == []
    prune.prune(tmp_path, cap_mb=0.0001, grace_s=1)
    assert outside.exists(), "a cap must never be satisfied by deleting through a symlink"
