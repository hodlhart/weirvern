"""Rotation enforcement: prune rotated Zeek logs to a byte cap.

THE PROBLEM, measured: Zeek rotates hourly and deletes NOTHING. The test deployment
reached 87 rotated files / 11 MB in a few hours of light traffic, growing ~7 MB/hour,
on a 40 GB disk. On a busier network `dns.log` alone ran 2.3 MB/hour. Zeek's rotation is
bounded in TIME and unbounded in SPACE, so a sensor eventually fills its disk and stops
capturing — and a full disk takes ClickHouse down with it, presenting as a database
fault rather than a capacity one.

WHY ZEEK CANNOT DO THIS ITSELF: `Log::default_rotation_interval` sets how often to
rotate, and there is no built-in size cap or retention count for the default log set.
Pruning has to be an external actor, which is why this module exists.

WHERE IT RUNS: inside the Zeek container, which is the only workload that mounts the log
directory writable. The worker mounts it READ-ONLY on purpose — an ingester should not be
able to mutate the logs it is reading — so pruning does not belong there.

THE ORDERING RULE THAT MATTERS MOST: never delete a file that has not been ingested.
Deleting a log the worker has not read yet loses data permanently and invisibly, which is
worse than the disk filling up (that at least fails loudly). So pruning only considers
files older than a grace period, and the grace period is derived from the ingest cadence
rather than guessed.
"""
from __future__ import annotations

import logging
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

# A rotated Zeek log is `<type>.<YYYY-MM-DD-HH-MM-SS>.log`, optionally gzipped
# (`....log.gz`) -- the shipped sensor writes uncompressed, but a deployment that turns on
# compression must not silently escape the cap, so both shapes are pruned. The CURRENT file
# is `<type>.log` with no timestamp, and must never be deleted — it is being written to.
#
# The timestamp is parsed rather than trusting mtime, for the same reason the tailer
# sorts by the embedded timestamp: a directory copy or restore preserves names and not
# mtimes, so mtime-based ordering silently becomes wrong after a backup round trip.
ROTATED_RE = re.compile(
    r"^(?P<type>[A-Za-z_]+)\.(?P<ts>\d{4}-\d{2}-\d{2}-\d{2}-\d{2}-\d{2})\.log(?:\.gz)?$")

# Never prune these, whatever the cap says:
#   * loaded_scripts / reporter / stats are tiny and diagnostically useful
#   * communication.log and the like are what an operator reads to debug Zeek itself
#   * capture_loss is the ONLY signal that the sensor is dropping packets, and it is
#     tiny; deleting it would hide a problem rather than free space
NEVER_PRUNE = {
    "capture_loss", "loaded_scripts", "reporter", "stats", "packet_filter",
    "communication", "weird",  # kept: low volume, high signal, and the tables are small
}

# The ingest cadence plus slack. A file is only eligible once the worker has had more
# than enough time to read it. Derived from DETECT_INTERVAL_S's default (300s) with a
# generous multiple, because the cost of waiting is a little disk and the cost of not
# waiting is silent, permanent data loss.
DEFAULT_GRACE_S = 3600


@dataclass
class PruneCandidate:
    path: Path
    size_bytes: int
    log_type: str
    mtime: float
    age_s: float = 0.0
    """Age derived from the TIMESTAMP IN THE FILENAME.

    Deliberately not from mtime. Ordering already uses the name because a copy or restore
    preserves names and not mtimes; using mtime for the grace period made the two
    disagree, and the failure is silent and bad: after a restore every file has a fresh
    mtime, looks "recent", and is therefore never pruned -- so the cap stops being
    enforced exactly when the directory is largest.
    """


@dataclass
class PruneResult:
    """What a prune pass did, so it can be reported rather than merely performed."""

    kept_bytes: int = 0
    deleted_files: int = 0
    deleted_bytes: int = 0
    skipped_current: int = 0
    skipped_protected: int = 0
    skipped_recent: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def deleted_mb(self) -> float:
        return self.deleted_bytes / 1024 / 1024


def rotated_files(log_dir: Path) -> list[PruneCandidate]:
    """Every rotated log, newest first by the timestamp IN ITS NAME.

    Sorted by name-embedded time rather than mtime so the ordering survives a copy or
    restore. A file whose name does not match the rotation pattern is skipped entirely:
    better to leave an unrecognised file than to delete the wrong one.

    RECURSIVE, because Zeek in per-interface mode writes `conn.<ts>.log` inside `eth1/` and
    `eth2/`, not at the top level. Walking only `log_dir.iterdir()` measured 1.39 GB against a
    2 GB cap while ~3 GB sat in those subdirectories, unbounded and invisible -- the cap
    reported "within budget" the whole time. A cap that cannot see a file cannot prune it.
    """
    out: list[PruneCandidate] = []
    if not log_dir.is_dir():
        return out
    for entry in log_dir.rglob("*"):
        if not entry.is_file() or entry.is_symlink():
            continue
        m = ROTATED_RE.match(entry.name)
        if not m:
            continue
        try:
            st = entry.stat()
        except OSError:
            continue
        # Age from the name-embedded timestamp; mtime is kept only for reporting.
        age = 0.0
        try:
            when = time.mktime(time.strptime(m.group("ts"), "%Y-%m-%d-%H-%M-%S"))
            age = max(0.0, time.time() - when)
        except (ValueError, OverflowError):
            # An unparseable name is treated as infinitely old, so it becomes eligible
            # rather than protected forever. It matched ROTATED_RE, so it IS a rotated
            # log; refusing to ever prune it would be the silent-failure direction.
            age = float("inf")
        out.append(PruneCandidate(path=entry, size_bytes=st.st_size,
                                  log_type=m.group("type"), mtime=st.st_mtime, age_s=age))
    # Newest first: the timestamp sorts lexicographically because it is zero-padded.
    out.sort(key=lambda c: c.path.name, reverse=True)
    return out


def plan_prune(log_dir: Path, cap_mb: int, grace_s: int = DEFAULT_GRACE_S,
               now: float | None = None, per_type: bool = False) -> list[PruneCandidate]:
    """Decide which files to delete to fit within `cap_mb`. Deletes nothing.

    `per_type=False` (default) treats the cap as a budget for the WHOLE directory, which
    is what an operator means by "cap Zeek at 2 GB". With `per_type=True` each log type
    gets its own share, which prevents one noisy log (`dns`) from crowding out a quiet
    but important one (`ssl`, `ssh`).

    Grace period: files modified within `grace_s` are never candidates. This is the
    safeguard against deleting a log the worker has not ingested yet.
    """
    now = now if now is not None else time.time()
    # ── 0 MEANS "NO CAP", NOT "A ZERO-BYTE BUDGET" ────────────────────────────────────────────
    #
    # MEASURED DEFECT (audit F026). `config.py` documents the setting as `0 means "no cap" and is
    # reported as unset rather than as within budget`, and `0` is the DEFAULT for all three caps.
    # This function did `cap_bytes = max(0, cap_mb) * 1024 * 1024`, which turns 0 into a ZERO-BYTE
    # budget -- so every file is over it and the oldest-first loop deletes EVERYTHING past the
    # grace period. Reproduced: five rotated logs, `plan_prune(cap_mb=0)` returned ALL FIVE as
    # doomed while `cap_mb=1000` returned none.
    #
    # The live cluster is safe because `k8s/20-configmap-env.yaml` sets real caps (2048/1024/2048),
    # so this bites a deployment that takes the default -- which is exactly the case the default
    # is for, and the failure mode is silent log destruction rather than an error.
    #
    # An empty list is the right signal here AND it is also the correct answer for "nothing to
    # delete", which is deliberate: both cases mean DELETE NOTHING, and `prune` treats an empty
    # plan as a no-op either way. The distinction that matters is not between those two -- it is
    # between "no cap" and "a zero-byte cap", and conflating THOSE is the defect.
    if cap_mb <= 0:
        return []

    cap_bytes = cap_mb * 1024 * 1024
    candidates = rotated_files(log_dir)

    # Newest first; everything is initially "keep".
    keep: list[PruneCandidate] = []
    doomed: list[PruneCandidate] = []
    total = 0

    if per_type:
        # Group by type, giving each an equal share of the cap. Simpler than weighting
        # by observed volume, and predictable: an operator can reason about "each log
        # type gets cap/N".
        groups: dict[str, list[PruneCandidate]] = {}
        for c in candidates:
            groups.setdefault(c.log_type, []).append(c)
        share = cap_bytes / max(1, len(groups))
        for _t, items in groups.items():
            running = 0
            for c in items:                      # already newest-first
                recent = c.age_s < grace_s
                if running + c.size_bytes <= share or recent:
                    keep.append(c)
                    running += c.size_bytes
                    total += c.size_bytes
                else:
                    doomed.append(c)
        return doomed

    for c in candidates:
        recent = c.age_s < grace_s
        if c.log_type in NEVER_PRUNE:
            keep.append(c)
            total += c.size_bytes
            continue
        if recent:
            keep.append(c)
            total += c.size_bytes
            continue
        if total + c.size_bytes <= cap_bytes:
            keep.append(c)
            total += c.size_bytes
        else:
            doomed.append(c)
    return doomed


def prune(log_dir: Path, cap_mb: int, grace_s: int = DEFAULT_GRACE_S,
          per_type: bool = False, dry_run: bool = False) -> PruneResult:
    """Delete rotated logs beyond the cap. Returns what happened.

    DELETES ONLY FILES THE PLAN NAMED. The plan is computed first and returned in full,
    so a caller can log exactly what is about to go before it goes — and so a bug in the
    selection logic is visible rather than silent.
    """
    result = PruneResult()
    # Report what is being protected, so "the cap is set but nothing was deleted" is
    # distinguishable from "the cap is not being enforced".
    for c in rotated_files(log_dir):
        if c.log_type in NEVER_PRUNE:
            result.skipped_protected += 1
        elif c.age_s < grace_s:
            result.skipped_recent += 1

    doomed = plan_prune(log_dir, cap_mb, grace_s=grace_s, per_type=per_type)
    for c in doomed:
        if dry_run:
            result.deleted_files += 1
            result.deleted_bytes += c.size_bytes
            continue
        try:
            os.unlink(c.path)
            result.deleted_files += 1
            result.deleted_bytes += c.size_bytes
        except OSError as exc:
            # A failure to delete is reported, never swallowed: silently failing to free
            # space is how a disk fills while the logs say everything is fine.
            msg = f"could not delete {c.path.name}: {exc}"
            logger.warning(msg)
            result.errors.append(msg)

    kept = sum(c.size_bytes for c in rotated_files(log_dir))
    result.kept_bytes = kept
    if result.deleted_files:
        logger.info("pruned %d rotated log(s), freed %.1f MB (cap %d MB)",
                    result.deleted_files, result.deleted_mb, cap_mb)
    return result


def total_bytes(log_dir: Path) -> int:
    """Size of the whole log directory tree, including the current files.

    Includes the live files because the CAP is about disk usage, and the current files
    occupy disk. A cap that ignored them would overshoot by however much the sensor is
    writing right now.

    RECURSIVE for the same reason as `rotated_files`: per-interface Zeek writes into
    `eth1/` and `eth2/`, and a top-level-only sum reports a fraction of the disk the
    sensor actually occupies.
    """
    total = 0
    if not log_dir.is_dir():
        return 0
    for entry in log_dir.rglob("*"):
        if entry.is_file():
            try:
                total += entry.stat().st_size
            except OSError:
                continue
    return total


def prune_loop(log_dir: Path, cap_mb: int, interval_s: int = 300,
               grace_s: int = DEFAULT_GRACE_S, stop=None, per_type: bool = False) -> None:
    """Prune every `interval_s` until `stop` is set. For the sensor container.

    Runs more often than the grace period so the directory never grows much past the cap
    between passes: with a 5-minute interval and a 1-hour grace, at most an hour of logs
    can accumulate beyond the cap.
    """
    while not (stop is not None and stop.is_set()):
        before = total_bytes(log_dir)
        # A ZERO OR NEGATIVE CAP MEANS "NO CAP" (see plan_prune), so this must not read as
        # `before > 0` -- which is true for any non-empty directory and would call prune() every
        # interval forever. prune() now returns early anyway, so the cost was a no-op, but a guard
        # that says the wrong thing is how the NEXT reader concludes the cap is enforced at zero.
        if cap_mb > 0 and before > cap_mb * 1024 * 1024:
            r = prune(log_dir, cap_mb, grace_s=grace_s, per_type=per_type)
            if r.errors:
                logger.warning("prune completed with %d error(s)", len(r.errors))
        # Sleep in short slices so a stop signal is honoured promptly rather than after
        # a full interval.
        deadline = time.time() + interval_s
        while time.time() < deadline:
            if stop is not None and stop.is_set():
                return
            time.sleep(min(1.0, deadline - time.time()))
