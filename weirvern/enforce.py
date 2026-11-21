"""Component disk-cap enforcement: one entrypoint, three components.

WHY A SINGLE COMMAND: the caps (`ZEEK_MAX_MB`, `NETFLOW_MAX_MB`, `ML_MAX_MB`) were
advisory -- `weirvern disk` recommended them and nothing enforced them. A recommendation
that nothing applies is worse than no recommendation, because it reads as handled. This
is the enforcement half: the CronJob and `weirvern prune` both call `enforce()`, so the
scheduled path and the manual path cannot diverge.

WHY THREE COMPONENTS HAVE DIFFERENT MECHANISMS:
  * zeek    -- rotated files `conn.2026-01-01-13-00-00.log`, or `.log.gz` if the sensor
               compresses a rotation. Deleted by age, under a byte cap. Zeek itself
               cannot cap by SIZE, only by rotation COUNT.
  * netflow -- the goflow2 JSONL sink, written continuously. Trimmed by rewriting, since
               there is no rotation boundary to delete at -- never past the reader's
               checkpoint, and recorded in a trim hint beside the file so the ingester
               SHIFTS its cursor instead of re-reading everything (see enforce_netflow).
  * ml      -- model artefacts from each 6-hourly retrain. Kept as a rolling set, because
               deleting the model the worker is currently serving is an outage.

Each is idempotent and safe to run repeatedly.
"""
from __future__ import annotations

import json
import logging
import os
import shutil
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import IO

log = logging.getLogger(__name__)

# How many times a trim re-checks the sink for bytes appended while it was copying. One pass
# covers the ordinary case (the writer appended during the kept-region copy); the loop exists
# because the writer can also append DURING the drain. Bounded so a sink being written faster
# than it can be copied cannot hold the prune job open forever.
APPEND_DRAIN_PASSES = 16

# Read the SAME variables the rest of the package already uses (weirvern/config.py), so a
# layout change moves one value instead of two. Hardcoding paths here would mean the
# CronJob could prune an empty directory and report success -- a silent no-op, which is
# the worst available failure for a disk cap.
ZEEK_DIR = Path(os.environ.get("ZEEK_LOG_DIR") or "/zeek/logs")
NETFLOW_DIR = Path(os.environ.get("NETFLOW_DIR") or "/data")
ML_DIR = Path(os.environ.get("MODEL_DIR") or "/models")


@dataclass
class ComponentResult:
    component: str
    cap_mb: float
    before_mb: float
    after_mb: float
    freed_mb: float
    actions: int = 0
    skipped: str = ""
    errors: list[str] = field(default_factory=list)

    @property
    def over_cap(self) -> bool:
        return self.before_mb > self.cap_mb


def _mb(n: int | float) -> float:
    return n / 1048576.0


def _total_bytes(path: Path) -> int:
    if not path.exists():
        return 0
    total = 0
    for p in path.rglob("*") if path.is_dir() else [path]:
        try:
            if p.is_file():
                total += p.stat().st_size
        except OSError:
            continue
    return total


def enforce_zeek(cap_mb: float, grace_s: int = 3600) -> ComponentResult:
    """Prune rotated Zeek logs to a byte cap."""
    from weirvern import prune

    before = prune.total_bytes(ZEEK_DIR)
    r = ComponentResult(component="zeek", cap_mb=cap_mb, before_mb=_mb(before),
                        after_mb=_mb(before), freed_mb=0.0)
    if cap_mb <= 0:
        r.skipped = "no cap set"
        return r
    if not ZEEK_DIR.exists():
        r.skipped = f"{ZEEK_DIR} does not exist"
        return r

    res = prune.prune(ZEEK_DIR, int(cap_mb), grace_s=grace_s)
    after = prune.total_bytes(ZEEK_DIR)
    r.after_mb = _mb(after)
    r.freed_mb = _mb(before - after)
    r.actions = res.deleted_files
    r.errors = list(res.errors)
    if res.skipped_recent:
        r.skipped = f"{res.skipped_recent} file(s) inside the grace period"
    return r


def _reader_boundary(p: Path, size: int) -> int | None:
    """The tail reader's checkpointed cursor for `p`, when it belongs to THIS file instance.

    None means "no reader is bound": no checkpoint yet (first run, or a deployment without
    the shared state volume) or one from a previous instance. The trim then proceeds
    unguarded -- the cap exists precisely for when nothing else bounds the disk -- and the
    reader falls back to its own detection.
    """
    try:
        from weirvern.ingester import load_tail_state
        state = load_tail_state(str(p))
    except Exception:  # noqa: BLE001 - a guard that can crash the pruner is worse than none
        log.warning("prune: could not read the tail cursor for %s; trimming unguarded", p)
        return None
    if not state.offset or state.offset > size:
        return None
    if state.inode:
        try:
            if int(p.stat().st_ino) != int(state.inode):
                return None
        except OSError:
            return None
    return int(state.offset)


def _append_trim_hint(p: Path, old_inode: int, new_inode: int, removed: int) -> None:
    """Record one rewrite of `p` so the reader can SHIFT its cursor instead of re-reading.

    The chain is ordered oldest-first and only extended while contiguous: an entry whose
    `from` does not match the previous entry's `to` starts a NEW chain. The reader walks it
    from ITS inode; a chain it cannot follow exactly falls back to the old re-read, which
    duplicates but never loses. Bounded length: a reader that far behind is not the case
    this protocol exists for, and the full reset recovers it.

    Best-effort on purpose: a read-only flows directory must not fail the trim (the space
    was already freed), and without the hint the reader degrades to the old behaviour.
    """
    from weirvern.ingester import TRIM_HINT_CHAIN_MAX, TRIM_HINT_SUFFIX
    hint_path = p.with_name(p.name + TRIM_HINT_SUFFIX)
    try:
        existing = json.loads(hint_path.read_text(encoding="utf-8"))
        chain = existing.get("chain") if isinstance(existing, dict) else None
        if not isinstance(chain, list):
            chain = []
    except (OSError, ValueError):
        chain = []
    if not chain or chain[-1].get("to") != old_inode:
        chain = []
    chain.append({"from": int(old_inode), "to": int(new_inode), "removed": int(removed)})
    if len(chain) > TRIM_HINT_CHAIN_MAX:
        chain = chain[-TRIM_HINT_CHAIN_MAX:]
    payload = {"chain": chain, "updated": datetime.now(UTC).isoformat()}
    try:
        tmp = str(hint_path) + ".tmp"
        Path(tmp).write_text(json.dumps(payload), encoding="utf-8")
        os.replace(tmp, hint_path)
    except OSError as exc:
        log.warning("prune: could not record the trim hint for %s: %s", p, exc)


def _copy_appends(src: IO[bytes], out: IO[bytes], start: int) -> int:
    """Move bytes the collector appended after `start` into the rewritten file.

    ── WHY THIS EXISTS (measured data-durability defect) ──────────────────────────────────────

    The in-place rewrite copies only the KEPT region back over the sink's front, then truncates.
    The collector does not pause for it: a record appended between the start of the copy and the
    truncate sits at an offset the copy never wrote, and `truncate()` deletes it. The trim then
    reports success with the size it intended -- no error, no gap in the count, just a record that
    vanished.

    So capture where the kept region ended IN THE SOURCE, and move everything after it into the
    new file before truncating. One pass covers what arrived during the copy; the loop re-reads the
    size because a writer can also append during the drain, and stops only when it has caught up.

    SAFE BY CONSTRUCTION: `start` is `kept_end`, the source offset just past the kept region, and
    the destination is positioned at `kept_end - cut` (the kept region is `cut` bytes shorter).
    Every write therefore stays exactly `cut` bytes behind the read cursor, so a drain can never
    overwrite source bytes it has not read yet.

    Returns the number of bytes moved.
    """
    moved = 0
    pos = start
    for _ in range(APPEND_DRAIN_PASSES):
        try:
            size_now = os.fstat(src.fileno()).st_size
        except OSError:
            return moved
        if size_now <= pos:
            return moved
        src.seek(pos)
        remaining = size_now - pos
        while remaining > 0:
            chunk = src.read(min(1024 * 1024, remaining))
            if not chunk:
                break
            out.write(chunk)
            pos += len(chunk)
            moved += len(chunk)
            remaining -= len(chunk)
    # Still behind after the bound: name the exposure rather than pretending the trim was clean.
    try:
        residual = max(0, os.fstat(src.fileno()).st_size - pos)
    except OSError:
        residual = 0
    if residual:
        log.error(
            "prune: the sink was still being appended to after %d drain pass(es); %d byte(s) "
            "written during the rewrite are beyond the truncation point and will be lost",
            APPEND_DRAIN_PASSES, residual,
        )
    return moved


def enforce_netflow(cap_mb: float) -> ComponentResult:
    """Trim the goflow2 JSONL sink to a byte cap, oldest lines first.

    WHY BYTE-OFFSET TRIM AND NOT ROTATION: goflow2 appends to one file continuously, so
    there is no rotation boundary to delete at. It has to be rewritten from a byte offset.
    That offset MUST land on a line boundary -- resuming mid-line would leave a truncated
    JSON object that the ingester reports as a parse error on every pass forever.

    ── TWO PROTOCOLS THE TRIM OWES THE READER (review round 2026-10-15) ─────────────────────

    1. NEVER REMOVE WHAT HAS NOT BEEN READ. The reader checkpoints its cursor in
       TAIL_STATE_DIR, which this pod mounts; when the checkpoint belongs to the file being
       trimmed, the cut is capped at that offset. Removing unread bytes destroys records
       before anything saw them, and the cap is a ceiling, not a deadline -- waiting one
       cycle is always the better trade.

    2. RECORD THE REWRITE SO THE READER CAN SHIFT, NOT RE-READ. replace() changes the
       inode, which is exactly what the reader's reset detection fires on -- and its naive
       response re-read the whole file from zero. While over cap that happened EVERY FIVE
       MINUTES, re-inserting up to the full cap into `flows`, a MergeTree with no
       deduplication: duplicate rows feeding the aggregates and models, at real cost. A
       trim-hint file beside the sink lists each rewrite (from-inode, to-inode, bytes
       removed); the reader walks that chain and subtracts, which is exact.

    3. THE WRITER IS STILL WRITING WHILE THE FILE IS REWRITTEN. The copy takes the kept
       region from a snapshot, and every record the collector appends meanwhile is beyond
       it. Those bytes are drained into the new layout BEFORE the truncate (see
       `_copy_appends`) -- otherwise the trim silently deletes exactly the records that
       arrived during it. There is also no unlink path any more: a file whose whole content
       is older than the cut is truncated in place, because "no reader bound" does not mean
       "nothing is appending to it" and unlinking a live sink is how capture goes dark.
    """
    before = _total_bytes(NETFLOW_DIR)
    r = ComponentResult(component="netflow", cap_mb=cap_mb, before_mb=_mb(before),
                        after_mb=_mb(before), freed_mb=0.0)
    if cap_mb <= 0:
        r.skipped = "no cap set"
        return r
    if not NETFLOW_DIR.exists():
        r.skipped = f"{NETFLOW_DIR} does not exist"
        return r

    cap_bytes = int(cap_mb * 1048576)
    if before <= cap_bytes:
        return r

    files = sorted((p for p in NETFLOW_DIR.rglob("*.jsonl") if p.is_file()),
                   key=lambda p: p.stat().st_mtime)
    excess = before - cap_bytes
    for p in files:
        if excess <= 0:
            break
        try:
            st = p.stat()
            size = st.st_size
            old_inode = st.st_ino
            guard = _reader_boundary(p, size)  # the reader's cursor, when it is for THIS file
            # ── ONE MECHANISM: TRIM IN PLACE. THERE IS NO UNLINK PATH. ────────────────────────
            #
            # A file whose whole content was older than the cut used to be UNLINKED when no reader
            # was bound to it. "No reader bound" is not "not live": a first boot, a lost checkpoint
            # and a checkpoint from a previous instance all look identical from here, and the file
            # is normally the collector's open sink. Unlinking it is the same failure the in-place
            # rewrite below exists to prevent -- the writer keeps appending to an inode nothing can
            # see, the visible log freezes at the trim point, and the disk fills through a handle
            # no path names. A full trim is simply a rewrite to zero bytes: same space freed, the
            # handle still valid.
            #
            # Partial trim: drop the OLDEST bytes, then discard the remainder of the line
            # the cut landed in so the file still starts at a record boundary.
            tmp = p.with_suffix(p.suffix + ".trim")
            with open(p, "rb") as src:
                src.seek(min(int(excess), size))
                _ = src.readline()  # partial line -- discarded on purpose
                cut = src.tell()
                if guard is not None and cut > guard:
                    # The reader's offset is itself a record start: cut EXACTLY there, and
                    # discard nothing -- the readline above would otherwise have eaten an
                    # unread record. Fewer bytes are freed; the next pass frees the rest.
                    cut = guard
                    src.seek(cut)
                # STREAM, NEVER read(). The file being trimmed is the flow log, and on the live
                # deployment it reached 17.9 GB against a 1 GB cap. Reading the remainder into
                # memory OOM-killed the prune CronJob at its 256Mi limit every five minutes
                # (measured 2026-11-12: exit 137, BackoffLimitExceeded, cap never enforced while
                # the disk filled). copyfileobj moves it in bounded chunks instead.
                with open(tmp, "wb") as kept_out:
                    shutil.copyfileobj(src, kept_out, length=1024 * 1024)
                # WHERE THE KEPT REGION ENDED, IN THE SOURCE. Everything after this point was
                # appended by the collector while the copy ran and belongs to the new file too.
                kept_end = src.tell()
            # REWRITE THE FILE IN PLACE -- SAME INODE, NOT A RENAME.
            #
            # A rename creates a NEW inode while the COLLECTOR still holds the old one open,
            # and every record it writes afterwards goes into the unlinked file and vanishes.
            # Measured live 2026-11-12: flows stopped at 19:17:57, the log on disk stayed at
            # the trim point while the disk filled to 17.9 GB through a handle nothing could
            # see, and a restart then failed with "permission denied" on a file owned by the
            # prune's user. Carrying the mode and owner across the rename did not fix it --
            # the handle, not the permission, was the problem.
            #
            # The collector opens this log for append, so writing the kept bytes back at
            # offset 0 and truncating keeps its handle valid: its next record lands after
            # ours. Ownership and mode are untouched by construction.
            with p.open("r+b") as out, tmp.open("rb") as kept, open(p, "rb") as live:
                out.seek(0)
                shutil.copyfileobj(kept, out, length=1024 * 1024)
                # DRAIN WHAT WAS APPENDED DURING THE REWRITE, THEN TRUNCATE. Truncating without
                # this deletes those records silently: the trim reports success and the file is
                # short by exactly the bytes the collector wrote while the copy was running.
                # `live` is a second read handle: it only touches [kept_end, EOF), which the
                # rewrite above (positions [0, kept_end - cut)) never wrote.
                _copy_appends(live, out, kept_end)
                out.truncate()
            tmp.unlink(missing_ok=True)
            # The hint records the trim even though the inode did not change: the reader's
            # cursor is now past the end, and this is what moves it instead of re-reading.
            _append_trim_hint(p, old_inode, p.stat().st_ino, cut)
            r.actions += 1
            excess -= cut
        except OSError as exc:
            r.errors.append(f"{p.name}: {exc}")

    after = _total_bytes(NETFLOW_DIR)
    r.after_mb = _mb(after)
    r.freed_mb = _mb(before - after)
    return r


def enforce_ml(cap_mb: float, keep_newest: int = 2) -> ComponentResult:
    """Keep the newest model artefacts within a cap.

    `keep_newest` is a floor that OVERRIDES the cap: the worker serves a model and retrains
    every 6 hours, so deleting the newest set is an outage regardless of the byte budget.
    A cap smaller than one model is therefore reported as unsatisfiable rather than
    obeyed destructively.
    """
    before = _total_bytes(ML_DIR)
    r = ComponentResult(component="ml", cap_mb=cap_mb, before_mb=_mb(before),
                        after_mb=_mb(before), freed_mb=0.0)
    if cap_mb <= 0:
        r.skipped = "no cap set"
        return r
    if not ML_DIR.exists():
        r.skipped = f"{ML_DIR} does not exist"
        return r

    # A model set is a directory (or a .joblib/.pkl file) identified by mtime.
    entries = [p for p in ML_DIR.iterdir() if p.is_dir() or p.suffix in (".joblib", ".pkl")]
    entries.sort(key=lambda p: p.stat().st_mtime, reverse=True)

    if len(entries) <= keep_newest:
        r.skipped = f"only {len(entries)} model set(s); keeping the newest {keep_newest}"
        return r

    cap_bytes = int(cap_mb * 1048576)
    running = before
    for p in entries[keep_newest:]:
        if running <= cap_bytes:
            break
        try:
            size = _total_bytes(p) if p.is_dir() else p.stat().st_size
            if p.is_dir():
                import shutil
                shutil.rmtree(p)
            else:
                p.unlink()
            running -= size
            r.actions += 1
        except OSError as exc:
            r.errors.append(f"{p.name}: {exc}")

    after = _total_bytes(ML_DIR)
    r.after_mb = _mb(after)
    r.freed_mb = _mb(before - after)
    return r


def enforce(caps: dict[str, int], grace_s: int = 3600) -> list[ComponentResult]:
    """Apply every configured cap. One component failing must not stop the others."""
    out: list[ComponentResult] = []
    for comp, fn in (("zeek", lambda: enforce_zeek(caps.get("zeek", 0), grace_s)),
                     ("netflow", lambda: enforce_netflow(caps.get("netflow", 0))),
                     ("ml", lambda: enforce_ml(caps.get("ml", 0)))):
        try:
            out.append(fn())
        except Exception as exc:  # noqa: BLE001
            # Never let one component's failure abort the rest: a broken ML path should
            # still leave Zeek pruned, or the disk fills from the direction nobody watched.
            log.warning("prune: %s failed: %s", comp, exc)
            out.append(ComponentResult(component=comp, cap_mb=caps.get(comp, 0),
                                       before_mb=0.0, after_mb=0.0, freed_mb=0.0,
                                       errors=[str(exc)]))
    return out


def render(results: list[ComponentResult]) -> str:
    lines = []
    for r in results:
        cap = f"{r.cap_mb} MB" if r.cap_mb else "unset"
        if r.errors:
            state = f"ERROR: {'; '.join(r.errors[:2])}"
        elif r.skipped and not r.actions:
            state = f"skipped ({r.skipped})"
        elif r.actions:
            state = f"freed {r.freed_mb:.1f} MB in {r.actions} action(s)"
        else:
            state = "within cap"
        lines.append(f"  {r.component:<8} {r.before_mb:8.1f} MB / cap {cap:<9} {state}")
    return "\n".join(lines)
