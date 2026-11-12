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

import contextlib
import json
import logging
import os
import shutil
import stat
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

log = logging.getLogger(__name__)

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
            if size <= excess and guard is None:
                # The whole file goes; it is entirely older than the cut, and no reader is
                # bound to this instance.
                p.unlink()
                excess -= size
                r.actions += 1
                continue
            # Partial trim: drop the OLDEST bytes, then discard the remainder of the line
            # the cut landed in so the file still starts at a record boundary.
            tmp = p.with_suffix(p.suffix + ".trim")
            with open(p, "rb") as src, open(tmp, "wb") as out:
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
                shutil.copyfileobj(src, out, length=1024 * 1024)
            # KEEP THE WRITER'S ACCESS. Replacing the log creates a new inode owned by whoever
            # ran the prune; the collector runs as a different user (measured live 2026-11-12:
            # goflow2 runs as uid 100, the prune job as 10001, mode 644 -> the collector got
            # "permission denied" on its own log and NetFlow stopped). Ownership and mode are
            # carried across the rewrite; a chown we are not allowed to do is not fatal.
            with contextlib.suppress(PermissionError, AttributeError):
                os.chown(tmp, st.st_uid, st.st_gid)
            os.chmod(tmp, stat.S_IMODE(st.st_mode))
            tmp.replace(p)
            # AFTER the replace, deliberately: in the millisecond between the two, a reader
            # pass falls back to the old re-read behaviour -- the known degraded path --
            # rather than applying a shift for a rewrite that has not happened yet.
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
