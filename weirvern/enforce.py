"""Component disk-cap enforcement: one entrypoint, three components.

WHY A SINGLE COMMAND: the caps (`ZEEK_MAX_MB`, `NETFLOW_MAX_MB`, `ML_MAX_MB`) were
advisory -- `weirvern disk` recommended them and nothing enforced them. A recommendation
that nothing applies is worse than no recommendation, because it reads as handled. This
is the enforcement half: the CronJob and `weirvern prune` both call `enforce()`, so the
scheduled path and the manual path cannot diverge.

WHY THREE COMPONENTS HAVE DIFFERENT MECHANISMS:
  * zeek    -- rotated files `conn.2026-01-01-13-00-00.log.gz`. Deleted by age, under a
               byte cap. Zeek itself cannot cap by SIZE, only by rotation COUNT.
  * netflow -- the goflow2 JSONL sink, written continuously. Trimmed by rewriting, since
               there is no rotation boundary to delete at.
  * ml      -- model artefacts from each 6-hourly retrain. Kept as a rolling set, because
               deleting the model the worker is currently serving is an outage.

Each is idempotent and safe to run repeatedly.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
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


def enforce_netflow(cap_mb: float) -> ComponentResult:
    """Trim the goflow2 JSONL sink to a byte cap, oldest lines first.

    WHY BYTE-OFFSET TRIM AND NOT ROTATION: goflow2 appends to one file continuously, so
    there is no rotation boundary to delete at. It has to be rewritten from a byte offset.
    That offset MUST land on a line boundary -- resuming mid-line would leave a truncated
    JSON object that the ingester reports as a parse error on every pass forever.
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
            size = p.stat().st_size
            if size <= excess:
                # The whole file goes; it is entirely older than the cut.
                p.unlink()
                excess -= size
                r.actions += 1
                continue
            # Partial trim: drop the OLDEST bytes, then discard the remainder of the line
            # the cut landed in so the file still starts at a record boundary.
            keep_from = int(excess)
            with open(p, "rb") as fh:
                fh.seek(keep_from)
                _ = fh.readline()  # partial line -- discarded on purpose
                rest = fh.read()
            tmp = p.with_suffix(p.suffix + ".trim")
            with open(tmp, "wb") as fh:
                fh.write(rest)
            tmp.replace(p)
            r.actions += 1
            excess = 0
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
