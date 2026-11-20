"""How long the detection and ripple tables keep their rows -- derived from free disk.

WHY THIS EXISTS. The ripple layer measures a channel against the SAME host's own trailing
history at 1h, 6h, 24h and 7d scales, with a 30-window minimum before a rank means anything.
Thirty non-overlapping windows of 6h is 7.5 days and of 24h is 30 days, so a deployment that
keeps flows for 3 days and Zeek for 7 can only ever speak at the 1h scale. The tables need
enough history; the question is how much this host can afford.

THE ANSWER IS MEASURED, NOT CHOSEN. `auto` (the default) derives the window from what the
deployment actually has:

    budget_bytes  = free_bytes * ratio / 100          # ratio defaults to 40%
    bytes_per_day = bytes_on_disk / observed_days      # the managed tables, really measured
    days          = floor(budget_bytes / bytes_per_day)

`free_bytes` comes from `system.disks` (the disk that holds this database's parts), and
`bytes_per_day` from `system.parts` over the managed tables -- retained bytes divided by the
span those bytes cover. Nothing is guessed and no rate is configured by hand.

WHY 40%, AND WHY 70% IS THE CEILING. ClickHouse needs room for merges, mutations and its own
metadata: budgeting ALL free space would leave a table that stops accepting inserts exactly
when it is biggest. The default keeps 60% of free space as headroom; the control refuses a
ratio above 70% because past that the next merge can fill the disk. The help text says this
in the operator's words, and the row shows the arithmetic.

FLOOR AND CAP. A derived value below 7 days becomes 7, and the report says what the disk
actually supports ("disk supports 4 days; holding the 7-day floor"). Above 365 it is capped.
An explicit override (7-365) is still allowed, but a value ABOVE the measured budget is
refused with the budget named: accepting it would fill the disk.

NEVER ON FAILURE. If a table's current TTL cannot be read or parsed, that table is left
exactly as it is and the receipt says `NOT CHANGED: TTL unreadable`. There is no fallback
window: choosing 365 days because the DDL was not understood would turn a read failure into a
disk-filling setting. `alter_sql` also refuses any interval longer than the derived window, so
a bad parse cannot produce a longer TTL than the arithmetic allows.

TWO PLACES ENFORCE THE RESULT, AND THEY MUST AGREE:

  * the schema files create every managed table with the 7-day FLOOR as a bootstrap (a fresh
    database has no ingest to measure yet, and the floor is the safe direction);
  * `ensure()` runs from `db.apply_schema` on every start (the schema Job and the worker both
    call it), derives again from the CURRENT disk and history, and converges each table with
    `ALTER TABLE <t> MODIFY TTL ...` only where its TTL differs.

The Settings apply path does the same derivation and read-back in the request, so the receipt
describes `system.tables` rather than the value someone typed.

WHAT IS DELIBERATELY NOT HERE. Audit and provenance tables (`fleet_audit`, `schema_versions`,
model history) must never expire on a data-volume schedule: their retention is a legal and
forensic decision. Operator intent and the rest of the Zeek corpus keep their own per-table
TTLs. `NEVER_EXPIRE` and `UNMANAGED` record the exclusions WITH their reasons.

LOWERING IS DESTRUCTIVE, AND IS TREATED AS SUCH. ClickHouse applies a TTL on the next merge,
not when the ALTER returns; shortening the window therefore deletes older rows in the
background and cannot be undone. Nothing here drops a partition -- the ALTER only changes the
TTL expression.
"""
from __future__ import annotations

import json
import logging
import math
import os
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

#: The value that means "derive it from free disk". Also what an unset ConfigMap key means.
AUTO = "auto"

#: The share of FREE space the tables may occupy. 40% leaves room for merges; 70% is the
#: hard ceiling, because past that the next merge can fill the disk.
DEFAULT_RATIO_PERCENT = 40
MIN_RATIO_PERCENT = 10
MAX_RATIO_PERCENT = 70

#: The derived window is held inside these. Seven days is the 6h scale's 30-window floor plus
#: a day; 365 is a year, past which raw flows are a capacity decision rather than a detection
#: one.
MIN_RETENTION_DAYS = 7
MAX_RETENTION_DAYS = 365

#: AUTO WILL NOT DERIVE FROM LESS THAN A DAY OF HISTORY. A ten-minute-old database multiplied
#: up to a daily rate is noise, and acting on it would size the tables off an outlier. The
#: explicit-override budget check still uses whatever has been observed (see `derive`).
MIN_OBSERVATION_DAYS = 1.0

#: The shortest span the rate is divided by, so a nearly-empty `system.parts` cannot produce
#: an infinite bytes/day.
MIN_RATE_SPAN_DAYS = 1.0 / 24.0

#: A history span longer than twice the cap cannot describe these tables: their own TTL is at
#: most 365 days. It is the sentinel `toDateTime(0)` from a part with no minmax index (an
#: unpartitioned table, or an empty part), which used to make the observed span 56 years and
#: the derived window collapse to the cap. Such a measurement is REFUSED, not converted into
#: a longer window.
MAX_PLAUSIBLE_SPAN_DAYS = float(MAX_RETENTION_DAYS * 2)

RETENTION_DAYS_KEY = "DATA_RETENTION_DAYS"
RETENTION_RATIO_KEY = "DATA_RETENTION_RATIO"

#: THE RATCHET, AND WHY IT EXISTS. The window above is derived from FREE space, so it SHRINKS
#: whenever the disk gets fuller -- measured on the live box: 284 days became 258 without anyone
#: touching a setting, and every shrink expired history on the next merge. A "high-water mark"
#: floor is persisted beside the other model state (`MODEL_DIR/retention_ratchet.json`, the same
#: place `detect_cursor.json` lives) and the derived window is held at `max(derived, floor)`.
#:
#: THE FLOOR ONLY RISES BY ITSELF. It falls only through an explicit operator reset (a
#: `RETENTION_RATCHET` record with the actor and reason, written by the Settings apply path).
#: A lower value never becomes the floor merely because the disk shrank.
RATCHET_FILE = "retention_ratchet.json"

#: THE OPERATOR'S RECORD, in the settings ConfigMap. A reset or an explicit raise is written
#: here by the apply path (the GUI's /models is read-only, by design: the worker owns it). The
#: effective floor is the NEWEST of this record and the worker's file, so a reset takes effect
#: immediately and a later worker derivation can still raise it. Not an editable settings key.
RETENTION_RATCHET_KEY = "RETENTION_RATCHET"

#: THE HARD CAPACITY GUARD. Honouring a floor is only safe while the tables' projected share of
#: the VOLUME stays below this fraction. A ratchet that fills the disk turns a safety feature
#: into an outage, so past this line the floor is NOT honoured: the control holds the largest
#: window that fits and says so on the Settings row, in the worker log, and in Health.
DEFAULT_MAX_DISK_FRACTION = 0.85
MAX_DISK_FRACTION_ENV = "ML_RETENTION_MAX_DISK_FRACTION"


@dataclass(frozen=True)
class RetentionTable:
    """One table the detection/ripple surface reads, and the column its TTL counts from.

    `expression` is the TTL's own left-hand side when it is not a bare column: `flows` keys
    its TTL on `toDateTime(timestamp)` because `timestamp` is DateTime64 and ClickHouse wants
    a DateTime in a TTL. Keeping it here means the ALTER writes the SAME expression the
    schema does, rather than a bare column that the server may refuse.

    `why` is not decoration: it is what makes a later reader able to decide whether a new
    table belongs here, rather than guessing from the name.
    """

    name: str
    column: str
    why: str
    expression: str = ""

    def ttl_expression(self) -> str:
        return self.expression or self.column


#: THE MANAGED SET, in dependency order (raw -> window -> evidence). Every table here is
#: either an input to the detection stack or a table `models/ripple_evidence.py` reads.
RETENTION_TABLES: tuple[RetentionTable, ...] = (
    # ── raw and windowed flows ────────────────────────────────────────────────────────────
    RetentionTable("flows", "timestamp",
                   "raw flow records; every aggregate below is derived from them",
                   expression="toDateTime(timestamp)"),
    RetentionTable("flows_aggregated", "window_start",
                   "legacy 5-minute host windows, still written and read by the console"),
    RetentionTable("flows_aggregated_diversity", "window_start",
                   "per-host diversity features derived from the same flows"),
    RetentionTable("flows_aggregated_temporal", "window_start",
                   "per-host timing features derived from the same flows"),
    RetentionTable("flows_window", "window_start",
                   "the detection stack's window unit and the ripple layer's flow source"),
    RetentionTable("flows_window_endpoint", "window_start",
                   "the per-ENDPOINT window (host, direction) the ripple flow channels read; "
                   "the inbound half of the network"),
    # ── the Zeek logs the detection and ripple layers read ────────────────────────────────
    RetentionTable("zeek_conn", "ts", "connection volume/diversity/reset channels"),
    RetentionTable("zeek_dns", "ts", "DNS volume/query-diversity/NXDOMAIN/reverse channels"),
    RetentionTable("zeek_http", "ts", "HTTP metadata used by the anomaly evidence"),
    RetentionTable("zeek_ssl", "ts", "TLS metadata and JA4 fingerprints"),
    RetentionTable("zeek_ssh", "ts", "SSH authentication history, which needs weeks to read"),
    RetentionTable("zeek_notice", "ts", "Zeek's own security notices"),
    RetentionTable("zeek_weird", "ts", "protocol anomalies: low volume, high signal"),
    # ── ripple evidence sources that the list above does not already cover ────────────────
    RetentionTable("zeek_kerberos", "ts", "identity channel read by ripple_evidence"),
    RetentionTable("zeek_ntlm", "ts", "identity channel read by ripple_evidence"),
    RetentionTable("zeek_smb_files", "ts", "SMB file channel read by ripple_evidence"),
    RetentionTable("ml_ripple_evidence", "window_start",
                   "the ripple layer's own evidence store and read path"),
)

#: Tables whose retention a data-volume control must NEVER touch. Absent from the managed
#: list on purpose, and listed here so the exclusion is a decision rather than an omission.
NEVER_EXPIRE: dict[str, str] = {
    "schema_versions": "the applied-schema history; expiring it erases how the database got here",
    "fleet_audit": "privileged-action audit trail; retention is a legal/forensic decision",
    "model_actions": "model promotion and retirement history",
    "ml_model_cards": "model card provenance that a score is explained from",
    "ml_models": "the model registry and its metrics",
    "host_watches": "operator intent, reviewed by hand",
    "network_scopes": "the operator's declared monitored networks; configuration, not telemetry",
    "weirlings": "sensor declarations; configuration, not telemetry",
    "host_roles": "operator-assigned host roles",
}

#: Tables that keep their OWN per-table policy, and why they are not on this control.
UNMANAGED: dict[str, str] = {
    "alert_reviews": "an operator disposition outlives the control it was made under",
    "alert_events": "delivery records; 30-day policy stated in docs/runbooks/data-retention.md",
    "alert_episodes": "incident grouping; 30-day policy",
    "netflow_anomalies": "detection OUTPUT, not a baseline input; its own 30-day policy",
    "near_misses": "tuning evidence; its own short 7-day policy",
    "host_hour_features": "derived from flows_window and rebuilt from it; not a ripple source",
    "host_hour_scores": "host-hour detector output, not a baseline input",
    "host_reference_samples": "the host-hour detector's own sample store",
    "host_reference_stats": "the host-hour detector's own reference store",
    "zeek_files": "file metadata, kept at its 30-day privacy budget",
    "zeek_dhcp": "L2 identity lease history, kept at 90 days",
    "zeek_x509": "certificate metadata, kept at 60 days",
    "sluice_rules": "durable enforcement rules, kept while the operator needs them",
}


def table_names() -> tuple[str, ...]:
    """Every managed table, in declaration order."""
    return tuple(t.name for t in RETENTION_TABLES)


_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_TTL_EXPRESSION = re.compile(
    r"^(?:[A-Za-z_][A-Za-z0-9_]*|toDateTime\([A-Za-z_][A-Za-z0-9_]*\))$")


def _checked(name: str) -> str:
    """Refuse anything that is not a bare identifier before it reaches DDL.

    The names are module constants, not caller input, but a TTL is written by string
    interpolation and the check costs nothing. A name that fails here is a bug, not a typo.
    """
    if not _IDENTIFIER.match(name or ""):
        raise ValueError(f"not a usable ClickHouse identifier: {name!r}")
    return name


def _checked_expression(expression: str) -> str:
    """The TTL's left-hand side: a bare column, or `toDateTime(<column>)`.

    Deliberately a closed set rather than "anything ClickHouse parses": this string is
    interpolated into an ALTER, and the only shapes the managed tables need are these two.
    """
    if not _TTL_EXPRESSION.match(expression or ""):
        raise ValueError(f"not a usable TTL expression: {expression!r}")
    return expression


def is_auto(value: Any) -> bool:
    """Whether a setting means "derive it" -- including an unset one, which is the default."""
    return str(value if value is not None else "").strip().lower() in ("", AUTO)


def normalise_days(value: Any) -> int:
    """An explicit day count inside 7..365, or ValueError.

    ONE place decides what a legal explicit value is, shared by the Settings validator, the
    migration and the CLI. A fractional day is refused rather than rounded: rounding a
    destructive value is choosing a number the operator did not.
    """
    if isinstance(value, bool):
        raise ValueError(f"retention must be 'auto' or a number of days, not {value!r}")
    try:
        number = float(str(value).strip())
    except (TypeError, ValueError):
        raise ValueError(
            f"retention must be 'auto' or a whole number of days between "
            f"{MIN_RETENTION_DAYS} and {MAX_RETENTION_DAYS}; got {value!r}") from None
    if number != int(number):
        raise ValueError(
            f"retention must be a whole number of days between {MIN_RETENTION_DAYS} and "
            f"{MAX_RETENTION_DAYS}; got {value!r}")
    days = int(number)
    if days < MIN_RETENTION_DAYS or days > MAX_RETENTION_DAYS:
        raise ValueError(
            f"retention must be between {MIN_RETENTION_DAYS} and {MAX_RETENTION_DAYS} "
            f"days; got {days}"
        )
    return days


def normalise_ratio(value: Any) -> int:
    """The disk-budget percentage, 10..70, or ValueError.

    Below 10% the budget is too small to be stable (a busy hour can move it by days); above
    70% the next merge can fill the disk. Both ends are refused with the reason stated.
    """
    if isinstance(value, bool):
        raise ValueError(f"the retention budget must be a percentage, not {value!r}")
    try:
        number = float(str(value).strip())
    except (TypeError, ValueError):
        raise ValueError(
            f"the retention budget must be a percentage between {MIN_RATIO_PERCENT} and "
            f"{MAX_RATIO_PERCENT}; got {value!r}") from None
    if number != int(number):
        raise ValueError(
            f"the retention budget must be a whole percentage between {MIN_RATIO_PERCENT} "
            f"and {MAX_RATIO_PERCENT}; got {value!r}")
    ratio = int(number)
    if ratio < MIN_RATIO_PERCENT or ratio > MAX_RATIO_PERCENT:
        raise ValueError(
            f"the retention budget must be between {MIN_RATIO_PERCENT} and "
            f"{MAX_RATIO_PERCENT} percent of free space; got {ratio}. Above "
            f"{MAX_RATIO_PERCENT}% ClickHouse has no room left for merges."
        )
    return ratio


def max_disk_fraction() -> float:
    """The guarded share of the VOLUME a held window may occupy. Default 0.85.

    Read from the environment each call rather than frozen at import: the worker, the schema Job
    and the GUI all parse the ConfigMap-backed env, and a test must be able to move it without
    reimporting the module. A nonsense value falls back to the default WITH a warning instead of
    becoming an accidental 0% (which would refuse every floor) or 150% (which would guard nothing).
    """
    raw = os.environ.get(MAX_DISK_FRACTION_ENV, "").strip()
    if not raw:
        return DEFAULT_MAX_DISK_FRACTION
    try:
        value = float(raw)
    except ValueError:
        logger.warning("retention: %s=%r is not a number; using %.2f",
                       MAX_DISK_FRACTION_ENV, raw, DEFAULT_MAX_DISK_FRACTION)
        return DEFAULT_MAX_DISK_FRACTION
    if not 0.0 < value <= 1.0:
        logger.warning("retention: %s=%r must be in (0, 1]; using %.2f",
                       MAX_DISK_FRACTION_ENV, raw, DEFAULT_MAX_DISK_FRACTION)
        return DEFAULT_MAX_DISK_FRACTION
    return value


@dataclass(frozen=True)
class Ratchet:
    """The highest window this deployment has ever held, and who set it.

    `floor_days` is a POLICY high-water mark, not a measurement. `set_at` is ISO-8601 UTC so two
    records (the worker's file and the operator's ConfigMap record) can be ordered without
    guessing which is newer. `by`/`reason` are the audit trail a reset must carry.
    """

    floor_days: int
    set_at: str
    by: str = "auto"
    reason: str = ""

    @property
    def set_on(self) -> str:
        """The date the floor was set, for the Settings sentence: `2026-11-20`."""
        return str(self.set_at or "")[:10]

    def as_dict(self) -> dict[str, Any]:
        return {"floor_days": int(self.floor_days), "set_at": self.set_at,
                "by": self.by, "reason": self.reason}

    def to_json(self) -> str:
        return json.dumps(self.as_dict(), sort_keys=True)


def _parse_set_at(value: Any) -> datetime | None:
    """A timezone-aware timestamp, or None. A naive stamp is read as UTC (the file is ours)."""
    try:
        parsed = datetime.fromisoformat(str(value or "").strip().replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(
        UTC)


def ratchet_from_json(raw: Any) -> Ratchet | None:
    """One persisted/recorded ratchet, or None when it is absent or unusable.

    Tolerant about the envelope (a dict or the JSON string the ConfigMap stores) and strict
    about the number: a floor outside 7..365 is NOT silently clamped here, because a corrupt
    record must not become a policy someone did not choose. `load_ratchet` reports the error.
    """
    if raw is None or (isinstance(raw, str) and not raw.strip()):
        return None
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except ValueError:
            return None
    if not isinstance(raw, dict):
        return None
    value = raw.get("floor_days")
    if value is None or isinstance(value, bool):
        return None
    try:
        days = int(value)
    except (TypeError, ValueError):
        return None
    if days < MIN_RETENTION_DAYS or days > MAX_RETENTION_DAYS:
        return None
    when = _parse_set_at(raw.get("set_at"))
    if when is None:
        return None
    return Ratchet(floor_days=days, set_at=when.isoformat(timespec="seconds"),
                   by=str(raw.get("by") or "auto"), reason=str(raw.get("reason") or ""))


def latest_ratchet(*records: Ratchet | None) -> Ratchet | None:
    """The NEWEST record; on an equal timestamp the HIGHER floor wins.

    Newest-wins is what lets an operator reset take effect immediately: a reset written today
    outranks a file written last week even though its number is lower. The tie-break is upward
    because "which record is this?" must never lower the floor by accident.
    """
    present = [r for r in records if r is not None]
    if not present:
        return None
    return max(present, key=lambda r: (_parse_set_at(r.set_at) or datetime.min.replace(
        tzinfo=UTC), int(r.floor_days)))


def ratchet_path(model_dir: Any) -> Path | None:
    """`MODEL_DIR/retention_ratchet.json`, or None when this process has no model directory."""
    if not model_dir:
        return None
    return Path(str(model_dir)) / RATCHET_FILE


def load_ratchet(model_dir: Any) -> tuple[Ratchet | None, str]:
    """(record, error) from the model directory. A missing file is `(None, "")`.

    A MISSING FILE IS A FRESH INSTALL and must behave exactly as before the ratchet existed.
    A file that exists but cannot be understood is DIFFERENT: it returns the error so the report
    can say the floor is unknown. Silently treating corruption as "no floor" would let the
    window contract while the operator believes a floor is being held.
    """
    path = ratchet_path(model_dir)
    if path is None:
        return None, ""
    try:
        raw = path.read_text()
    except FileNotFoundError:
        return None, ""
    except OSError as exc:
        return None, f"{path} could not be read: {exc}"
    state = ratchet_from_json(raw)
    if state is None:
        return None, f"{path} does not hold a usable ratchet record"
    return state, ""


def save_ratchet(model_dir: Any, state: Ratchet) -> str:
    """Persist one record atomically; returns "" on success, else the reason.

    Written via a temporary file in the same directory and `os.replace`, so a reader (the GUI)
    never sees a half-written record. A failed write is REPORTED to the caller, never raised:
    the retention pass has already converged the tables, and bookkeeping must not undo that.
    """
    path = ratchet_path(model_dir)
    if path is None:
        return "this process has no model directory, so the ratchet cannot be persisted"
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_text(state.to_json())
        os.replace(tmp, path)
        return ""
    except OSError as exc:
        return f"{path} could not be written: {exc}"


def new_ratchet(days: int, *, by: str = "auto", reason: str = "",
                at: datetime | None = None) -> Ratchet:
    """A record stamped now (UTC), with a whole day count inside the control's bounds."""
    want = normalise_days(days)
    stamp = at or datetime.now(UTC)
    return Ratchet(floor_days=want, set_at=stamp.isoformat(timespec="seconds"),
                   by=by or "auto", reason=reason or "")


def _capacity_max_days(measurement: Measurement, max_fraction: float) -> int | None:
    """The longest window whose projected table footprint stays under the hard fraction.

    THE PROJECTION REPLACES THE TABLES' CURRENT FOOTPRINT, it does not add to it: the managed
    tables already hold `bytes_on_disk`, and a new window resizes that footprint rather than
    stacking a second copy on top. `other` is everything else on the volume (the OS,
    ClickHouse's own files, unmanaged tables), which does not move.
    """
    total = int(measurement.total_bytes)
    rate = measurement.bytes_per_day
    if total <= 0 or rate <= 0:
        return None
    used = max(0, total - int(measurement.free_bytes))
    other = max(0, used - int(measurement.bytes_on_disk))
    room = max_fraction * total - other
    days = int(math.floor(room / rate))
    return max(MIN_RETENTION_DAYS, min(MAX_RETENTION_DAYS, days))


def _needed_fraction(measurement: Measurement, days: int) -> float | None:
    """The projected share of the VOLUME used if the tables held `days`."""
    total = int(measurement.total_bytes)
    rate = measurement.bytes_per_day
    if total <= 0 or rate <= 0:
        return None
    used = max(0, total - int(measurement.free_bytes))
    other = max(0, used - int(measurement.bytes_on_disk))
    return (other + max(0, int(days)) * rate) / float(total)


def alter_sql(table: RetentionTable, days: int, *, max_days: int | None = None) -> str:
    """The statement that sets one table's TTL, never longer than `max_days`.

    `MODIFY TTL`, never `DROP PARTITION`: the ALTER only changes when ClickHouse's own merge
    expires rows. Nothing here deletes a partition, and nothing here truncates a table.

    THE BOUND IS A HARD GUARD, NOT A CONVENTION. `max_days` is the derivation's answer for
    this deployment; an interval above it is refused with ValueError BEFORE any SQL exists.
    That is what makes a fallback (or a TTL parsed from the wrong clause) unable to produce a
    window the arithmetic did not allow. The 365-day cap applies even when the caller omits
    the bound, because `normalise_days` refuses anything above it.
    """
    want = normalise_days(days)
    if max_days is not None:
        bound = int(max_days)
        if bound < 0:
            raise ValueError(f"the retention bound must not be negative; got {bound}")
        bound = min(bound, MAX_RETENTION_DAYS)
        if want > bound:
            raise ValueError(
                f"refusing to set {table.name} to {want} days: the derived window is "
                f"{bound} day(s), and an interval may never exceed it")
    return (
        f"ALTER TABLE {_checked(table.name)} "
        f"MODIFY TTL {_checked_expression(table.ttl_expression())} + INTERVAL {want} DAY"
    )


# ── measuring the deployment ───────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Measurement:
    """What the deployment's own tables and disks say, right now.

    `span_days` is the union of the parts' timestamps and is what the UI shows as the history
    the deployment holds. `rate_bytes_per_day` is the MEASURED ingest: the sum of each table's
    own bytes divided by its OWN span, because a table keeping 7 days and a table keeping 30
    did not write their bytes over the same interval. `None` keeps the simple
    bytes/span division for callers that have one table or a synthetic measurement.
    """

    disk_name: str
    total_bytes: int
    free_bytes: int
    bytes_on_disk: int
    span_days: float
    rate_bytes_per_day: float | None = None

    @property
    def observed_days(self) -> float:
        """The span the rate is divided by, floored so a tiny sample cannot explode it."""
        return max(float(self.span_days), MIN_RATE_SPAN_DAYS)

    @property
    def bytes_per_day(self) -> float:
        if self.rate_bytes_per_day is not None:
            return max(0.0, float(self.rate_bytes_per_day))
        if self.bytes_on_disk <= 0:
            return 0.0
        return float(self.bytes_on_disk) / self.observed_days

    def as_dict(self) -> dict[str, Any]:
        return {
            "disk_name": self.disk_name,
            "total_bytes": self.total_bytes,
            "free_bytes": self.free_bytes,
            "bytes_on_disk": self.bytes_on_disk,
            "span_days": round(float(self.span_days), 3),
            "bytes_per_day": round(self.bytes_per_day, 1),
        }


def measure(client: Any) -> Measurement:
    """Disk capacity and the managed tables' OWN observed ingest.

    THE DISK IS THE ONE HOLDING THIS DATABASE. `system.disks` can list several (default,
    broken, an external volume); the parts below name the disk they live on, so that name
    wins, and the largest disk is the fallback when nothing has parts yet.

    THE RATE IS MEASURED, NOT CONFIGURED. `system.parts` carries each part's on-disk bytes and
    the time range it covers (from the table's minmax index), so retained bytes over the span
    they cover IS the observed bytes/day for these tables -- no constant and no guess.
    """
    disks: list[tuple[str, int, int]] = []
    for row in client.query("SELECT name, total_space, free_space FROM system.disks").result_rows:
        disks.append((str(row[0]), int(row[1] or 0), int(row[2] or 0)))
    if not disks:
        raise RuntimeError("system.disks returned no disks, so free space cannot be measured")
    preferred: set[str] = set()
    try:
        part_rows = client.query(
            "SELECT DISTINCT disk_name FROM system.parts "
            "WHERE database = currentDatabase() AND active").result_rows
        preferred = {str(r[0]) for r in part_rows if r and r[0]}
    except Exception:  # noqa: BLE001 - the disk list is still usable without part affinity
        preferred = set()
    candidates = [d for d in disks if d[2] > 0] or disks
    on_disk = [d for d in candidates if d[0] in preferred]
    chosen = max(on_disk or candidates, key=lambda d: (d[1], d[2]))

    listed = ", ".join("'" + _checked(name) + "'" for name in table_names())
    # THE EPOCH IS NOT HISTORY. `system.parts.min_time` is the sentinel `toDateTime(0)` for a
    # part with no minmax index (an empty part, or a table with no partition key). Taking
    # min() over every part therefore reported a 56-year span on the live box, crushed the
    # measured rate, and derived the 365-day cap on a 90%-full disk. Only parts that actually
    # hold rows AND carry a real timestamp define a span; their bytes still count toward the
    # rate.
    #
    # EACH TABLE IS DIVIDED BY ITS OWN SPAN. A table keeping 7 days and one keeping 30 did not
    # write their bytes over the same interval, so summing all bytes and dividing by the union
    # span (34 days on the live box) understated the ingest by ~5x -- and an understated rate
    # derives a window that fills the disk before the TTL expires it. Bytes with no usable span
    # (an unpartitioned table) are divided by the union span: the conservative choice.
    rows = client.query(
        "SELECT table, sum(bytes_on_disk), "
        "dateDiff('second', "
        "minIf(min_time, rows > 0 AND min_time > toDateTime(0)), "
        "maxIf(max_time, rows > 0 AND max_time > toDateTime(0))) "
        "FROM system.parts "
        f"WHERE database = currentDatabase() AND active AND table IN ({listed}) "
        "GROUP BY table"
    ).result_rows
    bytes_on_disk = 0
    per_table: list[tuple[int, int]] = []
    for _name, table_bytes, table_span_s in rows:
        held = int(table_bytes or 0)
        bytes_on_disk += held
        per_table.append((held, int(table_span_s or 0)))
    span_s = max((span for _held, span in per_table), default=0)
    min_span_s = MIN_RATE_SPAN_DAYS * 86400.0
    rate = 0.0
    for held, table_span_s in per_table:
        if held <= 0:
            continue
        use_s = table_span_s if table_span_s >= min_span_s else span_s
        if use_s > 0:
            rate += held / (use_s / 86400.0)
    return Measurement(
        disk_name=chosen[0], total_bytes=chosen[1], free_bytes=chosen[2],
        bytes_on_disk=bytes_on_disk, span_days=max(0.0, span_s / 86400.0),
        rate_bytes_per_day=rate)


def _gb(value: float) -> str:
    """Bytes as GB for a sentence a person reads: 214 GB, 1.9 GB/day."""
    number = float(value) / 1_000_000_000.0
    return f"{number:,.0f}" if number >= 10 else f"{number:,.1f}"


def derive(measurement: Measurement, ratio_percent: Any = DEFAULT_RATIO_PERCENT,
           ratchet: Ratchet | None = None, *,
           max_fraction: float | None = None) -> dict[str, Any]:
    """THE ARITHMETIC, pure and testable: budget / observed rate, held inside 7..365.

    Returns the fields the UI renders, not just the answer -- the operator is entitled to see
    why the number is what it is.

    `available` is false when AUTO cannot honestly derive yet (less than a day of history, or
    no bytes observed). `budget_days` is still filled in whenever a rate was observed, because
    an EXPLICIT override is checked against it even on a young database.

    THE RATCHET IS A SECOND, HIGHER FLOOR, AND IT IS GUARDED. With a persisted floor the answer
    is `max(disk-derived, floor)` -- but only while honoring it keeps the tables' projected share
    of the VOLUME under `max_fraction` (default 0.85). Past that the floor is NOT honored: the
    answer becomes the largest window that fits, and `ratchet_guard_blocked` carries the sentence
    the Settings row, the worker log and the health check all show. A ratchet that fills the disk
    is an outage with a reassuring name, so capacity wins over policy at that line.
    """
    ratio = normalise_ratio(ratio_percent)
    free = int(measurement.free_bytes)
    budget_bytes = free * ratio / 100.0
    rate = measurement.bytes_per_day
    budget_days: int | None = None
    raw_days: float | None = None
    span_days = float(measurement.span_days)
    implausible = span_days > MAX_PLAUSIBLE_SPAN_DAYS
    if rate > 0 and not implausible:
        raw_days = budget_bytes / rate
        budget_days = int(math.floor(raw_days))

    enough_history = MIN_OBSERVATION_DAYS <= span_days <= MAX_PLAUSIBLE_SPAN_DAYS
    available = rate > 0 and enough_history
    if rate <= 0:
        reason = "no bytes have been written to the managed tables yet"
    elif implausible:
        reason = (f"the observed history spans {span_days:,.0f} days, which is longer than "
                  f"any window this control can set ({MAX_PLAUSIBLE_SPAN_DAYS:,.0f} days); "
                  f"refusing to derive from an implausible span")
    elif not enough_history:
        reason = (f"only {measurement.span_days:.2f} day(s) of history has been observed; "
                  f"a full day is needed before deriving a daily rate")
    else:
        reason = ""

    disk_days: int | None = None
    floored = False
    capped = False
    if available:
        disk_days = int(math.floor(raw_days or 0))
        if disk_days < MIN_RETENTION_DAYS:
            disk_days = MIN_RETENTION_DAYS
            floored = True
        elif disk_days > MAX_RETENTION_DAYS:
            disk_days = MAX_RETENTION_DAYS
            capped = True

    guard_fraction = max_disk_fraction() if max_fraction is None else float(max_fraction)
    capacity_max = _capacity_max_days(measurement, guard_fraction) if available else None
    days = disk_days
    ratchet_floor = int(ratchet.floor_days) if ratchet is not None else None
    guard_blocked = False
    guard_percent: float | None = None
    guard_sentence = ""
    if available and ratchet is not None and ratchet_floor is not None:
        needed = _needed_fraction(measurement, ratchet_floor)
        if ratchet_floor > int(disk_days or 0):
            if needed is not None and needed > guard_fraction:
                guard_blocked = True
                guard_percent = round(needed * 100.0, 1)
                # THE LARGER OF (DERIVED, PREVIOUS) THAT FITS. `capacity_max` is the most the
                # volume supports under the guard; the floor itself is NOT rewritten downward.
                fits = int(capacity_max or disk_days or MIN_RETENTION_DAYS)
                days = max(int(disk_days or 0), min(ratchet_floor, fits))
                days = max(MIN_RETENTION_DAYS, min(MAX_RETENTION_DAYS, days))
                guard_sentence = (
                    f"retention floor {ratchet_floor}d needs {guard_percent:.0f}% of the volume; "
                    f"holding {days}d, the most the disk supports")
            else:
                days = max(int(disk_days or 0), ratchet_floor)

    report: dict[str, Any] = {
        "mode": AUTO,
        "available": available,
        "reason": reason,
        "ratio_percent": ratio,
        "free_bytes": free,
        "total_bytes": int(measurement.total_bytes),
        "disk_name": measurement.disk_name,
        "bytes_on_disk": int(measurement.bytes_on_disk),
        "span_days": round(float(measurement.span_days), 3),
        "bytes_per_day": round(rate, 1),
        "budget_bytes": int(budget_bytes),
        "budget_days": budget_days,
        "raw_days": round(raw_days, 2) if raw_days is not None else None,
        # `disk_days` is what free space alone supports (the old `days`); `days` is the EFFECTIVE
        # window after the ratchet and its guard. Both are shipped because the row has to explain
        # the difference, and an operator cannot check a number that has no counterfactual.
        "disk_days": disk_days,
        "days": days,
        "floored": floored,
        "capped": capped,
        "min_days": MIN_RETENTION_DAYS,
        "max_days": MAX_RETENTION_DAYS,
        # -- the ratchet and the capacity guard
        "ratchet_floor_days": ratchet_floor,
        "ratchet_set_at": ratchet.set_at if ratchet is not None else "",
        "ratchet_set_on": ratchet.set_on if ratchet is not None else "",
        "ratchet_by": ratchet.by if ratchet is not None else "",
        "ratchet_reason": ratchet.reason if ratchet is not None else "",
        "ratchet_active": bool(ratchet_floor is not None and days is not None
                               and int(days) > int(disk_days or 0)),
        "ratchet_guard_blocked": guard_blocked,
        "ratchet_guard_percent": guard_percent,
        "capacity_max_days": capacity_max,
        "max_disk_fraction": guard_fraction,
        "guard_sentence": guard_sentence,
    }
    report["sentence"] = _sentence(report)
    return report


def _sentence(report: dict[str, Any]) -> str:
    """The one line the Settings row shows. It states the arithmetic, not only the result.

    WITH A RATCHET THE FLOOR AND ITS DATE RIDE IN THE SAME SENTENCE AS THE NUMBER -- not in a
    tooltip and not on a second row. When the capacity guard refuses the floor, the sentence
    says so there too: the operator must not have to infer a held window from a number that
    silently stopped matching the stored floor.
    """
    if not report["available"]:
        return f"Auto — not derived yet: {report['reason']}. The tables keep their current TTL."
    days = report["days"]
    free = _gb(report["free_bytes"])
    rate = _gb(report["bytes_per_day"])
    ratio = report["ratio_percent"]
    floor = report.get("ratchet_floor_days")
    if floor:
        since = report.get("ratchet_set_on") or report.get("ratchet_set_at", "")[:10]
        if report.get("ratchet_guard_blocked"):
            note = (f"ratchet floor {floor}d since {since} needs "
                    f"{report['ratchet_guard_percent']:.0f}% of the volume; holding {days}d, "
                    f"the most the disk supports")
        else:
            note = (f"ratchet floor {floor}d since {since}; "
                    f"disk supports {report['disk_days']}d")
        return (f"Auto — {days} days ({note}). {free} GB free at {rate} GB/day "
                f"({ratio}% budget). Merge headroom kept.")
    if report["floored"]:
        return (f"Auto — disk supports {report['raw_days']:.1f} days; holding the "
                f"{MIN_RETENTION_DAYS}-day floor. ({free} GB free at {rate} GB/day, "
                f"{ratio}% budget.)")
    if report["capped"]:
        return (f"Auto — {days} days, capped at {MAX_RETENTION_DAYS}, from {free} GB free at "
                f"{rate} GB/day ({ratio}% budget). Merge headroom kept.")
    return (f"Auto — {days} days from {free} GB free at {rate} GB/day ({ratio}% budget). "
            f"Merge headroom kept.")


def unavailable(reason: str) -> dict[str, Any]:
    """An auto report for a deployment whose disk could not be measured at all."""
    text = f"Auto — could not read the disk budget: {reason}. The tables keep their current TTL."
    return {
        "mode": AUTO, "available": False, "reason": reason,
        "ratio_percent": None, "free_bytes": None, "total_bytes": None, "disk_name": "",
        "bytes_on_disk": None, "span_days": None, "bytes_per_day": None,
        "budget_bytes": None, "budget_days": None, "raw_days": None,
        "disk_days": None, "days": None,
        "floored": False, "capped": False,
        "min_days": MIN_RETENTION_DAYS, "max_days": MAX_RETENTION_DAYS,
        "ratchet_floor_days": None, "ratchet_set_at": "", "ratchet_set_on": "",
        "ratchet_by": "", "ratchet_reason": "", "ratchet_active": False,
        "ratchet_guard_blocked": False, "ratchet_guard_percent": None,
        "capacity_max_days": None, "max_disk_fraction": max_disk_fraction(),
        "guard_sentence": "",
        "sentence": text,
    }


def auto_report(client: Any, ratio_percent: Any = DEFAULT_RATIO_PERCENT,
                ratchet: Ratchet | None = None) -> dict[str, Any]:
    """Measure, derive, and never raise: an unreadable disk is a state the UI can explain."""
    try:
        return derive(measure(client), ratio_percent, ratchet)
    except Exception as exc:  # noqa: BLE001 - a failed measurement is reported, not fatal
        logger.warning("retention: could not measure the disk budget: %s", exc)
        return unavailable(f"{type(exc).__name__}: {str(exc)[:160]}")


def manual_report(days: int, ratio_percent: Any = DEFAULT_RATIO_PERCENT,
                  ratchet: Ratchet | None = None) -> dict[str, Any]:
    """The report shape for an explicit value, so both modes render the same fields.

    A MANUAL VALUE IS NOT HELD TO THE FLOOR -- the operator typed it, and the apply path has
    already made them acknowledge a reset when it is below the floor. The row still NAMES the
    floor, because switching back to auto will start from it and the operator should be able to
    see that before they switch.
    """
    want = normalise_days(days)
    floor = ratchet.floor_days if ratchet is not None else None
    sentence = f"Manual — {want} days, chosen rather than derived from free disk."
    if ratchet is not None:
        sentence = (f"Manual — {want} days (ratchet floor {floor}d since "
                    f"{ratchet.set_on}); an explicit value is not held to it.")
    return {
        "mode": "manual", "available": True, "reason": "",
        "ratio_percent": normalise_ratio(ratio_percent),
        "free_bytes": None, "total_bytes": None, "disk_name": "",
        "bytes_on_disk": None, "span_days": None, "bytes_per_day": None,
        "budget_bytes": None, "budget_days": None, "raw_days": None,
        "disk_days": want, "days": want,
        "floored": False, "capped": False,
        "min_days": MIN_RETENTION_DAYS, "max_days": MAX_RETENTION_DAYS,
        "ratchet_floor_days": floor, "ratchet_set_at": ratchet.set_at if ratchet else "",
        "ratchet_set_on": ratchet.set_on if ratchet else "",
        "ratchet_by": ratchet.by if ratchet else "", "ratchet_reason": ratchet.reason if ratchet else "",
        "ratchet_active": False, "ratchet_guard_blocked": False,
        "ratchet_guard_percent": None, "capacity_max_days": None,
        "max_disk_fraction": max_disk_fraction(), "guard_sentence": "",
        "sentence": sentence,
    }


def resolve(client: Any, setting: Any, ratio_percent: Any = DEFAULT_RATIO_PERCENT,
            ratchet: Ratchet | None = None) -> tuple[int | None, dict[str, Any]]:
    """(days to apply or None, the report the UI renders) for one setting value."""
    if is_auto(setting):
        report = auto_report(client, ratio_percent, ratchet)
        days = report["days"] if report.get("available") else None
        return days, report
    want = normalise_days(setting)
    return want, manual_report(want, ratio_percent, ratchet)


def budget_refusal(days: int, report: dict[str, Any]) -> str:
    """'' when an explicit value fits the measured budget, else the sentence that refuses it.

    `budget_days` is the DERIVED budget before the 7-day floor: a disk that supports 3 days
    still allows the floor of 7 (the policy minimum), but nothing above it.
    """
    budget = report.get("budget_days")
    if budget is None:
        return ""
    allowed = max(MIN_RETENTION_DAYS, int(budget))
    if int(days) <= allowed:
        return ""
    return (
        f"{days} days is more than this disk can hold: with {_gb(report['free_bytes'])} GB free, "
        f"{_gb(report['bytes_per_day'])} GB/day observed and a {report['ratio_percent']}% budget, "
        f"the measured budget is {budget} day(s). Choose {allowed} or fewer, or set it to auto."
    )


# ── reading and converging the tables ─────────────────────────────────────────────────────────


@dataclass(frozen=True)
class EffectiveTTL:
    """What the cluster ACTUALLY has for one table, parsed from its own DDL."""

    table: str
    days: int | None
    expression: str


# `create_table_query` is the query ClickHouse stored, so the table-level TTL is the LAST
# `TTL` keyword in it (column-level TTLs come earlier, inside the column list).
_TTL_WORD = re.compile(r"\bTTL\b", re.IGNORECASE)
_INTERVAL = re.compile(
    r"\bINTERVAL\s+(\d+)\s+(SECOND|MINUTE|HOUR|DAY|WEEK|MONTH|QUARTER|YEAR)\b", re.IGNORECASE)
# ClickHouse NORMALISES `INTERVAL 365 DAY` to `toIntervalDay(365)` in `create_table_query`.
# Reading only the first form made every table this control had ever written "unreadable",
# which is how a read failure became a re-ALTER on every worker start. Both forms are the same
# TTL and both must parse.
_INTERVAL_FN = re.compile(
    r"\btoInterval(Second|Minute|Hour|Day|Week|Month|Quarter|Year)\(\s*(\d+)\s*\)",
    re.IGNORECASE)
_UNIT_DAYS = {"DAY": 1, "WEEK": 7, "MONTH": 30, "QUARTER": 90, "YEAR": 365}


def parse_ttl(create_table_query: str) -> tuple[int | None, str]:
    """(days, expression) from a table's stored DDL. Days is None when it cannot be read.

    A None is reported as a mismatch, never as "fine": a TTL this function cannot understand
    is a TTL nobody has verified. Both the SQL spelling (`INTERVAL 7 DAY`) and the form
    ClickHouse stores back (`toIntervalDay(7)`) are understood; a table is not "unreadable"
    merely because the server normalised its own DDL.
    """
    body = (create_table_query or "").strip().rstrip(";").strip()
    found = list(_TTL_WORD.finditer(body))
    if not found:
        return None, ""
    clause = body[found[-1].start():].split(";", 1)[0].strip()
    expression = clause[3:].strip() if clause[:3].upper() == "TTL" else clause
    match = _INTERVAL.search(expression)
    if match:
        count = int(match.group(1))
        unit = match.group(2).upper()
    else:
        match = _INTERVAL_FN.search(expression)
        if not match:
            return None, expression
        unit = match.group(1).upper()
        count = int(match.group(2))
    if unit in ("SECOND", "MINUTE", "HOUR"):
        # A sub-day TTL is legal but not what this control writes. Reporting 0 would read as
        # "immediately expired"; report it unreadable instead.
        return None, expression
    return count * _UNIT_DAYS[unit], expression


def effective_ttls(client: Any, names: tuple[str, ...] | None = None) -> dict[str, EffectiveTTL]:
    """The TTL of every managed table, read from `system.tables`.

    READS WHAT THE CLUSTER HAS, not what a call asked for. `create_table_query` is used
    rather than an inferred default because it is the only column that reports a table-level
    TTL on every ClickHouse version this project pins.
    """
    wanted = tuple(names or table_names())
    if not wanted:
        return {}
    listed = ", ".join("'" + _checked(name) + "'" for name in wanted)
    sql = (
        "SELECT name, create_table_query FROM system.tables "
        f"WHERE database = currentDatabase() AND name IN ({listed})"
    )
    out: dict[str, EffectiveTTL] = {}
    for row in client.query(sql).result_rows:
        name = str(row[0])
        days, expression = parse_ttl(str(row[1] or ""))
        out[name] = EffectiveTTL(table=name, days=days, expression=expression)
    return out


def days_in_force(client: Any, names: tuple[str, ...] | None = None) -> dict[str, Any]:
    """The retention the TABLES actually keep, read from their own DDL.

    THE TTL IS WHAT THIS MODULE DERIVED. `converge()` writes the derived window onto every
    managed table with `ALTER TABLE ... MODIFY TTL`, so reading the TTL back is reading the value
    this module produced -- and it is the value that decides which rows still exist. Re-deriving
    on a read path would report a window the cluster has not applied yet: measured on the live
    box (2026-11-20) `derive()` answered 289 days while every managed table still kept 258.

    The answer is the SMALLEST window among `names`, because a baseline may only be as long as
    the shortest table it reads. A table whose TTL cannot be read is reported in `unknown` and
    never raises the answer: the minimum of the known windows is the conservative cap, and an
    unreadable TTL must not become an unlimited lookback. `days` is None only when NO table's
    TTL could be read; the caller decides what floor to fall back to.
    """
    wanted = tuple(names or table_names())
    if not wanted:
        return {"days": None, "source": "unreadable", "tables": {}, "unknown": [],
                "reason": "no table was named"}
    try:
        read = effective_ttls(client, wanted)
    except Exception as exc:  # noqa: BLE001 - an unreadable schema is a state, not a crash
        return {"days": None, "source": "unreadable", "tables": {}, "unknown": list(wanted),
                "reason": f"{type(exc).__name__}: {str(exc)[:160]}"}
    known = {name: int(ttl.days) for name, ttl in read.items() if ttl.days is not None}
    unknown = [name for name in wanted if name not in known]
    if not known:
        return {"days": None, "source": "unreadable", "tables": {}, "unknown": unknown,
                "reason": "no table-level TTL could be read from create_table_query"}
    return {
        "days": min(known.values()),
        "source": "system.tables TTL",
        "tables": known,
        "unknown": unknown,
        "reason": "",
    }


def not_derived_report(report: dict[str, Any]) -> dict[str, Any]:
    """The report for a converged-nothing pass: auto has no honest number yet."""
    return {
        "ok": True, "applied": False, "requested_days": None, "derivation": report,
        "tables": [], "changed": [], "failed": [], "failed_reasons": {},
        "unreadable": [], "unreadable_reasons": {}, "bound_days": None,
        "missing": [], "mismatched": [],
        "summary": report.get("sentence") or "retention was not derived",
    }


def converge(client: Any, days: Any, *, derivation: dict[str, Any] | None = None,
             bound_days: int | None = None) -> dict[str, Any]:
    """Set every managed table's TTL to `days`, then read back what the cluster has.

    IDEMPOTENT: a table already at the wanted TTL is left alone, so the startup path does not
    churn table metadata on every restart.

    A FAILED ALTER IS NAMED, NOT SWALLOWED, and the table keeps its previous TTL: the loop
    records the failure and continues, because one unwritable table must not leave the other
    fifteen on an old window.

    AN UNREADABLE TTL IS NOT A REASON TO CHOOSE ONE. A table whose current TTL cannot be read
    or parsed gets NO ALTER at all: it keeps exactly the TTL it has, and the receipt records
    `NOT CHANGED: TTL unreadable` with the DDL fragment that could not be understood. Inventing
    a fallback here (365 days was the old behaviour) turns a read failure into a disk-filling
    setting, so there is deliberately no fallback value in this function or in `alter_sql`.

    Every ALTER is bounded by `bound_days` (the derived window when the caller has one). The
    read-back afterwards is what makes the report true.
    """
    want = normalise_days(days)
    bound = MAX_RETENTION_DAYS if bound_days is None else min(int(bound_days), MAX_RETENTION_DAYS)
    if derivation:
        # THE DERIVATION ALWAYS WINS over a caller-supplied bound. If the receipt says 40 days,
        # no argument can make converge emit 365.
        derived = derivation.get("days")
        if isinstance(derived, int) and derived >= MIN_RETENTION_DAYS:
            bound = min(bound, derived, MAX_RETENTION_DAYS)
    if want > bound:
        raise ValueError(
            f"refusing to converge on {want} days: the derived window is {bound} day(s), "
            f"and an interval may never exceed it")

    before = effective_ttls(client)
    changed: list[str] = []
    failed: dict[str, str] = {}
    unreadable: dict[str, str] = {}
    for table in RETENTION_TABLES:
        current = before.get(table.name)
        if current is None:
            # No row in system.tables: there is nothing to ALTER. Recorded, not guessed at.
            continue
        if current.days is None:
            # NEVER CHOOSE A VALUE ON FAILURE. Leave the TTL exactly as it is.
            unreadable[table.name] = (current.expression
                                      or "no table-level TTL clause in create_table_query")
            logger.warning("retention: %s TTL unreadable (%s); leaving it unchanged",
                           table.name, unreadable[table.name])
            continue
        if current.days == want:
            continue
        try:
            client.command(alter_sql(table, want, max_days=bound))
        except Exception as exc:  # noqa: BLE001 - one table must not stop the rest
            failed[table.name] = f"{type(exc).__name__}: {str(exc)[:160]}"
            logger.warning("retention: could not set %s to %s days: %s", table.name, want, exc)
            continue
        changed.append(table.name)
        logger.info("retention: %s TTL %sd -> %sd", table.name, current.days, want)

    after = effective_ttls(client)
    rows: list[dict[str, Any]] = []
    rows_mismatched: list[str] = []
    missing: list[str] = []
    for table in RETENTION_TABLES:
        effective = after.get(table.name)
        error = failed.get(table.name, "")
        if effective is None:
            missing.append(table.name)
            error = error or "NOT CHANGED: table absent from the deployment database"
            ok = False
        elif table.name in unreadable:
            # The table was not touched, so the read-back is expected to still be unreadable.
            got = ("unreadable" if effective.days is None else f"{effective.days} days")
            error = f"NOT CHANGED: TTL unreadable ({unreadable[table.name]}); cluster reports {got}"
            ok = False
            if table.name not in rows_mismatched:
                rows_mismatched.append(table.name)
        else:
            ok = effective.days == want
            if not ok and not error:
                got = "unreadable" if effective.days is None else f"{effective.days} days"
                error = f"the cluster reports {got}, not {want}"
            if not ok:
                rows_mismatched.append(table.name)
        rows.append({
            "table": table.name,
            "column": table.column,
            "requested_days": want,
            "effective_days": None if effective is None else effective.days,
            "expression": "" if effective is None else effective.expression,
            "changed": table.name in changed,
            "ok": ok,
            "error": error,
        })

    result = {
        "ok": not (failed or missing or unreadable or rows_mismatched),
        "applied": bool(changed),
        "requested_days": want,
        "derivation": derivation or {},
        "tables": rows,
        "changed": changed,
        "failed": sorted(failed),
        "failed_reasons": failed,
        "unreadable": sorted(unreadable),
        "unreadable_reasons": unreadable,
        "missing": missing,
        "mismatched": rows_mismatched,
        "bound_days": bound,
    }
    result["summary"] = _summary(result)
    return result


def _summary(report: dict[str, Any]) -> str:
    """One sentence an operator (and a log line) can act on."""
    total = len(report["tables"])
    want = report["requested_days"]
    if report["ok"]:
        return f"all {total} table(s) keep {want} days"
    parts = [f"{len(report['changed'])} of {total} table(s) set to {want} days"]
    if report["failed"]:
        parts.append("ALTER failed for " + ", ".join(report["failed"]))
    if report.get("unreadable"):
        parts.append("NOT CHANGED (TTL unreadable): " + ", ".join(report["unreadable"]))
    if report["missing"]:
        parts.append("absent: " + ", ".join(report["missing"]))
    unexplained = [t for t in report["mismatched"]
                   if t not in report["failed"] and t not in report.get("unreadable", [])]
    if unexplained:
        parts.append("read-back disagrees for " + ", ".join(unexplained))
    return "; ".join(parts)


def ensure(client: Any, setting: Any = None, ratio_percent: Any = None, *,
           model_dir: Any = None, reset_record: Any = None) -> dict[str, Any]:
    """The startup migration: derive from CURRENT disk/history, converge, and report.

    A retention pass must not be the reason a worker refuses to start -- a wrong TTL costs
    history, while a crash-looping detector costs every alert. Failures are logged loudly
    with the table named, and the returned report says what the cluster actually has.

    THE RATCHET IS READ, RAISED AND WRITTEN HERE. `model_dir` names the worker-owned state
    directory (`MODEL_DIR`); `reset_record` is the operator's ConfigMap record when the pod's
    env carries one. A newer operator record wins, so a reset takes effect on the next start
    even though this process cannot write the ConfigMap. A derived window ABOVE the floor is
    persisted; a floor that the capacity guard refuses is NOT lowered -- the effective window
    is held at what fits and the refusal is logged at WARNING.
    """
    raw_setting = AUTO if setting is None else setting
    raw_ratio = DEFAULT_RATIO_PERCENT if ratio_percent is None else ratio_percent

    file_state, ratchet_error = load_ratchet(model_dir)
    operator_state = ratchet_from_json(reset_record)
    state = latest_ratchet(file_state, operator_state)
    previous_floor = state.floor_days if state is not None else None
    # A NEWER OPERATOR RECORD IS CONSUMED INTO THE FILE, so deleting the ConfigMap key later
    # cannot resurrect a floor the operator explicitly reset.
    if (model_dir is not None and state is not None and file_state != state):
        error = save_ratchet(model_dir, state)
        if error:
            ratchet_error = ratchet_error or error
            logger.warning("retention: could not record the ratchet: %s", error)

    try:
        days, derivation = resolve(client, raw_setting, raw_ratio, ratchet=state)
    except ValueError as exc:
        logger.warning("retention: %s; leaving every table's TTL unchanged", exc)
        report = unavailable(str(exc))
        return not_derived_report(report) | {"ok": False, "error": str(exc)}
    if days is None:
        report = not_derived_report(derivation)
        logger.info("retention: %s", report["summary"])
        return report

    # ── THE FLOOR RISES HERE, AND ONLY HERE, ON ITS OWN ──────────────────────────────────────
    # A fresh deployment with no file SEEDS from what the tables already keep, so upgrading to
    # the ratchet cannot shorten the window on the very pass that introduces it. From then on
    # a larger derivation raises the floor; a smaller one never lowers it.
    raised: Ratchet | None = None
    if model_dir is not None:
        desired: int | None = None
        if state is None:
            if is_auto(raw_setting):
                # The tables' own TTL is the best evidence of the window that was in force
                # before this version. Reading it is optional: a failed read seeds from the
                # derivation alone rather than inventing history.
                in_force: int | None = None
                try:
                    in_force = days_in_force(client).get("days")
                except Exception as exc:  # noqa: BLE001 - seeding is best-effort
                    logger.debug("retention: could not read the tables' current TTL: %s", exc)
                disk_days = derivation.get("disk_days")
                desired = max(int(disk_days or days),
                              int(in_force) if isinstance(in_force, int) else 0)
            else:
                desired = int(days)
            raised = new_ratchet(desired, by="auto")
        elif is_auto(raw_setting):
            disk_days = derivation.get("disk_days")
            if isinstance(disk_days, int) and disk_days > int(state.floor_days):
                raised = new_ratchet(disk_days, by="auto")
        elif int(days) > int(state.floor_days):
            raised = new_ratchet(int(days), by="auto")
        if raised is not None:
            error = save_ratchet(model_dir, raised)
            if error:
                ratchet_error = ratchet_error or error
                logger.warning("retention: the floor rose to %sd but could not be recorded: %s",
                               raised.floor_days, error)
            else:
                logger.info("retention: ratchet floor %s -> %sd (set %s)",
                            previous_floor if previous_floor is not None else "none",
                            raised.floor_days, raised.set_on)
                state = raised

    if derivation.get("ratchet_guard_blocked"):
        # A VISIBLE CONDITION, not a quiet clamp: the Settings row, this log and the health
        # check all carry the same sentence.
        logger.warning("retention: %s", derivation.get("guard_sentence"))

    try:
        result = converge(client, days, derivation=derivation, bound_days=days)
    except Exception as exc:  # noqa: BLE001 - see the docstring
        logger.warning("retention: the migration could not run: %s", exc)
        return not_derived_report(unavailable(str(exc))) | {"ok": False, "error": str(exc)}
    result["ratchet"] = {
        "previous_floor_days": previous_floor,
        "floor_days": state.floor_days if state is not None else None,
        "set_at": state.set_at if state is not None else "",
        "set_on": state.set_on if state is not None else "",
        "by": state.by if state is not None else "",
        "reason": state.reason if state is not None else "",
        "raised": raised is not None,
        "guard_blocked": bool(derivation.get("ratchet_guard_blocked")),
        "error": ratchet_error,
    }
    if result["ok"]:
        logger.info("retention: %s (%s)", result["summary"], derivation.get("sentence", ""))
    else:
        logger.warning("retention: %s", result["summary"])
    return result


__all__ = ["AUTO", "DEFAULT_MAX_DISK_FRACTION", "DEFAULT_RATIO_PERCENT", "MAX_DISK_FRACTION_ENV",
           "MAX_RATIO_PERCENT", "MAX_RETENTION_DAYS", "MIN_OBSERVATION_DAYS", "MIN_RATIO_PERCENT",
           "MIN_RETENTION_DAYS", "NEVER_EXPIRE", "RATCHET_FILE", "RETENTION_DAYS_KEY",
           "RETENTION_RATCHET_KEY", "RETENTION_RATIO_KEY", "RETENTION_TABLES", "Ratchet",
           "UNMANAGED", "EffectiveTTL", "Measurement", "RetentionTable", "alter_sql",
           "auto_report", "budget_refusal", "converge", "days_in_force", "derive",
           "effective_ttls", "ensure", "is_auto", "latest_ratchet", "load_ratchet",
           "manual_report", "max_disk_fraction", "measure", "new_ratchet", "normalise_days",
           "normalise_ratio", "not_derived_report", "parse_ttl", "ratchet_from_json",
           "ratchet_path", "resolve", "save_ratchet", "table_names", "unavailable"]
