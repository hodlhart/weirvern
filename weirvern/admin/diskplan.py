"""Disk budgeting and log rotation for the sensor host.

THE PROBLEM THIS SOLVES, measured on the test box: Zeek rotates its logs hourly
(`Log::default_rotation_interval=1hr`) but NOTHING ever deletes the rotated files. The
directory reached 87 files / 11 MB after a few hours of light traffic and grows about
7 MB/hour -- on a 40 GB disk. On a busy network `dns.log` alone ran to 2.3 MB/hour, and
the same applies to the flow sink and to ClickHouse's own data.

Zeek's rotation is bounded in TIME but unbounded in SPACE. A sensor that fills its disk
stops capturing, and a full disk also takes ClickHouse down -- so this is a
availability defect, not housekeeping.

WHAT SETUP SHOULD DO: detect the disk, offer a cap per component, and recommend a value
derived from the actual disk size rather than a number chosen arbitrarily. An operator
who fills a 40 GB disk with `dns.log` in a fortnight will blame the tool, and be right.

WHY THREE SEPARATE BUDGETS: they have different growth characteristics and different
value-per-byte, so one shared number would either starve the useful one or let the
noisy one dominate.
  * zeek    -- highest volume per unit of time, shortest useful life
  * netflow -- the goflow2 JSONL sink; raw flows, mostly valuable in the last day
  * ml      -- ClickHouse tables, the only component whose retention is a compliance
               decision as well as a capacity one
"""
from __future__ import annotations

import os
import shutil
from dataclasses import dataclass, field

# Fractions of the AVAILABLE disk offered to each component when the operator takes the
# recommendation. These are deliberately modest: a sensor that consumes most of a host's
# disk has traded one outage for another, and the host still needs room for its own
# logs, the container runtime and ClickHouse's merges (which can transiently need as much
# free space as the data being merged).
RECOMMENDED_SHARE = {
    "zeek": 0.10,
    "netflow": 0.05,
    "ml": 0.25,
}

# TARGET RETENTION, in days, for each component. This is what genuinely sizes a cap,
# and a bare percentage of free space does not: asking for 25% of a 1.6 TB disk produced
# a 414 GB recommendation for ClickHouse -- 35,000 days of history at the observed rate,
# which is not a recommendation but noise. Sizing from the retention we actually want
# gives a defensible number, and the free-space share then acts as a CEILING on a small
# disk rather than as the answer.
#
#   zeek     7 days  rotated text; valuable recent, mostly superseded after a week
#   netflow  3 days  raw flows, re-aggregated into ClickHouse MVs almost immediately
#   ml      90 days  ClickHouse tables; the longest TTL we ship is 90 days, so a cap
#                    shorter than this would silently truncate the retention policy
TARGET_RETENTION_DAYS = {
    "zeek": 7,
    "netflow": 3,
    "ml": 90,
}

# Headroom multiplier over the computed retention size, to absorb bursts and growth
# without the sensor deleting data it just wrote.
HEADROOM_FACTOR = 2.0

# Absolute floor per component. A cap below this is not a budget, it is a broken
# deployment: Zeek would delete logs faster than one rotation produces them, so a hunt
# could never see more than minutes of history.
FLOOR_MB = {
    "zeek": 512,
    "netflow": 256,
    "ml": 1024,
}

# Absolute ceiling per component, so a recommendation never swallows a whole large disk.
# A 4 TB NAS should not hand 1 TB to Zeek text logs.
CEILING_MB = {
    "zeek": 50 * 1024,
    "netflow": 20 * 1024,
    "ml": 500 * 1024,
}

# Rough observed growth, for a time-to-fill estimate in the setup output. Deliberately
# pessimistic: telling an operator "this lasts a fortnight" when it lasts three days is
# the kind of estimate that destroys trust in the tool.
#   dns.log dominated: 2.3 MB/hour of rotated text on light traffic, plus conn/ssl/http
#   and the odd bursts, measured at ~7 MB/hour total.
OBSERVED_MB_PER_HOUR = {
    "zeek": 7.0,
    "netflow": 1.2,      # goflow2 JSONL on the same light traffic
    "ml": 0.5,           # ClickHouse rows, highly dependent on flow cardinality
}


@dataclass
class DiskBudget:
    """A per-component cap, in MB, plus what it means in time."""

    component: str
    cap_mb: int
    path: str = ""
    used_mb: int = 0
    recommended_mb: int = 0
    reason: str = ""

    @property
    def hours_of_history(self) -> float | None:
        """Estimated hours of retained data at the observed growth rate.

        Returns None when the growth rate is unknown rather than guessing, because a
        fabricated estimate is worse than an absent one.
        """
        rate = OBSERVED_MB_PER_HOUR.get(self.component)
        if not rate or self.cap_mb <= 0:
            return None
        return self.cap_mb / rate

    @property
    def human_history(self) -> str:
        h = self.hours_of_history
        if h is None:
            return "unknown"
        if h < 48:
            return f"{h:.0f} hours"
        return f"{h / 24:.0f} days"


@dataclass
class DiskReport:
    total_mb: int
    used_mb: int
    available_mb: int
    mount: str = ""
    budgets: dict[str, DiskBudget] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    @property
    def allocated_mb(self) -> int:
        return sum(b.cap_mb for b in self.budgets.values())

    @property
    def headroom_mb(self) -> int:
        return self.available_mb - self.allocated_mb


def human_mb(mb: float) -> str:
    """Format MB as the unit a human would say."""
    if mb >= 1024 * 1024:
        return f"{mb / 1024 / 1024:.1f} TB"
    if mb >= 1024:
        return f"{mb / 1024:.1f} GB"
    return f"{mb:.0f} MB"


def _clamp(value: int, lo: int, hi: int) -> int:
    return max(lo, min(hi, value))


def retention_sized_mb(component: str) -> float:
    """How much space the target retention window needs, plus headroom.

    Derived from the observed growth rate, so it reflects what this software actually
    writes rather than a guess.
    """
    rate = OBSERVED_MB_PER_HOUR.get(component, 1.0)
    days = TARGET_RETENTION_DAYS.get(component, 7)
    return rate * 24 * days * HEADROOM_FACTOR


def recommend_cap(component: str, available_mb: int) -> int:
    """A sensible cap for one component given the free space.

    The recommendation is the SMALLER of two things:
      * what the target retention window needs, sized from the observed growth rate
      * the component's share of free space, which stops a small disk being
        over-committed

    On a large disk the retention figure binds and produces a defensible number; on a
    small disk the share binds and the caller is warned that retention will be shorter
    than target. Previously only the share was used, which recommended 414 GB for
    ClickHouse on a 1.6 TB disk -- a number with no relationship to what would ever be
    written.

    Clamped at both ends: the floor because a cap smaller than one rotation's output
    makes the sensor delete data it just wrote, the ceiling so a very large disk is not
    handed wholesale to text logs.
    """
    share_cap = int(available_mb * RECOMMENDED_SHARE.get(component, 0.05))
    want = int(retention_sized_mb(component))
    raw = min(want, share_cap) if share_cap > 0 else want
    return _clamp(raw, FLOOR_MB.get(component, 256), CEILING_MB.get(component, 50 * 1024))


def probe_disk(path: str = "/") -> tuple[int, int, int, str]:
    """(total_mb, used_mb, available_mb, mount) for the filesystem holding `path`.

    Uses the nearest EXISTING parent so this works before the sensor directories have
    been created -- which is the normal case at install time, and the reason a naive
    statvfs on the target path would fail exactly when the answer is needed.
    """
    probe = path
    while probe and not os.path.exists(probe):
        parent = os.path.dirname(probe.rstrip("/"))
        if parent == probe:
            break
        probe = parent or "/"
    try:
        usage = shutil.disk_usage(probe)
    except OSError:
        return 0, 0, 0, ""
    to_mb = 1024 * 1024
    # Resolve to the actual mount point so the report names a filesystem rather than
    # whatever subdirectory was asked about.
    mount = probe
    try:
        with open("/proc/mounts") as fh:
            best = ""
            for line in fh:
                parts = line.split()
                if len(parts) >= 2 and probe.startswith(parts[1]) and len(parts[1]) > len(best):
                    best = parts[1]
            if best:
                mount = best
    except OSError:
        pass
    return usage.total // to_mb, usage.used // to_mb, usage.free // to_mb, mount


def plan(available_mb: int, total_mb: int = 0, current: dict[str, int] | None = None
         ) -> DiskReport:
    """Build a budget report for the three components.

    `current` lets an operator's existing caps be reported alongside the recommendation,
    so `weirvern disk` can show what is configured versus what would be suggested without
    silently changing anything.
    """
    current = current or {}
    report = DiskReport(total_mb=total_mb or available_mb, used_mb=0,
                        available_mb=available_mb)

    for component in ("zeek", "netflow", "ml"):
        rec = recommend_cap(component, available_mb)
        cap = int(current.get(component) or rec)
        b = DiskBudget(component=component, cap_mb=cap, recommended_mb=rec)
        target_days = TARGET_RETENTION_DAYS.get(component, 7)
        if component in current:
            b.reason = "set by the operator"
        elif cap < retention_sized_mb(component):
            # The disk could not give what we would have asked for, which is a fact the
            # operator needs: the retention policy will be cut short.
            b.reason = (f"limited by disk ({int(RECOMMENDED_SHARE[component] * 100)}% of "
                        f"free); target was {target_days} days")
        else:
            b.reason = f"recommended (holds ~{target_days} days at the observed rate)"
        report.budgets[component] = b

    # A plan that allocates more than is free is not a plan. This is checked rather than
    # assumed because recommendations are clamped and the clamps can collectively exceed
    # a small disk.
    if report.allocated_mb > available_mb:
        report.warnings.append(
            f"the caps total {human_mb(report.allocated_mb)} but only "
            f"{human_mb(available_mb)} is free; reduce a cap or add disk"
        )
    if available_mb and report.allocated_mb > available_mb * 0.6:
        report.warnings.append(
            f"the caps would use {report.allocated_mb / available_mb:.0%} of free space, "
            f"leaving little for ClickHouse merges and the container runtime"
        )
    for name, b in report.budgets.items():
        if name in current:
            continue          # an explicit choice is not second-guessed
        target_days = TARGET_RETENTION_DAYS.get(name, 7)
        if b.hours_of_history is not None and b.hours_of_history < target_days * 24 * 0.5:
            report.warnings.append(
                f"the {name} cap holds only ~{b.human_history}; the target is "
                f"{target_days} days. Raise {name.upper()}_MAX_MB or add disk."
            )

    # The ClickHouse caveat is worth stating once, prominently: it is the failure that
    # looks like a database problem and is actually a capacity problem.
    report.warnings.append(
        "ClickHouse can transiently need as much free space as the data it is merging; "
        "a cap that leaves no headroom shows up as failed merges, not as a full disk"
    )
    return report


def default_caps_from_env() -> dict[str, int]:
    """Read existing caps from the environment, if any.

    Names the keys after the components so `.env` reads plainly and the three caps sit
    together. Zero or absent means 'not set', which makes them eligible for the
    recommendation.
    """
    out = {}
    for key, comp in (("ZEEK_MAX_MB", "zeek"), ("NETFLOW_MAX_MB", "netflow"),
                      ("ML_MAX_MB", "ml")):
        raw = (os.environ.get(key) or "").strip()
        if raw.isdigit() and int(raw) > 0:
            out[comp] = int(raw)
    return out


# ---------------------------------------------------------------------------
# the rotation policy the sensor should apply
# ---------------------------------------------------------------------------
@dataclass
class RotationPolicy:
    """How many rotated files to keep, derived from a byte cap.

    Zeek cannot delete by size -- it rotates by interval and keeps a fixed FILE COUNT.
    So a byte cap has to be translated into a count, and the count has to be based on
    the observed size PER ROTATION for this deployment rather than a guessed average.
    Getting that wrong is how a "1 GB cap" silently keeps 20 GB.
    """

    component: str
    cap_mb: int
    rotation_interval_s: int
    mb_per_rotation: float

    @property
    def keep(self) -> int:
        """How many rotated files fit in the cap.

        At least 2: keeping one file means a rotation can destroy the only copy of the
        current interval, and a hunt that spans a rotation boundary would find a gap.
        """
        if self.mb_per_rotation <= 0:
            return 2
        return max(2, int(self.cap_mb / self.mb_per_rotation))

    @property
    def actual_cap_mb(self) -> float:
        """What the FILE-COUNT policy really allocates, which may exceed the byte cap.

        Reported so the operator sees the true figure: `keep` is an integer, so a 700 MB
        cap with 300 MB rotations becomes 3 files = 900 MB. Showing the requested cap
        without this is how the disk fills unexpectedly.
        """
        return self.keep * self.mb_per_rotation


def rotation_policy(component: str, cap_mb: int, interval_s: int = 3600,
                    mb_per_rotation: float | None = None) -> RotationPolicy:
    """Translate a byte cap into Zeek's file-count terms.

    `mb_per_rotation` should come from measuring the deployment. The default derives from
    the observed hourly rate, which is the right ballpark for Zeek's default 1-hour
    rotation but is explicitly an estimate.
    """
    if mb_per_rotation is None:
        rate = OBSERVED_MB_PER_HOUR.get(component, 1.0)
        mb_per_rotation = rate * (interval_s / 3600.0)
    return RotationPolicy(component=component, cap_mb=cap_mb,
                          rotation_interval_s=interval_s,
                          mb_per_rotation=mb_per_rotation)
