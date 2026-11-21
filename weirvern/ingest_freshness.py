"""Is the RAW flow sink still advancing? One measurement, several surfaces.

WHY THIS EXISTS (measured 2026-11-21). The NetFlow feed stopped at 2026-11-20 23:33 and
nothing said so for eighteen hours. Every downstream surface was consistent with a quiet
network: `goflow2` was Ready (its probe is its own /metrics endpoint), the ingester logged
`Ingested 0 flow records` on every pass, and the detection sweep logged "examined NOTHING".
Each of those lines was individually true and none of them named the outage, because each
was written by a component describing ITS OWN last action rather than the age of the data.

The age of the newest row in `weirvern.flows` is the one number that separates "the network
is quiet" from "the ingest is dead", and it is cheap to read: the table is
`ORDER BY (timestamp, …)`, so `max(timestamp)` touches one granule. This module is the one
definition of that measurement so the Health panel and the worker's log cannot drift.

WHAT THIS IS NOT. It is not a replacement for `admin.status._feed_probe`, which asks a
different question (is the capture port carrying the NETWORK, or only broadcast noise?). A
feed can be fresh and still be capturing the wrong thing; a feed can be rich and still have
stopped an hour ago. Both are needed, and they are reported as separate checks.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)

# FIVE MINUTES, the same budget the feed probe uses, and for the same reason: the detection
# sweep re-evaluates five-minute buckets, so a sink that has not produced a row in one bucket
# has already missed a detection cycle. Making this looser would let a stalled ingest read as
# healthy through the cycle it failed to feed.
STALE_AFTER_S = 300.0

# The states are a closed set so a caller cannot invent a spelling a test then has to guess.
FRESH = "fresh"
STALLED = "stalled"
NO_DATA = "no_data"
UNREADABLE = "unreadable"

_TABLE = "weirvern.flows"


def _human_age(seconds: float) -> str:
    """A duration an operator can read at a glance, without a unit-conversion step."""
    value = float(seconds)
    if value < 90:
        return f"{value:.0f}s"
    if value < 5400:
        return f"{value / 60.0:.1f}m"
    if value < 172800:
        return f"{value / 3600.0:.1f}h"
    return f"{value / 86400.0:.1f}d"


@dataclass(frozen=True)
class Freshness:
    """The newest flow row's age, and the verdict that follows from it."""

    state: str
    limit_s: float
    age_s: float | None = None
    newest: str = ""
    rows: int | None = None
    error: str = ""

    @property
    def ok(self) -> bool | None:
        """True/False when the sink was measured; None when it could not be read.

        None is NOT a pass. `HealthReport.ok` ignores it (a deployment whose schema has not
        been applied yet is young, not broken), but a caller that wants a verdict must treat
        it as unknown rather than healthy.
        """
        if self.state == FRESH:
            return True
        if self.state in (STALLED, NO_DATA):
            return False
        return None

    def detail(self) -> str:
        if self.state == FRESH:
            return (f"the newest flow row is {_human_age(self.age_s or 0)} old "
                    f"(limit {_human_age(self.limit_s)}); NetFlow ingest is advancing")
        if self.state == NO_DATA:
            return ("weirvern.flows holds no rows: no flow has ever been ingested, so every "
                    "flow-based view is empty rather than quiet")
        if self.state == STALLED:
            return (
                f"the newest flow row is {_human_age(self.age_s or 0)} old "
                f"(limit {_human_age(self.limit_s)}): NetFlow INGEST HAS STOPPED. "
                "flows and flows_window cannot advance, so detection, calibration and every "
                "flow count are stale rather than small. Check the collector "
                "(`kubectl -n weirvern logs deploy/goflow2`) and the capture tap "
                "(`kubectl -n weirvern logs ds/zeek -c tap`); a tap that reports no targets "
                "meters nothing even though the collector stays Ready."
            )
        return f"the flow sink could not be read, so freshness was not judged: {self.error}"

    def as_value(self) -> dict[str, Any]:
        """The JSON-able shape the Health payload carries."""
        return {
            "state": self.state,
            "age_s": None if self.age_s is None else round(float(self.age_s), 1),
            "limit_s": float(self.limit_s),
            "newest": self.newest,
            "rows": self.rows,
            "error": self.error,
        }


def classify(age_s: float | None, limit_s: float = STALE_AFTER_S, *,
             rows: int | None = None, newest: str = "",
             error: str = "") -> Freshness:
    """The decision table, pure so every branch is testable without a database.

    A row that exists and is older than the limit is STALLED. An empty table is NO_DATA --
    a different remedy (nothing has ever arrived) from an ingest that has stopped (it was
    arriving and is not now). A read error is UNREADABLE, never a verdict.
    """
    limit = float(limit_s)
    if error:
        return Freshness(state=UNREADABLE, limit_s=limit, rows=rows, newest=newest,
                         error=error)
    if rows is not None and rows <= 0:
        return Freshness(state=NO_DATA, limit_s=limit, rows=rows, newest=newest)
    if age_s is None:
        return Freshness(state=NO_DATA, limit_s=limit, rows=rows, newest=newest)
    age = float(age_s)
    state = STALLED if age > limit else FRESH
    return Freshness(state=state, limit_s=limit, age_s=age, newest=newest, rows=rows)


def measure(client: Any, *, limit_s: float = STALE_AFTER_S,
            table: str = _TABLE) -> Freshness:
    """Read the newest row's age from `weirvern.flows`. Never raises.

    ONE AGGREGATE, not a count over the window: `count()` plus `max()` is answered from the
    table's own metadata and the last granule, so this costs the same on a one-hour table and
    a seven-day one. The age is computed by CLICKHOUSE (`dateDiff(…, now())`) rather than in
    Python, so the server's timezone cannot turn a fresh row into an eight-hour one.
    """
    # The table name is a module literal; it is never built from caller input.
    sql = ("SELECT count(), toString(max(timestamp)), "
           "toInt64(dateDiff('second', max(timestamp), now())) "
           f"FROM {table}")  # noqa: S608 - literal table name
    try:
        row = client.query(sql).result_rows[0]
    except Exception as exc:  # noqa: BLE001 - a probe must never raise at its caller
        return classify(None, limit_s, error=str(exc))
    rows = int(row[0] or 0) if len(row) > 0 else 0
    newest = str(row[1] or "") if len(row) > 1 else ""
    age = None
    if len(row) > 2 and row[2] is not None:
        try:
            age = float(row[2])
        except (TypeError, ValueError):
            age = None
    return classify(age, limit_s, rows=rows, newest=newest)


def log_verdict(freshness: Freshness, previous: bool | None = None,
                *, log: logging.Logger | None = None) -> bool | None:
    """Emit the worker's line for this verdict, and return the state to carry forward.

    ONE PLACE DECIDES THE LEVEL. `ERROR` while the sink is stalled (this is an outage, not a
    quiet network), `WARNING` on the recovery edge so it is findable in a log full of INFO, and
    `INFO` on a fresh cycle so "fresh" is a fact with a timestamp rather than an absence. The
    caller passes the previous return value back in; the transition is the only state kept.
    """
    target = log or logger
    if freshness.ok is False:
        target.error("FLOW INGEST STALLED: %s", freshness.detail())
    elif freshness.ok is True:
        if previous is False:
            target.warning("Flow ingest RECOVERED: %s", freshness.detail())
        else:
            target.info("Flow ingest fresh: %s", freshness.detail())
    else:
        # Unreadable is neither fresh nor stalled; the exception text is in the detail so a
        # missing table is not mistaken for a stopped collector.
        target.warning("Flow ingest freshness not judged: %s", freshness.detail())
    return freshness.ok


__all__ = ["FRESH", "NO_DATA", "STALE_AFTER_S", "STALLED", "UNREADABLE", "Freshness",
           "classify", "log_verdict", "measure"]
