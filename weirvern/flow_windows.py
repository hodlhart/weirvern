"""The single definition of a folded host-window, for every reader.

WHY THIS MODULE EXISTS
======================

`flows_window` is an AggregatingMergeTree: it stores PARTIAL aggregate states and the
engine merges rows that share the sorting key. Reading it therefore needs `-Merge`
combinators, and it needs them with the TIME PREDICATE INSIDE the same select.

That second part is not a style preference. Reading it through a view that contains
`GROUP BY` forces ClickHouse to materialise the whole grouped table before an outer
`WHERE` can filter, so a five-minute sweep asks for the entire retained history. On
2026-11-12 that got the worker OOMKilled three times at a 4 GiB limit. The predicate
has to sit beside the merge so part pruning applies.

So the fragment lives here, once, and callers splice it in. The alternative -- a view
-- was tried and was the bug.

THE ENDPOINT VARIANT. `flows_window` is keyed on the SOURCE of a flow, so it cannot represent a
host that only receives traffic. `flows_window_endpoint` (schema 061) is the parallel table keyed
on (window, host, direction), and `folded_endpoint()` is its folded read: same merge combinators,
same predicate-beside-the-merge rule, with `direction` ('out'/'in') as part of the grain. The
outbound direction is the same population as `flows_window`; the inbound direction is the half
that did not exist.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

# Columns the folded subquery exposes, in the order callers expect.
FOLDED_COLUMNS = (
    "window_start",
    "window_end",
    "src_addr",
    "flow_count",
    "total_bytes",
    "total_packets",
    "unique_dst_ips",
)

#: The directions `flows_window_endpoint` stores. 'out' is the source endpoint of a flow (the same
#: population `flows_window` holds); 'in' is the destination endpoint, which `flows_window` cannot
#: represent at all. A direction outside this tuple is refused rather than interpolated.
DIRECTIONS = ("out", "in")

#: Columns the folded ENDPOINT subquery exposes. `host_addr` replaces `src_addr` and `direction`
#: is part of the row's identity, because the grain is (window, host, direction).
ENDPOINT_COLUMNS = (
    "window_start",
    "window_end",
    "host_addr",
    "direction",
    "flow_count",
    "total_bytes",
    "total_packets",
    "unique_peer_ips",
)

_MERGE_BODY = """
        SELECT
            window_start,
            window_start + INTERVAL 5 MINUTE          AS window_end,
            src_addr,
            countMerge(flow_count)                    AS flow_count,
            sumMerge(total_bytes)                     AS total_bytes,
            sumMerge(total_packets)                   AS total_packets,
            uniqMerge(unique_dst_ips)                 AS unique_dst_ips
        FROM weirvern.flows_window
        WHERE {predicate}
        GROUP BY window_start, src_addr
"""


def between(start: str, end: str) -> str:
    """The folded-window predicate for a formatted start and end.

    THIS EXISTS BECAUSE A NESTED STRING LITERAL INSIDE AN F-STRING IS NOT SUBSTITUTED.

    Every detector's training query is one big f-string whose `WHERE` clause reads
    `BETWEEN '{s}' AND '{e}'` and gets filled in correctly. Writing the SAME predicate as a
    plain literal inside an f-string EXPRESSION --

        f"FROM {flow_windows.folded(\"window_start BETWEEN '{s}' AND '{e}'\")}"

    -- passes `{s}` through untouched, because that inner string is not part of the outer
    f-string at all. ClickHouse then fails with

        Cannot read DateTime: neither Date nor Time was parsed successfully:
        while converting '{s}' to DateTime

    and because `Adaptive Baseline.train` runs BEFORE the sweep in the worker loop, the
    exception took the WHOLE loop down on every cycle. Measured on the live box, 2026-11-12:
    one sweep completed, the next died in `train_if_due`, and detection stopped again.

    Python 3.11 cannot nest an f-string inside an f-string expression either (that is PEP 701,
    Python 3.12), and the deployed image is 3.11, so the predicate is built here in plain code.
    """
    return f"window_start BETWEEN '{start}' AND '{end}'"


def folded(predicate: str, alias: str = "a") -> str:
    """Return a derived table of merged host-windows, filtered by `predicate`.

    `predicate` is a SQL fragment referring to `window_start` (unqualified), for
    example ``"window_start BETWEEN '2026-11-12 10:00:00' AND '2026-11-12 11:00:00'"``.

    The predicate is interpolated, so it must be built by the caller from formatted
    datetimes or integers, never from flow data. Every call site in this repository
    already does that; the docstring is here so the next one does too.
    """
    body = _MERGE_BODY.replace("{predicate}", predicate)
    return f"(\n{body}\n    ) AS {alias}"


_ENDPOINT_MERGE_BODY = """
        SELECT
            window_start,
            window_start + INTERVAL 5 MINUTE          AS window_end,
            host_addr,
            direction,
            countMerge(flow_count)                    AS flow_count,
            sumMerge(total_bytes)                     AS total_bytes,
            sumMerge(total_packets)                   AS total_packets,
            uniqMerge(unique_peer_ips)                AS unique_peer_ips
        FROM weirvern.flows_window_endpoint
        WHERE {predicate} AND direction = '{direction}'
        GROUP BY window_start, host_addr, direction
"""


def endpoint_between(start: str, end: str) -> str:
    """The folded-endpoint predicate for a formatted start and end.

    The same helper as `between`, for the same reason: a string literal nested inside an f-string
    expression is not substituted by the enclosing f-string, so every caller must build the
    predicate in plain code rather than inline it.
    """
    return f"window_start BETWEEN '{start}' AND '{end}'"


def folded_endpoint(predicate: str, direction: str = "out", alias: str = "e") -> str:
    """Return a derived table of merged (host, direction) windows.

    THE GRAIN IS (window_start, host_addr, direction). `direction` is part of the GROUP BY and of
    the row's identity: 'out' rows describe the source endpoint of each flow, 'in' rows the
    destination endpoint. Reading both directions without distinguishing them would sum a host's
    sent and received bytes into a number that corresponds to nothing, so the direction is a
    required argument with a validated value rather than a free-form fragment.

    As with `folded`, the time predicate sits in the SAME select as the merge. Through a view (or
    an outer WHERE) ClickHouse would materialise the whole retained table first, which is the
    OOMKill 050 documents.
    """
    if direction not in DIRECTIONS:
        raise ValueError(
            f"unknown direction {direction!r}: expected one of {', '.join(DIRECTIONS)}"
        )
    body = _ENDPOINT_MERGE_BODY.replace("{predicate}", predicate).replace(
        "{direction}", direction)
    return f"(\n{body}\n    ) AS {alias}"


def host_windows(client: Any, host: str, *, since: datetime, until: datetime,
                 direction: str = "out", limit: int = 10_000) -> list[dict[str, Any]]:
    """One host's folded endpoint windows for ONE direction, oldest first.

    A THIN READER OVER `folded_endpoint`, not a second SQL shape: the merge, the direction filter
    and the time predicate are spliced exactly as the ripple channels splice them, so a number
    read here is the number the evidence layer measured. `host` and `direction` are bound as query
    parameters / validated against `DIRECTIONS`; the datetimes are formatted by the caller (or
    here) into the predicate, never taken from a row.

    Returns one dict per window with integer totals. An empty list means this host had no traffic
    in that direction inside the bounds -- not that the read failed (a failed read raises).
    """
    if direction not in DIRECTIONS:
        raise ValueError(
            f"unknown direction {direction!r}: expected one of {', '.join(DIRECTIONS)}"
        )
    predicate = endpoint_between(f"{since:%Y-%m-%d %H:%M:%S}", f"{until:%Y-%m-%d %H:%M:%S}")
    # THE HOST FILTER SITS INSIDE THE MERGED SELECT, beside the time predicate. An outer WHERE
    # would still be correct but would aggregate every host in the range before discarding all
    # but one; this keeps the read proportional to the host's own windows.
    columns = ", ".join(ENDPOINT_COLUMNS)
    fragment = folded_endpoint(predicate + " AND host_addr = %(host)s", direction)
    sql = f"SELECT {columns} FROM {fragment} ORDER BY window_start LIMIT %(limit)s"
    rows = list(client.query(sql, parameters={"host": host, "limit": int(limit)}).result_rows)
    return [dict(zip(ENDPOINT_COLUMNS, row, strict=False)) for row in rows]


def avg_fragment(alias: str = "a") -> str:
    """The two means, computed from sums and counts rather than averaged twice.

    The old table stored a per-block `avg_bytes`, and readers averaged those again,
    which is an average of averages and corresponds to no real quantity.
    """
    return (
        f"{alias}.total_bytes / greatest({alias}.flow_count, 1)   AS avg_bytes,\n"
        f"            {alias}.total_packets / greatest({alias}.flow_count, 1) AS avg_packets"
    )
