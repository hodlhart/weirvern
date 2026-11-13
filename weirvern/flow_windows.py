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
"""

from __future__ import annotations

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


def avg_fragment(alias: str = "a") -> str:
    """The two means, computed from sums and counts rather than averaged twice.

    The old table stored a per-block `avg_bytes`, and readers averaged those again,
    which is an average of averages and corresponds to no real quantity.
    """
    return (
        f"{alias}.total_bytes / greatest({alias}.flow_count, 1)   AS avg_bytes,\n"
        f"            {alias}.total_packets / greatest({alias}.flow_count, 1) AS avg_packets"
    )
