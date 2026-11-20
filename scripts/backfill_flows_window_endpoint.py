#!/usr/bin/env python3
"""Backfill `flows_window_endpoint` from `weirvern.flows` for a bounded recent window.

WHY A BACKFILL IS NEEDED. A materialized view only sees rows inserted AFTER it was created. Schema
061 installs the table and its UNION ALL view, so every flow from that moment on contributes both
its endpoints -- but the retained history in `flows` was rolled up before the view existed, and the
new table would start empty while `flows_window` already had a week. The half of the network this
work exists to make visible would stay invisible for exactly the retention window.

WHY IT IS IDEMPOTENT. `flows_window_endpoint` is an AggregatingMergeTree: the columns are partial
aggregate STATES and the engine ADDS rows that share (window_start, host_addr, direction). Running
an insert twice would therefore double every count and every byte total rather than replace it. So
the run deletes the target range first and waits for the mutation (`mutations_sync = 2`), then
inserts one freshly computed state per (window, host, direction). A second run recomputes the same
states and leaves the same values -- which the script verifies after writing, and which the
row-count and per-direction totals reported before/after make visible.

WHY IT IS BOUNDED BY THE RAW DATA, NOT ONLY BY `--days`. Raw `flows` is the only thing a backfill
can recompute from, and its TTL is shorter than `flows_window`'s in practice (measured 2026-11-20:
raw held 3.4 days while the window table held 7). Deleting a range whose raw rows are gone would
erase history that cannot be rebuilt. The run therefore clamps `since` to the FIRST COMPLETE
five-minute window that still has raw rows, and reports both the requested and the effective
window. The first raw timestamp generally falls inside a window whose earlier part has already
been pruned, so that window is excluded rather than written from a partial input.

WHY THE PARITY CHECK IS SCOPED. The outbound direction is the same population `flows_window`
holds, so it must equal the old table's totals over the same range. That is checked in two places,
because `flows_window` itself carries duplicated historical states from an earlier ingest epoch
(measured 2026-11-20: over Nov 17 it read 923,662 flows against 823,079 raw rows, while from
Nov 18 onward it matched raw window-for-window):

  * `raw` -- the outbound totals against RAW `flows` over the whole effective range. This is the
    ground truth the backfill was computed from.
  * `recent_24h` -- the outbound totals against `flows_window` over the last 24 hours, where the
    old table is a faithful roll-up. A mismatch there means the two views disagree about the same
    flows, which is the defect this check exists to catch.

Usage:
    python scripts/backfill_flows_window_endpoint.py                 # dry run (default)
    python scripts/backfill_flows_window_endpoint.py --days 7 --apply
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from weirvern import db  # noqa: E402
from weirvern.config import get_settings  # noqa: E402

TABLE = "weirvern.flows_window_endpoint"

#: The UNION ALL that defines the table, shared by the dry-run estimate and the real insert. It is
#: deliberately the SAME shape as `flows_window_endpoint_mv` (schema 061): if the two ever diverge,
#: the backfill and the live view would write different numbers for the same window.
AGGREGATE_SQL = """
SELECT
    window_start,
    host_addr,
    direction,
    countState()                AS flow_count,
    sumState(toUInt64(bytes))   AS total_bytes,
    sumState(toUInt64(packets)) AS total_packets,
    uniqState(peer_addr)        AS unique_peer_ips,
    now()                       AS updated_at
FROM
(
    SELECT
        toStartOfFiveMinute(time_flow_start) AS window_start,
        src_addr                             AS host_addr,
        'out'                                AS direction,
        dst_addr                             AS peer_addr,
        bytes,
        packets
    FROM weirvern.flows
    WHERE time_flow_start >= %(since)s AND time_flow_start < %(until)s
    UNION ALL
    SELECT
        toStartOfFiveMinute(time_flow_start) AS window_start,
        dst_addr                             AS host_addr,
        'in'                                 AS direction,
        src_addr                             AS peer_addr,
        bytes,
        packets
    FROM weirvern.flows
    WHERE time_flow_start >= %(since)s AND time_flow_start < %(until)s
)
GROUP BY window_start, host_addr, direction
"""

COLUMNS = ("window_start", "host_addr", "direction", "flow_count", "total_bytes",
           "total_packets", "unique_peer_ips", "updated_at")

#: Physical rows the table holds for the range, and the merged truth per direction. `count()` is a
#: row count of partial states; the `-Merge` columns are the values a reader would see.
STATE_SQL = """
SELECT
    direction,
    count()                    AS state_rows,
    uniqExact(host_addr)       AS hosts,
    countMerge(flow_count)     AS flows,
    sumMerge(total_bytes)      AS bytes,
    sumMerge(total_packets)    AS packets,
    uniqMerge(unique_peer_ips) AS peers
FROM {table}
WHERE window_start >= %(since)s AND window_start < %(until)s
GROUP BY direction
ORDER BY direction
"""

#: Hosts that appear ONLY as a destination in the range. This is the population the old table
#: cannot describe at all, so it is the number that says whether the fix landed. The two counters
#: are computed over BOTH directions in one pass; filtering to 'in' first would make the 'out'
#: count structurally zero and the answer meaningless.
INBOUND_ONLY_SQL = """
SELECT countIf(in_rows > 0 AND out_rows = 0) FROM
(
    SELECT
        host_addr,
        countIf(direction = 'in')  AS in_rows,
        countIf(direction = 'out') AS out_rows
    FROM {table}
    WHERE window_start >= %(since)s AND window_start < %(until)s
    GROUP BY host_addr
)
"""

#: The same population measured from RAW flows, so the backfill's result can be checked against
#: the data it was computed from rather than against itself. The inner UNION ALL is the same
#: endpoint expansion the view and the backfill use.
RAW_INBOUND_ONLY_SQL = """
SELECT countIf(in_rows > 0 AND out_rows = 0) FROM
(
    SELECT
        host_addr,
        countIf(direction = 'in')  AS in_rows,
        countIf(direction = 'out') AS out_rows
    FROM
    (
        SELECT src_addr AS host_addr, 'out' AS direction
        FROM weirvern.flows
        WHERE time_flow_start >= %(since)s AND time_flow_start < %(until)s
        UNION ALL
        SELECT dst_addr AS host_addr, 'in' AS direction
        FROM weirvern.flows
        WHERE time_flow_start >= %(since)s AND time_flow_start < %(until)s
    )
    GROUP BY host_addr
)
"""

#: RAW is the ground truth: the outbound direction must be every flow's source, with the same
#: bytes, over the whole effective range.
RAW_PARITY_SQL = """
SELECT
    count()          AS flows,
    sum(toUInt64(bytes))   AS bytes,
    sum(toUInt64(packets)) AS packets
FROM weirvern.flows
WHERE time_flow_start >= %(since)s AND time_flow_start < %(until)s
"""

#: The old table, over the last 24 hours only: that is where it is a faithful roll-up of the same
#: flows (see the module docstring for the measured divergence before it).
OLD_PARITY_SQL = """
SELECT
    countMerge(flow_count) AS flows,
    sumMerge(total_bytes)  AS bytes,
    sumMerge(total_packets) AS packets
FROM weirvern.flows_window
WHERE window_start >= %(since)s AND window_start < %(until)s
"""

OUT_PARITY_SQL = """
SELECT
    countMerge(flow_count) AS flows,
    sumMerge(total_bytes)  AS bytes,
    sumMerge(total_packets) AS packets
FROM {table}
WHERE window_start >= %(since)s AND window_start < %(until)s
  AND direction = 'out'
"""


def _naive(value: Any) -> datetime:
    """A server datetime as a naive value in the server's own zone.

    clickhouse-connect returns some columns with a tzinfo and some without. The datetime is the
    SERVER's wall clock either way, which is what `time_flow_start` compares against; the offset
    must be dropped rather than converted.
    """
    if isinstance(value, datetime):
        return value.replace(tzinfo=None) if value.tzinfo else value
    return datetime.fromisoformat(str(value).replace("Z", "+00:00")).replace(tzinfo=None)


def _floor_five(value: datetime) -> datetime:
    return value.replace(minute=value.minute - value.minute % 5, second=0, microsecond=0)


def _ceil_five(value: datetime) -> datetime:
    floored = _floor_five(value)
    return floored if value == floored else floored + timedelta(minutes=5)


def _state(client: Any, since: str, until: str) -> dict[str, dict[str, int]]:
    rows = client.query(STATE_SQL.format(table=TABLE),
                        parameters={"since": since, "until": until}).result_rows
    return {str(direction): {"state_rows": int(rows_n), "hosts": int(hosts),
                             "flows": int(flows), "bytes": int(b or 0),
                             "packets": int(packets or 0), "peers": int(peers or 0)}
            for direction, rows_n, hosts, flows, b, packets, peers in rows}


def _scalar(client: Any, sql: str, since: str, until: str) -> int:
    rows = client.query(sql.format(table=TABLE),
                        parameters={"since": since, "until": until}).result_rows
    return int(rows[0][0] or 0) if rows else 0


def _triple(client: Any, sql: str, since: str, until: str) -> tuple[int, int, int]:
    row = client.query(sql.format(table=TABLE),
                       parameters={"since": since, "until": until}).result_rows[0]
    return int(row[0] or 0), int(row[1] or 0), int(row[2] or 0)


def _estimate(client: Any, since: str, until: str, span_hours: float) -> dict[str, Any]:
    """Time the SAME aggregation over one hour and extrapolate linearly.

    A guess in seconds is not an estimate. This runs the real shape on the most recent complete
    hour, measures it, and multiplies by the span -- and says that the method is linear, because
    ClickHouse's cost here is dominated by rows scanned and the flow rate is not constant.
    """
    anchor = datetime.strptime(until, "%Y-%m-%d %H:%M:%S")
    sample_since = (anchor - timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")
    started = time.monotonic()
    client.query(f"SELECT count() FROM ({AGGREGATE_SQL})",
                 parameters={"since": sample_since, "until": until})
    elapsed = time.monotonic() - started
    return {"sample_seconds": round(elapsed, 2), "sample_window_hours": 1,
            "linear_estimate_seconds": round(elapsed * max(span_hours, 0.0), 1),
            "method": "one complete hour of the same aggregation, multiplied by the span"}


def _bounds(client: Any, requested_days: float,
            until_override: str = "") -> dict[str, Any]:
    """The requested window, and the part of it that can honestly be recomputed.

    `until_override` pins the window end (server-local, as `time_flow_start` is), which is what a
    re-run needs to prove idempotency against a fixed range: with a moving `now()` the boundary
    window advances between runs and the totals legitimately differ.
    """
    clock = client.query("SELECT now(), timezone()").result_rows[0]
    server_now, timezone = _naive(clock[0]), str(clock[1])
    # The open five-minute window belongs to the live view; backfill only complete windows.
    anchor = _naive(datetime.fromisoformat(until_override)) if until_override else server_now
    until_dt = _floor_five(anchor)
    requested_since = until_dt - timedelta(days=requested_days)
    until = until_dt.strftime("%Y-%m-%d %H:%M:%S")

    first = client.query(
        "SELECT min(time_flow_start) FROM weirvern.flows "
        "WHERE time_flow_start >= %(since)s AND time_flow_start < %(until)s",
        parameters={"since": requested_since.strftime("%Y-%m-%d %H:%M:%S"), "until": until},
    ).result_rows
    raw_first = _naive(first[0][0]) if first and first[0][0] is not None else None
    if raw_first is None:
        return {"since": requested_since.strftime("%Y-%m-%d %H:%M:%S"), "until": until,
                "requested_since": requested_since.strftime("%Y-%m-%d %H:%M:%S"),
                "requested_days": requested_days, "server_timezone": timezone,
                "raw_first": None, "clamped": False}
    # THE CLAMP. A window whose earlier part has been pruned cannot be recomputed; starting at
    # the first complete boundary excludes it instead of writing a partial state over a full one.
    effective_since = _ceil_five(max(requested_since, raw_first))
    return {"since": effective_since.strftime("%Y-%m-%d %H:%M:%S"), "until": until,
            "requested_since": requested_since.strftime("%Y-%m-%d %H:%M:%S"),
            "requested_days": requested_days, "server_timezone": timezone,
            "raw_first": raw_first.strftime("%Y-%m-%d %H:%M:%S"),
            "clamped": effective_since > requested_since}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--days", type=float, default=7, help="bounded lookback; default 7")
    ap.add_argument("--until", default="",
                    help="pin the window end (server-local 'YYYY-mm-dd HH:MM:SS'); "
                         "for a reproducible re-run")
    ap.add_argument("--apply", action="store_true", help="delete and rewrite the range")
    args = ap.parse_args()
    if args.days <= 0:
        ap.error("--days must be positive")

    client = db.connect(get_settings())
    window = _bounds(client, args.days, args.until)
    since, until = window["since"], window["until"]
    span = client.query(
        "SELECT count() FROM weirvern.flows "
        "WHERE time_flow_start >= %(since)s AND time_flow_start < %(until)s",
        parameters={"since": since, "until": until},
    ).result_rows[0]
    raw_rows = int(span[0] or 0)
    if raw_rows == 0:
        print(json.dumps({"applied": False, "reason": "no raw flows in the requested range",
                          "window": window}, indent=2, sort_keys=True))
        return 0

    before = _state(client, since, until)
    span_hours = ((datetime.strptime(until, "%Y-%m-%d %H:%M:%S")
                   - datetime.strptime(since, "%Y-%m-%d %H:%M:%S")).total_seconds() / 3600.0)
    report: dict[str, Any] = {
        "applied": False,
        "table": TABLE,
        "window": window,
        "raw_flows": raw_rows,
        "before": before,
        "inbound_only_hosts": {
            "in_table": _scalar(client, INBOUND_ONLY_SQL, since, until),
            "in_raw_flows": _scalar(client, RAW_INBOUND_ONLY_SQL, since, until),
        },
        "estimate": _estimate(client, since, until, span_hours),
    }

    if args.apply:
        started = time.monotonic()
        client.command(
            f"ALTER TABLE {TABLE} DELETE WHERE window_start >= %(since)s "
            "AND window_start < %(until)s",
            parameters={"since": since, "until": until},
            settings={"mutations_sync": 2},
        )
        delete_seconds = round(time.monotonic() - started, 1)
        insert_sql = (f"INSERT INTO {TABLE} (" + ", ".join(COLUMNS) + ") " + AGGREGATE_SQL)
        client.command(insert_sql, parameters={"since": since, "until": until},
                       settings={"mutations_sync": 2})
        write_seconds = round(time.monotonic() - started - delete_seconds, 1)

        raw_flows, raw_bytes, raw_packets = _triple(client, RAW_PARITY_SQL, since, until)
        out_flows, out_bytes, out_packets = _triple(client, OUT_PARITY_SQL, since, until)
        recent_start = (datetime.strptime(until, "%Y-%m-%d %H:%M:%S")
                        - timedelta(hours=24)).strftime("%Y-%m-%d %H:%M:%S")
        old_flows, old_bytes, old_packets = _triple(client, OLD_PARITY_SQL, recent_start, until)
        recent_out = _triple(client, OUT_PARITY_SQL, recent_start, until)
        report.update({
            "applied": True,
            "after": _state(client, since, until),
            "seconds": {"delete": delete_seconds, "insert": write_seconds,
                        "total": round(time.monotonic() - started, 1)},
            "inbound_only_hosts": {
                "in_table": _scalar(client, INBOUND_ONLY_SQL, since, until),
                "in_raw_flows": _scalar(client, RAW_INBOUND_ONLY_SQL, since, until),
            },
            # THE PARITY CHECKS. 'out' is the same population `flows_window` holds (every flow's
            # source). `raw` covers the whole effective range; `recent_24h` is where the old table
            # is itself a faithful roll-up (see the module docstring).
            "parity": {
                "raw_range": {
                    "raw": {"flows": raw_flows, "bytes": raw_bytes, "packets": raw_packets},
                    "out": {"flows": out_flows, "bytes": out_bytes, "packets": out_packets},
                    "match": (raw_flows, raw_bytes, raw_packets)
                             == (out_flows, out_bytes, out_packets),
                },
                "recent_24h": {
                    "window_start": recent_start,
                    "old": {"flows": old_flows, "bytes": old_bytes, "packets": old_packets},
                    "out": {"flows": recent_out[0], "bytes": recent_out[1],
                            "packets": recent_out[2]},
                    "match": (old_flows, old_bytes, old_packets) == recent_out,
                },
            },
        })

    print(json.dumps(report, indent=2, sort_keys=True))
    if args.apply:
        parity = report.get("parity") or {}
        if not all(block.get("match") for block in parity.values()):
            print("PARITY FAILED: the outbound direction disagrees with the data it came from",
                  file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
