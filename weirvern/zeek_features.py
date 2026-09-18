"""Zeek-derived features for the ML ensemble.

WHY THIS EXISTS. The ensemble trains and scores on NetFlow aggregates alone: bytes, packets,
destination and port diversity, and time-of-day. That describes VOLUME and BREADTH. It
cannot see what the traffic *is*, which is where most of the signal for real detection lives:

    a host beaconing to one destination every 60s with constant payload  -> low volume,
        low breadth, one destination. Every NetFlow feature says "quiet and normal".
        Zeek's conn.log shows the periodicity and the uniformity directly.
    a DNS-tunnelling exfil                                        -> a few large queries
        with high-entropy subdomains. NetFlow sees bytes; Zeek sees `query_entropy`.
    a TLS session with a known-bad client fingerprint              -> NetFlow sees a flow.
        Zeek sees `ja4`.
    a host that suddenly starts speaking a service it never has    -> NetFlow sees bytes.
        Zeek sees `service` change.
    a connection attempt that is always rejected                   -> NetFlow may not even
        record it. Zeek logs `conn_state = REJ` and `S0`.

WHAT THIS MODULE IS CAREFUL ABOUT, and why each matters:

  * **Absent is not zero.** Zeek and NetFlow are separate sensors. On a host that Zeek has
    never seen, every Zeek feature must be distinguishable from "Zeek saw it and there was
    nothing". A confident 0 would teach the model that a whole class of host is normal-by-
    emptiness. So every feature is computed from an explicit `_present` flag, and the
    imputation is the caller's decision, not this module's silent default.

  * **The join key is a host and a 5-minute window.** `flows_aggregated` is bucketed with
    `toStartOfFiveMinute`, so Zeek records are bucketed the SAME way. Joining on the host
    alone would compare a 5-minute NetFlow window against all of the host's Zeek history,
    which is a different question and would make a burst anywhere in the day look like it
    happened inside the current window.

  * **Measured overlap is low, and that is a fact about the deployment, not a bug here.**
    On the test box, `zeek_conn` sees 35 source addresses and `flows_aggregated` has 88,
    with an INTERSECTION OF 2 -- the sensor observes the real network while the NetFlow
    table is largely seeded test data. That is why the absent-case handling above is not
    theoretical: on that deployment most host-windows legitimately have no Zeek data, and a
    model that cannot tell that apart from "nothing happened" would learn nonsense. The
    first thing to check on any real deployment is the overlap, which `zeek_join_coverage`
    reports.

Pure functions plus SQL builders, so the feature maths is unit-testable without a database.
"""
from __future__ import annotations

import math
from typing import Any

# ── the Zeek feature set ─────────────────────────────────────────────────────────
#
# Chosen for what NetFlow cannot express, not for what is easy to compute. Every one of
# these is a property of the CONVERSATIONS a host had, not of the bytes it moved.
ZEEK_FEATURES = [
    # THE PRESENCE FLAG, and it goes FIRST in the block so the ordering is obvious.
    #
    # 1 means Zeek observed this host in this window; 0 means it did not. Every other Zeek
    # feature below is 0 in both cases, so WITHOUT this flag the model cannot tell "Zeek saw
    # nothing" from "Zeek saw a quiet host" -- and would learn that a whole class of
    # host-window is defined by empty features, which is an artefact of two sensors observing
    # different traffic rather than a property of the network.
    #
    # Measured on the test deployment: 35 hosts in zeek_conn against 88 in flows_aggregated
    # with an OVERLAP OF 2, so the absent case is the common one there. `zeek_join_coverage`
    # reports this so it can be watched rather than assumed.
    "zeek_present",
    # Connection shape. `S0` dominates a scan (SYN sent, nothing back); `REJ` is an active
    # refusal; `SF` is a normal completed connection. A shift in this mix with flat byte
    # volume is the signature of probing, and it is invisible in NetFlow.
    "zeek_conn_count",
    "zeek_rej_ratio",
    "zeek_s0_ratio",
    "zeek_completed_ratio",
    # DNS. High entropy across many queries is the shape of a tunnel; a long query name is
    # the same idea more crudely. Both are per-host so they describe THIS host's resolver
    # behaviour rather than the network's.
    "zeek_dns_count",
    "zeek_dns_mean_query_entropy",
    "zeek_dns_mean_query_len",
    "zeek_dns_rcode_error_ratio",
    "zeek_dns_failed_ratio",
    # Service variety and novelty. `zeek_service_count` is how many distinct protocols the
    # host spoke in the window; a host that normally does DNS and HTTPS suddenly doing SSH
    # is the interesting case, and NetFlow's port entropy is a weaker proxy for it.
    "zeek_service_count",
    "zeek_service_rarity",
    # TLS. `zeek_ja4_count` (distinct JA4 fingerprints) surfaces a client changing its TLS
    # stack, and `zeek_ssl_modern_ratio` catches a downgrade to something old.
    "zeek_ja4_count",
    "zeek_ssl_modern_ratio",
    # Notices and weird. Zeek's own detections, which are a second opinion on the same
    # traffic -- and `weird` is Zeek saying the protocol itself looked wrong.
    "zeek_notice_count",
    "zeek_weird_count",
    # Transfer shape. A single large outbound transfer with no matching inbound is exfil;
    # NetFlow gives bytes, Zeek gives the orig/resp split per connection.
    "zeek_outbound_ratio",
    "zeek_unique_dst_ips",
]

# The features that are DERIVED from the Zeek data being present at all. If Zeek saw nothing
# for this host-window, these are meaningless and must be imputed rather than set to 0.
ZEEK_PRESENCE_FEATURE = "zeek_present"

# Subset for DBSCAN, which uses a smaller set by design (clustering degrades with
# dimensionality on few samples). These are the ones that separate clusters most: how much
# the host talked, how varied it was, and how wrong the traffic looked.
ZEEK_DBSCAN_FEATURES = [
    "zeek_conn_count",
    "zeek_service_count",
    "zeek_rej_ratio",
    "zeek_notice_count",
    "zeek_weird_count",
    "zeek_present",
]

# TTL / value for modern TLS versions, used by `zeek_ssl_modern_ratio`.
MODERN_TLS = {"TLSv13", "TLSv12", "TLSv1.3", "TLSv1.2"}

# conn_states that mean "the connection was refused or never answered". `S0` is a SYN with
# no reply (a filtered port, the classic scan result); `REJ` is an active refusal.
REJECTED_STATES = {"REJ", "RSTO", "RSTR"}
UNANSWERED_STATES = {"S0", "S1", "SH"}
COMPLETED_STATES = {"SF", "S1", "S2", "S3", "OTH"}


def _f(v: Any, default: float = 0.0) -> float:
    """Float with a default, never raising on a NULL from ClickHouse."""
    try:
        if v is None:
            return default
        return float(v)
    except (TypeError, ValueError):
        return default


# ── the SQL that gathers the per-host-window Zeek summary ────────────────────────
#
# ONE query per model-training run and one per scoring sweep, not one per host. Everything
# is aggregated to (5-minute window, src_addr) so it lines up with `flows_aggregated`
# exactly.
#
# LEFT JOINed from the NetFlow side everywhere it is used, so a host with no Zeek data
# still produces a row -- with the presence flag false. An INNER JOIN would silently drop
# those hosts from training, which would bias the model toward the hosts Zeek happens to
# see and make the absent case unlearnable.
def zeek_window_summary_sql(start: str, end: str) -> str:
    """The per-(window, host) Zeek summary for a time range.

    BUILT AS A UNION OF KEYS, THEN JOINED -- not as a chain of FULL OUTER JOINs.

    Two bugs the earlier version had, both found by running it against the live database
    rather than by reading it:

      1. `coalesce(c.w, d.w, s.w, n.w, ww.w)` across a five-way FULL OUTER JOIN returned
         **1969-12-31** (epoch zero) for `window_start` and an EMPTY STRING for `src_addr`.
         The join keys were NULL in most branches, so the coalesce landed on something that
         was not a real key at all. A feature row keyed on (epoch, "") would silently join to
         nothing and every model would train on empty Zeek data while appearing to work.
      2. The five-way chain also cross-multiplied: connecting each aggregate to the running
         coalesce of the previous ones means a host present in three logs produces rows
         multiplied by its counts in each, and every COUNT is then wrong by that factor.

    The UNION of distinct keys first, then LEFT JOIN each aggregate to it, has neither
    problem: the key set is exactly the hosts Zeek saw in each window, and each aggregate
    contributes at most one row per key so no count can be multiplied.

    Each log is aggregated SEPARATELY before any join. Joining the raw logs on (host,
    window) and counting afterwards would count the cross-product -- a host with 10
    connections and 10 DNS queries would produce 100 joined rows and both counts would read
    100.

    The window function matches `flows_aggregated_mv`: toStartOfFiveMinute. Anything else
    would compare misaligned periods, making a burst look like it fell inside the current
    window when it did not.
    """
    return f"""
        WITH
        conn_agg AS (
            SELECT
                toStartOfFiveMinute(ts) AS w,
                src_addr,
                count()                                             AS conn_count,
                countIf(conn_state IN ('REJ','RSTO','RSTR'))        AS rej_count,
                countIf(conn_state = 'S0')                          AS s0_count,
                countIf(conn_state IN ('SF','S1','S2','S3','OTH'))  AS completed_count,
                uniqExact(dst_addr)                                 AS uniq_dst,
                sum(orig_bytes)                                     AS ob,
                sum(resp_bytes)                                     AS rb,
                uniqExactIf(service, service != '')                 AS svc_count
            FROM weirvern.zeek_conn
            WHERE ts BETWEEN '{start}' AND '{end}'
            GROUP BY w, src_addr
        ),
        dns_agg AS (
            SELECT
                toStartOfFiveMinute(ts) AS w,
                src_addr,
                count()                                     AS dns_count,
                avg(query_entropy)                          AS mean_entropy,
                avg(query_len)                              AS mean_len,
                countIf(rcode != 0)                         AS rcode_err,
                countIf(answers = '' OR answers = '-')      AS no_answer
            FROM weirvern.zeek_dns
            WHERE ts BETWEEN '{start}' AND '{end}'
            GROUP BY w, src_addr
        ),
        ssl_agg AS (
            SELECT
                toStartOfFiveMinute(ts) AS w,
                src_addr,
                uniqExactIf(ja4, ja4 != '')                 AS ja4_count,
                count()                                     AS ssl_count,
                countIf(version IN ('TLSv13','TLSv12','TLSv1.3','TLSv1.2')) AS modern_count
            FROM weirvern.zeek_ssl
            WHERE ts BETWEEN '{start}' AND '{end}'
            GROUP BY w, src_addr
        ),
        notice_agg AS (
            SELECT
                toStartOfFiveMinute(ts) AS w,
                src_addr,
                count() AS notice_count
            FROM weirvern.zeek_notice
            WHERE ts BETWEEN '{start}' AND '{end}'
            GROUP BY w, src_addr
        ),
        weird_agg AS (
            SELECT
                toStartOfFiveMinute(ts) AS w,
                src_addr,
                count() AS weird_count
            FROM weirvern.zeek_weird
            WHERE ts BETWEEN '{start}' AND '{end}'
            GROUP BY w, src_addr
        ),
        keys AS (
            SELECT w, src_addr FROM conn_agg
            UNION DISTINCT SELECT w, src_addr FROM dns_agg
            UNION DISTINCT SELECT w, src_addr FROM ssl_agg
            UNION DISTINCT SELECT w, src_addr FROM notice_agg
            UNION DISTINCT SELECT w, src_addr FROM weird_agg
        )
        SELECT
            k.w        AS window_start,
            k.src_addr AS src_addr,
            -- ONE NAME PER CONCEPT: these aliases are the FEATURE names, so the training
            -- queries can select ZEEK_FEATURES verbatim and a typo is a query error rather
            -- than a silently-zero feature. An earlier version exposed raw names
            -- (conn_count, s0_count) while the features were zeek_conn_count and
            -- zeek_s0_ratio, so every training query named a column that did not exist.
            coalesce(c.conn_count, 0)                              AS zeek_conn_count,
            coalesce(c.uniq_dst, 0)                                AS zeek_unique_dst_ips,
            coalesce(c.svc_count, 0)                               AS zeek_service_count,
            coalesce(d.dns_count, 0)                               AS zeek_dns_count,
            coalesce(d.mean_entropy, 0)                            AS zeek_dns_mean_query_entropy,
            coalesce(d.mean_len, 0)                                AS zeek_dns_mean_query_len,
            coalesce(s.ja4_count, 0)                               AS zeek_ja4_count,
            coalesce(n.notice_count, 0)                            AS zeek_notice_count,
            coalesce(ww.weird_count, 0)                            AS zeek_weird_count,
            -- RATIOS: computed in SQL so they cannot disagree with the Python path, and
            -- each guards its own denominator. A host with zero connections has no
            -- meaningful rejection ratio, and dividing by zero would produce nan, which
            -- sklearn rejects outright rather than treating as missing.
            if(coalesce(c.conn_count, 0) > 0,
               coalesce(c.rej_count, 0) / c.conn_count, 0)         AS zeek_rej_ratio,
            if(coalesce(c.conn_count, 0) > 0,
               coalesce(c.s0_count, 0) / c.conn_count, 0)          AS zeek_s0_ratio,
            if(coalesce(c.conn_count, 0) > 0,
               coalesce(c.completed_count, 0) / c.conn_count, 0)   AS zeek_completed_ratio,
            if(coalesce(c.ob, 0) + coalesce(c.rb, 0) > 0,
               coalesce(c.ob, 0) / (coalesce(c.ob, 0) + coalesce(c.rb, 0)), 0)
                                                                   AS zeek_outbound_ratio,
            if(coalesce(d.dns_count, 0) > 0,
               coalesce(d.rcode_err, 0) / d.dns_count, 0)          AS zeek_dns_rcode_error_ratio,
            if(coalesce(d.dns_count, 0) > 0,
               coalesce(d.no_answer, 0) / d.dns_count, 0)          AS zeek_dns_failed_ratio,
            if(coalesce(s.ssl_count, 0) > 0,
               coalesce(s.modern_count, 0) / s.ssl_count, 0)       AS zeek_ssl_modern_ratio,
            -- Rarity needs the host's longer-window baseline, which is a separate query;
            -- left at 0 here and filled by the caller that has it.
            0                                                      AS zeek_service_rarity,
            -- PRESENCE as a real column, so ZEEK_FEATURES works verbatim as a SELECT list.
            if(coalesce(c.conn_count, 0) + coalesce(d.dns_count, 0) + coalesce(s.ssl_count, 0)
               + coalesce(n.notice_count, 0) + coalesce(ww.weird_count, 0) > 0, 1, 0)
                                                                   AS zeek_present
        FROM keys k
        LEFT JOIN conn_agg   c  ON c.w  = k.w AND c.src_addr  = k.src_addr
        LEFT JOIN dns_agg    d  ON d.w  = k.w AND d.src_addr  = k.src_addr
        LEFT JOIN ssl_agg    s  ON s.w  = k.w AND s.src_addr  = k.src_addr
        LEFT JOIN notice_agg n  ON n.w  = k.w AND n.src_addr  = k.src_addr
        LEFT JOIN weird_agg  ww ON ww.w = k.w AND ww.src_addr = k.src_addr
        WHERE k.src_addr != ''
        ORDER BY window_start, src_addr
    """


def zeek_baseline_sql(start: str, end: str) -> str:
    """Per-host service and fingerprint baselines, over a LONGER window than the feature one.

    This is what makes novelty measurable. "This host spoke 4 services in the last 5 minutes"
    is not interesting on its own; "this host spoke 4 services, none of which it has used in
    the last 30 days" is. The baseline is deliberately separate so it can use a much longer
    range than the per-window features without widening the feature query.
    """
    return f"""
        SELECT
            src_addr,
            uniqExactIf(service, service != '')  AS baseline_service_count,
            uniqExactIf(ja4, ja4 != '')          AS baseline_ja4_count,
            count()                              AS baseline_conn_count
        FROM weirvern.zeek_conn
        LEFT JOIN (
            SELECT src_addr AS f_addr, ja4 FROM weirvern.zeek_ssl
            WHERE ts BETWEEN '{start}' AND '{end}'
        ) fp ON fp.f_addr = src_addr
        WHERE ts BETWEEN '{start}' AND '{end}'
        GROUP BY src_addr
    """


def extract_zeek_features(row: dict[str, Any],
                          baseline: dict[str, Any] | None = None) -> dict[str, float]:
    """Turn one summary row into the model's Zeek feature dict.

    `row` is a row from `zeek_window_summary_sql`. A row of all-NULLs (or None) means Zeek
    had no record of this host in this window -- which sets `zeek_present` to 0 and lets
    every other feature fall to a neutral value that the CALLER can recognise and impute.

    The ratios guard their own denominators: a host with zero connections has no meaningful
    rejection ratio, and dividing by zero into `nan` would poison the whole feature vector,
    since sklearn treats nan as an error rather than as missing.
    """
    out: dict[str, float] = {name: 0.0 for name in ZEEK_FEATURES}
    out[ZEEK_PRESENCE_FEATURE] = 0.0
    if not row:
        return out

    # The summary columns are named after the FEATURES now, so presence is decided from the
    # feature names -- NOT from the pre-rename ones (`conn_count`, `dns_count`), which no
    # longer exist. Deciding it from the old names made every row look absent: the tests
    # caught it as `zeek_present == 0` for a real scan row that had 89 connections.
    conn_n = _f(row.get("zeek_conn_count"))
    dns_n = _f(row.get("zeek_dns_count"))
    ssl_n = _f(row.get("zeek_ssl_count")) or _f(row.get("ssl_count"))
    notice_n = _f(row.get("zeek_notice_count"))
    weird_n = _f(row.get("zeek_weird_count"))

    # An explicit flag from the query wins when present: the SQL computes presence from the
    # raw counts across all five logs, including ones this function does not inspect.
    explicit = row.get("zeek_present")
    if explicit is not None and _f(explicit) > 0:
        out[ZEEK_PRESENCE_FEATURE] = 1.0
        _fill(out, row, baseline)
        return out

    if conn_n == 0 and dns_n == 0 and ssl_n == 0 and notice_n == 0 and weird_n == 0:
        # Zeek knows nothing about this host-window. Reported as absence rather than as a
        # row of zeroes, because "we did not look" and "we looked and saw nothing" are
        # different facts and only one of them is evidence of normality.
        return out

    out[ZEEK_PRESENCE_FEATURE] = 1.0
    _fill(out, row, baseline)
    return out


def _fill(out: dict[str, float], row: dict[str, Any],
          baseline: dict[str, Any] | None = None) -> None:
    """Copy the feature-named columns out of the row, then compute the two features that
    cannot come from the row alone.

    ONE place reads a column. An earlier version had the presence check and the value reading
    as separate copies, and after the SQL rename they disagreed -- the presence check read the
    pre-rename names and so decided every row was absent, which the tests caught as
    `zeek_present == 0` for a real scan row with 89 connections.
    """
    for name in ZEEK_FEATURES:
        if name in row and name != ZEEK_PRESENCE_FEATURE:
            out[name] = _f(row.get(name))

    conn_n = _f(row.get("zeek_conn_count")) or _f(row.get("conn_count"))

    # LEGACY FALLBACK for rows built against the pre-rename column names, which tests and
    # external callers may still use. Applied only where the feature-named key was absent, so
    # it can never override a real value.
    legacy = {
        "zeek_s0_ratio": ("s0_count", conn_n),
        "zeek_rej_ratio": ("rej_count", conn_n),
        "zeek_completed_ratio": ("completed_count", conn_n),
        "zeek_unique_dst_ips": ("uniq_dst", 1.0),
        "zeek_service_count": ("service_count", 1.0),
    }
    for feature, (old, denom) in legacy.items():
        if out[feature] == 0.0 and row.get(old) is not None and denom:
            out[feature] = _f(row.get(old)) / denom
    if out["zeek_outbound_ratio"] == 0.0 and row.get("orig_bytes") is not None:
        ob, rb = _f(row.get("orig_bytes")), _f(row.get("resp_bytes"))
        if ob + rb > 0:
            out["zeek_outbound_ratio"] = ob / (ob + rb)

    # SERVICE RARITY: how much of this window's service variety is OUTSIDE what the host
    # normally does. Needs the longer-window baseline, which the summary query cannot supply
    # (it only sees this window), so it is 0 when no baseline is given rather than guessed.
    # Clamped at 0 because using FEWER services than the baseline is not novelty.
    svc = out["zeek_service_count"]
    if baseline and svc:
        known = max(_f(baseline.get("baseline_service_count")), 1.0)
        out["zeek_service_rarity"] = max(0.0, svc - known) / known

    # Log-scale the counts so they sit on a comparable range to the NetFlow features, which
    # are log1p'd. Without this a host with 10,000 connections dominates any distance metric
    # -- DBSCAN's most of all, since it clusters on distance.
    #
    # Applied LAST, after rarity, because rarity is a ratio of raw service counts: scaling the
    # counts first would make rarity a ratio of logarithms, which is a different quantity.
    for name in ("zeek_conn_count", "zeek_dns_count", "zeek_notice_count",
                 "zeek_weird_count", "zeek_unique_dst_ips", "zeek_ja4_count",
                 "zeek_service_count"):
        out[name] = math.log1p(max(out[name], 0.0))


def zeek_join_coverage(netflow_hosts: int, zeek_hosts: int, overlapping: int) -> dict:
    """A one-line health reading of the NetFlow/Zeek join, for an operator to act on.

    WHY THIS IS PART OF THE FEATURE MODULE: if the two sensors are not observing the same
    hosts, every Zeek feature is imputed for nearly every row and the ensemble is training
    on NetFlow alone while appearing to use Zeek. That failure is invisible in the metrics
    -- the models train, score, and report normally. Measured on the test box: 35 Zeek hosts,
    88 NetFlow hosts, 2 overlapping, because the NetFlow table was largely seeded test data.
    """
    coverage = (overlapping / netflow_hosts) if netflow_hosts else 0.0
    if netflow_hosts == 0:
        verdict = "no NetFlow hosts; nothing to join"
    elif coverage >= 0.7:
        verdict = "good: Zeek covers most NetFlow hosts"
    elif coverage >= 0.2:
        verdict = ("partial: most host-windows will have no Zeek data, so Zeek features are "
                   "imputed for the majority. Check that both sensors see the same segment.")
    else:
        verdict = ("poor: the sensors are observing almost disjoint sets of hosts, so the "
                   "Zeek features carry almost no signal. Check CAPTURE_IFACE/ZEEK_IFACE and "
                   "whether the NetFlow table holds seeded data.")
    return {
        "netflow_hosts": netflow_hosts,
        "zeek_hosts": zeek_hosts,
        "overlapping": overlapping,
        "coverage": round(coverage, 3),
        "verdict": verdict,
    }


# ── the join fragment the training queries share ─────────────────────────────────
#
# ONE definition, used by all four detectors. Duplicating it per detector is how the join
# drifts: three models silently training on a slightly different window or key than the
# fourth, which is invisible in every metric and only shows up as one model disagreeing with
# the others for no stated reason.
#
# LEFT JOIN, not INNER. An inner join would drop every host-window Zeek did not see, which
# on the measured deployment is most of them -- the model would then be trained only on the
# hosts both sensors observe and would have no idea what to do with the rest. The
# `zeek_present` flag carries the distinction instead.
#
# The subquery is materialised per query via the CTE, and the join is on BOTH parts of the
# key. Joining on the host alone would compare a 5-minute NetFlow window against the host's
# entire Zeek history, so a burst from any time in the range would look like it happened
# inside the current window.
ZEEK_JOIN_CTE = """zeek_w AS ({summary})"""

ZEEK_JOIN_ON = """LEFT JOIN zeek_w z
                    ON z.window_start = a.window_start AND z.src_addr = a.src_addr"""


def zeek_join_cte(start: str, end: str) -> str:
    """The WITH-clause entry that makes `zeek_w` available to a training query."""
    return ZEEK_JOIN_CTE.format(summary=zeek_window_summary_sql(start, end))


def zeek_select_columns() -> str:
    """The Zeek columns a training query must SELECT, in the vector's tail order.

    ORDER IS LOAD-BEARING. These are appended to the NetFlow columns and must appear in the
    same order as ZEEK_FEATURES / ZEEK_DBSCAN_FEATURES, because the model rebuilds its
    input by position. A mismatch here produces a vector of the right LENGTH holding the
    wrong values -- nothing raises, and the model is quietly wrong.
    """
    return ",\n".join(f"    {c}" for c in ZEEK_FEATURES)


def zeek_window_sql(since: str, until: str | None = None) -> str:
    """The scoring-side summary: everything from `since` up to now (or `until`).

    A separate entry point from `zeek_window_summary_sql` because the two callers ask
    different questions. Training takes an explicit closed range so a retrain is
    reproducible; a live sweep takes "since the last sweep" and lets ClickHouse use `now()`.
    Wrapping the same builder keeps the join key and window function identical between them,
    which is the property that matters -- a scoring query bucketing differently from the
    training query would put the same traffic in different rows and the features would not
    line up with the model.
    """
    from datetime import datetime, timedelta

    if until is None:
        # A small forward margin so a record written during the sweep is not excluded by
        # clock skew between the worker and ClickHouse.
        until = (datetime.now() + timedelta(minutes=1)).strftime("%Y-%m-%d %H:%M:%S")
    return f"SELECT * FROM ({zeek_window_summary_sql(since, until)})"


def zeek_coverage_sql(since: str) -> str:
    """Host-set overlap between NetFlow and Zeek, for `zeek_join_coverage`.

    The check that tells an operator whether the Zeek features are carrying signal or being
    imputed for nearly every row. Cheap enough to run on each retrain, and it is the only
    thing that would reveal two sensors observing different segments.
    """
    return f"""
        SELECT
            (SELECT uniqExact(src_addr) FROM weirvern.flows_aggregated
              WHERE window_start >= '{since}') AS netflow_hosts,
            (SELECT uniqExact(src_addr) FROM weirvern.zeek_conn
              WHERE ts >= '{since}') AS zeek_hosts,
            (SELECT count() FROM (
                SELECT DISTINCT src_addr FROM weirvern.flows_aggregated
                 WHERE window_start >= '{since}'
                INTERSECT
                SELECT DISTINCT src_addr FROM weirvern.zeek_conn
                 WHERE ts >= '{since}'
            )) AS overlapping
    """
