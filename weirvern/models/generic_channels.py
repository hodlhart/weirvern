"""Any collected source can carry a ripple (RIP source-agnostic channels).

WHY THIS EXISTS. The fusion could only hear from seven hand-written specialists plus temporal and
changepoint models. Meanwhile the deployment already collects, with real volume on 2026-11-12:
zeek_http 116k, zeek_files 81k, zeek_ssh 19k, zeek_weird 1.6M, zeek_quic 5.9k, zeek_dhcp 1.3k,
zeek_kerberos 1.4k, zeek_ntlm 413, zeek_x509 306, zeek_tunnel 133, zeek_smb_* 206. None of it
reached the ripple layer. A product cannot ship a detector that only sees the sources someone
wrote a specialist for.

HOW A SOURCE BECOMES A CHANNEL. A ChannelSpec declares four things: the table, the host column,
the value whose diversity matters, and the family it belongs to. The score is the same shape for
every source -- how far this window's volume and diversity sit above the host's own recent
normal -- so adding a source is a declaration, not a new algorithm.

CALIBRATION. A score is not a p-value. Each host's windows over the last `LOOKBACK_DAYS` are
scored with the SAME function, and the current window is ranked against them. A source with no
history for a host produces no evidence at all, never a zero.

WHAT THIS CANNOT DO. A source that is silent because nothing happened and a source that is silent
because collection broke look identical here; freshness remains the collection layer's job.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from weirvern.models.ripple import ChannelEvidence, empirical_pvalue

WINDOW_MINUTES = 5
LOOKBACK_DAYS = 7
MIN_WINDOWS = 24          # at least two hours of the host's own history before ranking it
SCORE_FLOOR = 1.0         # ratio at or below 1.0 is "at or below normal"


@dataclass(frozen=True)
class ChannelSpec:
    """One source table, reduced to the two questions every source can answer.

    volume:   how much of this source did the host produce in the window?
    diversity: how many distinct values of `value_column` did it touch?

    A port scan shows up as volume on ssh/conn; a beacon as low volume with fixed diversity; an
    HTTP implant as a new user-agent (diversity) at ordinary volume. One score covers all three.
    """

    channel: str
    family: str
    table: str
    host_column: str
    value_column: str | None = None
    scale: str = "5m"
    #: "count"     -- volume only (the default)
    #: "diversity" -- volume plus distinct values of `value_column`
    #: "ratio"     -- the fraction of rows matching `predicate`
    kind: str = "count"
    predicate: str | None = None
    #: Rows that belong in the denominator. Without this, a field that is mostly unpopulated
    #: (measured live: zeek_ssl.validation_status is empty on 138,439 of 139,058 sessions)
    #: makes every ratio look like noise. The denominator must be "rows where the field is
    #: meaningful", not "all rows".
    denominator: str | None = None
    #: Rows that carry a value at all, for a diversity channel. A TLS session with neither SNI
    #: nor a JA4 fingerprint is ONE anonymous pair, not a distinct one; counting the empty string
    #: would give every host a permanent +1 and make the diversity mostly a row count.
    value_filter: str | None = None
    # ── the multi-scale evidence layer (phase 1) ────────────────────────────────────────────
    #: The timestamp the window is built from. `flows_window` is keyed on `window_start`.
    time_column: str = "ts"
    #: The OTHER endpoint of the row, when the table records one. This is what lets the ripple
    #: layer attribute an inbound flow to the monitored destination instead of its remote
    #: source. `flows_window` has no peer column: it is pre-aggregated by source only, so an
    #: unattributable row there is dropped rather than emitted under the external address.
    peer_column: str | None = None
    #: The scales this source can be measured at. `compute()` skips any scale the lookback
    #: cannot supply a baseline for, so declaring 7d costs nothing where retention is 7 days.
    scales: tuple[str, ...] = ("5m",)
    #: How long the table keeps rows. Used only to say, in the inventory, which scales are
    #: structurally possible; the live check is the sample count against the lookback.
    retention_days: int = 7
    #: A PRE-AGGREGATED source stores one row per five-minute host-window with aggregate
    #: STATES, not values. `flows_window` is the case: it must be read with `-Merge`
    #: combinators, and `uniqMerge` is the only way to get a true distinct count across a
    #: larger bucket. When `count_state` is set the table is read that way; otherwise it is
    #: read as raw rows, exactly as before.
    count_state: str | None = None
    sum_state: str | None = None
    uniq_state: str | None = None
    #: The physical columns this channel reads. `availability()` checks these against
    #: `system.columns` so a channel whose table lacks one is DECLARED UNAVAILABLE with the
    #: missing names, rather than silently producing nothing and looking like a quiet host.
    required_columns: tuple[str, ...] = ()

    def sql(self, *, since_s: int) -> str:
        if self.kind == "diversity":
            if not self.value_column:
                raise ValueError(f"{self.channel}: a diversity channel needs a value column")
            value = f", uniqExact({self.value_column}) AS u"
        elif self.kind == "ratio":
            if not self.predicate:
                raise ValueError(f"{self.channel}: a ratio channel needs a predicate")
            value = f", countIf({self.predicate}) AS u"
        else:
            value = ", 0 AS u"
        n_expr = f"countIf({self.denominator})" if self.denominator else "count()"
        return (f"SELECT {self.host_column}, toStartOfFiveMinute(ts) AS w, {n_expr} AS n{value} "
                f"FROM {self.table} "
                f"WHERE ts >= now() - INTERVAL {int(since_s)} SECOND "
                f"GROUP BY {self.host_column}, w ORDER BY w")

    def _attribution(
        self, scope_cidrs: tuple[str, ...] | None
    ) -> tuple[str, str, str]:
        """`(subject expression, peer expression, scope WHERE fragment)` for one query.

        THE SUBJECT IS THE MONITORED ENDPOINT, never a remote peer: the source when it is
        inside a monitored network, otherwise the destination. `scope_cidrs=None` keeps the
        old source-only shape for callers that do not have a scope list (there are none in
        this package). An empty scope list becomes the predicate `0`, so a caller that passes
        nothing can only under-report rather than measure the whole internet.
        """
        host_expr = self.host_column
        peer_expr = self.peer_column or self.host_column
        scope_where = ""
        if scope_cidrs is None:
            return host_expr, peer_expr, scope_where
        src_in = " OR ".join(
            f"isIPAddressInRange({self.host_column}, '{cidr}')" for cidr in scope_cidrs)
        src_in = src_in or "0"
        if self.peer_column:
            dst_in = " OR ".join(
                f"isIPAddressInRange({self.peer_column}, '{cidr}')" for cidr in scope_cidrs)
            dst_in = dst_in or "0"
            host_expr = f"if(({src_in}), {self.host_column}, {self.peer_column})"
            peer_expr = f"if(({src_in}), {self.peer_column}, {self.host_column})"
            scope_where = f" AND (({src_in}) OR ({dst_in}))"
        else:
            # PRE-AGGREGATED BY SOURCE, with no destination column to fall back to. A row
            # whose source is not monitored cannot be attributed to one of ours, so it is
            # dropped rather than reported under the remote address.
            scope_where = f" AND ({src_in})"
        return host_expr, peer_expr, scope_where

    def sql_values(self, *, bucket_s: int, anchor: datetime, since: datetime,
                   until: datetime,
                   scope_cidrs: tuple[str, ...] | None = None) -> str:
        """One row per DISTINCT VALUE per subject per bucket, for novelty/change channels.

        `sql_anchored` can only say HOW MANY distinct values a bucket held. A novelty channel
        needs to know WHICH values: "a user-agent this host has never sent" is a fact about
        set difference across buckets, and no count can be re-derived into it afterwards.
        The server deduplicates, so the caller never sees one row per event.

        Returns `(host, k, v)` with the same anchored bucket arithmetic and the same subject
        attribution as `sql_anchored`.
        """
        if not self.value_column:
            raise ValueError(f"{self.channel}: a novelty channel needs a value column")
        host_expr, _peer_expr, scope_where = self._attribution(scope_cidrs)
        anchor_ts = int(anchor.timestamp())
        return (
            f"SELECT {host_expr} AS host, "
            f"intDiv({anchor_ts} - toUnixTimestamp({self.time_column}), {int(bucket_s)}) AS k, "
            f"{self.value_column} AS v "
            f"FROM {self.table} "
            f"WHERE {self.time_column} >= '{since:%Y-%m-%d %H:%M:%S}' "
            f"AND {self.time_column} < '{until:%Y-%m-%d %H:%M:%S}'{scope_where} "
            "GROUP BY host, k, v"
        )

    def sql_anchored(self, *, bucket_s: int, anchor: datetime, since: datetime,
                     until: datetime,
                     scope_cidrs: tuple[str, ...] | None = None) -> str:
        """One bucket-per-host query whose buckets end exactly at `anchor`.

        WHY NOT `toStartOfInterval`. Calendar-aligned buckets make the CURRENT bucket partial:
        at 14:37 the 1h window holds 37 minutes while every baseline bucket holds 60, so every
        host looks quiet at the moment it is measured. Here bucket 0 is exactly
        `[anchor - bucket_s, anchor)` and bucket k reaches back k buckets, so the current value
        and its history are the same length.

        WHO THE SUBJECT IS. When `scope_cidrs` is given, the row is attributed to its monitored
        endpoint: the source if the source is inside a monitored network, otherwise the
        destination. A row with neither endpoint monitored is excluded in SQL. This is the rule
        that keeps a remote scanner out of a host-behaviour ripple: the change belongs to the
        internal host that talked to it. `scope_cidrs=None` keeps the old source-only shape for
        callers that do not have a scope list (there are none in this package).

        Returns `(host, k, n, u, b)`: rows in the bucket, distinct/numerator, and sum. The
        caller picks the one its `kind` needs. `k` is counted back from the anchor.
        """
        if self.count_state:
            n_expr = f"countMerge({self.count_state})"
            u_expr = f"uniqMerge({self.uniq_state})" if self.uniq_state else "0"
            b_expr = f"sumMerge({self.sum_state})" if self.sum_state else "0"
            if self.kind == "diversity" and not self.uniq_state:
                raise ValueError(f"{self.channel}: a diversity channel needs a uniq state")
            if self.kind == "sum" and not self.sum_state:
                raise ValueError(f"{self.channel}: a sum channel needs a sum state")
        else:
            n_expr = f"countIf({self.denominator})" if self.denominator else "count()"
            u_expr = "0"
            b_expr = "0"
            if self.kind == "diversity":
                if not self.value_column:
                    raise ValueError(f"{self.channel}: a diversity channel needs a value column")
                u_expr = f"uniqExact({self.value_column})"
                if self.value_filter:
                    u_expr = f"uniqExactIf({self.value_column}, {self.value_filter})"
            elif self.kind == "ratio":
                if not self.predicate:
                    raise ValueError(f"{self.channel}: a ratio channel needs a predicate")
                u_expr = f"countIf({self.predicate})"
            elif self.kind == "sum":
                if not self.value_column:
                    raise ValueError(f"{self.channel}: a sum channel needs a value column")
                b_expr = f"sum({self.value_column})"

        host_expr, peer_expr, scope_where = self._attribution(scope_cidrs)
        # A diversity channel whose value IS the peer column (flow_dst_diversity,
        # conn_dst_diversity) must count the peer FROM THE SUBJECT'S SIDE. Counting
        # dst_addr when the subject is the destination would measure the subject itself
        # and read as a constant one.
        if (scope_cidrs is not None and self.kind == "diversity"
                and self.value_column == self.peer_column):
            u_expr = f"uniqExact({peer_expr})"

        anchor_ts = int(anchor.timestamp())
        return (
            f"SELECT {host_expr} AS host, "
            f"intDiv({anchor_ts} - toUnixTimestamp({self.time_column}), {int(bucket_s)}) AS k, "
            f"{n_expr} AS n, {u_expr} AS u, {b_expr} AS b "
            f"FROM {self.table} "
            f"WHERE {self.time_column} >= '{since:%Y-%m-%d %H:%M:%S}' "
            f"AND {self.time_column} < '{until:%Y-%m-%d %H:%M:%S}'{scope_where} "
            f"GROUP BY host, k"
        )


#: The sources this deployment already collects and the ripple layer could not hear.
SPECS: tuple[ChannelSpec, ...] = (
    ChannelSpec("http", "http", "weirvern.zeek_http", "src_addr", "user_agent", kind="diversity"),
    ChannelSpec("files", "files", "weirvern.zeek_files", "src_addr", "mime_type", kind="diversity"),
    ChannelSpec("ssh", "ssh", "weirvern.zeek_ssh", "src_addr", "client", kind="diversity"),
    ChannelSpec("weird", "weird", "weirvern.zeek_weird", "src_addr", "name", kind="diversity"),
    ChannelSpec("quic", "quic", "weirvern.zeek_quic", "src_addr", "server_name", kind="diversity"),
    ChannelSpec("dhcp", "dhcp", "weirvern.zeek_dhcp", "client_addr", "host_name", kind="diversity"),
    # The second-order fields of sources already in the fusion. Each is a fraction of the
    # host's own traffic, so the baseline is comparable across hosts and volumes.
    ChannelSpec("tls_unvalidated", "tls", "weirvern.zeek_ssl", "src_addr", kind="ratio",
                predicate="lower(validation_status) != 'ok'",
                denominator="validation_status != ''"),
    ChannelSpec("tls_ja4_variety", "tls", "weirvern.zeek_ssl", "src_addr", "ja4_orig",
                kind="diversity"),
    ChannelSpec("dns_tcp", "dns", "weirvern.zeek_dns", "src_addr", kind="ratio",
                predicate="proto = 'tcp'"),
    ChannelSpec("dns_reverse", "dns", "weirvern.zeek_dns", "src_addr", kind="ratio",
                predicate="query LIKE '%in-addr.arpa%'"),
    ChannelSpec("conn_reset", "conn", "weirvern.zeek_conn", "src_addr", kind="ratio",
                predicate="conn_state IN ('RSTO','RSTR','S0','REJ')"),
    ChannelSpec("conn_service_variety", "conn", "weirvern.zeek_conn", "src_addr", "service",
                kind="diversity"),
)


def score_window(n: float, u: float, *, median_n: float, median_u: float) -> float:
    """How far this window sits above the host's own normal, in multiples.

    Ratios rather than z-scores: these counts are heavy-tailed and a mean/std would be set by the
    tail. A window at normal volume and normal diversity scores 1.0; ten times the volume scores
    10.0. Both components are kept because a quiet, diverse window is exactly what a tunnel looks
    like, and a loud, monotonous one is what a scan looks like.
    """
    # A normal window must score exactly 1.0, so the denominator is the median itself; the
    # floor of 1.0 only avoids dividing by zero for a source the host has never used.
    volume = float(n) / (float(median_n) if median_n > 0 else 1.0)
    diversity = float(u) / (float(median_u) if median_u > 0 else 1.0)
    return round(max(volume, diversity), 6)


def _median(values: list[float]) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    middle = len(ordered) // 2
    if len(ordered) % 2:
        return float(ordered[middle])
    return (ordered[middle - 1] + ordered[middle]) / 2.0


def _per_host(rows: list[Any], value_index: int | None) -> dict[str, list[tuple[datetime, float, float]]]:
    out: dict[str, list[tuple[datetime, float, float]]] = {}
    for row in rows:
        host, window, n = str(row[0] or ""), row[1], float(row[2] or 0)
        u = float(row[value_index]) if value_index is not None and len(row) > value_index else 0.0
        if not host:
            continue
        out.setdefault(host, []).append((window, n, u))
    for host in out:
        out[host].sort(key=lambda item: item[0])
    return out


def evidence(client: Any, hosts: list[str], *, now: datetime | None = None,
             specs: tuple[ChannelSpec, ...] = SPECS) -> dict[str, list[ChannelEvidence]]:
    """host -> evidence, one piece per source that has both a current window and history."""
    moment = now or datetime.now(UTC)
    wanted = set(hosts)
    out: dict[str, list[ChannelEvidence]] = {}
    since_s = LOOKBACK_DAYS * 86400

    for spec in specs:
        try:
            rows = list(client.query(spec.sql(since_s=since_s)).result_rows)
        except Exception:  # noqa: BLE001 - one missing source must not silence the others
            continue
        value_index = 3 if spec.kind in {"diversity", "ratio"} else None
        for host, windows in _per_host(rows, value_index).items():
            if host not in wanted or len(windows) < MIN_WINDOWS + 1:
                continue
            history, current = windows[:-1], windows[-1]
            if spec.kind == "ratio":
                # A ratio is already normalised: "12% of this host's connections reset" is
                # comparable across volumes without dividing by a median. Dividing again would
                # make a host whose normal is 0.01 explode on a single event.
                reference = [round(u / n, 6) if n else 0.0 for (_w, n, u) in history]
                score = round(current[2] / current[1], 6) if current[1] else 0.0
            else:
                # Score every historical window against the ones before it, with the same
                # function used on the current one. That is what makes the rank meaningful.
                reference = []
                for index, (_w, n, u) in enumerate(history):
                    prior = history[:index]
                    if not prior:
                        reference.append(SCORE_FLOOR)
                        continue
                    reference.append(score_window(
                        n, u,
                        median_n=_median([x[1] for x in prior]),
                        median_u=_median([x[2] for x in prior])))
                score = score_window(
                    current[1], current[2],
                    median_n=_median([w[1] for w in history]),
                    median_u=_median([w[2] for w in history]))

            reference = [value for value in reference if math.isfinite(value)]
            pvalue = empirical_pvalue(score, reference)
            if not math.isfinite(pvalue):
                continue
            out.setdefault(host, []).append(ChannelEvidence(
                channel=spec.channel, family=spec.family, scale=spec.scale,
                model_id=f"source:{spec.channel}", model_version="source-scan/1",
                score=score, pvalue=pvalue,
                freshness_s=max(0.0, (moment - current[0]).total_seconds()), present=True))
    return out


__all__ = ["ChannelSpec", "LOOKBACK_DAYS", "MIN_WINDOWS", "SPECS", "WINDOW_MINUTES", "evidence",
           "score_window"]
