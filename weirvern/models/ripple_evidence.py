"""The pieces a ripple is made of: one host, one channel, one scale, one empirical p-value.

WHY THIS EXISTS. The operator asked to "show all the ml and the pieces of ripples, then the
anomaly page is actually the ripples". This module is the missing middle: the fusion in
`ripple.py` could say whether a handful of shadow models agreed, and `generic_channels.py` could
score one five-minute window per source, but nothing measured a channel against the SAME host's
own trailing history at more than one scale, and nothing stored the measurement so it could be
read back. A ripple is only as good as the evidence under it.

WHAT A RIPPLE IS HERE. A small, statistically significant change in one channel's behaviour for
one host, measured against that host's OWN trailing history with an empirical p-value. No human
labels and no synthetic ground truth: the baseline is the host's own past, ranked. Several
pieces of evidence that line up in one time window on one host are grouped into one `Ripple` by
`ripple.group_evidence`; the ripple is what an operator reads, the evidence is what it is made
of.

THE SCALES, AND AN HONEST LIMIT. A scale is the length of the window being measured: 1h, 6h,
24h, 7d. A channel can only be measured at a scale the lookback can supply a baseline for, and
the baseline samples are NON-OVERLAPPING windows of that length. With the fixed 7-day lookback
and the 30-window minimum that means:

    1h  -> 167 baseline windows  floor 0.0060  measurable and resolvable below 0.01
    6h  ->  27 baseline windows  floor 0.0357  BELOW THE MINIMUM: not measured
    24h ->   6 baseline windows  floor 0.1429  BELOW THE MINIMUM: not measured
    7d  ->   0 baseline windows  NO EVIDENCE at all

That is not a bug to paper over. `flows` retains 3 days, the Zeek tables 7, so no collected
source can answer "is this week different from this host's previous weeks" yet. The 7d scale is
declared in `EVIDENCE_SCALES` and computed the moment the lookback is raised past 35 days; at
today's retention it produces nothing, which is the honest answer. The same rule kills the 6h
and 24h scales' ability to support the 0.01 ripple bar at a 7-day lookback, so they are reported
as baseline-too-short rather than measured and printed as if their floor meant something.

COVERAGE AND SILENCE. A host with four hours of data in a week does not have a week-long
normal. Evidence is emitted only when the baseline holds at least `MIN_BASELINE_SAMPLES`
non-empty windows AND those windows cover at least `MIN_COVERAGE` of the expected buckets. A
channel with too little history produces NO evidence at all -- never p=1.0, which would read as
"measured and quiet". For the same reason a missing CURRENT bucket produces no evidence: this
layer cannot tell a host that stopped talking from a collector that stopped writing, and the
collection layer owns freshness.

WHO THE SUBJECT IS. A ripple is a change in a MONITORED host's behaviour, never in a remote
peer's. Every row is attributed to its monitored endpoint: the source if the source is inside a
monitored CIDR, otherwise the destination. A flow row with no monitored endpoint is dropped.
`flows_window` is pre-aggregated by source and has no destination column, so a row there whose
source is external cannot be attributed to one of ours and is dropped too -- it is never
reported under the external address. An empty scope list produces no evidence, because "we
could not work out what we own" is not permission to measure everything.

WHAT THIS DOES NOT DO: it never writes `netflow_anomalies`, never pages, never promotes a model
and never touches the anomaly page. Phase 1 is measurement and a read-only card.
"""
from __future__ import annotations

import math
import statistics
from datetime import UTC, datetime, timedelta
from typing import Any

from weirvern import monitored as monitored_mod
from weirvern.models.generic_channels import ChannelSpec
from weirvern.models.ripple import (
    DEFAULT_FAMILY_MAX_P,
    EVIDENCE_SCALE_SECONDS,
    EVIDENCE_SCALES,
    MIN_BASELINE_SAMPLES,
    RIPPLE_WINDOW_S,
    ChannelEvidence,
    empirical_pvalue_two_sided,
    group_evidence,
    min_baseline_samples,
    pvalue_floor,
)

MODEL_VERSION = "ripple-evidence-2"

#: The trailing history every baseline is drawn from. One constant, as phase 1 requires.
LOOKBACK_DAYS = 7

#: The finest bucket any channel is measured in. Every scale is a whole number of these, so an
#: additive statistic is queried once and rolled up; only `diversity` needs a query per scale.
STEP_SECONDS = 3600

#: Below thirty baseline windows a rank is not evidence of anything: the smallest p the test
#: can express is 1/(n+1), and a floor that is not below the decision threshold turns the test's
#: resolution into a fake result. Imported from `ripple` so the grouping and the measurement
#: cannot disagree about what "short" means.
#: (The name is re-exported below for callers that read it from this module.)

#: The share of the expected baseline windows that must actually exist. A baseline drawn from a
#: host's three busiest hours in a week is not its normal; it is its busiest hours.
MIN_COVERAGE = 0.5

#: A pass is bounded so a scope mistake cannot turn an hourly job into an unbounded write.
#: The READ is already bounded by the lookback; this caps what one pass can store.
MAX_HOSTS = 200

ADDITIVE_KINDS = frozenset({"count", "sum", "ratio"})


# ── the channels this deployment can actually hear ──────────────────────────────────────────
#
# Every spec names a REAL table, a real host column and a statistic that table can answer.
# Nothing is declared for a source with no table. The family is one collection pipeline, not one
# channel: `flow_bytes` and `flow_volume` are two units for the SAME flow records, so they share
# a family and can never corroborate each other. See `ripple.CHANNEL_FAMILIES` for the map and
# the reason the other groups are drawn where they are.
#
# `flows_window` is pre-aggregated by source, so it has no peer column and cannot attribute an
# inbound row to its destination. Its rows are filtered to monitored sources; an external
# source is dropped rather than reported under the remote address. The Zeek tables do carry
# `dst_addr`, so those channels attribute an inbound row to the monitored destination.
FLOW_SPECS: tuple[ChannelSpec, ...] = (
    # flows_window is an AggregatingMergeTree. Reading it with plain `count()` would sum
    # partial states as if they were values; the `-Merge` combinators are mandatory.
    ChannelSpec("flow_volume", "flow", "weirvern.flows_window", "src_addr",
                time_column="window_start", kind="count", count_state="flow_count",
                scales=EVIDENCE_SCALES, retention_days=7),
    ChannelSpec("flow_bytes", "flow", "weirvern.flows_window", "src_addr",
                time_column="window_start", kind="sum", count_state="flow_count",
                sum_state="total_bytes", scales=EVIDENCE_SCALES, retention_days=7),
    ChannelSpec("flow_dst_diversity", "flow", "weirvern.flows_window", "src_addr",
                time_column="window_start", kind="diversity", count_state="flow_count",
                uniq_state="unique_dst_ips", scales=EVIDENCE_SCALES, retention_days=7),
)

CONN_SPECS: tuple[ChannelSpec, ...] = (
    ChannelSpec("conn_volume", "conn", "weirvern.zeek_conn", "src_addr",
                peer_column="dst_addr", scales=EVIDENCE_SCALES, retention_days=7),
    ChannelSpec("conn_dst_diversity", "conn", "weirvern.zeek_conn", "src_addr",
                "dst_addr", peer_column="dst_addr", kind="diversity", scales=EVIDENCE_SCALES,
                retention_days=7),
    ChannelSpec("conn_service_diversity", "conn", "weirvern.zeek_conn", "src_addr",
                "service", peer_column="dst_addr", kind="diversity", scales=EVIDENCE_SCALES,
                retention_days=7),
    ChannelSpec("conn_reset_ratio", "conn", "weirvern.zeek_conn", "src_addr",
                peer_column="dst_addr", kind="ratio",
                predicate="conn_state IN ('RSTO','RSTR','S0','REJ')",
                scales=EVIDENCE_SCALES, retention_days=7),
)

DNS_SPECS: tuple[ChannelSpec, ...] = (
    ChannelSpec("dns_volume", "dns", "weirvern.zeek_dns", "src_addr",
                peer_column="dst_addr", scales=EVIDENCE_SCALES, retention_days=7),
    ChannelSpec("dns_query_diversity", "dns", "weirvern.zeek_dns", "src_addr",
                "query", peer_column="dst_addr", kind="diversity", scales=EVIDENCE_SCALES,
                retention_days=7),
    ChannelSpec("dns_nxdomain_ratio", "dns", "weirvern.zeek_dns", "src_addr",
                peer_column="dst_addr", kind="ratio", predicate="rcode = 3",
                scales=EVIDENCE_SCALES, retention_days=7),
    ChannelSpec("dns_reverse_ratio", "dns", "weirvern.zeek_dns", "src_addr",
                peer_column="dst_addr", kind="ratio", predicate="query LIKE '%in-addr.arpa%'",
                scales=EVIDENCE_SCALES, retention_days=7),
)

# The identity tables carry `src_addr` as IPv4 and retain 30-90 days, which is why they are the
# only sources that could ever support a longer lookback without a schema change.
IDENTITY_SPECS: tuple[ChannelSpec, ...] = (
    ChannelSpec("kerberos_volume", "identity", "weirvern.zeek_kerberos", "src_addr",
                peer_column="dst_addr", scales=EVIDENCE_SCALES, retention_days=90),
    ChannelSpec("kerberos_service_diversity", "identity", "weirvern.zeek_kerberos", "src_addr",
                "service", peer_column="dst_addr", kind="diversity",
                scales=EVIDENCE_SCALES, retention_days=90),
    ChannelSpec("ntlm_volume", "identity", "weirvern.zeek_ntlm", "src_addr",
                peer_column="dst_addr", scales=EVIDENCE_SCALES, retention_days=60),
    ChannelSpec("ntlm_user_diversity", "identity", "weirvern.zeek_ntlm", "src_addr",
                "username", peer_column="dst_addr", kind="diversity", scales=EVIDENCE_SCALES,
                retention_days=60),
    ChannelSpec("smb_file_volume", "identity", "weirvern.zeek_smb_files", "src_addr",
                peer_column="dst_addr", scales=EVIDENCE_SCALES, retention_days=30),
    ChannelSpec("smb_path_diversity", "identity", "weirvern.zeek_smb_files", "src_addr",
                "path", peer_column="dst_addr", kind="diversity", scales=EVIDENCE_SCALES,
                retention_days=30),
)

SPECS: tuple[ChannelSpec, ...] = FLOW_SPECS + CONN_SPECS + DNS_SPECS + IDENTITY_SPECS


def effective_lookback_days(spec: ChannelSpec, lookback_days: int = LOOKBACK_DAYS) -> int:
    """How far back this source can actually be read: the lookback, capped by its retention.

    `flows` keeps 3 days while the Zeek tables keep 7. Measuring a 7-day baseline against a
    3-day table would count coverage against windows that do not exist; capping here is what
    makes `coverage` mean "share of the possible history", not "share of a wish".
    """
    return max(0, min(int(lookback_days), int(spec.retention_days)))


def baseline_windows(scale: str, lookback_days: int = LOOKBACK_DAYS) -> int:
    """How many non-overlapping baseline windows of `scale` fit before the current one."""
    seconds = EVIDENCE_SCALE_SECONDS.get(scale)
    if not seconds:
        return 0
    return max(0, int(lookback_days * 86400) // int(seconds) - 1)


def scale_report(scale: str, lookback_days: int = LOOKBACK_DAYS) -> dict[str, Any]:
    """The baseline a scale can offer, and whether that is enough to decide anything.

    `p_floor` is the smallest p a FULL baseline at this scale could express. A scale is usable
    only when it has the minimum number of windows AND that floor is strictly below the ripple
    family bar; otherwise the honest statement is "baseline too short at this scale", which the
    API exposes instead of printing a floor value as a result.
    """
    windows = baseline_windows(scale, lookback_days)
    minimum = min_baseline_samples(scale)
    floor = pvalue_floor(windows)
    if windows < minimum:
        reason = (f"baseline too short at this scale: {windows} window(s), "
                  f"{minimum} required")
        usable = False
    elif floor >= DEFAULT_FAMILY_MAX_P:
        reason = (f"baseline cannot resolve p < {DEFAULT_FAMILY_MAX_P:g} at this scale: "
                  f"floor {floor:.4f} with {windows} windows")
        usable = False
    else:
        reason = ""
        usable = True
    return {
        "baseline_windows": windows,
        "minimum_windows": minimum,
        "p_floor": round(floor, 6),
        "usable": usable,
        "reason": reason,
    }


def supported_scales(spec: ChannelSpec, lookback_days: int = LOOKBACK_DAYS) -> list[str]:
    """The scales this channel can actually be measured at, given its retention and the floor.

    A scale with fewer than `min_baseline_samples(scale)` windows is NOT listed. That is what
    makes the inventory honest: 7d is absent everywhere in this deployment, and a channel is
    never scored against a baseline it does not have.
    """
    effective = effective_lookback_days(spec, lookback_days)
    return [scale for scale in spec.scales
            if baseline_windows(scale, effective) >= min_baseline_samples(scale)]


def statistic(spec: ChannelSpec) -> str:
    """One phrase naming what the channel measures, for the inventory and the operator."""
    if spec.kind == "count":
        return "rows per window"
    if spec.kind == "sum":
        return f"sum of {spec.value_column or spec.sum_state} per window"
    if spec.kind == "diversity":
        return f"distinct {spec.value_column or spec.uniq_state} per window"
    return f"fraction where {spec.predicate}"


def inventory(lookback_days: int = LOOKBACK_DAYS) -> list[dict[str, Any]]:
    """What this deployment can hear, as data rather than prose.

    `scales` is what the channel can be measured at TODAY; `scale_detail` says why each declared
    scale is or is not usable, including the baseline's p-value floor. A scale missing from
    `scales` is missing for a reason, and the reason is visible in `baseline_windows` and
    `p_floor` rather than hidden in a comment.
    """
    out: list[dict[str, Any]] = []
    for spec in SPECS:
        effective = effective_lookback_days(spec, lookback_days)
        out.append({
            "channel": spec.channel,
            "family": spec.family,
            "source": spec.table,
            "statistic": statistic(spec),
            "scales": supported_scales(spec, lookback_days),
            "scale_detail": {scale: scale_report(scale, effective) for scale in spec.scales},
            "retention_days": spec.retention_days,
        })
    return out


# ── measuring ───────────────────────────────────────────────────────────────────────────────

def _aware(value: datetime) -> datetime:
    """ClickHouse and callers both hand back naive UTC; this package compares aware UTC."""
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _value(spec: ChannelSpec, bucket: tuple[float, float, float]) -> float:
    """The statistic for one bucket: (n rows, u distinct-or-numerator, b sum)."""
    n, u, b = bucket
    if spec.kind == "count":
        return float(n)
    if spec.kind == "sum":
        return float(b)
    if spec.kind == "diversity":
        return float(u)
    if spec.kind == "ratio":
        # A ratio is already normalised: "12% of this host's connections reset" is comparable
        # across volumes. Dividing by a median again would turn a 1% normal into infinity.
        return float(u) / float(n) if n else 0.0
    return float("nan")


def _fold(rows: list[Any], *, factor: int) -> dict[str, dict[int, tuple[float, float, float]]]:
    """Bucket rows into `factor`-sized groups by summing the parts.

    Only valid for additive statistics, and only called for those. `diversity` is queried at the
    scale itself because a distinct count cannot be reconstructed from smaller distinct counts.
    """
    out: dict[str, dict[int, tuple[float, float, float]]] = {}
    for row in rows:
        host = str(row[0] or "")
        if not host or row[1] is None:
            continue
        index = int(row[1]) // max(1, int(factor))
        n = float(row[2] or 0)
        u = float(row[3] or 0)
        b = float(row[4] or 0) if len(row) > 4 else 0.0
        held = out.setdefault(host, {}).get(index)
        out[host][index] = (n, u, b) if held is None else (
            held[0] + n, held[1] + u, held[2] + b)
    return out


def _buckets(
    client: Any, spec: ChannelSpec, *, scale: str, moment: datetime, lookback_days: int,
    scope_cidrs: tuple[str, ...] | None,
) -> dict[str, dict[int, tuple[float, float, float]]]:
    """One channel's per-bucket values for one scale, including the current bucket at k=0."""
    seconds = EVIDENCE_SCALE_SECONDS[scale]
    step = STEP_SECONDS if spec.kind in ADDITIVE_KINDS else seconds
    sql = spec.sql_anchored(
        bucket_s=step,
        anchor=moment,
        since=moment - timedelta(days=int(lookback_days)),
        until=moment,
        scope_cidrs=scope_cidrs,
    )
    rows = list(client.query(sql).result_rows)
    return _fold(rows, factor=max(1, seconds // step))


def _evidence_for_scale(spec: ChannelSpec, *, scale: str, buckets: dict[str, dict[int, tuple]],
                        moment: datetime, wanted: set[str] | None,
                        lookback_days: int) -> list[ChannelEvidence]:
    expected = baseline_windows(scale, lookback_days)
    minimum = min_baseline_samples(scale)
    out: list[ChannelEvidence] = []
    for host, by_index in buckets.items():
        if wanted is not None and host not in wanted:
            continue
        current = by_index.get(0)
        # NO CURRENT BUCKET, NO EVIDENCE. A host with no rows this hour may be silent or the
        # collector may be down; this layer cannot tell those apart, and inventing a zero would
        # turn a broken feed into a "drop" on every host at once.
        if current is None:
            continue
        history = {index: bucket for index, bucket in by_index.items() if index >= 1}
        coverage = len(history) / expected if expected else 0.0
        if len(history) < minimum or coverage < MIN_COVERAGE:
            continue
        value = _value(spec, current)
        reference = [_value(spec, bucket) for bucket in history.values()]
        if not math.isfinite(value) or not reference:
            continue
        median = float(statistics.median(reference))
        pvalue = empirical_pvalue_two_sided(value, reference)
        if not math.isfinite(pvalue):
            continue
        direction = "rose" if value > median else "fell" if value < median else "unchanged"
        out.append(ChannelEvidence(
            channel=spec.channel, family=spec.family, scale=scale,
            model_id=f"source:{spec.channel}", model_version=MODEL_VERSION,
            score=value, pvalue=pvalue, freshness_s=0.0, present=True,
            host=host, observed_at=moment, value=value, baseline_median=median,
            sample_count=len(reference), coverage=round(coverage, 4), direction=direction,
            p_floor=pvalue_floor(len(reference)), baseline_short=len(reference) < minimum,
        ))
    return out


def compute(client: Any, *, now: datetime | None = None, hosts: list[str] | None = None,
            lookback_days: int = LOOKBACK_DAYS,
            specs: tuple[ChannelSpec, ...] = SPECS,
            monitored_nets: list[Any] | None = None) -> list[ChannelEvidence]:
    """Every channel's evidence for every host it can be measured for, at every usable scale.

    ONLY MONITORED SUBJECTS. The operator's monitored networks are read from `network_scopes`
    unless the caller supplies them. Every row is attributed in SQL to its monitored endpoint
    (source first, otherwise destination), and an empty scope list produces no evidence at all:
    "we could not work out what we own" must not degrade into "measure everything".

    A source that cannot be read is skipped, not fatal: one missing table must not silence the
    other sixteen channels. The skip is visible because the channel is absent from the result
    while its siblings are present.
    """
    nets = (monitored_nets if monitored_nets is not None
            else monitored_mod.networks(client))
    if not nets:
        return []
    cidrs = tuple(str(net) for net in nets)
    moment = _aware(now or datetime.now(UTC)).replace(microsecond=0)
    wanted = set(hosts) if hosts is not None else None
    out: list[ChannelEvidence] = []
    for spec in specs:
        effective = effective_lookback_days(spec, lookback_days)
        scales = supported_scales(spec, lookback_days)
        if not scales:
            continue
        try:
            if spec.kind in ADDITIVE_KINDS:
                # One query at the finest bucket; every scale is then a sum of whole buckets.
                base = _buckets(client, spec, scale="1h", moment=moment,
                                lookback_days=effective, scope_cidrs=cidrs)
                for scale in scales:
                    factor = EVIDENCE_SCALE_SECONDS[scale] // STEP_SECONDS
                    folded = _fold_from_buckets(base, factor)
                    out.extend(_evidence_for_scale(
                        spec, scale=scale, buckets=folded, moment=moment,
                        wanted=wanted, lookback_days=effective))
            else:
                for scale in scales:
                    buckets = _buckets(client, spec, scale=scale, moment=moment,
                                       lookback_days=effective, scope_cidrs=cidrs)
                    out.extend(_evidence_for_scale(
                        spec, scale=scale, buckets=buckets, moment=moment,
                        wanted=wanted, lookback_days=effective))
        except Exception:  # noqa: BLE001 - one unreadable source must not silence the rest
            continue
    # DEFENCE IN DEPTH: the SQL attributed every row, but a stored or injected row must never
    # leave this function under a peer address.
    out = [item for item in out if monitored_mod.in_scope(item.host, nets)]
    out.sort(key=lambda item: (item.host, item.channel, item.scale))
    if wanted is None and len({item.host for item in out}) > MAX_HOSTS:
        keep = sorted({item.host for item in out})[:MAX_HOSTS]
        out = [item for item in out if item.host in set(keep)]
    return out


def _fold_from_buckets(buckets: dict[str, dict[int, tuple[float, float, float]]],
                       factor: int) -> dict[str, dict[int, tuple[float, float, float]]]:
    """Roll already-folded one-hour buckets up to a coarser scale."""
    if factor <= 1:
        return buckets
    out: dict[str, dict[int, tuple[float, float, float]]] = {}
    for host, by_index in buckets.items():
        for index, (n, u, b) in by_index.items():
            target = index // factor
            held = out.setdefault(host, {}).get(target)
            out[host][target] = (n, u, b) if held is None else (
                held[0] + n, held[1] + u, held[2] + b)
    return out


# ── persistence ─────────────────────────────────────────────────────────────────────────────

COLUMNS = ["window_start", "window_end", "src_addr", "channel", "family", "scale", "value",
           "baseline_median", "p_value", "sample_count", "coverage", "direction",
           "model_version", "observed_at", "computed_at"]


def _row(item: ChannelEvidence) -> list[Any]:
    moment = item.observed_at or datetime.now(UTC)
    start = moment.replace(minute=0, second=0, microsecond=0)
    return [start, start + timedelta(seconds=RIPPLE_WINDOW_S), item.host, item.channel,
            item.family, item.scale, float(item.value), float(item.baseline_median),
            float(item.pvalue), int(item.sample_count), float(item.coverage), item.direction,
            MODEL_VERSION, moment, moment]


def store(client: Any, items: list[ChannelEvidence]) -> int:
    """Write one row per (window, host, channel, scale); ReplacingMergeTree keeps the newest."""
    rows = [_row(item) for item in items if item.host]
    if not rows:
        return 0
    client.insert("weirvern.ml_ripple_evidence", rows, column_names=COLUMNS)
    return len(rows)


READ_COLUMNS = ["window_start", "window_end", "src_addr", "channel", "family", "scale", "value",
                "baseline_median", "p_value", "sample_count", "coverage", "direction",
                "observed_at"]

READ_SQL = (
    "SELECT " + ", ".join(READ_COLUMNS) + " "
    "FROM weirvern.ml_ripple_evidence FINAL "
    "WHERE window_start >= %(since)s "
    "ORDER BY window_start DESC, src_addr, channel, scale "
    "LIMIT %(limit)s"
)

#: A bounded read. 24h at this deployment's cardinality is ~26k rows; the cap keeps a 7-day
#: window from turning one poll into an unbounded scan while still covering every host.
MAX_READ_ROWS = 100_000


def read(client: Any, *, hours: int = 24, now: datetime | None = None) -> list[ChannelEvidence]:
    """Evidence inside the window, newest first, as `ChannelEvidence` objects."""
    moment = _aware(now or datetime.now(UTC))
    since = moment - timedelta(hours=max(1, int(hours)))
    rows = list(client.query(READ_SQL, parameters={"since": since,
                                                   "limit": MAX_READ_ROWS}).result_rows)
    out: list[ChannelEvidence] = []
    for row in rows:
        (window_start, _window_end, host, channel, family, scale, value, median, pvalue,
         sample_count, coverage, direction, observed_at) = row
        out.append(ChannelEvidence(
            channel=str(channel or ""), family=str(family or ""), scale=str(scale or ""),
            model_id=f"source:{channel}", model_version=MODEL_VERSION,
            score=float(value or 0.0), pvalue=float(pvalue), freshness_s=0.0, present=True,
            host=str(host or ""), observed_at=_aware(observed_at),
            value=float(value or 0.0), baseline_median=float(median or 0.0),
            sample_count=int(sample_count or 0), coverage=float(coverage or 0.0),
            direction=str(direction or ""),
            p_floor=pvalue_floor(int(sample_count or 0)),
            baseline_short=int(sample_count or 0) < min_baseline_samples(str(scale or "")),
        ))
    return out


def run(client: Any, *, now: datetime | None = None, hosts: list[str] | None = None,
        lookback_days: int = LOOKBACK_DAYS) -> dict[str, Any]:
    """Measure every channel, store the evidence, and return the counts the worker logs.

    THE RIPPLES ARE NOT STORED. A ripple is a deterministic projection of its evidence, so
    persisting it would create a second copy that can disagree with the rows it is made of
    (after a TTL, a re-run, or a changed grouping constant). The read path groups evidence
    instead, which keeps the explanation and the numbers in the same rows.
    """
    items = compute(client, now=now, hosts=hosts, lookback_days=lookback_days)
    stored = store(client, items)
    return {
        "evidence": len(items),
        "rows": stored,
        "hosts": len({item.host for item in items}),
        "channels": len({item.channel for item in items}),
        "scales": sorted({item.scale for item in items}),
        "model_version": MODEL_VERSION,
    }


def overview(client: Any, *, hours: int = 24, now: datetime | None = None) -> dict[str, Any]:
    """The read path: ripples plus the evidence they were grouped from, newest first.

    A failed read is a NAMED, EMPTY answer, not an exception and never a 500: the Models card
    must be able to draw "the evidence could not be read" around an empty list, which is a
    different statement from "no ripple formed". `available: false` is that distinction.

    `baseline` is the other distinction the card needs: a scale whose baseline cannot resolve
    the ripple bar is reported as such, with its window count and p-value floor, instead of
    letting a floor value be printed as if it were a result. `monitored_networks` is the scope
    the subjects were filtered to; an empty list means no subject could be attributed.
    """
    window_hours = max(1, int(hours))
    try:
        items = read(client, hours=window_hours, now=now)
    except Exception as exc:  # noqa: BLE001 - a read failure is a state, not a crash
        return {
            "available": False,
            "reason": f"could not read the ripple evidence: {type(exc).__name__}: "
                      f"{str(exc)[:160]}",
            "window_hours": window_hours,
            "model_version": MODEL_VERSION,
            "count": 0,
            "ripples": [],
        }
    nets = monitored_mod.networks(client)
    in_scope = [item for item in items if monitored_mod.in_scope(item.host, nets)]
    ripples = group_evidence(in_scope, monitored=nets)
    return {
        "available": True,
        "reason": "",
        "window_hours": window_hours,
        "model_version": MODEL_VERSION,
        "count": len(ripples),
        "ripples": [ripple.as_dict() for ripple in ripples],
        "monitored_networks": [str(net) for net in nets],
        "baseline": {scale: scale_report(scale) for scale in EVIDENCE_SCALES},
        "evidence": {
            "rows": len(items),
            "monitored_rows": len(in_scope),
            "subjects": len({item.host for item in in_scope}),
            "baseline_short_rows": sum(1 for item in in_scope if item.baseline_short),
        },
    }


__all__ = ["COLUMNS", "LOOKBACK_DAYS", "MAX_HOSTS", "MIN_BASELINE_SAMPLES", "MIN_COVERAGE",
           "MODEL_VERSION", "SPECS", "baseline_windows", "compute", "effective_lookback_days",
           "inventory", "overview", "read", "run", "scale_report", "statistic", "store",
           "supported_scales"]
