"""The host-hour: the unit the engine decides on, built on the window it already measures.

WHY THIS MODULE EXISTS
======================

A 22-host network produces about 87,000 five-minute host-windows a day and 528 host-hours.
Deciding per window gives the engine 165 times more opportunities to raise a false alarm on
the same evidence, and the measured result is 176 episodes a day against a budget of ten to
twenty. This is not a detector problem; it is an arithmetic one. The five-minute window stays
the atom -- `flows_window` and the sweep are untouched -- and this module merges twelve of
them into the hour that is scored.

WHAT "NORMAL" MEANS HERE
========================

Normal is the host's own past hours at the same time of day. Not a global model, not a
three-column mean: a per-host reference of whole hours, sampled across whole days, compared
with median and MAD. Fourteen days gives fourteen examples for a given hour, which is too few
to be stable, so the phase is pooled symmetrically until it holds at least fifty examples --
`phase_hours` records how wide the pooling had to go, so a thin phase is visible rather than
silently noisy.

The hour-of-day match is a SAMPLING RULE, not a seasonality term. Nothing models the rhythm;
the reference simply draws its samples from comparable hours.

THE P-VALUE IS EMPIRICAL, AND THAT IS THE POINT
==============================================

Each channel emits one p-value per host-hour: the share of the reference hours whose own
channel statistic was at least as extreme. `calibration.conformal_pvalue` is that formula and
is reused rather than restated.

A feature-level z-score cannot produce this honestly. The channel statistic is a MAX over
several features, and the distribution of a maximum is not the distribution of its parts --
so the reference's own per-hour channel scores are kept as samples. That is what makes the
p-value conformal instead of a normal approximation wearing a p-value's clothes.

FUSION, AND WHY IT IS BY FAMILY
===============================

Channels inside a family see the same underlying spike, so the family takes the MAX (the
strongest channel), never a combination -- a host is not more anomalous because four views of
one burst agree. Families are combined with Fisher, and today there is one family (flows);
DNS joins as a second when its channels land. The dependency Fisher assumes is imperfect even
then, which is acceptable only because the operating point is derived from the empirical
distribution of the fused statistic, so any dependence is already inside the threshold.
"""

from __future__ import annotations

import math
import statistics
from collections import defaultdict
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from typing import Any

from weirvern.clock import utcnow
from weirvern.models.calibration import conformal_pvalue

# Features the channels read, in the order the schema stores them.
FEATURES: tuple[str, ...] = (
    "log_bytes",
    "log_packets",
    "log_flows",
    "bytes_per_flow",
    "dst_hosts",
)

# A channel is a named group of features that measure the same underlying behaviour. The
# family map below the channel list is what fusion uses.
CHANNELS: dict[str, tuple[str, ...]] = {
    "volume": ("log_bytes", "log_packets", "log_flows", "bytes_per_flow"),
    "destinations": ("dst_hosts",),
}

# Channels that see the same traffic through different statistics. Max inside, Fisher across.
FAMILIES: dict[str, tuple[str, ...]] = {
    "flow": ("volume", "destinations"),
}

# Fifty examples is the design's floor for a stable median and MAD; below it the phase is
# pooled outward. Six hours either side is the widest we will go before saying "no reference"
# rather than pretending a thin sample is a baseline.
MIN_PHASE_SAMPLES = 50
MAX_PHASE_POOL_HOURS = 6

# The denominator floor for robust_z. A feature that has never varied has MAD 0, and dividing
# by zero would turn a one-unit change into infinity. Five percent of the host's typical value
# is large enough to keep a stable feature stable and small enough to notice a real move.
SCALE_FLOOR_FRACTION = 0.05

# A channel whose reference has fewer samples than this abstains instead of scoring.
MIN_CHANNEL_SAMPLES = MIN_PHASE_SAMPLES

STATES = ("scored", "no-reference", "no-data", "error")


# ── ONE CLOCK FOR BOTH SIDES OF A SUBTRACTION ─────────────────────────────────────────────────
#
# ClickHouse's unzoned `DateTime` is the SERVER'S WALL CLOCK, not UTC. The driver may hand it
# back with the deployment offset attached (`...16:00:00-06:00`), and this module used to convert
# that to UTC and then compare it with a naive UTC clock. On a host six hours west of UTC the two
# sides differed by six hours: the tick's six-hour window started in the future, found zero rows,
# and the host-hour tables stayed empty while every probe read green.
#
# The fix is to keep ONE wall clock, the one the column stores. An aware value keeps its wall
# clock and drops the offset; a naive value is already that wall clock and is left alone. Strings
# are accepted because a driver or a test shim may hand back text.

def hour_key(value: Any) -> datetime | None:
    """The offset-free SERVER wall clock for a stored timestamp (None when unreadable).

    Use this on BOTH sides of every comparison or subtraction in this module. Sorting mixed
    values raises the same TypeError that subtracting them does.
    """
    if value is None:
        return None
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        except ValueError:
            return None
    if not isinstance(value, datetime):
        return None
    # ONE INSTANT, AWARE UTC. The column is unzoned and stores the deployment's wall clock, so a
    # stored 18:00 at -06:00 is midnight UTC. `read_features` converts the window back to that
    # wall clock at the SQL boundary; that conversion is the missing half this module needed.
    if value.tzinfo is None:
        value = value.astimezone()  # legacy naive values mean local time
    return value.astimezone(UTC)


# ── pure: features ────────────────────────────────────────────────────────────────────────────

def feature_vector(*, flow_count: int, total_bytes: int, total_packets: int,
                   dst_hosts: int) -> dict[str, float]:
    """The comparable vector for one host-hour.

    Logs for the counts: a busy hour is not ten thousand times more anomalous than a quiet
    one, it is a few sigma. A ratio for bytes per flow so a host doing the same work in
    fewer, larger connections is visible rather than cancelled out.
    """
    flows = max(int(flow_count), 1)
    return {
        "log_bytes": math.log1p(max(int(total_bytes), 0)),
        "log_packets": math.log1p(max(int(total_packets), 0)),
        # log1p of the ACTUAL count: an hour with no flows is 0, not log1p(1). The ratio below
        # still guards its denominator so a zero-flow row cannot divide by zero.
        "log_flows": math.log1p(max(int(flow_count), 0)),
        "bytes_per_flow": float(total_bytes) / flows,
        "dst_hosts": float(dst_hosts),
    }


def scale_floor(median: float) -> float:
    return SCALE_FLOOR_FRACTION * max(1.0, abs(float(median)))


def robust_z(value: float, median: float, mad: float) -> float:
    """(x - median) / max(1.4826 * MAD, floor).

    MAD rather than standard deviation because a single burst must not define the spread it
    is then judged against -- the measured difference on this data was 5.0% actual false
    alarms at a nominal 1% for mean/sigma against 1.14% for median/MAD.
    """
    denom = max(1.4826 * float(mad), scale_floor(median))
    return (float(value) - float(median)) / denom


def pool_phase(by_hour_of_day: dict[int, list[float]], hour_of_day: int,
               *, min_samples: int = MIN_PHASE_SAMPLES,
               max_width: int = MAX_PHASE_POOL_HOURS) -> tuple[list[float], int]:
    """Samples for `hour_of_day`, widened symmetrically until there are enough of them.

    Returns the samples and the width actually used (0 = the hour alone). Widening stops at
    `max_width`; a caller that still has too few must say "no reference", never score against
    a sample it does not have.
    """
    samples = list(by_hour_of_day.get(int(hour_of_day), []))
    if len(samples) >= min_samples:
        return samples, 0
    for width in range(1, int(max_width) + 1):
        for phase in ((hour_of_day - width) % 24, (hour_of_day + width) % 24):
            samples.extend(by_hour_of_day.get(phase, []))
        if len(samples) >= min_samples:
            return samples, width
    return samples, int(max_width)


def summarize(samples: Iterable[float]) -> dict[str, float] | None:
    """median, MAD, p01, p99 and n -- or None when there is nothing to summarize."""
    values = [float(v) for v in samples if v is not None and not math.isnan(float(v))]
    if not values:
        return None
    ordered = sorted(values)
    median = statistics.median(ordered)
    mad = statistics.median([abs(v - median) for v in ordered])
    n = len(ordered)
    return {
        "median": median,
        "mad": mad,
        "p01": ordered[max(0, int(round(0.01 * (n - 1))))],
        "p99": ordered[min(n - 1, int(round(0.99 * (n - 1))))],
        "n": n,
    }


def channel_score(vector: dict[str, float],
                  stats: dict[str, dict[str, float]]) -> tuple[str, dict[str, float]]:
    """The channel statistic: the largest absolute robust z among the channel's features.

    Returns (state, {channel: score}). A channel whose features all lack a usable reference
    is `no-reference`; a vector missing every feature is `no-data`.
    """
    if not vector:
        return "no-data", {}
    scores: dict[str, float] = {}
    for channel, features in CHANNELS.items():
        usable = [f for f in features
                  if f in vector and f in stats and int(stats[f].get("n", 0)) >= MIN_CHANNEL_SAMPLES]
        if not usable:
            continue
        scores[channel] = max(abs(robust_z(vector[f], stats[f]["median"], stats[f]["mad"]))
                              for f in usable)
    if not scores:
        return "no-reference", {}
    return "scored", scores


def fuse(channel_ps: dict[str, float]) -> dict[str, Any]:
    """Max inside a family, Fisher across families.

    With one family the fused p IS that family's p, and `families` says so -- a caller must be
    able to tell "one family agreed" from "two did", because the second is corroboration and
    the first is a single view.
    """
    usable = {name: float(p) for name, p in channel_ps.items()
              if p is not None and not math.isnan(float(p))}
    if not usable:
        return {"fused_p": None, "family_p": {}, "families": 0}
    family_p: dict[str, float] = {}
    for family, channels in FAMILIES.items():
        ps = [usable[c] for c in channels if c in usable]
        if ps:
            family_p[family] = min(ps)
    # Any channel not named in a family is its own family, so a future channel cannot be
    # silently dropped from the fusion by forgetting to register it.
    named = {c for channels in FAMILIES.values() for c in channels}
    for channel, p in usable.items():
        if channel not in named:
            family_p[channel] = p
    if not family_p:
        return {"fused_p": None, "family_p": {}, "families": 0}
    fused = _fisher(list(family_p.values()))
    return {"fused_p": fused, "family_p": family_p, "families": len(family_p)}


def _fisher(ps: list[float]) -> float:
    """Fisher's combined p for independent tests; chi-square survival with 2k df.

    The closed form for even degrees of freedom, so no scipy dependency:
        sf(x, 2k) = exp(-x/2) * sum_{i=0}^{k-1} (x/2)^i / i!
    """
    k = len(ps)
    x = -2.0 * sum(math.log(max(min(p, 1.0), 1e-300)) for p in ps)
    half = x / 2.0
    term = 1.0
    total = 1.0
    for i in range(1, k):
        term *= half / i
        total += term
    return max(0.0, min(1.0, math.exp(-half) * total))


def is_episode(previous_anomalous: bool, current_anomalous: bool,
               signature: bool = False) -> bool:
    """Persistence: two consecutive anomalous hours, or one hour plus a structural signature.

    This is the rule that buys precision without losing speed -- it does the work a second
    detector was being asked to do, and unlike a detector it can be measured directly.
    """
    return bool(current_anomalous and (previous_anomalous or signature))


# ── database: build, reference, score ─────────────────────────────────────────────────────────

_FEATURE_COLUMNS = ("hour", "src_addr", "flow_count", "total_bytes", "total_packets",
                    "dst_hosts", "log_bytes", "log_packets", "log_flows", "bytes_per_flow")


def build_features(client: Any, since: datetime, until: datetime) -> int:
    """Merge the hour's five-minute windows from the raw flow log and store the vector.

    Raw `flows`, not `flows_window`, for the destination count: a uniq state cannot be merged
    across window boundaries and summing per-window uniques over-counts a destination seen in
    two windows. At this scale an hour is about 38,000 rows. The counts and sums would be
    identical either way.
    """
    sql = f"""
        SELECT
            toStartOfHour(time_flow_start)              AS hour,
            src_addr,
            count()                                    AS flow_count,
            sum(toUInt64(bytes))                       AS total_bytes,
            sum(toUInt64(packets))                     AS total_packets,
            uniq(dst_addr)                             AS dst_hosts,
            log1p(sum(toUInt64(bytes)))                AS log_bytes,
            log1p(sum(toUInt64(packets)))              AS log_packets,
            log1p(count())                             AS log_flows,
            sum(toUInt64(bytes)) / greatest(count(), 1) AS bytes_per_flow
        FROM weirvern.flows
        WHERE time_flow_start >= '{since:%Y-%m-%d %H:%M:%S}'
          AND time_flow_start <  '{until:%Y-%m-%d %H:%M:%S}'
        GROUP BY hour, src_addr
        ORDER BY hour, src_addr
    """
    rows = client.query(sql).result_rows
    if not rows:
        return 0
    now = utcnow()
    client.insert(
        "weirvern.host_hour_features",
        [(*r, now) for r in rows],
        column_names=[*_FEATURE_COLUMNS, "computed_at"],
    )
    return len(rows)


def read_features(client: Any, since: datetime, until: datetime) -> list[dict[str, Any]]:
    # THE SQL BOUNDARY IS THE COLUMN'S OWN WALL CLOCK. `since`/`until` are aware UTC; the
    # unzoned DateTime stores deployment-local wall clock, so format the local reading of the
    # same instant. Without this the window was six hours off its own rows on a CST host.
    def _wall(value: datetime) -> str:
        return (value if value.tzinfo is not None else value.astimezone()).astimezone() \
            .strftime("%Y-%m-%d %H:%M:%S")

    sql = f"""
        SELECT hour, src_addr, flow_count, total_bytes, total_packets, dst_hosts,
               log_bytes, log_packets, log_flows, bytes_per_flow
        FROM weirvern.host_hour_features FINAL
        WHERE hour >= '{_wall(since)}' AND hour < '{_wall(until)}'
        ORDER BY hour, src_addr
    """
    cols = list(_FEATURE_COLUMNS)
    return [dict(zip(cols, row, strict=False)) for row in client.query(sql).result_rows]


def rebuild_references(client: Any, *, days: int = 30,
                       now: datetime | None = None) -> dict[str, int]:
    """Recompute, per host, what normal looks like at each hour of day.

    Writes the summary stats AND the reference's own per-hour channel scores, because the
    p-value is the empirical tail of the latter. A reference hour is scored against stats
    that include itself; with fifty-plus samples that shifts the p-value by at most 1/n and
    keeps the rebuild cheap enough to run daily.
    """
    end = (hour_key(now) if now is not None else None) or utcnow()
    start = end - timedelta(days=int(days))
    rows = read_features(client, start, end)
    if not rows:
        return {"hosts": 0, "stats": 0, "samples": 0}

    by_host: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_host[str(row["src_addr"])].append(row)

    stats_rows: list[tuple] = []
    sample_rows: list[tuple] = []
    computed_at = end
    for host, hours in by_host.items():
        values: dict[int, dict[str, list[float]]] = defaultdict(lambda: defaultdict(list))
        for row in hours:
            phase = int(row["hour"].hour)
            for feature in FEATURES:
                values[phase][feature].append(float(row[feature]))

        # One stats row per (phase, feature), pooled exactly as a live score will pool.
        stats: dict[int, dict[str, dict[str, float]]] = {}
        for phase in range(24):
            stats[phase] = {}
            for feature in FEATURES:
                # Pool across the PHASES for this feature, not across features for this phase.
                series = {ph: values[ph][feature] for ph in range(24)}
                samples, width = pool_phase(series, phase)
                summary = summarize(samples)
                if summary is None:
                    continue
                stats[phase][feature] = summary
                stats_rows.append((host, phase, feature, summary["median"], summary["mad"],
                                   summary["p01"], summary["p99"], int(summary["n"]),
                                   int(width), int(days), computed_at))

        # The reference's own channel scores, one per reference hour.
        for row in hours:
            phase = int(row["hour"].hour)
            vector = {f: float(row[f]) for f in FEATURES}
            state, scores = channel_score(vector, stats[phase])
            if state != "scored":
                continue
            for channel, score in scores.items():
                sample_rows.append((host, phase, channel, float(score), row["hour"], computed_at))

    if stats_rows:
        client.insert("weirvern.host_reference_stats", stats_rows,
                      column_names=["src_addr", "hour_of_day", "feature", "median", "mad",
                                    "p01", "p99", "n", "phase_hours", "window_days",
                                    "computed_at"])
    if sample_rows:
        client.insert("weirvern.host_reference_samples", sample_rows,
                      column_names=["src_addr", "hour_of_day", "channel", "score",
                                    "observed_at", "computed_at"])
    return {"hosts": len(by_host), "stats": len(stats_rows), "samples": len(sample_rows)}


def load_reference(client: Any) -> tuple[dict[str, dict[int, dict[str, dict[str, float]]]],
                                         dict[str, dict[int, dict[str, list[float]]]]]:
    """(stats, samples) keyed host -> hour_of_day -> feature/channel."""
    stats: dict[str, dict[int, dict[str, dict[str, float]]]] = defaultdict(dict)
    for host, phase, feature, median, mad, p01, p99, n, width in client.query(
            "SELECT src_addr, hour_of_day, feature, median, mad, p01, p99, n, phase_hours "
            "FROM weirvern.host_reference_stats FINAL").result_rows:
        stats[str(host)].setdefault(int(phase), {})[str(feature)] = {
            "median": float(median), "mad": float(mad), "p01": float(p01),
            "p99": float(p99), "n": int(n), "phase_hours": int(width)}

    samples: dict[str, dict[int, dict[str, list[float]]]] = defaultdict(dict)
    for host, phase, channel, score in client.query(
            "SELECT src_addr, hour_of_day, channel, score "
            "FROM weirvern.host_reference_samples FINAL").result_rows:
        samples[str(host)].setdefault(int(phase), {}).setdefault(str(channel), []).append(
            float(score))
    return stats, samples


def pooled_samples(samples: dict[int, dict[str, list[float]]], phase: int, width: int,
                   channel: str) -> list[float]:
    """The reference scores for a channel, pooled exactly as the stats were pooled.

    The stats for a thin phase were computed over `phase_hours` neighbours; the p-value must
    be empirical over the SAME set, or a thirty-day reference silently abstains on every
    phase because it has thirty samples instead of ninety.
    """
    out: list[float] = []
    for offset in range(-int(width), int(width) + 1):
        out.extend(samples.get((int(phase) + offset) % 24, {}).get(channel, []))
    return out


def score_vector(host: str, hour: datetime, vector: dict[str, float],
                 stats: dict[int, dict[str, dict[str, float]]],
                 samples: dict[int, dict[str, list[float]]]) -> dict[str, Any]:
    """One host-hour: per-channel p-values, the fused p, and a state for every channel."""
    phase = int(hour.hour)
    state, scores = channel_score(vector, stats.get(phase, {}))
    channels: dict[str, dict[str, Any]] = {}
    if state != "scored":
        for channel in CHANNELS:
            channels[channel] = {"score": None, "p_value": None, "state": state}
        return {"host": host, "hour": hour, "channels": channels, "fused_p": None,
                "families": 0, "state": state}

    width = max((int(v.get("phase_hours", 0)) for v in stats.get(phase, {}).values()), default=0)
    ps: dict[str, float] = {}
    for channel, score in scores.items():
        reference = pooled_samples(samples, phase, width, channel)
        if len(reference) < MIN_CHANNEL_SAMPLES:
            channels[channel] = {"score": score, "p_value": None, "state": "no-reference"}
            continue
        p = conformal_pvalue(score, reference)
        channels[channel] = {"score": score, "p_value": p, "state": "scored"}
        ps[channel] = p

    fused = fuse(ps)
    return {"host": host, "hour": hour, "channels": channels,
            "fused_p": fused["fused_p"], "families": fused["families"],
            "family_p": fused["family_p"],
            "state": "scored" if ps else "no-reference"}


def store_scores(client: Any, results: Iterable[dict[str, Any]]) -> int:
    rows = []
    now = utcnow()
    for result in results:
        if result.get("fused_p") is not None:
            rows.append((result["hour"], result["host"], "fused", 0.0,
                         float(result["fused_p"]), str(result.get("state", "scored")), "", now))
        for channel, payload in result["channels"].items():
            rows.append((result["hour"], result["host"], channel,
                         float(payload["score"]) if payload["score"] is not None else 0.0,
                         float(payload["p_value"]) if payload["p_value"] is not None else 1.0,
                         str(payload["state"]), "", now))
    if rows:
        client.insert("weirvern.host_hour_scores", rows,
                      column_names=["hour", "src_addr", "channel", "score", "p_value",
                                    "state", "evidence", "computed_at"])
    return len(rows)


# ── the budget, and the hourly tick ───────────────────────────────────────────────────────────

def derive_alpha(host_hours_per_day: int, alerts_per_day: float) -> float:
    """The per-hour p threshold that spends a daily budget.

    The design's rule is that the threshold IS the budget, not a number chosen for how it
    feels. With N host-hours a day and a budget of A episodes, the largest p threshold that
    can spend A is A/N -- before persistence, which can only reduce the count. Deriving it
    this way makes the budget a setting and the outcome measurable against it.
    """
    return max(1e-9, min(1.0, float(alerts_per_day) / max(int(host_hours_per_day), 1)))


def count_episodes(rows: Iterable[tuple[str, datetime, float]], alpha: float) -> int:
    """Episodes in a window of (host, hour, fused_p) rows: one per run of two or more hours.

    A single anomalous hour is not an episode -- that is the persistence rule, and counting
    runs rather than hours is what keeps an eight-hour incident from being reported eight
    times.
    """
    by_host: dict[str, list[tuple[datetime, float]]] = defaultdict(list)
    for host, hour, p in rows:
        # ONE KEY ON BOTH SIDES. `sorted()` raises the same mix-of-offsets TypeError that the
        # subtraction below does, so the normalisation has to happen before either.
        key = hour_key(hour)
        if key is not None:
            by_host[str(host)].append((key, float(p)))
    episodes = 0
    for hours in by_host.values():
        streak = 0
        previous: datetime | None = None
        for hour, p in sorted(hours):
            # A gap is a break even when the missing hour has no row: a worker that was down
            # for three hours must not join the hours either side into one incident.
            if previous is not None and (hour - previous) > timedelta(hours=1):
                if streak >= 2:
                    episodes += 1
                streak = 0
            if p <= alpha:
                streak += 1
            else:
                if streak >= 2:
                    episodes += 1
                streak = 0
            previous = hour
        if streak >= 2:
            episodes += 1
    return episodes


def run(client: Any, *, alerts_per_day: float = 20.0, now: datetime | None = None,
        lookback_hours: int = 6) -> dict[str, Any]:
    """One hourly tick: build the hours that are missing, score them, count episodes.

    Shadow only. It writes `host_hour_features` and `host_hour_scores` and logs a line; it
    cannot page, because nothing in the alert path reads those tables yet. The point of
    running it now is that the reference cannot be back-filled later: `flows` is trimmed long
    before the thirty days a per-host baseline needs, so the hour has to be accumulated while
    the flow log still has it.
    """
    end = hour_key(now) or utcnow()
    end = end.replace(minute=0, second=0, microsecond=0)
    last_complete = end - timedelta(hours=1)
    # The window ENDS at the last completed hour and reaches back `lookback_hours`. An earlier
    # version wrote max(back, last_complete), which is the LATER of the two -- so the tick
    # rebuilt exactly one hour and reported a healthy zero on the rest.
    start = last_complete - timedelta(hours=max(int(lookback_hours), 1) - 1)

    built = build_features(client, start, end)

    # BOTH SIDES THROUGH `hour_key`. The stored max(computed_at) comes back AWARE from ClickHouse
    # while `end` is naive; subtracting them raised every tick and this whole shadow stayed dark.
    fresh_at = hour_key(client.query(
        "SELECT max(computed_at) FROM weirvern.host_reference_stats").result_rows[0][0])
    if fresh_at is None or (end - fresh_at) > timedelta(hours=24):
        rebuild_references(client, days=30, now=end)

    stats, samples = load_reference(client)
    rows = read_features(client, start, end)
    results = [score_vector(str(r["src_addr"]), r["hour"], r, stats.get(str(r["src_addr"]), {}),
                            samples.get(str(r["src_addr"]), {}))
               for r in rows]
    stored = store_scores(client, results)

    # The denominator is the hosts that actually produced an hour in the last day, not the
    # hosts in this tick: a host that was quiet for the last six hours still costs an
    # opportunity to raise a false alarm over twenty-four.
    hosts = int(client.query(
        "SELECT uniqExact(src_addr) FROM weirvern.host_hour_features "
        "WHERE hour >= %(since)s",
        parameters={"since": end - timedelta(hours=24)}).result_rows[0][0] or 0)
    alpha = derive_alpha(hosts * 24, alerts_per_day)
    window = client.query(
        "SELECT src_addr, hour, p_value FROM weirvern.host_hour_scores FINAL "
        "WHERE channel = 'fused' AND hour >= %(since)s ORDER BY src_addr, hour",
        parameters={"since": start - timedelta(hours=1)}).result_rows
    episodes = count_episodes([(r[0], r[1], r[2]) for r in window], alpha)
    # `result`, not `r`: these are scored host-hours, not database rows. The schema audit
    # treats a variable named `r` as a row and reported `fused_p` as a name no table produces.
    anomalous = sum(1 for result in results
                    if result.get("fused_p") is not None and result["fused_p"] <= alpha)
    return {"hours_built": built, "hours_scored": len(results), "rows": stored,
            "hosts": hosts, "anomalous": anomalous, "episodes": episodes,
            "alpha": round(alpha, 5),
            "budget_per_day": alerts_per_day}
