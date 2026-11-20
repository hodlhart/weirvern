"""The host-hour's arithmetic: features, references, p-values, fusion, persistence.

The database paths are exercised by running the builder against ClickHouse; what needs
pinning here is the part a wrong answer would be invisible in -- a p-value that is not
conformal, a channel that scores against a reference it does not have, or a fusion that
double-counts.
"""
from __future__ import annotations

import math
from datetime import UTC, datetime, timedelta, timezone

import pytest

from weirvern.models import host_hour


def stats(median: float, mad: float, n: int = 100) -> dict[str, float]:
    return {"median": median, "mad": mad, "p01": median, "p99": median, "n": n}


# ── features ─────────────────────────────────────────────────────────────────────────────────

def test_feature_vector_is_logged_where_it_is_a_count():
    v = host_hour.feature_vector(flow_count=100, total_bytes=1_000_000,
                                 total_packets=2000, dst_hosts=7)
    assert v["log_bytes"] == pytest.approx(math.log1p(1_000_000))
    assert v["log_flows"] == pytest.approx(math.log1p(100))
    assert v["bytes_per_flow"] == pytest.approx(10_000)
    assert v["dst_hosts"] == 7


def test_a_zero_flow_hour_does_not_divide_by_zero():
    v = host_hour.feature_vector(flow_count=0, total_bytes=0, total_packets=0, dst_hosts=0)
    assert v["bytes_per_flow"] == 0.0
    assert v["log_flows"] == 0.0


# ── robust z ─────────────────────────────────────────────────────────────────────────────────

def test_robust_z_uses_mad_not_sigma():
    # median 100, MAD 5 -> 1.4826*5 = 7.413; 30 above the median is ~4 sigma-ish for a
    # normal, and the MAD scale is what the design specifies.
    assert host_hour.robust_z(130, 100, 5) == pytest.approx(30 / (1.4826 * 5))


def test_a_feature_that_never_moved_cannot_produce_infinity():
    # MAD 0 would divide by zero; the floor turns a one-unit change into a large but finite z.
    z = host_hour.robust_z(101, 100, 0)
    assert math.isfinite(z)
    assert z == pytest.approx(1 / (0.05 * 100))


# ── phase pooling ────────────────────────────────────────────────────────────────────────────

def test_pooling_stops_at_the_hour_when_it_already_has_enough():
    by_phase = {14: [1.0] * 60}
    samples, width = host_hour.pool_phase(by_phase, 14)
    assert len(samples) == 60 and width == 0


def test_pooling_width_symmetrically_until_the_floor_is_met():
    # Six samples at 14:00, six at each neighbour: 13 and 15 add twelve, 12 and 16 add the rest.
    by_phase = {h: [float(h)] * 6 for h in range(24)}
    samples, width = host_hour.pool_phase(by_phase, 14)
    # 6 at the hour, then two more phases per step: 18, 30, 42, 54 -- the first count over
    # the floor of 50. Width 4, not 6: pooling stops as soon as it is enough.
    assert width == 4
    assert len(samples) == 54


def test_pooling_never_runs_past_the_cap_and_says_how_wide_it_went():
    by_phase = {h: [1.0] for h in range(24)}
    samples, width = host_hour.pool_phase(by_phase, 0)
    assert width == host_hour.MAX_PHASE_POOL_HOURS
    assert len(samples) == 13  # the hour plus six either side


# ── reference summary ────────────────────────────────────────────────────────────────────────

def test_summary_is_median_and_mad_and_reports_its_sample_count():
    s = host_hour.summarize([1, 2, 3, 4, 100])
    assert s is not None
    assert s["median"] == 3
    # deviations |1-3|=2, |2-3|=1, |3-3|=0, |4-3|=1, |100-3|=97; sorted 0,1,1,2,97 -> 1
    assert s["mad"] == 1
    assert s["n"] == 5
    assert s["p01"] <= s["median"] <= s["p99"]


def test_summary_of_nothing_is_none_not_zero():
    assert host_hour.summarize([]) is None


# ── channels, p-values, fusion ───────────────────────────────────────────────────────────────

def test_a_channel_without_a_reference_abstains_instead_of_scoring_zero():
    vector = {"log_bytes": 10.0}
    state, scores = host_hour.channel_score(vector, {})
    assert state == "no-reference"
    assert scores == {}


def test_channel_statistic_is_the_strongest_feature_not_a_sum():
    refs = {f: stats(0.0, 1.0) for f in host_hour.CHANNELS["volume"]}
    vector = {"log_bytes": 3.0, "log_packets": 0.0, "log_flows": 0.0, "bytes_per_flow": 0.0}
    state, scores = host_hour.channel_score(vector, refs)
    assert state == "scored"
    assert scores["volume"] == pytest.approx(3.0 / 1.4826)


def test_one_family_means_the_fused_p_is_that_family():
    fused = host_hour.fuse({"volume": 0.02, "destinations": 0.5})
    assert fused["families"] == 1
    assert fused["fused_p"] == pytest.approx(0.02)


def test_fusion_takes_the_strongest_channel_inside_a_family():
    # Two views of the same burst must not combine: the family takes the max, so a second
    # channel agreeing cannot manufacture significance.
    one = host_hour.fuse({"volume": 0.01})
    two = host_hour.fuse({"volume": 0.01, "destinations": 0.01})
    assert two["fused_p"] == pytest.approx(one["fused_p"])


def test_fisher_combines_independent_families():
    # Two families each at p=0.05 is stronger evidence than one; the closed form gives
    # 1 - (1 - 0.05*(1 - ln 0.05))... checked numerically against the survival function.
    fused = host_hour.fuse({"volume": 0.05, "dns_volume": 0.05})
    assert fused["families"] == 2
    assert fused["fused_p"] < 0.05


def test_a_live_hour_scores_against_its_own_phase():
    refs = {14: {f: stats(0.0, 1.0) for f in host_hour.CHANNELS["volume"]}}
    samples = {14: {"volume": [1.0] * 60, "destinations": [1.0] * 60}}
    vector = {"log_bytes": 5.0, "log_packets": 0.0, "log_flows": 0.0,
              "bytes_per_flow": 0.0, "dst_hosts": 0.0}
    result = host_hour.score_vector("198.51.100.10", datetime(2026, 11, 16, 14, 0),
                                    vector, refs, samples)
    assert result["state"] == "scored"
    assert result["channels"]["volume"]["p_value"] == pytest.approx(1 / 61)
    assert result["fused_p"] == pytest.approx(1 / 61)


# ── persistence ──────────────────────────────────────────────────────────────────────────────

def test_one_anomalous_hour_is_not_an_episode():
    assert not host_hour.is_episode(False, True)


def test_two_consecutive_hours_are_an_episode():
    assert host_hour.is_episode(True, True)


def test_one_hour_with_a_signature_is_an_episode():
    assert host_hour.is_episode(False, True, signature=True)


def test_a_signature_on_a_quiet_hour_is_not_an_episode():
    assert not host_hour.is_episode(False, False, signature=True)


# ── the budget and episodes ───────────────────────────────────────────────────────────────────

def test_the_budget_sets_the_threshold():
    # 22 hosts x 24 hours = 528 host-hours a day; twenty episodes a day is 20/528.
    assert host_hour.derive_alpha(528, 20) == pytest.approx(20 / 528)


def test_a_budget_larger_than_the_opportunities_does_not_exceed_one():
    assert host_hour.derive_alpha(10, 500) == 1.0


def test_zero_host_hours_clamps_to_one_rather_than_dividing_by_zero():
    # With no denominator the rule degenerates to "score everything anomalous", which is the
    # widest a p threshold can be -- not 20, which is not a probability.
    assert host_hour.derive_alpha(0, 20) == 1.0


def _hour(h: int):
    return datetime(2026, 11, 16, h, 0)


def test_a_single_anomalous_hour_is_not_an_episode():
    rows = [("198.51.100.5", _hour(3), 0.001)]
    assert host_hour.count_episodes(rows, 0.01) == 0


def test_two_consecutive_hours_are_one_episode_not_two():
    rows = [("198.51.100.5", _hour(3), 0.001), ("198.51.100.5", _hour(4), 0.002)]
    assert host_hour.count_episodes(rows, 0.01) == 1


def test_an_eight_hour_incident_is_reported_once():
    rows = [("198.51.100.5", _hour(h), 0.001) for h in range(3, 11)]
    assert host_hour.count_episodes(rows, 0.01) == 1


def test_two_separate_runs_are_two_episodes():
    rows = [("198.51.100.5", _hour(3), 0.001), ("198.51.100.5", _hour(4), 0.001),
            ("198.51.100.5", _hour(7), 0.001), ("198.51.100.5", _hour(8), 0.001)]
    assert host_hour.count_episodes(rows, 0.01) == 2


def test_episodes_are_counted_per_host():
    rows = [("198.51.100.5", _hour(3), 0.001), ("198.51.100.5", _hour(4), 0.001),
            ("198.51.100.6", _hour(3), 0.001), ("198.51.100.6", _hour(4), 0.001)]
    assert host_hour.count_episodes(rows, 0.01) == 2


# ── one clock: naive and aware timestamps must be comparable ─────────────────────────────────
#
# MEASURED: the worker logged `ML host-hour shadow failed: can't subtract offset-naive and
# offset-aware datetimes` on every tick. ClickHouse returns a DateTime column AWARE (the
# deployment's tz) while the tick's own clock is naive UTC, so `end - fresh_at` raised and the
# whole shadow stayed dark. Normalize's `_hour_key` had the same class of bug.

def test_hour_key_is_one_offset_free_key_for_every_input():
    # 18:00 at -06:00 is midnight UTC the next day -- the SAME instant as the naive form.
    aware = datetime(2026, 11, 20, 18, 0, tzinfo=timezone(timedelta(hours=-6)))
    assert host_hour.hour_key(aware) == datetime(2026, 11, 21, 0, 0)
    assert host_hour.hour_key(datetime(2026, 11, 21, 0, 0)) == datetime(2026, 11, 21, 0, 0)
    assert host_hour.hour_key("2026-11-21T00:00:00-06:00") == datetime(2026, 11, 21, 6, 0)
    assert host_hour.hour_key("2026-11-21T00:00:00Z") == datetime(2026, 11, 21, 0, 0)
    assert host_hour.hour_key(None) is None
    assert host_hour.hour_key("not a timestamp") is None


class _FakeClient:
    """Just enough of clickhouse_connect for the tick's freshness check.

    The live failure WAS the subtraction inside run(), so this exercises the real path rather
    than a helper extracted beside it. Every other query returns nothing, which is a legitimate
    empty tick.
    """

    def __init__(self, fresh_at):
        self.fresh_at = fresh_at
        self.inserts = []

    def query(self, sql, parameters=None):
        class _Result:
            def __init__(self, rows):
                self.result_rows = rows

        if "max(computed_at)" in sql:
            return _Result([(self.fresh_at,)])
        if "uniqExact(src_addr)" in sql:
            return _Result([(0,)])
        return _Result([])

    def insert(self, table, rows, column_names=None):
        self.inserts.append((table, rows))


def test_the_tick_survives_an_aware_reference_timestamp():
    client = _FakeClient(datetime(2026, 11, 20, 12, 0, tzinfo=UTC))
    out = host_hour.run(client, now=datetime(2026, 11, 20, 12, 0))
    assert out["hours_scored"] == 0
    assert out["episodes"] == 0


def test_the_tick_handles_a_naive_reference_timestamp_too():
    client = _FakeClient(datetime(2026, 11, 20, 12, 0))
    assert host_hour.run(client, now=datetime(2026, 11, 20, 12, 0))["hours_scored"] == 0


def test_the_tick_handles_an_aware_now():
    client = _FakeClient(datetime(2026, 11, 20, 12, 0, tzinfo=UTC))
    assert host_hour.run(client, now=datetime(2026, 11, 20, 18, 0,
                                               tzinfo=timezone(timedelta(hours=-6))))["hours_scored"] == 0


def test_episodes_compare_naive_and_aware_hours_without_raising():
    rows = [("198.51.100.5", _hour(3), 0.001),
            ("198.51.100.5", datetime(2026, 11, 16, 4, 0, tzinfo=UTC), 0.001)]
    assert host_hour.count_episodes(rows, 0.01) == 1
