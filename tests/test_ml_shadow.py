"""The shadow channels must answer their question and must not write alerts."""
from pathlib import Path

import numpy as np

from weirvern.models.changepoints import page_hinkley
from weirvern.models.ecod import ecod_scores
from weirvern.models.temporal import matrix_profile


def test_matrix_profile_finds_a_discord_and_its_nearest_window():
    # A repeated sawtooth with one inverted/odd segment.
    values = [float(i % 4) for i in range(60)]
    values[30:36] = [9.0, -9.0, 9.0, -9.0, 9.0, -9.0]
    profile, idx, score, nearest = matrix_profile(values, m=6)
    assert profile.size and score > 0
    assert 24 <= idx <= 36, idx
    assert nearest >= 0 and nearest != idx


def test_a_short_series_is_skipped_not_scored_as_zero():
    profile, idx, score, nearest = matrix_profile([1.0, 2.0, 3.0], m=6)
    assert profile.size == 0 and idx == -1 and score == 0.0 and nearest == -1


def test_the_blocked_profile_equals_the_broadcast_definition():
    """The dot-product form must compute the same number the n x n x m form did.

    ||a-b||^2 = 2m - 2<a,b> holds only for z-normalised windows; if that assumption ever stops
    being true (a change to the normalisation), this test is what notices.
    """
    rng = np.random.default_rng(11)
    values = list(rng.normal(0, 1, 90))
    m = 6
    got, got_idx, got_score, got_nearest = matrix_profile(values, m=m)

    x = np.asarray(values, dtype=float)
    win = np.lib.stride_tricks.sliding_window_view(x, m).astype(float, copy=True)
    win -= win.mean(axis=1, keepdims=True)
    sd = win.std(axis=1, keepdims=True)
    win = np.divide(win, sd, out=np.zeros_like(win), where=sd > 1e-12)
    dist = np.linalg.norm(win[:, None, :] - win[None, :, :], axis=2)
    for i in range(len(win)):
        lo, hi = max(0, i - m + 1), min(len(win), i + m)
        dist[i, lo:hi] = np.inf
    expected = dist.min(axis=1)
    expected[~np.isfinite(expected)] = 0.0

    assert np.allclose(got, expected, atol=1e-9)
    assert got_idx == int(np.argmax(expected))
    assert got_nearest == int(np.argmin(dist[got_idx]))


def test_a_long_series_is_bounded_before_the_pairwise_profile():
    """A busy host's series must not size the intermediate.

    Measured live 2026-11-12: the n x n x m intermediate OOM-killed the worker at 4 GiB, then at
    7 GiB, every ~35 s once the NetFlow feed was restored -- 8,000 points is ~6 GB of float64.
    """
    from weirvern.models.temporal import MAX_POINTS

    rng = np.random.default_rng(3)
    values = list(rng.normal(0, 1, 20_000))
    values[9_000:9_040] = [40.0, -40.0] * 20          # a discord at ~45% of the series
    profile, idx, score, nearest = matrix_profile(values, m=12)

    assert profile.size <= MAX_POINTS
    assert score > 0
    assert 0.30 <= idx / profile.size <= 0.60, idx


def test_page_hinkley_finds_a_step_and_does_not_fire_on_noise():
    step = [0.0] * 30 + [10.0] * 30
    changes = page_hinkley(step)
    assert changes and changes[0]["direction"] == "up"
    assert 20 <= changes[0]["index"] <= 40
    noise = [((i * 37) % 5) * 0.01 for i in range(80)]
    assert not page_hinkley(noise)


def test_ecod_scores_an_extreme_point_above_the_bulk():
    X = np.array([[1.0, 1.0], [1.1, 0.9], [0.9, 1.1], [1.0, 1.0], [50.0, 50.0]])
    scores = ecod_scores(X)
    assert scores[-1] == scores.max()
    assert scores[-1] > scores[0]


def test_the_shadow_tables_are_shipped():
    root = Path(__file__).resolve().parents[1] / "weirvern" / "schema"
    for name, table in (("032_ml_candidate_scores.sql", "ml_candidate_scores"),
                        ("033_ml_temporal_scores.sql", "ml_temporal_scores"),
                        ("034_ml_changepoints.sql", "ml_changepoints")):
        sql = (root / name).read_text()
        assert table in sql and "TTL" in sql


def test_hdbscan_centres_come_from_the_medoid_attribute():
    # sklearn 1.9 populates `.medoids_` for store_centers="medoid"; `.centers_` stays empty.
    # This is the regression that made the first live candidate report 0 clusters.
    from weirvern.models.candidates import _fit
    rng = np.random.default_rng(7)
    X = np.vstack([rng.normal(0, 0.2, (60, 3)),
                   rng.normal(5, 0.2, (60, 3)),
                   rng.normal(-5, 0.2, (60, 3))])
    _, _, centers = _fit(X, min_cluster_size=20)
    assert centers.shape[0] >= 2
    assert centers.shape[1] == 3


def test_shadow_overview_names_each_channel_and_a_broken_one_is_not_empty_success():
    from datetime import datetime
    from types import SimpleNamespace

    from weirvern.admin.status import shadow_overview

    class Stub:
        def query(self, sql):
            if "ml_candidate_scores" in sql:
                return SimpleNamespace(result_rows=[(5000, datetime(2026, 1, 1), 56)])
            if "ml_temporal_scores" in sql:
                return SimpleNamespace(result_rows=[(48, datetime(2026, 1, 1), 2)])
            if "ml_changepoints" in sql:
                return SimpleNamespace(result_rows=[(50, datetime(2026, 1, 1), 5)])
            if "ml_calibration" in sql:
                return SimpleNamespace(result_rows=[(4, datetime(2026, 1, 1))])
            raise AssertionError(sql)

    out = shadow_overview(Stub())
    assert out["available"] is True and len(out["rows"]) == 6
    by_key = {r["key"]: r for r in out["rows"]}
    assert by_key["hdbscan"]["detail"] == 56
    assert by_key["external"]["detail"] == 56
    assert by_key["calibration"]["rows"] == 4

    class Broken(Stub):
        def query(self, sql):
            if "ml_changepoints" in sql:
                raise RuntimeError("table unavailable")
            return super().query(sql)

    out2 = shadow_overview(Broken())
    broken = next(r for r in out2["rows"] if r["key"] == "changepoints")
    assert broken["available"] is False and broken["state"] == "unavailable"
    assert "table unavailable" in broken["reason"]


def test_candidate_matrix_collapses_aggregate_fragments_before_clustering():
    """COLLAPSE WITH THE MERGE COMBINATORS, BECAUSE THE COLUMNS ARE STATES.

    This check used to require `sum(total_bytes)`, which is the bug it was supposed to catch:
    `flows_window` is an AggregatingMergeTree and those four columns are AggregateFunction states,
    so summing them is illegal in ClickHouse. Measured on the 2026-11-16 roll, live:

        ML shadow pass failed (detection continues): Code: 43. DB::Exception: Illegal type
        AggregateFunction(sum, UInt64) of argument for aggregate function sum

    The shadow pass catches its own failure and carries on, so the only symptom was a WARNING and a
    candidate list that had quietly stopped existing. sumMerge/countMerge fold the states across
    insert blocks; uniqMerge unions the sketches so the destination count is the true cardinality
    rather than a sum of per-block estimates.
    """
    from weirvern.models.candidates import matrix_sql

    sql = matrix_sql(5000)
    assert "GROUP BY window_start, src_addr" in sql
    assert "sumMerge(total_bytes)" in sql, "the byte total is read as a state, not summed raw"
    assert "sumMerge(total_packets)" in sql
    assert "uniqMerge(unique_dst_ips)" in sql, (
        "a uniq state must be merged, not added: summing estimates is not a cardinality"
    )
    assert "countMerge(flow_count)" in sql
    for illegal in ("sum(total_bytes)", "sum(total_packets)", "sum(flow_count)",
                    "sum(unique_dst_ips)"):
        assert illegal not in sql, (
            f"{illegal} is illegal on an AggregateFunction column (ClickHouse code 43); the shadow "
            f"pass would fail with a warning and no candidates"
        )
    assert "ORDER BY sipHash64" in sql and "LIMIT 5000" in sql


def test_candidate_matrix_carries_the_production_zeek_and_dns_tail():
    # The challenger used to select only the eight NetFlow columns. The production DBSCAN
    # vector also carries the Zeek tail, including the DNS triple; a challenger without it is
    # a different model wearing the same name.
    from weirvern.features import CROSS_SECTIONAL_FEATURES
    from weirvern.models.candidates import matrix_sql
    from weirvern.zeek_features import ZEEK_CROSS_SECTIONAL_FEATURES

    assert len(CROSS_SECTIONAL_FEATURES) == 19
    sql = matrix_sql(5000)
    assert "zeek_w" in sql
    for column in ZEEK_CROSS_SECTIONAL_FEATURES:
        assert f"z.{column}" in sql, column
    assert "z.zeek_dns_count" in sql
    assert "z.zeek_dns_mean_query_entropy" in sql


def test_candidate_matrix_applies_the_monitored_scope_predicate():
    from weirvern.models.candidates import matrix_sql

    predicate = "AND (isIPAddressInRange(a.src_addr, '203.0.113.0/24'))"
    sql = matrix_sql(5000, scope_filter=predicate)
    assert predicate in sql
    assert "isIPAddressInRange" in sql


def test_candidate_refuses_to_rank_when_no_scope_is_monitored():
    from types import SimpleNamespace

    from weirvern.models.candidates import run

    class Stub:
        def query(self, sql):
            # The only query run() makes before refusing is load_scopes().
            assert "network_scopes" in sql
            return SimpleNamespace(result_rows=[
                ("scope-1", "203.0.113.0/24", "internal", 0, "observe", "", "operator"),
            ])

    result = run(Stub())
    assert result["available"] is False
    assert "no monitored scope" in result["reason"]
