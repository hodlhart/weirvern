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
    assert out["available"] is True and len(out["rows"]) == 5
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
    from weirvern.models.candidates import matrix_sql
    sql = matrix_sql(5000)
    assert "GROUP BY window_start, src_addr" in sql
    assert "sum(total_bytes)" in sql
    assert "ORDER BY sipHash64" in sql and "LIMIT 5000" in sql
