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
