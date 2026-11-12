"""The deployment must choose its own operating point, and must refuse to guess at cold start."""
from __future__ import annotations

import math

from weirvern.models import operating_point as op


def test_a_new_deployment_abstains_instead_of_guessing():
    point = op.derive([0.01] * 10, hosts=20)
    assert point.cold_start is True
    assert point.samples == 10
    assert point.required == 20 * op.PASSES_PER_HOST
    assert "learning" in point.reason


def test_the_required_history_scales_with_the_number_of_hosts():
    assert op.required_samples(1) == max(50, op.PASSES_PER_HOST)
    assert op.required_samples(50) > op.required_samples(5) > op.required_samples(1)


def test_the_threshold_lands_on_the_budget_it_was_given():
    # A uniform p-value distribution: asking for the 1% quantile must return ~0.01, whatever the
    # constant used to be.
    values = [i / 10_000 for i in range(1, 10_001)]
    point = op.derive(values, hosts=1, target_rate=0.01)
    assert point.cold_start is False
    assert 0.005 <= point.max_p <= 0.02, point.max_p
    fired = sum(1 for v in values if v <= point.max_p)
    assert fired / len(values) <= 0.02


def test_a_looser_budget_moves_the_threshold_up_and_never_past_the_old_constant():
    values = [i / 10_000 for i in range(1, 10_001)]
    tight = op.derive(values, hosts=1, target_rate=0.001)
    loose = op.derive(values, hosts=1, target_rate=1.0)
    assert tight.max_p <= loose.max_p
    assert loose.max_p == op.MAX_P_CAP


def test_the_threshold_never_drops_to_zero_or_becomes_a_negative():
    values = [0.0, 0.0, 0.0] + [0.5] * 400
    point = op.derive(values, hosts=1, target_rate=0.01)
    assert point.cold_start is False
    assert point.max_p >= op.MIN_P_FLOOR


def test_nonsense_values_are_not_allowed_to_poison_the_history():
    values = [float("nan"), float("inf"), -1.0, 2.0] + [0.2] * 300
    point = op.derive(values, hosts=1)
    assert point.cold_start is False
    assert point.samples == 300
    assert math.isfinite(point.max_p)


def test_the_point_is_reportable_without_exposing_internals():
    point = op.derive([i / 2000 for i in range(1, 2001)], hosts=1)
    described = point.as_dict()
    assert set(described) == {"max_p", "samples", "required", "target_rate", "cold_start", "reason"}
    assert described["cold_start"] is False
