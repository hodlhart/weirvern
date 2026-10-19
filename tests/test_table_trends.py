"""The Health table-size trend rule: direction, with unknowns left unknown."""
from __future__ import annotations

from weirvern.admin.soc import _trend_series


def _pts(*bytes_values):
    return [{"bytes": v} for v in bytes_values]


def test_a_table_that_grows_is_up():
    assert _trend_series(_pts(100, 120, 180)) == "up"


def test_a_table_that_shrinks_is_down():
    assert _trend_series(_pts(200, 150, 100)) == "down"


def test_a_flat_table_is_static_even_when_it_is_large():
    assert _trend_series(_pts(10_000_000, 10_010_000, 10_020_000)) == "static"


def test_one_sample_is_unknown_not_static():
    assert _trend_series(_pts(100)) == "unknown"
    assert _trend_series([]) == "unknown"


def test_growth_from_zero_is_up():
    assert _trend_series(_pts(0, 0, 500)) == "up"


def test_a_small_fluctuation_does_not_get_a_colour_it_did_not_earn():
    # 0.5% is within the static band; the operator's question is which tables are BUILDING.
    assert _trend_series(_pts(1_000_000, 1_004_000)) == "static"
