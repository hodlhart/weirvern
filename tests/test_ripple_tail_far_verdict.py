"""The tail validator's verdict must describe the DETECTOR, not the data's potential.

MEASURED LIVE 2026-11-21: 24h held 30 windows (one host/channel) and one held-out fit, and the
script called it "parametric, usable" -- while the production rule had the scale's tail disabled,
so `ml_ripple_evidence` contained zero 24h rows. The verdict now asks the production rule, and a
window count is not a measurement. The 6h tail is the scale that IS enabled, and its verdict is
still decided by the manufactured-ripple rate.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("ripple_tail_far",
                                              ROOT / "scripts" / "ripple_tail_far.py")
assert SPEC and SPEC.loader
tail_far = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tail_far)


def _report(**over):
    base = {
        "observed_max_windows": 30, "p_floor": 0.032258,
        "tail_only": {"tests": 1, "far": 0.0, "far_on_normal": 0.0},
        "far": 0.0, "far_on_normal": 0.0,
    }
    base.update(over)
    return base


def test_a_disabled_scale_is_not_usable_even_when_it_holds_the_window_floor():
    report = _report()
    tail_far._verdict(report, scale="24h", total=1, normal_total=1, normal_fires=0)
    assert report["method"] == "insufficient"
    assert report["usable"] is False
    assert "disabled" in report["reason"], report["reason"]


def test_an_enabled_scale_is_usable_when_the_ordinary_rate_is_inside_the_line():
    report = _report(observed_max_windows=97, p_floor=0.010204,
                     tail_only={"tests": 40, "far": 0.05, "far_on_normal": 0.0},
                     far=0.05, far_on_normal=0.0)
    tail_far._verdict(report, scale="6h", total=40, normal_total=35, normal_fires=0)
    assert report["method"] == "parametric"
    assert report["usable"] is True


def test_an_enabled_scale_with_no_usable_fit_is_refused():
    report = _report(observed_max_windows=60, p_floor=0.016393,
                     tail_only={"tests": 0, "far": None, "far_on_normal": None},
                     far=None, far_on_normal=None)
    tail_far._verdict(report, scale="6h", total=1, normal_total=0, normal_fires=0)
    assert report["method"] == "insufficient"
    assert report["usable"] is False
    assert "no held-out baseline produced a usable fitted tail" in report["reason"]


def test_force_tail_fits_where_production_prefers_the_empirical_rank():
    """At 100+ windows production uses the rank; the tail is still measurable on request."""
    from weirvern.models import ripple_evidence as rev

    spec = next(s for s in rev.SPECS if s.channel == "conn_volume")
    buckets = {index: (float(10 + (index % 7)), 0.0, 0.0) for index in range(0, 121)}
    production = tail_far._score_host(buckets, spec, scale="6h", limit_reference=None)
    forced = tail_far._score_host(buckets, spec, scale="6h", limit_reference=None,
                                  force_tail=True)
    assert production is not None and production["method"] == "empirical"
    assert forced is not None and forced["method"] in {"negbin", "poisson"}
    assert forced["n"] == production["n"] == 120
