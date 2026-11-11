"""Ripple ensemble: calibrated, abstaining, multi-scale fusion."""
from __future__ import annotations

import math

from weirvern.models.ripple import ChannelEvidence, fisher_combined_p, fuse


def _ch(channel="dns", family="dns", scale="1h", p=0.01, fresh=60.0, present=True):
    return ChannelEvidence(channel=channel, family=family, scale=scale, model_id=channel,
                           model_version="v1", score=1.0 - p, pvalue=p, freshness_s=fresh,
                           present=present)


def test_two_families_across_two_scales_make_a_ripple():
    out = fuse([_ch("dns", "dns", "1h", 0.01), _ch("graph", "graph", "5m", 0.02)])
    assert out.status == "ripple"
    assert out.combined_p < 0.05
    assert out.families == ["dns", "graph"]
    assert out.scales == ["5m", "1h"]


def test_one_family_cannot_make_a_ripple():
    out = fuse([_ch("dns-a", "dns", "1h", 0.001), _ch("dns-b", "dns", "5m", 0.001)])
    assert out.status == "observation"
    assert "one family" in out.reason


def test_one_scale_is_an_observation_not_a_ripple():
    out = fuse([_ch("dns", "dns", "1h", 0.001), _ch("graph", "graph", "1h", 0.001)])
    assert out.status == "observation"
    assert "one scale" in out.reason


def test_missing_or_stale_channels_are_unknown_not_zero():
    out = fuse([_ch("dns", "dns", "1h", 0.01, present=False),
                _ch("graph", "graph", "5m", 0.01, fresh=10_000)])
    assert out.status == "unknown"
    assert {x["reason"] for x in out.unknown} == {"missing", "stale"}


def test_no_valid_channel_is_unknown():
    out = fuse([])
    assert out.status == "unknown"
    assert out.combined_p == 1.0


def test_bonferroni_guard_prevents_many_channels_manufacturing_significance():
    # Ten weak channels must not manufacture a family-wise result.
    out = fuse([_ch(f"c{i}", f"f{i}", "5m" if i % 2 else "1h", 0.5) for i in range(10)])
    assert out.status == "observation"
    assert out.combined_p >= 0.05


def test_fisher_combines_independent_pvalues():
    assert fisher_combined_p([0.01, 0.01]) < 0.01
    assert fisher_combined_p([]) == 1.0
    assert 0.0 < fisher_combined_p([0.5]) <= 1.0


def test_result_is_json_friendly_and_names_contributors():
    out = fuse([_ch("dns", "dns", "1h", 0.01), _ch("graph", "graph", "5m", 0.02)])
    data = out.as_dict()
    assert data["status"] == "ripple"
    assert data["contributors"][0]["channel"] == "dns"
    assert data["pageable"] is False
    assert all(math.isfinite(v) for v in (data["confidence"], data["combined_p"]))
