"""Ripple ensemble: calibrated, abstaining, multi-scale fusion."""
from __future__ import annotations

import math

from weirvern.models import ripple
from weirvern.models.ripple import ChannelEvidence, fisher_combined_p, fuse


def _ch(channel="dns", family="dns", scale="1h", p=0.01, fresh=60.0, present=True):
    return ChannelEvidence(channel=channel, family=family, scale=scale, model_id=channel,
                           model_version="v1", score=1.0 - p, pvalue=p, freshness_s=fresh,
                           present=present)


def test_two_families_across_two_scales_make_a_ripple():
    out = fuse([_ch("dns", "dns", "1h", 0.01), _ch("http", "http", "5m", 0.02)])
    assert out.status == "ripple"
    assert out.combined_p < 0.05
    assert out.families == ["dns", "http"]
    assert out.scales == ["5m", "1h"]


def test_one_family_cannot_make_a_ripple():
    out = fuse([_ch("dns-a", "dns", "1h", 0.001), _ch("dns-b", "dns", "5m", 0.001)])
    assert out.status == "observation"
    assert "one family" in out.reason


def test_one_scale_is_an_observation_not_a_ripple():
    out = fuse([_ch("dns", "dns", "1h", 0.001), _ch("http", "http", "1h", 0.001)])
    assert out.status == "observation"
    assert "one scale" in out.reason


def test_missing_or_stale_channels_are_unknown_not_zero():
    out = fuse([_ch("dns", "dns", "1h", 0.01, present=False),
                _ch("http", "http", "5m", 0.01, fresh=10_000)])
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
    assert out.families == []
    assert out.combined_p >= 0.05


def test_fisher_combines_independent_pvalues():
    assert fisher_combined_p([0.01, 0.01]) < 0.01
    assert fisher_combined_p([]) == 1.0
    assert 0.0 < fisher_combined_p([0.5]) <= 1.0


def test_result_is_json_friendly_and_names_contributors():
    out = fuse([_ch("dns", "dns", "1h", 0.01), _ch("http", "http", "5m", 0.02)])
    data = out.as_dict()
    assert data["status"] == "ripple"
    assert data["contributors"][0]["channel"] == "dns"
    assert data["pageable"] is False
    assert all(math.isfinite(v) for v in (data["confidence"], data["combined_p"]))


def test_a_retired_channel_cannot_contribute_a_family():
    """A retired or merged channel is named, never counted as corroboration."""
    out = fuse([
        _ch("dns", "dns", "1h", 0.001),
        _ch("changepoint:bytes:up", "changepoint", "24h", 0.0001),
        _ch("HDBSCAN", "candidate", "5m", 0.0001),
        _ch("External exposure", "exposure", "1h", 0.0001),
    ])
    assert out.status == "observation"
    assert out.families == ["dns"]
    assert {item["reason"] for item in out.unknown} == {"retired"}
    assert [item["channel"] for item in out.contributors] == ["dns"]


def test_a_family_counts_only_when_its_own_p_clears_the_bar():
    """A quiet view of a second family is not corroboration; it was counted as one before."""
    out = fuse([
        _ch("dns", "dns", "1h", 0.0005),
        _ch("http", "http", "5m", 0.90),
        _ch("files", "files", "5m", 0.80),
    ], max_p=0.01)
    assert out.families == ["dns"]
    assert [item["family"] for item in out.contributors] == ["dns"]
    assert out.status == "observation"


def test_a_family_is_counted_once_even_when_its_views_disagree():
    out = fuse([
        _ch("dns_volume", "dns", "1h", 0.004),
        _ch("dns_query_diversity", "dns", "1h", 0.0001),
        _ch("http", "http", "5m", 0.002),
    ], max_p=0.01)
    assert out.families == ["dns", "http"]
    assert out.status == "ripple"


def test_empirical_pvalue_and_shadow_adapter():
    ref = [0.1, 0.2, 0.3, 0.4, 0.5]
    assert ripple.empirical_pvalue(0.3, ref) == 0.6666666666666666
    rows = [
        {"model_name": "http", "score": 0.9, "family": "http", "scale": "5m",
         "model_version": "v1", "freshness_s": 60},
        {"model_name": "ssh", "score": 0.8, "family": "ssh", "scale": "1h",
         "model_version": "v1", "freshness_s": 120},
    ]
    evidence = ripple.evidence_from_shadow(rows, reference_by_model={
        "http": [0.1, 0.2, 0.3], "ssh": [0.1, 0.2, 0.3]})
    assert len(evidence) == 2
    assert all(ch.pvalue <= 1.0 for ch in evidence)
    out = ripple.fuse(evidence)
    assert out.status in {"ripple", "observation"}
    # A model without a reference population must not be assigned a fabricated p-value.
    assert not ripple.evidence_from_shadow([rows[0]], reference_by_model={})
