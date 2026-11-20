"""The console's ONE criticality vocabulary for corroborating model detections.

The Alerts tab has two lists: ripples (the finding) and the model's fused-score detections
(corroboration). Ripples speak low/medium/high. The model rows carry the ensemble's four raw
severities. These tests pin the single fold between them -- and, just as importantly, pin that a
missing severity is `unclassified` rather than a reassuring `low`.
"""
from __future__ import annotations

from weirvern.criticality import (
    BAND_ORDER,
    annotate_bands,
    band_counts_from_severity_counts,
    band_rank,
    corroboration_band,
    sort_band_then_recency,
)


def test_critical_folds_into_high_and_the_three_bands_pass_through():
    assert corroboration_band("critical") == "high"
    assert corroboration_band("HIGH") == "high"
    assert corroboration_band("medium") == "medium"
    assert corroboration_band("low") == "low"


def test_an_absent_or_unknown_severity_is_unclassified_not_low():
    """Silence must look like silence. Defaulting to low would turn an unlabelled row into a
    rank the engine never assigned."""
    for value in (None, "", "   ", "unknown", "info", "critical-ish"):
        assert corroboration_band(value) == "unclassified"


def test_band_rank_orders_high_then_medium_then_low_then_unclassified():
    assert [band_rank(b) for b in BAND_ORDER] == sorted(
        [band_rank(b) for b in BAND_ORDER], reverse=True
    )


def test_counts_are_folded_with_the_same_rule_as_rows():
    counts = band_counts_from_severity_counts({
        "available": True,
        "counts": [
            {"severity": "critical", "count": 2},
            {"severity": "high", "count": 5},
            {"severity": "medium", "count": 146},
            {"severity": "low", "count": 43},
        ],
    })
    assert counts["counts"] == [
        {"band": "high", "count": 7},
        {"band": "medium", "count": 146},
        {"band": "low", "count": 43},
    ]


def test_a_failed_count_read_stays_a_failed_read_not_zero():
    out = band_counts_from_severity_counts(
        {"available": False, "reason": "severity counts failed: TimeoutError", "counts": []}
    )
    assert out["available"] is False
    assert "TimeoutError" in out["reason"]
    assert out["counts"] == []


def test_sort_is_by_band_then_recency():
    rows = [
        {"severity_band": "low", "detected_at": "2026-01-03T00:00:00"},
        {"severity_band": "high", "detected_at": "2026-01-01T00:00:00"},
        {"severity_band": "high", "detected_at": "2026-01-02T00:00:00"},
        {"severity_band": "unclassified", "detected_at": "2026-01-04T00:00:00"},
    ]
    ordered = sort_band_then_recency(rows)
    assert [r["severity_band"] for r in ordered] == ["high", "high", "low", "unclassified"]
    assert ordered[0]["detected_at"] == "2026-01-02T00:00:00"


def test_annotate_bands_ships_one_field_and_never_invents_a_rank():
    rows = [{"severity": "critical"}, {"severity": "medium"}, {}]
    out = annotate_bands(rows)
    assert [r["severity_band"] for r in out] == ["high", "medium", "unclassified"]
    assert out[0]["severity"] == "critical"  # the raw value is preserved for filters/audit
