"""Explainability tests.

These guard a specific class of dishonesty: the schema declared five
explainability columns and the code wrote placeholders into four of them
(`0.0, 0.0, "{}", ""`), while a helper whose docstring claimed to name "the
feature that dominated" returned a detector name. Every one of these tests would
have failed against that code.
"""
from __future__ import annotations

import json

from weirvern.explain import EXPLAINED_MEASUREMENTS, explain, summarise

# The real exfiltration case from validation: a host that normally peaks around
# 65 MB in a 5-minute window moved 3.6 GB to a single destination.
EXFIL_FLOW = {
    "total_bytes": 3_600_000_000,
    "total_packets": 2_400_000,
    "unique_dst_ips": 2,
    "flow_count": 180,
    "unique_dst_ports": 12,
    "port_entropy": 2.4,
    "activity_regularity": 0.8,
    "burstiness": 1.7,
    "avg_bytes": 20_000_000,
    "avg_packets": 13_333,
}
EXFIL_BASELINE = {
    "avg_bytes": 65_000_000, "stddev_bytes": 12_000_000,
    "avg_packets": 450_000, "stddev_packets": 90_000,
    "avg_unique_dsts": 6.0, "stddev_unique_dsts": 2.0,
    "p95_bytes": 1.2e8, "p99_bytes": 1.8e8, "p999_bytes": 2.4e8,
    "p95_packets": 8e5, "p99_packets": 1.1e6, "p999_packets": 1.5e6,
}

REQUIRED_KEYS = {
    "primary_deviation_feature", "primary_deviation_zscore", "deviation_magnitude",
    "feature_contributions", "baseline_comparison",
}


def test_explain_returns_exactly_the_schema_columns():
    """The five keys must match the schema's column names exactly. A rename on
    either side would silently write nothing."""
    assert set(explain(EXFIL_FLOW, EXFIL_BASELINE)) == REQUIRED_KEYS


def test_explain_names_the_dominant_feature_not_a_detector():
    """THE BUG: the old helper returned a DETECTOR name ('Adaptive Baseline'),
    so primary_deviation_feature held a model where a measurement belonged."""
    e = explain(EXFIL_FLOW, EXFIL_BASELINE)
    assert e["primary_deviation_feature"] == "total_bytes"
    for detector_name in ("Isolation Forest", "Gradient Boosting", "DBSCAN",
                          "Adaptive Baseline"):
        assert detector_name not in e["primary_deviation_feature"]


def test_explain_computes_a_real_zscore_not_zero():
    """THE BUG: primary_deviation_zscore was hardcoded 0.0. Here bytes are ~55x
    the host's normal, which is tens of sigma, not zero."""
    e = explain(EXFIL_FLOW, EXFIL_BASELINE)
    assert e["primary_deviation_zscore"] > 50, e["primary_deviation_zscore"]
    assert e["deviation_magnitude"] > 50
    # 3.6e9 vs mean 6.5e7 with sd 1.2e7
    expected = (3_600_000_000 - 65_000_000) / 12_000_000
    assert abs(e["primary_deviation_zscore"] - round(expected, 2)) < 0.01


def test_feature_contributions_is_populated_json_not_empty_dict():
    """THE BUG: feature_contributions was the literal string "{}"."""
    e = explain(EXFIL_FLOW, EXFIL_BASELINE)
    parsed = json.loads(e["feature_contributions"])
    assert parsed, "feature_contributions must not be an empty object"
    assert "total_bytes" in parsed
    entry = parsed["total_bytes"]
    assert entry["direction"] == "above"
    assert entry["ratio"] > 50
    assert entry["band"] == "above p99.9"


def test_explain_does_not_claim_a_deviation_without_a_baseline():
    """A host with no baseline has nothing to deviate FROM. The result must say
    so, and must not report a fabricated 0.0 that reads as 'no deviation'."""
    e = explain(EXFIL_FLOW, None)
    assert e["primary_deviation_feature"] == ""
    assert e["baseline_comparison"] == "no baseline for this host"
    # And it must be distinguishable from a genuine zero deviation.
    flat = explain(EXFIL_FLOW, {
        "avg_bytes": EXFIL_FLOW["total_bytes"], "stddev_bytes": 0.0,
        "avg_packets": EXFIL_FLOW["total_packets"], "stddev_packets": 0.0,
        "avg_unique_dsts": EXFIL_FLOW["unique_dst_ips"], "stddev_unique_dsts": 0.0,
    })
    assert flat["baseline_comparison"] != e["baseline_comparison"]


def test_zero_variance_baseline_is_flagged_rather_than_divided_by():
    """A perfectly constant host makes sd 0, and a bare division would produce
    inf/nan. It must be reported as approximate, not as a spectacular deviation."""
    e = explain(EXFIL_FLOW, {
        "avg_bytes": 1_000_000, "stddev_bytes": 0.0,
        "avg_packets": 1000, "stddev_packets": 0.0,
        "avg_unique_dsts": 1.0, "stddev_unique_dsts": 0.0,
    })
    parsed = json.loads(e["feature_contributions"])
    assert parsed["total_bytes"]["zero_variance"] is True
    assert "zero variance" in e["baseline_comparison"]
    assert e["deviation_magnitude"] < float("inf")


# ── the Zeek side of the why: JA4 novelty reaches the comparison sentence ─────────────────────


def _ja4_flow(fingerprints):
    """The exfil flow plus the Zeek window row the worker attaches at scoring time."""
    return {**EXFIL_FLOW, "_zeek": {"ja4_set": fingerprints}}


def test_a_new_tls_stack_is_named_in_the_comparison_sentence():
    """MEASURED GAP: an alert driven by a never-before-used TLS stack said "bytes normal".

    The models score `zeek_ja4_novelty`; this explanation spoke only about volume, so the one
    page an analyst reads for the WHY could not see the finding. The window's fingerprints ride
    on the `_zeek` row and the host's history on the baseline (both supplied by the worker since
    the JA4 wiring was completed), so the sentence can say what actually fired."""
    baseline = {**EXFIL_BASELINE, "baseline_ja4_set": ["fp_old"], "baseline_ja4_count": 1}
    e = explain(_ja4_flow("['fp_old', 'fp_new']"), baseline)
    assert "1 of 2 TLS fingerprints in this window is new for this host" in e["baseline_comparison"]


def test_a_familiar_stack_adds_no_clause():
    """Nothing new means nothing to say -- the sentence stays as it was."""
    baseline = {**EXFIL_BASELINE, "baseline_ja4_set": ["fp_old", "fp_new"],
                "baseline_ja4_count": 2}
    e = explain(_ja4_flow("['fp_old', 'fp_new']"), baseline)
    assert "TLS fingerprints" not in e["baseline_comparison"]
    # And a window with no TLS at all says nothing about TLS, on a baseline that has history.
    e = explain(EXFIL_FLOW, baseline)
    assert "TLS fingerprints" not in e["baseline_comparison"]


def test_a_count_only_baseline_never_overstates_novelty():
    """The same conservative rule as `extract_zeek_features`: with only the count, at most
    len(seen) - count fingerprints can be new. Claiming more invents alerts on ordinary hosts."""
    baseline = {**EXFIL_BASELINE, "baseline_ja4_count": 1}  # the set is absent, count only
    e = explain(_ja4_flow("['a', 'b', 'c']"), baseline)
    assert "2 of 3 TLS fingerprints in this window are new for this host" in e["baseline_comparison"]


def test_the_clause_matches_the_value_the_models_saw_when_no_history_exists():
    """An older caller ships no JA4 keys at all; the extractor treats that as "nothing known",
    novelty computes as 1.0, and the clause says the SAME thing rather than staying silent or
    claiming less than the model acted on. Consistency between sentence and vector is the
    point -- an alert that explains less than it saw is how a finding disappears."""
    e = explain(_ja4_flow("['a']"), EXFIL_BASELINE)  # no baseline_ja4_* keys
    assert "1 of 1 TLS fingerprints in this window is new for this host" in e["baseline_comparison"]


def test_a_tls_only_anomaly_still_gets_its_sentence():
    """Every volumetric measurement unremarkable, so there are no contributions -- but the
    window carries new fingerprints. The comparison must carry the real reason instead of
    "baseline present but no comparable measurements"."""
    flat = {"total_bytes": EXFIL_FLOW["total_bytes"], "total_packets": EXFIL_FLOW["total_packets"],
            "unique_dst_ips": EXFIL_FLOW["unique_dst_ips"], "flow_count": EXFIL_FLOW["flow_count"]}
    baseline = {"avg_bytes": flat["total_bytes"], "stddev_bytes": 0.0,
                "avg_packets": flat["total_packets"], "stddev_packets": 0.0,
                "avg_unique_dsts": flat["unique_dst_ips"], "stddev_unique_dsts": 0.0,
                "baseline_ja4_set": ["fp_old"]}
    e = explain({**flat, "_zeek": {"ja4_set": "['fp_new']"}}, baseline)
    assert "1 of 1 TLS fingerprints in this window is new for this host" in e["baseline_comparison"]


def test_a_below_normal_deviation_reports_its_direction():
    """'55x above normal' and '55x below normal' are different findings
    (exfiltration vs a service that went silent). A magnitude alone cannot say
    which, so the direction must survive into the JSON.

    All measurements are set low together: lowering only total_bytes would leave
    total_packets as the dominant deviation, and the comparison sentence would
    legitimately name packets instead (the first version of this test made exactly
    that mistake and asserted on the wrong sentence).
    """
    quiet = {"total_bytes": 1_000, "total_packets": 10, "unique_dst_ips": 1,
             "flow_count": 2, "avg_bytes": 500, "avg_packets": 5}
    e = explain(quiet, EXFIL_BASELINE)
    parsed = json.loads(e["feature_contributions"])
    assert parsed["total_bytes"]["direction"] == "below"
    assert parsed["total_bytes"]["z"] < -1
    assert e["primary_deviation_feature"] == "total_bytes"
    assert "below normal" in e["baseline_comparison"]


def test_small_deviations_do_not_claim_a_primary_feature():
    """A window can pass the ensemble gate on a structural signature while every
    measurement sits at its baseline (a pure SYN scan moves no bytes). Claiming a
    dominant feature there would invent a finding."""
    scan = {"total_bytes": 0, "total_packets": 0, "unique_dst_ips": 300,
            "flow_count": 305, "avg_bytes": 0, "avg_packets": 0}
    baseline = {**EXFIL_BASELINE, "avg_bytes": 0.0, "stddev_bytes": 0.0,
                "avg_packets": 0.0, "stddev_packets": 0.0,
                "avg_unique_dsts": 300.0, "stddev_unique_dsts": 5.0}
    e = explain(scan, baseline)
    assert e["primary_deviation_feature"] == "", (
        "a scan with no volume deviation must not name a primary feature"
    )
    assert "no single dominant feature" in summarise(e)


def test_missing_measurements_are_skipped_not_treated_as_zero():
    """An absent value is 'unknown', not 'measured zero'. Treating it as zero
    would manufacture a large negative deviation."""
    e = explain({"total_bytes": 3_600_000_000}, EXFIL_BASELINE)
    parsed = json.loads(e["feature_contributions"])
    assert "total_packets" not in parsed, "absent values must not be scored as 0"
    assert "unique_dst_ips" not in parsed
    assert parsed["total_bytes"]["z"] > 50


def test_summarise_never_returns_an_empty_string():
    """The alert body embeds this. An empty summary would silently drop the
    explanation block from the message."""
    for flow, baseline in ((EXFIL_FLOW, None), (EXFIL_FLOW, EXFIL_BASELINE)):
        assert summarise(explain(flow, baseline)).strip()


def test_explained_measurements_are_raw_not_log_transformed():
    """The explanation must name measurements an operator can reason about.
    The model features are log1p-transformed, so naming 'log_bytes' in an alert
    would tell a human nothing about magnitude."""
    for name in EXPLAINED_MEASUREMENTS:
        assert not name.startswith("log"), name
        assert name in EXFIL_FLOW, f"{name} is not a real aggregate column"


def test_shape_and_behaviour_measurements_are_baselined_without_moving_primary():
    """The card must show more than the three volume bars, but the severity rule stays put.

    These are real model inputs from the diversity/temporal rows: a host can be flagged by
    fan-out or port entropy while bytes look normal. The new values are contributions; the
    primary (and therefore the production severity rule) remains one of the original volume
    measurements until the operator has reviewed the new bars.
    """
    baseline = {
        **EXFIL_BASELINE,
        "avg_flow_count": 20.0, "stddev_flow_count": 3.0,
        "avg_unique_ports": 4.0, "stddev_unique_ports": 1.0,
        "avg_port_entropy": 0.9, "stddev_port_entropy": 0.2,
        "avg_activity_regularity": 0.95, "stddev_activity_regularity": 0.05,
        "avg_burstiness": 0.8, "stddev_burstiness": 0.1,
    }
    e = explain(EXFIL_FLOW, baseline)
    parsed = json.loads(e["feature_contributions"])
    for name in ("flow_count", "unique_dst_ports", "port_entropy",
                 "activity_regularity", "burstiness"):
        assert name in parsed, f"{name} is not explained even though a baseline exists"
    assert e["primary_deviation_feature"] == "total_bytes"
    assert parsed["unique_dst_ports"]["direction"] == "above"


def test_nested_diversity_and_temporal_values_are_read_from_the_window_row():
    """The worker attaches _diversity/_temporal; the explainer must read those, not zeros."""
    flow = {
        "total_bytes": 1, "total_packets": 1, "unique_dst_ips": 1, "flow_count": 1,
        "_diversity": {"unique_dst_ports": 30, "port_entropy": 4.5},
        "_temporal": {"activity_regularity": 0.1, "burstiness": 9.0},
    }
    baseline = {
        "avg_bytes": 1.0, "stddev_bytes": 1.0,
        "avg_packets": 1.0, "stddev_packets": 1.0,
        "avg_unique_dsts": 1.0, "stddev_unique_dsts": 1.0,
        "avg_flow_count": 1.0, "stddev_flow_count": 1.0,
        "avg_unique_ports": 4.0, "stddev_unique_ports": 1.0,
        "avg_port_entropy": 1.0, "stddev_port_entropy": 1.0,
        "avg_activity_regularity": 1.0, "stddev_activity_regularity": 1.0,
        "avg_burstiness": 1.0, "stddev_burstiness": 1.0,
    }
    parsed = json.loads(explain(flow, baseline)["feature_contributions"])
    assert parsed["unique_dst_ports"]["actual"] == 30
    assert parsed["port_entropy"]["actual"] == 4.5
    assert parsed["activity_regularity"]["actual"] == 0.1
    assert parsed["burstiness"]["actual"] == 9.0
