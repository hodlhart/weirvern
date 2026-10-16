
import dataclasses
import pathlib
from datetime import datetime

import pytest

from weirvern import ensemble
from weirvern.config import ModelConfig, Settings
from weirvern.ensemble import (
    adaptive_threshold_for,
    assert_thin_floor_is_reachable,
    detection_confidence_factor,
    fuse_scores,
    severity_of,
    signature_corroboration,
)


def test_base_threshold_unchanged_for_normal():
    flow = {"flow_count": 10, "unique_dst_ips": 8, "total_bytes": 500_000}
    assert adaptive_threshold_for(flow, 0.35) == 0.35


def test_scanning_lowers_threshold():
    flow = {"flow_count": 80, "unique_dst_ips": 2, "total_bytes": 300_000}
    assert adaptive_threshold_for(flow, 0.35) < 0.35


def test_tiny_packet_probe_lowers_threshold():
    flow = {"flow_count": 60, "unique_dst_ips": 10, "total_bytes": 30_000}  # <1000 B/flow
    assert adaptive_threshold_for(flow, 0.35) < 0.35


def test_exfil_lowers_threshold():
    flow = {"flow_count": 5, "unique_dst_ips": 1, "total_bytes": 80_000_000}
    assert adaptive_threshold_for(flow, 0.35) < 0.35


def test_floor_is_020():
    flow = {"flow_count": 500, "unique_dst_ips": 1, "total_bytes": 90_000_000}
    assert adaptive_threshold_for(flow, 0.35) >= 0.20


def test_credential_stuffing_lowers_threshold():
    flow = {"flow_count": 150, "unique_dst_ips": 1, "total_bytes": 2_000_000}
    assert adaptive_threshold_for(flow, 0.35) < 0.35


def test_severity_tiers():
    # Escalation to high/critical requires corroboration (>=2 strong detectors,
    # or one strong detector backed by a structural signature).
    assert severity_of(0.96, 0.8, strong_models=3) == "critical"
    assert severity_of(0.90, 0.6, strong_models=2) == "high"
    assert severity_of(0.86, 0.4, strong_models=2) == "high"   # >=0.85 score, corroborated
    assert severity_of(0.84, 0.5, strong_models=2) == "medium"
    assert severity_of(0.75, 0.5, strong_models=1) == "medium"
    assert severity_of(0.50, 0.5, strong_models=0) == "low"


def test_lone_strong_detector_does_not_escalate():
    """Measured false-positive shape: one strong model (GB 0.96) + weak others
    on ordinary low-activity traffic must NOT be critical/high."""
    assert severity_of(0.963, 0.75, strong_models=1) == "medium"
    assert severity_of(0.99, 1.0, strong_models=1) == "medium"


def test_two_strong_detectors_escalate():
    """Genuine attacks: port scan (IF+DBSCAN), exfil (all four)."""
    assert severity_of(0.99, 1.0, strong_models=2) == "critical"
    assert severity_of(0.90, 0.5, strong_models=2) == "high"


# --- structural signature corroboration --------------------------------------
SCAN_DIV = {"unique_dst_ports": 300, "port_entropy": 8.21}
NORMAL_DIV = {"unique_dst_ports": 2, "port_entropy": 0.92}


def test_lone_specialist_escalates_with_scan_signature():
    """Measured: a zero-byte SYN scan is invisible to volume models (IF 0.48,
    GB 0.01) but DBSCAN scores 0.99. The 300-port/8.2-entropy window is direct
    evidence, so this must escalate rather than sit at medium."""
    scores = {"Isolation Forest": 0.48, "Gradient Boosting": 0.01, "DBSCAN": 0.99, "Adaptive Baseline": 0.0}
    assert signature_corroboration({}, scores, SCAN_DIV, CFG)
    assert severity_of(0.99, 0.75, strong_models=1, signature=True) == "critical"


def test_lone_specialist_without_signature_stays_medium():
    """The measured false-positive shape: one strong model, no structural
    evidence, thin benign window -> must not escalate."""
    scores = {"Isolation Forest": 0.70, "Gradient Boosting": 0.96, "DBSCAN": 0.31, "Adaptive Baseline": 0.0}
    assert not signature_corroboration({}, scores, NORMAL_DIV, CFG)
    assert severity_of(0.96, 0.75, strong_models=1, signature=False) == "medium"


def test_signature_requires_lone_specialist():
    """Two strong models need no signature help."""
    two = {"a": 0.9, "b": 0.9, "c": 0.1, "d": 0.1}
    assert not signature_corroboration({}, two, SCAN_DIV, CFG)


def test_signature_thresholds():
    below = {"unique_dst_ports": 10, "port_entropy": 8.0}   # too few ports
    narrow = {"unique_dst_ports": 300, "port_entropy": 1.0}  # too concentrated
    one = {"DBSCAN": 0.99}
    assert not signature_corroboration({}, one, below, CFG)
    assert not signature_corroboration({}, one, narrow, CFG)
    assert not signature_corroboration({}, one, None, CFG)


# --- thin-window damping -----------------------------------------------------
CFG = ModelConfig()


def test_thin_window_damped():
    """Measured FP: 3-flow windows scored like attacks (one heavy-tailed flow
    dominates the window's statistics). Damping must push them below the
    default 0.35 detection threshold."""
    thin = detection_confidence_factor({"flow_count": 3}, CFG)
    assert thin < 0.5
    damped = 0.96 * thin  # a 0.96 fused score on a 3-flow window
    assert damped < 0.35, f"damped score {damped:.3f} would still alert"
    assert thin >= CFG.thin_window_floor


def test_full_window_untouched():
    assert detection_confidence_factor({"flow_count": 20}, CFG) == 1.0
    assert detection_confidence_factor({"flow_count": 305}, CFG) == 1.0


def test_damping_is_monotonic_and_floored():
    prev = 0.0
    for n in range(0, 12):
        v = detection_confidence_factor({"flow_count": n}, CFG)
        assert v >= prev
        assert v >= CFG.thin_window_floor
        prev = v


def test_attacks_survive_damping():
    """The real port scan had 305 flows -> no damping."""
    assert detection_confidence_factor({"flow_count": 305}, CFG) == 1.0


# --- fusion strategy ---------------------------------------------------------
W = {"a": 1.0, "b": 1.0, "c": 1.0, "d": 1.0}


def test_fusion_lets_specialist_fire_alone():
    """Core fix: a confident single detector must not be averaged away.
    (Real case: DBSCAN 0.99 on a port scan while volume models scored ~0.)"""
    score = fuse_scores({"a": 0.0, "b": 0.0, "c": 0.99, "d": 0.0}, W)
    assert score >= 0.90, f"specialist diluted to {score}"
    # legacy mean-fusion would have produced ~0.25 here
    assert sum({"a": 0.0, "b": 0.0, "c": 0.99, "d": 0.0}.values()) / 4 < 0.30


def test_fusion_all_quiet_is_zero():
    assert fuse_scores({"a": 0.0, "b": 0.0, "c": 0.0, "d": 0.0}, W) == 0.0


def test_fusion_empty_is_zero():
    assert fuse_scores({}, W) == 0.0


def test_fusion_respects_weights_in_mean_mode():
    """Weights are meaningful only in legacy mean mode (max mode must never
    suppress a confident specialist by scaling it down)."""
    high_w = fuse_scores({"a": 0.5}, {"a": 1.0}, mode="mean")
    low_w = fuse_scores({"a": 0.5, "b": 0.0}, {"a": 1.0, "b": 1.0}, mode="mean")
    assert high_w > low_w


def test_max_mode_never_scales_down():
    """Regression: weighting used to scale DBSCAN 0.99 -> 0.495, recreating
    the dilution bug. Max mode must report the raw confident signal."""
    scores = {"isolation_forest": 0.0, "gradient_boosting": 0.0, "dbscan": 0.99, "adaptive_baseline": 0.0}
    weights = {"isolation_forest": 1.0, "gradient_boosting": 0.75, "dbscan": 0.65, "adaptive_baseline": 0.5}
    assert fuse_scores(scores, weights, mode="max") >= 0.98


class SpyDetector:
    """Records the feature dict each predict got — proves enrichment wiring."""

    name = "Spy"

    def __init__(self):
        self.seen = []

    def predict(self, flow, features=None):  # noqa: ANN001
        self.seen.append(dict(features or {}))
        return 0.0

    def is_ready(self):
        return True


def _flow(with_enrichment):
    flow = {
        "window_start": datetime(2026, 9, 14, 10, 30),
        "window_end": datetime(2026, 9, 14, 10, 35),
        "src_addr": "198.51.100.10",
        "flow_count": 60,
        "total_bytes": 500_000,
        "total_packets": 500,
        "avg_bytes": 9000.0,
        "avg_packets": 9.0,
        "unique_dst_ips": 8,
    }
    if with_enrichment:
        flow["_diversity"] = {
            "unique_dst_ports": 80, "port_entropy": 3.2, "bytes_stddev": 25_000.0,
            "unique_connections": 55,
        }
        flow["_temporal"] = {"activity_regularity": 0.12, "burstiness": 4.0}
    return flow


def test_enrichment_reaches_feature_extraction():
    """v20 regression: worker-attached _diversity/_temporal must flow into the
    feature vector, or Phase 2 detectors score on defaults only."""
    spy = SpyDetector()
    # Scores 0.0 → no verdicts; we only assert on the features the spy saw.
    ensemble.detect_flows([_flow(with_enrichment=True)], [spy], _settings_lite(), ModelConfig())
    assert spy.seen, "detector was never called"
    feats = spy.seen[0]
    assert feats["port_entropy"] == 3.2
    assert feats["activity_regularity"] == 0.12
    assert feats["burstiness"] == 4.0
    assert feats["log_unique_dst_ports"] > 0


def test_no_enrichment_uses_safe_defaults():
    spy = SpyDetector()
    ensemble.detect_flows([_flow(with_enrichment=False)], [spy], _settings_lite(), ModelConfig())
    feats = spy.seen[0]
    assert feats["port_entropy"] == 0.0
    assert feats["activity_regularity"] == 1.0
    assert feats["burstiness"] == 1.0


def _settings_lite():
    return Settings()


# ── STRONG_SIGNAL is wired, not decorative ──────────────────────────────────────
#
# The defect: STRONG_SIGNAL was a module constant in ensemble.py while the GUI and the
# ConfigMap advertised it as editable and VALIDATED the value on apply. Changing it wrote
# a perfectly valid ConfigMap key that no code ever read -- the edit validated, the worker
# restarted, and the behaviour was identical. These tests drive detect_flows end to end
# with two different configured values and assert the severity ANSWER changes.

class _FixedDetector:
    """A detector that returns a scripted score, so the ensemble maths is isolated."""

    def __init__(self, name, score):
        self.name = name
        self._score = score

    def predict(self, flow, features=None):  # noqa: ANN001
        return self._score

    def is_ready(self):
        return True


def _strong_signal_flow():
    return {
        "window_start": "2026-09-19 10:00:00",
        "src_addr": "203.0.113.5",
        "flow_count": 60, "unique_dst_ips": 30, "total_bytes": 400_000,
    }


def test_the_configured_strong_signal_bar_decides_severity():
    """Two detectors at 0.86: 'strong' at the default 0.85 bar (two strong -> escalation),
    but NOT strong at a 0.90 bar (zero strong -> medium). Same scores, different setting,
    different verdict -- which is what "editable" has to mean."""
    import dataclasses

    scores = {"Isolation Forest": 0.86, "DBSCAN": 0.86, "Gradient Boosting": 0.0,
              "Adaptive Baseline": 0.0}
    dets = [_FixedDetector(n, s) for n, s in scores.items()]

    default = dataclasses.replace(Settings(), strong_signal=0.85, base_threshold=0.30)
    raised = dataclasses.replace(Settings(), strong_signal=0.90, base_threshold=0.30)

    low = ensemble.detect_flows([_strong_signal_flow()], dets, default, ModelConfig())
    high = ensemble.detect_flows([_strong_signal_flow()], dets, raised, ModelConfig())

    assert low, "the window fell below the alert threshold; adjust the fixture"
    assert high, "the window fell below the alert threshold; adjust the fixture"
    assert low[0]["severity"] == "high", low[0]["severity"]
    assert high[0]["severity"] == "medium", (
        f"raising STRONG_SIGNAL to 0.90 did not change the verdict ({high[0]['severity']}), "
        f"so the setting is not being read"
    )


def test_the_signature_gate_uses_the_configured_bar_too():
    """A LONE specialist at 0.86 with a scan signature escalates when the bar is 0.80 but not
    when it is 0.90 -- the second place the constant was read. The signature path only applies
    to a lone strong detector (see signature_corroboration), so exactly one detector fires."""
    import dataclasses

    scores = {"Isolation Forest": 0.0, "DBSCAN": 0.86, "Gradient Boosting": 0.0,
              "Adaptive Baseline": 0.0}
    dets = [_FixedDetector(n, s) for n, s in scores.items()]
    scan = _strong_signal_flow()
    scan["_diversity"] = {"unique_dst_ports": 300, "port_entropy": 8.2}

    lower = dataclasses.replace(Settings(), strong_signal=0.80, base_threshold=0.30)
    higher = dataclasses.replace(Settings(), strong_signal=0.90, base_threshold=0.30)

    a = ensemble.detect_flows([dict(scan)], dets, lower, ModelConfig())[0]
    # At the 0.90 bar the lone detector is no longer "strong" and carries no signature, so
    # the window is GATED -- not merely un-escalated. (Before the 2026-10-15 review the
    # top-tier agreement gate could never suppress a >= 0.6 window, so this case used to
    # alert at medium; that was the leak the gate fix closed. `a` proves the configured bar
    # is read; this proves the gate now binds.)
    b_near: list = []
    b = ensemble.detect_flows([dict(scan)], dets, higher, ModelConfig(), near_misses=b_near)
    assert a["strong_models"] == 1
    assert a["signature"] is True, "the scan signature was not recognised at the lower bar"
    assert a["severity"] == "high", (
        f"the signature gate did not escalate at the 0.80 bar ({a['severity']})"
    )
    assert b == [], (
        f"a lone specialist without a signature cleared the gate ({b[0] if b else None}) -- "
        f"the top-tier gate must bind"
    )
    assert b_near and b_near[0]["reason"] == "agreement-gate", (
        "the gated window did not surface as a near miss, so the drop would be invisible"
    )


def _top_tier_flow():
    """The strict-tier window paired with a 0.90 scripted score, so fusion lands in the
    >= 0.6 tier where the top-tier agreement bar applies."""
    return _strict_tier_flow()


def test_the_gate_binds_at_the_TOP_tier_too():
    """MEASURED DEFECT (review round 2026-10-15): with four detectors the smallest non-zero
    agreement (0.25) EQUALED the top-tier bar (MIN_AGREEMENT - margin = 0.25), and max-fusion
    guarantees some detector above the detected-by bar for any score >= 0.6 -- so
    `agreement < min_agreement` could never fire at the top tier. One detector's word alerted
    at medium and never appeared in near_misses."""
    scores = {"Isolation Forest": 0.90, "Gradient Boosting": 0.05,
              "DBSCAN": 0.05, "Adaptive Baseline": 0.05}
    dets = [_ScriptedDetector(n, s) for n, s in scores.items()]
    near: list = []
    got = ensemble.detect_flows([_top_tier_flow()], dets, _settings_lite(), ModelConfig(),
                                near_misses=near)
    assert got == [], "a lone 0.90 detector cleared the top-tier gate"
    assert near and near[0]["reason"] == "agreement-gate", (
        "the gated window did not surface as a near miss, so the drop would be invisible"
    )
    assert near[0]["model_agreement"] == 0.25


def test_a_lone_specialist_with_a_signature_still_clears_the_gate():
    """The gate's ONE deliberate exemption, which must survive the fix: one strong detector
    plus a direct structural signature is not "one detector's word" -- it is one detector
    plus the traffic's own shape (the zero-byte port scan, measured when the signature path
    was built)."""
    scores = {"Isolation Forest": 0.05, "Gradient Boosting": 0.05,
              "DBSCAN": 0.99, "Adaptive Baseline": 0.05}
    dets = [_ScriptedDetector(n, s) for n, s in scores.items()]
    flow = _top_tier_flow()
    flow["_diversity"] = {"unique_dst_ports": 300, "port_entropy": 8.2}
    near: list = []
    got = ensemble.detect_flows([flow], dets, _settings_lite(), ModelConfig(), near_misses=near)
    assert got, "a lone strong specialist with a scan signature was suppressed"
    assert got[0]["severity"] in ("high", "critical")
    assert not [m for m in near if m["reason"] == "agreement-gate"]


def test_two_agreeing_detectors_still_clear_the_top_tier():
    """The exclusion is 'more than ONE detector', not 'most detectors': 2 of 4 must pass."""
    scores = {"Isolation Forest": 0.90, "Gradient Boosting": 0.90,
              "DBSCAN": 0.05, "Adaptive Baseline": 0.05}
    dets = [_ScriptedDetector(n, s) for n, s in scores.items()]
    got = ensemble.detect_flows([_top_tier_flow()], dets, _settings_lite(), ModelConfig(),
                                near_misses=[])
    assert got, "2 of 4 detectors at 0.90 did not clear the top-tier gate"


def test_strong_signal_threshold_reads_settings_and_falls_back():
    assert ensemble.strong_signal_threshold(None) == ensemble.STRONG_SIGNAL
    import dataclasses
    s = dataclasses.replace(Settings(), strong_signal=0.91)
    assert ensemble.strong_signal_threshold(s) == 0.91
    # A settings object without the attribute (an older caller) must not crash the sweep.
    class _Bare:
        pass
    assert ensemble.strong_signal_threshold(_Bare()) == ensemble.STRONG_SIGNAL


# ── A DETECTOR THAT FAILED TO TRAIN LOOSENED THE AGREEMENT GATE (audit F043) ──────────────────
#
# `agreement = len(detected_by) / active`, where `active` counted only detectors reporting READY.
# `is_ready()` is "trained successfully", so a detector that failed to train removed itself from the
# denominator -- and because agreement is a RATIO, losing detectors made it LARGER.
#
# MEASURED by driving the real ensemble with the same flow and the same scores, varying only
# readiness (score 0.550, which puts it in the strict tier where min_agreement is the full 0.33):
#
#     all 4 ready (healthy)   agreement=0.25  -> SUPPRESSED
#     DBSCAN failed to train  agreement=0.33  -> ALERT
#     GB and DBSCAN failed    agreement=0.50  -> ALERT
#     only IF ready           agreement=1.00  -> ALERT, confidence 0.550
#
# A broken model turned a window the ensemble had DELIBERATELY SUPPRESSED into an alert that looked
# BETTER corroborated than a healthy one, because confidence is score*agreement. The failure is
# silent in the worst direction: it manufactures alerts, and its alerts look more certain.


class _ScriptedDetector:
    """A detector with a scripted score AND a scripted readiness."""

    def __init__(self, name, score, ready=True):
        self.name = name
        self._score = score
        self._ready = ready

    def predict(self, flow, features=None):  # noqa: ANN001
        return self._score

    def is_ready(self):
        return self._ready

    def train(self, *a, **k):
        return True


def _strict_tier_flow():
    """A flow whose fused score lands in the strict tier, where the full min_agreement applies."""
    return {
        "window_start": "2026-09-19 10:00:00",
        "src_addr": "203.0.113.5",
        "flow_count": 300, "unique_dst_ips": 42, "total_bytes": 5_000_000,
    }


def _verdict_with(missing: set[str]):
    """One alert-or-not verdict, with the named detectors NOT READY."""
    scores = {"Isolation Forest": 0.55, "Gradient Boosting": 0.05,
              "DBSCAN": 0.05, "Adaptive Baseline": 0.05}
    dets = [_ScriptedDetector(n, s, ready=(n not in missing)) for n, s in scores.items()]
    return ensemble.detect_flows([_strict_tier_flow()], dets, _settings_lite(),
                                 ModelConfig(), near_misses=[])


def test_a_MISSING_detector_does_not_manufacture_an_alert():
    """THE DEFECT. The healthy ensemble suppresses this window; a broken one must not promote it."""
    healthy = _verdict_with(set())
    assert healthy == [], (
        f"the fixture no longer models the defect: the healthy ensemble ALERTED "
        f"({[v['anomaly_score'] for v in healthy]}), so the comparison below is meaningless"
    )

    for missing in ({"DBSCAN"}, {"Gradient Boosting", "DBSCAN"},
                    {"Gradient Boosting", "DBSCAN", "Adaptive Baseline"}):
        got = _verdict_with(missing)
        assert got == [], (
            f"with {sorted(missing)} FAILED TO TRAIN, the ensemble alerted on a window the healthy "
            f"ensemble suppressed. Losing detectors made the gate LOOSER -- the ratio grew as the "
            f"denominator shrank. Verdict: {got[0] if got else None}"
        )


def test_agreement_denominator_is_the_ENSEMBLE_not_the_survivors():
    """The arithmetic itself, so the reason is pinned as well as the outcome.

    Asserted on a near-miss row, which carries `model_agreement` for a window that was scored but
    gated -- the one place the ratio is visible without an alert.
    """
    scores = {"Isolation Forest": 0.55, "Gradient Boosting": 0.05,
              "DBSCAN": 0.05, "Adaptive Baseline": 0.05}

    # A DETECTOR NAMED "DBSCAN" IS NOT READY, so only IF is above 0.20: 1 of 4 = 0.25.
    dets = [_ScriptedDetector(n, s, ready=(n != "DBSCAN")) for n, s in scores.items()]
    near: list = []
    ensemble.detect_flows([_strict_tier_flow()], dets, _settings_lite(), ModelConfig(),
                          near_misses=near)
    assert near, "the window did not produce a near miss, so this test proves nothing"
    assert near[0]["model_agreement"] == 0.25, (
        f"model_agreement was {near[0]['model_agreement']} with 1 of 4 detectors above the bar. "
        f"With the broken detector excluded from the denominator it would read 0.33 (1 of 3), which "
        f"is the defect: a failure made the ensemble look MORE agreed"
    )


def test_a_genuinely_CORROBORATED_window_still_alerts():
    """The other direction, so the fix cannot be "never alert".

    Three of four detectors agreeing must still fire, and a broken detector must LOWER the reported
    confidence rather than raise it.
    """
    scores = {"Isolation Forest": 0.90, "Gradient Boosting": 0.90,
              "DBSCAN": 0.90, "Adaptive Baseline": 0.05}
    all_ready = [_ScriptedDetector(n, s) for n, s in scores.items()]
    got = ensemble.detect_flows([_strict_tier_flow()], all_ready, _settings_lite(),
                                ModelConfig(), near_misses=[])
    assert got, "a window where three detectors agree at 0.90 did not alert"
    healthy_confidence = got[0]["confidence"]

    # Same scores, but DBSCAN failed to train. The other three still agree, so the ratio is
    # unchanged at 3 of 4 and the confidence must be IDENTICAL.
    #
    # MY FIRST ASSERTION HERE WAS WRONG and the failure was informative: I asserted the broken case
    # would report LOWER confidence, and it reported exactly the same (0.675). That is the fix
    # working -- the denominator is the ensemble either way, so a failure neither raises nor lowers
    # the ratio, it simply is not counted as agreement. Asserting a decrease would have locked in the
    # opposite of the intended behaviour.
    broken = [_ScriptedDetector(n, s, ready=(n != "DBSCAN")) for n, s in scores.items()]
    got2 = ensemble.detect_flows([_strict_tier_flow()], broken, _settings_lite(),
                                 ModelConfig(), near_misses=[])
    assert got2, "a window with three of four detectors at 0.90 stopped alerting when one broke"
    assert got2[0]["confidence"] == healthy_confidence, (
        f"confidence changed from {healthy_confidence} to {got2[0]['confidence']} when a detector "
        f"failed, but the SAME three of four detectors still agree -- the ratio is unchanged"
    )
    assert got2[0]["model_agreement"] == 0.75, (
        f"agreement is {got2[0]['model_agreement']}; three of four detectors are above the bar"
    )


def test_the_near_miss_agreement_uses_the_SAME_denominator_as_the_alert_path():
    """TWO PLACES COMPUTE THIS RATIO, and only one was pinned.

    A mutation restoring the ready-count denominator in the NEAR-MISS branch was MISSED, because my
    test used 1-of-4 above the bar -- where "1 of 4 ready" and "1 of 4 present" give the same 0.25.
    The two spellings only diverge once MORE detectors agree than are ready, which cannot happen in
    practice but is exactly what a mutation does.

    The assertion therefore uses a case where the two differ: three detectors above the bar with one
    of them NOT READY. Present-count says 3/4 = 0.75; ready-count says 3/3 = 1.00.
    """
    # The scores must fuse BELOW the threshold so the row lands in the near-miss band rather than
    # alerting -- three detectors at 0.55 fused high enough to alert, and the test found out by
    # producing no near miss at all. `max` fusion takes the largest, so one high score is enough to
    # sit just under the bar while the OTHERS still count as above the 0.20 agreement bar.
    scores = {"Isolation Forest": 0.30, "Gradient Boosting": 0.30,
              "DBSCAN": 0.30, "Adaptive Baseline": 0.05}
    dets = [_ScriptedDetector(n, s, ready=(n != "DBSCAN")) for n, s in scores.items()]

    near: list = []
    ensemble.detect_flows([_strict_tier_flow()], dets, _settings_lite(), ModelConfig(),
                          near_misses=near)
    assert near, "the window produced no near miss, so this test proves nothing"
    assert near[0]["model_agreement"] == 0.75, (
        f"near-miss model_agreement was {near[0]['model_agreement']}. Present-count says 3/4=0.75; "
        f"the ready-count spelling says 3/3=1.00 -- a failure must not inflate the ratio on this "
        f"path either"
    )


def test_the_denominator_is_the_LENGTH_OF_THE_LIST_not_a_literal():
    """`build_detectors` ships four, but the ensemble must not assume that.

    A mutation replacing `len(detectors)` with a hardcoded 4 was MISSED: with four detectors in the
    test the two are identical. This drives the same arithmetic with a TWO-detector ensemble, where a
    literal 4 would halve the agreement (1 of 4 = 0.25 instead of 1 of 2 = 0.50) and change the
    verdict.
    """
    # Two detectors, both above the bar: agreement must be 1.00, not 0.50.
    dets = [_ScriptedDetector("Isolation Forest", 0.55), _ScriptedDetector("DBSCAN", 0.55)]
    near: list = []
    verdicts = ensemble.detect_flows([_strict_tier_flow()], dets, _settings_lite(), ModelConfig(),
                                     near_misses=near)
    if verdicts:
        assert verdicts[0]["model_agreement"] == 1.0, (
            f"a two-detector ensemble where BOTH agree reported {verdicts[0]['model_agreement']}; "
            f"a hardcoded denominator would report 2/4=0.50"
        )
    else:
        assert near, "the window was neither alerted nor recorded as a near miss"
        assert near[0]["model_agreement"] == 1.0, (
            f"a two-detector ensemble where both agree reported {near[0]['model_agreement']}"
        )


# ── THE WEIGHTS ARE INERT UNDER max FUSION, AND THAT IS A DECISION, NOT A BUG (audit F046) ───────
#
# F046 claimed the weight settings are inert AND that "an operator's validated edit changes nothing".
# The first half is true and documented in `fuse_scores`; the second half is REFUTED, and the
# difference matters because acting on the false half would mean "fixing" the inertness of settings
# nobody can set -- which is how a documented decision gets undone by an audit.
#
# These tests pin BOTH halves so neither is rediscovered as a defect.


def test_weights_are_INERT_under_max_fusion_by_design():
    """The documented behaviour: max fusion reports the strongest detector, unscaled.

    Pinned so that making the weights "work" under max is a deliberate change with a failing test in
    front of it, rather than something an audit round does by accident. The rationale is measured:
    averaging a confident specialist's 0.99 down against quiet detectors is what let a seeded port
    scan score below benign hosts.
    """
    scores = {"Isolation Forest": 0.90, "Gradient Boosting": 0.10,
              "DBSCAN": 0.20, "Adaptive Baseline": 0.30}
    neutral = fuse_scores(dict(scores), {n: 1.0 for n in scores}, mode="max")
    scaled_down = fuse_scores(dict(scores), {**{n: 1.0 for n in scores}, "Isolation Forest": 0.1},
                              mode="max")
    scaled_up = fuse_scores(dict(scores), {**{n: 1.0 for n in scores}, "Isolation Forest": 9.9},
                            mode="max")

    assert neutral == scaled_down == scaled_up, (
        f"max fusion responded to a per-detector weight ({neutral} / {scaled_down} / {scaled_up}). "
        f"Scaling the strongest detector down re-introduces the dilution `fuse_scores` documents"
    )
    assert neutral == 0.90, f"max fusion is not the strongest signal: {neutral}"


def test_weights_DO_apply_under_mean_fusion():
    """The other half: the weights are not dead, they are scoped to the mode that reads them.

    A fix that deleted them as "unused" would break the A/B comparison the mode exists for.
    """
    scores = {"Isolation Forest": 0.90, "Gradient Boosting": 0.10,
              "DBSCAN": 0.20, "Adaptive Baseline": 0.30}
    low = fuse_scores(dict(scores), {**{n: 1.0 for n in scores}, "Isolation Forest": 0.1},
                      mode="mean")
    high = fuse_scores(dict(scores), {**{n: 1.0 for n in scores}, "Isolation Forest": 9.9},
                       mode="mean")
    assert low != high, (
        f"mean fusion ignored the weights ({low} == {high}); the weights exist for this mode"
    )
    assert low < high, f"raising a detector's weight lowered the mean-fused score ({low} > {high})"


def test_no_operator_path_can_SET_a_weight_or_fusion_mode():
    """THE HALF OF F046 THAT IS FALSE, pinned so it stays false.

    No env binding, not in the config's editable allowlist, and rejected by `validate()` -- so an edit
    is refused rather than silently discarded. If any of these ever becomes settable, this test fails
    and the inertness becomes a real finding at that moment.
    """
    import dataclasses

    from weirvern.admin.cluster_config import EDITABLE_KEYS, validate
    from weirvern.config import ModelConfig

    names = [f.name for f in dataclasses.fields(ModelConfig)
             if f.name.startswith("weight")] + ["fusion_mode"]
    assert names, "no weight fields found; the audit's subject has moved"

    for n in names:
        assert n.upper() not in EDITABLE_KEYS, (
            f"{n} is now settable from the GUI. It is INERT under max fusion, so an operator edit "
            f"would now genuinely change nothing -- audit F046 becomes a REAL finding"
        )
        with pytest.raises(Exception) as e:
            validate(n, "0.5")
        assert "not editable" in str(e.value), (
            f"validate({n!r}) no longer rejects on editability, so this guard no longer proves the "
            f"value cannot be set through the settings path"
        )


def test_weight_baseline_missing_is_applied_at_RUNTIME_not_in_the_base_map():
    """`weight_baseline_missing` is absent from `cfg.weights` on purpose.

    It is the baseline detector's weight when NO baseline exists for the host, and only
    `detection_sweep` knows which case applies -- the runtime branch overrides the base map there.
    Removing the override, or adding a base entry and calling it wired, are the two ways to break it.
    """
    from weirvern.config import ModelConfig

    cfg = ModelConfig()
    assert "weight_baseline_missing" not in cfg.weights, (
        "weight_baseline_missing moved into the base weight map; the runtime branch that decides "
        "baseline-present vs baseline-absent is the only place that can know which applies"
    )
    src = (pathlib.Path(__file__).resolve().parent.parent / "weirvern" / "ensemble.py").read_text()
    assert "weight_baseline_missing" in src, (
        "nothing in ensemble.py references weight_baseline_missing any more, so the setting is "
        "genuinely dead rather than applied at runtime"
    )
    assert "has_baseline" in src, "the runtime baseline-present branch is gone"


# ── A WHOLE CATEGORY OF WINDOWS WAS MATHEMATICALLY UNALERTABLE (audit F186) ─────────────────────
#
# FOUND LIVE: 23 of 23 near misses scored EXACTLY 0.3465 across six unrelated hosts, against a
# threshold of 0.35. A constant score is not a coincidence, it is an arithmetic ceiling.
#
# `fuse_scores` caps every score at MAX_FUSED_SCORE (0.99); `detection_confidence_factor` multiplies
# by `max(thin_window_floor, flow_count / min_flows_for_full_confidence)`. For a window with 1-3
# flows the ratio is 0.1-0.3, so the floor applies: 0.99 * 0.35 = 0.3465, which is 0.0035 SHORT of
# the 0.35 bar. So a one-flow window where EVERY detector reports the maximum was suppressed, and no
# input could change that -- the window was not scored low, it was UNREACHABLE.
#
# MEASURED ON THE CLUSTER: 566 of 567 windows in a 6-hour span (99.8%, carrying 99.98% of the bytes)
# were thin enough to be capped there. The counts were read from the COLLAPSED aggregates, because
# F181 established the raw table is fragmented per insert block and a per-block read would have
# understated them.
#
# THE TWO CONSTANTS ARE DIFFERENT KINDS OF NUMBER -- a multiplier floor and an absolute threshold --
# and they shipped as the same value, which is how the relationship went unstated and untested.


def test_the_shipped_config_lets_a_maximally_signalled_thin_window_alert():
    """THE DEFECT, on the shipped configuration rather than a synthetic one."""
    assert_thin_floor_is_reachable(CFG, _settings_lite().base_threshold)

    dets = [_FixedDetector("Isolation Forest", 0.99), _FixedDetector("Gradient Boosting", 0.99),
            _FixedDetector("DBSCAN", 0.99), _FixedDetector("Adaptive Baseline", 0.99)]
    for flows in (1, 2, 3):
        flow = {"window_start": "2026-09-19 10:00:00", "src_addr": "203.0.113.5",
                "flow_count": flows, "unique_dst_ips": 1, "total_bytes": 900}
        nm: list = []
        got = ensemble.detect_flows([dict(flow)], dets, _settings_lite(), CFG, near_misses=nm)
        assert got, (
            f"a {flows}-flow window with ALL FOUR detectors at the maximum 0.99 was suppressed "
            f"(score {nm[0]['anomaly_score'] if nm else None}, bar "
            f"{nm[0]['threshold_used'] if nm else None}). It cannot alert whatever the detectors "
            f"report, because MAX_FUSED_SCORE * thin_window_floor ({CFG.thin_window_floor}) is below "
            f"base_threshold -- audit F186"
        )


def test_the_check_REJECTS_the_configuration_that_shipped():
    """The old value must fail loudly, or the guard proves nothing."""
    bad = dataclasses.replace(CFG, thin_window_floor=0.35)
    with pytest.raises(ValueError) as e:
        assert_thin_floor_is_reachable(bad, _settings_lite().base_threshold)
    msg = str(e.value)
    assert "cannot reach the alert threshold" in msg, msg
    assert "0.3465" in msg, f"the error must name the actual ceiling so the fix is obvious: {msg}"


def test_a_zero_flow_window_is_still_handled():
    """`flow_count` 0 is a real value in the aggregate tables; it must not divide by zero or pass."""
    assert_thin_floor_is_reachable(CFG, _settings_lite().base_threshold)
    assert detection_confidence_factor({"flow_count": 0}, CFG) >= CFG.thin_window_floor


def test_the_measured_false_positive_is_STILL_suppressed():
    """THE OTHER DIRECTION. The damping exists because benign 3-4 flow windows scored 'critical':
    a single heavy-tailed flow dominates the window's mean/stddev. Raising the floor must not undo
    that, or this fix trades a blind band for alert noise."""
    dets = [_FixedDetector("Isolation Forest", 0.96), _FixedDetector("Gradient Boosting", 0.96),
            _FixedDetector("DBSCAN", 0.96), _FixedDetector("Adaptive Baseline", 0.96)]
    flow = {"window_start": "2026-09-19 10:00:00", "src_addr": "203.0.113.5",
            "flow_count": 3, "unique_dst_ips": 4, "total_bytes": 900}
    nm: list = []
    got = ensemble.detect_flows([dict(flow)], dets, _settings_lite(), CFG, near_misses=nm)
    assert not got, (
        "the measured benign 3-flow false positive (raw 0.96) now ALERTS. The damping was added "
        "for exactly this case; the floor must be reachable for a maximal signal without promoting "
        "a merely high one"
    )
    assert nm and nm[0]["anomaly_score"] < nm[0]["threshold_used"]


def test_the_relationship_is_expressed_once_not_reimplemented():
    """The guard computes the ceiling from MAX_FUSED_SCORE; a second copy of the literal would let
    the two drift, which is how this went wrong in the first place."""
    src = (pathlib.Path(__file__).resolve().parent.parent / "weirvern" / "ensemble.py").read_text()
    assert "MAX_FUSED_SCORE = 0.99" in src, "the score cap is no longer a named constant"
    # The cap must be USED, not merely declared.
    code = [ln for ln in src.splitlines() if not ln.lstrip().startswith("#")]
    uses = [ln for ln in code if "MAX_FUSED_SCORE" in ln]
    assert len(uses) >= 4, (
        f"MAX_FUSED_SCORE appears in only {len(uses)} code lines; the cap and the guard must share "
        f"one definition or they can disagree"
    )


def test_the_sweep_refuses_to_run_an_unalertable_configuration():
    """The check must run BEFORE detectors do, so a broken configuration names itself."""
    src = (pathlib.Path(__file__).resolve().parent.parent / "weirvern" / "worker.py").read_text()
    assert "assert_thin_floor_is_reachable" in src, (
        "detection_sweep no longer verifies the threshold relationship; a configuration that cannot "
        "alert would be silently accepted again"
    )
    i_check = src.index("assert_thin_floor_is_reachable")
    i_score = src.index("verdicts = ensemble.detect_flows(")
    assert i_check < i_score, "the configuration check runs AFTER scoring began"


def test_an_operators_RAISED_threshold_is_caught_without_stopping_detection():
    """`BASE_THRESHOLD` is operator-editable, so the guard has to hold for values nobody shipped.

    A raise from inside the sweep would be a worse failure than the one being fixed: the detection
    loop would error every cycle, replacing "blind to thin windows" with "detection stopped". So the
    sweep LOGS, and `main()` refuses to start. This pins the sweep's half -- the guard detects the
    condition -- and the startup half is asserted against the source below.
    """
    for raised in (0.36, 0.40, 0.50, 0.70):  # 0.3564 is the reachable ceiling at floor 0.36
        with pytest.raises(ValueError):
            assert_thin_floor_is_reachable(CFG, raised)
    # ...and the boundary itself must still be ACCEPTED, or the guard is off by its own rounding.
    assert_thin_floor_is_reachable(CFG, 0.3564)


def test_startup_REFUSES_an_unalertable_configuration_while_the_sweep_only_warns():
    """Two call sites, two behaviours, for a reason: startup can refuse, a live edit cannot.

    The startup check exists so a deployment that could never have alerted fails loudly instead of
    reporting itself healthy. The sweep check exists because BASE_THRESHOLD can change while the
    worker is running, and there the honest response is a loud warning -- stopping detection would
    trade a blind band for no detection at all.
    """
    src = (pathlib.Path(__file__).resolve().parent.parent / "weirvern" / "worker.py").read_text()

    # startup: raises SystemExit next to the malformed-CIDR precedent
    assert "Detection configuration is unalertable" in src, (
        "main() no longer refuses to start on an unalertable configuration"
    )
    assert "raise SystemExit(2) from exc" in src, "the startup refusal no longer exits non-zero"

    # sweep: logs, and only once per distinct configuration
    assert "_thin_floor_warned" in src, (
        "the sweep has no once-per-configuration latch, so a bad live edit would log every cycle"
    )
    assert "DETECTION CANNOT ALERT ON THIN WINDOWS" in src

    i_sweep_check = src.index("global _thin_floor_warned")
    i_scoring = src.index("verdicts = ensemble.detect_flows(")
    assert i_sweep_check < i_scoring, "the sweep checks the configuration after detection has run"


# ── THE TWO CALL SITES BEHAVE DIFFERENTLY, AND ONLY SOURCE GREPS PINNED IT (audit F186) ─────────
#
# Mutation testing missed both of these when the tests only searched the source text:
#   * making `main()` warn instead of exit was not detected, because "raise SystemExit" still
#     appeared elsewhere in the file;
#   * removing the sweep's once-per-configuration latch was not detected at all, because the only
#     assertion was that the name `_thin_floor_warned` exists.


def test_main_REFUSES_TO_START_on_an_unalertable_configuration(monkeypatch, caplog):
    """Behavioural, not textual. `main()` must exit non-zero, not merely mention the problem.

    Driven through the real `main()` with a settings object that can never alert, and with the work
    that follows it stubbed to fail loudly -- so if the refusal is removed, the test fails on the
    stubbed call rather than silently passing.
    """
    import weirvern.worker as worker_mod

    bad_cfg = dataclasses.replace(ModelConfig(), thin_window_floor=0.30)
    # Settings is a FROZEN dataclass, so a field cannot be assigned -- `replace` is the way to build
    # a variant, and my first version raised FrozenInstanceError instead of testing anything.
    bad_settings = dataclasses.replace(Settings(), base_threshold=0.90)

    monkeypatch.setattr(worker_mod, "get_settings", lambda: bad_settings)
    monkeypatch.setattr(worker_mod, "ModelConfig", lambda: bad_cfg)

    # If the refusal does NOT happen, execution continues into these and the test fails on them.
    def _must_not_be_reached(*a, **k):
        raise AssertionError("main() continued past an unalertable configuration")

    monkeypatch.setattr(worker_mod.db, "connect", _must_not_be_reached)
    monkeypatch.setattr(worker_mod.db, "apply_schema", _must_not_be_reached)
    monkeypatch.setattr(worker_mod, "_handle_sigterm", lambda *a, **k: None)
    monkeypatch.setattr(worker_mod.signal, "signal", lambda *a, **k: None)

    with pytest.raises(SystemExit) as e:
        worker_mod.main()
    assert e.value.code == 2, f"refused with the wrong exit code: {e.value.code}"


def test_the_sweep_warns_ONCE_per_configuration_not_once_per_cycle(monkeypatch):
    """THE LATCH, BY DRIVING IT.

    MY FIRST VERSION RE-IMPLEMENTED THE LATCH INSIDE THE TEST, so a mutation removing the product's
    latch changed nothing and the mutation survived. A test that re-implements what it is testing
    proves nothing about the product. The check is now a real function and this drives it.

    A warning that repeats every 300s is a warning operators filter out, which is the same silence
    by another route -- so it must fire once, and it must fire AGAIN when the configuration changes,
    or a second distinct misconfiguration hides behind the first.
    """
    import logging

    import weirvern.worker as worker_mod

    bad_settings = dataclasses.replace(Settings(), base_threshold=0.95)
    cfg = dataclasses.replace(ModelConfig(), thin_window_floor=0.36)

    seen = []

    class _Rec(logging.Handler):
        def emit(self, record):  # noqa: ANN001
            seen.append(record.getMessage())

    logger = logging.getLogger("weirvern.worker")
    h = _Rec()
    logger.addHandler(h)
    worker_mod._thin_floor_warned = None
    try:
        # Three sweeps with an UNCHANGED bad configuration.
        for _ in range(3):
            assert worker_mod.check_thin_floor_reachable(cfg, bad_settings) is False

        alarms = [m for m in seen if "CANNOT ALERT" in m]
        assert len(alarms) == 1, (
            f"the unalertable-configuration warning fired {len(alarms)} times across three sweeps "
            f"with an unchanged configuration. It must fire once per configuration, or operators "
            f"learn to filter it out"
        )

        # A DIFFERENT bad configuration must warn again.
        worker_mod.check_thin_floor_reachable(cfg, dataclasses.replace(Settings(), base_threshold=0.99))
        alarms = [m for m in seen if "CANNOT ALERT" in m]
        assert len(alarms) == 2, (
            "a DIFFERENT unalertable configuration did not warn again; a latch that never re-fires "
            "hides a second misconfiguration behind the first"
        )

        # And a GOOD configuration clears the latch, so returning to bad warns afresh.
        assert worker_mod.check_thin_floor_reachable(cfg, _settings_lite()) is True
        assert worker_mod._thin_floor_warned is None, (
            "a passing check left the latch set, so the next violation would be swallowed"
        )
    finally:
        logger.removeHandler(h)
        worker_mod._thin_floor_warned = None


def test_the_sweep_CALLS_the_check_before_scoring(monkeypatch):
    """The extracted function must actually be wired into the sweep, not merely exist.

    A helper nothing calls is the same silent failure in a new shape; this asserts the call site.
    """
    src = (pathlib.Path(__file__).resolve().parent.parent / "weirvern" / "worker.py").read_text()
    assert "check_thin_floor_reachable(cfg, settings)" in src, (
        "detection_sweep no longer calls check_thin_floor_reachable; the guard exists but nothing "
        "runs it"
    )
    i_call = src.index("check_thin_floor_reachable(cfg, settings)")
    i_score = src.index("verdicts = ensemble.detect_flows(")
    assert i_call < i_score, "the check runs after detection has already scored"


def test_severity_of_does_not_advertise_a_gate_it_does_not_read():
    """Issue #33: `agreement` survived the refactor as a DEAD parameter — the signature said
    severity was gated on the agreement ratio while the body reads only `strong_models` and
    the structural-signature flag. A parameter nothing reads is this project's oldest bug
    class: the next severity fix may wire it back in believing it is already consulted, and a
    caller reading the signature reasonably assumes the same. The signature must not carry
    it."""
    import inspect

    params = list(inspect.signature(ensemble.severity_of).parameters)
    assert params == ["score", "strong_models", "signature"], (
        f"severity_of's parameters no longer match what it reads: {params}"
    )


def test_no_dead_detector_catalog_next_to_the_real_mapping():
    """Issue #36: `_detector_catalog` duplicated the four display names that NAME_TO_KEY
    (inside detect_flows) already maps, with NO reader anywhere in the tree. A second copy
    next to the real mapping invites an edit to one of them -- the shape this codebase ruled
    on when worker._explain_primary was deleted rather than left "plausible next to the real
    one". The check strips comments and string contents through the tokenizer, so a comment
    MAY mention the removed name without resurrecting it; an identifier in real code cannot
    come back unnoticed."""
    import io
    import tokenize

    src = pathlib.Path(__file__).resolve().parents[1] / "weirvern" / "ensemble.py"
    code = " ".join(
        tok.string
        for tok in tokenize.generate_tokens(io.StringIO(src.read_text()).readline)
        if tok.type not in (tokenize.COMMENT, tokenize.STRING)
    )
    assert "_detector_catalog" not in code, (
        "a detector-name catalog is back beside NAME_TO_KEY -- wire one to the other, or "
        "delete it; two copies of the names is how they drift"
    )
