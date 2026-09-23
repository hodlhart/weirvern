
from datetime import datetime

from weirvern import ensemble
from weirvern.config import ModelConfig, Settings
from weirvern.ensemble import (
    adaptive_threshold_for,
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
    b = ensemble.detect_flows([dict(scan)], dets, higher, ModelConfig())[0]
    assert a["strong_models"] == 1 and b["strong_models"] == 0, (
        f"the bar did not move the strong count: {a['strong_models']} vs {b['strong_models']}"
    )
    assert a["signature"] is True, "the scan signature was not recognised at the lower bar"
    assert a["severity"] == "high", (
        f"the signature gate did not escalate at the 0.80 bar ({a['severity']})"
    )
    assert b["severity"] == "medium", (
        f"a 0.86 specialist stayed escalated at the 0.90 bar ({b['severity']}), so the "
        f"signature gate is still reading the constant"
    )


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
