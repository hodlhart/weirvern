
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
        "src_addr": "192.168.3.10",
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
