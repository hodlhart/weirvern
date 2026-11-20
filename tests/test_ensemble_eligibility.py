"""The eligibility gate must not let an out-of-budget detector set the fused score."""
from __future__ import annotations

from types import SimpleNamespace

from weirvern.config import ModelConfig, Settings
from weirvern.ensemble import contributing_scores, detect_flows, fuse_scores
from weirvern.models.calibration import eligibility_from_rows


def test_an_ineligible_detector_is_removed_from_fusion_not_zeroed():
    """Excluded, not counted as zero -- a zero would still drag a mean fusion down."""
    scores = {"KNN distance": 0.99, "Isolation Forest": 0.20, "Adaptive Baseline": 0.10}
    contributing = contributing_scores(scores, {"KNN distance": False,
                                                "Isolation Forest": True,
                                                "Adaptive Baseline": True})
    assert "KNN distance" not in contributing, "an ineligible model must not enter fusion"
    assert fuse_scores(contributing) == 0.20
    # Evidence still carries the raw score.
    assert scores["KNN distance"] == 0.99


def test_eligibility_uses_target_times_multiple():
    rows = [
        ("DBSCAN", 0.9994, 0.01),
        ("Adaptive Baseline", 0.0717, 0.01),
        ("Isolation Forest", 0.0119, 0.01),
        ("Gradient Boosting", 0.0118, 0.01),
    ]
    out = eligibility_from_rows(rows, target_far=0.01, multiple=3.0)
    assert out["DBSCAN"] is False
    assert out["Adaptive Baseline"] is False
    assert out["Isolation Forest"] is True
    assert out["Gradient Boosting"] is True


def test_an_empty_calibration_mapping_does_not_quarantine_a_model():
    """A deployment with no calibration rows at all still runs detection."""
    assert eligibility_from_rows([], target_far=0.01, multiple=3.0) == {}
    assert contributing_scores({"KNN distance": 0.99}, {})["KNN distance"] == 0.99
    # ... but once the mapping exists, a model absent from it has no met budget and is out.
    assert contributing_scores({"KNN distance": 0.99}, {"Isolation Forest": True}) == {}


def test_eligibility_default_is_on_with_a_kill_switch():
    settings = Settings()
    assert settings.ml_eligibility is True
    assert settings.ml_eligibility_multiple > 0


def test_ineligible_dbscan_still_allows_a_structural_signature_to_alert():
    # A pure SYN scan: no bytes, many ports. DBSCAN sees it; the volume models do not.
    flow = {
        "src_addr": "198.51.100.10",
        "window_start": "2026-10-30 00:00:00",
        "window_end": "2026-10-30 00:05:00",
        "flow_count": 305,
        "total_bytes": 0,
        "unique_dst_ips": 1,
        "_diversity": {"unique_dst_ports": 300, "port_entropy": 5.0},
    }
    fakes = [
        SimpleNamespace(name="Isolation Forest", predict=lambda *a, **k: 0.01),
        SimpleNamespace(name="Gradient Boosting", predict=lambda *a, **k: 0.01),
        SimpleNamespace(name="DBSCAN", predict=lambda *a, **k: 0.99),
        SimpleNamespace(name="Adaptive Baseline", predict=lambda *a, **k: 0.01),
    ]
    verdicts = detect_flows([flow], fakes, Settings(), ModelConfig(),
                            eligible={"DBSCAN": False})
    assert verdicts, "the structural signature must survive DBSCAN ineligibility"
    assert verdicts[0]["signature"] is True
    assert verdicts[0]["dbscan_score"] == 0.99
