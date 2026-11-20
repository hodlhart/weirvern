"""The alert bar must be the number the budget chose, and an excluded model must stay out.

Two changes, both measured before they were made.

THE FUSED SCORE COULD NOT BE CALIBRATED. `max` fusion over the Isolation Forest and the Gradient
Boosting student inherited the student's point mass: 3.04% of windows sit within 0.001 of 0.99, and
the student equals the fused maximum on 69.6% of them. A conformal threshold therefore returned
0.9900 for every target from 1% to 0.2%, so the budget stopped controlling the alert count, which is
the only thing a conformal calibrator is for. The student is now excluded from the fusion by name.

THE CALIBRATION NEVER REACHED THE DECISION. The calibrated threshold was 0.8556 while the decision
applied 0.20 to 0.35, so the measured false-alarm rate described a bar nothing alerted at. The
decision now takes the calibrated threshold for the FUSED score when one exists.

Both are rails with an off switch, and the tests below pin the switches as well as the behaviour.
"""

from __future__ import annotations

from types import SimpleNamespace

from weirvern.config import FUSED_MODEL, ModelConfig, Settings
from weirvern.ensemble import calibrated_scores, detect_flows, fuse_scores, fusion_excluded
from weirvern.models import calibration


def _fixed(value):
    """A predict that always returns `value`.

    Bound through a factory rather than a bare lambda in a comprehension, because a lambda defined
    inside a loop captures the loop variable: if two detectors disagreed, both would end up returning
    the last score. ruff's B023 is pointing at a real bug in a test that would then pass while
    measuring nothing.
    """
    def predict(*_a, **_k):
        return value
    return predict


def _det(**scores) -> list:
    """Detectors that return a fixed score each, named as the ensemble names them."""
    return [SimpleNamespace(name=name.replace("_", " "), predict=_fixed(value))
            for name, value in scores.items()]


FLOW = {
    "src_addr": "198.51.100.10",
    "window_start": "2026-11-13 20:00:00",
    "window_end": "2026-11-13 20:05:00",
    "flow_count": 60,          # comfortably above the thin-window floor, so no damping
    "total_bytes": 900_000,
    "unique_dst_ips": 8,
}


def _run(detectors, settings=None, **kwargs):
    settings = settings or Settings()
    return detect_flows([dict(FLOW)], detectors, settings, ModelConfig(), **kwargs)


# ── the fusion exclusion ───────────────────────────────────────────────────────────────────

def test_the_student_is_excluded_by_default_and_the_rail_can_be_switched_off():
    assert fusion_excluded(Settings()) == {"Gradient Boosting"}
    assert fusion_excluded(Settings(ml_fusion_exclude="")) == set()


def test_an_excluded_model_cannot_set_the_fused_score():
    """The student at 0.99 must not carry the window; the Isolation Forest's 0.40 must."""
    verdicts = _run(_det(Isolation_Forest=0.40, Gradient_Boosting=0.99))
    assert len(verdicts) == 1
    assert verdicts[0]["anomaly_score"] == 0.40, (
        f"the excluded student set the score: {verdicts[0]['anomaly_score']}"
    )
    # It is still named as evidence: exclusion is about the score, not about hiding the fact.
    assert "Gradient Boosting" in verdicts[0]["detected_by_models"]


def test_the_old_fusion_is_reachable_by_clearing_the_rail():
    """Without an off switch this would be an irreversible behaviour change, not a rail."""
    verdicts = _run(_det(Isolation_Forest=0.40, Gradient_Boosting=0.99),
                    settings=Settings(ml_fusion_exclude=""))
    assert verdicts[0]["anomaly_score"] == 0.99


def test_an_excluded_model_cannot_come_back_through_the_signature_exception():
    """THE DOCUMENTED PITFALL: an exception path reading RAW scores re-admits what a rail removed.

    A pure SYN scan is the case that exercises it: the structural signature fires, and the restore
    takes the strongest raw score. That restore must skip the excluded model, or the exclusion only
    applies to the fused path and the score is still set by the model we removed.
    """
    scan = dict(FLOW, flow_count=305, total_bytes=0, unique_dst_ips=1,
                _diversity={"unique_dst_ports": 300, "port_entropy": 5.0})
    settings = Settings()
    verdicts = detect_flows([scan], _det(Isolation_Forest=0.01, Gradient_Boosting=0.99),
                            settings, ModelConfig())
    if verdicts:
        assert verdicts[0]["anomaly_score"] != 0.99, (
            "the excluded student came back through the signature restore"
        )


def test_an_ELIGIBILITY_barred_model_may_still_alert_by_signature():
    """Deliberately unchanged: eligibility bars a model for budget reasons, and the barred model may
    be the only one that saw the scan. This asserts the exclusion rail did not break that."""
    scan = dict(FLOW, flow_count=305, total_bytes=0, unique_dst_ips=1,
                _diversity={"unique_dst_ports": 300, "port_entropy": 5.0})
    verdicts = detect_flows(
        [scan], _det(Isolation_Forest=0.01, Gradient_Boosting=0.01, DBSCAN=0.99),
        Settings(), ModelConfig(), eligible={"DBSCAN": False})
    assert verdicts, "an ineligible model's structural signature no longer alerts"
    assert verdicts[0]["anomaly_score"] >= 0.95


# ── the calibrated bar ────────────────────────────────────────────────────────────────────
#
# ASSERTED ON `near_misses.threshold_used`, deliberately. A near miss is recorded in the branch where
# the score was compared with the bar, BEFORE the agreement gate, so it isolates "which threshold was
# applied" from "did enough models agree". Testing the bar through verdicts would conflate the two and
# a failure would not say which of them moved.

def _threshold_used(**kwargs) -> float | None:
    near: list[dict] = []
    _run(_det(Isolation_Forest=0.55), near_misses=near, **kwargs)
    return near[0]["threshold_used"] if near else None


def test_the_base_threshold_is_used_when_there_is_no_calibration():
    assert _threshold_used() == 0.35


def test_a_calibrated_bar_replaces_the_base_threshold_verbatim():
    """No per-window reduction is applied on top of it: the budget IS the bar."""
    assert _threshold_used(calibrated_bar=0.60) == 0.60


def test_a_calibrated_bar_below_the_base_threshold_is_honoured_too():
    assert _threshold_used(calibrated_bar=0.25) == 0.25


def test_the_adaptive_reduction_does_not_run_on_a_calibrated_bar():
    """The adaptation lowers the bar for scan-shaped windows. Applied on top of a calibrated
    threshold it would spend a budget nobody chose, which is how the measured false-alarm rate came
    to describe a bar nothing alerted at."""
    scan = dict(FLOW, flow_count=305, total_bytes=0, unique_dst_ips=1)

    near: list[dict] = []
    detect_flows([scan], _det(Isolation_Forest=0.55), Settings(), ModelConfig(), near_misses=near)
    assert near and near[0]["threshold_used"] < 0.35, (
        "the adaptive reduction should lower the bar for a scan-shaped window"
    )

    near2: list[dict] = []
    detect_flows([scan], _det(Isolation_Forest=0.55), Settings(), ModelConfig(),
                 near_misses=near2, calibrated_bar=0.60)
    assert near2 and near2[0]["threshold_used"] == 0.60, (
        "the adaptive reduction was applied on top of a calibrated bar"
    )


def test_the_fused_score_is_recorded_so_it_can_be_calibrated_at_all():
    population: list[dict] = []
    _run(_det(Isolation_Forest=0.40, Gradient_Boosting=0.99), score_population=population)
    assert population, "nothing was recorded"
    scores = population[0]["scores"]
    assert FUSED_MODEL in scores, (
        f"the score the decision compares is missing from the population: {scores}"
    )
    assert scores[FUSED_MODEL] == 0.40, "the recorded fused score is not the one the decision used"


# ── reading the bar back ─────────────────────────────────────────────────────────────────

class _Res:
    def __init__(self, rows):
        self.result_rows = rows


class _Client:
    def __init__(self, rows):
        self.rows = rows
        self.seen = None

    def query(self, sql, parameters=None):
        self.seen = parameters
        return _Res(self.rows)


def test_a_usable_calibration_is_returned_as_the_bar():
    client = _Client([(0.7327, "all scored host-windows")])
    assert calibration.calibrated_bar(client, Settings()) == 0.7327
    assert client.seen["m"] == FUSED_MODEL


def test_a_SATURATED_calibration_is_refused_rather_than_used():
    """A bar at the reference ceiling cannot be crossed: using it would silence the engine while
    reporting a met budget, which is the failure this project keeps rediscovering."""
    client = _Client([(0.99, "the fused score itself; SATURATED at the reference ceiling (0.99)")])
    assert calibration.calibrated_bar(client, Settings()) is None


def test_no_usable_row_means_no_bar_rather_than_a_guess():
    assert calibration.calibrated_bar(_Client([]), Settings()) is None
    assert calibration.calibrated_bar(_Client([(float("nan"), "x")]), Settings()) is None
    assert calibration.calibrated_bar(_Client([(0.0, "x")]), Settings()) is None


def test_the_fused_score_is_never_treated_as_a_detector_for_eligibility():
    """It is the decision's own number; judging it would make the promotion gate circular."""
    from weirvern.models.eligibility import evaluate

    class _Client:
        def query(self, sql, parameters=None):  # noqa: ANN001, ANN201
            if "ml_calibration" in sql and "dateDiff" in sql:
                return type("R", (), {"result_rows": [
                    (FUSED_MODEL, 0.99, 0.01, 0.9, 17, 19, "2026-11-19 08:21:17", 60, 2000, 0.9)]})()
            return type("R", (), {"result_rows": []})()

    report = evaluate(_Client(), Settings(model_dir=""))
    assert FUSED_MODEL not in report.decisions


# ── the calibrated scale: 0.35 means the same thing with 1, 2 or 5 members ────────────────────
#
# BEFORE: `max` over raw scores. With KNN alone, 0.35 was a raw score it exceeded on 79.2% of
# windows (its own 1% threshold sat at 0.962); with five members the same 0.35 was a different
# quantile of a different distribution. The bar changed meaning whenever the membership changed.
# AFTER: each detector's own conformal threshold maps onto 0.35, so the bar is a position inside
# every member's measured tail rather than a raw number.

def test_a_single_detector_score_is_comparable_to_a_multi_detector_one():
    bar = Settings().base_threshold
    thresholds = {"KNN distance": 0.962, "Isolation Forest": 0.85, "LOF": 0.89}
    one = calibrated_scores({"KNN distance": 0.962}, thresholds, bar)
    many = calibrated_scores(
        {"KNN distance": 0.10, "Isolation Forest": 0.85, "LOF": 0.20}, thresholds, bar)
    # Each detector AT its own calibrated threshold lands exactly on the shared bar...
    assert one["KNN distance"] == many["Isolation Forest"] == bar
    assert fuse_scores(one) == fuse_scores(many) == bar
    # ...and the same raw KNN score is the same number whether it is alone or one of five.
    alone = calibrated_scores({"KNN distance": 0.48}, thresholds, bar)
    together = calibrated_scores(
        {"KNN distance": 0.48, "Isolation Forest": 0.1, "LOF": 0.2}, thresholds, bar)
    assert alone["KNN distance"] == together["KNN distance"]


def test_the_same_score_is_judged_the_same_way_with_one_or_five_members():
    """The near-miss record is written at the comparison, before the agreement gate."""
    thresholds = {"KNN distance": 0.962, "Isolation Forest": 0.85, "LOF": 0.89,
                  "Adaptive Baseline": 0.375}
    one: list[dict] = []
    _run(_det(KNN_distance=0.90), near_misses=one, thresholds=thresholds)
    five: list[dict] = []
    _run(_det(Isolation_Forest=0.20, Gradient_Boosting=0.01, KNN_distance=0.90,
              LOF=0.10, Adaptive_Baseline=0.0),
         near_misses=five, thresholds=thresholds)
    assert one and five, "both windows should be near misses at the calibrated bar"
    assert one[0]["anomaly_score"] == five[0]["anomaly_score"] == 0.90
    assert one[0]["threshold_used"] == five[0]["threshold_used"] == 0.962
