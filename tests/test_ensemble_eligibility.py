"""Eligibility is measured evidence, and a promotion must fit a measured alert budget.

WHY THESE TESTS EXIST. Eligibility used to be answered from `ml_model_cards`, a hand-curated
registry that went stale and, on 2026-11-20, had no row at all for the two cross-sectional
detectors -- so they were barred by ABSENCE while their calibration rows said they were within
budget. The replacement has two halves, and both are pinned here:

  * EVIDENCE -- fresh calibration, recorded coverage, realised FAR inside the configured multiple.
    Each failing check names itself, so the table sends an operator to the right remedy.
  * THE PROMOTION GUARD -- being calibrated is not the same as being safe to add. Measured on the
    live day, admitting both cross-sectional detectors took the share of windows at or above
    BASE_THRESHOLD from 25.6% to 42.8%. A promotion that does that is held, with both rates shown,
    and is promoted by itself once the rate fits.
"""
from __future__ import annotations

from types import SimpleNamespace

from weirvern.config import ModelConfig, Settings
from weirvern.ensemble import MODEL_FAMILIES, contributing_scores, detect_flows, fuse_scores
from weirvern.models.eligibility import (
    STATE_ELIGIBLE,
    STATE_HELD,
    STATE_NOT_ELIGIBLE,
    Rate,
    evaluate,
    evidence_from_row,
    promotion_plan,
)

# One calibration row, in the shape `calibration._calibration_rows` hands to the evidence rule.
FRESH = {"observed_far": 0.0, "target_far": 0.01, "coverage": 0.83,
         "coverage_observed": 16, "coverage_expected": 19, "age_hours": 0.5}


def _evidence(name: str = "KNN distance", **overrides):
    row = {**FRESH, **overrides}
    return evidence_from_row(name, row, target_far=0.01, multiple=3.0,
                             retrain_every_h=6.0, grace_h=1.0)


# ── the evidence rule ────────────────────────────────────────────────────────────────────────

def test_a_fresh_measured_calibration_with_coverage_is_eligible():
    ev = _evidence()
    assert ev.calibrated is True
    assert ev.reason == ""
    assert ev.age_hours == 0.5
    assert ev.coverage == 0.83
    assert ev.tolerance == 0.03


def test_no_calibration_row_is_refused_with_that_reason():
    ev = evidence_from_row("LOF", None, target_far=0.01, multiple=3.0, retrain_every_h=6.0)
    assert ev.calibrated is False
    assert ev.reason == "no calibration row"


def test_a_calibration_older_than_the_retrain_interval_is_stale_not_eligible():
    ev = _evidence(age_hours=9.0)
    assert ev.calibrated is False
    assert "calibration stale" in ev.reason
    assert "9.0h" in ev.reason and "6h retrain interval" in ev.reason


def test_null_coverage_is_never_eligible():
    """An unmeasured vector is not evidence about the detector -- NULL is not 100%."""
    ev = _evidence(coverage=None, coverage_observed=None, coverage_expected=None)
    assert ev.calibrated is False
    assert ev.reason == "coverage not recorded"


def test_a_coverage_ratio_without_its_counts_is_still_unrecorded():
    """Schema 058 stores the counts; a row with only the ratio cannot be audited."""
    ev = _evidence(coverage=0.8, coverage_observed=None, coverage_expected=None)
    assert ev.calibrated is False
    assert ev.reason == "coverage not recorded"


def test_coverage_below_the_floor_is_insufficient_telemetry():
    ev = _evidence(coverage=0.05, coverage_observed=1, coverage_expected=19)
    assert ev.calibrated is False
    assert "below the 0.15 floor" in ev.reason


def test_a_far_over_the_configured_multiple_names_both_numbers():
    ev = _evidence(observed_far=0.0833)
    assert ev.calibrated is False
    assert "FAR 0.083" in ev.reason and "0.030 tolerance" in ev.reason
    assert "3 x 0.010 target" in ev.reason


def test_the_tolerance_is_target_times_multiple_not_a_constant():
    """ML_ELIGIBILITY_MULTIPLE is a setting; 3x is not baked into the rule."""
    ev = evidence_from_row("LOF", {**FRESH, "observed_far": 0.04}, target_far=0.01, multiple=5.0,
                           retrain_every_h=6.0, grace_h=1.0)
    assert ev.calibrated is True and ev.tolerance == 0.05


# ── the promotion guard ─────────────────────────────────────────────────────────────────────

def test_a_calibrated_detector_over_the_alert_budget_is_held_with_both_rates():
    """The measured live case: 25.6% without it, 42.8% with it, budget 30%."""
    def measure(members, candidate):
        return Rate(windows=1000, without_hits=256, with_hits=428)
    plan = promotion_plan([_evidence("LOF")], [], measure, budget=0.30, min_windows=200)
    decision = plan["LOF"]
    assert decision.state == STATE_HELD
    assert decision.rate_with == 0.428 and decision.rate_without == 0.256
    assert decision.sentence() == (
        "calibrated, held for budget (fused 42.8% with it vs 25.6% without; budget 30.0%)")


def test_a_calibrated_detector_inside_the_budget_is_promoted_without_a_human():
    """No approval step, no stored flag: the measurement is the whole decision."""
    def measure(members, candidate):
        return Rate(windows=1000, without_hits=100, with_hits=120)
    plan = promotion_plan([_evidence("LOF")], [], measure, budget=0.30, min_windows=200)
    assert plan["LOF"].state == STATE_ELIGIBLE
    assert plan["LOF"].sentence() == "eligible"


def test_an_incumbent_is_never_demoted_by_the_budget():
    """A working detector is not a budget casualty: the guard governs promotions only."""
    def measure(members, candidate):
        return Rate(windows=1000, without_hits=320, with_hits=600)
    plan = promotion_plan(
        [_evidence("Isolation Forest"), _evidence("LOF")], ["Isolation Forest"], measure,
        budget=0.30, min_windows=200)
    assert plan["Isolation Forest"].state == STATE_ELIGIBLE
    assert plan["LOF"].state == STATE_HELD


def test_a_promotion_under_budget_needs_a_population_behind_it():
    """Under budget on a handful of windows is not proof; the hold says how many it needs."""
    def measure(members, candidate):
        return Rate(windows=25, without_hits=5, with_hits=6)
    plan = promotion_plan([_evidence("LOF")], [], measure, budget=0.30, min_windows=200)
    decision = plan["LOF"]
    assert decision.state == STATE_HELD
    assert "budget not measurable yet" in decision.reason
    assert "25 scored windows" in decision.reason and "200 needed" in decision.reason


def test_the_cheapest_candidate_is_promoted_first_when_only_one_fits():
    """Greedy by measured cost: the budget admits as many detectors as it can."""
    rates = {
        (frozenset(), "quiet"): Rate(1000, 200, 210),
        (frozenset(), "loud"): Rate(1000, 200, 600),
        (frozenset({"quiet"}), "loud"): Rate(1000, 210, 600),
    }
    plan = promotion_plan(
        [_evidence("quiet"), _evidence("loud")], [],
        lambda members, candidate: rates[(frozenset(members), candidate)],
        budget=0.30, min_windows=200)
    assert plan["quiet"].state == STATE_ELIGIBLE
    assert plan["loud"].state == STATE_HELD


def test_an_unmeasurable_candidate_is_held_rather_than_assumed_safe():
    plan = promotion_plan([_evidence("LOF")], [], lambda m, c: None, budget=0.30,
                          min_windows=200)
    assert plan["LOF"].state == STATE_HELD
    assert "could not be measured" in plan["LOF"].reason


# ── the composition the engine and the table both call ──────────────────────────────────────

class _Client:
    """Answers the two reads `evaluate` makes; the guard is stubbed through the rate query."""

    def __init__(self, *, cards=None, rates=None, calibration=None):
        self.cards = cards or []
        self.rates = rates or {}
        self.calibration = calibration or []

    def query(self, sql, parameters=None):  # noqa: ANN001, ANN201
        if "ml_model_cards" in sql:
            columns = ("model_id", "model_name", "version", "artifact_hash",
                       "training_window_start", "training_window_end", "feature_version",
                       "calibration_version", "eval_report_id", "status", "owner", "approved_by",
                       "approved_at", "rollback_ref", "intended_use", "out_of_scope",
                       "known_limitations", "updated_at")
            return SimpleNamespace(result_rows=[
                tuple(row.get(c) for c in columns) for row in self.cards])
        if "ml_window_scores" in sql:
            return SimpleNamespace(result_rows=[self.rates.get("row", (0, 0, 0))])
        if "ml_calibration" in sql:
            return SimpleNamespace(result_rows=self.calibration)
        if "ml_models" in sql:
            return SimpleNamespace(result_rows=[])
        return SimpleNamespace(result_rows=[])


def _cal(name, **over):
    values = {"observed_far": 0.0, "target_far": 0.01, "coverage": 0.83,
              "coverage_observed": 16, "coverage_expected": 19, "computed_at": None,
              "age_hours": 0.5, **over}
    # AGE IS IN HOURS, the unit `_calibration_rows` reads (the SQL alias is `age_hours`).
    # Converting it back to seconds here is what let a 60h fixture look fresh.
    return (name, values["observed_far"], values["target_far"], values["coverage"],
            values["coverage_observed"], values["coverage_expected"], values["computed_at"],
            float(values["age_hours"]))


def test_the_card_registry_no_longer_vetoes_a_calibrated_detector(tmp_path, monkeypatch):
    """A detector with NO card at all used to be barred by absence. It is not any more."""
    settings = Settings(model_dir=str(tmp_path), ml_fused_budget_min_windows=1)
    client = _Client(calibration=[_cal("LOF")], rates={"row": (500, 120, 100)})
    report = evaluate(client, settings, names=["LOF"])
    assert report.decisions["LOF"].state == STATE_ELIGIBLE
    # AND IT WAS MEASURED, NOT SEEDED. An empty registry must not blanket-admit every detector:
    # if LOF had been seeded as an incumbent the budget query would never run and windows would
    # stay 0. This is the guard's contract ("an unreadable registry seeds nothing"), pinned.
    assert report.windows == 500, "no card is not an incumbent seed: the budget was measured"


def test_with_no_recorded_state_the_card_registry_seeds_only_the_migration(tmp_path):
    """The OLD gate's admitted set is the first incumbent set, once -- never a live veto."""
    settings = Settings(model_dir=str(tmp_path), ml_fused_budget_min_windows=1)
    client = _Client(
        calibration=[_cal("Isolation Forest"), _cal("LOF")],
        cards=[{"model_name": "Isolation Forest", "status": "production"}],
        rates={"row": (500, 420, 300)},
    )
    report = evaluate(client, settings, names=["Isolation Forest", "LOF"])
    assert report.seeded is True
    # IF was admitted by the old gate, so it is an incumbent; LOF was not, so it faces the budget
    # and is held by the measured rate.
    assert report.decisions["Isolation Forest"].state == STATE_ELIGIBLE
    assert report.decisions["LOF"].state == STATE_HELD


def test_a_stale_detector_is_not_contributing_even_if_it_was_an_incumbent(tmp_path):
    settings = Settings(model_dir=str(tmp_path), ml_fused_budget_min_windows=1)
    client = _Client(calibration=[_cal("LOF", age_hours=30.0)], rates={"row": (500, 1, 1)})
    report = evaluate(client, settings, names=["LOF"])
    assert report.decisions["LOF"].state == STATE_NOT_ELIGIBLE
    assert "calibration stale" in report.decisions["LOF"].reason


def test_a_held_detector_is_promoted_by_the_next_evaluation_once_the_rate_fits(tmp_path):
    """AUTOMATIC: no approval, no stored flag, no human. The next measurement decides.

    The first sweep sees the measured overrun and records `held for budget`; the second sees a rate
    inside the budget -- the case the operator described as "after the other members recalibrate" --
    and promotes it by itself.
    """
    settings = Settings(model_dir=str(tmp_path), ml_fused_budget_min_windows=1)
    names = ["Isolation Forest", "LOF"]
    cards = [{"model_name": "Isolation Forest", "status": "production"}]

    held_client = _Client(calibration=[_cal("Isolation Forest"), _cal("LOF")], cards=cards,
                          rates={"row": (1000, 428, 256)})
    first = evaluate(held_client, settings, names=names, persist=True)
    assert first.decisions["LOF"].state == STATE_HELD
    assert first.decisions["LOF"].rate_with == 0.428

    fitting_client = _Client(calibration=[_cal("Isolation Forest"), _cal("LOF")], cards=cards,
                             rates={"row": (1000, 120, 100)})
    second = evaluate(fitting_client, settings, names=names, persist=True)
    assert second.seeded is False, "the recorded state replaced the migration seed"
    assert second.decisions["LOF"].state == STATE_ELIGIBLE
    assert second.decisions["LOF"].sentence() == "eligible"


def test_the_alert_budget_and_its_window_are_settings():
    settings = Settings()
    assert settings.ml_fused_alert_budget == 0.30, "the measured 25.6% baseline plus headroom"
    assert settings.ml_fused_budget_min_windows == 200
    assert settings.ml_fused_budget_hours == 24
    assert settings.ml_calibration_grace_h == 1.0


def test_the_fusion_mapping_carries_only_contributors_and_absent_means_out():
    scores = {"KNN distance": 0.99, "Isolation Forest": 0.20, "LOF": 0.10}
    contributing = contributing_scores(scores, {"KNN distance": False, "Isolation Forest": True,
                                                "LOF": False})
    assert "KNN distance" not in contributing, "an ineligible model must not enter fusion"
    assert fuse_scores(contributing) == 0.20
    # Evidence still carries the raw score.
    assert scores["KNN distance"] == 0.99
    assert contributing_scores({"KNN distance": 0.99}, {})["KNN distance"] == 0.99


# ── the two cross-sectional detectors stay independent ──────────────────────────────────────

def test_knn_and_lof_are_separate_families_and_separate_models():
    assert MODEL_FAMILIES["KNN distance"] != MODEL_FAMILIES["LOF"]
    from weirvern.models.detectors import KNNDistanceDetector, LOFDetector

    assert KNNDistanceDetector.name == "KNN distance"
    assert LOFDetector.name == "LOF"
    assert "KNN distance" in MODEL_FAMILIES and "LOF" in MODEL_FAMILIES
    assert "DBSCAN" not in MODEL_FAMILIES


def test_an_ineligible_cross_sectional_detector_still_allows_a_structural_signature():
    # A pure SYN scan: no bytes, many ports. The distance models see it; the volume models do not.
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
        SimpleNamespace(name="KNN distance", predict=lambda *a, **k: 0.99),
        SimpleNamespace(name="LOF", predict=lambda *a, **k: 0.01),
        SimpleNamespace(name="Adaptive Baseline", predict=lambda *a, **k: 0.01),
    ]
    verdicts = detect_flows([flow], fakes, Settings(), ModelConfig(),
                            eligible={"KNN distance": False})
    assert verdicts, "the structural signature must survive KNN ineligibility"
    assert verdicts[0]["signature"] is True
