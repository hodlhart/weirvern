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
    STATE_CALIBRATING,
    STATE_ELIGIBLE,
    STATE_HELD,
    STATE_NOT_ELIGIBLE,
    Decision,
    Rate,
    evaluate,
    evidence_from_row,
    promotion_plan,
)

# One calibration row, in the shape `calibration._calibration_rows` hands to the evidence rule.
# `validation_count` is the denominator the interval is computed on; 2,000 is comfortably above
# the 300-window floor, so these fixtures exercise the FAR rule rather than the calibrating state.
FRESH = {"observed_far": 0.0, "target_far": 0.01, "coverage": 0.83,
         "coverage_observed": 16, "coverage_expected": 19, "age_hours": 0.5,
         "validation_count": 2000, "threshold": 0.86}


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


def test_eligibility_reads_each_detectors_newest_row_not_the_newest_batch():
    """A detector skipped by the latest pass must be judged STALE, not absent.

    MEASURED 2026-11-21: the calibration pass could build no population for KNN/LOF under the
    running version, so it wrote rows only for the other three. `_calibration_rows` selected
    `computed_at = (SELECT max(computed_at) ...)`, which made KNN/LOF read "no calibration row"
    -- the same answer as a detector that had never been calibrated -- even though each held a
    row from 17:49. The remedy differs (wait for population vs. look for a broken detector), so
    the query now takes the newest row PER MODEL and lets the freshness check refuse it.
    """
    from weirvern.models import eligibility as module

    class _Result:
        result_rows = [
            ("Isolation Forest", 0.0103, 0.01, 0.9, 69, 77, "2026-11-21 11:24:00", 1.0, 9000, 0.8),
            ("LOF", 0.0, 0.01, 0.8, 15, 19, "2026-11-20 17:49:38", 18.2, 12, 0.7),
        ]

    class _Client:
        def __init__(self):
            self.sql = ""

        def query(self, sql, parameters=None):  # noqa: ANN001, ANN201
            self.sql = sql
            return _Result()

    client = _Client()
    rows = module._calibration_rows(client)
    assert set(rows) == {"Isolation Forest", "LOF"}, (
        "the older LOF row must be read, so freshness -- not absence -- is the finding")
    assert "LIMIT 1 BY model_name" in client.sql
    assert "computed_at = (SELECT max(computed_at)" not in client.sql


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
    # 4% at n=4000 has a Wilson upper bound of 4.6%, inside the 5% tolerance: the test is the
    # multiple, not a lucky sample. (At n=1000 the same rate's upper bound is 5.5% and the
    # interval rule would -- correctly -- refuse to call it within 5%.)
    ev = evidence_from_row("LOF", {**FRESH, "observed_far": 0.04, "validation_count": 4000},
                           target_far=0.01, multiple=5.0,
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
              "age_hours": 0.5, "validation_count": 2000, "threshold": 0.86, **over}
    # AGE IS IN HOURS, the unit `_calibration_rows` reads (the SQL alias is `age_hours`).
    # Converting it back to seconds here is what let a 60h fixture look fresh.
    return (name, values["observed_far"], values["target_far"], values["coverage"],
            values["coverage_observed"], values["coverage_expected"], values["computed_at"],
            float(values["age_hours"]), values["validation_count"], values["threshold"])


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


# ── the sample floor and the interval: a FAR estimate must be able to answer ──────────────────

def test_a_110_window_far_reading_cannot_bench_a_detector(tmp_path):
    """THE LIVE FLIP-FLOP, pinned: the same detector read 0.000 and 0.045 seven minutes apart.

    5/110 has a 95% interval of roughly 2%-10%; it cannot separate the 1% target from the 3%
    tolerance, so it must not change the detector's state. The detector was eligible and stays
    eligible, with the sample and the shortfall named in its sentence.
    """
    settings = Settings(model_dir=str(tmp_path), ml_fused_budget_min_windows=1)
    first = _Client(calibration=[_cal("KNN distance")], rates={"row": (500, 120, 100)})
    before = evaluate(first, settings, names=["KNN distance"], persist=True)
    assert before.decisions["KNN distance"].state == STATE_ELIGIBLE

    # Seven minutes later the same detector reads five exceedances in 110 validation windows.
    noisy = _Client(calibration=[_cal("KNN distance", observed_far=5 / 110,
                                      validation_count=110)])
    after = evaluate(noisy, settings, names=["KNN distance"], persist=True)
    decision = after.decisions["KNN distance"]
    assert decision.calibrating is True
    assert decision.state == STATE_ELIGIBLE, "an unjudgeable sample benched a working detector"
    assert decision.contributing is True
    assert "n=110" in decision.sentence() and "need 300" in decision.sentence()
    # Its calibrated scale is still the one it earned; the gap did not erase it.
    assert after.thresholds["KNN distance"] == 0.86


def test_a_detector_with_no_held_state_is_calibrating_not_failed():
    ev = _evidence(observed_far=5 / 110, validation_count=110)
    assert ev.calibrating is True and ev.calibrated is False
    assert "calibrating (n=110, need 300)" in ev.reason
    assert "FAR 0.045" in ev.reason, "the rate is still reported -- beside its sample"
    assert ev.far_upper is not None and ev.far_upper > 0.09


def test_a_genuinely_bad_far_on_a_large_sample_still_benches_it():
    """The rule must still be able to say NO: 9% at n=2,000 has an upper bound near 10%."""
    ev = _evidence(observed_far=0.09, validation_count=2000)
    assert ev.calibrated is False and ev.calibrating is False
    assert "95% CI" in ev.reason and "n=2000" in ev.reason
    assert "0.030 tolerance" in ev.reason and "3 x 0.010 target" in ev.reason


def test_a_far_is_never_sentenced_without_its_sample_size():
    """Every FAR sentence carries n and its interval; the fused summary carries them too."""
    from weirvern.models.detector_status import detector_summary

    ev = _evidence(observed_far=0.09, validation_count=2000)
    failed = Decision(name="LOF", state=STATE_NOT_ELIGIBLE, evidence=ev, reason=ev.reason)
    assert "n=2000" in failed.sentence() and "95% CI" in failed.sentence()
    assert "0.090" in failed.sentence()

    cal = _evidence(observed_far=5 / 110, validation_count=110)
    waiting = Decision(name="LOF", state=STATE_CALIBRATING, evidence=cal,
                       calibrating=True, reason=cal.reason)
    assert "n=110" in waiting.sentence() and "need 300" in waiting.sentence()

    summary = detector_summary(
        [{"name": "LOF", "contributing": False, "status": waiting.sentence()}],
        {"observed_far": 0.045, "target_far": 0.01, "validation_count": 110,
         "far_lower": 0.020, "far_upper": 0.102})
    assert "n=110" in summary and "95% CI 0.020-0.102" in summary


def test_a_calibrating_incumbent_is_still_counted_as_a_budget_member(tmp_path):
    """A candidate must be measured against the detector that is in the fused set right now."""
    settings = Settings(model_dir=str(tmp_path), ml_fused_budget_min_windows=1)
    first = _Client(calibration=[_cal("KNN distance")], rates={"row": (500, 120, 100)})
    evaluate(first, settings, names=["KNN distance"], persist=True)

    class _BudgetClient(_Client):
        def __init__(self, **kwargs):
            super().__init__(**kwargs)
            self.sql: list[str] = []

        def query(self, sql, parameters=None):
            if "ml_window_scores" in sql:
                self.sql.append(sql)
            return super().query(sql, parameters)

    second = _BudgetClient(
        calibration=[_cal("KNN distance", observed_far=5 / 110, validation_count=110),
                     _cal("LOF", validation_count=2000, threshold=0.89)],
        rates={"row": (500, 130, 120)})
    report = evaluate(second, settings, names=["KNN distance", "LOF"])
    assert report.decisions["KNN distance"].state == STATE_ELIGIBLE
    assert second.sql, "the candidate's rate was never measured"
    # LOF was measured against KNN (the calibrating incumbent), not against an empty set.
    assert "KNN distance" in second.sql[0] and "LOF" in second.sql[0]
    assert report.decisions["LOF"].state == STATE_ELIGIBLE
