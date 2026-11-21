"""The Detectors table: status derived from measured evidence, never from a stored card value.

WHY IT IS DERIVED. The table used to answer "is this detector contributing?" from
`ml_model_cards.status`, a curated snapshot that goes stale the moment the engine retrains -- and,
on 2026-11-20, had no row at all for the two cross-sectional detectors, so it barred them by
ABSENCE. A card is documentation of intent now: it cannot veto a detector.

THE ROWS SAY ONE OF FOUR THINGS, each with its own remedy:
  * `eligible` -- fresh calibration, recorded coverage, FAR inside tolerance, inside the budget;
  * `not contributing: <the failing measurement>` -- and the failing measurement is named;
  * `calibrated, held for budget (fused X% with it vs Y% without; budget Z%)` -- wait for the rate;
  * `not trained` / `not trained: degenerate reference` -- there is no model to measure.

The derivation is pure, so every case below runs without a ClickHouse. The last tests are the
seams the jsdom harness cannot see: the ids and the header/row widths must agree between the markup
and the script, and a removed detector must have no row at all.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from weirvern.models.detector_status import detector_rows, detector_summary
from weirvern.models.eligibility import STATE_HELD, Decision, Evidence

WEB = Path(__file__).resolve().parents[1] / "weirvern" / "admin" / "web"
TODAY = "2026-11-19 08:21:17"
WRITTEN = "2026-11-19T08:22:00+00:00"


def _rows(*, observed: float | None = 1.0, target: float | None = 0.01,
          trained: bool = True, name: str = "KNN distance",
          coverage: float | None = 0.83, coverage_observed: int | None = 16,
          coverage_expected: int | None = 19, age_hours: float = 0.5,
          validation_count: int = 2000, threshold: float = 0.86,
          decisions: dict | None = None) -> list[dict]:
    """One detector's row, with each evidence source switched on or off independently."""
    training = {name: {"trained_at": TODAY, "samples": 5000}} if trained else {}
    artifacts = {name: {"version": "v5", "written_at": WRITTEN}} if trained else {}
    calibration = ({name: {"observed_far": observed, "target_far": target,
                           "coverage": coverage, "coverage_observed": coverage_observed,
                           "coverage_expected": coverage_expected,
                           "age_hours": age_hours, "validation_count": validation_count,
                           "threshold": threshold}}
                   if observed is not None else {})
    return detector_rows(training, artifacts, calibration, decisions=decisions)


def test_a_trained_detector_over_its_far_budget_is_not_contributing() -> None:
    """A live detector trained today, measured 1.00 against a 0.01 target."""
    row = _rows()[0]
    assert row["status"].startswith("not contributing: FAR 1.000")
    assert "0.030 tolerance" in row["status"]
    assert row["contributing"] is False
    assert row["eligible"] is False


def test_a_detector_within_its_budget_is_eligible() -> None:
    row = _rows(observed=0.0)[0]
    assert row["eligible"] is True
    assert row["contributing"] is True
    assert row["status"] == "eligible"


def test_a_detector_with_no_calibration_row_fails_closed() -> None:
    """An unmeasured false-alarm rate is not a met budget."""
    row = _rows(observed=None)[0]
    assert row["eligible"] is False
    assert row["contributing"] is False
    assert row["status"] == "not contributing: no calibration row"
    # NO NUMBER, because there was no measurement to quote.
    assert not re.search(r"\d\.\d\d", row["status"])


def test_a_stored_card_status_is_not_consulted_at_all() -> None:
    """The old veto is gone: `detector_rows` no longer takes a card map, so it cannot bar one.

    A card saying `retired` is documentation of an old decision. The engine's measurements are the
    authority, and this call has no way to read the card at all.
    """
    row = _rows(observed=0.0)[0]
    assert row["status"] == "eligible"
    assert "retired" not in json.dumps(row).lower()
    assert "barred" not in row


def test_a_detector_with_no_training_and_no_artifact_is_not_trained() -> None:
    # The name is still known (a calibration row exists), but the engine has left no training
    # record and no artifact, so there is nothing to contribute.
    row = _rows(observed=0.0, trained=False)[0]
    assert row["status"] == "not trained"
    assert row["contributing"] is False


def test_a_calibrated_detector_held_for_budget_shows_both_rates() -> None:
    """The promotion guard's wording, verbatim: what it would do, what it does without it."""
    decision = Decision(name="LOF", state=STATE_HELD, windows=1000,
                        rate_without=0.256, rate_with=0.428, budget=0.30,
                        evidence=Evidence(name="LOF", calibrated=True))
    row = _rows(name="LOF", observed=0.0, decisions={"LOF": decision})[0]
    assert row["status"] == (
        "calibrated, held for budget (fused 42.8% with it vs 25.6% without; budget 30.0%)")
    assert row["contributing"] is False
    assert row["eligible"] is False


def test_a_calibrated_detector_inside_the_budget_reads_eligible_in_the_table() -> None:
    decision = Decision(name="LOF", state="eligible", windows=1000,
                        rate_without=0.10, rate_with=0.12, budget=0.30,
                        evidence=Evidence(name="LOF", calibrated=True))
    row = _rows(name="LOF", observed=0.0, decisions={"LOF": decision})[0]
    assert row["status"] == "eligible"
    assert row["contributing"] is True


def test_a_detector_the_engine_no_longer_builds_has_no_row() -> None:
    """REMOVED IS ABSENT. History in the training log cannot resurrect a name."""
    training = {"LOF": {"trained_at": TODAY, "samples": 5000},
                "DBSCAN": {"trained_at": TODAY, "samples": 5000}}
    artifacts = {"LOF": {"version": "v5"}, "DBSCAN": {"version": "v5"}}
    calibration = {"LOF": {"observed_far": 0.0, "target_far": 0.01, "coverage": 0.83,
                           "coverage_observed": 16, "coverage_expected": 19, "age_hours": 0.5,
                           "validation_count": 2000, "threshold": 0.89},
                   "DBSCAN": {"observed_far": 0.0, "target_far": 0.01, "coverage": 0.9,
                              "coverage_observed": 17, "coverage_expected": 19,
                              "age_hours": 0.5, "validation_count": 2000, "threshold": 0.9}}
    rows = detector_rows(training, artifacts, calibration, known_names=("LOF",))
    assert [row["name"] for row in rows] == ["LOF"]
    assert "DBSCAN" not in json.dumps(rows)


def test_the_fused_rate_is_reported_at_the_decision_bar_not_the_calibration_threshold() -> None:
    """MEASURED LIVE: 66/789 = 8.37% at base_threshold 0.35, 15/789 = 1.90% at 0.5807.

    The Models card printed only the second (as 0.00% in a smaller sample) while the ensemble
    alerted at the first. The headline must lead with the decision bar and show the calibration
    threshold beside it, labelled.
    """
    scores = [0.9] * 15 + [0.4] * 51 + [0.1] * (789 - 66)
    summary = detector_summary(
        [{"contributing": True}],
        {"observed_far": 15 / 789, "target_far": 0.01, "validation_count": 789,
         "threshold": 0.5807, "far_lower": 0.011, "far_upper": 0.031},
        scores=scores, decision_threshold=0.35)
    assert "8.37% at the 0.35 decision bar" in summary
    assert "1.90% at the 0.5807 calibration threshold" in summary
    assert "n=789" in summary and "1.00% target" in summary


def test_a_provisional_detector_is_not_counted_as_eligible_in_the_headline() -> None:
    summary = detector_summary(
        [{"contributing": True, "calibrating": True}],
        {"observed_far": 0.0, "target_far": 0.01, "validation_count": 67,
         "threshold": 0.5807, "far_lower": 0.0, "far_upper": 0.054})
    assert "0 eligible, 1 provisional" in summary


def test_the_fused_score_is_never_shown_without_its_target() -> None:
    names = ("Isolation Forest", "Gradient Boosting", "KNN distance", "Adaptive Baseline")
    rows = detector_rows(
        {n: {"trained_at": TODAY, "samples": 100} for n in names},
        {n: {"version": "v5"} for n in names},
        {"Isolation Forest": {"observed_far": 0.0, "target_far": 0.01, "coverage": 0.83,
                              "coverage_observed": 16, "coverage_expected": 19, "age_hours": 0.5,
                              "validation_count": 2000, "threshold": 0.85},
         "Gradient Boosting": {"observed_far": 0.0, "target_far": 0.01, "coverage": 0.83,
                               "coverage_observed": 16, "coverage_expected": 19, "age_hours": 0.5,
                               "validation_count": 2000, "threshold": 0.98},
         "KNN distance": {"observed_far": 1.0, "target_far": 0.01, "coverage": 0.83,
                          "coverage_observed": 16, "coverage_expected": 19, "age_hours": 0.5,
                          "validation_count": 2000, "threshold": 0.96},
         "Adaptive Baseline": {"observed_far": 1.0, "target_far": 0.01, "coverage": 0.83,
                               "coverage_observed": 16, "coverage_expected": 19, "age_hours": 0.5,
                               "validation_count": 2000, "threshold": 0.37}},
        known_names=names,
    )
    summary = detector_summary(rows, {"observed_far": 0.04, "target_far": 0.01,
                                      "validation_count": 110, "far_lower": 0.020,
                                      "far_upper": 0.089})
    assert summary == ("4 detectors: 2 eligible. Fused false-alarm rate 0.04 "
                       "(95% CI 0.020-0.089, n=110) against a 0.01 target.")
    assert "0.04" in summary and "0.01" in summary


def test_a_missing_fused_row_says_nothing_is_measured() -> None:
    summary = detector_summary(_rows(), None)
    assert "nothing measured yet" in summary.lower()
    assert not re.search(r"0\.\d\d", summary)


def test_the_fused_row_is_not_a_detector() -> None:
    assert detector_rows({}, {}, {"__fused__": {"observed_far": 0.04, "target_far": 0.01}}) == []


def test_the_api_payload_carries_the_rows_the_summary_and_the_budget() -> None:
    """The whitelist in models_payload is a wall: fields die at it unless they are named."""
    from weirvern.admin.web_api import models_payload

    out = models_payload({
        "available": True,
        "detectors": _rows(),
        "detector_summary": "1 detector: 0 eligible. Fused false-alarm rate 0.04 "
                            "against a 0.01 target.",
        "detector_budget": {"budget": 0.30, "bar": 0.35, "windows": 25, "reason": ""},
    })
    assert out["detectors"][0]["status"].startswith("not contributing: FAR")
    assert "0.04" in out["detector_summary"]
    assert out["detector_budget"]["budget"] == 0.30
    assert out["detector_budget"]["bar"] == 0.35


def test_the_models_fetcher_derives_the_rows_from_the_live_reads(monkeypatch, tmp_path) -> None:
    """The composition, not just the pure function: settings, artifacts and the budget reach it."""
    import types

    from weirvern.admin import payloads
    from weirvern.models import cards as cards_mod

    class _Client:
        """Answers the reads the detector table and the budget guard need."""

        def query(self, sql, parameters=None):  # noqa: ANN001, ANN201
            rows: list = []
            if "ml_models" in sql and "GROUP BY model_type" in sql:
                rows = [("KNN distance", "2026-11-19 08:21:17")]
            elif "ml_models" in sql:
                rows = [("KNN distance", "2026-11-19 08:21:17", "2026-11-19 08:21:08", 5000,
                         "ok")]
            elif "ml_calibration" in sql and "dateDiff" in sql:
                # AGE IS IN HOURS (`dateDiff('second', ...) / 3600.0 AS age_hours`): sixty
                # SECONDS old, not sixty hours.
                rows = [("KNN distance", 1.0, 0.01, 0.83, 16, 19, "2026-11-19 08:21:17",
                         60 / 3600.0, 2000, 0.86)]
            elif "argMax" in sql:
                rows = [("KNN distance", 1.0, 0.01, 0.83, 0, "16/19", 16, 19, "on",
                         2000, 0.86, 0.996, 1.0),
                        ("__fused__", 0.04, 0.01, 0.78, 0, "1542/1975", 1542, 1975, "on",
                         110, 0.71, 0.020, 0.089)]
            elif "ml_calibration" in sql:
                rows = [("KNN distance", 1.0, 0.01)]
            elif "ml_window_scores" in sql:
                rows = [(100, 42, 25)]
            return type("R", (), {"result_rows": rows})()

    monkeypatch.setattr(payloads.status_mod, "model_overview",
                        lambda client, **kw: {"available": True, "hours": 24})
    monkeypatch.setattr(cards_mod, "current_cards", lambda client: [])
    monkeypatch.setattr(cards_mod, "artifact_inventory",
                        lambda model_dir: {"KNN distance": {"version": "v5",
                                                           "written_at": WRITTEN}})
    settings = types.SimpleNamespace(ml_target_far=0.01, ml_eligibility_multiple=3.0,
                                     model_dir=str(tmp_path), retrain_every_h=6,
                                     ml_calibration_grace_h=1.0, ml_min_feature_coverage=0.15,
                                     ml_fused_alert_budget=0.30,
                                     ml_fused_budget_min_windows=1, ml_fused_budget_hours=24,
                                     base_threshold=0.35, ml_fusion_exclude="")

    out = payloads.models(_Client(), hours=24, settings=settings)

    assert [row["name"] for row in out["detectors"]] == ["KNN distance"]
    assert out["detectors"][0]["status"].startswith("not contributing: FAR")
    assert "retired" not in json.dumps(out["detectors"]).lower()
    assert "42.00%" in out["detector_summary"]
    assert "decision bar" in out["detector_summary"]
    assert "1.00% target" in out["detector_summary"]
    assert out["detector_budget"]["budget"] == 0.30


def test_the_card_and_its_summary_are_wired_in_both_files() -> None:
    """A table the JS cannot find renders as nothing, with no error: the seam is the test."""
    html = (WEB / "index.html").read_text(encoding="utf-8")
    js = (WEB / "app.js").read_text(encoding="utf-8")

    match = re.search(r'<table id="md-table">.*?<thead>(.*?)</thead>', html, re.S)
    assert match, "the Detectors table is not in the markup"
    headers = len(re.findall(r"<th", match.group(1)))
    assert headers == 8, f"{headers} header cells"

    assert 'id="md-summary"' in html, "the summary line has no element"
    assert 'querySelector("#md-table tbody")' in js, "the JS does not render into the table"
    assert 'getElementById("md-summary")' in js, "the JS does not update the summary"
    # The card is ABOVE Detection freshness, which is where the operator reads it.
    assert html.index('id="md-table"') < html.index('id="m-stale"')

    function = js[js.index("function renderDetectors"):]
    function = function[:function.index("\n}\n")]
    row = function[function.index("for (const d of detectors)"):]
    cells = row.count('el("td"')
    assert cells == headers, (
        f"{headers} header cells but {cells} data cells -- the table would render misaligned")
    assert "d.status" in row, "the row does not render the derived status"
    assert "data.detector_budget" in js, "the budget the rows were judged against is not rendered"


def test_a_calibration_older_than_the_artifact_is_not_evidence_about_it() -> None:
    """THE HOLDOUT LOCK. A retrain must not re-enable a model on its predecessor's calibration."""
    rows = detector_rows(
        {"KNN distance": {"trained_at": "2026-11-19 10:00:00", "samples": 5000}},
        {"KNN distance": {"version": "v5", "written_at": "2026-11-19T10:00:00"}},
        {"KNN distance": {"observed_far": 0.0, "target_far": 0.01, "coverage": 0.83,
                          "coverage_observed": 16, "coverage_expected": 19,
                          "computed_at": "2026-11-19 09:00:00", "age_hours": 0.5,
                          "validation_count": 2000, "threshold": 0.86}},
    )
    row = rows[0]
    assert row["contributing"] is False
    assert "calibration older than the artifact" in row["status"]


def test_a_calibration_newer_than_the_artifact_still_contributes():
    """The lock must not become a permanent bar: rerun the calibration and the model is back."""
    rows = detector_rows(
        {"KNN distance": {"trained_at": "2026-11-19 10:00:00", "samples": 5000}},
        {"KNN distance": {"version": "v5", "written_at": "2026-11-19T10:00:00"}},
        {"KNN distance": {"observed_far": 0.0, "target_far": 0.01, "coverage": 0.83,
                          "coverage_observed": 16, "coverage_expected": 19,
                          "computed_at": "2026-11-19 11:00:00", "age_hours": 0.5,
                          "validation_count": 2000, "threshold": 0.86}},
    )
    assert rows[0]["contributing"] is True
