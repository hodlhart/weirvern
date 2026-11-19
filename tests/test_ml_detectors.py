"""The Detectors table: status derived from evidence, never from a stored card value.

THE OPERATOR'S RULING IS THE SPEC: "DBSCAN trains, therefore it is not retired." The old table read
`ml_model_cards.status`, a curated snapshot that still said `retired` while DBSCAN was training
every six hours and writing a new artifact. These tests pin the replacement: a training row, an
artifact on disk, a measured false-alarm rate against its target, and the card's existing veto --
with no path from a stored status word to the rendered row.

The derivation is pure, so every case below runs without a ClickHouse. The last test is the seam
the jsdom harness cannot see statically: the ids and the header/row widths must agree between the
markup and the script, or the table renders misaligned with no error anywhere.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from weirvern.models.detector_status import detector_rows, detector_summary

WEB = Path(__file__).resolve().parents[1] / "weirvern" / "admin" / "web"
TODAY = "2026-11-19 08:21:17"
WRITTEN = "2026-11-19T08:22:00+00:00"


def _rows(*, observed: float | None = 1.0, target: float | None = 0.01,
          card: str | None = "production", trained: bool = True,
          name: str = "DBSCAN") -> list[dict]:
    """One detector's row, with each evidence source switched on or off independently."""
    training = {name: {"trained_at": TODAY, "samples": 5000}} if trained else {}
    artifacts = {name: {"version": "v5", "written_at": WRITTEN}} if trained else {}
    calibration = ({name: {"observed_far": observed, "target_far": target}}
                   if observed is not None else {})
    cards = {name: card} if card is not None else {}
    return detector_rows(training, artifacts, calibration, cards)


def test_a_trained_detector_over_its_far_budget_is_not_contributing() -> None:
    """The live DBSCAN reading: trained today, measured 1.00 against a 0.01 target."""
    row = _rows()[0]
    assert row["status"].startswith("trained, not contributing")
    assert "1.00" in row["status"] and "0.01" in row["status"]
    assert row["contributing"] is False
    assert row["eligible"] is False


def test_a_detector_within_its_budget_is_contributing() -> None:
    row = _rows(observed=0.0)[0]
    assert row["eligible"] is True
    assert row["barred"] is False
    assert row["contributing"] is True
    assert row["status"] == "contributing"


def test_a_detector_with_no_calibration_row_fails_closed() -> None:
    """An unmeasured false-alarm rate is not a met budget."""
    row = _rows(observed=None)[0]
    assert row["eligible"] is False
    assert row["contributing"] is False
    assert "no calibration row" in row["status"]
    # NO NUMBER, because there was no measurement to quote.
    assert not re.search(r"\d\.\d\d", row["status"])


def test_a_stored_card_status_is_never_rendered() -> None:
    """A card saying `retired` is a VETO, not a status: the engine training it outranks it."""
    row = _rows(observed=0.0, card="retired")[0]
    assert row["barred"] is True
    assert row["contributing"] is False
    assert row["status"] == "trained, barred by model card"
    assert "retired" not in json.dumps(row).lower()
    assert "retired" not in row["status"]


def test_a_detector_with_no_training_and_no_artifact_is_not_trained() -> None:
    # The name is still known (a calibration row exists), but the engine has left no training
    # record and no artifact, so there is nothing to contribute.
    row = _rows(observed=0.0, card=None, trained=False)[0]
    assert row["status"] == "not trained"
    assert row["contributing"] is False


def test_the_fused_score_is_never_shown_without_its_target() -> None:
    rows = detector_rows(
        {n: {"trained_at": TODAY, "samples": 100} for n in
         ("Isolation Forest", "Gradient Boosting", "DBSCAN", "Adaptive Baseline")},
        {n: {"version": "v5"} for n in
         ("Isolation Forest", "Gradient Boosting", "DBSCAN", "Adaptive Baseline")},
        {"Isolation Forest": {"observed_far": 0.0, "target_far": 0.01},
         "Gradient Boosting": {"observed_far": 0.0, "target_far": 0.01},
         "DBSCAN": {"observed_far": 1.0, "target_far": 0.01},
         "Adaptive Baseline": {"observed_far": 1.0, "target_far": 0.01}},
        dict.fromkeys(("Isolation Forest", "Gradient Boosting", "DBSCAN", "Adaptive Baseline"),
                      "production"),
    )
    summary = detector_summary(rows, {"observed_far": 0.04, "target_far": 0.01})
    assert summary == ("4 detectors: 2 contributing. Fused false-alarm rate 0.04 "
                       "against a 0.01 target.")
    assert "0.04" in summary and "0.01" in summary


def test_a_missing_fused_row_says_nothing_is_measured() -> None:
    summary = detector_summary(_rows(), None)
    assert "nothing measured yet" in summary.lower()
    assert not re.search(r"0\.\d\d", summary)


def test_the_fused_row_is_not_a_detector() -> None:
    rows = detector_rows({}, {}, {"__fused__": {"observed_far": 0.04, "target_far": 0.01}}, {})
    assert rows == []


def test_the_api_payload_carries_the_rows_and_the_summary() -> None:
    """The whitelist in models_payload is a wall: fields die at it unless they are named."""
    from weirvern.admin.web_api import models_payload

    out = models_payload({
        "available": True,
        "detectors": _rows(),
        "detector_summary": "1 detector: 0 contributing. Fused false-alarm rate 0.04 "
                            "against a 0.01 target.",
    })
    assert out["detectors"][0]["status"].startswith("trained, not contributing")
    assert "0.04" in out["detector_summary"]


def test_the_models_fetcher_derives_the_rows_from_the_live_reads(monkeypatch, tmp_path) -> None:
    """The composition, not just the pure function: settings, cards and the fused row reach it."""
    import types

    from weirvern.admin import payloads
    from weirvern.models import cards as cards_mod

    class _Client:
        """Answers the two reads the detector table needs; everything else is empty."""

        def query(self, sql, parameters=None):  # noqa: ANN001, ANN201
            rows: list = []
            if "ml_models" in sql:
                rows = [("DBSCAN", "2026-11-19 08:21:17", "2026-11-19 08:21:08", 5000)]
            elif "ml_calibration" in sql:
                rows = [("DBSCAN", 1.0, 0.01), ("__fused__", 0.04, 0.01)]
            return type("R", (), {"result_rows": rows})()

    monkeypatch.setattr(payloads.status_mod, "model_overview",
                        lambda client, **kw: {"available": True, "hours": 24})
    monkeypatch.setattr(cards_mod, "current_cards",
                        lambda client: [{"model_name": "DBSCAN", "status": "retired",
                                         "version": "v5"}])
    monkeypatch.setattr(cards_mod, "artifact_inventory",
                        lambda model_dir: {"DBSCAN": {"version": "v5",
                                                      "written_at": WRITTEN}})
    settings = types.SimpleNamespace(ml_target_far=0.01, ml_eligibility_multiple=3.0,
                                     model_dir=str(tmp_path))

    out = payloads.models(_Client(), hours=24, settings=settings)

    assert [row["name"] for row in out["detectors"]] == ["DBSCAN"]
    assert out["detectors"][0]["status"].startswith("trained, not contributing")
    assert "retired" not in json.dumps(out["detectors"]).lower()
    assert "0.04" in out["detector_summary"] and "0.01 target" in out["detector_summary"]


def test_the_card_and_its_summary_are_wired_in_both_files() -> None:
    """A table the JS cannot find renders as nothing, with no error: the seam is the test."""
    html = (WEB / "index.html").read_text(encoding="utf-8")
    js = (WEB / "app.js").read_text(encoding="utf-8")

    match = re.search(r'<table id="md-table">.*?<thead>(.*?)</thead>', html, re.S)
    assert match, "the Detectors table is not in the markup"
    headers = len(re.findall(r"<th", match.group(1)))
    assert headers == 7, f"{headers} header cells"

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


def test_a_calibration_older_than_the_artifact_is_not_evidence_about_it():
    """THE HOLDOUT LOCK. `calibration.eligibility` already refuses to let a retrain re-enable a
    model on its predecessor's calibration; the table must apply the same rule or it will call a
    freshly retrained model contributing on a score that measured a model no longer on disk.
    """
    from weirvern.models.detector_status import detector_rows

    rows = detector_rows(
        {"DBSCAN": {"trained_at": "2026-11-19 10:00:00", "samples": 5000}},
        {"DBSCAN": {"version": "v5", "written_at": "2026-11-19T10:00:00"}},
        {"DBSCAN": {"observed_far": 0.0, "target_far": 0.01,
                    "computed_at": "2026-11-19 09:00:00"}},
        {"DBSCAN": "production"},
    )
    row = rows[0]
    assert row["contributing"] is False
    assert "calibration older than the artifact" in row["status"]


def test_a_calibration_newer_than_the_artifact_still_contributes():
    """The lock must not become a permanent bar: rerun the calibration and the model is back."""
    from weirvern.models.detector_status import detector_rows

    rows = detector_rows(
        {"DBSCAN": {"trained_at": "2026-11-19 10:00:00", "samples": 5000}},
        {"DBSCAN": {"version": "v5", "written_at": "2026-11-19T10:00:00"}},
        {"DBSCAN": {"observed_far": 0.0, "target_far": 0.01,
                    "computed_at": "2026-11-19 11:00:00"}},
        {"DBSCAN": "production"},
    )
    assert rows[0]["contributing"] is True
