"""A FAR must never be read without knowing what the model was fed.

THE DEFECT: schema 056 added `coverage` to `ml_calibration` and nothing wrote it. After
ML_MISSING_FEATURES was switched on, Isolation Forest's observed FAR fell from a fused 0.25 to
0.0097 against a 0.01 target -- and the row could not say whether that was measured on 10 of 77
columns or on all 77. A rate measured on a mostly imputed vector is a different measurement.

These tests pin the four things that make the number readable:

  * the calibration row stores the counts behind the ratio, from the SAME `coverage_counts` the
    scoring path used, so '10/77' cannot drift from the vector the detector consumed;
  * the missing-data mode is recorded, so two rows from different vectors are distinguishable;
  * a NULL coverage stays NULL and renders as `coverage not recorded`, never as complete;
  * the Detectors row states the imputed count beside the FAR.
"""
from __future__ import annotations

from datetime import datetime

import pytest

from weirvern.config import ModelConfig, Settings
from weirvern.ensemble import detect_flows
from weirvern.features import IF_FEATURES, TELEMETRY_FEATURES
from weirvern.models.calibration import MODEL_EXPECTED_FEATURES, run
from weirvern.models.detector_status import coverage_note, detector_rows
from weirvern.models.detectors import (
    AdaptiveBaselineDetector,
    DBSCANDetector,
    GradientBoostingDetector,
    IsolationForestDetector,
)


class _Result:
    def __init__(self, rows, columns=None):
        self.result_rows = rows
        self.column_names = columns or []


class _Client:
    """Answers the population read the way a migration-level deployment would.

    `counts` selects which column set the query can answer, so the same fake exercises the
    058 shape, the 056 shape (ratio only) and the 038 shape (score only).
    """

    def __init__(self, population_rows, *, counts=True, coverage_columns=True,
                 fallback_rows=None):
        self.population_rows = population_rows
        self.counts = counts
        self.coverage_columns = coverage_columns
        self.fallback_rows = fallback_rows if fallback_rows is not None else [(0.5,)] * 40
        self.inserts: list[tuple[str, list, list]] = []

    def query(self, sql, parameters=None):  # noqa: ANN001, ANN201
        if "FROM weirvern.ml_window_scores" in sql:
            if "coverage_observed" in sql and self.counts:
                return _Result(self.population_rows)
            if "coverage" in sql and self.coverage_columns:
                return _Result([(r[0], r[1], r[2]) for r in self.population_rows])
            return _Result([(r[0], r[1]) for r in self.population_rows])
        if "FROM weirvern.netflow_anomalies" in sql:
            return _Result(self.fallback_rows)
        raise AssertionError(sql)

    def insert(self, table, rows, column_names=None):  # noqa: ANN001, ANN201
        self.inserts.append((table, rows, list(column_names or [])))
        return len(rows)

    def inserted(self, table: str) -> tuple[list, list]:
        found = [entry for entry in self.inserts if entry[0] == table]
        assert found, f"nothing was inserted into {table}"
        return found[-1][1], found[-1][2]


def _population(names=("Isolation Forest", "Gradient Boosting", "KNN distance", "LOF",
                       "Adaptive Baseline"),
                windows: int = 40, observed: int = 10, expected: int = 77):
    """A reference where every window measured `observed` of `expected` columns."""
    rows = []
    for name in names:
        for i in range(windows):
            rows.append([name, 0.5 + i / (windows * 100), observed / expected,
                         observed, expected])
    return rows


# ── the row stores the counts behind the ratio ───────────────────────────────────────────────

def test_a_calibration_row_records_the_coverage_of_its_reference():
    client = _Client(_population())
    # The floor is switched off for this test: at the shipped 0.15 a 10/77 window is excluded
    # from the reference by design, and the point here is what the row stores when it is kept.
    rows = run(client, Settings(ml_missing_features=True, ml_min_feature_coverage=0.0))
    pooled = [row for row in rows if row["scope"] == "global"]
    assert len(pooled) == 5, "one pooled row per live detector"
    # AND ONE ROW PER COVERAGE STRATUM beside each pooled row: the whole reference measured
    # 10/77, so every detector has exactly one stratum, and 40 windows is below the 400 needed
    # to resolve a 1% budget -- it therefore says it fell back to the pooled threshold.
    strata = [row for row in rows if row["scope"] == "coverage"]
    assert len(strata) == 5
    assert {row["subject"] for row in strata} == {"10/77"}
    assert all("FELL BACK to the pooled threshold" in row["reference_source"] for row in strata)
    for row in rows:
        assert row["coverage"] == pytest.approx(10 / 77)
        assert row["coverage_observed"] == 10 * 40
        assert row["coverage_expected"] == 77 * 40
        assert row["coverage_detail"] == "10/77"
        assert row["missing_mode"] == "on"
        # AND THE STORED ROW CARRIES IT, not only the returned dict.
        assert row["coverage"] == pytest.approx(
            row["coverage_observed"] / row["coverage_expected"])

    stored, columns = client.inserted("weirvern.ml_calibration")
    assert "coverage_detail" in columns and "missing_mode" in columns
    index = columns.index("coverage")
    detail_index = columns.index("coverage_detail")
    assert stored[0][index] == pytest.approx(10 / 77)
    assert stored[0][detail_index] == "10/77"

    history, history_columns = client.inserted("weirvern.ml_calibration_history")
    assert "coverage_detail" in history_columns and "missing_mode" in history_columns
    assert history_columns[0] == "computed_at"
    assert history[0][history_columns.index("coverage")] == pytest.approx(10 / 77)


def test_the_recorded_counts_are_the_ones_the_scoring_path_measured():
    """`record_population` writes the same integers `coverage_counts` produced at score time."""
    from weirvern.models.calibration import record_population

    client = _Client([])
    record_population(client, [{
        "window_start": "2026-11-19 08:00:00", "src_addr": "198.51.100.10",
        "scores": {"Isolation Forest": 0.4},
        "coverage": 10 / 77, "coverage_counts": (10, 77),
        "model_coverage": {"Isolation Forest": 10 / 77},
        "model_coverage_counts": {"Isolation Forest": (10, 77)},
        "excluded": False,
    }], model_version="9.9.9")
    rows, columns = client.inserted("weirvern.ml_window_scores")
    index = {name: i for i, name in enumerate(columns)}
    assert rows[0][index["coverage_observed"]] == 10
    assert rows[0][index["coverage_expected"]] == 77
    assert rows[0][index["coverage"]] == pytest.approx(10 / 77)


# ── the mode is part of the measurement ─────────────────────────────────────────────────────

def test_two_calibrations_in_different_missing_modes_are_distinguishable():
    on_rows = run(_Client(_population()),
                  Settings(ml_missing_features=True, ml_min_feature_coverage=0.0))
    off_population = [[name, 0.5 + i / 4000, None, None, None]
                      for name in ("Isolation Forest", "Gradient Boosting", "KNN distance",
                                   "LOF", "Adaptive Baseline") for i in range(40)]
    off_rows = run(_Client(off_population, counts=False),
                   Settings(ml_missing_features=False, ml_min_feature_coverage=0.0))

    assert on_rows and off_rows
    assert {row["missing_mode"] for row in on_rows} == {"on"}
    assert {row["missing_mode"] for row in off_rows} == {"off"}
    # The flag-off population carried no coverage, so the row says unrecorded -- not 100%.
    assert all(row["coverage"] is None for row in off_rows)
    assert all(row["coverage_detail"] == "" for row in off_rows)


def test_a_reference_without_coverage_writes_null_not_a_default():
    """The anomaly-tail fallback has no feature vector; the row must admit that."""
    client = _Client([], fallback_rows=[(0.5,)] * 40)
    rows = run(client, Settings(ml_missing_features=True))
    assert rows, "the fallback calibration produced no rows"
    for row in rows:
        assert row["coverage"] is None
        assert row["coverage_observed"] is None
        assert row["coverage_expected"] is None
        assert row["coverage_detail"] == ""
        assert "coverage not measured for this reference" in row["reference_source"]
    stored, columns = client.inserted("weirvern.ml_calibration")
    assert all(row[columns.index("coverage")] is None for row in stored)


# ── the Detectors row states it ─────────────────────────────────────────────────────────────

def _detector_row(coverage, detail="", observed=0.0, target=0.01):
    return detector_rows(
        {"DBSCAN": {"trained_at": "2026-11-19 08:21:17", "samples": 5000}},
        {"DBSCAN": {"version": "v5", "written_at": "2026-11-19T08:22:00+00:00"}},
        {"DBSCAN": {"observed_far": observed, "target_far": target, "coverage": coverage,
                    "coverage_detail": detail, "coverage_observed": 10,
                    "coverage_expected": 77, "missing_mode": "on"}},
        {"DBSCAN": "production"},
    )[0]


def test_the_detectors_row_prints_the_imputed_count():
    row = _detector_row(10 / 77, "10/77")
    assert row["coverage_note"] == "10 of 77 inputs (67 imputed)"
    assert row["missing_mode"] == "on"
    assert row["coverage_observed"] == 10 and row["coverage_expected"] == 77


def test_a_null_coverage_never_reads_as_complete():
    row = _detector_row(None)
    assert row["coverage_note"] == "coverage not recorded"
    assert "77 of 77" not in row["coverage_note"]
    assert coverage_note({"coverage": None, "coverage_detail": "77/77"}) == "coverage not recorded"


def test_a_ratio_without_counts_says_so_instead_of_inventing_them():
    assert coverage_note({"coverage": 0.13, "coverage_detail": ""}) == (
        "coverage 0.13 (counts not recorded)")


def test_the_models_payload_carries_the_coverage_note():
    """The whitelist in models_payload is a wall: a field must be carried or it dies there."""
    from weirvern.admin.web_api import models_payload

    out = models_payload({
        "available": True,
        "detectors": [_detector_row(10 / 77, "10/77")],
        "detector_summary": "1 detector: 1 contributing.",
    })
    assert out["detectors"][0]["coverage_note"] == "10 of 77 inputs (67 imputed)"
    assert out["detectors"][0]["missing_mode"] == "on"


# ── one denominator ────────────────────────────────────────────────────────────────────────

def test_the_expected_feature_count_comes_from_one_source(tmp_path):
    """The denominator is the detector's own list, not a number written down somewhere else."""
    detectors = [
        IsolationForestDetector(tmp_path),
        GradientBoostingDetector(tmp_path),
        DBSCANDetector(tmp_path),
        AdaptiveBaselineDetector(tmp_path),
    ]
    for detector in detectors:
        declared = getattr(detector, "expected_feature_columns", None)
        expected = declared() if callable(declared) else []
        denominator = (len(expected) if isinstance(expected, list) and expected
                       else len(TELEMETRY_FEATURES))
        assert MODEL_EXPECTED_FEATURES[detector.name] == denominator, (
            f"{detector.name}: the calibration denominator disagrees with the detector's vector")
    assert MODEL_EXPECTED_FEATURES["Isolation Forest"] == len(IF_FEATURES) == 77


def test_the_ensemble_measures_each_detector_against_its_own_vector(tmp_path):
    """10 host features measured, no diversity/temporal/Zeek row: 10 of 77, not 10 of 79."""
    detector = IsolationForestDetector(tmp_path, ModelConfig(missing_features=True))
    population: list[dict] = []
    flow = {"src_addr": "198.51.100.10", "window_start": datetime(2026, 11, 19, 8, 0, 0),
            "total_bytes": 1000, "total_packets": 10, "unique_dst_ips": 2, "flow_count": 4}
    detect_flows([flow], [detector], Settings(), detector.cfg, score_population=population)
    sample = population[0]
    counts = sample["model_coverage_counts"][detector.name]
    assert counts == (10, len(detector.expected_feature_columns()))
    assert counts[1] == 77
    assert sample["model_coverage"][detector.name] == pytest.approx(10 / 77)
    # The window union is wider than the detector's vector, and both are recorded.
    assert sample["coverage_counts"][1] == len(TELEMETRY_FEATURES)
