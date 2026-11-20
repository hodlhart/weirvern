"""PRD-2: calibration uses the population, not the alert tail; retrain locks it out."""
from __future__ import annotations

from datetime import datetime, timedelta

from weirvern.config import Settings
from weirvern.models.calibration import eligibility, record_population, run

BASE = datetime(2026, 10, 30, 0, 0, 0)


class Result:
    def __init__(self, columns, rows):
        self.column_names = columns
        self.result_rows = rows


class FakeClient:
    def __init__(self, population_rows=None, calibration_rows=None, trained_rows=None,
                 card_rows=None):
        self.population_rows = population_rows or []
        self.calibration_rows = calibration_rows or []
        self.trained_rows = trained_rows or []
        self.card_rows = card_rows if card_rows is not None else [
            _card("Isolation Forest"), _card("DBSCAN"),
        ]
        self.inserts = []

    def query(self, sql, parameters=None):
        if "FROM weirvern.ml_window_scores" in sql:
            return Result(["model_name", "score"], self.population_rows)
        if "FROM weirvern.ml_calibration" in sql:
            return Result(["model_name", "observed_far", "target_far", "computed_at"],
                          self.calibration_rows)
        if "FROM weirvern.ml_models" in sql:
            return Result(["model_type", "max(trained_at)"], self.trained_rows)
        if "FROM weirvern.ml_model_cards" in sql:
            return Result([], self.card_rows)
        raise AssertionError(sql)

    def insert(self, table, rows, column_names=None):
        self.inserts.append((table, rows, column_names))


def _card(name, status="production"):
    """The card row shape cards._rows maps positionally; content is what this test needs."""
    return [name.lower().replace(" ", "-"), name, "v4", "hash", BASE, BASE, "4", "v1",
            "not_measured", status, "operator", "operator", BASE, "rollback", "use", "out",
            "limit", BASE]


def population():
    names = ("Isolation Forest", "Gradient Boosting", "KNN distance", "LOF", "Adaptive Baseline")
    return [[name, 0.70] for name in names for _ in range(40)]


def test_run_uses_all_scored_windows_when_population_exists():
    client = FakeClient(population_rows=population())
    rows = run(client, Settings())
    assert len(rows) == 5
    assert all(row["subject"] == "all scored host-windows" for row in rows)
    assert all("ml_window_scores" in row["reference_source"] for row in rows)
    assert all(row["sample_count"] == 40 for row in rows)
    inserted = [i for i in client.inserts if i[0] == "weirvern.ml_calibration"]
    assert inserted and len(inserted[0][1]) == 5


def test_record_population_writes_one_row_per_model_and_window():
    client = FakeClient()
    count = record_population(client, [{
        "window_start": BASE, "src_addr": "198.51.100.10",
        "scores": {"Isolation Forest": 0.9, "DBSCAN": 0.2},
    }], model_version="0.23.15")
    assert count == 2
    table, rows, columns = client.inserts[-1]
    assert table == "weirvern.ml_window_scores"
    # `coverage`/`excluded` arrived with the missing-data work (schema 056); the counts arrived
    # with 058. They are written on every row -- NULL and 0 when the flag is off -- so the
    # population carries the evidence a coverage-excluding calibration needs, and the counts a
    # calibration row quotes, without a second table.
    assert columns == ["window_start", "src_addr", "model_name", "score",
                       "model_version", "computed_at", "coverage", "coverage_observed",
                       "coverage_expected", "excluded"]
    assert len(rows) == 2
    # The flag was not part of this sample, so coverage is UNKNOWN, not zero -- and the counts
    # are NULL with it. A 0/0 pair would be indistinguishable from a fully imputed window.
    assert all(row[6] is None and row[7] is None and row[8] is None for row in rows)
    assert all(row[9] == 0 for row in rows)


def test_retrain_newer_than_calibration_forces_ineligible():
    client = FakeClient(
        calibration_rows=[
            ["Isolation Forest", 0.01, 0.01, BASE],
            ["DBSCAN", 0.01, 0.01, BASE],
        ],
        trained_rows=[
            ["Isolation Forest", BASE + timedelta(hours=1)],
            ["DBSCAN", BASE - timedelta(hours=1)],
        ],
    )
    result = eligibility(client, Settings())
    assert result["Isolation Forest"] is False
    assert result["DBSCAN"] is True
