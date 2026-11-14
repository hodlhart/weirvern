"""The calibration reference must be one regime, and a threshold it cannot reach must say so.

Two measured defects, both in the path that decides what an alert threshold IS.

FIRST: the reference population spans model versions. Measured on the live engine, one rolling week
carried rows from eight distinct `model_version` values, because the version is the package version
and every deploy changes it. Calibrating across a model or aggregation change fits today's detector
against an older engine's score distribution, so the resulting threshold belongs to neither regime.
Restricting the reference to the current version moved the 1% threshold from 0.8165 to 0.7327 while
the highest score the current engine had produced was 0.853. That is not a tuning difference: at
0.8165 the engine alerts, and a mixture that lands above 0.853 silences it completely.

SECOND: a target false-alarm rate is only expressible down to 1/(n+1) of the reference. When the
fitted threshold lands AT the reference maximum, nothing can exceed it, and the stored row reads
exactly like a working calibration. The caller has no way to tell "the network is quiet" from "the
bar is above every score this detector produces", which is the same failure-rendered-as-benign shape
this project keeps finding.

Neither fix changes what alerts. Both make a number honest.
"""

from __future__ import annotations

import pytest

from weirvern import __version__
from weirvern.models import calibration

pytest.importorskip("numpy")


class _Result:
    def __init__(self, rows):
        self.result_rows = rows


class _Recorder:
    """A stub client that records the SQL it was handed and answers with a fixed population."""

    def __init__(self, population: dict[str, list[float]]):
        self.population = population
        self.queries: list[tuple[str, dict]] = []
        self.inserts: list[tuple[str, list, list]] = []

    def query(self, sql, parameters=None):
        self.queries.append((sql, dict(parameters or {})))
        if "model_name, score" in sql:
            rows = []
            for name, scores in self.population.items():
                rows.extend((name, s) for s in scores)
            return _Result(rows)
        # the fallback path reads one numeric column
        return _Result([(0.5,)] * 40)

    def insert(self, table, rows, column_names=None):
        self.inserts.append((table, rows, list(column_names or [])))
        return len(rows)


def _population(lo: float, hi: float, n: int = 60) -> dict[str, list[float]]:
    scores = [lo + (hi - lo) * i / (n - 1) for i in range(n)]
    return {name: list(scores) for name, _col in calibration.MODEL_COLUMNS}


# ── the reference is scoped to the model that produced it ──────────────────────────────────

def test_the_population_query_is_scoped_to_the_current_model_version():
    """A reference that spans a deploy calibrates today's detector against an older engine."""
    client = _Recorder(_population(0.0, 0.9))
    calibration._population_scores(client, 7, "9.9.9")

    sql, params = client.queries[0]
    assert "model_version" in sql, (
        "the reference query does not constrain model_version, so a rolling week mixes engines: "
        f"{sql}"
    )
    assert params.get("v") == "9.9.9", f"the version was not passed as a parameter: {params}"


def test_run_calibrates_on_the_version_it_is_running():
    client = _Recorder(_population(0.0, 0.9))
    calibration.run(client, _Settings(), days=7)

    sql, params = client.queries[0]
    assert params.get("v") == __version__, (
        f"run() calibrated on {params.get('v')!r} instead of the running version {__version__!r}"
    )


# ── a saturated threshold is reported, not stored as a working budget ──────────────────────

def test_a_threshold_at_the_reference_ceiling_is_marked_saturated():
    """The target lands on the maximum, so no score can cross it."""
    cal = calibration.fit([0.1] * 30 + [0.99] * 30, 0.01)
    assert cal is not None
    assert cal.threshold == pytest.approx(cal.ceiling), "expected the threshold to sit at the ceiling"
    assert cal.saturated is True


def test_a_threshold_inside_the_reference_is_not_marked_saturated():
    """The guard must be able to say no, or it is a constant that reads as a finding."""
    cal = calibration.fit([i / 100 for i in range(100)], 0.01)
    assert cal is not None
    assert cal.threshold < cal.ceiling
    assert cal.saturated is False


def test_a_saturated_calibration_says_so_where_an_operator_reads_it():
    """Storing a threshold that cannot be crossed, silently, is how a silent engine is born."""
    client = _Recorder(_population(0.99, 0.99))     # every score identical: nothing can exceed
    rows = calibration.run(client, _Settings(), days=7)

    assert rows, "run() produced no calibration rows"
    sources = " ".join(str(r["reference_source"]) for r in rows)
    assert "SATURATED" in sources.upper(), (
        f"a threshold at the ceiling was stored without a word of explanation: {sources!r}"
    )


def test_a_healthy_calibration_is_not_labelled_saturated():
    """The wording must not appear on a working calibration, or it becomes noise."""
    client = _Recorder(_population(0.0, 0.9))
    rows = calibration.run(client, _Settings(), days=7)

    sources = " ".join(str(r["reference_source"]) for r in rows)
    assert "SATURATED" not in sources.upper()


class _Settings:
    """The settings `run` reads, with the defaults the deployment ships."""

    ml_target_far = 0.01
    ml_calibration_days = 7
    ml_eligibility = None
    ml_eligibility_multiple = 1.0
