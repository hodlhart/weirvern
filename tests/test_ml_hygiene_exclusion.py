"""Training hygiene: the detectors must not learn from windows already flagged as attacks.

THE CLASS OF DEFECT THIS FILE EXISTS FOR. Detectors train on the last RETRAIN_WINDOW_H of
traffic -- which includes any ongoing incident. Isolation Forest's contamination (~6%) EXPECTS
outliers in its training data, so a sustained attack lasting days quietly becomes part of the
learned "normal". The failure is silent by construction: no exception, no metric moves, and the
model looks healthiest exactly when it has stopped recognising the thing it is supposed to catch.

THE DEFENCE, AND ITS HONEST LIMIT. Host-windows already flagged high/critical in
netflow_anomalies (same host, same 5-minute bucket) are excluded from the next training pass.
That uses the system's own prior detections as evidence about which rows not to trust -- it can
only be as wrong as the detector that flagged them, which is strictly better than trusting every
row unconditionally. It is NOT the full answer: a slow attack that never crosses the severity bar
still trains in, and the stronger design (a frozen benign baseline with champion/challenger
disagreement as its own signal) remains on the audit backlog.

VERIFIED AGAINST A LIVE ENGINE. The clause was executed against a real clickhouse-server:26.8
(the deployed image) with seeded rows: 5 flow windows, one flagged high, one flagged medium.
Observed: exclusion ON -> 4 rows (the high window dropped); OFF -> 5; the medium-flagged window
was NOT excluded either way. The offline tests below pin the clause's construction and its
wiring; the live measurement is recorded here because a query that parses is not a query that
filters.
"""
from __future__ import annotations

import dataclasses
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from weirvern.config import ModelConfig  # noqa: E402
from weirvern.models import detectors  # noqa: E402

DETECTORS_SRC = (ROOT / "weirvern" / "models" / "detectors.py").read_text()

START = "2026-09-19 00:00:00"
END = "2026-09-20 00:00:00"


# ── the clause itself ──────────────────────────────────────────────────────────────────────

def test_the_clause_filters_on_host_and_window_at_high_or_critical():
    clause = detectors._flagged_exclusion_clause(START, END, ModelConfig())
    assert clause, "the exclusion clause is empty with the feature enabled"
    assert "netflow_anomalies" in clause, "the exclusion does not consult the system's own flags"
    assert "sev" in clause and "'high', 'critical'" in clause, (
        "the exclusion does not filter on high/critical severity, so every previously-tuned "
        "windows is excluded and the exclusion list can swallow the segment"
    )
    # Host + window bucket, as a TUPLE. NOT EXISTS with a correlated subquery is not a
    # supported shape on the deployed engine; the tuple form is, and was verified live.
    assert "NOT IN" in clause and "src_addr" in clause and "window_start" in clause
    assert "toStartOfFiveMinutes" in clause, (
        "the window join is not bucketed, so an anomaly row at 10:05:00.000 and an aggregate "
        "at 10:05:00 fail to match and the exclusion silently does nothing"
    )


def test_severity_tiers_are_the_ones_severity_of_emits():
    """'medium' must NOT be excluded: ordinary noise and tuning misses stay trainable."""
    clause = detectors._flagged_exclusion_clause(START, END, ModelConfig())
    assert "'medium'" not in clause and "'low'" not in clause


def test_the_clause_disappears_when_disabled():
    cfg = dataclasses.replace(ModelConfig(), exclude_flagged_from_training=False)
    assert detectors._flagged_exclusion_clause(START, END, cfg) == "", (
        "disabling the exclusion still emits a fragment, so the switch does nothing"
    )


def test_the_switch_defaults_to_on():
    assert ModelConfig().exclude_flagged_from_training is True


# ── the wiring: every training query must carry it ─────────────────────────────────────────
#
# IF, DBSCAN and Adaptive Baseline each run their own query. Gradient Boosting inherits the
# IF matrix, so covering IF covers it. A helper that three queries must remember to call is
# exactly the shape that drifts -- so the wiring is asserted per query.

def test_all_three_training_queries_splice_the_exclusion():
    for cls in ("IsolationForestDetector", "DBSCANDetector", "AdaptiveBaselineDetector"):
        start = DETECTORS_SRC.index(f"class {cls}")
        # Slice to the NEXT class declaration, not a fixed width: the classes differ in
        # size, and a fixed window silently truncates the longest one mid-method.
        nxt = DETECTORS_SRC.find("\nclass ", start + 1)
        body = DETECTORS_SRC[start:nxt if nxt > 0 else len(DETECTORS_SRC)]
        assert "_flagged_exclusion_clause(" in body, (
            f"{cls}.train does not call _flagged_exclusion_clause, so it learns from "
            f"flagged windows"
        )
        assert "{excl}" in body, (
            f"{cls}'s query does not splice {{excl}}, so the clause is computed and unused"
        )


def test_the_clause_is_computed_where_the_datetimes_are_in_scope():
    """The f-string must be built after s/e exist -- a clause built from undefined names is
    a NameError at train time, on a path that only runs every RETRAIN_EVERY_H hours."""
    for call in ("excl = _flagged_exclusion_clause(s, e, self.cfg)",):
        assert call in DETECTORS_SRC, call
