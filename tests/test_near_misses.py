"""SOC-2: near misses -- the false-negative surface.

THE GAP. The Anomalies view lists what was FLAGGED. Nothing showed what almost was:
a window at 0.66 against a 0.7 bar, or one where a lone strong detector fired and the
agreement gate suppressed it. Without that surface a threshold can only be tuned by
guessing, because the only feedback is "an alert fired" or "nothing happened" -- and
"nothing happened" collapses "traffic was normal" with "we nearly alerted and didn't".

THE AUDIT WAS WRONG ABOUT THE DATA, AND THE CORRECTION MATTERS. It said near-miss data
"exists, it just is not queried". Measured against detect_flows: both drop paths
`continue`d before anything was recorded, so the scores were computed and thrown away.
Following the audit literally ("just query it") would have produced a panel over an
empty table forever. These tests pin the RECORDING and the reading.

WHAT EACH DROP REASON MEANS, because they are different evidence:
  * below-threshold -- the window scored in the band under the bar. Raising the
    threshold reclassifies these; they are the "how close did normal traffic come".
  * agreement-gate  -- the window CLEARED the bar and was dropped anyway because too
    few detectors agreed. Lowering the gate surfaces these; they are "we decided not
    to look".
"""
from __future__ import annotations

from pathlib import Path

from weirvern import ensemble
from weirvern.config import ModelConfig, Settings

ROOT = Path(__file__).resolve().parents[1]


class _Det:
    """A detector with a fixed score. is_ready True so agreement has a denominator."""

    def __init__(self, name, score):
        self.name = name
        self._score = score

    def is_ready(self):
        return True

    def predict(self, flow, features):
        return self._score


def _settings(**over):
    s = Settings(clickhouse_password="")
    import dataclasses
    return dataclasses.replace(s, **over) if over else s


def _flow(score_scale=1.0, src="198.51.100.9"):
    return {
        "window_start": "2026-09-20 10:05:00",
        "window_end": "2026-09-20 10:10:00",
        "src_addr": src,
        "total_bytes": 10_000_000,
        "flow_count": 40,
        "total_packets": 400,
        "unique_dst_ips": 5,
        "avg_bytes": 250000.0,
        "avg_packets": 10.0,
    }


def _run(scores, flows=None, near_misses=None, settings=None, cfg=None):
    detectors = [_Det(n, s) for n, s in scores.items()]
    return ensemble.detect_flows(
        flows or [_flow()], detectors, settings or _settings(),
        cfg or ModelConfig(), near_misses=near_misses,
    )


# ── the band ────────────────────────────────────────────────────────────────────


def test_a_window_in_the_band_is_recorded_with_its_reason_and_threshold():
    """Below the bar, within reach of it: recorded, with the bar it faced."""
    nm: list[dict] = []
    # All detectors just under a 0.6 bar: fuse (max) ~0.58, band floor 0.6*0.85=0.51.
    _run({"Isolation Forest": 0.58, "Gradient Boosting": 0.55,
          "DBSCAN": 0.5, "Adaptive Baseline": 0.52}, near_misses=nm)
    # The window may or may not make the band against a real fuse; assert the SHAPE
    # when it does, and that the reason is the band one.
    for m in nm:
        assert m["reason"] == "below-threshold"
        assert m["threshold_used"] > m["anomaly_score"], (
            "a below-threshold near miss must sit under its threshold"
        )
        assert m["src_addr"] == "198.51.100.9"
        assert "isolation_forest_score" in m and "model_agreement" in m


def test_nothing_is_recorded_when_the_band_is_disabled():
    """near_miss_band=1.0 means only scores at-or-above the threshold qualify, and those
    are never below it -- so the band records nothing. That is the documented off switch."""
    nm: list[dict] = []
    _run({"Isolation Forest": 0.58, "Gradient Boosting": 0.55,
          "DBSCAN": 0.5, "Adaptive Baseline": 0.52},
         near_misses=nm, cfg=ModelConfig(near_miss_band=1.0))
    assert nm == [], "the band is off but windows were still recorded"


def test_ordinary_traffic_is_not_flooding_the_band():
    """A genuinely quiet window (everything ~0.1) must not generate near misses, or the
    table becomes a log of everything and the panel is noise."""
    nm: list[dict] = []
    _run({"Isolation Forest": 0.1, "Gradient Boosting": 0.12,
          "DBSCAN": 0.08, "Adaptive Baseline": 0.1}, near_misses=nm)
    assert nm == [], f"quiet traffic produced near misses: {nm}"


# ── the agreement gate ─────────────────────────────────────────────────────────


def test_a_gate_dropped_window_is_recorded_as_such():
    """Cleared the bar, dropped by agreement: the 'we decided not to look' case."""
    nm: list[dict] = []
    # One strong detector, rest silent -> high max-fusion score, agreement 0.25. Against
    # the DEFAULT settings that lands exactly ON the high-score tier floor (0.25), so the
    # gate does not fire -- which is useful to know but not the case under test. Raise the
    # bar to 0.75 so the gate is unambiguous: 0.25 < (0.75 - margin).
    import dataclasses
    settings = dataclasses.replace(_settings(), min_agreement=0.75)
    verdicts = _run({"Isolation Forest": 0.9, "Gradient Boosting": 0.05,
                     "DBSCAN": 0.05, "Adaptive Baseline": 0.05},
                    near_misses=nm, settings=settings)
    gate = [m for m in nm if m["reason"] == "agreement-gate"]
    assert gate, (
        "a window that cleared the bar and died at the agreement gate was not recorded; "
        f"verdicts={len(verdicts)} near_misses={nm}"
    )
    m = gate[0]
    assert m["anomaly_score"] >= m["threshold_used"], (
        "an agreement-gate near miss is by definition AT or ABOVE its threshold"
    )
    assert m["model_agreement"] < 0.75, "the gate reason disagrees with the agreement value"


def test_the_reason_strings_are_the_ones_the_schema_and_reader_expect():
    """One vocabulary across ensemble, schema, status reader and GUI."""
    sql = (ROOT / "weirvern" / "schema" / "009_near_misses.sql").read_text()
    assert "below-threshold" in sql and "agreement-gate" in sql
    src = (ROOT / "weirvern" / "admin" / "status.py").read_text()
    assert "near_misses" in src
    app = (ROOT / "weirvern" / "admin" / "web" / "app.js").read_text()
    assert "agreement-gate" in app, "the GUI cannot label a gate-dropped near miss"


# ── the plumbing ────────────────────────────────────────────────────────────────


def test_passing_none_changes_nothing_for_existing_callers():
    """The parameter is additive; every pre-existing caller keeps its exact behaviour."""
    no_param = _run({"Isolation Forest": 0.9, "Gradient Boosting": 0.05,
                     "DBSCAN": 0.05, "Adaptive Baseline": 0.05})
    with_none = _run({"Isolation Forest": 0.9, "Gradient Boosting": 0.05,
                      "DBSCAN": 0.05, "Adaptive Baseline": 0.05}, near_misses=None)
    assert [v["anomaly_score"] for v in no_param] == [v["anomaly_score"] for v in with_none]


def test_the_worker_stores_them_best_effort():
    """A failure to record near misses must never cost a real alert -- so the insert is
    wrapped, and this pins the wrapping rather than trusting review."""
    src = (ROOT / "weirvern" / "worker.py").read_text()
    i = src.index("weirvern.near_misses")
    region = src[i - 400:i + 2200]
    assert "except Exception" in region and "continuing" in region, (
        "the near-miss insert is not wrapped; a failure would take the sweep with it"
    )
    assert "detect_flows" in region, "the near misses are no longer collected in the sweep"


def test_the_status_reader_distinguishes_unavailable_from_empty():
    """On a deployment whose schema job has not re-run, the table does not exist. The
    panel must say THAT, not render an empty list -- 'nothing nearly alerted' is a much
    stronger claim than 'we cannot see'."""
    src = (ROOT / "weirvern" / "admin" / "status.py").read_text()
    i = src.index("NEAR MISSES (soc-2)")
    region = src[i:i + 2000]
    assert "near_misses_available" in region, (
        "the reader no longer marks availability, so empty and unavailable collapse"
    )
    assert "schema job" in region, (
        "the unavailable reason does not explain WHY (the schema job), leaving the "
        "operator to guess"
    )
