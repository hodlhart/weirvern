"""OP-1: the ML quality surface must not turn an absent measurement into a zero."""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from tests.support_routes import routed
from weirvern.models import quality

ROOT = Path(__file__).resolve().parents[1]


class _Client:
    def query(self, sql, parameters=None):
        if "netflow_anomalies" in sql:
            return SimpleNamespace(result_rows=[(120, 4, 9, 42.0)])
        if "dateDiff('day', min(episode_start)" in sql:
            return SimpleNamespace(result_rows=[(10,)])
        if "alert_episodes" in sql:
            return SimpleNamespace(result_rows=[(10, 2, 1)])
        if "ml_window_scores" in sql:
            return SimpleNamespace(result_rows=[(30,)])
        if "ml_drift" in sql:
            return SimpleNamespace(result_rows=[(3,)])
        raise AssertionError(sql)


def test_slo_has_named_windows_and_explicit_unmeasured_metrics():
    out = quality.report(_Client())
    assert [w["days"] for w in out["windows"]] == [7, 14, 30]
    assert out["live_precision"] == "not measured"
    names = {m["name"] for w in out["windows"] for m in w["metrics"]}
    assert "precision at the page budget" in names
    assert "false alarms / host / day" in names
    precision = next(m for w in out["windows"] for m in w["metrics"]
                     if m["name"] == "precision at the page budget")
    assert precision["value"] is None and precision["state"] == "not measured"


def test_a_failed_source_is_not_rendered_as_zero():
    class Broken:
        def query(self, sql, parameters=None):
            raise RuntimeError("down")

    out = quality.report(Broken())
    assert out["available"] is True
    first = out["windows"][0]
    assert first["available"] is False
    assert first["metrics"][0]["state"] == "not measured"


def test_a_window_the_episode_source_cannot_cover_is_not_measured():
    # Measured live 2026-11-11: the 14- and 30-day windows returned the same episode count,
    # because the source only held 14 days. A 30-day label over it is a lie, not a plateau.
    out = quality.report(_Client())
    by_days = {w["days"]: w for w in out["windows"]}
    ep30 = next(m for m in by_days[30]["metrics"] if m["name"] == "episodes")
    assert ep30["state"] == "not measured" and ep30["value"] is None
    assert "10 day(s)" in ep30["note"]
    ep7 = next(m for m in by_days[7]["metrics"] if m["name"] == "episodes")
    assert ep7["state"] == "observed" and ep7["value"] == 10


def test_slo_is_exposed_on_the_models_surface():
    js = (ROOT / "weirvern" / "admin" / "web" / "app.js").read_text()
    html = (ROOT / "weirvern" / "admin" / "web" / "index.html").read_text()
    assert routed("/api/ml/slo"), "the SLO route is not registered"
    assert "renderMlSlo" in js and "m-slo" in js
    assert "ML quality SLO" in html and "m-slo" in html
