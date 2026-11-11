"""OP-1: the ML quality surface must not turn an absent measurement into a zero."""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from weirvern.models import quality

ROOT = Path(__file__).resolve().parents[1]


class _Client:
    def query(self, sql, parameters=None):
        if "netflow_anomalies" in sql:
            return SimpleNamespace(result_rows=[(120, 4, 9, 42.0)])
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


def test_slo_is_exposed_on_the_models_surface():
    web = (ROOT / "weirvern" / "admin" / "web.py").read_text()
    js = (ROOT / "weirvern" / "admin" / "web" / "app.js").read_text()
    html = (ROOT / "weirvern" / "admin" / "web" / "index.html").read_text()
    assert "/api/ml/slo" in web
    assert "renderMlSlo" in js and "m-slo" in js
    assert "ML quality SLO" in html and "m-slo" in html
