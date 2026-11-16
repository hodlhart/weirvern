"""GT-3: a zero-row source is not a quiet network; an unknown role is a gap."""
from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from tests.support_routes import routed
from weirvern.models import evaluation
from weirvern.models.source_coverage import summarise

ROOT = Path(__file__).resolve().parents[1]


def _source(name: str, rows: int | None, state: str, required: bool = True):
    return {"name": name, "table": "weirvern." + name, "rows": rows, "state": state,
            "usable": state == "fresh", "required": required, "reason": state}


def test_an_empty_required_source_blocks_promotion_and_is_not_measured():
    out = summarise([_source("flows", 0, "not measured")],
                    {"counts": [{"role": "unknown", "count": 85}], "unknown": 85,
                     "top_unknown": ["198.51.100.7"]})
    assert out["sources"][0]["state"] == "not measured"
    assert out["promotion_ok"] is False
    assert out["required_missing"] == ["flows"]
    assert out["models"][0]["usable"] is False
    assert "not measured" in out["sources"][0]["reason"]


def test_a_stale_source_is_also_not_usable():
    out = summarise([_source("flows", 10, "stale")], None)
    assert out["promotion_ok"] is False


def test_unknown_roles_are_named_not_folded_into_workstation():
    out = summarise([_source("flows", 10, "fresh")],
                    {"counts": [{"role": "unknown", "count": 85},
                                {"role": "workstation", "count": 64}],
                     "unknown": 85, "top_unknown": ["198.51.100.7"]})
    assert out["roles"]["unknown"] == 85
    assert out["roles"]["top_unknown"] == ["198.51.100.7"]


def test_promote_refuses_when_coverage_is_not_usable():
    now = datetime.now(UTC)
    base = evaluation.Metrics(
        name="b", budget_per_day=1, days=1, windows=1, selected=1, alerts_per_day=1.0,
        raw_alerts_per_day=1.0, precision=1.0, detection_rate=1.0,
        false_alarms_per_host_day=0.0, labels_available=True,
    )
    cand = evaluation.Metrics(
        name="c", budget_per_day=1, days=1, windows=1, selected=1, alerts_per_day=1.0,
        raw_alerts_per_day=1.0, precision=1.0, detection_rate=1.0,
        false_alarms_per_host_day=0.0, labels_available=True,
    )
    decision = evaluation.promote(base, cand, coverage={
        "promotion_ok": False, "required_missing": ["flows"],
    })
    assert not decision.promote
    assert any("source coverage" in reason for reason in decision.reasons)
    assert now  # the timestamp is irrelevant to this assertion; keeps the import intentional


def test_coverage_is_exposed_on_the_models_surface():
    js = (ROOT / "weirvern" / "admin" / "web" / "app.js").read_text()
    html = (ROOT / "weirvern" / "admin" / "web" / "index.html").read_text()
    assert routed("/api/ml/coverage"), "the coverage route is not registered"
    assert "renderSourceCoverage" in js and "m-cov" in js
    assert "Source coverage" in html and "m-cov" in html


def test_collect_unwraps_clickhouse_result_rows():
    from types import SimpleNamespace

    from weirvern.models import source_coverage

    class C:
        def query(self, sql, parameters=None):
            if "host_roles" in sql:
                if "GROUP BY" in sql:
                    return SimpleNamespace(result_rows=[("unknown", 85), ("workstation", 64)])
                return SimpleNamespace(result_rows=[("198.51.100.7",)])
            if sql.startswith("SELECT count(), max("):
                return SimpleNamespace(result_rows=[(123, None)])
            return SimpleNamespace(result_rows=[(123,)])

    out = source_coverage.collect(C())
    assert out["sources"][0]["rows"] == 123
    assert out["sources"][0]["state"] == "unknown"  # rows but no readable newest row
    assert out["roles"]["unknown"] == 85
