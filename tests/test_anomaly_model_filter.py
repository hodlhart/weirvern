"""US-5 pins: the anomalies model filter -- exact per-name semantics, both query builders.

The failure this guards: a substring match would let "DBSCAN" collide with any future name
containing it, and the quiet-a-noisy-detector job's whole point is that clicking a registry
row shows THAT detector's alerts and no others.
"""
from __future__ import annotations

from types import SimpleNamespace

from weirvern.admin import status


class _Capture:
    def __init__(self):
        self.sql = ""
        self.params = {}

    def query(self, sql, parameters=None):
        self.sql = sql
        self.params = dict(parameters or {})
        return SimpleNamespace(column_names=[], result_rows=[])


def test_detailed_binds_the_model_exactly():
    c = _Capture()
    status.anomalies_detailed(c, model="DBSCAN")
    assert "splitByChar(',', detected_by_models)" in c.sql, \
        "the filter must split the comma-joined list, not search the raw string"
    assert "trimBoth(m) = %(model)s" in c.sql, \
        "names are stored with a leading space after the comma; trim before comparing"
    assert c.params["model"] == "DBSCAN"


def test_grouped_binds_the_model_exactly():
    c = _Capture()
    status.anomalies_grouped(c, model="Isolation Forest")
    assert "trimBoth(m) = %(model)s" in c.sql
    assert c.params["model"] == "Isolation Forest"


def test_no_model_no_clause():
    c = _Capture()
    status.anomalies_grouped(c)
    assert "model" not in c.params and "splitByChar" not in c.sql, \
        "an absent filter must not touch the query"


def test_the_route_reads_and_passes_the_model_filter():
    """UI seam pin: the route must accept ?model= and hand it to the grouped builder."""
    from pathlib import Path

    src = (Path(__file__).resolve().parents[1] / "weirvern" / "admin" / "web.py").read_text()
    seg = src.split("def _anomalies(self, query: dict) -> None:", 1)[1].split("def ", 1)[0]
    assert 'query.get("model")' in seg, "the route no longer reads ?model="
    assert "model=model_f" in seg, "the route reads ?model= but drops it before the query"
    assert "implausibly long" in seg


def test_grouping_counts_windows_not_detection_passes():
    """Operator, 2026-10-21: two almost-identical rows each read count 1.

    `detected_at` was a GROUP BY key, so two sweeps of the same verdict produced separate rows
    and the count could never rise. It is now MAX(detected_at) only, and n is the number of
    distinct windows -- a re-seen window cannot inflate the count either.
    """
    c = _Capture()
    status.anomalies_grouped(c)
    sql = " ".join(c.sql.split())
    assert "GROUP BY detected_at" not in sql, (
        "detected_at is still a grouping key, so repeated sweeps produce count-1 duplicates"
    )
    assert "max(detected_at) AS detected_at" in sql
    assert "uniqExact(window_start) AS n" in sql
    assert "groupUniqArray(window_start)" in sql
