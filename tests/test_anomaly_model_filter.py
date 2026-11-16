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
    """UI seam pin: the route must accept ?model= and hand it to the grouped builder.

    THE SEAM MOVED when the route crossed to Flask, so the assertion follows both halves: the shared
    parser reads the parameter, and the shared fetcher passes it to the grouped query. An assertion
    on the old handler body would demand the copy stay there and forbid the port.
    """
    from pathlib import Path

    admin = Path(__file__).resolve().parents[1] / "weirvern" / "admin"
    web = (admin / "web.py").read_text()
    parser = web.split("def anomalies_args(", 1)[1].split("\ndef ", 1)[0]
    assert '"model"' in parser, "the route no longer reads ?model="
    assert "implausibly long" in parser
    payloads = (admin / "payloads.py").read_text()
    fetcher = payloads.split("def anomalies(", 1)[1].split("\ndef ", 1)[0]
    assert "model=model" in fetcher, "the route reads ?model= but drops it before the query"


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
    # The visible verdict is the identity; a 0.0005 model-score difference must not split it.
    assert "GROUP BY src_addr, anomaly_score, severity, detected_by_models" in sql
    assert "GROUP BY src_addr, anomaly_score, confidence" not in sql
    assert "isolation_forest_score," not in sql.split("GROUP BY", 1)[1]


def test_the_alert_queue_honours_the_global_time_window():
    """GitHub #54: the header range must reach /api/anomalies.

    The query used to read every anomaly row regardless of the selected range, and the UI's
    API builder never sent `hours` at all. Both halves are pinned: the SQL has the window and
    the route passes the parsed value through.
    """
    c = _Capture()
    status.anomalies_grouped(c, hours=6)
    sql = " ".join(c.sql.split())
    assert "window_start >= %(since)s AND window_start <= %(until)s" in sql
    assert c.params["since"] and c.params["until"]
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    flask_py = (root / "weirvern/admin/flask_app.py").read_text()
    seg = flask_py.split("def anomalies(", 1)[1].split("    @app.", 1)[0]
    assert "web.window_arg(request.args, 24" in seg
    assert "hours=hours" in seg
    app = (root / "weirvern/admin/web/app.js").read_text()
    assert "&hours=${trHours()}" in app
