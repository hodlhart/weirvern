"""The alert-to-evidence pivot.

The gap these tests defend: the UI could say WHAT the model flagged but never show
WHY. `host_detail` answers "what has this host done in 24 hours", which is an
aggregate; an analyst needs the individual records inside the detection's own
window. The anomaly row carried window_start/window_end and nothing read them.

These tests assert the properties that make the pivot trustworthy:

  * the window bounds are the ALERT'S, not a widened range -- showing extra traffic
    would misrepresent what the detector actually scored
  * the queries name columns that exist (the same class as the `total_bytes` bug,
    which silently produced empty panels)
  * a query failure is REPORTED, not rendered as "no evidence"
"""
from __future__ import annotations

import re
from datetime import UTC
from pathlib import Path

import pytest

SCHEMA = Path(__file__).resolve().parent.parent / "weirvern" / "schema" / "001_weirvern.sql"


def _columns_of(table: str) -> set[str]:
    bare = table.split(".")[-1]
    text = SCHEMA.read_text()
    m = re.search(
        rf"CREATE TABLE IF NOT EXISTS\s+`?(?:weirvern\.)?{re.escape(bare)}`?\s*\((.*?)\)\s*ENGINE",
        text, re.S | re.I,
    )
    assert m, f"table {bare} not in the schema"
    cols = set()
    for line in m.group(1).splitlines():
        line = line.strip()
        if not line or line.startswith("--") or line.upper().startswith("INDEX"):
            continue
        name = line.split()[0].strip(",").strip("`")
        if name and not name.startswith((")", "PRIMARY", "ORDER", "PARTITION")):
            cols.add(name)
    return cols


def _sql(func) -> str:
    """SQL string literals only -- comments excluded, so documenting a bug does not
    trip a guard that checks for the bug's identifier."""
    import ast
    import inspect
    import textwrap

    tree = ast.parse(textwrap.dedent(inspect.getsource(func)))
    return " ".join(
        n.value for n in ast.walk(tree)
        if isinstance(n, ast.Constant) and isinstance(n.value, str)
    )


# --- a fake client that records queries ---------------------------------------
class RecordingClient:
    """Returns one row per query so the code paths complete, and records the SQL.

    Rows are padded generously: `zip(strict=True)` in evidence_payload means a
    too-short row would raise, and that is deliberate -- but this fake feeds the
    status layer, which unpacks positionally per query.
    """

    def __init__(self, rows_per_query=0, raise_for=()):
        self.queries: list[tuple[str, dict]] = []
        self.rows_per_query = rows_per_query
        self.raise_for = raise_for

    class _Res:
        def __init__(self, rows):
            self.result_rows = rows

    def query(self, sql, parameters=None):
        self.queries.append((sql, parameters or {}))
        for needle in self.raise_for:
            if needle in sql:
                raise RuntimeError(f"Code: 47. simulated failure for {needle}")
        # A wide row: enough values for every SELECT list in alert_evidence.
        row = tuple(range(20))
        return self._Res([row] * self.rows_per_query)


# --- the window contract ------------------------------------------------------
def test_evidence_scopes_to_the_alerts_own_window():
    """The raw-flow query must be bounded by the ALERT'S window, and must not use
    now() or a caller-supplied hour count. Widening the range would show traffic the
    detector never saw, making the evidence misleading in exactly the case where a
    false positive is being investigated."""
    from weirvern.admin import status

    sql = _sql(status.alert_evidence)
    flows = [q for q in sql.split("SELECT") if "FROM weirvern.flows" in q]
    assert flows, "no flows query found in alert_evidence"
    for q in flows:
        assert "time_flow_start >= %(ws)s" in q, "flow query is not lower-bounded by the window"
        assert "time_flow_start <= %(we)s" in q, "flow query is not upper-bounded by the window"
        assert "INTERVAL" not in q, (
            "the evidence query uses a relative interval rather than the alert's "
            "own window; it must show what the detector scored"
        )


def test_evidence_bounds_every_table_to_the_same_window():
    """Flows, Zeek sessions, DNS and notices must all share the window, or the
    panels show different time ranges under one heading."""
    from weirvern.admin import status

    sql = _sql(status.alert_evidence)
    for table in ("weirvern.zeek_conn", "weirvern.zeek_ssl", "weirvern.zeek_dns",
                  "weirvern.zeek_notice"):
        seg = [q for q in sql.split("SELECT") if table in q]
        assert seg, f"no query against {table}"
        for q in seg:
            assert "%(ws)s" in q and "%(we)s" in q, f"{table} is not window-bounded"


def test_evidence_queries_columns_that_exist():
    """Parses the real schema. This is the check that catches a wrong column name
    BEFORE it becomes an empty panel -- the failure mode behind `total_bytes` and
    `id_orig_h`."""
    from weirvern.admin import status

    sql = _sql(status.alert_evidence)
    needed = {
        "weirvern.flows": ["time_flow_start", "time_flow_end", "dst_addr", "dst_port",
                           "proto", "bytes", "packets", "src_addr"],
        "weirvern.zeek_conn": ["ts", "dst_addr", "dst_port", "proto", "service",
                               "duration", "orig_bytes", "resp_bytes", "conn_state",
                               "src_addr"],
        "weirvern.zeek_ssl": ["ts", "dst_addr", "dst_port", "version", "server_name",
                              "ja4", "ja4_orig", "validation_status", "src_addr"],
        "weirvern.zeek_dns": ["ts", "query", "qtype", "rcode", "answers",
                              "query_entropy", "src_addr"],
        "weirvern.zeek_notice": ["ts", "note", "msg", "actions", "src_addr"],
        "weirvern.netflow_anomalies": ["window_start", "window_end", "anomaly_score",
                                       "severity", "detected_by_models",
                                       "baseline_comparison"],
    }
    for table, cols in needed.items():
        real = _columns_of(table)
        assert table in sql, f"alert_evidence no longer queries {table}"
        for c in cols:
            assert c in real, f"{c} is not a real column on {table}"
            assert c in sql, f"{table}.{c} is not referenced by alert_evidence"


def test_flows_duration_is_computed_not_selected():
    """`flows` has no duration column, so it must be derived. Selecting a
    non-existent duration_ms is precisely the bug class this file exists for.

    Checks for a BARE reference: `duration_ms` is fine as an alias of a computed
    expression (`... AS duration_ms`), but not as a selected column. An earlier
    version of this test used a substring match and flagged the correct
    `AS duration_ms` too.
    """
    from weirvern.admin import status

    sql = _sql(status.alert_evidence)
    assert "dateDiff" in sql, "duration must be computed from the flow timestamps"
    assert "time_flow_end" in sql, "the duration computation needs the flow end time"
    for m in re.finditer(r"duration_ms", sql):
        before = sql[max(0, m.start() - 12):m.start()]
        assert " AS " in before, (
            f"duration_ms appears without an AS alias: ...{sql[max(0, m.start()-60):m.end()+10]!r}"
        )


# --- error reporting ----------------------------------------------------------
def test_a_failing_query_is_recorded_not_hidden():
    """An empty evidence table and a broken query must be distinguishable. Two real
    bugs hid behind 'the panel is just empty'."""
    from weirvern.admin import status

    client = RecordingClient(rows_per_query=0, raise_for=("zeek_dns",))
    out = status.alert_evidence(client, "198.51.100.5", "2026-09-17T16:37:00")
    assert out.get("_errors"), "the failure was swallowed"
    assert "zeek_dns" in out["_errors"]
    assert out["zeek_dns"] == [], "the failed section should be empty, not absent"


def test_anomaly_row_width_matches_the_columns_the_code_indexes():
    """The anomaly lookup is positional. A query that selects fewer columns than the
    mapping indexes raises IndexError inside the guarded lookup, and the page then says
    'no verdict stored' and hides every disposition action -- the exact 2026-10-28 alert
    regression. This fake returns EXACTLY the width the SELECT promises, so a missing
    column cannot be masked by generously padded test data.
    """
    from weirvern.admin import status

    class WidthAwareClient(RecordingClient):
        def query(self, sql, parameters=None):
            self.queries.append((sql, parameters or {}))
            if "FROM weirvern.netflow_anomalies" in sql:
                select = sql.split("SELECT", 1)[1].split("FROM", 1)[0]
                width = len([part for part in select.split(",") if part.strip()])
                return self._Res([tuple(range(width))])
            return self._Res([])

    out = status.alert_evidence(WidthAwareClient(), "198.51.100.5", "2026-09-17T16:37:00")
    assert out.get("anomaly"), "the anomaly lookup failed; the evidence page would lose its verdict"
    assert out["anomaly"]["strong_families"] == 11
    assert out["anomaly"]["severity_basis"] == 12
    assert not (out.get("_errors") or {}).get("anomaly")



def test_evidence_payload_surfaces_errors():
    from weirvern.admin import web_api

    payload = web_api.evidence_payload({
        "src_addr": "198.51.100.5", "flows": [], "zeek_conn": [], "zeek_dns": [],
        "notice": [], "_errors": {"zeek_dns": "Code: 47"},
    })
    assert payload["errors"] == {"zeek_dns": "Code: 47"}, (
        "the API dropped the error; the UI would show an empty panel with no reason"
    )


def test_payload_is_json_serialisable_with_real_datetimes():
    """Timestamps out of ClickHouse are datetime objects, which json.dumps rejects.
    The payload must convert them."""
    import json
    from datetime import datetime

    from weirvern.admin import web_api

    now = datetime(2026, 9, 17, 16, 37, 36, tzinfo=UTC)
    payload = web_api.evidence_payload({
        "src_addr": "198.51.100.5",
        "window_start": now, "window_end": now,
        "flows": [(now, "1.2.3.4", 443, 6, 1234, 9, 12.5)],
        "zeek_conn": [(now, "1.2.3.4", 443, "tcp", "ssl", 1.0, 10, 20, "SF")],
        "zeek_dns": [(now, "example.com", "A", 0, "1.2.3.4", 3.1)],
        "notice": [(now, "Scan::Port_Scan", "msg", "Notice::ACTION_LOG")],
    })
    text = json.dumps(payload)  # must not raise
    back = json.loads(text)
    assert back["flows"][0]["dst_addr"] == "1.2.3.4"
    assert back["zeek_dns"][0]["query"] == "example.com"
    assert back["window_start"]


def test_column_count_mismatch_raises_rather_than_truncating():
    """evidence_payload zips a field list against each row. Without strict=True a
    short row silently loses fields; with it, the bug is loud."""
    from weirvern.admin import web_api

    with pytest.raises(ValueError):
        web_api.evidence_payload({
            "src_addr": "198.51.100.5",
            # Seven field names, five values.
            "flows": [("a", "b", "c", "d", "e")],
        })


# --- routing ------------------------------------------------------------------
def test_evidence_route_is_registered_and_validates_input():
    """The route must exist and must reject a request with no start, since a pivot
    without a window is not a pivot."""
    import inspect

    from weirvern.admin import web

    src = inspect.getsource(web)
    assert '"/api/evidence"' in src, "the evidence route is not registered"
    handler_src = inspect.getsource(web)
    assert "start is required" in handler_src, "a missing window is not rejected"
    assert "addr is required" in handler_src


def test_evidence_route_is_not_in_the_static_allowlist():
    """It must go through the API path, not be served as a file."""
    from weirvern.admin.web import STATIC_FILES

    assert "/api/evidence" not in STATIC_FILES


# --- the frontend actually wires it up ----------------------------------------
def test_frontend_calls_the_evidence_endpoint_with_the_window():
    """A backend endpoint nothing calls is dead code. The row click must pass the
    alert's window, not just the address."""
    js = (Path(__file__).resolve().parent.parent
          / "weirvern" / "admin" / "web" / "app.js").read_text()
    assert "/api/evidence?addr=" in js, "the frontend never calls the evidence API"
    assert "start=" in js and "encodeURIComponent" in js
    assert "window_start" in js, (
        "the frontend does not pass the alert's window_start, so the pivot would "
        "not be scoped to the detection"
    )
    assert "openEvidence" in js


def test_frontend_has_a_view_for_the_evidence():
    html = (Path(__file__).resolve().parent.parent
            / "weirvern" / "admin" / "web" / "index.html").read_text()
    assert 'id="view-evidence"' in html, "no view container for the evidence"
    for table in ("ev-flows", "ev-zeek", "ev-dns"):
        assert f'id="{table}"' in html, f"missing {table} table"


def test_frontend_stat_cells_use_the_classes_the_stylesheet_defines():
    """The CSS defines .stat .v and .stat .k. Using stat-v/stat-k renders unstyled
    and is invisible in a screenshot review."""
    root = Path(__file__).resolve().parent.parent / "weirvern" / "admin" / "web"
    js = (root / "app.js").read_text()
    css = (root / "style.css").read_text()
    assert re.search(r"\.stat\s+\.v\b", css), "stylesheet lost .stat .v"
    assert "stat-v" not in js, "app.js uses a class the stylesheet does not define"
    assert "stat-k" not in js


def test_logo_assets_are_shipped_and_served():
    """The header logo and favicon must exist on disk AND be in the server's
    allow-list, or the dashboard renders a broken image."""
    from weirvern.admin.web import STATIC_DIR, STATIC_FILES

    assert "/logo.svg" in STATIC_FILES, "the logo is not served"
    assert (STATIC_DIR / STATIC_FILES["/logo.svg"][0]).exists(), "logo.svg missing"
    assert "/favicon.svg" in STATIC_FILES, "the vector favicon is not served"
    assert (STATIC_DIR / STATIC_FILES["/favicon.svg"][0]).exists(), "favicon.svg missing"
    # logo.png stays for apple-touch-icon, and /favicon.ico stays for the browsers that
    # ask for it unprompted -- neither may silently vanish.
    assert "/logo.png" in STATIC_FILES and (STATIC_DIR / "logo.png").exists()
    assert "/favicon.ico" in STATIC_FILES, "no favicon route; browsers 404 on every load"
    assert (STATIC_DIR / STATIC_FILES["/favicon.ico"][0]).exists(), "favicon missing"
    html = (STATIC_DIR / "index.html").read_text()
    # THE HEADER WEARS THE README'S MARK (operator, 2026-10-18: "the top left icon on the
    # platform should be the same as the one in the readme"). It is the supplied raster emblem,
    # cropped above the wordmark -- the header already carries the word "Weirvern" beside it, so
    # a second wordmark at 28px would be an illegible smudge. The geometric vector mark stays
    # served (and still parses) but is no longer the chrome's identity: one brand, one source.
    assert 'src="/logo.png"' in html, "the header does not use the README's mark"
    assert 'src="/logo.svg"' not in html, "the retired geometric mark is still in the chrome"
    assert 'href="/apple-touch-icon.png"' in html, "the iOS touch icon is not the README's mark"
    # AN SVG THAT DOES NOT PARSE RENDERS AS THE BROKEN-IMAGE GLYPH (found by looking at the
    # rendered page: an ASCII double hyphen inside a comment makes the XML malformed). The
    # vectors must parse as XML, every byte of them.
    import xml.dom.minidom
    for name in ("logo.svg", "favicon.svg"):
        xml.dom.minidom.parse(str(STATIC_DIR / name))


# --- bugs found only by looking at the rendered page --------------------------
def test_flow_summary_is_labelled_not_a_positional_row():
    """THE BUG: flow_summary was forwarded as the raw ClickHouse tuple. The frontend
    reads summary.bytes, so every field came back undefined and the panel rendered
    "0 BYTES / — PACKETS" while the underlying numbers were correct. A positional row
    must be NAMED before it crosses the API boundary."""
    from weirvern.admin import web_api

    summary = web_api.evidence_payload({
        "src_addr": "198.51.100.5",
        "flow_summary": (3604, 53, 53, 1, 1, "2026-09-17T16:35:23", "2026-09-17T16:39:36"),
    })["flow_summary"]
    assert isinstance(summary, dict), "flow_summary must be a labelled object"
    assert summary["bytes"] == 3604
    assert summary["packets"] == 53
    assert summary["flows"] == 53
    assert summary["unique_destinations"] == 1
    assert summary["unique_ports"] == 1


def test_flow_summary_field_order_matches_the_select():
    """The labels are positional, so the order must match the SELECT in
    status.alert_evidence. Reordering either side without the other would silently
    mislabel the numbers -- worse than showing nothing."""
    import ast
    import inspect
    import textwrap

    from weirvern.admin import status, web_api

    sql = _sql(status.alert_evidence)
    assert "SELECT sum(bytes), sum(packets), count(), uniqExact(dst_addr), " in sql
    assert "uniqExact(dst_port), min(time_flow_start), max(time_flow_start) " in sql

    src = textwrap.dedent(inspect.getsource(web_api._summary))
    fields = ast.literal_eval(
        re.search(r"fields = (\(.*?\))", src, re.S).group(1)
    )
    assert list(fields) == [
        "bytes", "packets", "flows", "unique_destinations", "unique_ports",
        "first_seen", "last_seen",
    ], "the summary labels no longer line up with the SELECT order"


def test_flow_summary_of_wrong_width_is_dropped_not_mislabelled():
    """A row that does not match the field list must be discarded with a warning,
    never zipped into wrong labels."""
    from weirvern.admin import web_api

    assert web_api.evidence_payload(
        {"src_addr": "198.51.100.5", "flow_summary": (1, 2)}
    )["flow_summary"] is None
    assert web_api.evidence_payload({"src_addr": "198.51.100.5"})["flow_summary"] is None


def test_evidence_title_is_not_uppercased():
    """The title holds a hostname; CSS uppercasing turned host-a.example into
    host-a.example, which misrepresents an identifier the operator may need verbatim."""
    css = (Path(__file__).resolve().parent.parent
           / "weirvern" / "admin" / "web" / "style.css").read_text()
    m = re.search(r"#ev-title\s*\{[^}]*\}", css, re.S)
    assert m, "no #ev-title rule; it would inherit the uppercase h2 transform"
    assert "text-transform: none" in m.group(0)
