"""The Models view: model telemetry rendered for an analyst.

WHY THESE TESTS EXIST, given how this project has failed before:

The expensive bugs here have not been crashes. They have been elements that reference
something which does not exist -- a formatter that was never written, a CSS class that is
not in the stylesheet -- which render as an empty box or unstyled text and produce no
error anywhere. On a monitoring surface that is indistinguishable from "nothing to
report", which is the worst possible failure.

So these tests assert the SEAMS: every element id the JS touches exists in the HTML, every
CSS class the JS emits is in the stylesheet, and every function the JS calls is defined.

The other theme is honesty about emptiness. This view was built against a deployment with
THREE anomalies. A chart of three points is easy to mistake for a rendering bug, so each
panel must either draw real data or say in words what is absent. Nothing is padded or
interpolated to look fuller, and the tests check that the empty paths exist rather than
assuming they do.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

WEB = Path(__file__).resolve().parents[1] / "weirvern" / "admin" / "web"
APP_JS = (WEB / "app.js").read_text()
INDEX_HTML = (WEB / "index.html").read_text()
STYLE_CSS = (WEB / "style.css").read_text()


def _js_ids() -> set[str]:
    """Every element id the JS looks up."""
    return set(re.findall(r'getElementById\("([^"]+)"\)', APP_JS))


def _js_query_selectors() -> set[str]:
    return set(re.findall(r'querySelector\("([^"]+)"\)', APP_JS))


def _html_ids() -> set[str]:
    return set(re.findall(r'id="([^"]+)"', INDEX_HTML))


# ── the seams: JS must not reference things that do not exist ────────────────────

# Ids owned by other views, which live in the HTML but are not this view's concern.
# Created by the JS itself at runtime (the error banner), so its absence from the static
# markup is correct. An id that is neither in the markup NOR created in code is the bug.
_JS_CREATED_IDS = set(re.findall(r'attrs:\s*\{\s*id:\s*"([^"]+)"', APP_JS))


def test_every_element_id_the_js_looks_up_exists_in_the_markup():
    missing = sorted(_js_ids() - _html_ids() - _JS_CREATED_IDS)
    assert not missing, (
        f"the JS looks up element id(s) that are not in index.html: {missing}. "
        f"getElementById returns null, so this fails silently at runtime as an empty or "
        f"un-updated box -- exactly how the missing fmtAge and .warn bugs presented."
    )


def _selector_missing(sel: str) -> bool:
    """Whether a simple selector has no counterpart in the markup.

    Only #id and .class selectors are checked; structural selectors are not our business.
    querySelector returns null silently, so a typo here renders as nothing at all.
    """
    if re.fullmatch(r"#[A-Za-z0-9_-]+", sel):
        return sel[1:] not in _html_ids()
    if re.fullmatch(r"\.[A-Za-z0-9_-]+", sel):
        return not re.search(rf"class=\"[^\"]*\b{re.escape(sel[1:])}\b", INDEX_HTML)
    return False


def test_every_query_selector_the_js_uses_exists_in_the_markup():
    """querySelector returns null silently too, so the same check applies."""
    missing = sorted(s for s in _js_query_selectors() if _selector_missing(s))
    assert not missing, f"querySelector target(s) not in the markup: {missing}"


def test_every_css_class_the_models_js_emits_is_styled():
    """A class with no rule renders unstyled -- invisible in review, obvious to a user.

    Every class name in the models code is checked against the stylesheet. Dynamic
    prefixes (built by concatenation) are excluded, because a literal search cannot see
    them -- they are covered by their own test below.
    """
    tail = APP_JS[APP_JS.index("/* ── models ──"):]
    literal = set(re.findall(r'class:\s*"([^"]+)"', tail))
    # `class: "sev-" + severity` yields "sev-": a dynamic prefix, not a real class.
    literal = {c for c in literal if not c.endswith("-")}
    classes: set[str] = set()
    for c in literal:
        classes.update(c.split())
    # Two class names are built dynamically and handled separately.
    classes.discard("sev-")
    missing = sorted(c for c in classes if not re.search(rf"\.{re.escape(c)}\b", STYLE_CSS))
    assert not missing, (
        f"class(es) emitted by the models JS with no CSS rule: {missing}. "
        f"These render as unstyled text with no error."
    )


def test_the_severity_classes_used_dynamically_all_exist():
    """`class: "sev-" + sev` cannot be found by a literal search, so the four values the
    backend can produce are checked against the stylesheet explicitly."""
    for sev in ("low", "medium", "high", "critical"):
        assert re.search(rf"\.sev-{sev}\b", STYLE_CSS), (
            f".sev-{sev} is emitted for that severity but has no CSS rule"
        )


def test_every_function_the_models_code_calls_is_defined():
    """An undefined function is a ReferenceError that kills the whole view."""
    tail = APP_JS[APP_JS.index("/* ── models ──"):]
    # Only calls written as a bare statement -- `foo(` not `x.foo(` -- can be OUR
    # functions. A dotted call is a method on an object (element.appendChild, Math.floor),
    # and a built-in is not ours to define. Checking those produced a list of 20 false
    # positives, which is worse than no check: it hides the real one.
    # Strip object-literal KEYS first: `run(` inside `{ run(...) {} }` and a doc word like
    # `score(` appear in text that is not a call. Removing quoted strings and then
    # requiring the name not to be preceded by `{`/`,`/`"` leaves genuine calls.
    cleaned = re.sub(r"`[^`]*`", '``', tail)   # template literals hold prose
    cleaned = re.sub(r'"[^"\n]*"', '""', cleaned)
    cleaned = re.sub(r"'[^'\n]*'", "''", cleaned)
    called = set(re.findall(r"(?<![.\w{,])[\s,;(]?([a-z][A-Za-z0-9_]*)\(", cleaned))
    defined = set(re.findall(r"function\s+([A-Za-z0-9_]+)", APP_JS))
    defined |= set(re.findall(r"(?:const|let|var)\s+([A-Za-z0-9_]+)\s*=", APP_JS))
    keywords = {"if", "for", "while", "switch", "catch", "function", "return", "typeof",
                "new", "of", "in", "do", "else", "try", "await", "async", "yield"}
    # Names that are genuinely global in a browser and never defined by us.
    globals_ok = {"fetch", "encodeURIComponent", "parseInt", "parseFloat", "alert",
                  "setTimeout", "clearTimeout", "requestAnimationFrame"}
    suspicious = sorted(c for c in called
                        if c not in defined and c not in keywords and c not in globals_ok)
    assert not suspicious, (
        f"the models code calls function(s) that are never defined: {suspicious}. "
        f"This is how fmtAge was previously invented -- the call would throw and the "
        f"panel would stay blank."
    )


# ── the models view must be reachable and load on demand ─────────────────────────

def test_the_models_tab_and_section_exist_and_are_paired():
    assert 'data-view="models"' in INDEX_HTML, "no Models tab"
    assert 'id="view-models"' in INDEX_HTML, "no Models section"
    # showView matches "view-" + name, so a mismatched pair shows nothing at all.
    assert re.search(r'data-view="models"', INDEX_HTML) and \
           re.search(r'id="view-models"', INDEX_HTML)


def test_switching_to_models_loads_its_data():
    """showView loads anomalies on demand; models must be wired the same way or the tab
    renders permanently blank until an unrelated refresh."""
    body = APP_JS[APP_JS.index("function showView"):]
    body = body[:body.index("\n}")]
    assert re.search(r'name === "models"', body), "showView does not load the models view"
    assert "loadModels()" in body


def test_the_models_view_handles_being_unavailable_without_breaking_its_siblings():
    """The endpoint returns available:false rather than 503, so the surrounding panels
    survive. The JS must render the reason instead of throwing."""
    assert re.search(r'if\s*\(!data\s*\|\|\s*!data\.available\)', APP_JS), (
        "loadModels does not check availability, so an unavailable payload would throw"
    )
    assert "data.reason" in APP_JS or "(data && data.reason)" in APP_JS, (
        "the unavailable path does not surface the reason, so an operator sees a blank "
        "panel with no explanation"
    )


# ── the backend query layer ─────────────────────────────────────────────────────

class FakeClient:
    """A ClickHouse client that records queries and returns canned rows per substring."""

    def __init__(self, rows_for: dict[str, list]) -> None:
        self.queries: list[str] = []
        self.rows_for = rows_for

    def query(self, sql: str, parameters=None):  # noqa: ANN001, ANN201
        self.queries.append(sql)
        for key, rows in self.rows_for.items():
            if key in sql:
                return type("R", (), {"result_rows": rows})()
        return type("R", (), {"result_rows": []})()


def _status_module():
    from weirvern.admin import status
    return status


def test_model_overview_parses_the_training_history():
    rows = [
        ("Isolation Forest", None, 360, 1.0, '{"n": 1}'),
        ("Isolation Forest", None, 9496, 1.2, '{"n": 2}'),
        ("DBSCAN", None, 281, 1.0, "{}"),
    ]
    client = FakeClient({"ml_models": rows})
    out = _status_module().model_overview(client, hours=72)
    assert out["available"] is True
    assert out["run_count"] == 3, "training runs were not counted"
    assert len(out["training_history"]["Isolation Forest"]) == 2
    assert out["training_history"]["Isolation Forest"][0]["n"] == 360


def test_model_overview_returns_a_reason_not_an_exception_on_failure():
    """A panel must never take down the page around it."""
    class Boom:
        def query(self, *_a, **_k):
            raise RuntimeError("clickhouse is down")

    out = _status_module().model_overview(Boom())
    assert out["available"] is False
    assert "clickhouse is down" in out["reason"], "the reason was swallowed"


def test_model_overview_survives_malformed_feature_contributions():
    """feature_contributions is a String holding JSON. A malformed value must degrade,
    not raise -- one bad row should not blank the whole panel."""
    rows = [(
        0.5, 0.4, 0.3, 0.2, 0.1, 0.5, "Isolation Forest", "low",
        "total_bytes", 1.0, None, "203.0.113.9",
        "NOT JSON{{{",
    )]
    client = FakeClient({"netflow_anomalies": rows})
    out = _status_module().model_overview(client, hours=72)
    assert out["available"] is True
    assert out["feature_deviations"] == []
    assert len(out["points"]) == 1, "the good fields were discarded along with the bad one"


def test_model_overview_aggregates_feature_deviation_z_scores():
    contrib_a = json.dumps({"total_bytes": {"z": 2.0}, "unique_dst_ips": {"z": 1.0}})
    contrib_b = json.dumps({"total_bytes": {"z": 4.0}})
    rows = [
        (0.9, 0.9, 0.9, 0.9, 0.9, 1.0, "Isolation Forest", "high", "total_bytes",
         3.0, None, "203.0.113.1", contrib_a),
        (0.8, 0.8, 0.8, 0.8, 0.8, 1.0, "Gradient Boosting", "medium", "total_bytes",
         2.0, None, "203.0.113.2", contrib_b),
    ]
    client = FakeClient({"netflow_anomalies": rows})
    out = _status_module().model_overview(client, hours=24)
    by_name = {r["feature"]: r for r in out["feature_deviations"]}
    assert by_name["total_bytes"]["n"] == 2
    # mean of |2| and |4| is 3
    assert by_name["total_bytes"]["mean_abs_z"] == pytest.approx(3.0)
    # the PEAK is kept separately: an average of 3.0 would hide a single 4.0 spike
    assert by_name["total_bytes"]["max_abs_z"] == pytest.approx(4.0)
    assert by_name["unique_dst_ips"]["n"] == 1


def test_model_overview_counts_which_models_fired_together():
    rows = [
        (0.9, 0, 0, 0, 0, 0.5, "Isolation Forest,Gradient Boosting", "low",
         "x", 1.0, None, "198.51.100.1", ""),
        (0.9, 0, 0, 0, 0, 0.5, "Isolation Forest", "low", "x", 1.0, None, "198.51.100.2", ""),
    ]
    client = FakeClient({"netflow_anomalies": rows})
    out = _status_module().model_overview(client, hours=24)
    assert out["model_counts"]["Isolation Forest"] == 2
    assert out["model_counts"]["Gradient Boosting"] == 1
    assert out["points"][0]["models"] == ["Isolation Forest", "Gradient Boosting"]


def test_the_api_payload_keeps_addresses_and_adds_names():
    """The IP is the fact, the name is the convenience. Both must be present."""
    from weirvern.admin import web_api

    data = {
        "available": True, "hours": 24, "run_count": 2,
        "training_history": {}, "scores": {}, "model_counts": {},
        "feature_deviations": [],
        "points": [{"score": 0.9, "agreement": 1.0, "severity": "high",
                    "models": ["Isolation Forest"], "primary": "total_bytes",
                    "magnitude": 3.0, "src_addr": "203.0.113.42"}],
    }
    out = web_api.models_payload(data)
    assert out["available"] is True
    pt = out["points"][0]
    assert pt["src_addr"] == "203.0.113.42", "the raw address was dropped, losing the fact"
    assert "hostname" in pt, "the display name was not added"
    assert "summary" in out and out["summary"], "no plain-language summary was produced"


def test_the_api_payload_passes_the_unavailable_reason_through():
    from weirvern.admin import web_api

    out = web_api.models_payload({"available": False, "reason": "clickhouse is down"})
    assert out["available"] is False
    assert out["reason"] == "clickhouse is down"


def test_the_summary_distinguishes_no_runs_from_no_anomalies():
    """These need different words on screen: one is a healthy quiet window, the other is
    a detector that has never trained."""
    from weirvern.admin import web_api

    quiet = web_api.models_payload({
        "available": True, "hours": 24, "run_count": 5, "training_history": {},
        "scores": {}, "model_counts": {}, "feature_deviations": [], "points": [],
    })
    assert "5 training run" in quiet["summary"]
    assert "no anomalies" in quiet["summary"]

    never = web_api.models_payload({
        "available": True, "hours": 24, "run_count": 0, "training_history": {},
        "scores": {}, "model_counts": {}, "feature_deviations": [], "points": [],
    })
    assert "No training runs" in never["summary"], (
        "a detector that has never trained reads the same as a quiet window"
    )


def test_the_models_route_is_registered():
    web_py = (Path(__file__).resolve().parents[1] / "weirvern" / "admin" / "web.py").read_text()
    assert '"/api/models"' in web_py, "no route for /api/models"
    assert "def _models(" in web_py, "the route has no handler"
    assert "models_payload" in web_py, "the handler does not serialise through web_api"


def test_the_models_route_does_not_require_the_health_probe_path_to_change():
    """The liveness probe must stay independent of ClickHouse. A regression here would
    restart the GUI whenever the database is slow, hiding the real problem."""
    web_py = (Path(__file__).resolve().parents[1] / "weirvern" / "admin" / "web.py").read_text()
    # ANCHORED ON THE ROUTE DISPATCH LINE, not the bare path string: "/api/healthz" now also
    # appears in the READ_EXEMPT tuple near the top of the file, so `index('"/api/healthz"')`
    # sliced from there and the assertion read unrelated prose (the GuiContext docstring).
    # The dispatch line is unique to the healthz branch of _route.
    healthz = web_py[web_py.index('if path == "/api/healthz":'):]
    healthz = healthz[:healthz.index("_error(404")]
    # Assert on the CODE, not the surrounding prose: the comment legitimately names
    # ClickHouse to explain why it is not used. Strip comments, then look for a query.
    body = "\n".join(ln.split("#")[0] for ln in healthz.splitlines())
    assert "query" not in body and "_with_client" not in body, (
        "the liveness probe now touches the database, so a slow database would restart "
        "the GUI and hide the real problem"
    )


# ── the ATT&CK block, which is part of the same "explain what was measured" contract ──

def test_the_anomalies_table_has_a_header_for_every_cell():
    """The technique column was added to the renderer; a missing <th> misaligns the whole
    table silently, because HTML does not complain about a row wider than its header."""
    # The table moved to #anomalies-table when the Overview tab was removed. The assertion
    # follows it: a table that stops being checked is a table that drifts.
    html = (WEB / "index.html").read_text()
    m = re.search(r'<table id="anomalies-table">.*?<thead>(.*?)</thead>', html, re.S)
    assert m, "the anomalies table was not found"
    headers = len(re.findall(r"<th", m.group(1)))

    app = (WEB / "app.js").read_text()
    region = app[app.index('querySelector("#anomalies-table tbody")'):]
    # The row is one `tbody.appendChild(el("tr", {...}, [ ...cells... ]));`, so the cells belong to
    # the span between the tr opening and the array's close.
    region = region[region.index('el("tr"'):]
    # The boundary is the ROW's OWN array close (4-space indent). It used to be a 6-space
    # closer that happened to be the next tiles array; TH-5 shortened that neighbour and the
    # old boundary walked 8k chars into unrelated renderers. Pin the row's own close.
    region = region[:region.index("\n    ]));")]
    cells = region.count('el("td"')
    # The empty-state row must span the same width, or the "no anomalies" message sits under a
    # header it does not fill.
    empty = re.search(r"emptyRow\(tbody, (\d+), note", app)   # the action argument is optional (BF-8)
    assert empty and int(empty.group(1)) == headers, (
        f"the empty-state row spans {empty.group(1) if empty else '?'} columns but the table has "
        f"{headers} headers"
    )
    assert headers == cells, (
        f"{headers} header cells but {cells} data cells -- the table would render misaligned"
    )


def test_the_technique_block_renders_evidence_not_just_the_id():
    """A bare MITRE ID is not checkable. The block must show the measurements that produced
    it, the confidence, and what a network sensor can see for that technique."""
    app = (WEB / "app.js").read_text()
    for field in ("attack_techniques", "t.evidence", "t.confidence", "t.network_visibility"):
        assert field in app, f"the GUI does not render {field}"


def test_the_gui_shows_an_explicit_absence_instead_of_hiding_the_attack_section():
    """The section is a product surface, not a conditional extra.

    Operator, 2026-10-20: "I am not seeing mitre attack frame work when I select an anomaly."
    Drawing nothing made the feature invisible. The stable section must say no network-observable
    technique was supported AND that this is not a benign verdict -- an empty frame is still a
    clearance, so the sentence carries the meaning.
    """
    app = (WEB / "app.js").read_text()
    region = app[app.index("parseTechniques(d.anomaly.attack_techniques)"):]
    region = region[:2200]
    assert "if (techs.length)" in region, (
        "the technique rows are not guarded by a non-empty list"
    )
    assert "No technique in the network-observable ATT&CK set" in region, (
        "the evidence page hides ATT&CK when nothing matched; the operator cannot tell a "
        "missing feature from a missing technique"
    )
    assert "not a benign verdict" in region, (
        "the absence state must not read as an all-clear"
    )


def test_malformed_technique_json_does_not_blank_the_evidence_view():
    """The techniques ride in a String column. A parse failure must degrade the technique
    block, not throw and take out the evidence the analyst opened the page for."""
    app = (WEB / "app.js").read_text()
    assert "function parseTechniques" in app
    region = app[app.index("function parseTechniques"):]
    region = region[:500]
    assert "catch" in region, "parseTechniques does not guard against malformed JSON"
    assert "return []" in region, "a parse failure must yield an empty list, not throw"
