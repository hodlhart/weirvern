"""Contracts for the Assets inventory and the Network connection graph.

WHY THIS FILE EXISTS. These two views span an HTML file, two JavaScript files, a Python
module, and three routes, and every seam between them is a place where the feature can be
"implemented" and still do nothing:

  * an element id referenced by JS but absent from index.html (a silent no-op -- the handler
    binds to null and the control does nothing forever),
  * a JS file added to index.html but NOT to STATIC_FILES (the browser 404s and the whole view
    is dead while the page loads fine),
  * a route added to _route but with no handler, or a handler reading a query parameter the
    frontend never sends,
  * a payload key the backend produces but the frontend reads under a different name.

None of these raise. The page renders, the tab clicks, and the panel stays empty -- the exact
"empty looks like a quiet network" failure this project has already shipped more than once, so
the seams are pinned here rather than trusted.

These are STATIC tests: they read the shipped files. That is deliberate, because every defect
above is a property of the source rather than of one execution, and because they must run in CI
without a browser or a cluster.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

WEB = Path(__file__).resolve().parent.parent / "weirvern" / "admin" / "web"

APP_JS = (WEB / "app.js").read_text()
SOC_JS = (WEB / "soc.js").read_text()
ASSETS_JS = (WEB / "assets.js").read_text()
INDEX = (WEB / "index.html").read_text()

# Comments are stripped before scanning. An earlier version of a sibling test matched a class
# name inside a comment and reported a false positive; stripping comments removes the whole
# class of that mistake.
def _code(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"^\s*//.*$", "", text, flags=re.M)


JS_ALL = _code(ASSETS_JS) + _code(APP_JS) + _code(SOC_JS)
INDEX_CODE = re.sub(r"<!--.*?-->", "", INDEX, flags=re.S)


def _ids_in_js(text: str) -> set[str]:
    return set(re.findall(r'getElementById\("([\w-]+)"\)', text)) | set(
        re.findall(r'querySelector\("#([\w-]+)', text)
    )


def _ids_in_html() -> set[str]:
    return set(re.findall(r'id="([\w-]+)"', INDEX_CODE))


# ── the seams that fail silently ────────────────────────────────────────────────────────────


def test_every_element_the_new_views_reach_for_exists_in_the_html():
    """A getElementById that returns null makes the control a permanent no-op."""
    needed = _ids_in_js(_code(ASSETS_JS))
    have = _ids_in_html()
    missing = sorted(n for n in needed if n not in have)
    assert not missing, (
        f"assets.js reaches for elements that index.html does not define: {missing}. "
        f"Every handler on those would bind to null and do nothing, with no error anywhere."
    )


def test_the_new_controls_in_the_html_all_have_a_handler():
    """The reverse direction: a control with no listener is a control that does nothing."""
    # Controls this view owns; each must be wired in app.js (the DOMContentLoaded block).
    controls = [
        "as-search", "as-sort", "as-hours", "as-reload",
        "nw-hours", "nw-reload", "nw-clear", "nw-min", "nw-labels",
    ]
    have = _ids_in_html()
    for cid in controls:
        assert cid in have, f"#{cid} is wired in JS but missing from index.html"
        assert f'"{cid}"' in APP_JS, (
            f"#{cid} exists in the HTML but nothing in app.js references it -- "
            f"the control would render and do nothing"
        )


def test_both_new_scripts_are_served_by_the_static_allow_list():
    """A script tag without an allow-list entry is a 404, and the view is dead."""
    from weirvern.admin.web import STATIC_FILES

    for name in ("app.js", "soc.js", "assets.js"):
        assert f"/{name}" in STATIC_FILES, (
            f"/{name} is not in STATIC_FILES. index.html loads it, so the browser would 404 "
            f"and every view defined in it would be missing with no server-side error."
        )
        assert f'src="/{name}"' in INDEX, f"index.html does not load /{name}"


def test_the_new_scripts_load_after_the_helpers_they_use():
    """assets.js calls chartFrame/svgEl/el/fmtBytes, which app.js defines.

    Load order is not optional here: these are plain scripts, not modules, so a helper defined
    later is simply undefined at call time. The failure appears only when a panel renders.
    """
    order = [m.group(1) for m in re.finditer(r'<script src="/([\w.]+)"></script>', INDEX)]
    assert "app.js" in order and "assets.js" in order, f"script tags not found in index.html: {order}"
    assert order.index("app.js") < order.index("assets.js"), (
        "assets.js must load after app.js: it calls the shared chart helpers, and a plain "
        "script cannot see a function defined later in a different file"
    )
    for helper in ("chartFrame", "svgEl", "fmtBytes", "chartEmpty", "emptyRow", "renderBars"):
        assert f"function {helper}" in _code(APP_JS) or f"function {helper}" in _code(SOC_JS), (
            f"assets.js uses {helper} but no loaded script defines it"
        )


# ── the routes ──────────────────────────────────────────────────────────────────────────────


def _routes() -> dict[str, str]:
    src = (WEB.parent / "web.py").read_text()
    # path -> handler name, from the `if path == "/api/x": return self._handler(query)` shape.
    # The leading underscore is part of the method name, so the capture must keep it: without
    # it the route is recorded as `assets` and the comparison below fails against `_assets`.
    return dict(re.findall(r'if path == "(/api/[\w/]+)":\s*\n\s*return self\.(_\w+)', src))


def test_the_new_routes_are_registered_and_have_handlers():
    routes = _routes()
    assert routes, "no routes were extracted -- the parser has drifted from web.py"
    for path, handler in (
        ("/api/assets", "_assets"),
        ("/api/graph", "_graph"),
        ("/api/zeeklog", "_zeeklog"),
        ("/api/flows", "_flows"),
    ):
        assert routes.get(path) == handler, (
            f"{path} is not routed to {handler}; found {routes.get(path)!r}"
        )


def test_every_route_method_actually_exists():
    """A route pointing at a missing method raises AttributeError at request time, not at import.

    So the page loads, the tab clicks, and the panel fails with a 500 that the operator reads as
    a data problem.
    """
    src = (WEB.parent / "web.py").read_text()
    defined = set(re.findall(r"^\s+def (_\w+)\(", src, re.M))
    missing = sorted(
        f"{path} -> {handler}" for path, handler in _routes().items() if handler not in defined
    )
    assert not missing, f"routes point at methods that are not defined: {missing}"


def test_the_route_paths_match_what_the_frontend_fetches():
    """A route and a fetch that disagree give a 404 the panel renders as 'no data'."""
    routed = set(_routes())
    called = set(re.findall(r"`(/api/[\w]+)", ASSETS_JS))
    assert called, "assets.js fetches no /api path -- the regex or the code has changed"
    for path in called:
        assert path in routed, (
            f"assets.js fetches {path} but web.py has no route for it. The fetch would 404 and "
            f"the panel would render as empty rather than as broken."
        )


def test_each_new_route_validates_its_input_before_querying():
    """The handlers must reject bad input rather than pass it into a query.

    `/api/zeeklog` is the one that matters most: its log label selects a TABLE NAME, so an
    unvalidated value would be interpolated into SQL. The check is that the handler resolves
    the label through ZEEK_LOGS rather than using it directly.
    """
    src = (WEB.parent / "web.py").read_text()
    i = src.find("def _zeeklog")
    assert i > 0, "_zeeklog handler not found"
    body = src[i : i + 1800]
    assert "ZEEK_LOGS" in body, (
        "the log label must be resolved through soc.ZEEK_LOGS, not interpolated into the SQL: "
        "the table name reaches an f-string in soc.zeek_log_hosts"
    )
    assert "allowed.get(label)" in body, "the label is not looked up in the allow-list"

    j = src.find("def _graph")
    graph = src[j : j + 1800]
    assert "too many hosts" in graph, "the tracked-host list must be capped"
    assert "does not look like an address" in graph, "tracked hosts must be validated"


def test_soc_refuses_a_label_and_table_that_disagree():
    """The second check, inside the query module, is the backstop for the first."""
    from weirvern.admin import soc

    with pytest.raises(ValueError):
        soc.zeek_log_hosts(client=None, table="flows", label="conn", hours=24)


def test_the_dhcp_address_column_is_not_assumed_to_be_src_addr():
    """zeek_dhcp has no src_addr. Assuming one is a bug already shipped twice in this project."""
    from weirvern.admin import soc

    assert soc._ADDR_COLUMN.get("zeek_dhcp") == "client_addr", (
        "zeek_dhcp keys its peers as client_addr/server_addr; src_addr does not exist in that "
        "table, and this exact assumption made the Zeek feature query return nothing at all"
    )


# ── the contract with the payload ───────────────────────────────────────────────────────────


def test_the_frontend_reads_the_keys_the_backend_actually_sends():
    """A renamed payload key is a silently empty panel."""
    import inspect

    from weirvern.admin import assets

    inv_src = inspect.getsource(assets.asset_inventory)
    for key in ('"addr"', '"name"', '"bytes"', '"flows"', '"dst_count"', '"services"',
                '"anomalies"', '"last_seen"'):
        assert key in inv_src, f"asset_inventory no longer produces {key}"
        # The renderer must read the same name.
        assert key.strip('"') in ASSETS_JS, f"assets.js never reads {key.strip(chr(34))}"

    graph_src = inspect.getsource(assets.connection_graph)
    for key in ('"nodes"', '"edges"', '"truncated"', '"total_edges"', '"degree"'):
        assert key in graph_src, f"connection_graph no longer produces {key}"
        assert key.strip('"') in ASSETS_JS, f"assets.js never reads {key.strip(chr(34))}"


def test_the_about_tab_is_gone_and_its_facts_survive_elsewhere():
    """User directive: remove the About tab -- without losing what it documented."""
    assert "view-about" not in INDEX, "the About tab was not removed"
    assert 'data-view="about"' not in INDEX, "the About tab button is still in the nav"

    readme = (WEB.parent.parent.parent / "README.md").read_text()
    # The two facts it carried must still be documented somewhere the operator can find them.
    assert "WEIRVERN_REVERSE_DNS" in readme, (
        "the reverse-DNS behaviour (private-only by default, 'all' to include public) was "
        "documented only in the About tab and is now gone from the README too"
    )
    assert "Read-only by design" in readme, (
        "the read-only / no-lifecycle-controls design decision is no longer documented"
    )


def test_the_network_view_can_track_multiple_hosts():
    """The user's requirement: select ANY NUMBER of hosts and track only their connections."""
    assert "tracked" in ASSETS_JS, "assets.js has no tracked-host state"
    assert "toggleTracked" in ASSETS_JS, "there is no way to add a host to the selection"
    # The selection must be a LIST sent to the server, not a single host.
    assert re.search(r"hosts\.map\(\(h\) => `&host=", ASSETS_JS), (
        "the tracked hosts must be sent as repeated &host= parameters (a set), not one host"
    )
    src = (WEB.parent / "web.py").read_text()
    assert 'query.get("host")' in src, "the route does not read repeated host parameters"


def test_the_graph_reports_when_it_truncated():
    """A capped graph that does not say so looks complete."""
    import inspect

    from weirvern.admin import assets

    src = inspect.getsource(assets.connection_graph)
    assert '"truncated"' in src, "connection_graph does not report truncation"
    assert "truncated" in ASSETS_JS, "the graph view ignores the truncation flag"

# ── the Netflow click-through ──────────────────────────────────────────────────────────────


def test_the_netflow_port_and_protocol_charts_are_clickable():
    """User requirement: BOTH zeek and netflow need to be clickable.

    The talkers and spread charts already drilled down; ports and protocols did not, which left
    the two charts an analyst most wants to enter as dead ends.
    """
    code = _code(SOC_JS)
    for chart in ("nf-proto", "nf-ports"):
        i = code.find(f'renderBars("{chart}"')
        assert i > 0, f"{chart} is not rendered -- update this test"
        call = code[i : code.index("});", i)]
        assert "onClick" in call, (
            f"{chart} has no onClick, so its bars are decoration. Both directions are needed: "
            f"a protocol bar and a port bar must both lead into the underlying flows."
        )
        assert "loadFlowDetail" in call, f"{chart} does not call the drill-down"


def test_the_flow_drilldown_demands_a_filter_and_the_route_enforces_it():
    """An unfiltered request would be a full-table scan behind one bar click."""
    from weirvern.admin import soc

    d = soc.flows_matching(client=None, hours=24)
    assert d["available"] is False, "an unfiltered flow query must refuse rather than scan"
    assert "port or a protocol" in d["reason"]

    src = (WEB.parent / "web.py").read_text()
    i = src.find("def _flows")
    assert i > 0, "_flows handler not found"
    body = src[i : i + 1400]
    assert "port or proto is required" in body, "the route does not require a filter"


def test_the_flow_drilldown_reports_truncation_and_the_total():
    """A capped list that does not say it was capped looks complete."""
    import inspect

    from weirvern.admin import soc

    src = inspect.getsource(soc.flows_matching)
    for key in ("total_pairs", "total_flows", "truncated"):
        assert key in src, f"flows_matching does not report {key}"
    assert 'truncated' in ASSETS_JS, "the view ignores the truncation flag"
    assert "total_pairs" in ASSETS_JS, "the view does not report how many pairs exist"


def test_the_flow_drilldown_excludes_port_zero():
    """Port 0 means 'not recorded' in NetFlow, and including it dominates every real service."""
    import inspect

    from weirvern.admin import soc

    src = inspect.getsource(soc.flows_matching)
    # top_ports documents this; flows_matching must not silently reintroduce the problem.
    assert "dst_port = %(port)s" in src, "the port filter is not applied literally"
    assert "dst_port > 0" in inspect.getsource(soc.top_ports), (
        "top_ports must keep excluding port 0"
    )

# ── the graph's click result: source and destination ───────────────────────────────────────


def test_edges_carry_ports_and_a_time_range():
    """The user clicked the graph and could not tell what a connection WAS.

    "A talked to B" is not actionable without the port and since when -- and the detail panel
    exists precisely to answer that, so the edge has to carry it.
    """
    import inspect

    from weirvern.admin import assets

    src = inspect.getsource(assets.connection_graph)
    assert "dst_port" in src, (
        "the edge query does not select dst_port, so the detail panel cannot say which service "
        "a connection is"
    )
    for key in ("ports", "first_seen", "last_seen"):
        assert key in src, f"connection_graph does not put {key!r} on the edge"
        assert key in ASSETS_JS, f"assets.js never reads the edge's {key!r}"


def test_edges_carry_both_endpoint_names_so_a_row_needs_no_join():
    import inspect

    from weirvern.admin import assets

    src = inspect.getsource(assets.connection_graph)
    assert '"source_name"' in src and '"target_name"' in src, (
        "the edge does not carry its endpoint names, so the panel would have to look them up "
        "and the name could disagree with the node's"
    )


def test_clicking_a_node_opens_data_before_it_toggles_tracking():
    """Clicking used to toggle a filter only, which the user could not infer from the screen.

    The click must lead with the answer (what this host talks to), and tracking must become an
    explicit action rather than the silent effect of a click.
    """
    code = _code(ASSETS_JS)
    i = code.find("function showNodeDetail")
    assert i > 0, "there is no node detail renderer"
    body = code[i : code.find("\nfunction ", i + 10)]
    assert "outbound" in body and "inbound" in body, (
        "the node detail does not separate direction, so a server answering everything would "
        "bury its own few outbound flows"
    )
    # And the node's click must open the panel, not change the selection.
    j = code.find('g.addEventListener("click"')
    assert j > 0, "the node click handler is gone"
    handler = code[j : j + 120]
    assert "showNodeDetail" in handler, (
        f"clicking a node does not open the detail panel: {handler!r}"
    )
    assert "toggleTracked" not in handler, (
        "clicking a node still toggles tracking directly, which is the behaviour the user "
        "reported as not understanding"
    )


def test_the_edges_have_a_clickable_target():
    """A 0.6-3px line is not a realistic pointer target, so the edges would be decorative."""
    code = _code(ASSETS_JS)
    assert "edge-hit" in code, (
        "there is no widened hit-line under the drawn edges, so clicking a specific connection "
        "is impractical"
    )
    css = (WEB / "style.css").read_text()
    assert ".edge-hit" in css, "the hit-line class has no styling (it would not be clickable)"
    assert "pointer" in css[css.find(".edge-hit") : css.find(".edge-hit") + 200], (
        "the hit-line has no pointer cursor, so it does not look clickable"
    )


def test_the_detail_panel_shows_the_address_alongside_the_name():
    """Standing directive: a name is never shown INSTEAD of the address."""
    code = _code(ASSETS_JS)
    i = code.find("function label(")
    assert i > 0, "the label helper is gone"
    body = code[i : i + 220]
    assert "name ?" in body and "addr" in body, (
        f"label() does not fall back to the address when there is no name: {body!r}"
    )
    # The panel must render the raw address as well as the label.
    assert 'pair-addr' in code, "the source/destination card does not show a bare address"


def test_clicking_an_edge_shows_that_pair_not_the_whole_host():
    """The two clicks answer different questions and must not render the same panel."""
    code = _code(ASSETS_JS)
    assert "function showEdgeDetail" in code and "function showNodeDetail" in code, (
        "edge and node clicks must have separate renderers"
    )
    edge = code[code.find("function showEdgeDetail") : code.find("function showNodeDetail")]
    assert "ports" in edge, "the edge detail does not mention the ports"
    assert "→" in edge or "&rarr;" in edge, (
        "the edge detail does not render the source→destination relationship visually"
    )
