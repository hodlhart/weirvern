"""Contracts for the Network host sheet, its route, and the map's composable filters.

WHY THIS FILE EXISTS. The host sheet is the answer to "why is this address interesting", and
every failure mode it can have is silent:

  * a section that could not be read and renders as a zero ("no model detections" on a host the
    engine flagged, because the read threw);
  * a window that says 7d while the raw flow source only holds 3.3 days;
  * a ripple count that answers a different window than the header;
  * a filter that looks applied while the map keeps the full population, or a count line whose
    denominator is the already-filtered set ("showing 2 of 2" while one host is hidden);
  * a URL that carries a filter the reload cannot restore.

`tests/jsdom_render.js` drives the rendered behaviour. These tests hold the payload and the
source seams, so a regression names the section or the key that broke instead of one red DOM
check with no location. They are static where the property is a source property and behavioural
where a payload can be built without a cluster.
"""

from __future__ import annotations

import datetime as _dt
import re
from pathlib import Path

from weirvern.admin import network_host, payloads

ROOT = Path(__file__).resolve().parent.parent
WEB = ROOT / "weirvern" / "admin" / "web"
INDEX = (WEB / "index.html").read_text()
INDEX_CODE = re.sub(r"<!--.*?-->", "", INDEX, flags=re.S)
APP_JS = (WEB / "app.js").read_text()
ASSETS_JS = (WEB / "assets.js").read_text()
NORMALIZE_JS = (WEB / "normalize.js").read_text()


def _code(text: str) -> str:
    """The source with its comments removed, so prose about a rule cannot satisfy it."""
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"^\s*//.*$", "", text, flags=re.M)


def _body(source: str, name: str) -> str:
    """The body of a top-level JS function, sliced to the next top-level declaration."""
    start = source.index(f"function {name}(")
    end = source.find("\nfunction ", start + 10)
    return source[start:end if end != -1 else len(source)]


class _Result:
    def __init__(self, rows):
        self.result_rows = rows


class _Client:
    """A ClickHouse stand-in keyed by the table/aggregate each read names.

    `fail` names the sections that must raise, so "the read failed" can be exercised without a
    broken database. Anything unnamed answers an empty successful read.
    """

    def __init__(self, *, fail: tuple[str, ...] = (), addr: str = "192.0.2.40"):
        self.fail = set(fail)
        self.addr = addr
        self.seen: list[str] = []

    def query(self, sql, parameters=None, **_kw):  # noqa: ARG002 - shape of the real client
        self.seen.append(sql)
        key = self._key(sql)
        if key in self.fail:
            raise RuntimeError(f"{key} is unavailable")
        return _Result(self._rows(key, sql))

    @staticmethod
    def _key(sql: str) -> str:
        if "FROM weirvern.host_identity" in sql:
            return "identity"
        if "FROM weirvern.asset_registry" in sql:
            return "asset"
        if "FROM weirvern.host_roles" in sql:
            return "role"
        if "FROM weirvern.zeek_ntlm" in sql:
            return "netbios"
        if "FROM weirvern.zeek_dhcp" in sql:
            return "dhcp_name"
        if "uniqExact(ja4)" in sql:
            return "ja4"
        if "server_name" in sql:
            return "tls"
        if "FROM weirvern.zeek_dns" in sql:
            return "dns"
        if "normal_ripple_signatures" in sql:
            return "normalized"
        if "GROUP BY peer" in sql:
            return "peers"
        if "GROUP BY service" in sql:
            return "services"
        if "src_port AS port" in sql:
            return "listening_ports"
        if "dst_port AS port" in sql:
            return "used_ports"
        if "ORDER BY window_start DESC" in sql:
            return "models"
        if "SELECT severity, count() AS n" in sql:
            return "model_counts"
        if "unique_peer_ips" in sql:
            return "traffic_in_out"
        if "unique_dst_ips" in sql:
            return "traffic_outbound"
        if "weirvern.ml_ripple_evidence" in sql:
            return "coverage:ripple_evidence"
        if "weirvern.netflow_anomalies" in sql and "SELECT min(" in sql:
            return "coverage:netflow_anomalies"
        if "SELECT min(window_start), max(window_start) FROM weirvern.flows_window_endpoint" in sql:
            return "coverage:flows_window_endpoint"
        if "SELECT min(window_start), max(window_start) FROM weirvern.flows_window" in sql:
            return ("seen" if "WHERE src_addr" in sql else "coverage:flows_window")
        return "other"

    def _rows(self, key: str, sql: str):
        ts = _dt.datetime(2026, 11, 20, 9, 0)
        if key == "identity":
            return [('["vault.example", "vault"]', '["t13d1516"]', "aa:bb:cc:dd:ee:ff",
                     "Linux 6", 0.92, "2026-11-20 08:00:00")]
        if key == "asset":
            return [("vault-registry", _dt.datetime(2026, 11, 1),
                     _dt.datetime(2026, 11, 20), "scanned")]
        if key == "role":
            return [("file server", "corp", "operator", 0.8)]
        if key == "netbios":
            return [("VAULT", "CORP", 4)]
        if key == "dhcp_name":
            return [("vault-dhcp", 2)]
        if key == "seen":
            return [(_dt.datetime(2026, 11, 17, 5, 30), _dt.datetime(2026, 11, 20, 9, 0))]
        if key == "traffic_in_out":
            return [("in", 12, 4096, 30, 3, ts, ts),
                    ("out", 8, 2048, 20, 2, ts, ts)]
        if key == "traffic_outbound":
            return [(8, 2048, 20, 2, ts, ts)]
        if key == "peers":
            return [("203.0.113.9", 1000, 2000, 3, 4)]
        if key == "services":
            return [("ssl", 5)]
        if key == "listening_ports":
            return [(443, "tcp", 4)]
        if key == "used_ports":
            return [(53, "udp", 2)]
        if key == "dns":
            return [("example.test", 1, 7)]
        if key == "tls":
            return [("vault.example", 3)]
        if key == "ja4":
            return [(2,)]
        if key == "models":
            return [(ts, "high", 0.91, "LOF,IF", "beacon")]
        if key == "model_counts":
            return [("high", 2), ("low", 1)]
        if key == "normalized":
            return [("dns", "flow", "example.test", ts, "known baseline", ts)]
        if key == "coverage:flows_window":
            return [(_dt.datetime(2026, 11, 12, 13, 50), _dt.datetime(2026, 11, 20, 9, 0))]
        if key == "coverage:flows_window_endpoint":
            return [(_dt.datetime(2026, 11, 17, 5, 30), _dt.datetime(2026, 11, 20, 9, 0))]
        if key == "coverage:ripple_evidence":
            return [(_dt.datetime(2026, 11, 19, 14, 0), _dt.datetime(2026, 11, 20, 9, 0))]
        if key == "coverage:netflow_anomalies":
            return [(_dt.datetime(2026, 11, 10, 0, 0), _dt.datetime(2026, 11, 20, 9, 0))]
        return []


def _patch_optional_sources(monkeypatch, *, ripple_available: bool = True) -> None:
    """Pin reverse DNS and the ripple grouping to documented answers.

    Both are guarded imports inside `host_sheet`; leaving them live would make this file depend
    on the machine's resolver and a real ripple table.
    """
    from weirvern.admin import revdns
    from weirvern.models import ripple_evidence

    monkeypatch.setattr(revdns, "lookup", lambda addr: "vault.example")
    monkeypatch.setattr(
        ripple_evidence, "overview",
        lambda client, hours=24: {
            "available": ripple_available,
            "reason": "" if ripple_available else "ripple evidence not read",
            "window_hours": 24,
            "ripples": [{"host": "192.0.2.40", "severity": "high", "score": 7.11,
                         "window_start": "2026-11-20T08:00:00", "families": ["conn", "dns"],
                         "explanation": "a ripple on 192.0.2.40", "evidence": []}],
        },
    )


# ── the sheet's payload ─────────────────────────────────────────────────────────────────────


def test_the_host_sheet_answers_every_section_for_one_address(monkeypatch):
    _patch_optional_sources(monkeypatch)
    out = network_host.host_sheet(_Client(), "192.0.2.40", hours=24)

    assert out["available"] is True and out["addr"] == "192.0.2.40"
    assert out["window"]["hours"] == 24 and out["window"]["since"] and out["window"]["until"]

    ident = out["identity"]
    assert ident["available"] is True
    assert ident["ptr"] == "vault.example"
    assert ident["hostnames"] == ["vault.example", "vault"], "the JSON name list must be parsed"
    assert ident["ja4"] == ["t13d1516"]
    assert ident["netbios"][0]["name"] == "VAULT"
    assert ident["dhcp_names"][0]["name"] == "vault-dhcp"
    assert ident["role"] == "file server" and ident["scan_state"] == "scanned"

    assert out["traffic"]["in"]["bytes"] == 4096
    assert out["traffic"]["out"]["flows"] == 8
    assert out["traffic"]["available"] is True

    assert out["peers"]["rows"][0]["peer"] == "203.0.113.9"
    assert out["services"]["listening_ports"][0]["port"] == 443
    assert out["services"]["used_ports"][0]["port"] == 53
    assert out["dns"]["queries"][0]["name"] == "example.test"
    assert out["tls"]["names"][0]["name"] == "vault.example"
    assert out["tls"]["ja4_count"] == 2

    assert out["models"]["available"] is True
    assert out["models"]["count"] == 3 and out["models"]["worst"] == "high"
    assert out["models"]["by_severity"] == {"high": 2, "low": 1}

    assert out["ripples"]["available"] is True
    assert out["ripples"]["count"] == 1 and out["ripples"]["worst"] == "high"
    assert out["ripples"]["rows"][0]["explanation"] == "a ripple on 192.0.2.40"

    assert out["normalized"]["available"] is True and out["normalized"]["count"] == 1
    assert out["coverage"]["flows_window_endpoint"]["from"] == "2026-11-17T05:30:00"
    assert out["errors"] == {}


def test_a_failed_section_is_unavailable_and_never_reported_as_zero(monkeypatch):
    """`unknown` and `zero` are different facts; a failed read must not become "nothing there"."""
    _patch_optional_sources(monkeypatch, ripple_available=False)
    client = _Client(fail=("identity", "traffic_in_out", "traffic_outbound", "dns",
                           "models", "model_counts", "normalized"))
    out = network_host.host_sheet(client, "192.0.2.40", hours=24)

    assert out["available"] is True, "one failed section must not take the sheet down"
    for section, flag in (("identity", "available"), ("dns", "available"),
                          ("models", "available"), ("normalized", "available"),
                          ("traffic", "available")):
        assert out[section][flag] is False, f"{section} claimed a successful read it did not have"
        assert out[section]["reason"], f"{section} failed without naming why"

    # The sections that DID answer are still readable: nothing zeroed them on a neighbour's failure.
    assert out["peers"]["available"] is True
    assert out["services"]["available"] is True
    # Ripple availability follows the grouping, not the fact that no row matched this host.
    assert out["ripples"]["available"] is False
    assert out["ripples"]["reason"] == "ripple evidence not read"
    assert out["errors"], "the sheet must carry the section failures for the operator"


def test_coverage_names_what_each_source_actually_holds(monkeypatch):
    """A 7d request against 3.3d of raw flows is a 3.3d reading labelled 7d unless it says so."""
    _patch_optional_sources(monkeypatch)
    out = network_host.host_sheet(_Client(), "192.0.2.40", hours=168)

    assert out["window"]["hours"] == 168
    cov = out["coverage"]
    assert cov["flows_window_endpoint"]["from"] == "2026-11-17T05:30:00"
    assert cov["flows_window"]["from"] == "2026-11-12T13:50:00"
    assert cov["ripple_evidence"]["from"] == "2026-11-19T14:00:00"
    assert cov["netflow_anomalies"]["from"] == "2026-11-10T00:00:00"
    # The ripple grouping answers its OWN held window, never the requested one.
    assert out["ripples"]["window_hours"] == 24
    assert out["ripples"]["window_hours"] != out["window"]["hours"], (
        "a one-day ripple history answering a 7d request must not be labelled 7d"
    )


def test_coverage_that_could_not_be_read_says_unknown_not_zero(monkeypatch):
    _patch_optional_sources(monkeypatch)
    client = _Client(fail=("coverage:flows_window_endpoint",))
    out = network_host.host_sheet(client, "192.0.2.40", hours=24)
    block = out["coverage"]["flows_window_endpoint"]
    assert block["from"] == "" and block["to"] == ""
    assert "flows_window_endpoint" in block["reason"] or block["reason"]


def test_the_failure_shape_marks_every_section_unavailable():
    out = network_host.host_sheet_failure(RuntimeError("clickhouse is down"),
                                          addr="192.0.2.40", hours=6)
    assert out["available"] is False
    assert out["addr"] == "192.0.2.40" and out["window"]["hours"] == 6
    for section in ("identity", "traffic", "peers", "services", "dns", "tls",
                    "models", "ripples", "normalized"):
        assert out[section]["available"] is False, f"{section} survived a failed sheet as readable"
        assert out[section]["reason"], f"{section} is unavailable without a reason"
    assert out["errors"]


def test_the_payload_wrapper_returns_the_failure_shape_rather_than_raising(monkeypatch):
    """A section read is guarded; a failure OUTSIDE those guards is the sheet's failure shape."""
    from weirvern.admin import timewindow

    def boom(hours):
        raise RuntimeError("no cluster")

    monkeypatch.setattr(timewindow, "w", boom)
    out = payloads.network_host(_Client(), addr="192.0.2.40", hours=24)
    assert out["available"] is False and "no cluster" in out["errors"]["read"]


# ── the route ──────────────────────────────────────────────────────────────────────────────


def _client():
    from tests.support_routes import _Ctx
    from weirvern.admin import flask_app

    return flask_app.create_app(_Ctx(), secret_key="network-host").test_client()


def test_the_network_host_route_rejects_an_address_that_is_not_an_address():
    client = _client()
    for bad in ("", "not an address", "192.0.2.40/24", "http://example.test/x", "addr;drop table"):
        got = client.get("/api/network/host", query_string={"addr": bad})
        assert got.status_code == 400, (bad, got.status_code, got.data[:160])
        assert got.get_json()["error"], "a 400 without the console's own sentence"


def test_the_network_host_route_bounds_hours_and_names_a_bad_absolute_range():
    """Hours are CLAMPED like every other console route; an unusable from/to is a 400.

    `web.window_arg` has one contract for every windowed route. Making this route reject a
    non-integer would give the console two behaviours for the same control, so the bound is
    asserted where it is enforced: the payload echoes the clamped value it answered for.
    """
    client = _client()
    high = client.get("/api/network/host?addr=192.0.2.40&hours=9999")
    low = client.get("/api/network/host?addr=192.0.2.40&hours=-5")
    assert high.status_code == 200 and high.get_json()["window"]["hours"] == 336
    assert low.status_code == 200 and low.get_json()["window"]["hours"] == 1

    bad = client.get("/api/network/host?addr=192.0.2.40&from=not-a-time")
    assert bad.status_code == 400, bad.data[:200]
    assert "bad time range" in bad.get_json()["error"]


def test_the_host_sheet_is_a_route_the_frontend_calls():
    assert 'networkHost: (addr, hours) =>' in ASSETS_JS
    assert "/api/network/host?addr=" in ASSETS_JS
    assert "/api/network/host" in APP_JS or "ASSET_API.networkHost" in ASSETS_JS


# ── the composable filters, the count line, the URL ────────────────────────────────────────


def test_the_family_subnet_and_text_filters_all_narrow_one_predicate():
    """Composition is the contract: a host must pass EVERY active reading, not the last one."""
    body = _body(_code(ASSETS_JS), "nwExtraMatch")
    assert "nwFamilyMode()" in body and "ripple_families" in body, (
        "the family filter is not applied to the host's own ripple families")
    assert "matcher.active" in body and "matcher.test(node.id)" in body, (
        "the subnet filter is not applied to the host address")
    assert "ASSETS_STATE.query" in body and "node.name" in body and "node.id" in body, (
        "the text filter does not search both the address and the name")
    # Each branch RETURNS FALSE, so the checks compose instead of overwriting one another.
    assert body.count("return false") >= 3, body


def test_the_filters_narrow_the_graph_the_host_table_and_the_edge_table_together():
    code = _code(ASSETS_JS)
    render = _body(code, "renderNetwork")
    assert "let matched = rippleMatched" in render
    assert "matched = new Set([...matched].filter(" in render, (
        "the extra filters must narrow the ripple-matched set, not replace it")
    assert "renderNetworkHosts(matchedNodes, d)" in render, (
        "the host table must show the matched population, not the context peers")
    assert "nwExtraMatch(node, subnetMatcher)" in render
    assert "matched.has(String(e.source))" in render and "matched.has(String(e.target))" in render


def test_the_filter_inputs_re_render_without_refetching():
    """The filters are readings over ONE cached payload; a keystroke must not run a query."""
    code = _code(APP_JS)
    for el_id in ("nw-subnet", "nw-find"):
        start = code.index(f'getElementById("{el_id}")')
        block = code[start:start + 320]
        assert "renderNetwork()" in block, f"#{el_id} does not re-render the map"
        assert "loadNetwork" not in block, (
            f"#{el_id} refetches the graph; the filters must compose over the cached payload")


def test_the_count_line_reports_the_population_before_tracked_only():
    """'showing 2 of 2' while the tracked chip hides a third host is a dishonest count."""
    render = _body(_code(ASSETS_JS), "renderNetwork")
    assert "const population = ASSETS_STATE.trackedOnly ? nodes0.length : rippleBase.length" in render
    assert "showing ${matched.size} of ${population} hosts" in render
    # ...and the line still names the window and every active filter.
    assert "`${d.hours || ASSETS_STATE.hours}h window`" in render
    assert "ripples: ${nwRippleModeLabel(rippleMode)}" in render
    assert "nwExtraNames(subnetMatcher).join" in render


def test_the_caption_states_the_retention_behind_the_window():
    """The graph's own caption must print the held range when it is shorter than the ask."""
    render = _body(_code(ASSETS_JS), "renderNetwork")
    assert "d.coverage" in render or "const cov = d.coverage" in render
    assert "flows held from" in render, "a 7d map drawn over 3.3d of flows must say so"
    assert "flows coverage unknown" in render, "an unread coverage is unknown, not full"


def test_the_new_filter_state_round_trips_through_the_url():
    for key in ("nw.family", "nw.subnet", "nw.q", "nw.sort"):
        assert f'p.set("{key}"' in APP_JS, f"{key} is never written to the URL"
        assert f'p.get("{key}")' in APP_JS, f"{key} is never restored from the URL"
    # The restored state must reach the controls, or the map and the chips disagree on reload.
    for control in ("nwSubnetEl.value", "nwFindEl.value", "nwSortEl.value"):
        assert control in APP_JS, f"{control} is not restored, so the control shows stale state"
    assert 'dataset.nwFamily === ASSETS_STATE.family' in APP_JS, (
        "the family chips are not re-pressed from the restored state")


def test_no_view_declares_its_own_time_control():
    """One range, in the header. A per-view hours select silently ignores the global choice."""
    stale = sorted(re.findall(r'id="([\w-]*hours)"', INDEX))
    assert not stale, (
        f"index.html still declares a per-view time control: {stale}. The header owns the range; "
        f"a view keeps its own selector only by ignoring every other tab's window.")
    assert "nz-hours" not in INDEX_CODE and "nz-hours" not in _code(NORMALIZE_JS)
    # Normalize reads the same global state every other loader does.
    normal_code = _code(NORMALIZE_JS)
    body = normal_code[normal_code.index("  function hours()"):
                       normal_code.index("\n  function ", normal_code.index("  function hours()") + 10)]
    assert "trHours()" in body, (
        "normalize.js must answer the header's window through trHours(), not a private default")
    assert "getElementById" not in body
