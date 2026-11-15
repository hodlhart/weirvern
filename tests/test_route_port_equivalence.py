"""Every ported route must answer EXACTLY as the console does.

WHY THIS FILE IS THE POINT OF THE PORT. The console has 53 GET reads and 34 POST entries over 84
distinct API paths, and its JavaScript depends on the exact payload shape of most of them.
Hand-rewriting a handler onto the shared payload layer is therefore a change to a contract that
nothing else checks: the console's own tests exercise the legacy handler, and the DOM harness renders
against fixtures rather than the server. A ported route that drifts by one key returns a panel that
renders blanks with no error, which is this project's most-repeated defect.

So each ported route is driven on BOTH surfaces over the SAME stubbed data, and the two responses are
compared whole -- status and body. That is the only check that makes porting 84 routes safe, and it is
why it exists before the bulk of the porting rather than after.

THE REGISTRY BELOW IS THE WORK LIST. A route appears in `PORTED` only once it has moved, and the count
is asserted at the end so the number can only fall as routes cross.

TWO READS ARE DELIBERATELY OUTSIDE IT. `/api/session` and `/api/healthz` are auth and liveness
probes, not data reads: neither has a fetcher to stub, and their subject is the session payload and
the gate rather than a table. They are pinned in `test_flask_surface.py`, which drives them with
accounts armed and disarmed. Listing them here would mean adding a second, weaker mechanism.
"""

from __future__ import annotations

import importlib
import json
import pathlib
import re
import urllib.error
import urllib.request

import pytest

from weirvern.admin import flask_app, web

flask = pytest.importorskip("flask")

ROOT = pathlib.Path(__file__).resolve().parent.parent


# ── the work list: path -> (fetcher, dotted patch target or None, canned return, query) ──────
#
# The patch target is DOTTED because ported routes no longer all read the same module: the gate state
# comes from `sluice_store`, asset posture from `admin.assets`, the data contract from
# `models.data_contract`. Naming the module in the entry is what lets one parametrised test cover all
# of them instead of growing a bespoke test per route.
#
# A canned value can be trivial: both surfaces run the SAME payload function, so equality proves the
# port regardless of what the stub returns. What it must NOT be is a shape only one side can handle.
PORTED: dict[str, tuple[str, str | None, object, str]] = {
    "/api/detectors": ("detectors", "weirvern.admin.status.detectors_overview",
                       {"detectors": [], "catch_counts": {}}, ""),
    "/api/models/shadow": ("models_shadow", "weirvern.admin.status.shadow_overview",
                           {"available": True, "rows": [{"a": 1}]}, ""),
    "/api/models/calibration": ("models_calibration", "weirvern.admin.status.calibration_overview",
                                {"rows": []}, ""),
    "/api/audit": ("audit", "weirvern.admin.status.pipeline_audit", {"checks": []}, ""),
    "/api/ml/ripple": ("ml_ripple", "weirvern.admin.status.ripple_overview",
                       {"rows": [], "counts": {}}, ""),
    "/api/sluice/state": ("sluice_state", "weirvern.sluice_store.load_gate_state",
                          {"available": True, "gate": "on"}, ""),
    "/api/asset-posture": ("asset_posture", "weirvern.admin.assets.asset_posture_overview",
                           {"available": True, "scored": 3, "bands": {}}, ""),
    "/api/ml/data-contract": ("ml_data_contract", "weirvern.models.data_contract.inventory",
                              {"available": True, "sources": []}, ""),
    "/api/discover/trends": ("discover_trends", "weirvern.admin.soc.discover_trends",
                             {"available": True, "feeds": {}}, "?hours=6"),
    "/api/dns/reverse": ("dns_reverse", "weirvern.admin.soc.dns_reverse_for",
                         {"available": True, "domains": ["example.com"]}, "?ip=203.0.113.9&hours=6"),
    # File-backed reads: no client and no stub, because both surfaces read the same files.
    "/api/ml/ledger": ("ml_ledger", None, None, ""),
    "/api/ml/eval-report": ("ml_eval_report", None, None, ""),
    "/api/ml/review": ("ml_review", None, None, ""),
    # Ported BEFORE the registry caught up: these four were live on Flask with no equivalence
    # entry, which is exactly the way a port grows on trust. The failure shapes are the interesting
    # half -- `/api/baselines` answered 200/available:false on the console and 503 on Flask until
    # `payloads.baselines_failure` was shared, and the registry is what surfaced it.
    "/api/episodes": ("episodes", "weirvern.admin.status.episodes_recent",
                      {"episodes": [{"src_addr": ""}]}, "?hours=6&limit=5"),
    "/api/baselines": ("baselines", "weirvern.admin.status.baselines_overview",
                       {"available": True, "host_count": 0, "hosts": []}, ""),
    "/api/ml/slo": ("ml_slo", "weirvern.models.quality.report",
                    {"available": True, "windows": []}, ""),
    "/api/ml/coverage": ("ml_coverage", "weirvern.models.source_coverage.collect",
                         {"available": True, "sources": []}, ""),
    # The inventory reads: one fetch each, and a failure the panel draws around rather than a 503.
    "/api/assets": ("assets", "weirvern.admin.assets.asset_inventory",
                    {"available": True, "hosts": []}, "?hours=6"),
    "/api/asset-changes": ("asset_changes", "weirvern.admin.assets.asset_changes",
                           {"available": True, "changes": [], "count": 0}, "?hours=6"),
    "/api/scan-jobs": ("scan_jobs", "weirvern.scan_jobs.list_jobs", [], "?ip=203.0.113.9"),
    "/api/identity": ("host_identity", "weirvern.admin.status.host_identity_view",
                      {"available": True, "hosts": []}, ""),
    "/api/networks": ("networks_overview", "weirvern.networks.overview",
                      {"available": True, "scopes": [{"cidr": "10.0.0.0/8"}]}, "?hours=6"),
    # The panel reads whose fetch has more than one query: the FETCHER is the stub, because stubbing
    # one inner function would leave the others running against the placeholder client and land both
    # surfaces in the failure path. Argument parsing is pinned separately, by the recorder tests.
    "/api/write-trail": ("write_trail", "weirvern.fleet_store.read_audit",
                         ([{"scope": "networks"}], ""), "?scope=networks&limit=5"),
    "/api/blocklists": ("blocklists", "weirvern.admin.payloads.blocklists",
                        {"available": True, "sources": [], "custom": []}, ""),
    "/api/models": ("models", "weirvern.admin.payloads.models",
                    {"available": True, "run_count": 0}, "?hours=12"),
    "/api/scanner": ("scanner", "weirvern.admin.payloads.scanner",
                     {"available": True, "sensors": [], "count": 0}, ""),
    "/api/system": ("system_payload", "weirvern.admin.payloads.system_payload",
                    {"available": True, "history": []}, "?sensor="),
    # The windowed families: the fetcher composes several queries, so it is the stub; the argument
    # parsing is pinned separately by the refusal and paging checks below.
    "/api/netflow": ("netflow", "weirvern.admin.payloads.netflow",
                     {"volume": {"available": True, "points": []}}, "?hours=6&proto=6"),
    "/api/zeek": ("zeek", "weirvern.admin.payloads.zeek",
                  {"counts": {"available": True, "points": []}, "filters": {}},
                  "?hours=6&log=conn"),
    "/api/flows": ("flows", "weirvern.admin.payloads.flows",
                   {"available": True, "points": []}, "?hours=6&port=443"),
    "/api/dns": ("dns", "weirvern.admin.payloads.dns",
                 {"available": True, "rows": []}, "?hours=6"),
    # The address-validated detail reads. `host` stubs only the load-bearing read: the exposure
    # annotation runs against the placeholder client, fails, and takes its documented fallback,
    # which is the behaviour under test as much as the happy path.
    "/api/host": ("host", "weirvern.admin.status.host_detail",
                  {"src_addr": "203.0.113.9", "hours": 6}, "?addr=203.0.113.9&hours=6"),
    "/api/evidence": ("evidence", "weirvern.admin.status.alert_evidence",
                      {"rows": []}, "?addr=203.0.113.9&start=2026-11-13T00:00:00"),
    "/api/incident": ("incident", "weirvern.admin.status.incident_detail",
                      {"available": True}, "?addr=203.0.113.9&start=2026-11-13T00:00:00"),
    "/api/fingerprints": ("fingerprints", "weirvern.admin.status.fingerprint_hosts",
                          {"hosts": []}, "?ja4=t13d1516h2_abc"),
    "/api/findings": ("findings", "weirvern.admin.payloads.findings",
                      {"available": True, "findings": []}, "?severity=high&limit=5"),
    "/api/models/retrain": ("model_retrain", "weirvern.admin.payloads.model_retrain",
                            {"available": True}, ""),
    "/api/graph": ("graph", "weirvern.admin.payloads.graph",
                   {"available": True, "nodes": [], "edges": []}, "?hours=6"),
    "/api/blocked": ("blocked", "weirvern.admin.payloads.blocked",
                     {"available": True, "hits": []}, "?hours=6&limit=5"),
    "/api/zeeklog": ("zeeklog", "weirvern.admin.payloads.zeeklog",
                     {"available": True, "points": []}, "?log=ssl&hours=6"),
    "/api/update": ("update_meta", "weirvern.admin.payloads.update_meta",
                    {"available": True, "current": "0.0.0"}, "?refresh=1"),
    # The landing views and the fleet drill-downs. `users` is admin-gated, so WITHOUT a granted
    # role this entry exercises the 403 both surfaces must word the same; the granted path has its
    # own test below, because a gate that refuses first would hide the payload entirely.
    "/api/overview": ("overview", "weirvern.admin.payloads.overview",
                      {"services": [], "data_error": None}, ""),
    "/api/health": ("health_deep", "weirvern.admin.payloads.health_deep",
                    {"health": None, "ingest": {}, "tables": {}, "sensor": {}, "alerts": {}},
                    "?hours=6"),
    "/api/weirlings/detail": ("weirlings_detail", "weirvern.admin.payloads.weirlings_detail",
                              {"available": True, "sensor": None}, "?sensor=hub"),
    # The status is part of the canned value: this route answers 404 and 503, not only 200.
    "/api/weirlings/probe": ("weirlings_probe", "weirvern.admin.payloads.weirlings_probe",
                             (200, {"ok": True}), "?request=r1"),
    "/api/users": ("users_list", "weirvern.admin.payloads.users_list",
                   {"available": True, "users": []}, ""),
    "/api/anomalies": ("anomalies", "weirvern.admin.payloads.anomalies",
                       {"rows": [], "severity_counts": {}}, "?hours=6&min_score=0.5"),
    # feed=dns on purpose: it takes the OTHER branch, which is the one with different arguments.
    "/api/discover": ("discover", "weirvern.admin.payloads.discover",
                      {"available": True, "rows": []}, "?hours=6&feed=dns&addr=203.0.113.9"),
    # The two largest reads. `sluice` takes a connection factory and `settings` takes the
    # request-scoped role/identity, so both are stubbed at the FETCHER: the surface contract being
    # compared is which fetcher runs and what body it answers with.
    "/api/sluice": ("sluice", "weirvern.admin.payloads.sluice",
                    {"available": True, "rules": []}, "?hours=6"),
    "/api/settings": ("settings_payload", "weirvern.admin.payloads.settings_payload",
                      {"available": True, "groups": {}}, ""),
}


def test_no_flask_route_is_missing_from_the_registry():
    """Every API read Flask serves is in the registry, or one of the three named exceptions.

    THE FAILURE THIS CATCHES IS THE ONE THAT PRODUCED IT. Five routes (`session`, `episodes`,
    `baselines`, `ml/slo`, `ml/coverage`) were live on Flask with no equivalence entry, so nothing
    compared them with the console -- and when `baselines` was finally driven, its failure path
    answered 200 here and 503 there. A registry that is only appended to by hand cannot notice that,
    so the Flask route list is the second source of truth and the difference is asserted empty.

    `/api/proposals` never existed on the console (it is new work, not a port) and the other two are
    auth and liveness probes, pinned in `test_flask_surface.py`.
    """
    src = (ROOT / "weirvern" / "admin" / "flask_app.py").read_text()
    served = set(re.findall(r'@app\.get\("(/api/[^"]+)"\)', src))
    unregistered = served - set(PORTED) - {"/api/session", "/api/healthz", "/api/proposals"}
    assert not unregistered, (
        f"Flask serves {sorted(unregistered)} with no equivalence entry, so nothing compares it "
        f"with the console"
    )


class _CM:
    def __init__(self, client):
        self.client = client

    def __enter__(self):
        return self.client

    def __exit__(self, *a):
        return False


def _ctx(client):
    class _Auth:
        enabled = False

        def check(self, presented, client=""):
            return False

    class _Ctx:
        settings = None
        backend = None
        config_client = None
        user_store = None
        sessions = None
        throttle = None
        accounts_note = ""
        auth = _Auth()
        connect_factory = staticmethod(lambda settings: _CM(client))

    return _Ctx()


def _legacy_http(port: int, path: str):
    """GET from the console, treating a refusal as an answer -- a 503 IS the thing being compared."""
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=10) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def _flask_http(app, path: str):
    resp = app.test_client().get(path)
    return resp.status_code, resp.data


@pytest.fixture
def surfaces():
    """Build a console on a loopback port and a Flask app over the same context."""
    started = []

    def build():
        ctx = _ctx(object())
        legacy = web.GuiServer(ctx, host="127.0.0.1", port=0).start_background()
        app = flask_app.create_app(ctx, secret_key="equivalence-test")
        app.config.update(TESTING=True)
        # THE CONSOLE ANSWERS AN UNCAUGHT EXCEPTION WITH ITS OWN JSON 500, and Flask's test client
        # otherwise re-raises it instead of letting the app's handler answer. Turning propagation
        # off is what lets the failure half of an equivalence test compare the two bodies, rather
        # than comparing one JSON body with a traceback.
        app.config["PROPAGATE_EXCEPTIONS"] = False
        started.append(legacy)
        return legacy, app

    try:
        yield build
    finally:
        for legacy in started:
            legacy.stop()


# ── the equivalence checks ─────────────────────────────────────────────────────────────────

def _patch(monkeypatch, dotted: str, value):
    """Patch a dotted target, failing loudly if the target moved.

    `raising=True` matters: a silently-created attribute would make both surfaces read a stub that
    the shipping code never consults, and the comparison would pass while proving nothing.
    """
    module, _, attr = dotted.rpartition(".")
    monkeypatch.setattr(importlib.import_module(module), attr, value, raising=True)


@pytest.mark.parametrize("path", sorted(PORTED))
def test_each_ported_route_answers_identically(path, surfaces, monkeypatch):
    _fetcher, patch, canned, query = PORTED[path]
    if patch:
        _patch(monkeypatch, patch, lambda *a, **k: canned)

    legacy, app = surfaces()
    lstatus, lbody = _legacy_http(legacy.port, path + query)
    fstatus, fbody = _flask_http(app, path + query)

    assert fstatus == lstatus, f"{path}: console {lstatus}, flask {fstatus}"
    assert json.loads(fbody) == json.loads(lbody), (
        f"{path} drifted from the console. A panel reading one of these keys renders blank with no "
        f"error.\n  console: {lbody[:300]!r}\n  flask:   {fbody[:300]!r}"
    )


@pytest.mark.parametrize(
    "path", sorted(p for p, (_f, patch, _c, _q) in PORTED.items() if patch))
def test_each_ported_route_words_a_FAILURE_identically(path, surfaces, monkeypatch):
    """The failure wording is part of the payload contract: one vocabulary whichever surface answered.
    A missing binary must not be reported as a database fault on either."""
    def boom(*a, **k):
        raise FileNotFoundError(2, "No such file or directory", "kubectl")

    _fetcher, patch, _canned, query = PORTED[path]
    _patch(monkeypatch, patch, boom)

    legacy, app = surfaces()
    lstatus, lbody = _legacy_http(legacy.port, path + query)
    fstatus, fbody = _flask_http(app, path + query)

    assert fstatus == lstatus, f"{path}: console {lstatus}, flask {fstatus}"
    assert json.loads(fbody) == json.loads(lbody), (
        f"{path} words a failure differently.\n  console: {lbody[:250]!r}\n  flask: {fbody[:250]!r}"
    )
    blob = json.dumps(json.loads(fbody))
    assert "ClickHouse" not in blob, f"{path} blamed the database for a missing binary: {blob[:200]}"


# ── the guards that keep the port honest ───────────────────────────────────────────────────

def test_every_port_has_a_fetcher_that_exists():
    src = (ROOT / "weirvern" / "admin" / "payloads.py").read_text()
    for path, (fetcher, _p, _c, _q) in PORTED.items():
        assert f"def {fetcher}(" in src, f"{path} names payloads.{fetcher}, which does not exist"


def test_every_port_is_routed_by_flask():
    src = (ROOT / "weirvern" / "admin" / "flask_app.py").read_text()
    for path in PORTED:
        assert f'@app.get("{path}")' in src, f"{path} is listed as ported but Flask does not route it"


def test_the_ported_count_only_grows():
    """A ratchet on progress, not a target: if a route moves BACK to the legacy handler, this notices."""
    assert len(PORTED) >= 50, f"{len(PORTED)} routes ported; the ratchet must not go backwards"


# ── argument parsing is part of the contract ────────────────────────────────────────────────
#
# `_int_arg` CLAMPS and DEFAULTS rather than rejecting, deliberately: the docstring says a client
# asking for limit=99999 gets the maximum, which protects the database without an error. So the thing
# to pin is not a 400 (neither surface raises one) but that both surfaces hand the SAME number to the
# fetcher. Comparing response bytes alone would prove nothing here, because the stub ignores its
# arguments -- so the stub records what it was given and the assertions are on those values.

class _Recorder:
    def __init__(self, value=None):
        self.value = value if value is not None else {"feeds": {}}
        self.seen: list[dict] = []

    def __call__(self, *_a, **kwargs):
        self.seen.append(dict(kwargs))
        return self.value


def test_a_malformed_window_falls_back_to_the_default_on_both_surfaces(surfaces, monkeypatch):
    rec = _Recorder()
    _patch(monkeypatch, "weirvern.admin.soc.discover_trends", rec)
    legacy, app = surfaces()

    lstatus, lbody = _legacy_http(legacy.port, "/api/discover/trends?hours=banana")
    fstatus, fbody = _flask_http(app, "/api/discover/trends?hours=banana")

    assert fstatus == lstatus == 200, f"console {lstatus}, flask {fstatus}"
    assert json.loads(fbody) == json.loads(lbody)
    assert [c.get("hours") for c in rec.seen] == [24, 24], (
        f"the two surfaces disagreed about the default: {rec.seen}"
    )


def test_an_out_of_range_window_is_clamped_identically_on_both_surfaces(surfaces, monkeypatch):
    rec = _Recorder()
    _patch(monkeypatch, "weirvern.admin.soc.discover_trends", rec)
    legacy, app = surfaces()

    _legacy_http(legacy.port, "/api/discover/trends?hours=9999")
    _flask_http(app, "/api/discover/trends?hours=9999")

    hours = [c.get("hours") for c in rec.seen]
    assert hours == [336, 336], (
        f"the clamp differs between surfaces, so one asks the database for a different range: {hours}"
    )


def test_a_reverse_lookup_without_an_address_is_refused_identically(surfaces):
    """This one DOES refuse, and the wording is part of what a caller sees."""
    legacy, app = surfaces()

    lstatus, lbody = _legacy_http(legacy.port, "/api/dns/reverse")
    fstatus, fbody = _flask_http(app, "/api/dns/reverse")

    assert fstatus == lstatus == 400, f"console {lstatus}, flask {fstatus}"
    assert json.loads(fbody) == json.loads(lbody)


def test_an_absolute_range_is_honoured_identically_on_both_surfaces(surfaces, monkeypatch):
    """`from`/`to` win over `hours`, and the span becomes the window.

    THIS PATH HAD NO TEST UNTIL A MUTATION SHOWED IT: restoring the old scalar indexing left the whole
    suite green, because every existing case went through `hours`. The defect it hides is the same one,
    and worse here: `"2026-11-13T00:00:00"[0]` is `"2"`, so the absolute range would have been parsed
    from a single character.
    """
    rec = _Recorder()
    _patch(monkeypatch, "weirvern.admin.soc.discover_trends", rec)
    legacy, app = surfaces()

    q = "?from=2026-11-13T00:00:00&to=2026-11-13T06:00:00"
    lstatus, lbody = _legacy_http(legacy.port, "/api/discover/trends" + q)
    fstatus, fbody = _flask_http(app, "/api/discover/trends" + q)

    assert fstatus == lstatus == 200, f"console {lstatus}, flask {fstatus}: {lbody[:160]!r}"
    assert json.loads(fbody) == json.loads(lbody)
    hours = [c.get("hours") for c in rec.seen]
    assert hours == [6, 6], (
        f"the absolute range resolved differently on the two surfaces: {hours}"
    )


def test_the_models_window_defaults_and_clamps_identically(surfaces, monkeypatch):
    """`/api/models` defaults to 72 hours and its ceiling is 30 days, not the usual 14.

    The shared `window_arg` is used with DIFFERENT bounds per route, so the number that matters is
    the one the fetcher receives, not the shape of the parser.
    """
    rec = _Recorder({"available": True})
    _patch(monkeypatch, "weirvern.admin.payloads.models", rec)
    legacy, app = surfaces()

    for query in ("?hours=banana", "?hours=9999"):
        _legacy_http(legacy.port, "/api/models" + query)
        _flask_http(app, "/api/models" + query)

    hours = [c.get("hours") for c in rec.seen]
    assert hours == [72, 72, 720, 720], (
        f"the two surfaces disagreed about the models window: {hours}"
    )


def test_the_write_trail_bounds_its_filters_identically(surfaces, monkeypatch):
    """`limit` clamps to 200 and `scope` is TRUNCATED to 32 characters, on both surfaces.

    Truncation rather than refusal is the console's contract for this route, so the assertion is on
    the value the audit read received. A surface that refused the long scope would need its own
    error body, which is a different answer to the same request.
    """
    rec = _Recorder(([], ""))
    _patch(monkeypatch, "weirvern.fleet_store.read_audit", rec)
    legacy, app = surfaces()

    long_scope = "s" * 40
    query = f"?scope={long_scope}&limit=9999"
    _legacy_http(legacy.port, "/api/write-trail" + query)
    _flask_http(app, "/api/write-trail" + query)

    seen = rec.seen
    assert [c.get("limit") for c in seen] == [200, 200], f"the limit clamp differs: {seen}"
    assert [len(str(c.get("scope"))) for c in seen] == [32, 32], (
        f"the scope truncation differs: {seen}"
    )


# ── the windowed families refuse rather than clamp, and the sentence is the contract ─────────
#
# A clamped filter would answer a different question silently, which is the failure this console
# keeps finding. So the console answers 400 for each of these, and the port has to reproduce the
# words -- including the odd "does not look like a number" an OUT-OF-RANGE qtype gets. Improving the
# wording during a port would make the two surfaces disagree about the same bad request.

REFUSALS = [
    ("/api/netflow", "?proto=999"),
    ("/api/flows", ""),
    ("/api/dns", "?qtype=abc"),
    ("/api/dns", "?qtype=99999"),
    ("/api/zeek", "?log=bogus"),
    ("/api/host", ""),
    ("/api/host", "?addr=not%20an%20address!"),
    ("/api/evidence", "?addr=203.0.113.9"),
    ("/api/incident", ""),
    ("/api/fingerprints", "?ja4=###"),
    ("/api/findings", "?severity=bogus"),
    ("/api/findings", "?limit=abc"),
    ("/api/zeeklog", ""),
    ("/api/zeeklog", "?log=bogus"),
    ("/api/graph", "?host=bad%20host!"),
    ("/api/blocked", "?domain=" + "a" * 201),
    ("/api/blocked", "?client=" + "a" * 65),
    ("/api/weirlings/detail", ""),
    ("/api/weirlings/probe", ""),
    ("/api/discover", "?feed=bogus"),
    ("/api/discover", "?proto=bogusproto"),
    ("/api/discover", "?sport=99999"),
    ("/api/anomalies", "?host=" + "a" * 65),
]


@pytest.mark.parametrize("path,query", REFUSALS)
def test_a_refused_filter_is_worded_identically(path, query, surfaces):
    legacy, app = surfaces()
    lstatus, lbody = _legacy_http(legacy.port, path + query)
    fstatus, fbody = _flask_http(app, path + query)

    assert fstatus == lstatus == 400, f"{path}{query}: console {lstatus}, flask {fstatus}"
    assert json.loads(fbody) == json.loads(lbody), (
        f"{path}{query} is refused with different words.\n"
        f"  console: {lbody[:200]!r}\n  flask:   {fbody[:200]!r}"
    )


def test_the_dns_filters_and_paging_reach_the_fetcher_identically(surfaces, monkeypatch):
    """The clamped paging and the parsed qtype/rcode, compared at the fetcher, not the response.

    `offset` clamps at a million and `limit` at 500, and qtype/rcode become INTEGERS here. A surface
    that passed the raw strings would still render a page, from a different query.
    """
    rec = _Recorder({"available": True, "rows": []})
    _patch(monkeypatch, "weirvern.admin.payloads.dns", rec)
    legacy, app = surfaces()

    q = "?offset=999999999&limit=9999&qtype=1&rcode=3&domain=example.com&client=203.0.113.9"
    _legacy_http(legacy.port, "/api/dns" + q)
    _flask_http(app, "/api/dns" + q)

    seen = rec.seen
    assert [(c.get("offset"), c.get("limit")) for c in seen] == [(1000000, 500), (1000000, 500)]
    assert [(c.get("qtype"), c.get("rcode")) for c in seen] == [(1, 3), (1, 3)]
    assert [c.get("domain") for c in seen] == ["example.com", "example.com"]
    assert [c.get("client_ip") for c in seen] == ["203.0.113.9", "203.0.113.9"]


def test_the_findings_filters_parse_identically_and_the_limit_is_NOT_clamped(surfaces, monkeypatch):
    """`severity` lowercases and `limit` passes through unbounded, on both surfaces.

    THE ABSENCE OF A CLAMP IS THE CONTRACT. Findings are historical evidence and this route hands
    the caller's number straight to the query, so a port that "helpfully" clamped it would answer a
    different question than the one asked -- while both surfaces agreed with each other, which is
    exactly the kind of agreement that hides a defect.
    """
    rec = _Recorder({"available": True, "findings": []})
    _patch(monkeypatch, "weirvern.admin.payloads.findings", rec)
    legacy, app = surfaces()

    q = "?ip=203.0.113.9&severity=HIGH&limit=999999"
    _legacy_http(legacy.port, "/api/findings" + q)
    _flask_http(app, "/api/findings" + q)

    seen = rec.seen
    assert [c.get("severity") for c in seen] == ["high", "high"]
    assert [c.get("limit") for c in seen] == [999999, 999999], (
        f"the findings limit is not supposed to be clamped: {seen}"
    )
    assert [c.get("ip") for c in seen] == ["203.0.113.9", "203.0.113.9"]


def test_the_discover_chips_survive_repetition_on_both_surfaces(surfaces, monkeypatch):
    """`?src=A&src=B&dport=443&dport=80` must reach the fetcher as FOUR values, not two.

    THE CHIP FILTERS ARE THE MULTI-SELECT, and the shapes differ again: parse_qs gives lists,
    MultiDict.get gives the first scalar. A parser that read the scalar would filter by one address
    and one port while the UI showed two chips selected.
    """
    rec = _Recorder({"available": True, "rows": []})
    _patch(monkeypatch, "weirvern.admin.payloads.discover", rec)
    legacy, app = surfaces()

    q = "?hours=6&src=203.0.113.9&src=203.0.113.10&dport=443&dport=80"
    _legacy_http(legacy.port, "/api/discover" + q)
    _flask_http(app, "/api/discover" + q)

    seen = rec.seen
    assert [c.get("src") for c in seen] == [
        ["203.0.113.9", "203.0.113.10"], ["203.0.113.9", "203.0.113.10"]], (
        f"a repeated src chip was collapsed on one surface: {seen}"
    )
    assert [c.get("dport") for c in seen] == [[443, 80], [443, 80]], (
        f"a repeated dport chip was collapsed or left unparsed: {seen}"
    )


def test_the_graph_tracked_selection_survives_repetition_on_both_surfaces(surfaces, monkeypatch):
    """`?host=A&host=B` must reach the fetcher as TWO addresses, not one.

    THIS IS THE QUERY-SHAPE TRAP AGAIN, in a place bytes cannot see it. The console's `parse_qs`
    hands a list for a repeated key; Flask's `MultiDict.get` returns the FIRST scalar. A parser that
    read `query.get("host")` would silently track one host and render a graph that looks like the
    operator's selection while ignoring most of it. The route uses `getlist`, and this asserts the
    two surfaces hand the fetcher the same list.
    """
    rec = _Recorder({"available": True, "nodes": [], "edges": []})
    _patch(monkeypatch, "weirvern.admin.payloads.graph", rec)
    legacy, app = surfaces()

    q = "?hours=6&host=203.0.113.9&host=203.0.113.10"
    _legacy_http(legacy.port, "/api/graph" + q)
    _flask_http(app, "/api/graph" + q)

    tracked = [c.get("tracked") for c in rec.seen]
    assert tracked == [["203.0.113.9", "203.0.113.10"], ["203.0.113.9", "203.0.113.10"]], (
        f"a repeated host was collapsed on one surface: {tracked}"
    )


def test_the_capture_probe_status_travels_on_both_surfaces(surfaces, monkeypatch):
    """A missing probe is a 404 with its own body, not a 200 carrying an error string.

    THE STATUS IS PART OF THE ANSWER. This route uses three of them (200, 404, 503) and a port that
    answered 200 for all three would leave the caller's error handling reading the wrong branch.
    """
    _patch(monkeypatch, "weirvern.admin.payloads.weirlings_probe",
           lambda *a, **k: (404, {"ok": False, "error": "no such capture probe"}))
    legacy, app = surfaces()

    lstatus, lbody = _legacy_http(legacy.port, "/api/weirlings/probe?request=r1")
    fstatus, fbody = _flask_http(app, "/api/weirlings/probe?request=r1")

    assert fstatus == lstatus == 404, f"console {lstatus}, flask {fstatus}"
    assert json.loads(fbody) == json.loads(lbody)


def test_the_users_read_is_admin_gated_identically_and_answers_when_granted(surfaces, monkeypatch):
    """The 403 comes first and is worded the same; the granted read then returns the same payload.

    THE GATE IS THE INTERESTING HALF. `/api/users` checks a ROLE on top of the read gate, and a
    surface that checked it differently would leak the account list to a viewer. The role is granted
    here through `requestauth.token_role`, the shared helper BOTH surfaces ask, so neither gets a
    private path to "admin".
    """
    legacy, app = surfaces()

    lstatus, lbody = _legacy_http(legacy.port, "/api/users")
    fstatus, fbody = _flask_http(app, "/api/users")
    assert fstatus == lstatus == 403, f"console {lstatus}, flask {fstatus}"
    assert json.loads(fbody) == json.loads(lbody)

    _patch(monkeypatch, "weirvern.admin.requestauth.token_role", lambda *a, **k: "admin")
    rec = _Recorder({"available": True, "users": [{"username": "sam"}]})
    _patch(monkeypatch, "weirvern.admin.payloads.users_list", rec)

    lstatus, lbody = _legacy_http(legacy.port, "/api/users")
    fstatus, fbody = _flask_http(app, "/api/users")
    assert fstatus == lstatus == 200, f"console {lstatus}, flask {fstatus}"
    assert json.loads(fbody) == json.loads(lbody)

