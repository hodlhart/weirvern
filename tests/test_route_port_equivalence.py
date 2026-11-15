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
    "/api/weirlings": ("weirlings", "weirvern.admin.payloads.weirlings",
                       {"available": True, "sensors": []}, "?problems=1"),
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
        reason = "no token configured"

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


def _post_legacy(port: int, path: str, raw: bytes, headers: dict | None = None):
    """POST to the console, treating a refusal as an answer."""
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}", data=raw, method="POST",
        headers={"Content-Type": "application/json", **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def _post_flask(app, path: str, raw: bytes, headers: dict | None = None):
    resp = app.test_client().post(
        path, data=raw,
        headers={"Content-Type": "application/json", **(headers or {})})
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
        # THE CONTEXT IS SHARED by both surfaces, and a test that wants an account store installed
        # has to reach it. GuiServer does not keep one, so the fixture hands it back here rather
        # than making callers rebuild it.
        legacy.ctx = ctx  # type: ignore[attr-defined]
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
    assert len(PORTED) >= 51, f"{len(PORTED)} routes ported; the ratchet must not go backwards"


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


# ── the WRITE surface ───────────────────────────────────────────────────────────────────────
#
# Writes are a different contract from reads: the GATE answers before the body is read, several
# routes answer with a status of their own, and a mutation's answer is what the store says AFTER it
# landed. The registry below is the work list for the 34 POST entries; a route appears once it has
# moved, and the count is a ratchet like the read one.

PORTED_WRITES: dict[str, tuple[str, str]] = {
    "/api/watch": ("watch", "weirvern.admin.payloads.watch"),
    "/api/review": ("review", "weirvern.admin.payloads.review"),
    "/api/users/create": ("user_create", "weirvern.admin.payloads.user_create"),
    "/api/users/role": ("user_role", "weirvern.admin.payloads.user_role"),
    "/api/users/delete": ("user_delete", "weirvern.admin.payloads.user_delete"),
    "/api/users/reset": ("user_reset", "weirvern.admin.payloads.user_reset"),
    "/api/login": ("login", "weirvern.admin.payloads.login"),
    "/api/logout": ("logout", "weirvern.admin.payloads.logout"),
    "/api/password": ("password_change", "weirvern.admin.payloads.password_change"),
    "/api/scan-jobs": ("scan_job_create", "weirvern.admin.payloads.scan_job_create"),
    "/api/sluice/block": ("sluice_block", "weirvern.admin.payloads.sluice_block"),
    "/api/sluice/revoke": ("sluice_revoke", "weirvern.admin.payloads.sluice_revoke"),
    "/api/sluice/rule/mode": ("sluice_rule_mode", "weirvern.admin.payloads.sluice_rule_mode"),
    "/api/sluice/rule/domain": ("sluice_rule_domain", "weirvern.admin.payloads.sluice_rule_domain"),
    "/api/sluice/rule/disabled": ("sluice_rule_disabled",
                                  "weirvern.admin.payloads.sluice_rule_disabled"),
    "/api/blocklists/sync": ("blocklist_sync", "weirvern.admin.payloads.blocklist_sync"),
    "/api/blocklists/source": ("blocklist_source_add",
                              "weirvern.admin.payloads.blocklist_source_add"),
    "/api/blocklists/custom": ("blocklist_custom", "weirvern.admin.payloads.blocklist_custom"),
    "/api/blocklists/enable": ("blocklist_enable", "weirvern.admin.payloads.blocklist_enable"),
    "/api/networks/save": ("network_scope_save", "weirvern.admin.payloads.network_scope_save"),
    "/api/networks/delete": ("network_scope_delete",
                             "weirvern.admin.payloads.network_scope_delete"),
    "/api/weirlings/register": ("weirling_register",
                                "weirvern.admin.payloads.weirling_register"),
    "/api/weirlings/enable": ("weirling_enable", "weirvern.admin.payloads.weirling_enable"),
    "/api/weirlings/revoke": ("weirling_revoke", "weirvern.admin.payloads.weirling_revoke"),
    "/api/weirlings/plan": ("weirling_plan", "weirvern.admin.payloads.weirling_plan"),
    "/api/weirlings/apply": ("weirling_apply", "weirvern.admin.payloads.weirling_apply"),
    "/api/weirlings/probe": ("weirling_probe", "weirvern.admin.payloads.weirling_probe"),
    "/api/networks/autofill": ("network_scope_autofill",
                               "weirvern.admin.payloads.network_scope_autofill"),
    "/api/settings/plan": ("settings_plan", "weirvern.admin.payloads.settings_plan"),
    "/api/settings/apply": ("settings_apply", "weirvern.admin.payloads.settings_apply"),
    "/api/settings/test": ("settings_test", "weirvern.admin.payloads.settings_test"),
    "/api/settings/sonar": ("settings_sonar", "weirvern.admin.payloads.settings_sonar"),
    # THE ONE PREFIX FAMILY: the console matches /api/models/retrain/<action> and takes the tail as
    # the action, so the registry key is a template and the guard looks for that literal decorator.
    "/api/models/retrain/<tail>": ("model_action", "weirvern.admin.payloads.model_action"),
}


def test_every_write_port_has_a_fetcher_that_exists():
    src = (ROOT / "weirvern" / "admin" / "payloads.py").read_text()
    for path, (fetcher, _dotted) in PORTED_WRITES.items():
        assert f"def {fetcher}(" in src, f"{path} names payloads.{fetcher}, which does not exist"


def test_every_write_port_is_routed_by_flask():
    src = (ROOT / "weirvern" / "admin" / "flask_app.py").read_text()
    for path in PORTED_WRITES:
        assert f'@app.post("{path}")' in src, f"{path} is listed as ported but Flask does not route it"


def test_the_ported_write_count_only_grows():
    assert len(PORTED_WRITES) >= 33, (
        f"{len(PORTED_WRITES)} writes ported; the ratchet must not go backwards")


def test_the_watch_write_answers_identically(surfaces, monkeypatch):
    """The WRITE GATE, the body sentences and the read-back all match on both surfaces.

    THE GATE IS THE POINT OF THIS TEST. The two write-gate implementations had already drifted: the
    console answered 401 with its own sentence and applied the escalating delay, while
    `requestauth.write_refusal` answered 403 with a different sentence and no delay. Both surfaces
    now call the shared one, so this compares the refusal, the landed write and every malformed-body
    case.
    """
    import types

    legacy, app = surfaces()
    raw = b'{"src_addr": "203.0.113.9", "on": true}'

    # 1. Refused: no session and no token.
    ls, lb = _post_legacy(legacy.port, "/api/watch", raw)
    fs, fb = _post_flask(app, "/api/watch", raw)
    assert fs == ls, f"console {ls}, flask {fs}"
    assert json.loads(fb) == json.loads(lb), (
        f"the write refusal differs.\n  console: {lb[:200]!r}\n  flask:   {fb[:200]!r}")

    # 2. Granted: an admin session through the SHARED identity helper, then the write lands.
    ident = types.SimpleNamespace(is_admin=True, must_change=False, username="sam")
    _patch(monkeypatch, "weirvern.admin.requestauth.identity", lambda *a, **k: ident)
    calls = []
    _patch(monkeypatch, "weirvern.admin.status.write_watch",
           lambda client, *, src_addr, watching: calls.append((src_addr, watching)))
    _patch(monkeypatch, "weirvern.admin.status.watch_index",
           lambda client: ({"203.0.113.9"}, None))

    ls, lb = _post_legacy(legacy.port, "/api/watch", raw)
    fs, fb = _post_flask(app, "/api/watch", raw)
    assert fs == ls == 200, f"console {ls}, flask {fs}: {lb[:160]!r} / {fb[:160]!r}"
    assert json.loads(fb) == json.loads(lb)
    assert calls == [("203.0.113.9", True), ("203.0.113.9", True)], (
        f"the write did not land identically on both surfaces: {calls}")

    # 3. Field validation and body parsing, worded the same.
    for bad, expected in (
        (b'{"on": true}', b"'src_addr' is required"),
        (b'{"src_addr": "203.0.113.9", "on": "yes"}', b"'on' must be true or false"),
        (b"[]", b"body must be a JSON object"),
        (b"not json", b"body is not valid JSON"),
    ):
        ls, lb = _post_legacy(legacy.port, "/api/watch", bad)
        fs, fb = _post_flask(app, "/api/watch", bad)
        assert fs == ls == 400, f"{bad!r}: console {ls}, flask {fs}"
        assert expected in lb and expected in fb, (bad, lb[:160], fb[:160])
        assert json.loads(fb) == json.loads(lb), (bad, lb[:160], fb[:160])


def test_the_review_write_answers_identically(surfaces, monkeypatch):
    """A disposition and its optional adjustment, plus every refusal around them.

    THE UNKNOWN-STATE ANSWER IS ITS OWN SHAPE: a 400 carrying `valid_states`, not the house error.
    The adjustment has three sentences of its own, and a review that lands beside a REJECTED
    adjustment still 400s -- the console's behaviour, preserved rather than tidied.
    """
    import types

    legacy, app = surfaces()
    ident = types.SimpleNamespace(is_admin=True, must_change=False, username="sam")
    _patch(monkeypatch, "weirvern.admin.requestauth.identity", lambda *a, **k: ident)
    writes = []
    _patch(monkeypatch, "weirvern.admin.status.write_review",
           lambda client, **k: writes.append(k))
    _patch(monkeypatch, "weirvern.models.active_learning.build_adjustment",
           lambda **k: dict(k))
    adjustments = []
    _patch(monkeypatch, "weirvern.models.active_learning.write_adjustment",
           lambda client, adj: adjustments.append(adj))

    stamp = '"window_start": "2026-11-13T00:00:00", "src_addr": "203.0.113.9"'

    # 1. A plain disposition lands, and both surfaces wrote the same row.
    good = ('{' + stamp + ', "state": "ack", "note": "seen"}').encode()
    ls, lb = _post_legacy(legacy.port, "/api/review", good)
    fs, fb = _post_flask(app, "/api/review", good)
    assert fs == ls == 200, f"console {ls}, flask {fs}: {lb[:200]!r} / {fb[:200]!r}"
    assert json.loads(fb) == json.loads(lb)
    assert len(writes) == 2 and writes[0] == writes[1], writes

    # 2. An unknown state is the 400 WITH valid_states.
    bad_state = ('{' + stamp + ', "state": "nope"}').encode()
    ls, lb = _post_legacy(legacy.port, "/api/review", bad_state)
    fs, fb = _post_flask(app, "/api/review", bad_state)
    assert fs == ls == 400, f"console {ls}, flask {fs}"
    assert json.loads(fb) == json.loads(lb)
    assert json.loads(fb).get("valid_states"), "the refusal lost its valid_states list"

    # 3. Missing fields.
    missing = b'{"state": "ack"}'
    ls, lb = _post_legacy(legacy.port, "/api/review", missing)
    fs, fb = _post_flask(app, "/api/review", missing)
    assert fs == ls == 400, f"console {ls}, flask {fs}"
    assert json.loads(fb) == json.loads(lb)

    # 4. Adjustment validation: not an object, then a non-numeric value.
    for adj, expected in (
        ('"adjustment": 5', b"'adjustment' must be an object"),
        ('"adjustment": {"before_value": "x", "after_value": 2}',
         b"before_value and after_value must be numbers"),
    ):
        raw = ('{' + stamp + ', "state": "ack", ' + adj + '}').encode()
        ls, lb = _post_legacy(legacy.port, "/api/review", raw)
        fs, fb = _post_flask(app, "/api/review", raw)
        assert fs == ls == 400, f"{adj}: console {ls}, flask {fs}"
        assert expected in lb and expected in fb, (adj, lb[:200], fb[:200])
        assert json.loads(fb) == json.loads(lb), (adj, lb[:200], fb[:200])

    # 5. A valid adjustment rides the response.
    adj_ok = ('{' + stamp + ', "state": "ack", "adjustment": {"before_value": 1, '
              '"after_value": 2, "reason": "tuned"}}').encode()
    ls, lb = _post_legacy(legacy.port, "/api/review", adj_ok)
    fs, fb = _post_flask(app, "/api/review", adj_ok)
    assert fs == ls == 200, f"console {ls}, flask {fs}: {lb[:200]!r} / {fb[:200]!r}"
    assert json.loads(fb) == json.loads(lb)
    assert json.loads(fb).get("adjustment"), "the adjustment is missing from the answer"
    assert len(adjustments) == 2, adjustments


def test_the_account_writes_answer_identically(surfaces, monkeypatch):
    """Create, role, delete and reset: same store calls, same statuses, same words.

    THE NO-OP ROLE CHANGE IS THE CASE WORTH PINNING. Setting the role an account already has must
    revoke NOTHING -- a revoke signs the operator out of the tab they are working in, which reads as
    the change having failed. The store's `find()` returns its LIVE record and `set_role` mutates it
    in place, so this stub mutates in place too; a port that read the role after the write would
    revoke on every call and the difference shows up here.
    """
    import types

    from weirvern.admin import users as users_mod

    legacy, app = surfaces()
    ctx = legacy.ctx
    ident = types.SimpleNamespace(is_admin=True, must_change=False, username="sam")
    _patch(monkeypatch, "weirvern.admin.requestauth.identity", lambda *a, **k: ident)

    calls: list = []
    revoked: list = []
    roles = {"alice": "viewer", "bob": "admin"}

    class _Record:
        def __init__(self, username, role):
            self.username = username
            self.role = role

        def public(self):
            return {"username": self.username, "role": self.role}

    class _Store:
        def create_user(self, username, role, password, must_change=False):
            calls.append(("create", username, role, password, must_change))
            return _Record(username, role)

        def find(self, username):
            return _Record(username, roles[username]) if username in roles else None

        def set_role(self, username, role):
            calls.append(("role", username, role))
            roles[username] = role  # in place, like the real store

        def delete_user(self, username):
            calls.append(("delete", username))
            roles.pop(username, None)

        def set_password(self, username, password, must_change=False):
            calls.append(("password", username, password, must_change))

    ctx.user_store = _Store()
    ctx.sessions = types.SimpleNamespace(revoke_user=lambda u: revoked.append(u) or 0)

    def _compare(path, payload):
        """Run the same request on both surfaces from the same starting state."""
        def one(surface):
            del calls[:], revoked[:]
            roles.clear()
            roles.update({"alice": "viewer", "bob": "admin"})
            raw = json.dumps(payload).encode()
            if surface == "console":
                status, body = _post_legacy(legacy.port, path, raw)
            else:
                status, body = _post_flask(app, path, raw)
            return status, body, list(calls), list(revoked)

        ls, lb, lcalls, lrevoked = one("console")
        fs, fb, fcalls, frevoked = one("flask")
        assert fs == ls, f"{path} {payload}: console {ls}, flask {fs}"
        assert json.loads(fb) == json.loads(lb), (
            f"{path} {payload} drifted.\n  console: {lb[:200]!r}\n  flask:   {fb[:200]!r}")
        assert fcalls == lcalls, (
            f"{path} {payload}: the surfaces touched the store differently.\n"
            f"  console: {lcalls}\n  flask:   {fcalls}")
        assert frevoked == lrevoked, (
            f"{path} {payload}: the surfaces revoked different sessions.\n"
            f"  console: {lrevoked}\n  flask:   {frevoked}")
        return json.loads(fb)

    # 1. Create: the record's public() rides the answer.
    body = _compare("/api/users/create",
                    {"username": "carol", "role": "viewer", "password": "long enough to pass"})
    assert body["user"] == {"username": "carol", "role": "viewer"}

    # 2. A real role change revokes; setting the SAME role revokes nothing.
    _compare("/api/users/role", {"username": "alice", "role": "admin"})
    assert revoked == ["alice"]
    _compare("/api/users/role", {"username": "bob", "role": "admin"})
    assert revoked == [], "a no-op role change signed the operator out"

    # 3. Delete and reset both revoke.
    _compare("/api/users/delete", {"username": "alice"})
    assert revoked == ["alice"]
    _compare("/api/users/reset", {"username": "bob", "password": "temporary one"})
    assert revoked == ["bob"]

    # 4. A store refusal is a 400 carrying the store's own sentence and NO code key.
    def refuse(username, role, password, must_change=False):
        raise users_mod.UserError("the password must be at least 12 characters")

    ctx.user_store.create_user = refuse
    body = _compare("/api/users/create",
                    {"username": "dave", "role": "viewer", "password": "short"})
    assert body == {"ok": False, "error": "the password must be at least 12 characters"}

    # 5. No store at all is a 503 BEFORE the body is validated, as on the console.
    ctx.user_store = None
    ls, lb = _post_legacy(legacy.port, "/api/users/create", b"{}")
    fs, fb = _post_flask(app, "/api/users/create", b"{}")
    assert fs == ls == 503, f"console {ls}, flask {fs}"
    assert json.loads(fb) == json.loads(lb)


def test_the_session_writes_answer_identically(surfaces, monkeypatch):
    """Sign in, sign out and change your own password: same order, same bodies, same revocations.

    THE ORDER IS THE POINT IN TWO PLACES. A GUI with no accounts refuses a sign-in BEFORE it looks at
    the body, so a malformed one still gets 403; and a request with no session is refused before the
    body is parsed, so sign-out and password-change answer 401 even when the JSON is garbage.
    """
    import types

    from weirvern.admin import gui_auth

    legacy, app = surfaces()
    ctx = legacy.ctx
    ident = types.SimpleNamespace(is_admin=False, must_change=False, username="viewer",
                                  role="viewer")

    class _Store:
        def has_users(self):
            return True

        def find(self, username):
            return types.SimpleNamespace(username=username, hash="hashed",
                                        role="viewer", is_admin=False, must_change=False)

        def set_password(self, username, password, must_change=False):
            revocations.append(("password", username, password, must_change))

    revocations: list = []
    ctx.user_store = _Store()
    ctx.sessions = types.SimpleNamespace(
        revoke=lambda token: revocations.append(("revoke", token)) or 1,
        revoke_user=lambda u: revocations.append(("revoke_user", u)) or 1,
    )
    audited: list = []
    _patch(monkeypatch, "weirvern.admin.requestauth.audit_auth",
           lambda ctx_, action, username, reason: audited.append((action, username, reason)))
    _patch(monkeypatch, "weirvern.admin.users.verify_password",
           lambda presented, hashed: presented == "right")

    def _both(path, payload, headers=None):
        raw = json.dumps(payload).encode() if payload is not None else b""
        return (_post_legacy(legacy.port, path, raw, headers),
                _post_flask(app, path, raw, headers))

    def _same(path, payload, headers=None, expected=None):
        (ls, lb), (fs, fb) = _both(path, payload, headers)
        if expected is not None:
            assert ls == fs == expected, f"{path}: console {ls}, flask {fs}: {lb[:160]!r} / {fb[:160]!r}"
        assert fs == ls, f"{path}: console {ls}, flask {fs}"
        assert json.loads(fb) == json.loads(lb), (
            f"{path} drifted.\n  console: {lb[:200]!r}\n  flask:   {fb[:200]!r}")
        return json.loads(fb)

    # 1. No accounts: 403 BEFORE the body is examined, so malformed JSON does not become a 400.
    ctx.user_store = None
    body = _same("/api/login", None, expected=403)
    assert body["error"].startswith("cannot sign in: "), body
    (ls, lb), (fs, fb) = _both("/api/login", None)
    assert b"is required" not in lb and b"is required" not in fb

    # 2. With accounts: a good password mints a token, a bad one answers 401 with the same words.
    ctx.user_store = _Store()
    _patch(monkeypatch, "weirvern.admin.requestauth.authenticate",
           lambda ctx_, u, p, addr="": ((ident, "tok-abc", None) if p == "right"
                                        else (None, None, "the username or password is not correct")))
    body = _same("/api/login", {"username": "viewer", "password": "right"}, expected=200)
    assert body["session"] == "tok-abc" and body["role"] == "viewer", body
    body = _same("/api/login", {"username": "viewer", "password": "wrong"}, expected=401)
    assert body["error"] == "the username or password is not correct", body

    # 3. No session: 401 "sign in first" on both, and no body parsing to get in the way.
    body = _same("/api/logout", None, expected=401)
    assert body == {"error": "sign in first", "code": 401}, body
    body = _same("/api/password", {"current": "wrong"}, expected=401)
    assert body == {"error": "sign in first", "code": 401}, body

    # 4. With a session: sign-out revokes THIS session and audits the fact.
    _patch(monkeypatch, "weirvern.admin.requestauth.identity", lambda *a, **k: ident)
    headers = {gui_auth.SESSION_HEADER: "tok-abc"}
    del revocations[:], audited[:]
    body = _same("/api/logout", None, headers, expected=200)
    assert body == {"ok": True}, body
    assert revocations == [("revoke", "tok-abc"), ("revoke", "tok-abc")], revocations
    assert audited == [("logout", "viewer", "signed out")] * 2, audited

    # 5. A wrong current password is a 401 and writes nothing.
    del revocations[:]
    body = _same("/api/password", {"current": "wrong", "new": "new-one"}, headers, expected=401)
    assert body == {"ok": False, "error": "the current password is not correct"}, body
    assert revocations == [], revocations

    # 6. The right one saves, then revokes every session for the account.
    body = _same("/api/password", {"current": "right", "new": "new-one"}, headers, expected=200)
    assert body["signed_out"] is True, body
    assert revocations == [("password", "viewer", "new-one", False),
                          ("revoke_user", "viewer"),
                          ("password", "viewer", "new-one", False),
                          ("revoke_user", "viewer")], revocations


def test_the_sluice_and_scan_writes_answer_identically(surfaces, monkeypatch):
    """Rules that can take a network down, and a scan queue: same refusals, same order, same notes.

    TWO 400 SHAPES, PINNED APART. A malformed NUMBER is the house `{"error", "code"}` body; a REFUSED
    RULE is `{"ok": false, "error"}` with the sentence the form renders inline. A port that collapsed
    them would look tidy and change what the operator sees.
    """
    import types

    from weirvern import sluice, sluice_store

    legacy, app = surfaces()
    ctx = legacy.ctx
    ctx.settings = types.SimpleNamespace(
        sluice_iface="eth0", zeek_iface="", mgmt_iface="eth1", sluice_interval_s=15)
    ident = types.SimpleNamespace(is_admin=True, must_change=False, username="sam", role="admin")
    _patch(monkeypatch, "weirvern.admin.requestauth.identity", lambda *a, **k: ident)

    def _no_probe(**kwargs):
        raise RuntimeError("no probe in this test")

    _patch(monkeypatch, "weirvern.admin.interfaces.probe_local", _no_probe)

    def _both(path, payload):
        raw = json.dumps(payload).encode()
        return (_post_legacy(legacy.port, path, raw), _post_flask(app, path, raw))

    def _same(path, payload, expected):
        (ls, lb), (fs, fb) = _both(path, payload)
        assert ls == fs == expected, f"{path} {payload}: console {ls}, flask {fs}: {lb[:200]!r} / {fb[:200]!r}"
        assert json.loads(fb) == json.loads(lb), (
            f"{path} {payload} drifted.\n  console: {lb[:220]!r}\n  flask:   {fb[:220]!r}")
        return json.loads(fb)

    # ── scan jobs ──────────────────────────────────────────────────────────────────────────────
    body = _same("/api/scan-jobs", {"ip": "203.0.113.300"}, 400)
    assert body["error"] == "'ip' must be a single IP address", body

    _patch(monkeypatch, "weirvern.scan_jobs.find_asset", lambda client, ip: None)
    _same("/api/scan-jobs", {"ip": "203.0.113.5"}, 404)

    _patch(monkeypatch, "weirvern.scan_jobs.find_asset",
           lambda client, ip: {"asset_key": "asset-1"})
    _patch(monkeypatch, "weirvern.scan_jobs.active_for_asset",
           lambda client, key: {"job_id": 7, "state": "running"})
    body = _same("/api/scan-jobs", {"ip": "203.0.113.5"}, 200)
    assert body == {"ok": True, "job_id": "7", "ip": "203.0.113.5",
                    "state": "running", "already": True}, body

    _patch(monkeypatch, "weirvern.scan_jobs.active_for_asset", lambda client, key: None)
    _patch(monkeypatch, "weirvern.scan_jobs.create_job",
           lambda client, asset, requested_by="": {"job_id": 9})
    body = _same("/api/scan-jobs", {"ip": "203.0.113.5"}, 200)
    assert body == {"ok": True, "job_id": "9", "ip": "203.0.113.5",
                    "state": "queued", "already": False}, body

    # ── sluice: block ──────────────────────────────────────────────────────────────────────────
    _patch(monkeypatch, "weirvern.sluice.parse_cidr", lambda raw, role: raw or "203.0.113.0/24")
    _patch(monkeypatch, "weirvern.sluice.refuse_reason", lambda **kw: "")

    body = _same("/api/sluice/block", {"src_cidr": "203.0.113.0/24", "dst_port": "abc"}, 400)
    assert "dst_port must be a number" in body["error"] and body["code"] == 400, body

    body = _same("/api/sluice/block", {"src_cidr": "203.0.113.0/24", "ttl_minutes": "soon"}, 400)
    assert "ttl_minutes must be a number" in body["error"], body

    rule = types.SimpleNamespace(
        rule_id="rule-1", mode="block",
        expires_at=__import__("datetime").datetime(2026, 11, 15, 12, 0),
        describes=lambda: "203.0.113.0/24 -> any tcp/443",
    )
    _patch(monkeypatch, "weirvern.sluice_store.create_rule", lambda client, **kw: rule)
    body = _same("/api/sluice/block", {"src_cidr": "203.0.113.0/24", "dst_port": 443}, 200)
    assert body["rule_id"] == "rule-1" and body["note"].startswith("recorded;"), body
    assert "ALERT mode" not in body["note"], body

    # A refused rule is the OTHER 400 shape: `{"ok": false, "error"}` and nothing else.
    _patch(monkeypatch, "weirvern.sluice.refuse_reason",
           lambda **kw: "refusing to block the management address 203.0.113.2")
    body = _same("/api/sluice/block", {"src_cidr": "203.0.113.2", "dst_port": 443}, 400)
    assert body == {"ok": False,
                    "error": "refusing to block the management address 203.0.113.2"}, body

    # Indefinite and ALERT-mode rules say so; the note is part of the contract.
    _patch(monkeypatch, "weirvern.sluice.refuse_reason", lambda **kw: "")
    indefinite = types.SimpleNamespace(rule_id="rule-2", mode="alert", expires_at=None,
                                       describes=lambda: "dns name")
    _patch(monkeypatch, "weirvern.sluice_store.create_rule", lambda client, **kw: indefinite)
    body = _same("/api/sluice/block", {"domain": "example.com"}, 200)
    assert "it stays until it is revoked" in body["note"], body
    assert "ALERT mode" in body["note"], body

    # ── sluice: revoke ─────────────────────────────────────────────────────────────────────────
    body = _same("/api/sluice/revoke", {"rule_id": "rule-1"}, 400)
    assert "a reason is required" in body["error"], body

    _patch(monkeypatch, "weirvern.sluice_store.revoke_rule", lambda client, rid, by="": False)
    body = _same("/api/sluice/revoke", {"rule_id": "rule-9", "reason": "false positive"}, 404)
    assert body == {"ok": False, "error": "no rule with id 'rule-9'"}, body

    _patch(monkeypatch, "weirvern.sluice_store.revoke_rule", lambda client, rid, by="": True)
    body = _same("/api/sluice/revoke", {"rule_id": "rule-1", "reason": "false positive"}, 200)
    assert body["rule_id"] == "rule-1" and "within 15s" in body["note"], body

    _patch(monkeypatch, "weirvern.sluice_store.revoke_rules",
           lambda client, ids, by="": {"revoked": list(ids), "missing": ["rule-x"]})
    body = _same("/api/sluice/revoke",
                 {"rule_ids": ["rule-1", "rule-x"], "reason": "cleanup"}, 200)
    assert body["revoked"] == ["rule-1", "rule-x"] and body["missing"] == ["rule-x"], body
    assert sluice and sluice_store, "the patches above must target the real modules"


def test_the_sluice_rule_edits_answer_identically(surfaces, monkeypatch):
    """Mode, rename and park: the `confirmed` friction, the odd 503, and per-id refusals.

    THREE SHAPES THAT ARE EASY TO "TIDY" AWAY. Arming the kernel without `confirmed: true` is a 400
    carrying `{"ok": false}`; a store failure the console knows nothing about is a 503 that ALSO says
    `{"ok": false}` rather than the house error body; and a bulk park reports the rules it refused in
    a list beside the ones it changed instead of failing the whole selection.
    """
    import types

    from weirvern import sluice, sluice_store

    legacy, app = surfaces()
    ctx = legacy.ctx
    ctx.settings = types.SimpleNamespace(
        sluice_iface="eth0", zeek_iface="", mgmt_iface="eth1", sluice_interval_s=15)
    ident = types.SimpleNamespace(is_admin=True, must_change=False, username="sam", role="admin")
    _patch(monkeypatch, "weirvern.admin.requestauth.identity", lambda *a, **k: ident)

    def _same(path, payload, expected):
        raw = json.dumps(payload).encode()
        (ls, lb) = _post_legacy(legacy.port, path, raw)
        (fs, fb) = _post_flask(app, path, raw)
        assert ls == fs == expected, (
            f"{path} {payload}: console {ls}, flask {fs}: {lb[:200]!r} / {fb[:200]!r}")
        assert json.loads(fb) == json.loads(lb), (
            f"{path} {payload} drifted.\n  console: {lb[:220]!r}\n  flask:   {fb[:220]!r}")
        return json.loads(fb)

    rule = types.SimpleNamespace(rule_id="rule-1", mode="alert", domain="*.example.com",
                                 describes=lambda: "*.example.com")

    # ── mode ──────────────────────────────────────────────────────────────────────────────────
    body = _same("/api/sluice/rule/mode", {"rule_id": "rule-1", "mode": "block"}, 400)
    assert body == {"ok": False, "error": "moving a rule to block changes what the kernel drops; "
                                          "resend with confirmed: true"}, body

    calls = []
    _patch(monkeypatch, "weirvern.sluice_store.update_rule_mode",
           lambda client, rid, mode, by="": (calls.append((rid, mode, by)) or rule))
    body = _same("/api/sluice/rule/mode",
                 {"rule_id": "rule-1", "mode": "block", "confirmed": True}, 200)
    assert body == {"ok": True, "rule": {"rule_id": "rule-1", "describes": "*.example.com",
                                        "mode": "alert"}}, body
    assert calls == [("rule-1", "block", "sam")] * 2, calls

    # Moving BACK to alert needs no confirmation: widening what drops is not the dangerous direction.
    _same("/api/sluice/rule/mode", {"rule_id": "rule-1", "mode": "alert"}, 200)

    # ── rename ────────────────────────────────────────────────────────────────────────────────
    body = _same("/api/sluice/rule/domain", {"rule_id": "rule-1"}, 400)
    assert body["error"] == "a domain is required" and body["code"] == 400, body

    _patch(monkeypatch, "weirvern.sluice_store.update_rule",
           lambda client, rid, domain="", by="": rule)
    body = _same("/api/sluice/rule/domain",
                 {"rule_id": "rule-1", "domain": "*.example.com"}, 200)
    assert body == {"ok": True, "rule": {"rule_id": "rule-1", "describes": "*.example.com",
                                        "domain": "*.example.com"}}, body

    # ── park ──────────────────────────────────────────────────────────────────────────────────
    body = _same("/api/sluice/rule/disabled", {"disabled": True}, 400)
    assert body["error"] == "rule_id (or rule_ids) is required", body

    parked: list = []
    _patch(monkeypatch, "weirvern.sluice_store.set_rule_disabled",
           lambda client, rid, disabled, by="": parked.append((rid, disabled, by)))
    body = _same("/api/sluice/rule/disabled", {"rule_id": "rule-1", "disabled": True}, 200)
    assert body == {"ok": True, "changed": ["rule-1"], "refused": [],
                    "note": "disabled; enforcement reflects it within 15s"}, body
    assert parked == [("rule-1", True, "sam")] * 2, parked

    # ONE REFUSED ID DOES NOT SINK THE REST OF THE SELECTION.
    def _park(client, rid, disabled, by=""):
        if rid == "rule-x":
            raise sluice_store.SluiceError("rule-x was revoked while you were selecting")
        parked.append((rid, disabled, by))

    _patch(monkeypatch, "weirvern.sluice_store.set_rule_disabled", _park)
    body = _same("/api/sluice/rule/disabled",
                 {"rule_ids": ["rule-1", "rule-x"], "disabled": False}, 200)
    assert body["changed"] == ["rule-1"] and body["refused"] == [
        {"rule_id": "rule-x", "error": "rule-x was revoked while you were selecting"}], body
    assert body["note"].startswith("re-enabled;"), body
    assert sluice, "the patches above must target the real module"


def test_the_blocklist_and_network_writes_answer_identically(surfaces, monkeypatch):
    """Six routes with one shape: sync, add a source, edit the custom list, toggle a list, save and
    delete a network scope.

    THREE FAILURE SHAPES, ALL PRESERVED. A refused source or a bad action is a 400 saying
    `{"ok": false}`; a toggle that fails on the store is a 503 that ALSO says `{"ok": false}` with the
    read_failure wording; and a network scope that cannot be written is a 500 carrying only the first
    200 characters of the reason, because the form has one line for it.
    """
    import types

    from weirvern import blocklists, networks, sluice

    legacy, app = surfaces()
    ctx = legacy.ctx
    ctx.settings = types.SimpleNamespace(sluice_iface="eth0", zeek_iface="", mgmt_iface="eth1",
                                         sluice_interval_s=15)
    ident = types.SimpleNamespace(is_admin=True, must_change=False, username="sam", role="admin")
    _patch(monkeypatch, "weirvern.admin.requestauth.identity", lambda *a, **k: ident)

    def _same(path, payload, expected):
        raw = b"" if payload is None else json.dumps(payload).encode()
        (ls, lb) = _post_legacy(legacy.port, path, raw)
        (fs, fb) = _post_flask(app, path, raw)
        assert ls == fs == expected, (
            f"{path} {payload}: console {ls}, flask {fs}: {lb[:200]!r} / {fb[:200]!r}")
        assert json.loads(fb) == json.loads(lb), (
            f"{path} {payload} drifted.\n  console: {lb[:240]!r}\n  flask:   {fb[:240]!r}")
        return json.loads(fb)

    # ── sync ──────────────────────────────────────────────────────────────────────────────────
    synced: list = []
    _patch(monkeypatch, "weirvern.blocklists.ensure_default_sources", lambda client: None)
    _patch(monkeypatch, "weirvern.blocklists.load_sources",
           lambda client: [{"source_id": "ad", "enabled": True},
                           {"source_id": "custom", "enabled": True},
                           {"source_id": "off", "enabled": False}])
    _patch(monkeypatch, "weirvern.blocklists.sync_source",
           lambda client, src: (synced.append(src["source_id"]) or {"added": 2}))
    body = _same("/api/blocklists/sync", None, 200)
    # THE CUSTOM LIST IS NOT A FEED: syncing it would replace typed names with a URL's answer.
    assert body == {"ok": True, "results": [{"source_id": "ad", "added": 2}]}, body
    assert synced == ["ad", "ad"], synced

    # ── add a source ──────────────────────────────────────────────────────────────────────────
    def _refuse(client, url, name="", fmt="domains"):
        raise ValueError("the list is in Adblock format, which this importer cannot read")

    _patch(monkeypatch, "weirvern.blocklists.add_source", _refuse)
    body = _same("/api/blocklists/source", {"url": "https://lists.example/x.txt"}, 400)
    assert body["ok"] is False and "Adblock" in body["error"], body
    assert "code" not in body, "a store refusal must not grow a code key"

    _patch(monkeypatch, "weirvern.blocklists.add_source",
           lambda client, url, name="", fmt="domains": {"source_id": "ad", "url": url,
                                                        "format": fmt})
    body = _same("/api/blocklists/source",
                 {"url": "https://lists.example/x.txt", "format": "domains"}, 200)
    assert body["source"]["format"] == "domains" and "Sync now" in body["note"], body

    # ── the custom list ──────────────────────────────────────────────────────────────────────
    body = _same("/api/blocklists/custom", {"action": "erase", "domain": "x"}, 400)
    assert body == {"error": "action must be add or remove, not 'erase'", "code": 400}, body

    def _bad_name(client, domain):
        raise sluice.SluiceError("that is not a domain name")

    _patch(monkeypatch, "weirvern.blocklists.add_custom_domain", _bad_name)
    body = _same("/api/blocklists/custom", {"action": "add", "domain": "nope"}, 400)
    assert body == {"ok": False, "error": "that is not a domain name"}, body

    _patch(monkeypatch, "weirvern.blocklists.remove_custom_domain",
           lambda client, domain: domain)
    body = _same("/api/blocklists/custom", {"action": "remove", "domain": "bad.example"}, 200)
    assert body == {"ok": True, "action": "remove", "domain": "bad.example"}, body

    # ── toggle a list ────────────────────────────────────────────────────────────────────────
    body = _same("/api/blocklists/enable", {"source_id": "ad", "enabled": "yes"}, 400)
    assert body == {"error": "source_id and a boolean enabled are required", "code": 400}, body

    _patch(monkeypatch, "weirvern.blocklists.set_source_enabled",
           lambda client, sid, enabled: {"source_id": sid, "enabled": enabled})
    on = _same("/api/blocklists/enable", {"source_id": "ad", "enabled": True}, 200)
    assert on["note"].startswith("on \u2014 its names join"), on
    off = _same("/api/blocklists/enable", {"source_id": "ad", "enabled": False}, 200)
    assert off["note"].startswith("off \u2014 its names leave"), off

    def _enable_boom(client, sid, enabled):
        raise RuntimeError("the table is gone")

    _patch(monkeypatch, "weirvern.blocklists.set_source_enabled", _enable_boom)
    body = _same("/api/blocklists/enable", {"source_id": "ad", "enabled": True}, 503)
    # The 503 keeps the read_failure wording, which NAMES the layer that failed and the exception.
    assert body["ok"] is False and body["error"].startswith("could not read the data:"), body

    # ── network scopes ──────────────────────────────────────────────────────────────────────
    _patch(monkeypatch, "weirvern.networks.overview",
           lambda client, hours=24: {"scopes": [], "hours": hours})

    def _scope_refuse(client, body):
        raise ValueError("a scope needs a name")

    _patch(monkeypatch, "weirvern.networks.save_scope", _scope_refuse)
    body = _same("/api/networks/save", {"name": ""}, 400)
    assert body == {"error": "a scope needs a name", "code": 400}, body

    _patch(monkeypatch, "weirvern.networks.save_scope",
           lambda client, body: types.SimpleNamespace(public=lambda: {"id": "n1",
                                                                     "name": body.get("name")}))
    body = _same("/api/networks/save", {"name": "home"}, 200)
    assert body["ok"] is True and body["scope"] == {"id": "n1", "name": "home"}, body

    # THE 500 KEEPS THE CONSOLE'S 200-CHARACTER CUT.
    _patch(monkeypatch, "weirvern.networks.delete_scope",
           lambda client, sid: (_ for _ in ()).throw(RuntimeError("x" * 400)))
    body = _same("/api/networks/delete", {"id": "n1"}, 500)
    assert len(body["error"]) == len("could not delete the network scope: ") + 200, len(body["error"])

    _patch(monkeypatch, "weirvern.networks.delete_scope", lambda client, sid: False)
    body = _same("/api/networks/delete", {"id": "n1"}, 200)
    assert body["ok"] is False and body["scopes"] == [], body

    _patch(monkeypatch, "weirvern.networks.delete_scope", lambda client, sid: True)
    body = _same("/api/networks/delete", {"id": "n1"}, 200)
    assert body["ok"] is True, body
    assert blocklists and networks, "the patches above must target the real modules"


def test_the_fleet_writes_answer_identically(surfaces, monkeypatch):
    """Register, enable, revoke, plan, apply and probe: the fleet panel's whole write surface.

    THREE THINGS WORTH PINNING. A rejected registration is a 400 carrying {"ok": false} rather than a
    5xx -- it is a normal outcome of a form. Revoking the HUB'S OWN sensor clears the ConfigMap keys
    and restarts what read them, because a registry row alone left the worker forwarding; revoking a
    remote one touches no settings at all. And a probe never guesses an interface: a sensor reporting
    several NICs is refused rather than probed on the wrong one.
    """
    import types

    from weirvern import fleet_store

    legacy, app = surfaces()
    ctx = legacy.ctx
    ctx.settings = types.SimpleNamespace(sluice_iface="eth0", zeek_iface="", mgmt_iface="eth1",
                                         sluice_interval_s=15)
    ident = types.SimpleNamespace(is_admin=True, must_change=False, username="sam", role="admin")
    _patch(monkeypatch, "weirvern.admin.requestauth.identity", lambda *a, **k: ident)
    _patch(monkeypatch, "weirvern.admin.web._gate_sensor_name", lambda: "hub-eth0")

    def _same(path, payload, expected):
        raw = json.dumps(payload).encode()
        (ls, lb) = _post_legacy(legacy.port, path, raw)
        (fs, fb) = _post_flask(app, path, raw)
        assert ls == fs == expected, (
            f"{path} {payload}: console {ls}, flask {fs}: {lb[:200]!r} / {fb[:200]!r}")
        assert json.loads(fb) == json.loads(lb), (
            f"{path} {payload} drifted.\n  console: {lb[:240]!r}\n  flask:   {fb[:240]!r}")
        return json.loads(fb)

    # ── register ──────────────────────────────────────────────────────────────────────────────
    def _fleet_error(*a, **k):
        raise fleet_store.FleetError("a sensor id is required")

    _patch(monkeypatch, "weirvern.fleet_store.register", _fleet_error)
    body = _same("/api/weirlings/register", {"sensor_id": ""}, 400)
    assert body == {"ok": False, "error": "a sensor id is required"}, body

    _patch(monkeypatch, "weirvern.fleet_store.register",
           lambda client, sensor_id, **k: types.SimpleNamespace(sensor_id=sensor_id))
    body = _same("/api/weirlings/register", {"sensor_id": "remote-1"}, 200)
    assert body == {"ok": True, "sensor_id": "remote-1"}, body

    # ── enable: the STRING "false" must not enable anything ──────────────────────────────────
    body = _same("/api/weirlings/enable", {"sensor_id": "remote-1", "enabled": "false"}, 400)
    assert body == {"ok": False, "error": "`enabled` must be true or false"}, body

    _patch(monkeypatch, "weirvern.fleet_store.set_enabled",
           lambda client, sid, enabled: types.SimpleNamespace(sensor_id=sid, enabled=enabled))
    body = _same("/api/weirlings/enable", {"sensor_id": "remote-1", "enabled": False}, 200)
    assert body == {"ok": True, "sensor_id": "remote-1", "enabled": False}, body

    # ── revoke ────────────────────────────────────────────────────────────────────────────────
    body = _same("/api/weirlings/revoke", {"sensor_id": "remote-1"}, 400)
    assert "revoking a registration is a decision" in body["error"], body

    audits: list = []
    _patch(monkeypatch, "weirvern.fleet_store.revoke_registration",
           lambda client, sid: types.SimpleNamespace(sensor_id=sid))
    _patch(monkeypatch, "weirvern.fleet_store.write_audit", lambda client, **k: audits.append(k))
    body = _same("/api/weirlings/revoke",
                 {"sensor_id": "remote-1", "reason": "decommissioned"}, 200)
    assert body == {"ok": True, "sensor_id": "remote-1", "settings_cleared": None,
                    "settings_error": ""}, body
    assert audits and audits[0]["action"] == "revoke", audits

    # THE HUB'S OWN SENSOR: the registry row is not enough, the ConfigMap must be cleared too.
    applied: list = []
    restarted: list = []
    ctx.config_client = types.SimpleNamespace(
        read=lambda: {"SENSOR_MODE": "siphon"},
        apply=lambda changes, reason="", by="": applied.append((dict(changes), reason, by)),
        restart=lambda target: restarted.append(target),
    )
    body = _same("/api/weirlings/revoke", {"sensor_id": "hub-eth0", "reason": "retiring"}, 200)
    assert body["settings_cleared"] is True, body
    assert applied and "SENSOR_MODE" in applied[0][0], applied
    assert applied[0][2] == "sam", applied

    # ── plan: the preview cannot be looser than the write ─────────────────────────────────────
    _patch(monkeypatch, "weirvern.fleet_store.plan_subject", lambda client, sid: (None, ""))
    body = _same("/api/weirlings/plan", {"sensor_id": "remote-1"}, 400)
    assert body["ok"] is False and "`changes`" in body["error"], body

    body = _same("/api/weirlings/plan",
                 {"sensor_id": "remote-1", "changes": {"mode": "siphon"}}, 200)
    prop = next(p for p in body["proposals"] if p["key"] == "mode")
    assert prop["value"] == "siphon" and "IN THE TRAFFIC PATH" in prop["warning"], prop
    assert body["restart_targets"] == [], body

    # ── apply: an in-path plan needs a reason, and the row lands ──────────────────────────────
    registered: list = []
    _patch(monkeypatch, "weirvern.fleet_store.register",
           lambda client, sensor_id, plan=None, **k: registered.append((sensor_id, plan)))
    body = _same("/api/weirlings/apply",
                 {"sensor_id": "remote-1", "changes": {"mode": "siphon"}}, 400)
    assert "irreversible enough to deserve a reason" in body["error"], body

    body = _same("/api/weirlings/apply",
                 {"sensor_id": "remote-1", "changes": {"mode": "siphon"},
                  "reason": "splitting traffic"}, 200)
    assert body["applied"] == {"mode": "siphon"}, body
    assert len(registered) == 2, registered

    # ── probe ─────────────────────────────────────────────────────────────────────────────────
    body = _same("/api/weirlings/probe", {}, 400)
    assert body == {"ok": False, "error": "sensor_id is required"}, body

    body = _same("/api/weirlings/probe", {"sensor_id": "hub-eth0"}, 400)
    assert "the hub's own sensor" in body["error"], body

    _patch(monkeypatch, "weirvern.fleet_store.classify_one", lambda client, sid: {"interfaces": []})
    _patch(monkeypatch, "weirvern.fleet_store.read_registrations", lambda client: [])
    body = _same("/api/weirlings/probe", {"sensor_id": "ghost"}, 404)
    assert body == {"ok": False, "error": "no registered weirling named 'ghost'"}, body

    _patch(monkeypatch, "weirvern.fleet_store.read_registrations",
           lambda client: [types.SimpleNamespace(sensor_id="remote-1", plan=None, enabled=True)])
    _patch(monkeypatch, "weirvern.fleet_store.classify_one",
           lambda client, sid: {"interfaces": ["eth2", "eth3"]})
    body = _same("/api/weirlings/probe", {"sensor_id": "remote-1"}, 400)
    assert "reports several NICs" in body["error"], body

    _patch(monkeypatch, "weirvern.probe_store.create_request",
           lambda client, sensor_id, iface, seconds: {
               "request_id": "p1", "sensor_id": sensor_id, "iface": iface,
               "seconds": seconds, "status": "queued"})
    body = _same("/api/weirlings/probe", {"sensor_id": "remote-1", "iface": "eth2"}, 202)
    assert body["request_id"] == "p1" and body["scope"] == "capture-liveness", body


def test_autofill_and_the_settings_plan_answer_identically(surfaces, monkeypatch):
    """The one-approval scope fill, and the dry run that states the blast radius.

    THE 409 IS THE SAFETY PROPERTY: a second call, or a deployment whose scopes the operator already
    edited by hand, must be refused rather than overwritten with a suggestion. And the plan must
    ECHO THE CALLER'S KEY VOCABULARY (`sensor_mode`, not `SENSOR_MODE`) or the UI's warning lookup
    misses and skips the costly-change dialog for exactly the changes that need it.
    """
    import types

    from weirvern import networks
    from weirvern.admin import cluster_config as cc

    legacy, app = surfaces()
    ctx = legacy.ctx
    ctx.settings = types.SimpleNamespace(sluice_iface="eth0", zeek_iface="", mgmt_iface="eth1",
                                         sluice_interval_s=15)
    ident = types.SimpleNamespace(is_admin=True, must_change=False, username="sam", role="admin")
    _patch(monkeypatch, "weirvern.admin.requestauth.identity", lambda *a, **k: ident)

    def _same(path, payload, expected):
        raw = b"" if payload is None else json.dumps(payload).encode()
        (ls, lb) = _post_legacy(legacy.port, path, raw)
        (fs, fb) = _post_flask(app, path, raw)
        assert ls == fs == expected, (
            f"{path} {payload}: console {ls}, flask {fs}: {lb[:200]!r} / {fb[:200]!r}")
        assert json.loads(fb) == json.loads(lb), (
            f"{path} {payload} drifted.\n  console: {lb[:240]!r}\n  flask:   {fb[:240]!r}")
        return json.loads(fb)

    # ── autofill ──────────────────────────────────────────────────────────────────────────────
    _patch(monkeypatch, "weirvern.networks.load_scopes", lambda client: [{"id": "n1"}])
    body = _same("/api/networks/autofill", None, 409)
    assert body == {"error": "network scopes are already declared", "code": 409}, body

    _patch(monkeypatch, "weirvern.networks.load_scopes", lambda client: [])
    _patch(monkeypatch, "weirvern.networks.suggested_monitored_scopes", lambda: [])
    body = _same("/api/networks/autofill", None, 400)
    assert body == {"error": "no monitored networks are configured to fill from",
                    "code": 400}, body

    saved: list = []
    scope = types.SimpleNamespace(public=lambda: {"id": "n1", "name": "lan"})
    _patch(monkeypatch, "weirvern.networks.suggested_monitored_scopes", lambda: [scope])
    _patch(monkeypatch, "weirvern.networks.save_scope",
           lambda client, body: (saved.append(body) or scope))
    _patch(monkeypatch, "weirvern.networks.overview",
           lambda client, hours=24: {"scopes": [], "hours": hours})
    body = _same("/api/networks/autofill", None, 200)
    assert body["created"] == 1 and body["scopes_added"] == [{"id": "n1", "name": "lan"}], body
    assert saved == [{"id": "n1", "name": "lan"}] * 2, saved

    # ── the settings plan ─────────────────────────────────────────────────────────────────────
    body = _same("/api/settings/plan", {}, 400)
    assert body == {"error": "a non-empty 'changes' object is required", "code": 400}, body

    ctx.config_client = types.SimpleNamespace(
        read=lambda: {"SENSOR_MODE": "loch", "INTERCEPT_SECONDS": "600"})

    class _Proposal:
        key = "SENSOR_MODE"
        current = "loch"
        proposed = "siphon"
        restarts = ["worker"]
        blast = "in path"
        warning = "this puts the sensor in the traffic path"

    _patch(monkeypatch, "weirvern.admin.cluster_config.plan",
           lambda changes, current: types.SimpleNamespace(
               proposals=[_Proposal], restart_targets=["worker"]))
    _patch(monkeypatch, "weirvern.admin.cluster_config.to_configmap_key",
           lambda key: "SENSOR_MODE" if key == "sensor_mode" else key.upper())
    body = _same("/api/settings/plan", {"changes": {"sensor_mode": "siphon"}}, 200)
    # THE KEY COMES BACK AS THE CALLER NAMED IT, or the UI's warning lookup never matches.
    assert body["proposals"][0]["key"] == "sensor_mode", body["proposals"]
    assert body["proposals"][0]["warning"], body["proposals"]
    assert body["restart_targets"] == ["worker"], body

    def _cfg_error(*a, **k):
        raise cc.ConfigError("SENSOR_MODE must be loch or siphon")

    _patch(monkeypatch, "weirvern.admin.cluster_config.plan", _cfg_error)
    body = _same("/api/settings/plan", {"changes": {"sensor_mode": "sideways"}}, 400)
    assert body == {"ok": False, "error": "SENSOR_MODE must be loch or siphon"}, body
    assert networks, "the patches above must target the real module"


def test_the_settings_apply_answers_identically(surfaces, monkeypatch):
    """The one route that writes the ConfigMap: four gates before the write, and a receipt after it.

    THE ORDER OF THE GATES IS THE CONTRACT. A siphon change with no reason is refused BEFORE the
    configuration is even read, so the operator is told what is missing rather than being shown a
    validation error from a plan nobody needed. Then the plan's validation, then the explicit
    confirmation of any warned change, then the mode's own prerequisite gate. Only after all four
    does anything get written.
    """
    import types

    from weirvern.admin import cluster_config as cc
    from weirvern.admin import mode as mode_mod

    legacy, app = surfaces()
    ctx = legacy.ctx
    ident = types.SimpleNamespace(is_admin=True, must_change=False, username="sam", role="admin")
    _patch(monkeypatch, "weirvern.admin.requestauth.identity", lambda *a, **k: ident)

    applied: list = []
    restarted: list = []
    ctx.config_client = types.SimpleNamespace(
        read=lambda: {"SENSOR_MODE": "loch", "INTERCEPT_SECONDS": "600"},
        apply=lambda changes, reason="", by="": (applied.append((dict(changes), reason, by))
                                                 or {"SENSOR_MODE": "siphon"}),
        restart=lambda target: restarted.append(target),
        get_json=lambda path: {},
    )

    def _same(path, payload, expected):
        raw = json.dumps(payload).encode()
        (ls, lb) = _post_legacy(legacy.port, path, raw)
        (fs, fb) = _post_flask(app, path, raw)
        assert ls == fs == expected, (
            f"{path} {payload}: console {ls}, flask {fs}: {lb[:220]!r} / {fb[:220]!r}")
        assert json.loads(fb) == json.loads(lb), (
            f"{path} {payload} drifted.\n  console: {lb[:260]!r}\n  flask:   {fb[:260]!r}")
        return json.loads(fb)

    class _Proposal:
        key = "SENSOR_MODE"
        current = "loch"
        proposed = "siphon"
        restarts = ["worker"]
        blast = "in path"
        warning = "this puts the deployment in the traffic path"

    _patch(monkeypatch, "weirvern.admin.cluster_config.plan",
           lambda changes, current: types.SimpleNamespace(
               proposals=[_Proposal], restart_targets=["worker"]))
    _patch(monkeypatch, "weirvern.admin.cluster_config.to_configmap_key",
           lambda key: key.upper())
    _patch(monkeypatch, "weirvern.admin.cluster_config.receipt_items",
           lambda changes, landed, after=None, error=None: [
               {"key": k, "value": (landed or {}).get(k.upper(), "")} for k in changes])

    # 1. An empty changes object.
    body = _same("/api/settings/apply", {}, 400)
    assert body == {"error": "a non-empty 'changes' object is required", "code": 400}, body

    # 2. IN PATH WITHOUT A REASON, refused before the configuration is read.
    body = _same("/api/settings/apply", {"changes": {"sensor_mode": "siphon"}}, 400)
    assert body["ok"] is False and "puts this deployment in the traffic path" in body["error"], body
    assert applied == [], "a refused apply must not write"

    # 3. A plan validation error is `{"ok": false}` with the validator's own sentence.
    def _plan_refuse(changes, current):
        raise cc.ConfigError("SENSOR_MODE must be loch or siphon")

    _patch(monkeypatch, "weirvern.admin.cluster_config.plan", _plan_refuse)
    body = _same("/api/settings/apply",
                 {"changes": {"sensor_mode": "sideways"}, "reason": "testing"}, 400)
    assert body == {"ok": False, "error": "SENSOR_MODE must be loch or siphon"}, body

    _patch(monkeypatch, "weirvern.admin.cluster_config.plan",
           lambda changes, current: types.SimpleNamespace(
               proposals=[_Proposal], restart_targets=["worker"]))

    # 4. A WARNED CHANGE WITHOUT `confirmed` IS A 409 CARRYING THE PROPOSALS, not a write.
    body = _same("/api/settings/apply",
                 {"changes": {"sensor_mode": "siphon"}, "reason": "splitting traffic"}, 409)
    assert body["ok"] is False and body["needs_confirmation"] is True, body
    assert body["proposals"] == [{"key": "SENSOR_MODE", "current": "loch",
                                  "proposed": "siphon",
                                  "warning": "this puts the deployment in the traffic path"}], body
    assert applied == [], "an unconfirmed warned change must not write"

    # 5. THE MODE'S OWN GATE, which the CLI also runs.
    _patch(monkeypatch, "weirvern.admin.mode.validate",
           lambda *a, **k: types.SimpleNamespace(ok=False, blockers=["NET_ADMIN is missing"]))
    body = _same("/api/settings/apply",
                 {"changes": {"sensor_mode": "siphon"}, "reason": "splitting traffic",
                  "confirmed": True}, 409)
    assert body == {"ok": False, "error": "cannot enable siphon: NET_ADMIN is missing"}, body
    assert applied == [], "a mode the prerequisites forbid must not write"

    _patch(monkeypatch, "weirvern.admin.mode.validate",
           lambda *a, **k: types.SimpleNamespace(ok=True, blockers=[]))

    # 6. The apply-time checks can BLOCK the write, and say which check failed.
    _patch(monkeypatch, "weirvern.apply_checks.run_apply_checks",
           lambda **k: {"results": [{"name": "forwarding"}], "blocked": True,
                        "failed": ["forwarding is not working"], "summary": "1 failed"})
    body = _same("/api/settings/apply",
                 {"changes": {"sensor_mode": "siphon"}, "reason": "splitting traffic",
                  "confirmed": True}, 409)
    assert body["blocked"] is True, body
    assert body["error"] == "blocked by apply-time checks: forwarding is not working", body
    assert body["tests"] == [{"name": "forwarding"}], body
    assert applied == [], "a blocked apply must not write"

    # 7. And when every gate passes, the write lands and the receipt translates back to row keys.
    _patch(monkeypatch, "weirvern.apply_checks.run_apply_checks",
           lambda **k: {"results": [{"name": "forwarding", "ok": True}], "blocked": False,
                        "failed": [], "summary": "1 passed"})
    body = _same("/api/settings/apply",
                 {"changes": {"sensor_mode": "siphon"}, "reason": "splitting traffic",
                  "confirmed": True}, 200)
    assert body["applied"] == {"sensor_mode": "siphon"}, body
    assert body["restarted"] == ["worker"] and body["restart_errors"] == [], body
    assert body["note"] == "restarted worker", body
    assert body["items"] == [{"key": "sensor_mode", "value": "siphon"}], body
    assert body["summary"] == "1 passed", body
    assert len(applied) == 2 and applied[0][1:] == ("splitting traffic", "sam"), applied
    assert restarted == ["worker", "worker"], restarted
    assert mode_mod, "the patches above must target the real module"


def test_the_settings_test_and_sonar_answer_identically(surfaces, monkeypatch):
    """The live probe and the segment survey: both bounded, both reporting an outcome, neither one
    inventing a success.

    THREE THINGS WORTH PINNING. A probe that RAN but could not revert is a 500 -- saved-but-inert is a
    failure of applying. A survey that ran and REFUSED passes its reason through as a 422, distinct
    from a job that could not run at all (502). And the NDJSON stream must carry the same lines on
    both surfaces: progress as it happens, then one result line.
    """
    import types

    from weirvern.admin import cluster_config as cc
    from weirvern.admin import sonar as sonar_mod

    legacy, app = surfaces()
    ctx = legacy.ctx
    ident = types.SimpleNamespace(is_admin=True, must_change=False, username="sam", role="admin")
    _patch(monkeypatch, "weirvern.admin.requestauth.identity", lambda *a, **k: ident)
    _patch(monkeypatch, "weirvern.admin.web._gate_sensor_name", lambda: "hub-eth0")
    monkeypatch.delenv("CAPTURE_IFACE", raising=False)
    monkeypatch.delenv("ZEEK_IFACE", raising=False)
    monkeypatch.delenv("MGMT_IFACE", raising=False)

    def _same(path, payload, expected):
        raw = json.dumps(payload).encode()
        (ls, lb) = _post_legacy(legacy.port, path, raw)
        (fs, fb) = _post_flask(app, path, raw)
        assert ls == fs == expected, (
            f"{path} {payload}: console {ls}, flask {fs}: {lb[:220]!r} / {fb[:220]!r}")
        assert json.loads(fb) == json.loads(lb), (
            f"{path} {payload} drifted.\n  console: {lb[:260]!r}\n  flask:   {fb[:260]!r}")
        return json.loads(fb)

    # ── the test run ──────────────────────────────────────────────────────────────────────────
    body = _same("/api/settings/test", {"seconds": "soon"}, 400)
    assert body["error"] == "seconds must be a number", body
    body = _same("/api/settings/test", {"seconds": 2}, 400)
    assert body["error"] == "seconds must be between 5 and 600", body

    ctx.config_client = types.SimpleNamespace(read=lambda: {"SENSOR_MODE": "loch"})
    probed: list = []
    _patch(monkeypatch, "weirvern.admin.siphon_probe.run_probe",
           lambda client, seconds, liveness: (probed.append(seconds)
                                              or {"ok": True, "reverted": True, "live": True}))
    body = _same("/api/settings/test", {}, 200)
    assert body["reverted"] is True, body
    assert probed == [30.0, 30.0], probed

    _patch(monkeypatch, "weirvern.admin.siphon_probe.run_probe",
           lambda client, seconds, liveness: {"ok": True, "reverted": False})
    body = _same("/api/settings/test", {"seconds": 10}, 500)
    assert body["reverted"] is False, body

    _patch(monkeypatch, "weirvern.admin.siphon_probe.run_probe",
           lambda client, seconds, liveness: {"ok": False, "error": "forwarding is not working"})
    body = _same("/api/settings/test", {}, 422)
    assert body["ok"] is False, body

    # ── the survey ────────────────────────────────────────────────────────────────────────────
    body = _same("/api/settings/sonar", {}, 400)
    assert "no capture interface is configured" in body["error"], body

    _patch(monkeypatch, "weirvern.admin.sonar.validate_survey_ifaces",
           lambda iface, mgmt: "that is not an interface name")
    _patch(monkeypatch, "weirvern.admin.sonar.iface_input_remedy", lambda: "Use eth0.")
    body = _same("/api/settings/sonar", {"interface": "--bad"}, 400)
    assert body["error"] == "cannot survey: that is not an interface name. Use eth0.", body

    _patch(monkeypatch, "weirvern.admin.sonar.validate_survey_ifaces", lambda iface, mgmt: "")

    def _job(client, iface, mgmt, progress=None):
        if progress:
            progress({"step": "dhcp"})
        return {"ok": True, "recommendations": [{"setting": "x"}], "interface": iface}

    _patch(monkeypatch, "weirvern.admin.sonar.run_survey_job", _job)
    body = _same("/api/settings/sonar", {"interface": "eth2"}, 200)
    assert body["interface"] == "eth2" and body["sensor"] == "", body

    # A job that RAN and refused is a 422 carrying its reason, not a 502.
    _patch(monkeypatch, "weirvern.admin.sonar.run_survey_job",
           lambda client, iface, mgmt, progress=None: {"ok": False,
                                                       "error": "no such interface"})
    body = _same("/api/settings/sonar", {"interface": "eth9"}, 422)
    assert body["error"] == "no such interface", body

    _patch(monkeypatch, "weirvern.admin.sonar.run_survey_job",
           lambda client, iface, mgmt, progress=None: (_ for _ in ()).throw(
               sonar_mod.SonarError("the job could not be created")))
    body = _same("/api/settings/sonar", {"interface": "eth2"}, 502)
    assert body["error"] == "the job could not be created", body

    # ── the NDJSON stream, on both surfaces ───────────────────────────────────────────────────
    _patch(monkeypatch, "weirvern.admin.sonar.run_survey_job", _job)
    raw = json.dumps({"interface": "eth2", "stream": True}).encode()

    import urllib.request as urlreq
    req = urlreq.Request(f"http://127.0.0.1:{legacy.port}/api/settings/sonar", data=raw,
                         method="POST", headers={"Content-Type": "application/json"})
    with urlreq.urlopen(req, timeout=10) as resp:
        assert resp.status == 200
        assert resp.headers.get("Content-Type", "").startswith("application/x-ndjson")
        console_lines = [json.loads(ln) for ln in resp.read().decode().splitlines() if ln.strip()]

    flask_resp = app.test_client().post(
        "/api/settings/sonar", data=raw, headers={"Content-Type": "application/json"})
    assert flask_resp.status_code == 200
    assert flask_resp.headers["Content-Type"].startswith("application/x-ndjson")
    flask_lines = [json.loads(ln) for ln in flask_resp.get_data(as_text=True).splitlines()
                   if ln.strip()]

    assert console_lines == flask_lines, (console_lines, flask_lines)
    assert console_lines[0] == {"progress": {"step": "dhcp"}}, console_lines
    assert console_lines[-1]["result"]["ok"] is True, console_lines
    assert cc, "the patches above must target the real module"


def test_the_retrain_family_answers_identically(surfaces, monkeypatch):
    """The LAST family: /api/models/retrain and its /<action> sibling.

    THREE THINGS THAT DECIDE WHAT WATCHES THE NETWORK. A retrain files a candidate and changes nothing
    live; a keep installs it; a trash discards it. The note is required for the last two and, exactly
    as the console has always done, NOT recorded on the request row. And a keep with no retrain to
    judge answers 400 rather than filing an action with an empty target, which the worker would then
    have to guess about.
    """
    import types

    from weirvern.models import actions

    legacy, app = surfaces()
    ident = types.SimpleNamespace(is_admin=True, must_change=False, username="sam", role="admin")
    _patch(monkeypatch, "weirvern.admin.requestauth.identity", lambda *a, **k: ident)

    def _same(path, payload, expected):
        raw = json.dumps(payload).encode()
        (ls, lb) = _post_legacy(legacy.port, path, raw)
        (fs, fb) = _post_flask(app, path, raw)
        assert ls == fs == expected, (
            f"{path} {payload}: console {ls}, flask {fs}: {lb[:220]!r} / {fb[:220]!r}")
        assert json.loads(fb) == json.loads(lb), (
            f"{path} {payload} drifted.\n  console: {lb[:260]!r}\n  flask:   {fb[:260]!r}")
        return json.loads(fb)

    filed: list = []
    latest: dict = {"action_id": ""}
    _patch(monkeypatch, "weirvern.models.actions.request",
           lambda client, **kw: (filed.append(kw) or "act-1"))
    _patch(monkeypatch, "weirvern.models.actions.latest",
           lambda client, action: {"action_id": latest["action_id"]})

    # 1. An unknown action is refused with the vocabulary.
    body = _same("/api/models/retrain", {"action": "delete"}, 400)
    assert body["error"] == "action must be retrain, keep or trash", body

    # 2. keep and trash need a note; retrain does not.
    body = _same("/api/models/retrain", {"action": "keep"}, 400)
    assert "a note is required for keep and trash" in body["error"], body
    assert filed == [], filed

    body = _same("/api/models/retrain", {"action": "retrain"}, 200)
    assert body == {"ok": True, "action": "retrain", "action_id": "act-1",
                    "note": "filed; the worker builds a candidate on its next cycle and NOTHING "
                            "live changes until you keep it"}, body

    # 3. A keep with nothing to judge is a 400, not a request with an empty target.
    body = _same("/api/models/retrain", {"action": "keep", "note": "it looks better"}, 400)
    assert body == {"error": "there is no retrain to judge yet", "code": 400}, body

    # 4. With a retrain to judge, the target is the LATEST one and the note is NOT recorded.
    latest["action_id"] = "act-0"
    del filed[:]
    body = _same("/api/models/retrain", {"action": "keep", "note": "it looks better"}, 200)
    assert body == {"ok": True, "action": "keep", "action_id": "act-1",
                    "note": "filed; the worker applies it on its next cycle"}, body
    assert filed[0]["target_id"] == "act-0" and filed[0]["note"] == "", filed
    assert filed[0]["action"] == actions.KEEP, filed

    # 5. THE ACTION MAY RIDE IN THE URL, and the body wins over it.
    del filed[:]
    body = _same("/api/models/retrain/trash", {"note": "stale candidate"}, 200)
    assert body["action"] == "trash", body
    assert filed[0]["action"] == actions.TRASH, filed

    del filed[:]
    body = _same("/api/models/retrain/trash", {"action": "retrain"}, 200)
    assert body["action"] == "retrain", body
    assert filed[0]["action"] == actions.RETRAIN, filed

    # 6. A named target wins over the latest.
    del filed[:]
    _same("/api/models/retrain", {"action": "trash", "note": "x", "target_id": "act-7"}, 200)
    assert filed[0]["target_id"] == "act-7", filed


def test_no_route_kwarg_collides_with_the_payload_route_helper():
    """A route's `settings=` must reach the FETCHER, never the helper's own parameter list.

    MEASURED DEFECT (live, after the switch): `_payload_route` had a parameter named `settings`, so
    `/api/anomalies` passing `settings=ctx.settings` set that FLAG instead of forwarding the value, and
    the fetcher was then called with settings POSITIONALLY. `payloads.anomalies` declares it keyword-
    only, so the route answered 503 "could not read the data: TypeError: anomalies() takes 1 positional
    argument but 2 positional arguments ... were given" on the Anomalies tab.

    THE EQUIVALENCE TESTS COULD NOT SEE IT because they replace the fetcher with `lambda *a, **k`, which
    accepts any call shape. This guard pins the helper's parameter names against the fetcher kwargs the
    routes pass, which is the trap itself rather than one instance of it.
    """
    src = (ROOT / "weirvern" / "admin" / "flask_app.py").read_text()
    head = src.split("def _payload_route(", 1)[1]
    params = head[:head.index("):")].replace("\n", " ")
    names = {p.split("=")[0].strip().lstrip("*") for p in params.split(",") if p.strip()}
    # Every fetcher kwarg a route may legitimately pass. `settings` is the one that bit us.
    for shadow in ("settings", "hours", "limit", "backend", "user_store"):
        assert shadow not in names, (
            f"_payload_route has a parameter named {shadow!r}, so a route passing {shadow}= as a fetcher "
            f"argument would set the helper's flag instead and the fetcher would never receive it"
        )


def test_the_anomalies_route_reaches_the_real_fetcher(surfaces, monkeypatch):
    """A SIGNATURE-FAITHFUL stub, unlike the permissive ones the equivalence matrix uses.

    The stub here declares `(client, **kwargs)` exactly as `payloads.anomalies` does, so a route that
    passes settings POSITIONALLY fails loudly instead of being absorbed.
    """
    legacy, app = surfaces()

    seen: dict = {}

    def faithful(client, **kwargs):
        seen.update(kwargs)
        return {"available": True, "rows": [], "hours": kwargs["hours"],
                "min_score": kwargs["min_score"], "unreviewed_only": kwargs["unreviewed_only"],
                "watched_only": kwargs["watched_only"], "tiles": {}}

    _patch(monkeypatch, "weirvern.admin.payloads.anomalies", faithful)

    path = "/api/anomalies?min_score=0&limit=50&hours=24"
    lstatus, lbody = _legacy_http(legacy.port, path)
    assert lstatus == 200, f"console {lstatus}: {lbody[:200]!r}"
    console_kwargs = dict(seen)
    seen.clear()

    fstatus, fbody = _flask_http(app, path)
    assert fstatus == 200, (
        f"flask {fstatus}: {fbody[:200]!r}. A 503 carrying TypeError is the arity defect this test "
        f"exists for: the route passed settings positionally to a keyword-only fetcher"
    )
    assert json.loads(fbody) == json.loads(lbody)
    # BOTH SURFACES PASS IT AS A KEYWORD. The stub declares (client, **kwargs), exactly as the real
    # fetcher does, so a positional pass would have raised rather than reached this assertion.
    assert "settings" in console_kwargs and "settings" in seen, (console_kwargs, seen)
    assert set(console_kwargs) == set(seen), (console_kwargs, seen)
