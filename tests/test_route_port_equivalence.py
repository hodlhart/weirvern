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
    assert len(PORTED_WRITES) >= 12, (
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
