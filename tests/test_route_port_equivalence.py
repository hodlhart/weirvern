"""Every ported route must answer EXACTLY as the console does.

WHY THIS FILE IS THE POINT OF THE PORT. The console has 52 GET reads and 31 POST writes, and its
JavaScript depends on the exact payload shape of most of them. Hand-rewriting a handler onto the
shared payload layer is therefore a change to a contract that nothing else checks: the console's own
tests exercise the legacy handler, and the DOM harness renders against fixtures rather than the
server. A ported route that drifts by one key returns a panel that renders blanks with no error,
which is this project's most-repeated defect.

So each ported route is driven on BOTH surfaces over the SAME stubbed data, and the two responses are
compared whole -- status and body. That is the only check that makes porting 83 routes safe, and it is
why it exists before the bulk of the porting rather than after.

THE REGISTRY BELOW IS THE WORK LIST. A route appears in `PORTED` only once it has moved, and the count
is asserted at the end so the number can only fall as routes cross.
"""

from __future__ import annotations

import importlib
import json
import pathlib
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
}

CONSOLE_GET_ROUTES = 52
CONSOLE_POST_ROUTES = 31


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
    assert len(PORTED) >= 13, f"{len(PORTED)} routes ported; the ratchet must not go backwards"


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

