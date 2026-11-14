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

import json
import pathlib
import urllib.error
import urllib.request

import pytest

from weirvern.admin import flask_app, web
from weirvern.admin import status as status_mod

flask = pytest.importorskip("flask")

ROOT = pathlib.Path(__file__).resolve().parent.parent


# ── the work list: path -> (fetcher, status function to stub, canned return) ────────────────
#
# A canned value can be trivial: both surfaces run the SAME payload function, so equality proves the
# port regardless of what the stub returns. What it must NOT be is a shape only one side can handle.
PORTED: dict[str, tuple[str, str | None, object]] = {
    "/api/detectors": ("detectors", "detectors_overview", {"detectors": [], "catch_counts": {}}),
    "/api/models/shadow": ("models_shadow", "shadow_overview", {"available": True, "rows": [{"a": 1}]}),
    "/api/models/calibration": ("models_calibration", "calibration_overview", {"rows": []}),
    # File-backed reads: no client and no stub, because both surfaces read the same files.
    "/api/ml/ledger": ("ml_ledger", None, None),
    "/api/ml/eval-report": ("ml_eval_report", None, None),
    "/api/ml/review": ("ml_review", None, None),
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

@pytest.mark.parametrize("path", sorted(PORTED))
def test_each_ported_route_answers_identically(path, surfaces, monkeypatch):
    _fetcher, patch, canned = PORTED[path]
    if patch:
        monkeypatch.setattr(status_mod, patch, lambda *a, **k: canned, raising=True)

    legacy, app = surfaces()
    lstatus, lbody = _legacy_http(legacy.port, path)
    fstatus, fbody = _flask_http(app, path)

    assert fstatus == lstatus, f"{path}: console {lstatus}, flask {fstatus}"
    assert json.loads(fbody) == json.loads(lbody), (
        f"{path} drifted from the console. A panel reading one of these keys renders blank with no "
        f"error.\n  console: {lbody[:300]!r}\n  flask:   {fbody[:300]!r}"
    )


@pytest.mark.parametrize("path", sorted(p for p, (_f, patch, _c) in PORTED.items() if patch))
def test_each_ported_route_words_a_FAILURE_identically(path, surfaces, monkeypatch):
    """The failure wording is part of the payload contract: one vocabulary whichever surface answered.
    A missing binary must not be reported as a database fault on either."""
    def boom(*a, **k):
        raise FileNotFoundError(2, "No such file or directory", "kubectl")

    _fetcher, patch, _canned = PORTED[path]
    monkeypatch.setattr(status_mod, patch, boom, raising=True)

    legacy, app = surfaces()
    lstatus, lbody = _legacy_http(legacy.port, path)
    fstatus, fbody = _flask_http(app, path)

    assert fstatus == lstatus, f"{path}: console {lstatus}, flask {fstatus}"
    assert json.loads(fbody) == json.loads(lbody), (
        f"{path} words a failure differently.\n  console: {lbody[:250]!r}\n  flask: {fbody[:250]!r}"
    )
    blob = json.dumps(json.loads(fbody))
    assert "ClickHouse" not in blob, f"{path} blamed the database for a missing binary: {blob[:200]}"


# ── the guards that keep the port honest ───────────────────────────────────────────────────

def test_every_port_has_a_fetcher_that_exists():
    src = (ROOT / "weirvern" / "admin" / "payloads.py").read_text()
    for path, (fetcher, _patch, _canned) in PORTED.items():
        assert f"def {fetcher}(" in src, f"{path} names payloads.{fetcher}, which does not exist"


def test_every_port_is_routed_by_flask():
    src = (ROOT / "weirvern" / "admin" / "flask_app.py").read_text()
    for path in PORTED:
        assert f'@app.get("{path}")' in src, f"{path} is listed as ported but Flask does not route it"


def test_the_ported_count_only_grows():
    """A ratchet on progress, not a target: if a route moves BACK to the legacy handler, this notices."""
    assert len(PORTED) >= 6, f"{len(PORTED)} routes ported; the ratchet must not go backwards"
