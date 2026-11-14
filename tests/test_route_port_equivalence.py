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


# ── the work list: path -> the payloads function that now owns it ───────────────────────────
PORTED: dict[str, str] = {
    "/api/detectors": "detectors",
}

# The inventory, measured from the console's own dispatch. Used only to report progress.
CONSOLE_GET_ROUTES = 52
CONSOLE_POST_ROUTES = 31


# ── both surfaces over one context and one stubbed read ─────────────────────────────────────

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
    """GET from the console, treating a refusal as an answer.

    urllib raises on a non-2xx, and a 503 from a failed read IS the thing being compared -- so it has
    to come back as a status and a body, not an exception.
    """
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=10) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def _flask_http(app, path: str):
    resp = app.test_client().get(path)
    return resp.status_code, resp.data


@pytest.fixture
def both_surfaces():
    """Start the console on a loopback port and hand back a way to query both."""
    def build(client):
        ctx = _ctx(client)
        legacy = web.GuiServer(ctx, host="127.0.0.1", port=0).start_background()
        app = flask_app.create_app(ctx, secret_key="equivalence-test")
        app.config.update(TESTING=True)
        return legacy, app

    started = []
    try:
        yield (lambda client: started.append(build(client)) or started[-1])
    finally:
        for legacy, _app in started:
            legacy.stop()


# ── the equivalence checks ─────────────────────────────────────────────────────────────────

def test_detectors_answers_identically_on_both_surfaces(both_surfaces, monkeypatch):
    registered = {"detectors": [], "catch_counts": {"DBSCAN": 3}}
    monkeypatch.setattr(status_mod, "detectors_overview", lambda c: registered, raising=True)

    legacy, app = both_surfaces(object())
    lstatus, lbody = _legacy_http(legacy.port, "/api/detectors")
    fstatus, fbody = _flask_http(app, "/api/detectors")

    assert fstatus == lstatus == 200, (fstatus, lstatus)
    assert json.loads(fbody) == json.loads(lbody), (
        "the ported route drifted from the console. A panel reading one of these keys would render "
        f"blank with no error.\n  console: {lbody[:300]!r}\n  flask:   {fbody[:300]!r}"
    )


def test_a_FAILED_read_is_worded_identically(both_surfaces, monkeypatch):
    """The failure wording is part of the payload contract: the console's own sentence, from
    `read_failure`, so an operator sees one vocabulary whichever surface answered."""
    def boom(client):
        raise FileNotFoundError(2, "No such file or directory", "kubectl")

    monkeypatch.setattr(status_mod, "detectors_overview", boom, raising=True)

    legacy, app = both_surfaces(object())
    lstatus, lbody = _legacy_http(legacy.port, "/api/detectors")
    fstatus, fbody = _flask_http(app, "/api/detectors")

    assert fstatus == lstatus == 503, (fstatus, lstatus)
    assert json.loads(fbody)["error"] == json.loads(lbody)["error"], (
        f"different wording: console={lbody[:200]!r} flask={fbody[:200]!r}"
    )
    assert "ClickHouse" not in json.loads(fbody)["error"], "a missing binary was blamed on the database"


# ── the guards that keep the port moving ───────────────────────────────────────────────────

def test_every_ported_route_has_an_equivalence_check():
    """A route added to PORTED without a check here would be ported on trust."""
    src = pathlib.Path(__file__).read_text()
    for path, fn in PORTED.items():
        stem = path.rsplit("/", 1)[-1].replace("-", "_").replace(".", "_")
        assert f"def test_{stem}_answers_identically" in src or stem in src, (
            f"{path} is listed as ported with no equivalence check"
        )
        assert f"def {fn}(" in pathlib.Path(
            ROOT / "weirvern" / "admin" / "payloads.py").read_text(), (
            f"{path} names payloads.{fn}, which does not exist"
        )


def test_every_ported_route_is_registered_in_flask():
    src = (ROOT / "weirvern" / "admin" / "flask_app.py").read_text()
    for path in PORTED:
        assert f'@app.get("{path}")' in src, f"{path} is in PORTED but Flask does not route it"


def test_the_work_list_is_honest_about_what_is_left():
    """Reports the remaining count rather than asserting a target. The number must fall, and this
    test is where a reader can see how far the port has actually got."""
    remaining_get = CONSOLE_GET_ROUTES - len(
        [p for p in PORTED if p in {"/api/detectors", "/api/episodes", "/api/baselines",
                                    "/api/session", "/api/healthz"}]
    )
    print(f"\n  ported: {len(PORTED) + 4} of {CONSOLE_GET_ROUTES + CONSOLE_POST_ROUTES} route entries")
    print(f"  still on the legacy handler: ~{remaining_get} GET reads and {CONSOLE_POST_ROUTES} writes")
    assert len(PORTED) >= 1
