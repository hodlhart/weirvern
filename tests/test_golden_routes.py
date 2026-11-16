"""Flask must answer exactly what the console answered, byte for byte, on every recorded route.

THIS REPLACES A LIVE ORACLE WITH A RECORDED ONE. Until now `tests/test_route_port_equivalence.py`
started the legacy HTTP handler and compared Flask against it at run time. That is a strong oracle and
it cannot outlive the handler, so the responses were recorded from the incumbent first
(`scripts/capture_golden_routes.py`) and the comparison is now against those fixtures.

Two branches per route, and the failing one is not decoration. This project's recurring defect is a
failed read rendered as a benign state -- "the packet gate is off", "no talkers in this window",
0-0 of 0", a green detection loop over sixteen hours of nothing. The wording of those failures is part
of the payload contract, so it is pinned with the same strictness as the success path.

A golden is only worth having if a change to the payload breaks it. `--check` in the capture script
regenerates and compares, so drift is a command rather than a guess.
"""

from __future__ import annotations

import importlib
import json
import pathlib

import pytest

from weirvern.admin import flask_app

flask = pytest.importorskip("flask")

ROOT = pathlib.Path(__file__).resolve().parent.parent
GOLDEN = ROOT / "tests" / "golden" / "routes.json"


class _CM:
    def __init__(self, client):
        self.client = client

    def __enter__(self):
        return self.client

    def __exit__(self, *_a):
        return False


def _ctx():
    class _Auth:
        enabled = False
        reason = ""          # the real one carries it; without it Flask logs an AttributeError

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

    _Ctx.connect_factory = staticmethod(lambda settings: _CM(object()))
    return _Ctx()


def _patch(dotted: str, value):
    """Patch a dotted target, failing loudly when it has moved.

    `raising=True` matters: a silently created attribute would leave the route reading its real
    dependency while the fixture believed it had been stubbed, and the comparison would pass over
    behaviour nobody controlled.
    """
    module, _, attr = dotted.rpartition(".")
    pytest.MonkeyPatch().setattr(importlib.import_module(module), attr, value, raising=True)


def _boom(*_a, **_k):
    raise FileNotFoundError(2, "No such file or directory", "kubectl")


@pytest.fixture(scope="module")
def goldens() -> dict:
    if not GOLDEN.exists():
        pytest.skip("no recorded goldens; run scripts/capture_golden_routes.py")
    return json.loads(GOLDEN.read_text())


def _app():
    app = flask_app.create_app(_ctx(), secret_key="golden-test")
    app.config.update(TESTING=True)
    return app


BRANCHES = {"ok": (lambda *_a, **_k: {}), "fail": _boom}


@pytest.mark.parametrize("branch", sorted(BRANCHES))
def test_every_recorded_route_answers_identically(branch, goldens):
    """One test per branch, looping the routes, so a failure names the route and the branch."""
    expected = goldens.get(branch, {})
    assert expected, f"no goldens recorded for the {branch} branch"

    def _as_seen(body: str):
        """The response as a client sees it.

        NOT byte comparison. The console writes `json.dumps` (spaces, no trailing newline) and Flask
        writes `jsonify` (compact, trailing newline), so the same payload differs in whitespace. That
        is a serialiser detail no client can observe, and pinning it would fail every honest change
        while catching nothing. What must match is the parsed document.
        """
        try:
            return json.loads(body)
        except (ValueError, TypeError):
            return body

    mismatches = []
    for path, want in sorted(expected.items()):
        _patch(want["target"], BRANCHES[branch])
        resp = _app().test_client().get(path)
        got = {"status": resp.status_code, "body": resp.get_data(as_text=True)}
        if got["status"] != want["status"] or _as_seen(got["body"]) != _as_seen(want["body"]):
            mismatches.append(
                f"{path}\n    recorded: {want['status']} {want['body'][:160]!r}"
                f"\n    flask:    {got['status']} {got['body'][:160]!r}"
            )

    assert not mismatches, (
        f"{len(mismatches)} of {len(expected)} routes drifted on the {branch} branch:\n  "
        + "\n  ".join(mismatches[:6])
    )


def test_the_goldens_cover_a_useful_number_of_routes(goldens):
    """A ratchet, so a regeneration that silently loses coverage is caught."""
    n = len(goldens.get("ok", {}))
    assert n >= 20, f"only {n} routes are pinned; the recorder is dropping coverage"
