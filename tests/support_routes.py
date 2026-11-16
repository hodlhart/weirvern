"""Ask the application what it routes, instead of grepping a dispatch that no longer exists.

THE MIGRATION THIS EXISTS FOR. Twenty-odd tests asserted that a route was wired by searching
`weirvern/admin/web.py` for its `if path == "/api/x":` line. That worked while the console owned its own
dispatch table. Flask owns routing now, so the same question has a direct answer: the URL map. A grep
can only prove a string is present somewhere in a file, and the whole reason to move these assertions
is that the string and the routing were only ever correlated, never the same fact.

Nothing here starts a server. `create_app` builds the URL map without binding a socket, so this is
cheap enough for the tests that call it repeatedly.

A NOTE ON WHAT THIS STILL DOES NOT PROVE. Being in the URL map means Flask would dispatch the request.
It does not prove the view answers correctly -- that is the goldens' job, and the DOM harness's after
that. Keep the distinction: this replaces "the route is registered", nothing more.
"""

from __future__ import annotations

from functools import lru_cache


class _CM:
    def __enter__(self):
        return None

    def __exit__(self, *_a):
        return False


class _Ctx:
    """The minimum a context has to be for `create_app` to build its routes."""

    settings = None
    backend = None
    config_client = None
    user_store = None
    sessions = None
    throttle = None
    accounts_note = ""
    connect_factory = staticmethod(lambda settings: _CM())

    class auth:
        enabled = False
        reason = ""

        @staticmethod
        def check(presented, client=""):
            return False


@lru_cache(maxsize=1)
def flask_api_paths() -> frozenset[str]:
    """Every /api/ path Flask routes."""
    from weirvern.admin import flask_app

    app = flask_app.create_app(_Ctx(), secret_key="route-surface")
    return frozenset(rule.rule for rule in app.url_map.iter_rules()
                     if rule.rule.startswith("/api/"))


@lru_cache(maxsize=1)
def flask_write_paths() -> frozenset[str]:
    """Every /api/ path Flask accepts a non-GET method on."""
    from weirvern.admin import flask_app

    app = flask_app.create_app(_Ctx(), secret_key="route-surface")
    out = set()
    for rule in app.url_map.iter_rules():
        if not rule.rule.startswith("/api/"):
            continue
        if set(rule.methods or ()) - {"GET", "HEAD", "OPTIONS"}:
            out.add(rule.rule)
    return frozenset(out)


def routed(path: str) -> bool:
    return path in flask_api_paths()


def route_map() -> dict[str, str]:
    """path -> the view function's name, for tests that check a route has a handler."""
    from weirvern.admin import flask_app

    app = flask_app.create_app(_Ctx(), secret_key="route-surface")
    return {rule.rule: rule.endpoint for rule in app.url_map.iter_rules()
            if rule.rule.startswith("/api/")}
