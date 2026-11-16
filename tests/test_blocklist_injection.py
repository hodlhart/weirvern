"""Issue #11, pinned: the remove path took the operator's word for it.

`remove_custom_domain` lowercased the input and CONCATENATED it into an
`ALTER TABLE ... DELETE WHERE domain = '<name>'`; `add_custom_domain` validated its input and the
remove path did not. Only one of two paths checking means neither is checked: a value that could
not be ADDED could still be REMOVED with, and a name carrying a quote widened the predicate.

The fix has two halves and each is tested where it can fail:
  * the STORE validates through the same `validate_domain` as `add`, and binds the name as a
    parameter, so a widened statement is not expressible -- tested against a recording client;
  * the ROUTE refuses with a 400 that says why, and NOTHING reaches the database -- tested by
    driving the real route method of the real handler.
"""

import contextlib
from types import SimpleNamespace

import pytest

from weirvern import blocklists
from weirvern.sluice import SluiceError

INJECTED = "x' OR 1 --"


class _Rec:
    """Records what the store asked ClickHouse to run -- statement AND parameters both,
    because part of the fix is that the name no longer lives inside the statement."""

    def __init__(self):
        self.commands: list[tuple[str, dict | None]] = []

    def command(self, sql, parameters=None, **_kw):
        self.commands.append((sql, parameters))

    def query(self, sql, parameters=None, **_kw):
        return SimpleNamespace(result_rows=[])

    def insert(self, *a, **k):
        pass


def test_a_name_with_a_quote_is_refused_and_nothing_runs():
    """The reproduction: `x' OR 1 --` completes the literal and widens the DELETE. It cannot be
    a name, and a refused name must not reach the database at all."""
    rec = _Rec()
    with pytest.raises(SluiceError):
        blocklists.remove_custom_domain(rec, INJECTED)
    assert rec.commands == [], "a refused name still reached ClickHouse"


def test_a_dotted_name_with_a_quote_still_cannot_be_a_name():
    """The other half of the reproduction class: a name WITH a dot so the no-dot check cannot
    be what saves us -- the quote itself must be refused."""
    rec = _Rec()
    with pytest.raises(SluiceError):
        blocklists.remove_custom_domain(rec, "evil' OR 1 --.example.com")
    assert rec.commands == []


def test_a_legitimate_name_round_trips_and_the_delete_is_bound_not_concatenated():
    rec = _Rec()
    added = blocklists.add_custom_domain(rec, "Ads.Example.COM.")
    assert added == "ads.example.com"
    removed = blocklists.remove_custom_domain(rec, "Ads.Example.COM.")
    assert removed == added, "remove normalizes differently from add -- the two paths drifted"
    sql, params = rec.commands[-1]
    assert "%(name)s" in sql, "the DELETE must bind the name, not embed it"
    assert "ads.example.com" not in sql, "the name still travels inside the statement"
    assert params == {"name": "ads.example.com"}


def test_a_wildcard_name_removes_exactly_as_it_was_stored():
    """`*.example.com` is stored as typed; remove must target that stored name, not a stripped
    variant that matches nothing."""
    rec = _Rec()
    assert blocklists.remove_custom_domain(rec, "*.Example.com") == "*.example.com"
    assert rec.commands[-1][1] == {"name": "*.example.com"}


def test_the_route_refuses_an_injected_name_with_a_400_and_runs_no_sql():
    """The real route, the real validator, a recording client: a 400 whose body says why, and ZERO
    statements -- not a sanitized statement, none at all.

    THE ROUTE IS DRIVEN OVER HTTP, NOT THROUGH THE RETIRED HANDLER. `_build_handler` went with the
    console's server; `/api/blocklists/custom` is a Flask route now, and a test that called
    `blocklist_custom` directly would skip the gate, the body parse and the field parsing that sit
    between a request and the store. The recording client is injected through `ctx.connect_factory`,
    which is what the route actually uses.
    """
    from weirvern.admin import flask_app

    rec = _Rec()

    class _Auth:
        enabled = True
        reason = ""

        @staticmethod
        def check(presented, client=""):
            return presented == "test-token"

    class _Ctx:
        settings = None
        backend = None
        config_client = None
        user_store = None
        sessions = None
        throttle = None
        accounts_note = ""
        capabilities = None
        auth = _Auth()
        connect_factory = staticmethod(lambda settings: contextlib.nullcontext(rec))

    client = flask_app.create_app(_Ctx(), secret_key="blocklist-injection").test_client()

    got = client.post("/api/blocklists/custom",
                      json={"action": "remove", "domain": INJECTED},
                      headers={"X-Weirvern-Token": "test-token"})

    assert got.status_code == 400, f"expected a 400 refusal, got {got.status_code}: {got.data!r}"
    err = (got.get_json() or {}).get("error") or ""
    assert "has no dot" in err, f"the 400 must say what was wrong with the name: {err!r}"
    assert rec.commands == [], "the rejected name still reached ClickHouse"
