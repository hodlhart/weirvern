"""BF-9: destructive actions -- reasons are required where they are destructive and recorded
where they are not. The write trail is the difference between an incident review and a guess."""
from pathlib import Path

from weirvern import fleet_store

ROOT = Path(__file__).resolve().parents[1]


class _CH:
    """Captures inserts; answers reads from what it captured. The write inserts
    (scope, action, target, reason, actor); the read selects
    (at, scope, action, target, reason, actor) -- the stub mirrors both shapes."""

    def __init__(self):
        self.rows = []

    def insert(self, table, data, column_names=None):
        assert table == "weirvern.fleet_audit"
        assert column_names == ["scope", "action", "target", "reason", "actor"]
        self.rows.extend(data)

    def query(self, sql, parameters=None):
        class R:
            def __init__(self, rows):
                self.result_rows = rows
        out = [(f"2026-10-17T12:00:{i:02d}", r[0], r[1], r[2], r[3], r[4])
               for i, r in enumerate(self.rows)]
        if parameters and parameters.get("target"):
            out = [r for r in out if r[3] == parameters["target"]]
        if parameters and parameters.get("scope"):
            out = [r for r in out if r[1] == parameters["scope"]]
        return R(out)


def test_the_audit_roundtrips_through_the_store():
    ch = _CH()
    fleet_store.write_audit(ch, scope="fleet", action="revoke", target="edge-1",
                            reason="decommissioned", actor="sam")
    rows, err = fleet_store.read_audit(ch, scope="fleet", target="edge-1")
    assert err == ""
    assert rows and rows[0]["target"] == "edge-1" and rows[0]["reason"] == "decommissioned"
    assert rows[0]["actor"] == "sam"


def test_the_audit_read_degrades_instead_of_raising():
    class Boom:
        def query(self, *a, **k):
            raise RuntimeError("clickhouse down")

    rows, err = fleet_store.read_audit(Boom())
    assert rows == [] and "clickhouse down" in err


def test_the_write_trail_table_is_a_shipped_schema():
    ddl = (ROOT / "weirvern" / "schema" / "022_fleet_audit.sql").read_text()
    assert "CREATE TABLE IF NOT EXISTS weirvern.fleet_audit" in ddl
    for col in ("scope", "action", "target", "reason", "actor"):
        assert col in ddl


def test_enabling_siphon_in_settings_demands_a_reason():
    """THE GUARD MOVED into payloads.settings_apply with the port; the route must still ask it."""
    src = (ROOT / "weirvern" / "admin" / "flask_app.py").read_text()
    assert "payloads.settings_apply(" in src, "the apply route no longer uses the shared fetcher"
    payloads = (ROOT / "weirvern" / "admin" / "payloads.py").read_text()
    guard = payloads.split("def settings_apply(", 1)[1].split("\ndef ", 1)[0]
    assert 'enabling siphon puts this deployment in the traffic path' in guard
    assert 'siphon_now and not reason' in guard


def test_a_siphon_plan_write_demands_a_reason():
    """The guard MOVED into payloads.weirling_apply with the port; the handler must still ask it.

    Asserting the console handler's text would demand the check be duplicated on the second surface,
    which is the defect this port keeps removing.
    """
    src = (ROOT / "weirvern" / "admin" / "flask_app.py").read_text()
    assert "payloads.weirling_apply(" in src, "the apply route no longer uses the shared fetcher"
    payloads = (ROOT / "weirvern" / "admin" / "payloads.py").read_text()
    guard = payloads.split("def weirling_apply(", 1)[1].split("\ndef ", 1)[0]
    assert 'merged.mode == "siphon" and not reason' in guard, (
        "the in-path reason guard vanished from the write path, so a plan that puts the sensor in "
        "the traffic path can be applied without recording why"
    )


def test_revoke_demands_a_reason_on_both_surfaces():
    """The GUARD is what is pinned, not just the message: a flipped condition would leave the
    message in place while the write sails through (learned by mutating exactly that)."""
    src = (ROOT / "weirvern" / "admin" / "web.py").read_text()
    flask_src = (ROOT / "weirvern" / "admin" / "flask_app.py").read_text()
    # THE WEIRLING-REVOKE GUARD LIVES in web.weirling_revoke_args; the ROUTE that must ask it is the
    # Flask view (the console's handler went with its dispatch table).
    rev = flask_src.split("def weirlings_revoke(", 1)[1].split("    @app.", 1)[0]
    assert "web.weirling_revoke_args(" in rev, "the weirling-revoke route no longer asks the guard"
    guard = src.split("def weirling_revoke_args(", 1)[1].split("\ndef ", 1)[0]
    assert 'if not reason:' in guard, "the weirling-revoke reason guard vanished"
    assert 'revoking a registration is a decision' in guard, "the refusal stopped naming why"
    # the sluice-revoke guard, on its own route
    sl = flask_src.split("def sluice_revoke(", 1)[1].split("    @app.", 1)[0]
    # THE GUARD MOVED into web.sluice_revoke_args when the Flask surface began serving the route;
    # asserting the handler's text would demand the logic be duplicated again. The handler must still
    # ASK the shared guard, and the condition and sentence are pinned where they now live.
    assert "web.sluice_revoke_args(" in sl, "the sluice-revoke route no longer asks the shared guard"
    guard = src.split("def sluice_revoke_args(", 1)[1].split("\ndef ", 1)[0]
    assert 'if not reason:' in guard, "the sluice-revoke reason guard vanished"
    assert 'a reason is required to revoke a rule' in guard, "the refusal stopped naming why"


def test_keep_and_trash_demand_a_note():
    import weirvern.models.actions as actions
    # the retrain write path requires it; the retrain itself (a candidate producer) does not
    src = (ROOT / "weirvern" / "admin" / "web.py").read_text()
    assert "choosing the model to serve" in src or "keep_note_required" in src \
        or "a note is required" in src
    assert actions.TRASH in src and actions.KEEP in src


def test_the_settings_provenance_records_who_and_why():
    src = (ROOT / "weirvern" / "admin" / "cluster_config.py").read_text()
    assert 'record["by"] = by' in src and 'record["reason"] = reason' in src
    assert "def apply(self, changes: dict[str, str], *, reason: str =" in src
