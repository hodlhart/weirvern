"""Rule management on the Sluice view (the operator, 2026-10-16): "rules needs a trashcan and a
disable icon next to each rule and a confirm if selected. it also needs a bulk select with check
boxes along the side. for mass delete or disable. and rules should be clickable to edit".

These pin the new state machine (disabled is neither live nor revoked), the bulk operations'
bounds, and the wiring the operator actually sees."""

from datetime import UTC
from pathlib import Path

import pytest

from tests.support_routes import routed

ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / "weirvern" / "admin" / "web"

# The FINAL-read row shape the store re-inserts from, in the SELECT's column order.
_ROW = ["r-1", "2026-10-16 10:00:00", "operator", "because", "198.51.100.7", "", "example.com",
        "alert", "", 0, "forward", None, "manual", "", "", None, None]


class _Result:
    def __init__(self, rows):
        self.result_rows = rows


class _Client:
    def __init__(self, rows):
        self._rows = list(rows)
        self.inserts = []

    def query(self, sql, parameters=None):
        assert "sluice_rules" in sql
        return _Result([self._rows.pop(0)] if self._rows else [])

    def insert(self, table, rows, column_names=None):
        self.inserts.append({"table": table, "row": list(rows[0]),
                             "cols": list(column_names or [])})


def test_disabled_is_a_third_state_next_to_live_and_revoked():
    from datetime import datetime

    from weirvern.sluice import Rule

    now = datetime.now(UTC)
    assert Rule(rule_id="x").is_live(now) is True
    assert Rule(rule_id="x", disabled_at=now).is_live(now) is False
    assert Rule(rule_id="x", revoked_at=now, disabled_at=now).is_live(now) is False


def test_set_rule_disabled_edits_in_place_and_records_the_flip():
    from weirvern import sluice_store

    client = _Client([_ROW])
    out = sluice_store.set_rule_disabled(client, "r-1", True, by="samuel")
    assert out.disabled_at is not None, "the returned rule carries the new state"
    ins = client.inserts[0]
    assert ins["table"] == "weirvern.sluice_rules"
    assert ins["row"][0] == "r-1", "the SAME rule id: an edit, not a delete-and-recreate"
    assert ins["row"][3] == "because", "the reason survives"
    assert ins["row"][-1] is not None, "disabled_at written last"
    note = ins["row"][ins["cols"].index("note")]
    assert "disabled" in note and "samuel" in note
    assert ins["cols"].index("disabled_at") == len(ins["cols"]) - 1


def test_reenabling_writes_null_and_refuses_a_no_op():
    from weirvern import sluice_store
    from weirvern.sluice import SluiceError

    client = _Client([_ROW[:16] + ["2026-10-16 11:00:00"]])
    out = sluice_store.set_rule_disabled(client, "r-1", False, by="samuel")
    assert out.disabled_at is None
    assert client.inserts[0]["row"][-1] is None

    with pytest.raises(SluiceError, match="already"):
        sluice_store.set_rule_disabled(_Client([_ROW]), "r-1", False)


def test_a_revoked_rule_cannot_be_disabled_or_reenabled():
    from weirvern import sluice_store
    from weirvern.sluice import SluiceError

    with pytest.raises(SluiceError, match="revoked"):
        sluice_store.set_rule_disabled(_Client([_ROW[:15] + ["2026-10-16 09:00:00", None]]),
                                       "r-1", True)


def test_revoke_rules_is_bulk_and_bounded(monkeypatch):
    from weirvern import sluice_store
    from weirvern.sluice import SluiceError

    seen = []

    def fake_revoke(client, rule_id, *, by="", now=None):
        seen.append(rule_id)
        return rule_id != "missing"

    monkeypatch.setattr(sluice_store, "revoke_rule", fake_revoke)
    out = sluice_store.revoke_rules(None, ["a", "b", "missing"], by="samuel")
    assert out == {"revoked": ["a", "b"], "missing": ["missing"]}
    assert seen == ["a", "b", "missing"]
    with pytest.raises(SluiceError, match="cap"):
        sluice_store.revoke_rules(None, [f"r{i}" for i in range(201)])


def test_the_enforcement_query_excludes_disabled_rules():
    body = (ROOT / "weirvern" / "sluice_store.py").read_text()
    live_sql = body[body.index("LIVE_RULE_SQL"):body.index("LIVE_RULE_SQL") + 900]
    assert "disabled_at IS NULL" in live_sql, (
        "the kernel compile and the alert pass both read live rules through this query; if a "
        "disabled rule leaks in, the operator's switch means nothing"
    )


def test_the_schema_file_adds_the_column_idempotently():
    sql = (ROOT / "weirvern" / "schema" / "017_sluice_rules_disabled.sql").read_text()
    assert "ADD COLUMN IF NOT EXISTS disabled_at" in sql


def test_the_routes_and_serializer_carry_the_new_state():
    body = (ROOT / "weirvern" / "admin" / "web.py").read_text()
    assert routed("/api/sluice/rule/disabled")
    # THE REVOKE MOVED into payloads.sluice_revoke with the port; the route must still go through it
    # and the shared fetcher must still accept a selection.
    assert "payloads.sluice_revoke(" in body, "the revoke route must use the shared fetcher"
    revoke = (ROOT / "weirvern" / "admin" / "payloads.py").read_text()
    revoke = revoke.split("def sluice_revoke(", 1)[1].split("\ndef ", 1)[0]
    assert "revoke_rules(" in revoke, "the revoke path must accept a selection"
    # THE SERIALISER MOVED into payloads.sluice with the port; the state it must carry did not.
    payloads = (ROOT / "weirvern" / "admin" / "payloads.py").read_text()
    assert '"disabled": r.disabled_at is not None' in payloads


def test_the_view_has_no_checkbox_furniture_and_one_rule_sheet():
    html = (WEB / "index.html").read_text()
    # The rebuild removed always-on selection furniture. A rule is opened from its sentence and
    # deleted in its own sheet, behind a required reason and a second click.
    assert 'id="sl-pick-all"' not in html
    assert 'id="sl-bulk"' not in html
    assert 'id="sl-rule-delete"' in html
    assert 'id="sl-rule-delete-reason"' in html
    js = (WEB / "sluice.js").read_text()
    assert "slRuleRevoke(" in js
    assert "openRuleSheet(" in js
    assert "A reason is required to delete a rule" in js
    assert 'slIcon("trash")' not in js



def test_opening_a_rule_does_not_depend_on_the_blocked_tab_having_loaded():
    """Issue #15: the card is fed from BLOCKED_STATE.data, so the click path must fetch the
    live sets on demand (once), never fabricate "expired or revoked" from a missing payload --
    and must not call an UNREADABLE set "not live" either."""
    blocked = (WEB / "blocked.js").read_text()
    assert "blEnsureLiveSets" in blocked, (
        "the on-demand fetch is gone; a fresh console would show live rules as expired again"
    )
    assert "async function blOpenRuleById" in blocked
    assert "lookup_failed" in blocked, (
        "a failed read has no distinct note -- a read we could not perform would render as a "
        "decision that ended"
    )
