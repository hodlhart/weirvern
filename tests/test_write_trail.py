"""US-10 pins: the write trail gets a face, and plan changes get a revert that is itself a write.

The trail was append-only and invisible; the read side is filterable (scope/action/target),
the settings applies write their OWN rows (one per key, so a provenance link matches exactly),
and a revert goes through the BF-9 echo and is audited as action=revert.
"""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from weirvern import fleet_store

WEB = Path(__file__).resolve().parents[1] / "weirvern" / "admin" / "web"
PY = Path(__file__).resolve().parents[1] / "weirvern"


def test_read_audit_filters_by_action_too():
    captured = {}

    class C:
        def query(self, sql, parameters=None):
            captured["sql"] = sql
            captured["params"] = parameters
            return SimpleNamespace(result_rows=[])

    fleet_store.read_audit(C(), action="revert")
    assert "action = %(act)s" in captured["sql"]
    assert captured["params"]["act"] == "revert"
    fleet_store.read_audit(C())
    assert "action = " not in captured["sql"], "an absent filter must not touch the query"


def test_the_trail_route_is_filterable_and_self_guarding():
    src = (PY / "admin" / "web.py").read_text()
    seg = src.split("def _write_trail(self, query: dict) -> None:", 1)[1].split("def _audit(", 1)[0]
    for key in ('query.get("scope")', 'query.get("action")', 'query.get("target")'):
        assert key in seg
    assert "read_audit(" in seg and "action=action_f" in seg
    assert "available" in seg and "reason" in seg, \
        "an unreadable trail must say so, never read as a quiet history"
    assert "DISTINCT scope" in seg and "DISTINCT action" in seg, \
        "the filter menus must come from the table itself"


def test_a_settings_apply_writes_one_audit_row_PER_KEY():
    src = (PY / "admin" / "web.py").read_text()
    seg = src.split('# US-10: THE TRAIL GETS THE SETTINGS WRITE TOO.', 1)[1].split("self._json({", 1)[0]
    assert 'action = "revert" if body.get("revert") else "apply"' in seg
    assert "for key in raw_changes:" in seg, (
        "one row per key keeps a single-key provenance link an EXACT match; derived keys "
        "such as the reconciled ZEEK_IFACES are real writes and must be audited too")
    assert 'scope="settings"' in seg and "write_audit(" in seg
    assert "except Exception" in seg, "an audit failure must not fail a write that landed"


def test_the_settings_payload_carries_provenance():
    src = (PY / "admin" / "web.py").read_text()
    seg = src.split("def _settings(self, query: dict) -> None:", 1)[1].split("def _settings_plan", 1)[0]
    assert "GUI_WRITE_ANNOTATION" in seg
    assert 'payload["provenance"] = provenance' in seg


def test_apply_records_the_previous_landed_value():
    src = (PY / "admin" / "cluster_config.py").read_text()
    seg = src.split("before: dict = {}", 1)[1].split("prior =", 1)[0]
    assert "self.read()" in seg, "the previous value must come from the configmap itself"
    rec = src.split("record = {", 1)[1].split("records[key] = record", 1)[0]
    assert 'record["prev_value"] = before.get(key, "")' in rec
    assert "if before:" in rec, "an unreadable configmap degrades to NO previous, not a guess"


def test_the_row_says_where_the_value_came_from():
    src = (WEB / "app.js").read_text()
    seg = src.split("(data.provenance || {})[r.key]", 1)[1].split("})() : null", 1)[0]
    assert "set via GUI" in seg
    assert "openSettingTrail(r.key)" in seg and "revertSetting(r.key, prov)" in seg


def test_a_revert_is_a_write_of_its_own():
    src = (WEB / "app.js").read_text()
    seg = src.split("async function revertSetting(", 1)[1].split("\n}", 1)[0]
    assert "confirmDestructive(" in seg, "the echo is the gate"
    assert "revert: true" in seg, "the server needs the flag to audit it as a revert"
    assert "reason: res.reason" in seg
