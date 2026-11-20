"""US-9 pins: every alert carries a stable reason code; every rule surface states its reach.

The code is DERIVED (detector initials + the measurement that moved), so identical verdicts
always read identically and a ticket can quote it. The reach is the same 'would this act?'
test the gate form uses, stated on the rule surface with each sensor a door to its sheet.
"""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from weirvern.admin import status

WEB = Path(__file__).resolve().parents[1] / "weirvern" / "admin" / "web"


def test_the_code_is_detector_initials_plus_the_measurement():
    assert status.reason_code("Isolation Forest", "bytes_z") == "IF:bytes_z"
    assert status.reason_code("DBSCAN", "flows") == "DBSCAN:flows"
    assert status.reason_code("Gradient Boosting", "unique_dsts") == "GB:unique_dsts"
    assert status.reason_code("Adaptive Baseline", "") == "AB:score"


def test_the_code_is_stable_and_deduped():
    a = status.reason_code("Isolation Forest, DBSCAN", "bytes_z")
    assert a == status.reason_code("Isolation Forest, DBSCAN", "bytes_z"), "not stable"
    assert status.reason_code("DBSCAN, DBSCAN", "x") == "DBSCAN:x", "duplicates must fold"
    assert status.reason_code("", "") == "?:score", "an unnamed verdict still carries a code"


def test_the_grouped_rows_carry_it():
    class C:
        def query(self, sql, parameters=None):
            return SimpleNamespace(
                column_names=["detected_by_models", "primary_deviation_feature", "n", "windows"],
                result_rows=[("Isolation Forest, DBSCAN", "bytes_z", 3, [])])

    rows = status.anomalies_grouped(C())
    assert rows[0]["reason_code"] == "IF+DBSCAN:bytes_z"


def test_the_row_renders_it_and_offers_the_tune_verb():
    src = (WEB / "app.js").read_text()
    seg = src.split("a.reason_code ? el(", 1)[1].split("null,", 1)[0]
    assert "reason-code" in seg and "a.reason_code" in seg
    act = src.split("function anActions(a) {", 1)[1].split("\n}", 1)[0]
    assert '"Tune"' in act, "the per-row Tune detection verb vanished"
    assert 'openSettingKey("base_threshold")' in act, \
        "Tune must land on the detection threshold, not the top of Settings"


def test_one_settings_landing_implementation():
    app = (WEB / "app.js").read_text()
    seg = app.split("function openSettingKey(key) {", 1)[1].split("\n}", 1)[0]
    assert seg.index("collapsed") < seg.index("scrollIntoView"), \
        "the card must expand BEFORE the scroll"
    pal = (WEB / "palette.js").read_text()
    assert "openSettingKey(r.key)" in pal, \
        "the palette grew a second copy of the landing logic"
    assert 'data-key="' not in pal.split("function paletteCommands(")[1].split("function paletteMatch(")[0], \
        "the palette still queries settings rows itself (two implementations again)"


def test_the_rule_surface_states_its_reach():
    src = (WEB / "sluice.js").read_text()
    # Re-authored with the 2026-11-20 rebuild: reach is its own renderer now, so the contract is
    # read from that function rather than from a block inside the rules renderer.
    seg = src.split("function renderSluiceReach(", 1)[1].split("\n}\n", 1)[0]
    assert "can act on" in seg
    assert "g.enforcement && !g.stale" in seg, \
        "reach must be the verified in-path sensors, not every sensor in the fleet"
    assert "openWeirling(sen)" in seg, "each sensor chip must open its fleet sheet"
    assert "gates_available" in seg, "an unreadable fleet must be said, not shown as zero"
    html = (WEB / "index.html").read_text()
    assert 'id="sl-reach"' in html
