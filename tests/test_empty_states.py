"""The empty-state audit checklist (BF-8) -- one row per tab, pinned in code.

WHY THIS FILE EXISTS. The console research (soc-tools' fleet CTA, pfSense's batched wizard)
and this operator's own rule -- "no lying states" -- found that an empty table which says
nothing makes the reader hunt for the fix, and an empty chart that reads as zero traffic
lies about the network. The checklist below is deliberately per-tab and mechanical: for every
main surface, the empty state must name the CAUSE, point at the NEXT ACTION, and -- where a
control exists that genuinely fixes it -- offer that control as a button. Drill-downs must say
"an empty window is not zero traffic". And the first run must be skippable and end in the
ordinary staged plan, never a parallel one.

WHAT THESE TESTS PIN:
  * the empty-state machinery (emptyRow/blEmptyRow grow an action; .empty-act exists)
  * the queue: cause + Clear filters + the reset itself
  * the fleet: cause + How adding works -> the wl-info explainer
  * DNS / Blocked / Discover: cause + next action (button where the renderer builds cells)
  * drill-down honesty: the not-zero line, in every drill-down that can be empty
  * the first run: card, skip, staging through the REAL path, landing on the real review
"""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / "weirvern" / "admin" / "web"
S = {name: (WEB / name).read_text() for name in
     ("app.js", "weirlings.js", "dnsview.js", "blocked.js", "discover.js",
      "index.html", "style.css")}


def test_the_empty_state_row_can_offer_a_button():
    assert "function emptyRow(tbody, cols, message, action)" in S["app.js"], (
        "emptyRow lost its action parameter -- an empty state that cannot offer the button "
        "makes the reader go find the fix"
    )
    assert ".empty-act" in S["style.css"], "the empty-state button has no style"
    assert "function blEmptyRow(body, span, text, action)" in S["blocked.js"], (
        "the Blocked tab's own empty helper does not accept an action"
    )


def test_the_queue_names_its_cause_and_offers_the_way_back():
    js = S["app.js"]
    assert "No anomalies recorded yet — rows land as scan windows complete." in js, (
        "the never-anything queue empty no longer says why rows are not there yet"
    )
    assert "Clear filters" in js and "function anClearAllFilters" in js, (
        "the filtered-empty queue must offer Clear filters as a working button"
    )


def test_the_fleet_teaches_and_opens_its_explainer():
    js = S["weirlings.js"]
    assert "Point a sensor's exporter at this hub — it appears here to adopt." in js
    assert "How adding works" in js and 'openHelpPanel("wl-info")' in js, (
        "the empty fleet's button must open the wl-info explainer"
    )
    assert "No weirling has a problem right now." in js and "Show all" in js


def test_dns_offers_a_working_reset_from_its_filtered_empty():
    js = S["dnsview.js"]
    assert "No DNS records matched. Widen the window or clear a filter." in js
    assert 'openHelpPanel' not in js  # nothing to open here -- the fix is a control, not prose
    assert "Clear filters" in js and "dn-qtype" in js, (
        "the dns empty state's button must clear the real filter inputs and reload"
    )


def test_blocked_and_discover_name_the_cause_and_next_action():
    assert "How hits work" in S["blocked.js"] and 'openHelpPanel("bl-info")' in S["blocked.js"]
    assert "widen the range or clear a filter" in S["discover.js"], (
        "the discover tables' empty copy must carry a cause and a next action"
    )


def test_drill_downs_never_imply_zero_traffic():
    app_js = S["app.js"]
    assert app_js.count("an empty window is not zero traffic") >= 4, (
        "the four evidence drill-downs must each say an empty window is not zero traffic"
    )
    assert "an empty window is not zero traffic" in S["dnsview.js"], (
        "the DNS host drill-down must say it too"
    )


def test_the_first_run_is_skippable_and_ends_in_the_ordinary_plan():
    assert 'id="firstrun-card"' in S["index.html"] and "Skip for now" in S["app.js"]
    assert "wv-firstrun" in S["app.js"] and "function firstrunDismissed" in S["app.js"], (
        "the skip must persist for the tab (sessionStorage, like the stage it protects)"
    )
    assert "function firstrunShow" in S["app.js"] and "FIRSTRUN_KEYS" in S["app.js"]
    # the wizard edits REAL settings through the REAL staging path and lands on the REAL review
    assert "stageChange(spec.key, input.value, row.value)" in S["app.js"], (
        "the first run must stage through the same stageChange every other edit uses"
    )
    assert 'showView("settings")' in S["app.js"], (
        "the last step must land on the ordinary settings review"
    )
