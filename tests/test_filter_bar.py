"""THE FILTER-BAR CONTRACT: one surface, two verbs, never both.

Operator (2026-11-20): "clicking a value should filter by adding a removable pill at the top;
clicking a row opens the right-side sheet; never both." Before this, every view grew its own chip
row, so where a filter lived depended on the tab and removing one was a different gesture each
time.

This file pins the parts a source review can hold: the bar is ONE element in the shell, every tab
has an adapter, the pill and Clear all are the house bubble, and the value-click handler is a
CAPTURE-phase listener that swallows the event before a row can also act. The rendered behaviour
(adds a pill and narrows, row opens the sheet and adds nothing, remove restores, Clear all
empties, URL round trip) is executed in `scripts/jsdom_render.js`; its five checks are pinned
here so they cannot be deleted from CI.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / "weirvern" / "admin" / "web"
INDEX = (WEB / "index.html").read_text(encoding="utf-8")
FILTERS = (WEB / "filters.js").read_text(encoding="utf-8")
APP = (WEB / "app.js").read_text(encoding="utf-8")


def test_the_bar_is_one_element_in_the_shell_not_a_per_view_row():
    assert INDEX.count('id="filter-bar"') == 1, "the console declares more than one filter bar"
    assert 'role="region" aria-label="active filters"' in INDEX
    # It sits between the header and <main>: one location, every view.
    assert INDEX.index('id="filter-bar"') < INDEX.index("<main")


def test_every_tab_has_an_adapter_so_no_view_falls_off_the_surface():
    tabs = set(re.findall(r'data-view="([a-z0-9-]+)"', INDEX))
    assert len(tabs) == 14, sorted(tabs)
    views = set(re.findall(r"^    ([a-z]+): \{", FILTERS, flags=re.M))
    missing = sorted(tabs - views)
    assert not missing, f"a tab has no filter-bar adapter, so its filters are invisible: {missing}"


def test_a_value_click_is_captured_before_the_row_and_never_does_both():
    # The capture listener is the mechanism that separates the two verbs. Without `true` the
    # row's bubble handler runs first and the operator gets a sheet AND a filter.
    click = FILTERS.split('document.addEventListener("click"', 1)[1].split("}, false)", 1)[0]
    assert 'closest("[data-filter-field]")' in click
    assert "ev.stopPropagation()" in click and "ev.preventDefault()" in click
    assert "add(cell.dataset.filterField, cell.dataset.filterValue)" in click
    assert click.rstrip().endswith("true") or ", true);" in FILTERS.split(
        'document.addEventListener("click"', 1)[1][:1200], (
        "the value-click listener must run in the CAPTURE phase")
    # Keyboard parity: Enter/Space on a focused value cell is the same verb.
    key = FILTERS.split('document.addEventListener("keydown"', 1)[1].split("}, true)", 1)[0]
    assert '"Enter"' in key and '" "' in key and "ev.preventDefault()" in key


def test_the_pill_and_clear_all_are_the_house_bubble():
    assert 'class: "bubble filter",' in FILTERS
    assert '"aria-pressed": "true"' in FILTERS, "a holding pill must announce that it holds"
    assert 'class: "bubble-x"' in FILTERS
    assert 'class: "bubble filter filter-clear"' in FILTERS
    # No second pill shape (the retired `.chip`) grew back inside the bar.
    assert not re.search(r'class: "[^"]*\b(chip|pill|dc-chip)\b', FILTERS)


def test_the_bar_and_the_url_cannot_disagree():
    """The bar is a mirror of view state, and that state is URL-backed: every bar render
    follows a sync, and a cold load re-renders the bar after restore."""
    assert "function scheduleURLSync()" in APP and "FILTER_BAR.render()" in APP
    sync = APP.split("function syncURL()", 1)[1].split("\n}", 1)[0]
    assert "FILTER_BAR" in sync, "the URL writer does not refresh the bar, so they can drift"
    apply = APP.split("function applyURLState()", 1)[1]
    assert "FILTER_BAR" in apply[:4000] or "showView(" in apply, (
        "a cold load must reach a path that renders the bar")


def test_the_rendered_contract_is_executed_in_the_harness():
    """The five behaviours the operator named, kept in CI. Deleting one is a test failure."""
    harness = (ROOT / "scripts" / "jsdom_render.js").read_text(encoding="utf-8")
    for label in (
        "a value click adds ONE removable pill naming the value",
        "it narrows the table to the value that was clicked",
        "does NOT also open the host sheet",
        "a row click opens the host sheet",
        "adds NO pill and leaves the value filter in place",
        "removing the pill restores the full table and hides the bar",
        "Clear all empties every pill and restores the view",
        "a cold load from a filtered URL rebuilds the pill and the table",
    ):
        assert label in harness, f"the filter-bar behaviour is no longer executed: {label!r}"
