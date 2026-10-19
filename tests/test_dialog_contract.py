"""The dialog contract and keyboard filter cells (HD-17, GitHub #17).

The modal shell moved nodes correctly but was invisible to assistive technology and unusable
from a keyboard: no label, no focus move, no Tab containment, no focus restore, and `.dcell`
filter cells were mouse-only. These pins keep the contract from silently regressing.
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / "weirvern" / "admin" / "web"


def test_the_shell_is_a_labelled_modal_dialog():
    html = (WEB / "index.html").read_text()
    tag = html[html.index('id="modal"'):html.index(">", html.index('id="modal"'))]
    assert 'role="dialog"' in tag and 'aria-modal="true"' in tag


def test_open_modal_labels_focuses_and_restores():
    js = (WEB / "app.js").read_text()
    assert "shell.setAttribute(\"aria-labelledby\"" in js, "the dialog has no accessible name"
    assert "MODAL_RETURN = document.activeElement" in js, "the opener is not remembered"
    assert "if (typeof target.focus === \"function\") target.focus();" in js, "focus does not enter"
    assert "if (back && document.contains(back)" in js, "focus does not return to the opener"


def test_tab_is_contained_while_the_dialog_is_the_top_surface():
    js = (WEB / "app.js").read_text()
    assert "function modalFocusables()" in js
    assert "e.key !== \"Tab\"" in js and "e.preventDefault()" in js
    assert "document.querySelector(\".sheet:not(.hidden)\")" in js, \
        "a sheet above the modal must own the keyboard instead"


def test_filter_cells_are_keyboard_operable():
    js = (WEB / "app.js").read_text()
    assert "function markFilterCells()" in js
    assert 'cell.setAttribute("tabindex", "0")' in js
    assert 'cell.setAttribute("role", "button")' in js
    assert "e.key === \"Enter\"" in js and '" "' in js, "Enter/Space must activate a focused cell"
    assert "filterCellWiring();" in js, "the wiring is never called at startup"
