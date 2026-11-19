"""The sheet standard (docs/design/sheets.md, 2026-10-18: "Make that pop out a standard.").

A sheet is the primitive for changing or reading ONE object. It must be a real class, one
implementation (scrim, Escape, focus in sheets.js), a labelled dialog, and one close control.
These tests pin the standard; the browser audit measures the pixels.
"""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / "weirvern" / "admin" / "web"


def _opening_tag(html: str, element_id: str) -> str:
    at = html.index(f'id="{element_id}"')
    start = html.rindex("<div", 0, at)
    end = html.index(">", at)
    return html[start:end]


def test_the_sheet_is_a_class_not_one_special_id():
    css = (WEB / "style.css").read_text()
    assert re.search(r"^\.sheet \{", css, re.M), "no generic .sheet rule"
    assert re.search(r"^\.sheet\.hidden \{", css, re.M), "no generic hidden rule"
    assert "#wl-detail-card.sheet {" not in css, "the overlay is still pinned to one id"
    assert "width: min(480px, 94vw)" in css
    phone = css.split("@media (max-width: 720px) {", 1)[1]
    assert ".sheet { width: 100vw" in phone, "a phone sheet is not full width"


def test_every_sheet_is_a_labelled_dialog_with_one_close():
    html = (WEB / "index.html").read_text()
    for card_id, title_id in (("wl-detail-card", "wl-detail-title"),
                              ("sl-rule-sheet", "sl-rule-title")):
        tag = _opening_tag(html, card_id)
        assert "card sheet" in tag, f"{card_id} is not a sheet"
        assert 'role="dialog"' in tag and 'aria-modal="true"' in tag, f"{card_id} is not a dialog"
        assert f'aria-labelledby="{title_id}"' in tag, f"{card_id} has no label"
        assert 'aria-hidden="true"' in tag, f"{card_id} hides with a class but not from AT"
        assert f'<span id="{title_id}"' in html, f"{title_id} missing"
    # 3 since the Normalize sheet (operator, 2026-11-19): weirlings, identity detail, normalize.
    assert html.count('class="sheet-close"') == 3, "not exactly one close per sheet"


def test_the_sheets_share_one_opener_and_build_no_private_machinery():
    sheets = (WEB / "sheets.js").read_text()
    for fn in ("function openSheet(", "function closeSheet(", "function sheetIsOpen(",
               "function wireSheet("):
        assert fn in sheets, f"sheets.js lacks {fn}"
    assert 'document.addEventListener("keydown"' in sheets, "the one Escape/Tab handler is missing"
    assert 'e.stopImmediatePropagation' in sheets, "a sheet over a modal must win Escape"
    for name in ("weirlings.js", "sluice.js"):
        js = (WEB / name).read_text()
        assert "openSheet(" in js and "closeSheet(" in js, f"{name} does not use the standard"
        assert "className = \"sheet-scrim\"" not in js and "sheet-scrim hidden" not in js, \
            f"{name} still builds a private scrim"
        assert 'e.key === "Escape"' not in js, f"{name} still binds its own sheet Escape"
        assert 'card.classList.remove("hidden")' not in js, f"{name} still opens the sheet by hand"


def test_the_standard_is_loaded_before_the_sheets():
    html = (WEB / "index.html").read_text()
    assert '/sheets.js' in html
    assert html.index('/sheets.js') < html.index('/sluice.js') < html.index('/weirlings.js')


def test_the_action_bar_is_sticky_in_both_sheets():
    css = (WEB / "style.css").read_text()
    assert ".sheet-actions { position: sticky; bottom: 0" in css
    html = (WEB / "index.html").read_text()
    assert html.count('class="controls sheet-actions"') >= 3, "a sheet action row is not sticky"


def test_the_standard_document_exists_and_names_the_implementation():
    doc = (ROOT / "docs" / "design" / "sheets.md").read_text()
    for phrase in ("When a sheet, and when not", "Anatomy", "checklist",
                   "sheets.js", "arm twice"):
        assert phrase.lower() in doc.lower(), f"the standard does not cover {phrase!r}"
