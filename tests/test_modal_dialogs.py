"""The modal (the operator, 2026-10-16): "any time we click to edit or see a rule or block or allow
dns, clicking that button should generate a popup something. not just added to the bottom of the
screen or in the middle of the current screen between rows".

Pin the shell, the move-and-restore mechanics that keep one editor with one set of ids, and the
two surfaces that must open in it."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / "weirvern" / "admin" / "web"


def test_the_shell_exists_exactly_once():
    html = (WEB / "index.html").read_text()
    for elem in ('id="modal"', 'id="modal-body"', 'id="modal-backdrop"', 'id="modal-close"'):
        assert elem in html, f"{elem} missing"
    assert html.count('id="modal"') == 1, "one dialog shell, not one per view"


def test_open_and_close_move_the_node_and_restore_it():
    js = (WEB / "app.js").read_text()
    assert "function openModal(" in js and "function closeModal(" in js
    assert "MODAL_HOME" in js, "the home a node returns to must be remembered"
    assert "body.appendChild(node)" in js, "MOVED, not cloned -- one editor, one id set"
    assert 'home.appendChild(node)' in js, "closing must restore the node to its home"


def test_escape_and_backdrop_close():
    js = (WEB / "app.js").read_text()
    assert 'e.key === "Escape"' in js
    assert 'modal-backdrop' in js


def test_the_rule_card_opens_in_the_modal_but_the_composer_is_a_sheet():
    blocked = (WEB / "blocked.js").read_text()
    assert "openModal(els.card)" in blocked and "closeModal(els.card)" in blocked
    sluice = (WEB / "sluice.js").read_text()
    assert "openRuleSheet(" in sluice
    html = (WEB / "index.html").read_text()
    assert 'id="sl-rule-sheet"' in html, "the rule sheet is missing"
    assert 'id="rule-composer"' not in html, "the old centred composer survives"


def test_the_dns_block_verb_lives_behind_one_row_disclosure():
    html = (WEB / "index.html").read_text()
    thead = html[html.index("<th>time</th><th>client</th><th>query</th>"):]
    thead = thead[:thead.index("</tr>")]
    assert thead.count("<th>") == 7 and thead.rstrip().endswith("<th></th>"), (
        "the action column must be a real trailing header, not a cell inside query"
    )
    js = (WEB / "dnsview.js").read_text()
    assert "q.appendChild(blk)" not in js, "the button moved OUT of the query cell"
    assert "dn-actions" in js and "dn-more" in js
    assert "act.appendChild(more)" in js and "more.appendChild(blk)" in js
    assert "act.appendChild(blk)" not in js, "the verb is row furniture again"
