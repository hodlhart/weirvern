"""The console's copy budget: one status line, one action, the rest behind Details.

The operator's constraint (2026-11-20): "This is not simple. There are too many words. It needs
to be user friendly." These assertions pin the EXACT short strings the operator named, and pin
the rendered-DOM budget check that fails when a card or sheet shows more than 25 words before a
`details` disclosure. The rendering half lives in scripts/jsdom_render.js (`visibleWords`), which
measures the built DOM rather than the source.
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / "weirvern" / "admin" / "web"
BUDGET = 25

READINESS = "Not scanning — nmap missing on this weirling."
INSTALL_SUCCESS = "Installed. This weirling can scan "
PASSWORD_LINE = "Needed to install on this host."
CANCEL_Q = "Cancel scan?"
CANCEL_CONSEQUENCE = "This removes the job from the record."
DISABLED = "No weirling can scan."


def test_the_rendered_dom_budget_is_part_of_the_harness():
    harness = (ROOT / "scripts" / "jsdom_render.js").read_text(encoding="utf-8")
    assert "function visibleWords(root)" in harness
    # The budget is measured on the rendered text, excluding details/title/commands/table cells.
    assert "DETAILS" in harness and "TITLE" in harness
    assert "<= 25" in harness
    assert "the scanner card stays inside the 25-word copy budget" in harness
    assert "keeps the install sheet inside the 25-word copy budget" in harness


def test_scanner_readiness_is_one_line_and_one_action():
    js = (WEB / "weirlings.js").read_text(encoding="utf-8")
    assert READINESS in js
    assert 'id="scanner-install"' in (WEB / "index.html").read_text(encoding="utf-8")
    assert ">Install nmap<" in (WEB / "index.html").read_text(encoding="utf-8")
    # The count is a chip: "<n> of <m> can scan", not a sentence about the count.
    assert "`${capable} of ${total} can scan`" in js
    # The measured sentence is written into the Details body, never the status line.
    assert "detailText.textContent = String(cap.sentence" in js


def test_install_sheet_copy():
    js = (WEB / "weirlings.js").read_text(encoding="utf-8")
    html = (WEB / "index.html").read_text(encoding="utf-8")
    assert "Install nmap" in html
    assert "Runs: " in html
    assert 'text: "Install"' in js or "Install" in html
    assert INSTALL_SUCCESS in js
    assert PASSWORD_LINE in html
    # Password is shown only for the password case.
    assert 'item.sudo_state === "password"' in js
    # The long explanation lives inside the disclosure.
    assert "install-details" in html and "install-answer" in html


def test_cancel_is_two_words_and_a_consequence():
    html = (WEB / "index.html").read_text(encoding="utf-8")
    js = (WEB / "scan.js").read_text(encoding="utf-8")
    assert CANCEL_Q in html
    assert CANCEL_CONSEQUENCE in html
    assert "Cancel scan" in html and "Keep" in html
    # The audit reason is written by the console; the operator is not asked to type it.
    assert "cancelled from the console" in html
    assert '"cancelled from the console"' in js


def test_disabled_scan_reason_is_not_a_sentence_chain():
    js = (WEB / "scan.js").read_text(encoding="utf-8")
    assert f'text = "{DISABLED}"' in js
    assert "No weirling can scan this host:" not in js
    # The verbose honesty essay is inside Details in the sheet body, not a bare paragraph above it.
    assert 'el("details", { class: "copy-details scan-more" })' in js


def test_visible_copy_drops_jargon():
    """Plain words above the fold: the precise terms stay in Details or the info tooltip."""
    visible_sources = {
        "weirlings.js": (WEB / "weirlings.js").read_text(encoding="utf-8"),
        "scan.js": (WEB / "scan.js").read_text(encoding="utf-8"),
    }
    banned = ("advisory band",)
    for name, text in visible_sources.items():
        for word in banned:
            assert word not in text.lower(), f"{name} still says {word!r}"
    # The scan sheet's visible consequence lines are short and jargon-free.
    js = visible_sources["scan.js"]
    for line in ("Nothing will run this job.", "This job timed out.", "Scan failed.",
                 "Job not found.", "Still waiting for a weirling.", "Queue unavailable."):
        assert line in js, line
    assert "no weirling has claimed it" not in js
    assert "capability report" not in js.split("function scanRenderBody")[1].split("els.body.appendChild(more)")[0]
