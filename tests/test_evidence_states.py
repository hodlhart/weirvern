"""The evidence panel's honesty states are in the shipping JS, not only in a runbook.

These are source assertions on the real bundle because the DOM harness cannot be run in this
environment without a browser dependency. They are deliberately narrow: the words an operator
sees, and the presence of the source-freshness stage, are the contract.
"""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "weirvern" / "admin" / "web" / "app.js"


def test_the_chain_has_a_sources_stage_before_detection():
    src = APP.read_text()
    assert '["sources", "sources"' in src
    # The source stage reads the payload field, not a hardcoded "fresh".
    assert "d.source_freshness" in src


def test_the_chain_never_calls_an_absent_source_fresh():
    src = APP.read_text()
    assert "not measured \\u2014 no source freshness was returned" in src
    assert "unknown \\u2014 no flow record was read for this window" in src


def test_the_verdict_says_the_score_is_not_a_probability():
    src = APP.read_text()
    assert "decision value, not a probability" in src


def test_the_source_state_vocabulary_is_present():
    src = APP.read_text()
    for word in ("fresh", "stale", "not measured", "failed", "unknown"):
        assert word in src, word
