"""The ML charter is a contract, so its required terms are testable.

The card requires no code; these assertions prevent a later edit from quietly dropping the
envelope, the risk owners or the unmeasured-risk statement.
"""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CHARTER = ROOT / "docs" / "runbooks" / "ml-charter.md"
RISKS = ROOT / "docs" / "runbooks" / "ml-risk-register.md"


def test_the_envelope_names_the_operator_and_the_decisions():
    text = CHARTER.read_text()
    assert "Samuel Hart" in text
    assert "Page vs ticket" in text
    assert "Page:" in text and "Ticket:" in text


def test_the_envelope_is_bounded_with_numbers():
    text = CHARTER.read_text()
    for token in ("EPISODE_PAGE_BUDGET=2", "14 days", "72 hours", "5%", "ML_ELIGIBILITY=false"):
        assert token in text, token


def test_non_goals_and_unmeasured_risks_are_explicit():
    text = CHARTER.read_text()
    assert "Non-goals" in text
    assert "not measured" in text
    for phrase in ("insider abuse", "encrypted command-and-control", "upstream image"):
        assert phrase in text, phrase


def test_the_risk_register_covers_every_required_risk():
    text = RISKS.read_text()
    for risk in (
        "Missed attack", "Alert fatigue", "Automated ground-truth bias", "Concept drift",
        "Telemetry / source gap", "Feedback-loop collapse", "Adversarial or poisoned input",
    ):
        assert risk in text, risk
    for field in ("Likelihood", "Impact", "Mitigation", "Owner", "Review"):
        assert field in text, field
