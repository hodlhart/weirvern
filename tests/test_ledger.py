"""PR-3: the ledger is append-only and the gate names every unaccounted blocker."""
from __future__ import annotations

from pathlib import Path

from weirvern.models import ledger


def _boards(done=True):
    status = "done" if done else "blocked"
    return {b: [{"id": f"t_{b}", "title": b, "status": status}] for b in ledger.PHASE_BOARDS}


def _verification():
    return {"verified_attack_windows": 3, "verified_negative_hours": 8.0}


def test_complete_boards_and_verification_pass():
    out = ledger.gate(boards=_boards(), model_cards=[{"model_name": "AB", "status": "production",
                                                      "artifact_hash": "sha256:x"}],
                      verification=_verification())
    assert out["status"] == "pass"


def test_blocked_card_and_missing_card_fail_with_names():
    boards = _boards()
    boards["wv-ml-ops"][0]["status"] = "blocked"
    out = ledger.gate(boards=boards,
                      model_cards=[{"model_name": "AB", "status": "production",
                                    "artifact_hash": ""}],
                      verification=_verification())
    assert out["status"] == "fail"
    assert out["blocked_cards"][0]["id"] == "t_wv-ml-ops"
    assert out["missing_model_cards"] == ["AB"]


def test_missing_verification_fails():
    out = ledger.gate(boards=_boards(), model_cards=[], verification=None)
    assert any("verification" in failure for failure in out["failures"])


def test_ledger_is_append_only_and_round_trips(tmp_path: Path):
    path = tmp_path / "ledger.jsonl"
    ledger.append(path, {"kind": "promotion", "action": "promote"})
    ledger.append(path, {"kind": "retirement", "action": "retire"})
    rows = ledger.read(path)
    assert [row["action"] for row in rows] == ["promote", "retire"]
    assert path.read_text().count("\n") == 2


def test_two_consecutive_failed_reviews_retire():
    reviews = [{"review_id": "r1", "status": "fail", "generated_at": "2026-10-01"},
               {"review_id": "r2", "status": "fail", "generated_at": "2026-11-01"}]
    out = ledger.retirement_decision(reviews)
    assert out["retire"] is True
    assert out["review_ids"] == ["r1", "r2"]


def test_one_failed_review_does_not_retire():
    assert ledger.retirement_decision(
        [{"review_id": "r1", "status": "fail", "generated_at": "2026-10-01"}]
    )["retire"] is False
