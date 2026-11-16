"""OP-3: a monthly review that passes while a phase card is blocked is not a review."""
from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from tests.support_routes import routed
from weirvern.models import review

ROOT = Path(__file__).resolve().parents[1]


def _boards(done: bool = True):
    status = "done" if done else "blocked"
    return {board: [{"id": f"t_{board}", "title": board, "status": status}]
            for board in review.PHASE_BOARDS}


def _verification() -> dict:
    return {"available": True, "verified_attack_windows": 4,
            "verified_negative_hours": 12.0, "generator_version": "scenario-2026-11"}


def _report(**overrides):
    params: dict[str, Any] = dict(
        generated_at=datetime(2026, 11, 11, tzinfo=UTC), boards=_boards(),
        slo={"available": True, "windows": []},
        coverage={"available": True, "sources": [], "promotion_ok": True},
        cards=[{"model_name": "Adaptive Baseline", "status": "production"}],
        calibration=[], verification=_verification(), next_review="2026-12-11",
    )
    params.update(overrides)
    return review.build_report(**params)


def test_a_complete_program_with_verified_evidence_passes():
    out = _report()
    assert out["status"] == "pass"
    assert out["blocked_cards"] == []
    assert out["decision"] == "continue"


def test_a_blocked_card_fails_the_review_and_names_it():
    boards = _boards()
    boards[review.PHASE_BOARDS[0]][0]["status"] = "blocked"
    out = _report(boards=boards)
    assert out["status"] == "fail"
    assert out["blocked_cards"][0]["id"] == f"t_{review.PHASE_BOARDS[0]}"
    any(review.PHASE_BOARDS[0] in failure for failure in out["failures"])


def test_a_missing_board_fails_the_review():
    boards = _boards()
    del boards[review.PHASE_BOARDS[1]]
    out = _report(boards=boards)
    assert out["status"] == "fail"
    assert any(card["status"] == "missing" for card in out["blocked_cards"])


def test_missing_or_weak_verification_fails_the_review():
    out = _report(verification=None)
    assert out["status"] == "fail"
    assert any("verification report is missing" in failure for failure in out["failures"])
    weak = dict(_verification())
    weak["verified_attack_windows"] = 0
    weak["generator_version"] = ""
    out = _report(verification=weak)
    assert out["status"] == "fail"
    assert any("verified attack windows" in failure for failure in out["failures"])
    assert any("generator version" in failure for failure in out["failures"])


def test_the_archive_and_review_surface_are_exposed():
    api = (ROOT / "weirvern" / "admin" / "web_api.py").read_text()
    js = (ROOT / "weirvern" / "admin" / "web" / "app.js").read_text()
    html = (ROOT / "weirvern" / "admin" / "web" / "index.html").read_text()
    assert routed("/api/ml/review"), "the review route is not registered"
    assert "latest_report" in api
    assert "renderReview" in js and "m-review" in js
    assert "Program review" in html and "m-review" in html
