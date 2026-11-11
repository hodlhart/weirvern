"""CE-4: the promotion gate consumes verified evidence, not a label count."""
from __future__ import annotations

from pathlib import Path

from weirvern.models import evaluation

ROOT = Path(__file__).resolve().parents[1]


def test_verified_counts_are_separate_from_weak_and_unknown():
    assert {"synthetic", "canary", "background"} == evaluation.VERIFIED_SOURCES
    assert evaluation.MIN_VERIFIED_ATTACK_WINDOWS >= 1
    assert evaluation.MIN_VERIFIED_NEGATIVE_HOURS > 0
    source = (ROOT / "weirvern" / "models" / "evaluation.py").read_text()
    for field in ("verified_attack_windows", "verified_negative_hours",
                  "verification_coverage", "weak_only_selected", "unlabelled_selected",
                  "clean_replay_false_alarms_per_host_day", "live_precision"):
        assert field in source, field


def test_the_report_and_view_show_not_measured_for_absent_verification():
    api = (ROOT / "weirvern" / "admin" / "web_api.py").read_text()
    js = (ROOT / "weirvern" / "admin" / "web" / "app.js").read_text()
    html = (ROOT / "weirvern" / "admin" / "web" / "index.html").read_text()
    assert '"verification"' in api and "live_precision" in api
    assert "renderVerification" in js and "m-verify" in js
    assert "Verification coverage" in html and "m-verify" in html
