"""PR-2: green canary promotes, red canary rolls back, bad inputs do neither."""
from __future__ import annotations

from dataclasses import replace

from weirvern.models.promotion import CanaryEvidence, decide, ledger_entry, next_card_status


def _evidence(**overrides):
    base = CanaryEvidence(
        candidate_id="HDBSCAN-v2", artifact_hash="sha256:" + "a" * 64,
        model_card_status="canary", generator_version="scenario-2026-11",
        gate_report_id="eval-2026-11-11", gate_promote=True, shadow_days=14.0,
        shadow_pageable=0, soak_ok=True, canary_days=3.0, canary_requests=1000,
        canary_errors=0, canary_p95_s=0.4, baseline_p95_s=0.4, telemetry_fresh=True,
        kill_switch=False,
    )
    return replace(base, **overrides)


def test_green_canary_promotes_automatically():
    out = decide(_evidence())
    assert out["action"] == "promote"
    assert next_card_status("canary", "promote") == "production"


def test_red_canary_rolls_back():
    out = decide(_evidence(canary_errors=3))
    assert out["action"] == "rollback"
    assert next_card_status("canary", "rollback") == "shadow"

    out = decide(_evidence(gate_promote=False))
    assert out["action"] == "rollback"


def test_degraded_telemetry_blocks_promotion():
    out = decide(_evidence(telemetry_fresh=False))
    assert out["action"] == "block"
    assert any("telemetry" in reason for reason in out["reasons"])


def test_kill_switch_freezes_automation():
    out = decide(_evidence(kill_switch=True))
    assert out["action"] == "freeze"
    assert "kill switch" in out["reasons"][0]


def test_in_flight_and_short_soak_hold():
    out = decide(_evidence(), active_in_flight=1)
    assert out["action"] == "hold"
    out = decide(_evidence(shadow_days=13.9))
    assert out["action"] == "hold"


def test_ledger_entry_is_explicit_about_status_change():
    decision = decide(_evidence())
    entry = ledger_entry(decision, previous_status="canary", next_status="production")
    assert entry["action"] == "promote"
    assert entry["previous_status"] == "canary"
    assert entry["next_status"] == "production"
    assert entry["policy_version"] == "pr2-v1"
