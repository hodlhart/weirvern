"""GT-4: a canary hit is one high-confidence positive; health checks are excluded."""
from __future__ import annotations

from datetime import UTC, datetime

from weirvern.models import canary


def _hit(**kw):
    base = dict(src_addr="198.51.100.240", service_id="canary-ssh", token="ssh-token",
                fingerprint=canary.fingerprint("canary-ssh", "ssh-token"),
                observed_at=datetime(2026, 11, 11, tzinfo=UTC))
    base.update(kw)
    return canary.CanaryHit(**base)


def test_synthetic_hit_is_emitted_once_with_source_and_fingerprint():
    event = canary.event_from_hit(_hit(), generator_version="canary-v1")
    assert event["label_source"] == "canary"
    assert event["label"] == "attack"
    assert event["src_addr"] == "198.51.100.240"
    assert event["service_id"] == "canary-ssh"
    assert event["fingerprint"]


def test_authorized_health_check_is_excluded():
    assert canary.event_from_hit(_hit(authorized=True), generator_version="canary-v1") is None


def test_unknown_service_or_token_is_refused():
    for kwargs in ({"service_id": "not-a-canary"}, {"token": "wrong"}):
        try:
            canary.event_from_hit(_hit(**kwargs), generator_version="canary-v1")
        except ValueError:
            pass
        else:
            raise AssertionError(f"accepted invalid canary hit: {kwargs}")


def test_canary_hit_cannot_be_benign_background():
    event = canary.event_from_hit(_hit(), generator_version="canary-v1")
    assert event is not None and event["label"] != "benign"
    health = canary.health([event])
    assert health["state"] == "observed"
    assert health["hits"]["canary-ssh"] == 1
