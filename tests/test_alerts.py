from datetime import datetime

from weirvern.alerts import AlertState, format_message
from weirvern.config import Settings


def _settings(**kw):
    base = dict(
        pushover_enabled=False, pushover_user_key="u", pushover_api_token="t",
        pushover_cooldown_s=1800, pushover_max_per_hour=20,
    )
    base.update(kw)
    return Settings(
        pushover_enabled=bool(base["pushover_enabled"]),
        pushover_user_key=str(base["pushover_user_key"]),
        pushover_api_token=str(base["pushover_api_token"]),
        pushover_cooldown_s=int(base["pushover_cooldown_s"]),
        pushover_max_per_hour=int(base["pushover_max_per_hour"]),
    )


def _verdict(src="198.51.100.5", score=0.55, agreement=0.66, sev="medium"):
    return {
        "src_addr": src, "anomaly_score": score, "model_agreement": agreement,
        "severity": sev, "detected_by_models": "Isolation Forest,DBSCAN",
        "isolation_forest_score": 0.6, "gradient_boosting_score": 0.2,
        "dbscan_score": 0.55, "baseline_score": 0.0,
        "window_start": datetime(2026, 9, 14, 10, 30),
    }


def test_cooldown_blocks_second_send():
    state = AlertState()
    _settings(pushover_cooldown_s=1800)
    assert state.cooldown_remaining("198.51.100.5", 1800) == 0.0
    state.last_sent["198.51.100.5"] = 0.0  # "sent" long ago
    assert state.cooldown_remaining("198.51.100.5", 1800) == 0.0


def test_can_send_respects_cap():
    import time

    state = AlertState()
    settings = _settings(pushover_max_per_hour=2)
    now = time.time()
    state.hourly_events = [now - 10, now - 20]  # both inside the current hour
    allowed, reason = state.can_send("198.51.100.5", settings)
    assert not allowed and reason == "cap"


def test_can_send_prunes_old_events():
    state = AlertState()
    settings = _settings(pushover_max_per_hour=2)
    state.hourly_events = [1.0, 2.0]  # > 1h ago
    allowed, _ = state.can_send("198.51.100.5", settings)
    assert allowed


def test_format_message_compact():
    msg = format_message(_verdict())
    assert "198.51.100.5" in msg
    assert "medium" in msg.lower()
    assert "IF:0.60" in msg
    assert len(msg) < 1024  # Pushover limit

def test_the_last_sent_map_is_PRUNED_not_left_to_grow():
    """Issue #29: the per-source cooldown map was never pruned and grew for the process
    lifetime (a review measured it at 10k entries). Eviction rides prune_hourly, which runs
    on every send decision: entries older than the horizon cannot affect any cooldown, and a
    recent one survives with its cooldown intact."""
    import time

    from weirvern.alerts import LAST_SENT_MAX_AGE_S

    st = AlertState()
    now = time.time()
    for i in range(10_000):
        st.last_sent["198.51.100." + str(i % 250) + "-" + str(i)] = now - LAST_SENT_MAX_AGE_S - 60
    fresh = "203.0.113.7"
    st.last_sent[fresh] = now - 30
    st.prune_hourly(now)
    assert len(st.last_sent) == 1, "stale entries survived the prune"
    assert fresh in st.last_sent
    assert st.cooldown_remaining(fresh, cooldown_s=300, now=now) > 0, (
        "a fresh entry lost its cooldown -- eviction must not cut into the live window")
    # an hour later the fresh entry is beyond the horizon too and goes
    st.prune_hourly(now + LAST_SENT_MAX_AGE_S + 1)
    assert not st.last_sent
