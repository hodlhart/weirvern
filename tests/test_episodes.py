"""Episode grouping and the per-host page budget."""
from __future__ import annotations

from datetime import datetime, timedelta

from weirvern.episodes import apply_budget, build_episodes

BASE = datetime(2026, 10, 30, 0, 0, 0)


def row(minute: int, *, host: str = "192.0.2.10", score: float = 0.9,
        severity: str = "high") -> dict:
    start = BASE + timedelta(minutes=minute)
    return {
        "src_addr": host,
        "window_start": start,
        "window_end": start + timedelta(minutes=5),
        "detected_at": start + timedelta(minutes=6),
        "anomaly_score": score,
        "severity": severity,
    }


def test_continuous_windows_are_one_episode():
    episodes = build_episodes([row(0, score=0.7), row(5, score=0.99), row(10, score=0.8)])
    assert len(episodes) == 1
    episode = episodes[0]
    assert episode["occurrences"] == 3
    assert episode["window_count"] == 3
    assert episode["severity"] == "high"
    assert episode["max_score"] == 0.99
    assert episode["page_window"] == BASE + timedelta(minutes=5)


def test_gap_larger_than_thirty_minutes_starts_a_new_episode():
    episodes = build_episodes([row(0), row(5), row(41)])  # 31 minutes after the prior end
    assert len(episodes) == 2
    assert [episode["occurrences"] for episode in episodes] == [2, 1]


def test_hosts_never_share_an_episode():
    episodes = build_episodes([row(0, host="192.0.2.10"), row(0, host="192.0.2.11")])
    assert len(episodes) == 2
    assert {episode["src_addr"] for episode in episodes} == {"192.0.2.10", "192.0.2.11"}


def test_budget_marks_only_top_episode_for_a_host():
    episodes = build_episodes([
        row(0, score=0.91, severity="high"),
        row(60, score=0.95, severity="critical"),
        row(120, score=0.90, severity="high"),
    ])
    apply_budget(episodes, per_host_budget=1, min_severity="high")
    pageable = [episode for episode in episodes if episode["pageable"]]
    assert len(pageable) == 1
    assert pageable[0]["max_score"] == 0.95
    assert {episode["page_reason"] for episode in episodes} == {"within-budget", "budget"}


def test_medium_never_pages_and_claimed_episode_consumes_budget():
    episodes = build_episodes([
        row(0, score=0.55, severity="medium"),
        row(60, score=0.99, severity="critical"),
    ])
    episodes[0]["paged_at"] = BASE + timedelta(minutes=1)
    apply_budget(episodes, per_host_budget=1, min_severity="high",
                 paged_by_host={"192.0.2.10": 1})
    assert all(not episode["pageable"] for episode in episodes)
    assert episodes[0]["page_reason"] == "paged"
    assert episodes[1]["page_reason"] == "budget"
