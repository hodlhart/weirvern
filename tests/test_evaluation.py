"""ML-15: the fixed-budget gate must measure, not bless a plausible story."""
from __future__ import annotations

from datetime import datetime, timedelta

from weirvern.models import evaluation


def _rows(scores_by_host: dict[str, dict[str, float]], base: datetime):
    rows = []
    for host, scores in scores_by_host.items():
        for model, score in scores.items():
            rows.append(evaluation.ScoreRow(base, host, model, score))
    return rows


def _fixture():
    base = datetime(2026, 11, 10, 20, 0)
    baseline = {
        "198.51.100.10": {"Adaptive Baseline": 0.70, "Isolation Forest": 0.20,
                            "Gradient Boosting": 0.10},
        "198.51.100.13": {"Adaptive Baseline": 0.20, "Isolation Forest": 0.80,
                            "Gradient Boosting": 0.70},
        "198.51.100.14": {"Adaptive Baseline": 0.10, "Isolation Forest": 0.20,
                            "Gradient Boosting": 0.20},
    }
    labels = [
        {"src_addr": "198.51.100.10", "window_start": base.isoformat(),
         "label": "attack", "start": (base - timedelta(minutes=5)).isoformat(),
         "scenario": "port_scan", "label_source": "synthetic"},
        {"src_addr": "198.51.100.13", "window_start": base.isoformat(), "label": "benign",
         "label_source": "background", "duration_min": 5},
        {"src_addr": "198.51.100.14", "window_start": base.isoformat(), "label": "benign",
         "label_source": "background", "duration_min": 5},
    ]
    return base, _rows(baseline, base), labels


def test_the_fixed_budget_takes_the_top_k_per_day():
    base = datetime(2026, 11, 10, 0, 0)
    scores = {
        (base, "a"): 0.9, (base + timedelta(hours=1), "b"): 0.8,
        (base + timedelta(hours=2), "c"): 0.7,
        (base + timedelta(days=1), "d"): 0.95,
    }
    picked = evaluation.select_fixed_budget(scores, 2)
    assert len(picked) == 3
    assert {item.src_addr for item in picked if item.day == base.date()} == {"a", "b"}
    assert {item.src_addr for item in picked if item.day != base.date()} == {"d"}


def test_an_equal_candidate_is_not_promoted():
    base, rows, labels = _fixture()
    windows = evaluation.build_windows(rows)
    baseline = evaluation.measure(windows, models=("Adaptive Baseline", "Isolation Forest",
                                                   "Gradient Boosting"),
                                  budget_per_day=1, name="baseline", labels=labels)
    candidate = evaluation.measure(windows, models=("Adaptive Baseline", "Isolation Forest",
                                                    "Gradient Boosting"),
                                   budget_per_day=1, name="candidate", labels=labels)
    decision = evaluation.promote(baseline, candidate)
    assert not decision.promote
    assert any("no measured improvement" in reason for reason in decision.reasons)


def test_a_better_candidate_is_promoted_at_the_same_budget():
    base, rows, labels = _fixture()
    windows = evaluation.build_windows(rows)
    # Baseline's top slot is the benign 0.80 host; candidate's is the attack at 0.95.
    candidate_scores = {("198.51.100.10"): 0.95, "198.51.100.13": 0.10,
                        "198.51.100.14": 0.05}
    candidate_rows = [
        evaluation.ScoreRow(base, host, "HDBSCAN", score)
        for host, score in candidate_scores.items()
    ]
    baseline = evaluation.measure(windows, models=("Adaptive Baseline", "Isolation Forest",
                                                   "Gradient Boosting"),
                                  budget_per_day=1, name="baseline", labels=labels)
    candidate = evaluation.measure(evaluation.build_windows(candidate_rows), models=("HDBSCAN",),
                                   budget_per_day=1, name="HDBSCAN", labels=labels)
    decision = evaluation.promote(baseline, candidate)
    assert decision.promote, decision.reasons
    assert candidate.precision > baseline.precision
    assert candidate.detection_rate >= baseline.detection_rate


def test_more_raw_alerts_without_better_precision_is_rejected():
    base, rows, labels = _fixture()
    windows = evaluation.build_windows(rows)
    # The candidate shouts on every benign host; at budget 1 it still misses the attack.
    candidate_rows = [
        evaluation.ScoreRow(base, "198.51.100.10", "HDBSCAN", 0.10),
        evaluation.ScoreRow(base, "198.51.100.13", "HDBSCAN", 0.99),
        evaluation.ScoreRow(base, "198.51.100.14", "HDBSCAN", 0.98),
    ]
    baseline = evaluation.measure(windows, models=("Adaptive Baseline", "Isolation Forest",
                                                   "Gradient Boosting"),
                                  budget_per_day=1, name="baseline", labels=labels)
    candidate = evaluation.measure(evaluation.build_windows(candidate_rows), models=("HDBSCAN",),
                                   budget_per_day=1, name="HDBSCAN", labels=labels)
    decision = evaluation.promote(baseline, candidate)
    assert not decision.promote
    assert any("precision" in reason or "detection" in reason
               or "more raw alerts" in reason or "no measured improvement" in reason
               for reason in decision.reasons)


def test_unlabelled_population_cannot_promote():
    base, rows, _labels = _fixture()
    windows = evaluation.build_windows(rows)
    baseline = evaluation.measure(windows, models=("Adaptive Baseline",), budget_per_day=1,
                                  name="baseline")
    candidate = evaluation.measure(windows, models=("Adaptive Baseline",), budget_per_day=1,
                                   name="candidate")
    decision = evaluation.promote(baseline, candidate)
    assert not decision.promote
    assert any("no labels" in reason for reason in decision.reasons)


def test_distribution_is_over_every_window_not_only_alerts():
    base, rows, _labels = _fixture()
    windows = evaluation.build_windows(rows)
    dist = evaluation.score_distribution(windows.values(), ("Isolation Forest",))
    assert dist["Isolation Forest"]["count"] == 3
    assert "p99" in dist["Isolation Forest"]


def test_weak_only_labels_cannot_promote():
    base, rows, labels = _fixture()
    weak = [dict(item) for item in labels]
    for item in weak:
        item["label_source"] = "weak"
    windows = evaluation.build_windows(rows)
    baseline = evaluation.measure(windows, models=("Adaptive Baseline",), budget_per_day=1,
                                  name="baseline", labels=weak)
    candidate = evaluation.measure(windows, models=("Adaptive Baseline",), budget_per_day=1,
                                   name="candidate", labels=weak)
    decision = evaluation.promote(baseline, candidate)
    assert not decision.promote
    assert any("verified attack windows" in reason for reason in decision.reasons)
    assert any("verified negative hours" in reason for reason in decision.reasons)
    assert candidate.verified_attack_windows == 0
