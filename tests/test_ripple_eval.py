"""The measurement harness itself must be trustworthy: it is what the cards are evidenced with."""
from __future__ import annotations

from weirvern.models import ripple_corpus as corpus
from weirvern.models import ripple_eval as evaluation


def _run(seed: int, hosts: int = 2, reference_days: int = 8):
    payload = corpus.generate(seed=seed, hosts_per_scenario=hosts,
                              reference_days=reference_days)
    days = corpus.host_days(payload)
    reference = evaluation._reference(
        [evaluation.channel_series(day) for day in days
         if day.scenario in {"clean", "clean_reference"}])
    measured = [day for day in days if day.scenario != "clean_reference"]
    results = evaluation.evaluate_days(measured, reference)
    return results, evaluation.summarise(results)


def test_a_clean_day_produces_no_fire_and_a_large_change_does():
    results, summary = _run(seed=101)
    clean = [r for r in results if r.scenario == "clean"]
    assert clean and all(not r.fires for r in clean), "a clean day must not fire"
    assert summary["false_alarms_per_host_day"] == 0.0
    big = [d for r in results for d in r.detections
           if d["expected"] == "ripple" and d["amplitude"] >= 0.50]
    assert big and any(d["detected_with_grace"] for d in big), (
        "a 50% change over hours must be detected; the corpus exists to catch a regression here")


def test_a_single_window_burst_never_becomes_a_ripple():
    _, summary = _run(seed=103)
    burst = summary["by_scenario"].get("burst", {})
    assert burst and burst["fired"] == 0


def test_the_summary_reports_an_interval_not_a_bare_rate():
    _, summary = _run(seed=107, hosts=1, reference_days=4)
    low, high = summary["detection_ci95_with_grace"]
    assert 0.0 <= low <= high <= 1.0
    assert summary["min_consecutive_buckets"] >= 2
